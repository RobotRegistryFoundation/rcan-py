"""Tests for rcan.assurance — RCAN Appendix C evidence-chain helpers (informative).

Mirrors rcan-spec ``tests/assurance/evidence-chain.test.ts``. These tests prove
the verification procedure catches what it claims to catch. They test the
method and the fixtures, not any robot or runtime.

Fixture origin: copied verbatim from RobotRegistryFoundation/rcan-spec, branch
``align/bounded-embodiment`` (PR #221, commit 34ad1ca), paths
``fixtures/envelope/*.json`` and ``fixtures/gate-decision/rover-chain.valid.json``,
into ``tests/fixtures/assurance/``. The chain's ``hash`` and ``envelope`` values
were produced by the TypeScript reference verifier
(``scripts/assurance/evidence-chain.ts``), so recomputing them here is the
cross-language parity check. ``tests/fixtures/canonical-json-v1.json`` was
already present and is byte-identical to the rcan-spec copy.
"""

from __future__ import annotations

import base64
import copy
import json
from pathlib import Path
from typing import Any

import pytest

from rcan.assurance import (
    ASSURANCE_LEVELS,
    DECISIONS,
    GENESIS_PREV,
    Finding,
    append_record,
    audit_authority,
    envelope_hash,
    record_hash,
    replay_against_envelope,
    verify_chain,
)
from rcan.encoding import canonical_json

FIXTURES = Path(__file__).parent / "fixtures"
ASSURANCE = FIXTURES / "assurance"


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


ENVELOPE: dict[str, Any] = _load(ASSURANCE / "envelope" / "rover.valid.json")
CHAIN: list[dict[str, Any]] = _load(ASSURANCE / "gate-decision" / "rover-chain.valid.json")
CANONICAL_CASES = _load(FIXTURES / "canonical-json-v1.json")["cases"]


def clone(x: Any) -> Any:
    return copy.deepcopy(x)


def codes(findings: list[Finding]) -> list[str]:
    return [f.code for f in findings]


# ── Canonical JSON and cross-language hash parity ──────────────────────────


@pytest.mark.parametrize("case", CANONICAL_CASES, ids=[c["name"] for c in CANONICAL_CASES])
def test_canonical_json_matches_fixture(case: dict[str, Any]) -> None:
    got = base64.b64encode(canonical_json(case["input"])).decode("ascii")
    assert got == case["expected_bytes_base64"]


@pytest.mark.parametrize("i", range(len(CHAIN)))
def test_record_hash_matches_typescript_reference(i: int) -> None:
    """record_hash of each fixture record equals the hash rcan-spec's TS verifier stored."""
    assert record_hash(CHAIN[i]) == CHAIN[i]["hash"]


def test_envelope_hash_matches_typescript_reference() -> None:
    # The envelope contains whole-number floats (max_accel_mps2 1.0,
    # human_within_m 1.0) that Python parses as float; they must hash as the
    # integers JavaScript sees.
    assert isinstance(ENVELOPE["motion"]["max_accel_mps2"], float)
    for rec in CHAIN:
        assert rec["envelope"] == envelope_hash(ENVELOPE)


def test_whole_number_floats_hash_like_integers() -> None:
    rec = clone(CHAIN[4])  # stop record with linear_mps 0, angular_radps 0
    assert rec["applied"]["linear_mps"] == 0
    rec["applied"]["linear_mps"] = 0.0
    rec["applied"]["angular_radps"] = -0.0
    rec["t"] = float(rec["t"])
    assert record_hash(rec) == CHAIN[4]["hash"]


# ── Fixture chain ───────────────────────────────────────────────────────────


def test_fixture_chain_verifies_clean() -> None:
    assert verify_chain(CHAIN) == []


def test_fixture_chain_starts_at_genesis() -> None:
    assert CHAIN[0]["prev"] == GENESIS_PREV
    assert GENESIS_PREV == "sha256:" + "0" * 64


def test_envelope_hash_ignores_signature() -> None:
    assert envelope_hash({**ENVELOPE, "signature": "ed25519:other"}) == envelope_hash(ENVELOPE)
    unsigned = {k: v for k, v in ENVELOPE.items() if k != "signature"}
    assert envelope_hash(unsigned) == envelope_hash(ENVELOPE)


def test_constants() -> None:
    assert ASSURANCE_LEVELS == ("A1", "A2", "A3")
    assert DECISIONS == ("allow", "clamp", "reject", "stop")
    assert ENVELOPE["level"] in ASSURANCE_LEVELS
    assert all(r["decision"] in DECISIONS for r in CHAIN)


def test_append_record_rebuilds_the_fixture_chain() -> None:
    chain: list[Any] = []
    for rec in CHAIN:
        partial = {k: v for k, v in rec.items() if k not in ("seq", "prev", "hash")}
        chain = append_record(chain, partial)
    assert chain == CHAIN


def test_append_record_does_not_mutate_input() -> None:
    base = clone(CHAIN[:2])
    partial = {k: v for k, v in CHAIN[2].items() if k not in ("seq", "prev", "hash")}
    out = append_record(base, partial)
    assert len(base) == 2 and len(out) == 3
    assert out[2]["seq"] == 2 and out[2]["prev"] == base[1]["hash"]


# ── EV-08 log tampering ─────────────────────────────────────────────────────


def test_mutating_a_field_is_detected() -> None:
    c = clone(CHAIN)
    c[1]["applied"]["linear_mps"] = 0.9
    assert "HASH_MISMATCH" in codes(verify_chain(c))


def test_mutating_and_rehashing_breaks_next_link() -> None:
    c = clone(CHAIN)
    c[1]["decision"] = "allow"
    c[1]["hash"] = record_hash(c[1])
    assert "PREV_MISMATCH" in codes(verify_chain(c))


def test_deleting_a_record_is_detected() -> None:
    c = clone(CHAIN)
    del c[2]
    got = codes(verify_chain(c))
    assert "SEQ_GAP" in got and "PREV_MISMATCH" in got


def test_inserting_a_forged_record_is_detected() -> None:
    c = clone(CHAIN)
    forged = {**clone(c[0]), "seq": 1, "prev": c[0]["hash"], "t": c[0]["t"] + 1}
    forged["hash"] = record_hash(forged)
    c.insert(1, forged)
    got = codes(verify_chain(c))
    assert "SEQ_GAP" in got and "PREV_MISMATCH" in got


def test_reordering_records_is_detected() -> None:
    c = clone(CHAIN)
    c[2], c[3] = c[3], c[2]
    assert len(verify_chain(c)) > 0


def test_bad_genesis_is_detected() -> None:
    assert "BAD_GENESIS" in codes(verify_chain(clone(CHAIN[1:])))


def test_tail_truncation_not_detectable_without_anchor() -> None:
    # Stated limit of a hash chain, asserted so nobody reads the verifier as covering it.
    assert verify_chain(CHAIN[:3]) == []


def test_tail_truncation_detected_with_anchored_head() -> None:
    head = CHAIN[-1]["hash"]
    assert codes(verify_chain(CHAIN[:3], head)) == ["HEAD_MISMATCH"]
    assert verify_chain(CHAIN, expected_head=head) == []


def test_empty_chain_head_is_genesis() -> None:
    assert verify_chain([]) == []
    assert verify_chain([], expected_head=GENESIS_PREV) == []
    assert codes(verify_chain([], expected_head=CHAIN[0]["hash"])) == ["HEAD_MISMATCH"]


def test_head_mismatch_finding_has_no_seq() -> None:
    [f] = verify_chain(CHAIN[:3], CHAIN[-1]["hash"])
    assert f == Finding(None, "HEAD_MISMATCH", "chain head does not match the anchored head")


# ── EV-07 log half: accountable commands ────────────────────────────────────


def test_fixture_chain_has_no_executed_command_without_authority() -> None:
    assert audit_authority(CHAIN, ENVELOPE) == []


def test_executed_motion_without_authority_is_flagged() -> None:
    src = CHAIN[0]
    partial = {
        k: src[k]
        for k in ("type", "t", "principal", "cmd", "applied", "envelope", "state_digest")
    }
    c = append_record([], {**partial, "authority": None, "decision": "allow"})
    assert codes(audit_authority(c, ENVELOPE)) == ["NO_AUTHORITY"]


def test_executed_command_without_principal_is_flagged() -> None:
    c = clone(CHAIN)
    c[0]["principal"] = ""
    assert codes(audit_authority(c, ENVELOPE)) == ["NO_PRINCIPAL"]


def test_command_without_kind_is_treated_as_motion() -> None:
    c = clone(CHAIN)
    del c[0]["cmd"]["kind"]
    c[0]["authority"] = None
    assert codes(audit_authority(c, ENVELOPE)) == ["NO_AUTHORITY"]


def test_ungated_command_kind_is_not_flagged() -> None:
    env = {**ENVELOPE, "authority": {"required_for": ["gripper"], "resolver": "external"}}
    c = [{**r, "authority": None} for r in clone(CHAIN)]
    assert audit_authority(c, env) == []


def test_reject_and_stop_are_not_audited() -> None:
    # seq 3 is a reject with authority null; seq 4 and 5 are gate-originated
    # stops with authority null. None of them executed a gated command.
    assert [r["authority"] for r in CHAIN[3:]] == [None, None, None]
    assert audit_authority(CHAIN, ENVELOPE) == []


# ── Replay against the envelope ─────────────────────────────────────────────


def test_fixture_chain_replays_clean() -> None:
    assert replay_against_envelope(CHAIN, ENVELOPE) == []


def test_speed_exceeded_is_flagged() -> None:
    c = clone(CHAIN)
    c[0]["applied"]["linear_mps"] = 0.8
    assert "SPEED_EXCEEDED" in codes(replay_against_envelope(c, ENVELOPE))


def test_turn_exceeded_is_flagged() -> None:
    c = clone(CHAIN)
    c[0]["applied"]["angular_radps"] = -2
    assert "TURN_EXCEEDED" in codes(replay_against_envelope(c, ENVELOPE))


def test_target_outside_keep_in_is_flagged() -> None:
    c = clone(CHAIN)
    c[0]["applied"]["target"] = [6.5, 1]
    found = replay_against_envelope(c, ENVELOPE)
    assert "OUTSIDE_KEEP_IN" in codes(found)
    assert any(f.detail == "target [6.5,1] outside keep_in" for f in found)


def test_target_on_keep_in_edge_counts_as_inside() -> None:
    c = clone(CHAIN)
    c[0]["applied"]["target"] = [6, 2]
    assert "OUTSIDE_KEEP_IN" not in codes(replay_against_envelope(c, ENVELOPE))


def test_target_inside_keep_out_is_flagged() -> None:
    zone = [[1, 0], [3, 0], [3, 2], [1, 2]]
    env = {**ENVELOPE, "workspace": {**ENVELOPE["workspace"], "keep_out": [zone]}}
    c = clone(CHAIN)
    for r in c:
        r["envelope"] = envelope_hash(env)
    assert codes(replay_against_envelope(c, env)) == ["INSIDE_KEEP_OUT"]


def test_stop_with_motion_is_flagged() -> None:
    c = clone(CHAIN)
    stop = next(r for r in c if r["decision"] == "stop")
    stop["applied"]["linear_mps"] = 0.1
    assert "STOP_WITH_MOTION" in codes(replay_against_envelope(c, ENVELOPE))


def test_reject_that_applied_something_is_flagged() -> None:
    c = clone(CHAIN)
    c[2]["applied"] = {"kind": "motion", "linear_mps": 0.1}
    assert "REJECT_APPLIED" in codes(replay_against_envelope(c, ENVELOPE))


def test_envelope_mismatch_is_flagged() -> None:
    tighter = {**ENVELOPE, "motion": {**ENVELOPE["motion"], "max_speed_mps": 0.25}}
    assert "ENVELOPE_MISMATCH" in codes(replay_against_envelope(CHAIN, tighter))


def test_unchecked_fields_are_reported_not_silently_passed() -> None:
    c = clone(CHAIN)
    c[0]["applied"]["joint_torque_nm"] = [1, 2]
    c[1]["applied"]["joint_torque_nm"] = [1, 2]
    found = replay_against_envelope(c, ENVELOPE)
    unchecked = [f for f in found if f.code == "UNCHECKED_FIELDS"]
    detail = "applied.joint_torque_nm is not judged by this reference replay"
    assert unchecked == [Finding(None, "UNCHECKED_FIELDS", detail, field="joint_torque_nm")]


def test_bool_is_not_treated_as_a_speed() -> None:
    c = clone(CHAIN)
    c[4]["applied"]["linear_mps"] = True
    assert "STOP_WITH_MOTION" not in codes(replay_against_envelope(c, ENVELOPE))


def test_top_level_exports() -> None:
    import rcan

    for name in (
        "ASSURANCE_LEVELS",
        "GENESIS_PREV",
        "append_record",
        "audit_authority",
        "envelope_hash",
        "record_hash",
        "replay_against_envelope",
        "verify_chain",
    ):
        assert name in rcan.__all__
        assert getattr(rcan, name) is getattr(__import__("rcan.assurance").assurance, name)


# ── Parity with the TypeScript reference (two cases the port used to get wrong) ──


def test_reject_without_applied_member_is_flagged_like_the_reference():
    """Absent is not null: the reference flags it (undefined !== null)."""
    c = clone(CHAIN)
    rej = next(r for r in c if r["decision"] == "reject")
    del rej["applied"]
    assert "REJECT_APPLIED" in codes(replay_against_envelope(c, ENVELOPE))


def test_authority_that_is_not_an_object_gates_nothing():
    """The reference reads envelope.authority?.required_for; a list has none."""
    c = [dict(clone(CHAIN[0]), authority=None)]
    assert audit_authority(c, {**ENVELOPE, "authority": ["motion"]}) == []
    assert audit_authority(c, {**ENVELOPE, "authority": "motion"}) == []


# ── Mirrors RobotRegistryFoundation/rcan-spec#225 (reference verifier checks) ──


def _replay_codes(chain: list[dict[str, Any]], env: dict[str, Any] = ENVELOPE) -> list[str]:
    return [f"{f.code}:{f.field}" if f.field else f.code for f in replay_against_envelope(chain, env)]


@pytest.mark.parametrize(
    "mutate",
    [
        lambda c: c[1].pop("seq"),
        lambda c: c[1].__setitem__("seq", "1"),
        lambda c: c[0].__setitem__("seq", -1),
        lambda c: c[1].__setitem__("seq", 1.5),
        lambda c: c.__setitem__(1, []),
    ],
    ids=["seq missing", "seq a string", "seq negative", "seq a fraction", "record not an object"],
)
def test_malformed_records_raise_before_anything_is_judged(mutate: Any) -> None:
    c = clone(CHAIN)
    mutate(c)
    with pytest.raises(TypeError):
        verify_chain(c)
    with pytest.raises(TypeError):
        audit_authority(c, ENVELOPE)
    with pytest.raises(TypeError):
        replay_against_envelope(c, ENVELOPE)


def test_verify_chain_needs_string_prev_and_hash() -> None:
    c = clone(CHAIN)
    c[2]["hash"] = 7
    with pytest.raises(TypeError):
        verify_chain(c)


def test_authority_and_principal_are_non_empty_strings() -> None:
    rec = clone(CHAIN[0])
    assert codes(audit_authority([dict(rec, authority=5)], ENVELOPE)) == ["NO_AUTHORITY"]
    assert codes(audit_authority([dict(rec, principal=True)], ENVELOPE)) == ["NO_PRINCIPAL"]


def test_only_string_entries_of_a_list_required_for_gate() -> None:
    c = [dict(clone(CHAIN[0]), authority=None)]
    assert audit_authority(c, {**ENVELOPE, "authority": {"required_for": "motion"}}) == []
    assert codes(audit_authority(c, {**ENVELOPE, "authority": {"required_for": [1, "motion"]}})) == [
        "NO_AUTHORITY"
    ]


def _at(seq: int, drop: tuple[str, ...] = (), **patch: Any) -> list[dict[str, Any]]:
    c = clone(CHAIN)
    c[seq].update(patch)
    for k in drop:
        del c[seq][k]
    return c


def test_allow_that_changed_the_command_is_flagged() -> None:
    applied = dict(CHAIN[0]["applied"], linear_mps=0.25)
    assert _replay_codes(_at(0, applied=applied)) == ["ALLOW_MODIFIED"]


def test_allow_equal_to_its_command_in_another_member_order_passes() -> None:
    cmd = CHAIN[0]["cmd"]
    reordered = {k: cmd[k] for k in reversed(list(cmd))}
    assert _replay_codes(_at(0, applied=reordered)) == []


def test_clamp_reject_and_stop_need_a_reason() -> None:
    assert _replay_codes(_at(1, drop=("reason",))) == ["MISSING_REASON"]
    assert _replay_codes(_at(2, reason="")) == ["MISSING_REASON"]
    assert _replay_codes(_at(4, drop=("reason",))) == ["MISSING_REASON"]


def test_allow_clamp_and_stop_must_apply_an_object() -> None:
    assert _replay_codes(_at(0, applied=None)) == ["APPLIED_NOT_OBJECT"]
    assert _replay_codes(_at(1, applied=[0.5])) == ["APPLIED_NOT_OBJECT"]
    assert _replay_codes(_at(4, drop=("applied",))) == ["APPLIED_NOT_OBJECT"]


def test_unknown_decision_is_flagged_not_judged_as_allow() -> None:
    assert _replay_codes(_at(0, decision="permit")) == ["UNKNOWN_DECISION"]
    assert _replay_codes(_at(0, decision=["allow"])) == ["UNKNOWN_DECISION"]


def test_unknown_decision_detail_reads_like_the_reference() -> None:
    """The reference writes JSON.stringify(rec.decision): null is null, absent is undefined."""

    def detail(chain: list[dict[str, Any]]) -> str:
        return next(f.detail for f in replay_against_envelope(chain, ENVELOPE) if f.code == "UNKNOWN_DECISION")

    assert detail(_at(0, decision=None)) == "decision null is not allow, clamp, reject or stop"
    assert detail(_at(0, drop=("decision",))) == "decision undefined is not allow, clamp, reject or stop"
    assert detail(_at(0, decision={"z": 1, "a": 2})) == 'decision {"z":1,"a":2} is not allow, clamp, reject or stop'


def _reenvelope(motion: dict[str, Any], workspace: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    env = {
        **ENVELOPE,
        "motion": {**ENVELOPE["motion"], **motion},
        "workspace": {**ENVELOPE["workspace"], **workspace},
    }
    h = envelope_hash(env)
    return env, [dict(r, envelope=h) for r in clone(CHAIN)]


def test_bound_written_as_a_string_is_not_used() -> None:
    env, c = _reenvelope({"max_speed_mps": "0.1"}, {})
    assert _replay_codes(c, env) == []


def test_two_point_keep_out_is_not_a_polygon() -> None:
    env, c = _reenvelope({}, {"keep_out": [[[0, 1], [10, 1]]]})
    assert _replay_codes(c, env) == []


def test_unusable_target_and_speed_are_unchecked_not_judged() -> None:
    c = clone(CHAIN)
    c[1]["applied"]["target"] = ["99", 1]
    assert _replay_codes(c) == ["UNCHECKED_FIELDS:target"]
    c = clone(CHAIN)
    c[1]["applied"]["linear_mps"] = "9"
    assert _replay_codes(c) == ["UNCHECKED_FIELDS:linear_mps"]


def test_unchecked_names_are_sorted_by_utf16_code_units() -> None:
    c = clone(CHAIN)
    c[1]["applied"].update({"": 1, "\U0001F600": 1, "gripper": 1, "B": 1})
    assert _replay_codes(c) == [
        "UNCHECKED_FIELDS:B",
        "UNCHECKED_FIELDS:gripper",
        "UNCHECKED_FIELDS:\U0001F600",
        "UNCHECKED_FIELDS:",
    ]
