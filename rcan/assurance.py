"""rcan.assurance — RCAN Appendix C (Physical Assurance Profile) helpers.

Informative and optional. Nothing in RCAN requires an implementation to use
this module, and nothing here changes any existing conformance level.

Python port of the rcan-spec reference verifier
``scripts/assurance/evidence-chain.ts`` (rcan-spec PR #221). Three checks a
third party can run with nothing but the log and the envelope:

    verify_chain             R5: hash linkage, sequence, per-record hash
    audit_authority          R4: every executed authority-gated command names
                             a principal and an authority
    replay_against_envelope  R5: every applied command sits inside the
                             declared envelope

Finding codes, hashing and edge-case behaviour match the TypeScript reference
so the two verifiers agree on the same chain.

These helpers check evidence. They do not check a robot, and a passing chain
says nothing about whether the machine behaved as the log claims.

Physical assurance levels A1-A3 are a separate axis from RCAN protocol
conformance levels L1-L4. An L3 robot can be A1. Conformance is not
certification.
"""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass
from typing import Any, Literal, Mapping, Optional, Sequence, TypedDict

from rcan.encoding import canonical_json

__all__ = [
    "ASSURANCE_LEVELS",
    "DECISIONS",
    "GENESIS_PREV",
    "AssuranceLevel",
    "Decision",
    "Envelope",
    "Finding",
    "GateDecision",
    "append_record",
    "audit_authority",
    "envelope_hash",
    "record_hash",
    "replay_against_envelope",
    "sha256_text",
    "verify_chain",
]

#: ``prev`` of the first record in a chain: ``sha256:`` followed by 64 zeros.
GENESIS_PREV: str = "sha256:" + "0" * 64

AssuranceLevel = Literal["A1", "A2", "A3"]

#: Physical assurance levels (A1 Declared, A2 Enforced, A3 Assured).
#: Independent of RCAN protocol conformance levels L1-L4. Self-declared unless
#: accompanied by third-party evidence.
ASSURANCE_LEVELS: tuple[str, ...] = ("A1", "A2", "A3")

Decision = Literal["allow", "clamp", "reject", "stop"]

#: The four gate decisions, in the order Appendix C lists them.
DECISIONS: tuple[str, ...] = ("allow", "clamp", "reject", "stop")


# ── Typed structures (shapes of schemas/envelope.json and gate-decision.json) ──
#
# TypedDicts, not dataclasses: records are hashed as plain JSON objects, so the
# verifier works directly on what ``json.load`` returns.


class _GateDecisionRequired(TypedDict):
    type: Literal["gate_decision"]
    seq: int
    t: int
    principal: str
    authority: Optional[str]
    cmd: Optional[dict[str, Any]]
    decision: Decision
    applied: Optional[dict[str, Any]]
    envelope: str
    state_digest: str
    prev: str
    hash: str


class GateDecision(_GateDecisionRequired, total=False):
    """One ``gate_decision`` evidence record (schemas/gate-decision.json)."""

    reason: str


class EnvelopeMachine(TypedDict, total=False):
    id: str
    # "class" is a Python keyword; read it as envelope["machine"]["class"].
    mass_kg: float


class EnvelopeWorkspace(TypedDict, total=False):
    frame: str
    keep_in: list[list[float]]
    keep_out: list[list[list[float]]]
    z_range_m: list[float]


class EnvelopeMotion(TypedDict, total=False):
    max_speed_mps: float
    max_turn_radps: float
    max_accel_mps2: float
    max_joint_speed_radps: float


class EnvelopeAuthority(TypedDict, total=False):
    required_for: list[str]
    resolver: Literal["external", "local"]


class Envelope(TypedDict, total=False):
    """Physical envelope (schemas/envelope.json). Shape only; not validated.

    Required by the schema: envelope_version, machine, level, workspace,
    motion, stop, heartbeat. Declared total=False so partial envelopes can be
    passed to the replay helpers, which read only what they understand.
    """

    envelope_version: str
    machine: EnvelopeMachine
    level: AssuranceLevel
    workspace: EnvelopeWorkspace
    motion: EnvelopeMotion
    force: dict[str, float]
    proximity: list[dict[str, Any]]
    sensing: dict[str, int]
    stop: dict[str, Any]
    heartbeat: dict[str, Any]
    authority: EnvelopeAuthority
    signature: str


@dataclass(frozen=True)
class Finding:
    """One verification finding. ``seq`` is None for chain-wide findings.

    ``field`` names the member, for ``UNCHECKED_FIELDS`` only.
    """

    seq: Optional[int]
    code: str
    detail: str
    field: Optional[str] = None


# ── Hashing ─────────────────────────────────────────────────────────────────


def sha256_text(text: bytes | str) -> str:
    """``sha256:<hex>`` of UTF-8 text (or raw bytes)."""
    data = text.encode("utf-8") if isinstance(text, str) else text
    return "sha256:" + hashlib.sha256(data).hexdigest()


def envelope_hash(envelope: Mapping[str, Any]) -> str:
    """Hash of an envelope: canonical JSON with the ``signature`` member removed."""
    return sha256_text(canonical_json(dict(envelope), exclude="signature"))


def record_hash(record: Mapping[str, Any]) -> str:
    """Hash of a record: canonical JSON with the ``hash`` member removed."""
    return sha256_text(canonical_json(dict(record), exclude="hash"))


def append_record(
    chain: Sequence[Mapping[str, Any]], partial: Mapping[str, Any]
) -> list[GateDecision]:
    """Return a new chain with ``partial`` appended, filling seq, prev and hash.

    Used to build fixtures and tests. Does not modify ``chain``.
    """
    last = chain[-1] if chain else None
    rec: dict[str, Any] = dict(partial)
    rec["seq"] = last["seq"] + 1 if last is not None else 0
    rec["prev"] = last["hash"] if last is not None else GENESIS_PREV
    rec.pop("hash", None)
    rec["hash"] = record_hash(rec)
    return [*chain, rec]  # type: ignore[list-item]


# ── Input shape ─────────────────────────────────────────────────────────────


def _require_records(chain: Any, links: bool) -> None:
    """The record shape every check relies on.

    Records must be objects whose ``seq`` is a non-negative integer and, for
    :func:`verify_chain`, whose ``prev`` and ``hash`` are strings. Without that
    a finding means nothing (a missing seq used to give "expected seq NaN"), so
    such input raises ``TypeError`` instead of being judged.
    """
    if not isinstance(chain, (list, tuple)):
        raise TypeError("records: expected a list of gate_decision records")
    for i, rec in enumerate(chain):
        if not isinstance(rec, Mapping):
            raise TypeError(f"records[{i}]: not an object")
        seq = rec.get("seq")
        if not (_is_number(seq) and _finite(seq) and seq == int(seq) and seq >= 0):
            raise TypeError(f"records[{i}]: seq must be a non-negative integer")
        if links and not (isinstance(rec.get("prev"), str) and isinstance(rec.get("hash"), str)):
            raise TypeError(f"records[{i}]: prev and hash must be strings")


# ── EV-08: chain verification ───────────────────────────────────────────────


def verify_chain(
    chain: Sequence[Mapping[str, Any]], expected_head: Optional[str] = None
) -> list[Finding]:
    """EV-08. Detect mutation, insertion, deletion and reordering of records.

    It cannot detect removal of records from the END of the chain: that needs
    the last hash anchored somewhere the writer cannot rewrite (a signed
    checkpoint, a registry, a second log). Callers that hold such an anchor
    pass it as ``expected_head``.
    """
    _require_records(chain, links=True)
    findings: list[Finding] = []
    for i, rec in enumerate(chain):
        seq = rec.get("seq")
        expected_prev = GENESIS_PREV if i == 0 else chain[i - 1].get("hash")
        if i == 0 and seq != 0:
            findings.append(Finding(seq, "BAD_GENESIS", "first record must have seq 0"))
        if i > 0:
            prev_seq: Any = chain[i - 1].get("seq")
            if not _is_number(prev_seq) or seq != prev_seq + 1:
                want = _js(prev_seq + 1) if _is_number(prev_seq) else "NaN"
                findings.append(Finding(seq, "SEQ_GAP", f"expected seq {want}"))
        if rec.get("prev") != expected_prev:
            findings.append(
                Finding(seq, "PREV_MISMATCH", "prev does not equal the previous record's hash")
            )
        if record_hash(rec) != rec.get("hash"):
            findings.append(Finding(seq, "HASH_MISMATCH", "record contents do not match its hash"))
    if expected_head is not None:
        head = chain[-1].get("hash") if chain else GENESIS_PREV
        if head != expected_head:
            findings.append(
                Finding(None, "HEAD_MISMATCH", "chain head does not match the anchored head")
            )
    return findings


# ── EV-07 (log half): authority audit ───────────────────────────────────────


def audit_authority(
    chain: Sequence[Mapping[str, Any]], envelope: Mapping[str, Any]
) -> list[Finding]:
    """EV-07 (log half). Flag executed, authority-gated commands without attribution.

    An executed command (allow or clamp) whose kind the envelope lists in
    ``authority.required_for`` must carry a principal and an authority, each a
    non-empty string. The command kind is read from ``cmd.kind``; a command
    without a kind is treated as ``"motion"``, the conservative reading. Only
    string entries of a list ``required_for`` gate a kind.
    """
    _require_records(chain, links=False)
    authority = envelope.get("authority")
    required_for = authority.get("required_for") if isinstance(authority, Mapping) else None
    gated = (
        {k for k in required_for if isinstance(k, str)}
        if isinstance(required_for, (list, tuple))
        else set()
    )
    findings: list[Finding] = []
    for rec in chain:
        if rec.get("decision") not in ("allow", "clamp"):
            continue
        cmd = rec.get("cmd")
        raw_kind = cmd.get("kind") if isinstance(cmd, Mapping) else None
        kind = raw_kind if isinstance(raw_kind, str) else "motion"
        if kind not in gated:
            continue
        if not _non_empty_str(rec.get("principal")):
            findings.append(
                Finding(rec.get("seq"), "NO_PRINCIPAL", f"executed {kind} command has no principal")
            )
        if not _non_empty_str(rec.get("authority")):
            findings.append(
                Finding(rec.get("seq"), "NO_AUTHORITY", f"executed {kind} command has no authority")
            )
    return findings


# ── Replay against the envelope ─────────────────────────────────────────────

def replay_against_envelope(
    chain: Sequence[Mapping[str, Any]], envelope: Mapping[str, Any]
) -> list[Finding]:
    """Replay every record against the envelope and the Appendix C decision table.

    C.1.1 and C.6: ``allow`` applies the command unchanged; ``clamp``,
    ``reject`` and ``stop`` carry a reason; ``reject`` applies ``null``; the
    others apply an object.

    Understands the illustrative command shape used in Appendix C:
    ``{kind, linear_mps, angular_radps, target: [x, y]}``. A bound, polygon or
    target is used only when it has the type replay needs (a number; three or
    more points; two finite numbers). Members of ``applied`` that replay cannot
    judge, because the name is unknown or the value unusable, are reported as
    ``UNCHECKED_FIELDS`` once per name, sorted by UTF-16 code units, so
    silence is never read as a pass.
    """
    _require_records(chain, links=False)
    findings: list[Finding] = []
    env_hash = envelope_hash(envelope)
    unchecked: set[str] = set()
    motion = envelope.get("motion")
    motion = motion if isinstance(motion, Mapping) else {}
    workspace = envelope.get("workspace")
    workspace = workspace if isinstance(workspace, Mapping) else {}
    max_v = motion.get("max_speed_mps") if _is_number(motion.get("max_speed_mps")) else None
    max_w = motion.get("max_turn_radps") if _is_number(motion.get("max_turn_radps")) else None
    keep_in = workspace.get("keep_in") if _is_polygon(workspace.get("keep_in")) else None
    keep_out_raw = workspace.get("keep_out")
    keep_out = (
        [z for z in keep_out_raw if _is_polygon(z)] if isinstance(keep_out_raw, (list, tuple)) else []
    )

    for rec in chain:
        seq = rec.get("seq")
        decision = rec.get("decision")
        if rec.get("envelope") != env_hash:
            findings.append(
                Finding(seq, "ENVELOPE_MISMATCH", "record was decided under a different envelope")
            )
        if not (isinstance(decision, str) and decision in DECISIONS):
            findings.append(
                Finding(
                    seq,
                    "UNKNOWN_DECISION",
                    f"decision {_stringify_member(rec, 'decision')} is not allow, clamp, reject or stop",
                )
            )
            continue
        applied = rec.get("applied")
        if decision == "reject":
            # A missing applied member is not the null that reject requires.
            if "applied" not in rec or applied is not None:
                findings.append(Finding(seq, "REJECT_APPLIED", "reject must apply null"))
        elif not isinstance(applied, Mapping):
            findings.append(Finding(seq, "APPLIED_NOT_OBJECT", f"{decision} must apply an object"))
        else:
            v = applied.get("linear_mps") if _is_number(applied.get("linear_mps")) else None
            w = applied.get("angular_radps") if _is_number(applied.get("angular_radps")) else None
            target = applied.get("target") if decision != "stop" and _is_point(applied.get("target")) else None
            for k in applied:
                judged = (
                    k == "kind"
                    or (k == "linear_mps" and v is not None)
                    or (k == "angular_radps" and w is not None)
                    or (k == "target" and target is not None)
                )
                if not judged:
                    unchecked.add(k)
            if decision == "stop":
                if (v is not None and v != 0) or (w is not None and w != 0):
                    findings.append(Finding(seq, "STOP_WITH_MOTION", "stop applied a non-zero velocity"))
            else:
                if v is not None and max_v is not None and abs(v) > max_v:
                    findings.append(
                        Finding(seq, "SPEED_EXCEEDED", f"|{_js(v)}| > max_speed_mps {_js(max_v)}")
                    )
                if w is not None and max_w is not None and abs(w) > max_w:
                    findings.append(
                        Finding(seq, "TURN_EXCEEDED", f"|{_js(w)}| > max_turn_radps {_js(max_w)}")
                    )
                if target is not None:
                    if keep_in is not None and not _inside_polygon(target, keep_in):
                        findings.append(
                            Finding(seq, "OUTSIDE_KEEP_IN", f"target {_js(target)} outside keep_in")
                        )
                    for zone in keep_out:
                        if _inside_polygon(target, zone):
                            findings.append(
                                Finding(seq, "INSIDE_KEEP_OUT", f"target {_js(target)} inside keep_out")
                            )
                # A missing cmd counts as null.
                if decision == "allow" and canonical_json({"v": applied}) != canonical_json(
                    {"v": rec.get("cmd")}
                ):
                    findings.append(
                        Finding(seq, "ALLOW_MODIFIED", "allow must apply the command unchanged")
                    )
        if decision != "allow" and not _non_empty_str(rec.get("reason")):
            findings.append(Finding(seq, "MISSING_REASON", f"{decision} must give a reason"))
    for k in sorted(unchecked, key=lambda name: name.encode("utf-16-be", "surrogatepass")):
        findings.append(
            Finding(
                None,
                "UNCHECKED_FIELDS",
                f"applied.{k} is not judged by this reference replay",
                field=k,
            )
        )
    return findings


# ── Internals ───────────────────────────────────────────────────────────────


def _is_number(x: Any) -> bool:
    """JavaScript ``typeof x === "number"``, excluding Python bools."""
    return isinstance(x, (int, float)) and not isinstance(x, bool)


def _stringify_member(rec: Mapping[str, Any], key: str) -> str:
    """``JSON.stringify(rec[key])`` as the reference writes it into a detail.

    ``undefined`` when the member is absent and ``null`` when it is null;
    object members keep their order (unlike :func:`_js`, which writes
    canonical JSON).
    """
    if key not in rec:
        return "undefined"
    return json.dumps(rec[key], ensure_ascii=False, separators=(",", ":"))


def _finite(x: Any) -> bool:
    """Finite as a binary64 value (an int too large for a float is not)."""
    try:
        return math.isfinite(x)
    except OverflowError:
        return False


def _is_point(x: Any) -> bool:
    """Two finite numbers."""
    return (
        isinstance(x, (list, tuple))
        and len(x) == 2
        and all(_is_number(c) and _finite(c) for c in x)
    )


def _is_polygon(x: Any) -> bool:
    """Three or more points."""
    return isinstance(x, (list, tuple)) and len(x) >= 3 and all(_is_point(p) for p in x)


def _non_empty_str(x: Any) -> bool:
    return isinstance(x, str) and len(x) > 0


def _js(value: Any) -> str:
    """Render a value the way the TS reference interpolates it into details."""
    if value is None:
        return "undefined"
    if isinstance(value, float) and value.is_integer() and math.isfinite(value):
        return str(int(value))
    if _is_number(value):
        return str(value)
    # JSON.stringify equivalent (canonical form: no spaces, whole floats as ints).
    return canonical_json({"v": value}).decode("utf-8")[len('{"v":') : -1]


def _inside_polygon(point: Sequence[Any], poly: Sequence[Sequence[Any]]) -> bool:
    """Ray casting. Points exactly on an edge count as inside."""
    x, y = point[0], point[1]
    inside = False
    j = len(poly) - 1
    for i in range(len(poly)):
        xi, yi = poly[i][0], poly[i][1]
        xj, yj = poly[j][0], poly[j][1]
        cross = (x - xi) * (yj - yi) - (y - yi) * (xj - xi)
        on_segment = (
            abs(cross) < 1e-12
            and min(xi, xj) <= x <= max(xi, xj)
            and min(yi, yj) <= y <= max(yi, yj)
        )
        if on_segment:
            return True
        if (yi > y) != (yj > y) and x < ((xj - xi) * (y - yi)) / (yj - yi) + xi:
            inside = not inside
        j = i
    return inside

