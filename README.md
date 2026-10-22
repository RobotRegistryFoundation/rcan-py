# rcan-py

**Python SDK for the [RCAN protocol](https://rcan.dev/spec/).** Build robots that communicate securely, audit every action, enforce safety gates locally, and register with the Robot Registry Foundation. Pinned protocol version: see the [live compatibility matrix](https://rcan.dev/compatibility).

Spec: [rcan.dev](https://rcan.dev) · Docs: [docs.rcan.dev](https://docs.rcan.dev) · Package: [PyPI `rcan`](https://pypi.org/project/rcan/)

[![PyPI version](https://img.shields.io/pypi/v/rcan.svg)](https://pypi.org/project/rcan/)
[![RCAN Spec](https://img.shields.io/badge/RCAN-live%20matrix-blue)](https://rcan.dev/compatibility)
[![Tests](https://github.com/RobotRegistryFoundation/rcan-py/actions/workflows/ci.yml/badge.svg)](https://github.com/RobotRegistryFoundation/rcan-py/actions)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://pypi.org/project/rcan/)

## Where this fits in the stack

This repo is the **Python SDK** layer — the library any Python planner, gateway, or driver links against to speak RCAN. Everything below is independent; adopt one, or all seven.

| Layer | Piece | What it is |
|---|---|---|
| **Declaration** | [ROBOT.md](https://github.com/RobotRegistryFoundation/robot-md) | The file a robot ships at its root. YAML frontmatter + markdown prose. Declares identity, capabilities, safety gates. Spec + Python CLI. |
| **Agent bridge** | [robot-md-mcp](https://github.com/RobotRegistryFoundation/robot-md-mcp) | MCP server that exposes a `ROBOT.md` to Claude Code, Claude Desktop, Cursor, Zed, Gemini CLI — any MCP-aware agent. |
| **Wire protocol** | [RCAN](https://rcan.dev/spec/) | How robots, gateways, and planners talk. Signed envelopes, LoA enforcement, PQC crypto. Think HTTP for robots. |
| **Python SDK** ← *this* | [rcan-py](https://github.com/RobotRegistryFoundation/rcan-py) | `pip install rcan` — `RCANMessage`, `RobotURI`, `ConfidenceGate`, `HiTLGate`, `AuditChain`, `RegistryClient`. |
| **TypeScript SDK** | [rcan-ts](https://github.com/RobotRegistryFoundation/rcan-ts) | `npm install rcan-ts` — same API surface for Node + browser. |
| **Registry** | [Robot Registry Foundation](https://robotregistryfoundation.org) | Permanent RRN identities. Public resolver at `/r/<rrn>`. Like ICANN for robots. |
| **Reference runtime** | [OpenCastor](https://github.com/craigm26/OpenCastor) | Open-source robot runtime — connects LLM brains to hardware bodies. One implementation of RCAN. |

## Install

```bash
pip install rcan
```

Optional extras:

```bash
pip install rcan[http]    # httpx for registry client
pip install rcan[crypto]  # cryptography for Ed25519 signing
pip install rcan[all]     # everything
```

## Quick Start

```python
from rcan import RobotURI, RCANMessage, ConfidenceGate
from rcan.audit import AuditChain, CommitmentRecord
from rcan.replay import ReplayCache

# 1. Address a robot
uri = RobotURI.build(manufacturer="acme", model="arm", version="v2", device_id="unit-001")
print(uri)  # rcan://registry.rcan.dev/acme/arm/v2/unit-001

# 2. Gate on model confidence before acting
gate = ConfidenceGate(threshold=0.8)
confidence = 0.91
if not gate.allows(confidence):
    raise SystemExit("confidence below threshold")

msg = RCANMessage(
    cmd="move_forward",
    target=uri,
    params={"distance_m": 1.0},
    confidence=confidence,
)

# 3. Replay prevention: reject a msg_id seen inside the window
cache = ReplayCache(window_s=30)
allowed, reason = cache.check_and_record(msg.msg_id, msg.timestamp)
assert allowed, reason
allowed, reason = cache.check_and_record(msg.msg_id, msg.timestamp)
assert not allowed  # the same msg_id again is a replay

# 4. HMAC-chained audit log
chain = AuditChain(secret="your-hmac-secret")
chain.append(CommitmentRecord(
    action="move_forward",
    params={"distance_m": 1.0},
    robot_uri=str(uri),
    confidence=confidence,
    model_identity="example-model",
    safety_approved=True,
))
assert chain.verify_all()

print(msg.to_json())
```

## Modules

| Module | Description |
|---|---|
| `rcan.message` | Core `RCANMessage` envelope with all v1.6 fields |
| `rcan.address` | `RobotURI` — parse, build, and validate RCAN robot addresses |
| `rcan.audit` | `AuditChain` + `CommitmentRecord` — tamper-evident HMAC-chained logs |
| `rcan.gates` | `ConfidenceGate`, `HiTLGate` — safety gates for AI-driven actions |
| `rcan.replay` | `ReplayCache` — sliding-window replay attack prevention (GAP-03) |
| `rcan.clock` | `ClockSyncStatus` — NTP clock sync verification (GAP-04) |
| `rcan.qos` | `QoSLevel` — FIRE_AND_FORGET / ACKNOWLEDGED / EXACTLY_ONCE (GAP-11) |
| `rcan.consent` | Consent wire protocol — request/grant/deny (GAP-05) |
| `rcan.revocation` | Robot identity revocation with TTL cache (GAP-02) |
| `rcan.training_consent` | Training data consent, GDPR/EU AI Act Annex III §5 (GAP-10) |
| `rcan.delegation` | Command delegation chain, max 4 hops, Ed25519-signed (GAP-01) |
| `rcan.offline` | Offline operation mode — ESTOP always allowed (GAP-06) |
| `rcan.fault` | `FaultCode` structured fault taxonomy (GAP-20) |
| `rcan.federation` | Federated consent — cross-registry trust, DNS discovery (GAP-16) |
| `rcan.transport` | Constrained transports — compact CBOR, 32-byte ESTOP minimal, BLE (GAP-17) |
| `rcan.multimodal` | Multi-modal payloads — inline/ref media, streaming (GAP-18) |
| `rcan.identity` | Level of Assurance — LoA policies, JWT parsing (GAP-14) |
| `rcan.keys` | Key rotation with JWKS-compatible `KeyStore` (GAP-09) |
| `rcan.config_update` | `CONFIG_UPDATE` protocol with safety scope enforcement (GAP-07) |
| `rcan.node` | `NodeClient` — resolve RRNs across federated registry nodes (§17) |
| `rcan.validate` | L1/L2/L3 conformance validation for configs, messages, URIs |
| `rcan.assurance` | RCAN Appendix C evidence checks: gate-decision chains, envelopes, recovery fields (informative) |

## Protocol 66 Compliance

Protocol 66 is RCAN's safety layer. Key invariants enforced by this SDK:

- **ESTOP always delivered** — `QoSLevel.EXACTLY_ONCE`, never blocked by QoS downgrade
- **Local safety wins** — `offline` module enforces local limits even without cloud connectivity
- **Confidence gates run locally** — `ConfidenceGate` never makes a network call
- **Audit chain required** — `AuditChain.verify_all()` before executing any flagged command

```python
from rcan import RCANMessage
from rcan.offline import OfflineModeManager
from rcan.safety import make_estop_message, validate_safety_message

robot = "rcan://registry.rcan.dev/acme/arm/v2/unit-001"
estop = make_estop_message(robot, reason="operator button")
assert validate_safety_message(estop) == []

offline = OfflineModeManager()
offline.go_offline()
allowed, why = offline.can_accept_command(RCANMessage(cmd="estop", target=robot))
assert allowed, why  # ESTOP is never blocked, even offline
allowed, why = offline.can_accept_command(
    RCANMessage(cmd="move_forward", target=robot), local_network=False
)
assert not allowed  # remote commands are blocked while offline
```

## CLI

```bash
# Validate a robot config (L1/L2/L3 conformance)
rcan-validate config myrobot.rcan.yaml

# Validate a RCAN message
rcan-validate message command.json

# Verify an audit chain
rcan-validate audit audit.jsonl

# Validate a Robot URI
rcan-validate uri 'rcan://registry.rcan.dev/acme/arm/v2/unit-001'

# Run all checks
rcan-validate all myrobot.rcan.yaml
```

## Spec Compliance

Implements [the RCAN protocol](https://rcan.dev/compatibility); run `pytest` for the current test count. See the [live compatibility matrix](https://rcan.dev/compatibility) for the pinned version this SDK targets.

Covered sections: §1 Robot URI · §2 RBAC · §3 Message Format · §5 Authentication · §5.3 QoS · §6 Safety Invariants · §8.3 Replay Prevention · §8.4 Clock Sync · §8.5 Sender Type · §8.6 Key Lifecycle · §8.7 Level of Assurance · §9 Capabilities · §11 Behavior Scripts · §12 Command Delegation · §13 Revocation · §14 Offline Mode · §16 AI Accountability · §17 Distributed Registry · §18 Federation · §19 Constrained Transport · §21 Registry Integration

## Physical assurance (RCAN Appendix C, informative)

`rcan.assurance` ports the reference verifier from
[RCAN Appendix C](https://github.com/RobotRegistryFoundation/rcan-spec/blob/master/spec/appendix-c-physical-assurance.md),
the Physical Assurance Profile. The appendix is informative and these helpers
are optional: nothing in RCAN requires them, and using them changes no
conformance level.

RCAN is one open implementation of the Bounded Embodiment property; the
property and its [vendor-neutral method](https://github.com/RobotRegistryFoundation/bounded-embodiment/blob/main/method/bounded-embodiment-method-v0.1.md)
do not depend on RCAN.

```python
import json
from rcan.assurance import (
    audit_authority, check_envelope_recovery, check_stop_fields,
    replay_against_envelope, verify_chain,
)

chain = json.load(open("gate-decisions.json"))   # list of gate_decision records
envelope = json.load(open("envelope.json"))

findings = [
    *verify_chain(chain, expected_head=None),    # pass an anchored head if you hold one
    *audit_authority(chain, envelope),
    *replay_against_envelope(chain, envelope),
    *check_envelope_recovery(envelope),          # stop.safe_state, recovery.*
    *check_stop_fields(chain),                   # stop_kind, reason_returned
]
for f in findings:
    print(f.seq, f.code, f.detail)
```

What these helpers do and do not tell you:

- **They verify evidence, not robots.** They check that a `gate_decision` log
  is internally consistent, that executed authority-gated commands name a
  principal and an authority, and that applied commands sit inside the declared
  envelope. A passing chain says nothing about whether the machine behaved as
  logged.
- Without an anchored head, `verify_chain` cannot detect records removed from
  the end of a chain. Pass `expected_head` when you hold the last hash from
  somewhere the log writer cannot rewrite.
- `replay_against_envelope` judges only `linear_mps`, `angular_radps` and a 2D
  `target`. Any other applied field is reported as `UNCHECKED_FIELDS`, never
  silently passed.
- `check_envelope_recovery` and `check_stop_fields` check only the optional
  recovery fields from Appendix C.1.3 (`stop.safe_state`, `recovery`,
  `stop_kind`, `reason_returned`) and their conditional rules: `stop_kind`
  only with `stop`, `reason_returned` never with `allow`, `estop_reset` only
  `manual`. They are not a full JSON Schema validation.
- Physical assurance levels BE-1 to BE-3 (`BE_LEVELS`; named A1 to A3 before
  rcan-spec #226, still exported as `ASSURANCE_LEVELS`) are a separate axis
  from RCAN protocol conformance levels L1 to L4. An L3 robot can be BE-1, and
  neither level implies the other. A BE-level is self-declared unless
  third-party evidence accompanies it.

Conformance is not certification.

## Ecosystem

| Package | Purpose |
|---|---|
| **rcan-py** (this) | Python SDK, [PyPI `rcan`](https://pypi.org/project/rcan/) |
| [rcan-ts](https://github.com/RobotRegistryFoundation/rcan-ts) | TypeScript SDK, [npm `rcan-ts`](https://www.npmjs.com/package/rcan-ts) |
| [rcan-spec](https://github.com/RobotRegistryFoundation/rcan-spec) | Protocol spec, published at [rcan.dev](https://rcan.dev) |
| [RCAN docs](https://docs.rcan.dev) | Guides and reference |
| [ROBOT.md](https://robotmd.dev) | Single-file robot manifest |
| [OpenCastor](https://github.com/craigm26/OpenCastor) | Robot runtime, one implementation of RCAN |
| [RRF](https://robotregistryfoundation.org) | Robot identity registry |

Current versions: see the [live compatibility matrix](https://rcan.dev/compatibility).

## Contributing

Issues and PRs welcome at [github.com/RobotRegistryFoundation/rcan-py](https://github.com/RobotRegistryFoundation/rcan-py).

Spec discussions: [github.com/RobotRegistryFoundation/rcan-spec/issues](https://github.com/RobotRegistryFoundation/rcan-spec/issues)

## License

MIT

---

> **Stewarded by the [Robot Registry Foundation](https://github.com/RobotRegistryFoundation).** RCAN is an open standard; issues and PRs welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).
