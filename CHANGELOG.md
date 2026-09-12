## [3.5.0] — 2026-09-12

### Changed

- **Behaviour change (fail direction).** `rcan.federation.validate_cross_registry_command`
  now refuses a cross-registry command whose params carry no `consent_id`
  (or `consent_ref`), returning
  `(False, "Cross-registry command missing consent_id")`. Previously it logged a
  warning and returned `(True, "ok")`, which contradicted the function's own
  documented rule that a local consent record must exist. Callers that relied on
  the application layer enforcing consent after the fact will now see refusals at
  this call instead.
- The P66 stop exemption is now the module-level constant
  `rcan.federation.STOP_VERBS = frozenset({"ESTOP", "E_STOP", "EMERGENCY_STOP", "STOP"})`
  and no longer contains the bare string `SAFETY`. The exemption covers stopping
  verbs only, so a start command (for example a RESUME) carried as a SAFETY-typed
  message can no longer bypass the LoA, source-registry JWT and consent checks.
  The stop path itself is unchanged: ESTOP/E_STOP/EMERGENCY_STOP/STOP remain
  unrefusable, and `STOP` is newly exempt.

### Documentation

- `validate_cross_registry_command`'s docstring now states plainly that the stop
  exemption is also a denial-of-service primitive: a stop verb skips replay
  prevention, LoA, JWT, consent and revocation, so an unauthenticated remote
  message can stop a robot. Availability is not protected by this function.

## [3.4.1] — 2026-05-09

### Fixed

- `rcan.audit_bundle.verify_bundle` now accepts the hybrid (Ed25519 + ML-DSA-65)
  signature shape emitted by the opencastor-ops compliance-bundle aggregator —
  `sig: {"ed25519": b64, "ml_dsa": b64, "ed25519_pub": b64}`. The Ed25519 portion
  is verified inline; full PQC verification of the ml_dsa half remains the job
  of `rcan.hybrid.verify_body` for callers who want both layers. Previously the
  function raised `TypeError: argument should be a bytes-like object or ASCII
  string, not 'dict'` against any real Plan 4/Plan 6 aggregator bundle.

### Changed

- `Signature.alg` is now `str | list[str]` and `Signature.sig` is now
  `str | dict[str, str]`, matching what hybrid bundles already produce.

## [3.4.0] — 2026-05-03

### Added

- `rcan.audit_bundle` — typed Python helpers for the audit-bundle v1.0 envelope
  (locked in rcan-spec `schemas/audit-bundle-v1.json`, Plan 4 Task 1):
  - `AuditBundle.new(rrn=, robot_md_sha256=, artifacts=, ...)` constructs a
    fresh unsigned bundle with a UUID-derived `bundle_id` and ISO-8601
    `signed_at` stamp.
  - `Artifact` + `Signature` dataclasses for the inner nested-signature shape.
  - `verify_bundle(bundle_json, mode=, kid_to_pem=)` returns a typed
    `BundleVerificationResult` with per-artifact + outer-signature verdicts.
    `mode=VerifyMode.STRICT` walks every inner artifact against its registered
    kid; `mode=VerifyMode.AGGREGATOR_TRUST` checks only the outer signature.
  - `kid_to_pem` accepts either a `dict[str, bytes]` or a callable
    `(kid) -> bytes | None` so callers can plug their own resolver (RRF
    lookup, local cache, etc).
  - `hash_robot_md(content)` computes the canonical
    `robot_md_sha256` field used in the bundle header.
- `rcan.encoding.canonical_json(body, *, exclude=None)` — additive `exclude`
  kwarg drops a top-level field before serializing. Used by audit-bundle and
  any nested-signature scheme where the signature must not cover itself. All
  existing callers continue to work unchanged (default `exclude=None`).
  `rcan.audit_bundle.canonical_json` re-exports this — single source of truth
  for cross-language byte parity (the rcan-ts whole-number-float
  normalization landed in 3.3.2 carries through).

### Notes

- No SPEC_VERSION change. SDK_VERSION 3.3.3 → 3.4.0 (minor — new public API).
- `verify_bundle` requires the `[crypto]` extra (`pip install rcan[crypto]`);
  imports are deferred so construction-only callers do not need
  `cryptography`.

## [3.3.3] — 2026-04-28

### Added

- `ManifestInfo.voice: dict[str, Any] | None` — parses the optional `voice:`
  block from rcan-spec v3.3 §8.7. Block carries wake-word aliases beyond
  `name`, BCP-47 spoken language, and an advisory Piper TTS voice id. Robots
  that omit the block work unchanged. The block is held as a raw dict (not a
  dataclass) since the schema is small and may evolve.
- `_validate_voice_block(voice, robot_name)` — soft validation per spec.
  Emits `UserWarning` (never raises) on shape errors, malformed BCP-47,
  alias matching robot name, and aliases that NFKC-collapse to duplicates.
- `_normalize_alias(s)` — wake-word matching pre-image (NFKC + casefold)
  exposed for hosts that adopt the block.

### Notes

- No SPEC_VERSION change. SDK_VERSION 3.3.2 → 3.3.3.
- Wire-format and signing pre-image are unchanged. The `voice:` block does
  NOT participate in any RCAN canonical pre-image, RRN derivation, or
  §22-26 compliance artifact (host-advisory only).

## [3.3.2] — 2026-04-28

### Fixed

- `rcan.encoding.canonical_json` now normalizes whole-number floats to integers
  before serializing (e.g. `50.0` → `50`). Without this, a body containing a
  whole-number float would sign as `{"x":50.0}` in Python but verify against
  `{"x":50}` in rcan-ts (because JS's `JSON.parse` loses the int/float
  distinction at parse time, so `50.0` always parses as `50`). The asymmetry
  caused RRF-side verification of any artifact with whole-number floats to
  fail with HTTP 401 — observed on `safety-benchmark` POST after the rcan-py
  3.3.1 sign↔verify fix landed (RRF issue #71). FRIA / IFU / EU-register
  bodies happened not to contain whole-number floats, so they verified fine.
- New cross-language parity fixture cases in
  `rcan-spec/fixtures/canonical-json-v1.json`: `whole_float_normalized_to_int`,
  `whole_float_negative_and_zero`, `whole_float_large_within_safe_int`,
  `mixed_whole_and_decimal_floats`, `whole_float_in_nested_array_of_dicts`,
  `bool_not_coerced_to_int`. rcan-ts already passes these without code change
  (JS's coercion gives this behavior for free).

### Notes

- Wire-format compatible with 3.3.1 only when the signed body contains no
  whole-number floats. Existing 3.3.1-signed artifacts with whole-floats
  (e.g. bob's pre-3.3.2 `safety-benchmark.json`) must be re-emitted with
  3.3.2. Per memory's runtime-change protocol, RCAN-bearing robots must
  re-emit + re-submit any whole-float-bearing artifact after this bump.
- No SPEC_VERSION change. SDK_VERSION 3.3.1 → 3.3.2.

## [3.3.1] — 2026-04-27

### Fixed

- `rcan.hybrid.sign_body` now strips any pre-existing `sig` key from the body
  before canonicalizing, mirroring `verify_body`'s long-standing behavior.
  Bodies materialized via `dataclasses.asdict()` on a signed-envelope
  dataclass (where `sig: dict` defaults to `{}`) previously produced
  signatures whose canonical bytes included the empty `sig: {}` placeholder,
  while `verify_body` reconstructed the canonical bytes without it. Hashes
  diverged → every such signed artifact failed verification at the registry.
  All robot-md ≥ 1.2.2 callers of FRIA / IFU / safety-benchmark /
  incident-report / EU-register builders were affected.

### Notes

- Wire-format compatible with 3.3.0: a 3.3.0 signature over a body without a
  `sig` placeholder still verifies under 3.3.1 unchanged. Only the
  previously-unverifiable placeholder case becomes verifiable.
- No SPEC_VERSION change. SDK_VERSION 3.3.0 → 3.3.1.
- Existing 3.3.0-signed artifacts with the placeholder pattern will need
  to be re-emitted with 3.3.1 to verify. Per memory's runtime-change
  protocol, RCAN-bearing robots must re-emit + re-submit after this bump.

## [3.3.0] — 2026-04-23

### Added
- `ManifestInfo.agent_runtimes: list[dict] | None` — the normalized `agent.runtimes[]` list from the ROBOT.md frontmatter. Matches rcan-spec v3.2 §8.6 Multi-Runtime Agent Declaration.
- `rcan.manifest._normalize_agent` — normalizes the `agent:` block. Structured `runtimes[]` returned as-is. Flat `agent.provider`/`agent.model` form is auto-wrapped into a single-entry `runtimes[]` with `default: true` and emits `DeprecationWarning`. Mixed-form (both flat AND runtimes[]) raises `ValueError`.
- `rcan.manifest._validate_agent_runtimes` — enforces required `id` + `harness`, and exactly-one-default when multiple entries are declared.

### Changed
- `SPEC_VERSION`: `"3.1"` → `"3.2"`
- `SDK_VERSION` / package version: `"3.2.0"` → `"3.3.0"`
- `from_manifest()` now validates the `agent:` block; invalid `runtimes[]` (missing id/harness or wrong number of defaults) raises `ValueError`.

### Deprecated
- Flat `agent.provider` / `agent.model` form in ROBOT.md frontmatter. Still valid in v3.2 with a `DeprecationWarning`; scheduled for removal in rcan-spec v4.0.

### Unchanged
- §22–§26 compliance builders (`build_fria`, `build_safety_benchmark`, `build_ifu`, `build_incident_report`, `build_eu_register_entry`)
- Canonical JSON + ML-DSA-65 hybrid signing (`rcan.canonical`, `rcan.crypto`)
- `tests/fixtures/compliance-v1.json` byte parity (no regeneration this release)

## [3.2.0] — 2026-04-24

### Changed (breaking for §26 callers)

- `build_eu_register_entry` now requires `rmn: str` as a keyword argument.
  rcan-spec v3.1 adds a required top-level `rmn` field to the
  `rcan-eu-register-v1` envelope so Art. 49 registrations can be routed
  per-model. `system.rrn` remains for per-submission provenance. This is
  a breaking change to §26 per rcan-spec MINOR versioning; §26 was
  introduced in v3.0 13 days ago as Experimental tier with zero
  production consumers at bump time.
- `EuRegisterEntry` dataclass unchanged (it was a summary record, not the
  builder envelope).
- `SPEC_VERSION` → `"3.1"`.
- Byte-parity: rcan-eu-register-v1 envelopes built with this version
  differ byte-for-byte from 3.1.1 envelopes. The rcan-spec
  `compliance-v1.json` fixture is regenerated against 3.2.0.

### Cross-language coordination

- rcan-ts 3.3.0 (to follow) will match this envelope shape and verify
  byte-parity against the regenerated rcan-spec fixture.
- RRF D3 will consume rcan-ts 3.3.0 to expose
  `/v2/models/:rmn/eu-register`.

---

## [3.1.1] — 2026-04-23

### Fixed (breaking for direct 3.1.0 callers — zero known consumers)

- `build_safety_benchmark`, `build_ifu`, `build_incident_report`, and
  `build_eu_register_entry` now emit envelope shapes matching robot-md's
  actual production artifact format. 3.1.0's minimal shapes did not align
  with downstream consumers. Because 3.1.0 was published <24h ago and had
  no adopters, this correction is released as a patch rather than a minor
  bump. Any direct 3.1.0 caller must update kwargs — no compatibility shim.

### Changed

- `rcan.compliance` exports spec-domain constants: `ART13_COVERAGE`,
  `VALID_SEVERITIES`, `REPORTING_DEADLINES`, `ART72_NOTE`,
  `CONFORMITY_STATUS_DECLARED`, `SUBMISSION_INSTRUCTIONS`. Re-exported
  from `rcan` top-level.
- `build_safety_benchmark` signature:
  `(*, iterations, thresholds, results, mode, generated_at, overall_pass)`.
- `build_ifu` signature: 8 Art. 13(3) section kwargs + `generated_at`.
  Auto-emits `art13_coverage`.
- `build_incident_report` signature: `(*, rrn, incidents, generated_at)`.
  Auto-computes `total_incidents` and `incidents_by_severity`.
- `build_eu_register_entry` signature:
  `(*, fria_ref, provider, system, annex_iii_basis, generated_at,
  conformity_status=..., submission_instructions=...)`.

---

## [3.1.0] — 2026-04-23

### Added

- **`rcan.encoding.canonical_json(body)`** — deterministic UTF-8 bytes of
  `json.dumps(body, sort_keys=True, separators=(",",":"), ensure_ascii=False)`.
  The byte-parity invariants are pinned by the shared
  `rcan-spec/fixtures/canonical-json-v1.json` fixture.
- **`rcan.hybrid.sign_body(keypair, body, *, ed25519_secret, ed25519_public)`**
  and **`rcan.hybrid.verify_body(signed, pq_signing_pub)`** — dict-level
  wrappers around the low-level ML-DSA-65 + Ed25519 hybrid primitives in
  `rcan.crypto`. Wire format matches RobotRegistryFoundation's
  `/v2/*/register` endpoints.
- **Four compliance artifact builders** in `rcan.compliance`:
  `build_safety_benchmark` (§23), `build_ifu` (§24),
  `build_incident_report` (§25), `build_eu_register_entry` (§26). All
  additive; existing dataclasses untouched.
- **Top-level re-exports** in `rcan.__init__`: `from rcan import
  canonical_json, sign_body, verify_body, build_*` all work.

### Why

Ecosystem audit (2026-04-23) found robot-md 1.0.0 and
RobotRegistryFoundation 1.10.0 had reimplemented canonical JSON, hybrid
body signing, and the §22-26 envelope shapes locally — violating the
"fix upstream first, no shims in downstream consumers" rule. 3.1.0 pulls
all of it into the SDK.

### Non-breaking

All 3.0.x exports remain unchanged. `rcan/signing.py`'s v2.2-era
message PKI module is untouched (its wrong-doctrine "Ed25519 deprecated"
docstring is a future-release cleanup).

### Downstream cleanup

- `robot-md 1.0.1` (same release cycle) deletes local
  `canonical_json`/`sign_body`/`verify_body` in `signing.py` and the
  four local `build_*` functions, importing from `rcan` instead.
- `rcan-ts 3.1.0` (same release cycle) ships the mirror API surface
  (no compliance builders — YAGNI).
- `RobotRegistryFoundation` (same cycle) swaps
  `functions/_lib/verify.ts` for imports from `rcan-ts`.

---

## [3.0.1] — 2026-04-23

### Fixed

- `rcan.__version__` now returns `"3.0.1"` to match the package version.
  The 3.0.0 release shipped with `__version__ = "2.1.0"` in
  `rcan/__init__.py` — cosmetic but confusing for downstream tooling
  that reads the SDK version at runtime (e.g. robot-md's dependency
  audit). No API change, no behavior change.

---

## [3.0.0] — 2026-04-21

### Added
- Bumped SDK to v3.0.0 to officially align with the RCAN Spec v3.0 release.
- Added implementation for EU AI Act compliance schemas: §23–§26.

---

## [2.1.0] — 2026-04-18
### Added

- **`rcan.from_manifest(path)`** — cross-link to the ROBOT.md file format.
  Reads a `ROBOT.md` manifest and returns a `ManifestInfo` with rrn,
  rcan_uri, endpoint (`network.rrf_endpoint`), signing_alg, public
  resolver URL, robot_name, rcan_version, and the raw frontmatter.
  Lets operators go from a manifest on disk to a preconfigured
  `RegistryClient` without hand-copying identity fields:

  ```python
  from rcan import from_manifest
  from rcan.registry import RegistryClient

  info = from_manifest("./ROBOT.md")
  async with RegistryClient(base_url=info.endpoint) as rc:
      robot = await rc.get_robot(info.rrn)
  ```
- **Optional extra `rcan[manifest]`** — installs `pyyaml` for manifest
  parsing. Without the extra, `from_manifest` raises `ImportError` with
  a helpful message.

See <https://robotmd.dev> for the ROBOT.md spec.

---

## [2.0.0] — 2026-04-12

### Breaking Changes
- `REGISTRY_REGISTER` payload now requires `fria_ref` (RCAN v3.0 §21.3). Use the new `make_registry_register()` helper which enforces this field.
- `SPEC_VERSION` updated from `"2.2.1"` to `"3.0"`.
- `__version__` updated from `"1.4.0"` to `"2.0.0"`.

### Added
- `rcan.compliance` module: `FriaDocument`, `FriaSigningKey`, `FriaConformance`, `SafetyBenchmark`, `InstructionsForUse`, `PostMarketIncident`, `EuRegisterEntry` — compliance dataclasses for RCAN v3.0 §22–§26.
- `RegistryRegisterPayload` TypedDict — typed constructor for REGISTRY_REGISTER payloads.
- `make_registry_register()` — builder function for REGISTRY_REGISTER messages.
- New feature flags in `SUPPORTED_FEATURES`: `FRIA_COMPLIANCE`, `SAFETY_BENCHMARK`, `INSTRUCTIONS_FOR_USE`, `POST_MARKET_MONITORING`, `EU_REGISTER`.

---

## [1.4.0] — 2026-04-10

### Added
- `rcan/watermark.py` — AI output watermark module (RCAN §16.5): `compute_watermark_token()`, `verify_token_format()`, `verify_via_api()`. Mirrors the OpenCastor runtime implementation for SDK consumers that hold the robot's ML-DSA-65 private key; `verify_via_api` calls the robot's public `GET /api/v1/watermark/verify` endpoint
- `compute_watermark_token`, `verify_token_format`, `verify_via_api` exported from `rcan.__init__` and listed in `__all__`

### Tests
- `tests/test_watermark.py` — 12 tests: compute determinism/sensitivity, format validation, async API mock (200/404), `httpx` ImportError path

---

## [1.3.0] — 2026-03-31

### Added
- `rcan/crypto.py` — ML-DSA-65 post-quantum signing primitives (`MlDsaKeyPair`, `HybridSignature`, `generate_ml_dsa_keypair`, `sign_hybrid`, `verify_hybrid`, `encode_public_key_jwk`)
- `RobotURI.sign_pqc()` / `verify_sig_pqc()` — pqc-hybrid-v1 RURI signing
- `sign_m2m_pqc()` / `verify_m2m_pqc()` — PQC M2M token signing
- Implements RCAN spec v2.3 pqc-hybrid-v1 profile (NIST FIPS 204 ML-DSA-65)

# Changelog

All notable changes to rcan-py are documented here.

---

## [1.2.2] - 2026-03-28

### Changed
- `SPEC_VERSION` updated to `2.2.1`
- `SDK_VERSION` bumped to `1.2.2`
- `SUPPORTED_FEATURES`: added `MULTI_TYPE_ENTITY_NUMBERING` (§21.2.2)

Closes #44.


## [0.6.0] — 2026-03-16

### Added — RCAN v1.6 support (4 gaps closed)

#### Federation & Identity
- **GAP-16** `rcan.federation`: `RegistryTier` enum (root/authoritative/community), `FederationSyncType` enum (consent/revocation/key), `RegistryIdentity` dataclass, `FederationSyncPayload` dataclass. `TrustAnchorCache` with 24-hour TTL — `lookup()`, `discover_via_dns()` (reads `_rcan-registry.<domain>` TXT), `verify_registry_jwt()` (issuer/expiry/Ed25519 check). `make_federation_sync()` builder. `validate_cross_registry_command()` — enforces LoA ≥ 2 and trust cache check; ESTOP always allowed (P66 invariant). New `MessageType.FEDERATION_SYNC = 33`.
- **GAP-14** `rcan.identity`: `LevelOfAssurance` IntEnum (ANONYMOUS=1, EMAIL_VERIFIED=2, HARDWARE_TOKEN=3). `IdentityRecord` dataclass. `extract_loa_from_jwt()` — JWT payload parsing without verification, graceful fallback to ANONYMOUS. `validate_loa_for_scope()` — scope-based LoA gating with configurable `min_loa_overrides` and `LoaPolicy`. `DEFAULT_LOA_POLICY` (all LoA=1, backward compatible). `PRODUCTION_LOA_POLICY` (control≥2, safety≥3). New `loa: Optional[int]` field on `RCANMessage`.

#### Constrained Transport
- **GAP-17** `rcan.transport`: `TransportEncoding` enum (HTTP/COMPACT/MINIMAL/BLE). `encode_compact()` / `decode_compact()` — msgpack (if available) or compact JSON with abbreviated field names. `encode_minimal()` / `decode_minimal()` — 32-byte ESTOP-only binary format with from/to RRN hashes, HMAC-SHA256 truncated signature, XOR checksum. `encode_ble_frame()` / `decode_ble_frames()` — MTU-fragmented BLE frames with stream reassembly. `select_transport()` — safety messages prefer MINIMAL > COMPACT > BLE > HTTP. New `transport_encoding: Optional[str]` field on `RCANMessage`.

#### Multi-Modal Payloads
- **GAP-18** `rcan.multimodal`: `MediaEncoding` enum (BASE64/REF). `MediaChunk` dataclass. `add_media_inline()` — inline media with SHA-256 integrity, 64 KB size limit (`MediaSizeError`). `add_media_ref()` — external media reference. `validate_media_chunks()` — inline hash recomputation, ref hash format check. `make_training_data_message()` — TRAINING_DATA message with inline media. `StreamChunk` dataclass. `make_stream_chunk()` — incremental media stream helper. New `media_chunks: list` field on `RCANMessage`. New `MessageType.TRAINING_DATA = 34`, `MessageType.STREAM_CHUNK = 35`.

### Changed
- `rcan.version`: `SPEC_VERSION = "1.6"`, `SDK_VERSION = "0.6.0"`. Added v1.6 feature flags: `FEDERATED_CONSENT`, `CONSTRAINED_TRANSPORT`, `MULTIMODAL_PAYLOADS`, `IDENTITY_LOA`.
- `rcan.message.RCANMessage`: added `media_chunks`, `loa`, `transport_encoding` fields. Updated `to_dict()`/`from_dict()` serialization.
- `rcan.exceptions`: added `FederationError`, `IdentityError`.

### Breaking Changes
- None. All existing tests pass. New fields on `RCANMessage` are optional with safe defaults.

---

## [0.5.0] — 2026-03-16

### Added — RCAN v1.5 support (18 gaps closed)

#### Security & Safety
- **GAP-03** `rcan.replay`: `ReplayCache` with sliding-window seen-set; `validate_replay()`. Safety messages enforce 10s max window. Prevents replay attacks before signature verification.
- **GAP-04** `rcan.clock`: `ClockSyncStatus`, `check_clock_sync()`, `assert_clock_synced()`. NTP sync check via systemd-timesyncd, timedatectl, chronyc, or pool.ntp.org. Raises `ClockDriftError` if clock is unsynchronized.
- **GAP-09** `rcan.keys`: `KeyStore` with JWKS-compatible key history, `make_key_rotation_message()`. New `MessageType.KEY_ROTATION = 27`.
- **GAP-12** `rcan.version`: `SPEC_VERSION = "1.5"` as single source of truth. `validate_version_compat()` with MAJOR version enforcement. Registry now imports from `version.py`.

#### Robot Identity & Trust
- **GAP-01** `rcan.delegation`: `DelegationHop`, `add_delegation_hop()`, `validate_delegation_chain()`. Max 4 hops with Ed25519 per-hop signing.
- **GAP-02** `rcan.revocation`: `RevocationStatus`, `RevocationCache` (1h TTL), `check_revocation()`, `make_revocation_broadcast()`. New `MessageType.ROBOT_REVOCATION = 19`.
- **GAP-08** `rcan.message`: `SenderType` enum (robot/human/cloud_function/system). New `sender_type`, `cloud_provider` fields on `RCANMessage`. `make_cloud_relay_message()` helper.

#### Consent & Compliance
- **GAP-05** `rcan.consent`: `ConsentRequestPayload`, `ConsentGrantPayload`, `ConsentDenyPayload`, `make_consent_request/grant/deny()`, `validate_consent_message()`. `MessageType.CONSENT_REQUEST=20`, `CONSENT_GRANT=21`, `CONSENT_DENY=22`.
- **GAP-10** `rcan.training_consent`: `DataCategory` enum (VIDEO/AUDIO/LOCATION/BIOMETRIC/TELEMETRY), `TrainingConsentRequest`, `make_training_consent_request/grant/deny()`. EU AI Act Annex III §5 compliance. `MessageType.TRAINING_CONSENT_REQUEST=30/31/32`.

#### Reliability & Operations
- **GAP-06** `rcan.offline`: `OfflineModeManager`, `OfflineStatus`. Offline mode with cross-owner grace period. ESTOP always allowed (P66 invariant). New principals blocked.
- **GAP-07** `rcan.config_update`: `ConfigUpdateMessage`, `make_config_update()`, `validate_config_update()`. Safety fields require `scope='creator'`. SHA-256 config hash verification.
- **GAP-11** `rcan.qos`: `QoSLevel` (FIRE_AND_FORGET/ACKNOWLEDGED/EXACTLY_ONCE), `QoSManager` with retry + exponential backoff, `make_estop_with_qos()`. ESTOP ACK timeout triggers `SafetyHaltError`. New `MessageType.COMMAND_ACK=17`, `COMMAND_NACK=28`, `COMMAND_COMMIT=29`.

#### Fleet & Observability
- **GAP-13** Fleet broadcast: `group_id: Optional[str]` on `RCANMessage`. `MessageType.FLEET_COMMAND=23`.
- **GAP-15** Observer mode: `read_only: bool` field on `RCANMessage`. `MessageType.SUBSCRIBE=24`, `UNSUBSCRIBE=25`.
- **GAP-19** Physical presence: `presence_verified: bool`, `proximity_m: Optional[float]` on `RCANMessage`.
- **GAP-20** `rcan.fault`: `FaultCode` enum (25 standard codes), `FaultReport`, `make_fault_report()`. `MessageType.FAULT_REPORT=26`.

### Changed
- `SPEC_VERSION` = `"1.5"` (`rcan/version.py` is now single source of truth)
- `__version__` = `"0.5.0"`
- `rcan/registry.py` imports `SPEC_VERSION` from `rcan/version.py` (was hardcoded `"1.2"`)
- `rcan/validate.py` `_CURRENT_SPEC_VERSION` now imports from `rcan/version.py`
- `RCANMessage.from_dict()` validates version compatibility before any other check (GAP-12)
- All new `RCANMessage` fields are optional with sane defaults — fully backward compatible

### New Exceptions
`VersionIncompatibleError`, `ReplayAttackError`, `ClockDriftError`, `DelegationChainExceededError`, `DelegationVerificationError`, `QoSAckTimeoutError`, `SafetyHaltError`, `ConfigAuthorizationError`, `ConfigHashMismatchError`, `RevocationError`, `ConsentError`

### Tests
430 tests (was 287) — +143 new tests covering all v1.5 modules.

---

## [0.4.0] — 2026-03-13

### Changed
- `SPEC_VERSION` = `"1.4"`, `__spec_version__` = `"1.4"` — tracks RCAN v1.4 stable release
- Package version `0.3.1` → `0.4.0` (minor bump for spec version milestone)

### Added
- `rcan-validate --version` now reports `rcan-py 0.4.0 / spec 1.4`

---

## [0.3.1] — 2026-03-13

### Changed
- `SPEC_VERSION` updated to `"1.3"` (was `"1.2"`) — tracks RCAN v1.3 stable release (§21 Registry Integration, L4 conformance)
- `rcan/__init__.py`, `rcan/message.py`: `SPEC_VERSION` and `__spec_version__` = `"1.3"`

---

## [0.3.0] — 2026-03-06

### Added
- `rcan-validate --version` — prints version and spec compatibility
- `rcan-validate robot <rrn>` — validate live robot record from registry via NodeClient
- `rcan-validate config --strict` — treat warnings as errors, require canonical schema
- `rcan-validate node <url>` — validate node manifest from rcan.dev or any registry node
- `rcan-validate config --watch` — live re-validation on file changes (1s polling)
- Canonical JSON schema validation with 24h local cache (`~/.cache/rcan/schemas/`)
- `SPEC_VERSION = "1.2"` exported from `rcan` package
- RRN address space expansion: sequences 8→8-16 digits, prefix `[A-Z0-9]{2,8}` (backward compatible)
- mypy CI integration with `mypy.ini`

### Changed
- `rcan-validate config` now fetches canonical schema from rcan.dev by default (use `--no-schema` to skip)

## [0.2.0] — 2026-03-06
### Features
- `RegistryClient` — full async/sync CRUD for rcan.dev API (register, get, list, search, patch, delete)
- `RegistryClient.search()` — filter by manufacturer, model, or tier
- Exception hierarchy: `RCANError`, `RCANNotFoundError`, `RCANAuthError`, `RCANValidationError`, `RCANNetworkError`
- `TypedDicts` for config/message shapes (RCANConfig, RCANMetadata, RCANMessageEnvelope)
- Config validation hardening — required fields, version format, --json output
- Audit chain verification — HMAC chain integrity, --secret flag
- Async context manager support with proper session cleanup
- `py.typed` marker for mypy compatibility
- `__all__` exports from rcan package root
### CI
- Pre-commit hook: `.pre-commit-hooks.yaml`
- GitHub Action: `continuonai/rcan-py/.github/actions/validate-rcan@main`
- pyyaml added to dev dependencies

---

## [0.1.1] — 2026-03-06
### Features
- TypedDicts: RCANConfig, RCANMetadata, RCANAgentConfig, RCANMessageEnvelope in rcan/types.py
- Config validation hardening: required keys, rcan_version format, device_id check

---

## [0.1.0] — 2026-03-05
### Initial Release
- `RobotURI` — parse/build RCAN URIs
- `RCANMessage` — signed message envelope
- `ConfidenceGate`, `HiTLGate` — runtime safety gates
- `CommitmentRecord`, `AuditChain` — HMAC-chained audit ledger
- `RegistryClient` — async/sync rcan.dev API client
- Exception hierarchy: RCANError and subclasses
- `rcan-validate` CLI: message, config, audit, uri, all subcommands
- `py.typed` marker for mypy compatibility

## v1.2.1 (2026-03-27)

### Breaking Changes
- **Ed25519 fully removed** — `KeyPair` class raises `DeprecationWarning` and redirects to `MLDSAKeyPair`
- **`pq_sig` field removed** from wire format — `signature` field is now the sole ML-DSA-65 block
- **`sign_message()` simplified** — takes `(msg, mldsa_keypair)`, no `pq_keypair` kwarg
- **`verify_message()` simplified** — takes `(msg, trusted: list[MLDSAKeyPair])`, no `require_pq` kwarg

### Summary
Clean ML-DSA-65-only release. Bob (RRN-000000000001) is the first robot running this stack.
Q-Day timeline: ML-DSA-65 primary NOW (2026), Ed25519 sunset 2027, NIST deadline 2029.
