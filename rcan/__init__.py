"""
rcan — Official Python SDK for the RCAN Robot Communication Protocol.

RCAN (Robot Communication and Addressing Network) is an open protocol for
robot networking built from safety requirements outward. This SDK provides
Python bindings for building RCAN-compliant robot systems.

Spec: https://rcan.dev/spec
Docs: https://rcan.dev/docs

Quick start:
    from rcan import RobotURI, RCANMessage, ConfidenceGate

    uri = RobotURI.parse("rcan://registry.rcan.dev/acme/arm/v1/unit-001")
    gate = ConfidenceGate(threshold=0.8)

    if gate.check(confidence=0.91):
        msg = RCANMessage(
            cmd="move_forward",
            target=uri,
            params={"distance_m": 1.0},
            confidence=0.91,
        )
        print(msg.to_json())
"""

# v1.6 modules — Federated Consent (GAP-16)
# v1.6 modules — Constrained Transports (GAP-17)
# v1.6 modules — Multi-Modal Payloads (GAP-18)
# v1.10 modules — Competition Protocol
# v1.6 modules — Human Identity Verification (GAP-14)
# v2.1 modules
from rcan import (
    competition,
    federation,
    firmware,
    identity,
    m2m,
    multimodal,
    sbom,
    transport,
)
# v3.0 — Compliance schemas (§22–§26)
from rcan.compliance import (
    EuRegisterEntry,
    FriaConformance,
    FriaDocument,
    FriaSigningKey,
    InstructionsForUse,
    PostMarketIncident,
    SafetyBenchmark,
)

# v3.1 — consolidation: dict-level hybrid signing + canonical JSON +
# compliance artifact builders. See CHANGELOG [3.1.0] for rationale.
from rcan.compliance import (
    ART13_COVERAGE,
    ART72_NOTE,
    CONFORMITY_STATUS_DECLARED,
    REPORTING_DEADLINES,
    SUBMISSION_INSTRUCTIONS,
    VALID_SEVERITIES,
    build_eu_register_entry,
    build_ifu,
    build_incident_report,
    build_safety_benchmark,
)
from rcan.encoding import canonical_json
from rcan.hybrid import sign_body, verify_body

from rcan.address import RobotURI
from rcan.manifest import ManifestInfo, from_manifest
from rcan.audit import CommitmentRecord

# v1.5 modules — Clock Synchronization (GAP-04)
from rcan.clock import ClockSyncStatus, assert_clock_synced, check_clock_sync
from rcan.competition import (
    COMPETITION_SCOPE_LEVEL,
    CompetitionBadge,
    CompetitionEnter,
    CompetitionError,
    CompetitionFormat,
    CompetitionScore,
    PersonalResearchResult,
    RunType,
    SeasonStanding,
    validate_competition_scope,
)

# v1.5 modules — Config Update (GAP-07)
from rcan.config_update import (
    ConfigUpdateMessage,
    make_config_update,
    validate_config_update,
)

# v1.5 modules — Consent Wire Protocol (GAP-05)
from rcan.consent import (
    ConsentDenyPayload,
    ConsentGrantPayload,
    ConsentRequestPayload,
    make_consent_deny,
    make_consent_grant,
    make_consent_request,
    validate_consent_message,
)

# v1.5 modules — Command Delegation Chain (GAP-01)
from rcan.delegation import (
    DelegationHop,
    add_delegation_hop,
    validate_delegation_chain,
)

# v2.2 envelope types
from rcan.envelope import (
    DelegationHop as EnvelopeDelegationHop,
)
from rcan.envelope import (
    MediaChunk as EnvelopeMediaChunk,
)
from rcan.exceptions import (
    ClockDriftError,
    ConfigAuthorizationError,
    ConfigHashMismatchError,
    ConsentError,
    DelegationChainExceededError,
    DelegationVerificationError,
    # v1.6 exceptions
    FederationError,
    IdentityError,
    QoSAckTimeoutError,
    RCANAddressError,
    RCANError,
    RCANGateError,
    RCANNodeError,
    RCANRegistryError,
    RCANSignatureError,
    RCANTimeoutError,
    RCANValidationError,
    ReplayAttackError,
    RevocationError,
    SafetyHaltError,
    # v1.5 exceptions
    VersionIncompatibleError,
)

# v1.5 modules — Fault Reporting (GAP-20)
from rcan.fault import FaultCode, FaultReport, make_fault_report
from rcan.federation import (
    FederationSyncPayload,
    FederationSyncType,
    RegistryIdentity,
    RegistryTier,
    TrustAnchorCache,
    make_federation_sync,
    validate_cross_registry_command,
)
from rcan.firmware import (
    FirmwareComponent,
    FirmwareIntegrityError,
    FirmwareManifest,
    firmware_hash_from_manifest,
    sign_manifest,
    verify_manifest,
)
from rcan.gates import ConfidenceGate, GateResult, HiTLGate
from rcan.identity import (
    DEFAULT_LOA_POLICY,
    PRODUCTION_LOA_POLICY,
    ROLE_TO_JWT_LEVEL,
    SCOPE_MIN_ROLE,
    IdentityRecord,
    LevelOfAssurance,  # backward-compat alias for Role
    LoaPolicy,
    Role,
    extract_identity_from_jwt,
    extract_loa_from_jwt,  # backward-compat alias
    extract_role_from_jwt,
    role_from_jwt_level,
    validate_loa_for_scope,
    validate_role_for_scope,
)

# v1.5 modules — Key Rotation (GAP-09)
from rcan.keys import KeyRotationMessage, KeyStore, make_key_rotation_message
from rcan.m2m import (
    M2MAuthError,
    M2MPeerClaims,
    M2MTrustedClaims,
    RRFRevocationPoller,
    parse_m2m_peer_token,
    verify_m2m_trusted_token,
    sign_m2m_pqc,
    verify_m2m_pqc,
)
from rcan.message import (
    MessageType,
    RCANMessage,
    RCANResponse,
    SenderType,
    make_cloud_relay_message,
    make_registry_register,
    RegistryRegisterPayload,
    validate_version_compat,
)
from rcan.multimodal import (
    MediaChunk,
    MediaEncoding,
    MediaSizeError,
    StreamChunk,
    add_media_inline,
    add_media_ref,
    make_stream_chunk,
    make_training_data_message,
    validate_media_chunks,
)
from rcan.node import NodeClient

# v1.5 modules — Offline Operation Mode (GAP-06)
from rcan.offline import OfflineModeManager, OfflineStatus

# v1.5 modules — QoS / Delivery Guarantees (GAP-11)
from rcan.qos import QoSLevel, QoSManager, make_estop_with_qos

# v1.5 modules — Replay Prevention (GAP-03)
from rcan.replay import ReplayCache, validate_replay

# v1.5 modules — Robot Identity Revocation (GAP-02)
from rcan.revocation import (
    RevocationCache,
    RevocationStatus,
    check_revocation,
    make_revocation_broadcast,
)
from rcan.sbom import (
    RCANBOM,
    RCANSBOMExtensions,
    SBOMComponent,
)

# v1.5 modules — Training Data Consent (GAP-10)
from rcan.training_consent import (
    DataCategory,
    TrainingConsentRequest,
    make_training_consent_deny,
    make_training_consent_grant,
    make_training_consent_request,
)
from rcan.transport import (
    TransportEncoding,
    TransportError,
    TransportNegotiation,
    decode_ble_frames,
    decode_compact,
    decode_minimal,
    encode_ble_frame,
    encode_compact,
    encode_minimal,
    select_transport,
)
from rcan.types import RCANAgentConfig, RCANConfig, RCANMessageEnvelope, RCANMetadata
from rcan.version import SPEC_VERSION, SUPPORTED_FEATURES
from rcan.watermark import compute_watermark_token, verify_token_format, verify_via_api

__version__ = "3.5.0"
__spec_version__ = "3.2"

__all__ = [
    # Address
    "RobotURI",
    # ROBOT.md cross-link (optional extra: `rcan[manifest]`)
    "from_manifest",
    "ManifestInfo",
    # Message
    "RCANMessage",
    "RCANResponse",
    "MessageType",
    "SenderType",
    "make_cloud_relay_message",
    "validate_version_compat",
    # v3.0 — Compliance schemas
    "FriaSigningKey",
    "FriaConformance",
    "FriaDocument",
    "SafetyBenchmark",
    "InstructionsForUse",
    "PostMarketIncident",
    "EuRegisterEntry",
    "RegistryRegisterPayload",
    "make_registry_register",
    # v3.1 — Consolidation API: builders + hybrid signing + canonical JSON
    "build_safety_benchmark",
    "build_ifu",
    "build_incident_report",
    "build_eu_register_entry",
    "canonical_json",
    "sign_body",
    "verify_body",
    # v3.1 spec-domain constants
    "ART13_COVERAGE",
    "VALID_SEVERITIES",
    "REPORTING_DEADLINES",
    "ART72_NOTE",
    "CONFORMITY_STATUS_DECLARED",
    "SUBMISSION_INSTRUCTIONS",
    # Audit
    "CommitmentRecord",
    # Gates
    "ConfidenceGate",
    "HiTLGate",
    "GateResult",
    # Exceptions — original
    "RCANError",
    "RCANAddressError",
    "RCANGateError",
    "RCANNodeError",
    "RCANRegistryError",
    "RCANSignatureError",
    "RCANTimeoutError",
    "RCANValidationError",
    # Exceptions — v1.5
    "VersionIncompatibleError",
    "ReplayAttackError",
    "ClockDriftError",
    "DelegationChainExceededError",
    "DelegationVerificationError",
    "QoSAckTimeoutError",
    "SafetyHaltError",
    "ConfigAuthorizationError",
    "ConfigHashMismatchError",
    "RevocationError",
    "ConsentError",
    # Node federation
    "NodeClient",
    # Types
    "RCANConfig",
    "RCANMetadata",
    "RCANAgentConfig",
    "RCANMessageEnvelope",
    # Version
    "__version__",
    "SPEC_VERSION",
    "SUPPORTED_FEATURES",
    # v1.5 — Replay Prevention (GAP-03)
    "ReplayCache",
    "validate_replay",
    # v1.5 — Clock Sync (GAP-04)
    "ClockSyncStatus",
    "check_clock_sync",
    "assert_clock_synced",
    # v1.5 — QoS (GAP-11)
    "QoSLevel",
    "QoSManager",
    "make_estop_with_qos",
    # v1.5 — Config Update (GAP-07)
    "ConfigUpdateMessage",
    "make_config_update",
    "validate_config_update",
    # v1.5 — Key Rotation (GAP-09)
    "KeyRotationMessage",
    "KeyStore",
    "make_key_rotation_message",
    # v1.5 — Consent Wire Protocol (GAP-05)
    "ConsentRequestPayload",
    "ConsentGrantPayload",
    "ConsentDenyPayload",
    "make_consent_request",
    "make_consent_grant",
    "make_consent_deny",
    "validate_consent_message",
    # v1.5 — Robot Identity Revocation (GAP-02)
    "RevocationStatus",
    "RevocationCache",
    "check_revocation",
    "make_revocation_broadcast",
    # v1.5 — Training Data Consent (GAP-10)
    "DataCategory",
    "TrainingConsentRequest",
    "make_training_consent_request",
    "make_training_consent_grant",
    "make_training_consent_deny",
    # v1.5 — Command Delegation Chain (GAP-01)
    "DelegationHop",
    "add_delegation_hop",
    "validate_delegation_chain",
    # v1.5 — Offline Operation Mode (GAP-06)
    "OfflineModeManager",
    "OfflineStatus",
    # v1.5 — Fault Reporting (GAP-20)
    "FaultCode",
    "FaultReport",
    "make_fault_report",
    # v1.6 — Federated Consent (GAP-16)
    "federation",
    "RegistryTier",
    "FederationSyncType",
    "RegistryIdentity",
    "FederationSyncPayload",
    "TrustAnchorCache",
    "make_federation_sync",
    "validate_cross_registry_command",
    # v1.6 — Constrained Transports (GAP-17)
    "transport",
    "TransportEncoding",
    "TransportNegotiation",
    "TransportError",
    "encode_compact",
    "decode_compact",
    "encode_minimal",
    "decode_minimal",
    "encode_ble_frame",
    "decode_ble_frames",
    "select_transport",
    # v1.6 — Multi-Modal Payloads (GAP-18)
    "multimodal",
    "MediaEncoding",
    "MediaChunk",
    "StreamChunk",
    "MediaSizeError",
    "add_media_inline",
    "add_media_ref",
    "validate_media_chunks",
    "make_training_data_message",
    "make_stream_chunk",
    # v1.6 — Human Identity Verification (GAP-14) / v2.1 RBAC
    "identity",
    "Role",
    "LevelOfAssurance",
    "ROLE_TO_JWT_LEVEL",
    "role_from_jwt_level",
    "SCOPE_MIN_ROLE",
    "IdentityRecord",
    "LoaPolicy",
    "DEFAULT_LOA_POLICY",
    "PRODUCTION_LOA_POLICY",
    "extract_role_from_jwt",
    "extract_loa_from_jwt",
    "extract_identity_from_jwt",
    "validate_role_for_scope",
    "validate_loa_for_scope",
    # v2.2 — Envelope types
    "EnvelopeDelegationHop",
    "EnvelopeMediaChunk",
    # v2.1 — Firmware Manifests
    "firmware",
    "FirmwareManifest",
    "FirmwareComponent",
    "FirmwareIntegrityError",
    "sign_manifest",
    "verify_manifest",
    "firmware_hash_from_manifest",
    # v2.1 — SBOM
    "sbom",
    "RCANBOM",
    "SBOMComponent",
    "RCANSBOMExtensions",
    # v2.1 — M2M Authorization
    "m2m",
    "M2MPeerClaims",
    "M2MTrustedClaims",
    "M2MAuthError",
    "parse_m2m_peer_token",
    "verify_m2m_trusted_token",
    "RRFRevocationPoller",
    # v1.10 — Competition Protocol
    "competition",
    "COMPETITION_SCOPE_LEVEL",
    "CompetitionBadge",
    "CompetitionEnter",
    "CompetitionError",
    "CompetitionFormat",
    "CompetitionScore",
    "PersonalResearchResult",
    "RunType",
    "SeasonStanding",
    "validate_competition_scope",
    # v1.6 exceptions
    "FederationError",
    "IdentityError",
    # Sub-modules (imported explicitly)
    # rcan.registry — RegistryClient (requires rcan[http])
    # rcan.signing  — KeyPair, MLDSAKeyPair, sign_message, verify_message (requires rcan[crypto]; dilithium-py for ML-DSA)
    # rcan.audit    — AuditChain
    # v2.2 — PQC crypto primitives (issue #47)
    "MlDsaKeyPair",
    "HybridSignature",
    "generate_ml_dsa_keypair",
    "sign_ml_dsa",
    "verify_ml_dsa",
    "sign_hybrid",
    "verify_hybrid",
    "encode_public_key_jwk",
    "decode_public_key_jwk",
    "ML_DSA_ALG",
    "HYBRID_ALG",
    # v2.2 — M2M PQC helpers
    "sign_m2m_pqc",
    "verify_m2m_pqc",
    # Watermark
    "compute_watermark_token",
    "verify_token_format",
    "verify_via_api",
]

from .mcp import LOA_TO_SCOPE, TOOL_LOA_REQUIREMENTS, McpClientConfig, McpServerConfig

# v2.2 — PQC crypto primitives (issue #47)
from rcan.crypto import (
    HYBRID_ALG,
    ML_DSA_ALG,
    HybridSignature,
    MlDsaKeyPair,
    decode_public_key_jwk,
    encode_public_key_jwk,
    generate_ml_dsa_keypair,
    sign_hybrid,
    sign_ml_dsa,
    verify_hybrid,
    verify_ml_dsa,
)
