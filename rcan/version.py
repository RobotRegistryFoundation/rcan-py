"""
rcan.version — single source of truth for the RCAN spec version.

All modules that need the current spec version MUST import from here.
Do NOT hardcode version strings anywhere else.

Spec: https://rcan.dev/spec#section-3-5
"""

from __future__ import annotations

# RCAN specification version this SDK implements.
SPEC_VERSION: str = "3.2"

# SDK version (Python package)
SDK_VERSION: str = "3.5.0"

# v2.2 feature flags
SUPPORTED_FEATURES: frozenset[str] = frozenset(
    {
        # v1.x carry-forward
        "REPLAY_PREVENTION",
        "CLOCK_SYNC",
        "CLOUD_RELAY_IDENTITY",
        "QOS_DELIVERY",
        "CONFIG_UPDATE",
        "KEY_ROTATION",
        "CONSENT_WIRE",
        "ROBOT_REVOCATION",
        "TRAINING_CONSENT",
        "DELEGATION_CHAIN",
        "OFFLINE_OPERATION",
        "FLEET_BROADCAST",
        "OBSERVER_MODE",
        "PHYSICAL_PRESENCE",
        "FAULT_REPORTING",
        "AUDIT_EXPORT",
        "FEDERATED_CONSENT",
        "CONSTRAINED_TRANSPORT",
        "MULTIMODAL_PAYLOADS",
        "IDENTITY_LOA",
        "COMPETITION_PROTOCOL",
        # v2.1 features
        "SIGNED_RURI",
        "FIRMWARE_MANIFEST",
        "SBOM_ATTESTATION",
        "M2M_PEER",
        "M2M_TRUSTED",
        "AUTHORITY_ACCESS",
        # v2.2 features — ML-DSA-65 PRIMARY (Q-Day timeline accelerated to 2026)
        "PQ_HYBRID_SIGNING",  # ML-DSA-65 + Ed25519 hybrid (FIPS 204)
        "ML_DSA_PRIMARY",  # ML-DSA-65 is the primary signing algorithm (Ed25519 = legacy compat only)
        # v2.2.1 features
        "MULTI_TYPE_ENTITY_NUMBERING",  # §21.2.2 RRN/RCN/RMN/RHN sequential registry IDs
        "FRIA_COMPLIANCE",        # §22 Fundamental Rights Impact Assessment
        "SAFETY_BENCHMARK",       # §23 Safety Benchmark Protocol
        "INSTRUCTIONS_FOR_USE",   # §24 EU AI Act Art. 13 IFU
        "POST_MARKET_MONITORING", # §25 EU AI Act Art. 72 incidents
        "EU_REGISTER",            # §26 EU AI Act Art. 49/60 register submission
    }
)

__all__ = ["SPEC_VERSION", "SDK_VERSION", "SUPPORTED_FEATURES"]
