"""Cross-SDK canonical MessageType verification (v1.10).

This test ensures rcan-py MessageType values match the v1.10 canonical table
exactly. Any drift from the spec will fail CI immediately.
"""

from rcan.message import MessageType

# v1.8 canonical table — single source of truth from rcan-spec §3
CANONICAL_TABLE = {
    "COMMAND": 1,
    "RESPONSE": 2,
    "STATUS": 3,
    "HEARTBEAT": 4,
    "CONFIG": 5,
    "SAFETY": 6,
    "AUTH": 7,
    "ERROR": 8,
    "DISCOVER": 9,
    "PENDING_AUTH": 10,
    "INVOKE": 11,
    "INVOKE_RESULT": 12,
    "INVOKE_CANCEL": 13,
    "REGISTRY_REGISTER": 14,
    "REGISTRY_RESOLVE": 15,
    "TRANSPARENCY": 16,
    "COMMAND_ACK": 17,
    "COMMAND_NACK": 18,
    "ROBOT_REVOCATION": 19,
    "CONSENT_REQUEST": 20,
    "CONSENT_GRANT": 21,
    "CONSENT_DENY": 22,
    "FLEET_COMMAND": 23,
    "SUBSCRIBE": 24,
    "UNSUBSCRIBE": 25,
    "FAULT_REPORT": 26,
    "KEY_ROTATION": 27,
    "COMMAND_COMMIT": 28,
    "SENSOR_DATA": 29,
    "TRAINING_CONSENT_REQUEST": 30,
    "TRAINING_CONSENT_GRANT": 31,
    "TRAINING_CONSENT_DENY": 32,
    "CONTRIBUTE_REQUEST": 33,
    "CONTRIBUTE_RESULT": 34,
    "CONTRIBUTE_CANCEL": 35,
    "TRAINING_DATA": 36,
    # v1.10 — Competition protocol
    "COMPETITION_ENTER": 37,
    "COMPETITION_SCORE": 38,
    "SEASON_STANDING": 39,
    "PERSONAL_RESEARCH_RESULT": 40,
    # Authority & attestation — v2.1 (41–44)
    "AUTHORITY_ACCESS": 41,
    "AUTHORITY_RESPONSE": 42,
    "FIRMWARE_ATTESTATION": 43,
    "SBOM_UPDATE": 44,
    # HiTL authorization — v3.3 (45)
    "AUTHORIZE": 45,
}


def test_all_canonical_types_present():
    """Every canonical type must exist in MessageType."""
    for name in CANONICAL_TABLE:
        assert hasattr(MessageType, name), f"Missing MessageType.{name}"


def test_all_canonical_values_match():
    """Every canonical type must have the exact integer value from the spec."""
    for name, expected in CANONICAL_TABLE.items():
        actual = getattr(MessageType, name)
        assert actual == expected, (
            f"MessageType.{name} = {actual}, expected {expected} (v1.8 canonical)"
        )


def test_no_duplicate_values():
    """No two MessageType members should share the same integer value."""
    seen: dict[int, str] = {}
    for member in MessageType:
        if member.value in seen:
            raise AssertionError(
                f"Duplicate value {member.value}: "
                f"{seen[member.value]} and {member.name}"
            )
        seen[member.value] = member.name


def test_canonical_count():
    """MessageType should have exactly 45 members (v3.3: AUTHORIZE = 45)."""
    assert len(MessageType) == 45, (
        f"Expected 45 MessageType members, got {len(MessageType)}"
    )
