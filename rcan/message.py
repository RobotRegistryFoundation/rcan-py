"""
RCAN message types — command, response, and status.

Spec: https://rcan.dev/spec#section-3
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum, IntEnum
from typing import Any, Optional, TypedDict

from rcan.address import RobotURI
from rcan.exceptions import RCANValidationError, VersionIncompatibleError
from rcan.version import SPEC_VERSION

logger = logging.getLogger(__name__)

# Required fields for a valid RCAN command message
_REQUIRED_CMD_FIELDS = {"rcan", "cmd", "target"}


# ---------------------------------------------------------------------------
# MessageType enum — canonical v1.5 integer table
# ---------------------------------------------------------------------------


class MessageType(IntEnum):
    """RCAN v1.10 Canonical MessageType Table.

    This is the SINGLE SOURCE OF TRUTH for message type integers.
    Values MUST match rcan-spec §3 and rcan-ts exactly.
    See: https://rcan.dev/spec/v1.10
    """

    # Core protocol (1–8)
    COMMAND = 1
    RESPONSE = 2
    STATUS = 3
    HEARTBEAT = 4
    CONFIG = 5
    SAFETY = 6
    AUTH = 7
    ERROR = 8

    # Discovery & authorization (9–10)
    DISCOVER = 9
    PENDING_AUTH = 10

    # Skill invocation (11–13)
    INVOKE = 11
    INVOKE_RESULT = 12
    INVOKE_CANCEL = 13

    # Registry (14–15)
    REGISTRY_REGISTER = 14
    REGISTRY_RESOLVE = 15

    # Audit & transparency (16)
    TRANSPARENCY = 16  # EU AI Act Art. 13 audit record

    # Acknowledgement & QoS (17–18)
    COMMAND_ACK = 17
    COMMAND_NACK = 18

    # Identity & consent (19–22)
    ROBOT_REVOCATION = 19
    CONSENT_REQUEST = 20
    CONSENT_GRANT = 21
    CONSENT_DENY = 22

    # Fleet & telemetry (23–25)
    FLEET_COMMAND = 23
    SUBSCRIBE = 24
    UNSUBSCRIBE = 25

    # Diagnostics (26–28)
    FAULT_REPORT = 26
    KEY_ROTATION = 27
    COMMAND_COMMIT = 28

    # Sensor & training consent (29–32)
    SENSOR_DATA = 29
    TRAINING_CONSENT_REQUEST = 30
    TRAINING_CONSENT_GRANT = 31
    TRAINING_CONSENT_DENY = 32

    # Idle compute contribution — v1.7 (33–35)
    CONTRIBUTE_REQUEST = 33
    CONTRIBUTE_RESULT = 34
    CONTRIBUTE_CANCEL = 35

    # Multimodal training data — v1.8 (36)
    TRAINING_DATA = 36

    # Competition protocol — v1.10 (37–40)
    COMPETITION_ENTER = 37
    COMPETITION_SCORE = 38
    SEASON_STANDING = 39
    PERSONAL_RESEARCH_RESULT = 40

    # Authority & attestation — v2.1 (41–44)
    AUTHORITY_ACCESS = 41  # authority → robot: EU AI Act Art. 16(j) audit request
    AUTHORITY_RESPONSE = 42  # robot → authority: audit data response
    FIRMWARE_ATTESTATION = 43  # robot → RRF: publish signed firmware manifest
    SBOM_UPDATE = 44  # robot → RRF: publish updated CycloneDX SBOM

    # HiTL authorization — v3.3 (45)
    AUTHORIZE = 45  # approve or deny a PENDING_AUTH (spec §16.4)


# ---------------------------------------------------------------------------
# SenderType enum — GAP-08: Cloud Relay Identity
# ---------------------------------------------------------------------------


class SenderType(str, Enum):
    """Identifies the category of the message sender.

    Spec: §8.5 — Sender Type and Service Identity
    """

    robot = "robot"
    human = "human"
    cloud_function = "cloud_function"
    system = "system"


# ---------------------------------------------------------------------------
# Version compatibility helper — GAP-12
# ---------------------------------------------------------------------------


def validate_version_compat(incoming_version: str) -> bool:
    """Check if *incoming_version* is compatible with this receiver's version.

    Rules (RCAN §3.5):
    - Same MAJOR: accept if incoming MINOR ≤ receiver MINOR.
    - Different MAJOR: raise :class:`VersionIncompatibleError`.
    - Higher MINOR: log a warning (forward-compat; new fields are ignored).

    Args:
        incoming_version: Version string from an incoming message (e.g. "1.3").

    Returns:
        True if compatible.

    Raises:
        VersionIncompatibleError: If MAJOR version mismatch.
    """
    try:
        parts = incoming_version.split(".")
        incoming_major = int(parts[0])
        incoming_minor = int(parts[1]) if len(parts) > 1 else 0
    except (ValueError, IndexError) as exc:
        raise VersionIncompatibleError(
            f"Cannot parse incoming version: {incoming_version!r}"
        ) from exc

    try:
        our_parts = SPEC_VERSION.split(".")
        our_major = int(our_parts[0])
        our_minor = int(our_parts[1]) if len(our_parts) > 1 else 0
    except (ValueError, IndexError):
        our_major, our_minor = 1, 5

    if incoming_major != our_major:
        raise VersionIncompatibleError(
            f"MAJOR version mismatch: receiver={SPEC_VERSION!r}, "
            f"sender={incoming_version!r}. Only same-MAJOR is compatible."
        )

    if incoming_minor > our_minor:
        logger.warning(
            "Incoming message version %s is newer than receiver version %s. "
            "Unknown fields will be ignored (forward-compat mode).",
            incoming_version,
            SPEC_VERSION,
        )

    return True


# ---------------------------------------------------------------------------
# RCANMessage dataclass
# ---------------------------------------------------------------------------


@dataclass
class RCANMessage:
    """
    An RCAN command message.

    Attributes:
        cmd:            Command name (e.g. ``move_forward``, ``stop``, ``speak``).
        target:         Destination robot URI.
        params:         Command parameters (free-form dict).
        confidence:     AI inference confidence [0.0–1.0]. None if not AI-driven.
        rcan:           RCAN spec version. Defaults to current SPEC_VERSION.
        msg_id:         Unique message ID. Auto-generated if not provided.
        timestamp:      Unix timestamp. Auto-set if not provided.
        sender:         Sender identity (operator URI or name).
        scope:          Authorization scope (e.g. ``"operator"``, ``"fleet"``).
        signature:      ML-DSA-65 signature dict (``alg: "ml-dsa-65"``, ``kid``, ``value``). RCAN v2.2+.
        rcan_version:   Explicit spec version (mirrors ``rcan`` for v1.5 compat).
        sender_type:    Category of sender (GAP-08: cloud relay identity).
        cloud_provider: Cloud provider name when sender_type==cloud_function.
        key_id:         Key identifier for the signing key (GAP-09).
        qos:            Quality of service level (GAP-11). 0=fire-and-forget.
        sequence_number: Message sequence number for QoS ordering (GAP-11).
        delegation_chain: Chain of delegation hops (GAP-01).
        group_id:       Fleet group identifier (GAP-13).
        read_only:      Observer-mode flag — sender requests read-only stream (GAP-15).
        presence_verified: Physical presence has been verified (GAP-19).
        proximity_m:    Physical proximity in metres (GAP-19).
        media_chunks:   List of MediaChunk objects attached to this message (GAP-18).
        loa:            Level of Assurance integer for the sender (GAP-14).
        transport_encoding: Transport encoding hint for constrained channels (GAP-17).
    """

    cmd: str = ""
    target: RobotURI | str = ""
    params: dict[str, Any] = field(default_factory=dict)
    type: Optional["MessageType"] = None
    payload: dict[str, Any] = field(default_factory=dict)
    confidence: float | None = None
    rcan: str = field(default_factory=lambda: SPEC_VERSION)
    msg_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float = field(default_factory=time.time)
    sender: str | None = None
    scope: str | None = None
    signature: dict[str, str] | None = None

    # v1.5 additions
    rcan_version: str = field(default_factory=lambda: SPEC_VERSION)
    sender_type: Optional[SenderType] = None
    cloud_provider: Optional[str] = None
    key_id: Optional[str] = None
    qos: int = 0
    sequence_number: Optional[int] = None
    delegation_chain: list = field(default_factory=list)  # list[DelegationHop]
    group_id: Optional[str] = None
    read_only: bool = False
    presence_verified: bool = False
    proximity_m: Optional[float] = None

    # v1.6 additions
    media_chunks: list = field(default_factory=list)  # list[MediaChunk] (GAP-18)
    loa: Optional[int] = None  # Level of Assurance (GAP-14)
    transport_encoding: Optional[str] = None  # Transport encoding hint (GAP-17)

    # v2.1 additions — REQUIRED for all messages at L2+ conformance
    firmware_hash: Optional[str] = (
        None  # SHA-256 of sender's firmware manifest (field 13)
    )
    attestation_ref: Optional[str] = None  # URI to sender's SBOM endpoint (field 14)

    # v2.2 additions — post-quantum signature fields (FIPS 204)
    pq_sig: str = ""  # ML-DSA-65 post-quantum signature (base64url)
    pq_alg: str = "ml-dsa-65"  # PQ algorithm identifier

    def __post_init__(self) -> None:
        # Normalize target to RobotURI (skip for typed messages with no target)
        if isinstance(self.target, str) and self.target:
            self.target = RobotURI.parse(self.target)
        # Validate confidence range
        if self.confidence is not None and not (0.0 <= self.confidence <= 1.0):
            raise RCANValidationError(
                f"confidence must be in [0.0, 1.0], got {self.confidence}"
            )
        # cmd is required only for command-style messages (type=None)
        if not self.cmd and self.type is None:
            raise RCANValidationError("cmd must not be empty")
        # Sync rcan and rcan_version (both carry the spec version)
        if self.rcan_version == SPEC_VERSION and self.rcan != SPEC_VERSION:
            self.rcan_version = self.rcan
        elif self.rcan == SPEC_VERSION and self.rcan_version != SPEC_VERSION:
            self.rcan = self.rcan_version
        # GAP-08 validation: cloud_function senders must declare cloud_provider
        if self.sender_type == SenderType.cloud_function and not self.cloud_provider:
            raise RCANValidationError(
                "cloud_provider is required when sender_type == 'cloud_function'"
            )
        # v2.2: delegation_chain max depth is 3
        if len(self.delegation_chain) > 3:
            raise ValueError("RCAN: delegation chain max depth is 3")
        # v2.1: hard-remove signature:"pending" — rejected at parse time
        if (
            isinstance(self.signature, dict)
            and self.signature.get("value") == "pending"
        ):
            raise RCANValidationError(
                "signature:'pending' is not valid in RCAN v2.2. "
                "Sign the message before sending or omit the signature field."
            )
        if isinstance(self.signature, str) and self.signature == "pending":
            raise RCANValidationError("signature:'pending' is not valid in RCAN v2.2.")

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable dict representation."""
        d: dict[str, Any] = {
            "rcan": self.rcan,
            "rcan_version": self.rcan_version,
            "msg_id": self.msg_id,
            "timestamp": self.timestamp,
            "cmd": self.cmd,
            "target": str(self.target),
            "params": self.params,
        }
        if self.confidence is not None:
            d["confidence"] = self.confidence
        if self.sender is not None:
            d["sender"] = self.sender
        if self.scope is not None:
            d["scope"] = self.scope
        if self.signature is not None:
            d["sig"] = self.signature
        # v1.5 optional fields
        if self.sender_type is not None:
            d["sender_type"] = self.sender_type.value
        if self.cloud_provider is not None:
            d["cloud_provider"] = self.cloud_provider
        if self.key_id is not None:
            d["key_id"] = self.key_id
        if self.qos != 0:
            d["qos"] = self.qos
        if self.sequence_number is not None:
            d["sequence_number"] = self.sequence_number
        if self.delegation_chain:
            d["delegation_chain"] = [
                hop.to_dict() if hasattr(hop, "to_dict") else hop
                for hop in self.delegation_chain
            ]
        if self.group_id is not None:
            d["group_id"] = self.group_id
        if self.read_only:
            d["read_only"] = self.read_only
        if self.presence_verified:
            d["presence_verified"] = self.presence_verified
        if self.proximity_m is not None:
            d["proximity_m"] = self.proximity_m
        # v1.6 optional fields
        if self.media_chunks:
            d["media_chunks"] = [
                chunk.to_dict() if hasattr(chunk, "to_dict") else chunk
                for chunk in self.media_chunks
            ]
        if self.loa is not None:
            d["loa"] = self.loa
        if self.transport_encoding is not None:
            d["transport_encoding"] = self.transport_encoding
        # v2.1 envelope fields
        if self.firmware_hash is not None:
            d["firmware_hash"] = self.firmware_hash
        if self.attestation_ref is not None:
            d["attestation_ref"] = self.attestation_ref
        return d

    def to_json(self, indent: int | None = None) -> str:
        """Serialize to a JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "RCANMessage":
        """
        Deserialize a dict into an :class:`RCANMessage`.

        v1.5: validates rcan_version compatibility first (GAP-12).

        Raises:
            VersionIncompatibleError: If incoming MAJOR version differs.
            RCANValidationError: If required fields are missing.
        """
        # GAP-12: version compatibility check is the FIRST validation
        incoming_version = data.get("rcan_version") or data.get("rcan")
        if incoming_version and str(incoming_version) != SPEC_VERSION:
            try:
                validate_version_compat(str(incoming_version))
            except VersionIncompatibleError:
                raise

        missing = _REQUIRED_CMD_FIELDS - data.keys()
        if missing:
            raise RCANValidationError(f"Missing required RCAN fields: {missing}")

        # Parse sender_type
        sender_type = None
        st_raw = data.get("sender_type")
        if st_raw is not None:
            try:
                sender_type = SenderType(st_raw)
            except ValueError:
                pass  # unknown sender_type — ignore (forward compat)

        return cls(
            rcan=data.get("rcan", SPEC_VERSION),
            rcan_version=data.get("rcan_version", data.get("rcan", SPEC_VERSION)),
            msg_id=data.get("msg_id", str(uuid.uuid4())),
            timestamp=data.get("timestamp", time.time()),
            cmd=data["cmd"],
            target=RobotURI.parse(data["target"]),
            params=data.get("params", {}),
            confidence=data.get("confidence"),
            sender=data.get("sender"),
            scope=data.get("scope"),
            signature=data.get("sig"),
            sender_type=sender_type,
            cloud_provider=data.get("cloud_provider"),
            key_id=data.get("key_id"),
            qos=data.get("qos", 0),
            sequence_number=data.get("sequence_number"),
            delegation_chain=data.get("delegation_chain", []),
            group_id=data.get("group_id"),
            read_only=data.get("read_only", False),
            presence_verified=data.get("presence_verified", False),
            proximity_m=data.get("proximity_m"),
            # v1.6
            media_chunks=data.get("media_chunks", []),
            loa=data.get("loa"),
            transport_encoding=data.get("transport_encoding"),
            # v2.1
            firmware_hash=data.get("firmware_hash"),
            attestation_ref=data.get("attestation_ref"),
        )

    @classmethod
    def from_json(cls, json_str: str) -> "RCANMessage":
        """Deserialize from a JSON string."""
        try:
            data = json.loads(json_str)
        except json.JSONDecodeError as e:
            raise RCANValidationError(f"Invalid JSON: {e}") from e
        return cls.from_dict(data)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @property
    def is_signed(self) -> bool:
        """True if this message carries a signature."""
        return self.signature is not None

    @property
    def is_ai_driven(self) -> bool:
        """True if this message carries an AI confidence score."""
        return self.confidence is not None

    def __repr__(self) -> str:
        return (
            f"RCANMessage(cmd={self.cmd!r}, target={self.target!r}, "
            f"confidence={self.confidence})"
        )


# ---------------------------------------------------------------------------
# GAP-08: Cloud Relay Identity helper
# ---------------------------------------------------------------------------


def make_cloud_relay_message(base: RCANMessage, provider: str) -> RCANMessage:
    """Stamp a message as originating from a cloud function.

    Creates a shallow copy of *base* with ``sender_type=cloud_function`` and
    the given *provider* name. The commitment record will reflect the cloud
    origin for audit trail integrity.

    Args:
        base:     Original :class:`RCANMessage`.
        provider: Cloud provider identifier (e.g. ``"google-cloud-functions"``).

    Returns:
        A new :class:`RCANMessage` with cloud relay fields set.

    Raises:
        RCANValidationError: If *provider* is empty.
    """
    if not provider:
        raise RCANValidationError("provider must not be empty for cloud relay messages")

    d = base.to_dict()
    d["sender_type"] = SenderType.cloud_function.value
    d["cloud_provider"] = provider
    return RCANMessage.from_dict(d)


# ---------------------------------------------------------------------------
# RCANResponse
# ---------------------------------------------------------------------------


@dataclass
class RCANResponse:
    """
    Response from a robot to an RCAN command.

    Attributes:
        msg_id:            Echo of the originating message ID.
        status:            ``"ok"``, ``"error"``, ``"pending"``, or ``"blocked"``.
        message:           Human-readable status description.
        result:            Free-form result data from the command.
        safety_approved:   Whether the safety gate approved the action.
        safety_reason:     Reason if blocked.
        commitment_id:     ID of the :class:`CommitmentRecord` for this action.
        duration_ms:       Execution time in milliseconds.
        timestamp:         Unix timestamp of the response.
    """

    msg_id: str
    status: str  # ok | error | pending | blocked
    message: str = ""
    result: dict[str, Any] = field(default_factory=dict)
    safety_approved: bool = True
    safety_reason: str = ""
    commitment_id: str | None = None
    duration_ms: float | None = None
    timestamp: float = field(default_factory=time.time)

    @property
    def ok(self) -> bool:
        """True if status is ``"ok"``."""
        return self.status == "ok"

    @property
    def blocked(self) -> bool:
        """True if status is ``"blocked"`` (safety gate rejected)."""
        return self.status == "blocked"

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "RCANResponse":
        return cls(
            msg_id=data.get("msg_id", ""),
            status=data.get("status", "error"),
            message=data.get("message", ""),
            result=data.get("result", {}),
            safety_approved=data.get("safety_approved", True),
            safety_reason=data.get("safety_reason", ""),
            commitment_id=data.get("commitment_id"),
            duration_ms=data.get("duration_ms"),
            timestamp=data.get("timestamp", time.time()),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "msg_id": self.msg_id,
            "status": self.status,
            "message": self.message,
            "result": self.result,
            "safety_approved": self.safety_approved,
            "safety_reason": self.safety_reason,
            "commitment_id": self.commitment_id,
            "duration_ms": self.duration_ms,
            "timestamp": self.timestamp,
        }


# ---------------------------------------------------------------------------
# REGISTRY_REGISTER payload — v3.0 breaking change (fria_ref required)
# ---------------------------------------------------------------------------


class RegistryRegisterPayload(TypedDict):
    """Typed payload for REGISTRY_REGISTER messages.

    ``fria_ref`` is required in RCAN v3.0. Callers must submit a FRIA
    document via POST /api/v1/robots/:rrn/fria and pass the returned
    document ID here before registering.

    Spec: https://rcan.dev/spec/section-21 (§21.3 REGISTRY_REGISTER)
    """

    rrn: str
    robot_name: str
    public_key: str          # base64url Ed25519 or ML-DSA-65 public key
    verification_tier: str   # "community" | "verified" | "manufacturer" | "certified"
    fria_ref: str            # REQUIRED — ID of submitted FRIA document
    metadata: dict           # implementation-defined extra fields


def make_registry_register(
    rrn: str,
    robot_name: str,
    public_key: str,
    verification_tier: str,
    fria_ref: str,
    metadata: dict | None = None,
) -> RCANMessage:
    """Build a REGISTRY_REGISTER message with a required fria_ref.

    ``fria_ref`` is required in RCAN v3.0. Callers must obtain this ID
    by first submitting a FRIA document via POST /api/v1/robots/:rrn/fria.

    Args:
        rrn: Robot Registry Number, e.g. "RRN-000000000001"
        robot_name: Human-readable robot name
        public_key: Base64url-encoded public key (Ed25519 or ML-DSA-65)
        verification_tier: One of "community", "verified", "manufacturer", "certified"
        fria_ref: ID of the FRIA document (returned by the registry API)
        metadata: Optional dict of extra fields

    Returns:
        RCANMessage with type=REGISTRY_REGISTER and the payload set.
    """
    payload = RegistryRegisterPayload(
        rrn=rrn,
        robot_name=robot_name,
        public_key=public_key,
        verification_tier=verification_tier,
        fria_ref=fria_ref,
        metadata=metadata or {},
    )
    return RCANMessage(type=MessageType.REGISTRY_REGISTER, payload=dict(payload))
