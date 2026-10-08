"""RCAN exception hierarchy."""

from __future__ import annotations


class RCANError(Exception):
    """Base exception for all RCAN errors."""


class RCANAddressError(RCANError):
    """Invalid or unresolvable Robot URI."""


class RCANValidationError(RCANError):
    """RCAN message failed schema validation."""


class RCANGateError(RCANError):
    """Action blocked by a safety gate (confidence or HiTL)."""

    def __init__(
        self,
        message: str,
        gate_type: str = "unknown",
        value: float | None = None,
        threshold: float | None = None,
    ):
        super().__init__(message)
        self.gate_type = gate_type
        self.value = value
        self.threshold = threshold


class RCANSignatureError(RCANError):
    """RCAN message signature is missing, invalid, or from an untrusted key."""


class RCANEncodingError(RCANError, ValueError):
    """A value has no canonical JSON form (RFC 8785).

    ``code`` is ``"non_finite_number"`` for NaN or Infinity, or
    ``"invalid_string"`` for a string or object key with an unpaired surrogate.
    Also a :class:`ValueError`, which is what :func:`json.dumps` raises for
    NaN when ``allow_nan=False``.
    """

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


class RCANRegistryError(RCANError):
    """Error communicating with the RCAN robot registry."""


class RCANTimeoutError(RCANError):
    """Command timed out waiting for a response or HiTL approval."""


class RCANNodeError(RCANError):
    """Error communicating with an RCAN distributed registry node."""


# ---------------------------------------------------------------------------
# v1.5 additions
# ---------------------------------------------------------------------------


class VersionIncompatibleError(RCANError):
    """Incoming message MAJOR version does not match receiver's MAJOR version."""


class ReplayAttackError(RCANError):
    """Message rejected as a replay (duplicate msg_id or stale timestamp)."""


class ClockDriftError(RCANError):
    """System clock is not synchronized or exceeds allowed drift tolerance."""


class DelegationChainExceededError(RCANError):
    """Delegation chain depth exceeds the maximum allowed (4 hops)."""


class DelegationVerificationError(RCANError):
    """A delegation hop signature failed verification."""


class QoSAckTimeoutError(RCANError):
    """QoS acknowledgement timed out after max retries."""


class SafetyHaltError(RCANError):
    """A safety halt was triggered (e.g. ESTOP ACK timeout)."""


class ConfigAuthorizationError(RCANError):
    """Config update requires elevated role (creator) for safety overrides."""


class ConfigHashMismatchError(RCANError):
    """Config payload hash does not match declared config_hash."""


class RevocationError(RCANError):
    """A robot's identity has been revoked or suspended."""


class ConsentError(RCANError):
    """Consent is missing, expired, or invalid."""


# ---------------------------------------------------------------------------
# v1.6 additions
# ---------------------------------------------------------------------------


class FederationError(RCANError):
    """Federation trust check failed or registry is untrusted."""


class IdentityError(RCANError):
    """Identity verification failed or LoA requirement not met."""


__all__ = [
    "RCANError",
    "RCANAddressError",
    "RCANValidationError",
    "RCANGateError",
    "RCANSignatureError",
    "RCANRegistryError",
    "RCANTimeoutError",
    "RCANNodeError",
    # v1.5
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
    # v1.6
    "FederationError",
    "IdentityError",
]
