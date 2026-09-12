"""
rcan.federation — Federated Consent (GAP-16).

Provides registry identity, trust anchor caching, federation sync
message builders, and cross-registry command validation.

ESTOP P66 invariant: ESTOP is NEVER blocked by federation checks.

Spec: §17 — Federated Consent and Registry Trust
"""

from __future__ import annotations

import base64
import json
import logging
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Optional

log = logging.getLogger(__name__)

# TTL for trust anchor cache entries: 24 hours
TRUST_ANCHOR_TTL_S: float = 86_400.0

# Commands that stop a robot. These — and only these — are exempt from the
# cross-registry trust checks in :func:`validate_cross_registry_command`
# (P66 invariant). The exemption covers stopping, never starting: a message
# *type* such as SAFETY is deliberately not a member, because a SAFETY-typed
# RESUME must not smuggle a start command through a stop exemption.
STOP_VERBS: frozenset[str] = frozenset({"ESTOP", "E_STOP", "EMERGENCY_STOP", "STOP"})


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class RegistryTier(str, Enum):
    """Trust tier of an RCAN registry."""

    ROOT = "root"
    AUTHORITATIVE = "authoritative"
    COMMUNITY = "community"


class FederationSyncType(str, Enum):
    """Type of data being synchronised across registries."""

    CONSENT = "consent"
    REVOCATION = "revocation"
    KEY = "key"


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass
class RegistryIdentity:
    """Identity record for a remote RCAN registry.

    Attributes:
        registry_url:   Base URL of the registry (e.g. ``"https://registry.example.com"``).
        tier:           Trust tier of this registry.
        public_key_pem: PEM-encoded Ed25519 public key for JWT verification.
        domain:         Apex domain served by this registry.
        verified_at:    ISO-8601 timestamp when this identity was last verified.
    """

    registry_url: str
    tier: RegistryTier
    public_key_pem: str
    domain: str
    verified_at: Optional[str] = None


@dataclass
class FederationSyncPayload:
    """Wire payload for a FEDERATION_SYNC message.

    Attributes:
        source_registry: URL of the originating registry.
        target_registry: URL of the destination registry.
        sync_type:       Category of data being synced.
        payload:         Sync-type-specific data dict.
        signature:       Base64-encoded signature over the payload.
    """

    source_registry: str
    target_registry: str
    sync_type: FederationSyncType
    payload: dict
    signature: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_registry": self.source_registry,
            "target_registry": self.target_registry,
            "sync_type": self.sync_type.value,
            "payload": self.payload,
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "FederationSyncPayload":
        return cls(
            source_registry=data["source_registry"],
            target_registry=data["target_registry"],
            sync_type=FederationSyncType(data.get("sync_type", "consent")),
            payload=data.get("payload", {}),
            signature=data.get("signature", ""),
        )


# ---------------------------------------------------------------------------
# Trust Anchor Cache
# ---------------------------------------------------------------------------


class TrustAnchorCache:
    """TTL cache (24 h) for registry public keys and identity records.

    Thread-safety: single-threaded only (in-process dict).
    Use an external store for multi-process deployments.
    """

    def __init__(self, ttl_s: float = TRUST_ANCHOR_TTL_S) -> None:
        self._ttl_s = ttl_s
        # registry_url → (RegistryIdentity, stored_at_unix)
        self._cache: dict[str, tuple[RegistryIdentity, float]] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def store(self, identity: RegistryIdentity) -> None:
        """Insert or refresh a registry identity in the cache."""
        self._cache[identity.registry_url] = (identity, time.time())
        log.debug(
            "Stored trust anchor for %s (tier=%s)", identity.registry_url, identity.tier
        )

    def lookup(self, registry_url: str) -> Optional[RegistryIdentity]:
        """Return a cached :class:`RegistryIdentity`, or ``None`` if absent / expired."""
        entry = self._cache.get(registry_url)
        if entry is None:
            return None
        identity, stored_at = entry
        if time.time() - stored_at > self._ttl_s:
            del self._cache[registry_url]
            log.debug("Trust anchor for %s expired; evicted from cache", registry_url)
            return None
        return identity

    def discover_via_dns(self, domain: str) -> Optional[RegistryIdentity]:
        """Read ``_rcan-registry.<domain>`` TXT record to discover a registry.

        The TXT record MUST contain a JSON object with at minimum:
        ``registry_url``, ``tier``, and optionally ``public_key_pem``,
        ``verified_at``.

        Requires the ``dnspython`` package (``pip install dnspython``).

        Returns:
            A :class:`RegistryIdentity` on success, or ``None`` on failure.
        """
        try:
            import dns.resolver  # type: ignore[import]
        except ImportError:
            log.warning(
                "dnspython not installed; DNS registry discovery disabled. "
                "Install with: pip install dnspython"
            )
            return None

        try:
            answers = dns.resolver.resolve(f"_rcan-registry.{domain}", "TXT")
            for rdata in answers:
                txt = "".join(
                    s.decode() if isinstance(s, bytes) else str(s)
                    for s in rdata.strings
                )
                data = json.loads(txt)
                identity = RegistryIdentity(
                    registry_url=data["registry_url"],
                    tier=RegistryTier(data.get("tier", "community")),
                    public_key_pem=data.get("public_key_pem", ""),
                    domain=domain,
                    verified_at=data.get("verified_at"),
                )
                self.store(identity)
                log.info(
                    "Discovered registry %s for domain %s via DNS",
                    identity.registry_url,
                    domain,
                )
                return identity
        except Exception as exc:  # noqa: BLE001
            log.warning("DNS discovery for domain %r failed: %s", domain, exc)
        return None

    def verify_registry_jwt(self, token: str, registry_url: str) -> tuple[bool, str]:
        """Check that *token* is a structurally valid JWT issued by *registry_url*.

        Performs:
        - Structure check (3 parts)
        - Issuer claim verification
        - Expiry check
        - Trust cache presence check (full signature verification requires
          a ``cryptography`` dependency; if public key is unavailable the
          JWT is accepted with a warning)

        Args:
            token:        Raw JWT string.
            registry_url: Expected issuer URL.

        Returns:
            ``(valid: bool, reason: str)`` — reason is ``"ok"`` on success.
        """
        if not token:
            return False, "Empty token"

        parts = token.split(".")
        if len(parts) != 3:
            return False, f"Invalid JWT structure: expected 3 parts, got {len(parts)}"

        try:
            payload_b64 = parts[1]
            # Restore base64 padding
            padding = 4 - len(payload_b64) % 4
            if padding != 4:
                payload_b64 += "=" * padding
            payload = json.loads(base64.urlsafe_b64decode(payload_b64))
        except Exception as exc:  # noqa: BLE001
            return False, f"JWT payload decode error: {exc}"

        # Issuer check
        iss = payload.get("iss", "")
        if iss != registry_url:
            return False, (
                f"JWT issuer {iss!r} does not match expected registry {registry_url!r}"
            )

        # Expiry check
        exp = payload.get("exp")
        if exp is not None and time.time() > float(exp):
            return False, "JWT is expired"

        # Trust cache lookup
        identity = self.lookup(registry_url)
        if identity is None or not identity.public_key_pem:
            log.warning(
                "Registry %s not in trust cache or has no public key; "
                "accepting JWT without cryptographic verification",
                registry_url,
            )
            return True, "structurally valid (no public key for signature check)"

        # Full Ed25519 verification (requires cryptography)
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # type: ignore[import]
                Ed25519PublicKey,
            )
            from cryptography.hazmat.primitives.serialization import (  # type: ignore[import]
                load_pem_public_key,
            )

            pub_key = load_pem_public_key(identity.public_key_pem.encode())
            # JWT signature covers base64url(header) + "." + base64url(payload)
            signing_input = f"{parts[0]}.{parts[1]}".encode()
            sig_b64 = parts[2]
            padding = 4 - len(sig_b64) % 4
            if padding != 4:
                sig_b64 += "=" * padding
            sig_bytes = base64.urlsafe_b64decode(sig_b64)
            pub_key.verify(sig_bytes, signing_input)
        except ImportError:
            log.debug(
                "cryptography package not available; skipping Ed25519 JWT verification"
            )
            return True, "structurally valid (cryptography not installed)"
        except Exception as exc:  # noqa: BLE001
            return False, f"JWT signature verification failed: {exc}"

        return True, "ok"


# ---------------------------------------------------------------------------
# Builder helpers
# ---------------------------------------------------------------------------


def make_federation_sync(
    source: str,
    target: str,
    sync_type: FederationSyncType,
    payload: dict,
    target_uri: str = "rcan://rcan.dev/system/federation/v1/local",
) -> Any:
    """Build a FEDERATION_SYNC :class:`~rcan.message.RCANMessage`.

    Args:
        source:     Source registry URL.
        target:     Target registry URL.
        sync_type:  Category of data being synced.
        payload:    Sync-type-specific data.
        target_uri: RCAN URI to address the message to.

    Returns:
        :class:`~rcan.message.RCANMessage` with ``cmd="FEDERATION_SYNC"``.
    """
    from rcan.message import RCANMessage

    sync_payload = FederationSyncPayload(
        source_registry=source,
        target_registry=target,
        sync_type=sync_type,
        payload=payload,
        signature="",  # populated by signing layer
    )
    return RCANMessage(
        cmd="FEDERATION_SYNC",
        target=target_uri,
        params=sync_payload.to_dict(),
    )


def validate_cross_registry_command(
    msg: Any,
    local_registry: str,
    trust_cache: TrustAnchorCache,
) -> tuple[bool, str]:
    """Validate a command that originated from a foreign registry.

    Rules:
    - **Stop verbs are always allowed** (P66 invariant — never blocked).
      The exempt set is :data:`STOP_VERBS`; it contains only commands that
      stop a robot, not message types such as ``SAFETY``, so a resume
      cannot ride in on a stop exemption.
    - Cross-registry commands require LoA ≥ 2.
    - Source registry JWT must be valid (if present).
    - Local consent record must exist (checked via ``params["consent_id"]``);
      a cross-registry command without one is refused.

    The stop exemption is also a denial-of-service primitive, and an
    implementer should size their deployment knowing it: a command in
    :data:`STOP_VERBS` skips replay prevention, the LoA check, the source
    registry JWT check, the consent check and revocation, so any party that
    can put a message on the wire can stop the robot, repeatedly, without
    authenticating. That is the deliberate trade — local safety wins over
    authentication, a stop is never refused — but it means availability of
    the robot is not protected by this function. Rate limiting, transport
    authentication or physical access control have to carry that load.

    Args:
        msg:            Incoming :class:`~rcan.message.RCANMessage`.
        local_registry: URL of the receiving registry.
        trust_cache:    Cache of trusted remote registries.

    Returns:
        ``(valid: bool, reason: str)`` — reason is ``"ok"`` on success.
    """
    # P66 invariant: a stop is NEVER blocked by federation checks
    if msg.cmd.upper() in STOP_VERBS:
        log.debug("Stop verb bypasses cross-registry trust check (P66 invariant)")
        return True, "ESTOP always allowed"

    # LoA check
    msg_loa = getattr(msg, "loa", None)
    if msg_loa is None or int(msg_loa) < 2:
        return False, (f"Cross-registry command requires LoA ≥ 2, got loa={msg_loa!r}")

    # Source registry JWT verification
    source_registry: Optional[str] = None
    if msg.signature and isinstance(msg.signature, dict):
        source_registry = msg.signature.get("registry_url") or msg.signature.get("iss")

    if source_registry:
        jwt_token = msg.signature.get("value", "") if msg.signature else ""  # type: ignore[union-attr]
        if jwt_token:
            valid, reason = trust_cache.verify_registry_jwt(jwt_token, source_registry)
            if not valid:
                return False, f"Source registry JWT invalid: {reason}"

    # Local consent record check
    consent_id = (
        (msg.params.get("consent_id") or msg.params.get("consent_ref"))
        if msg.params
        else None
    )
    if not consent_id:
        return False, "Cross-registry command missing consent_id"

    return True, "ok"


__all__ = [
    "RegistryTier",
    "FederationSyncType",
    "RegistryIdentity",
    "FederationSyncPayload",
    "TrustAnchorCache",
    "make_federation_sync",
    "validate_cross_registry_command",
    "STOP_VERBS",
    "TRUST_ANCHOR_TTL_S",
]
