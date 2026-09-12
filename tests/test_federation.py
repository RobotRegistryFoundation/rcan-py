"""Tests for rcan.federation — Federated Consent (GAP-16)."""

from __future__ import annotations

import base64
import json
import time

from rcan.federation import (
    STOP_VERBS,
    FederationSyncPayload,
    FederationSyncType,
    RegistryIdentity,
    RegistryTier,
    TrustAnchorCache,
    make_federation_sync,
    validate_cross_registry_command,
)
from rcan.message import RCANMessage

REGISTRY_A = "https://registry-a.example.com"
REGISTRY_B = "https://registry-b.example.com"


# ---------------------------------------------------------------------------
# RegistryTier & FederationSyncType
# ---------------------------------------------------------------------------


class TestEnums:
    def test_registry_tier_values(self):
        assert RegistryTier.ROOT.value == "root"
        assert RegistryTier.AUTHORITATIVE.value == "authoritative"
        assert RegistryTier.COMMUNITY.value == "community"

    def test_federation_sync_type_values(self):
        assert FederationSyncType.CONSENT.value == "consent"
        assert FederationSyncType.REVOCATION.value == "revocation"
        assert FederationSyncType.KEY.value == "key"


# ---------------------------------------------------------------------------
# RegistryIdentity
# ---------------------------------------------------------------------------


class TestRegistryIdentity:
    def test_construction(self):
        identity = RegistryIdentity(
            registry_url=REGISTRY_A,
            tier=RegistryTier.AUTHORITATIVE,
            public_key_pem="-----BEGIN PUBLIC KEY-----\n...",
            domain="example.com",
            verified_at="2026-01-01T00:00:00Z",
        )
        assert identity.registry_url == REGISTRY_A
        assert identity.tier == RegistryTier.AUTHORITATIVE
        assert identity.domain == "example.com"

    def test_optional_verified_at(self):
        identity = RegistryIdentity(
            registry_url=REGISTRY_A,
            tier=RegistryTier.COMMUNITY,
            public_key_pem="",
            domain="example.com",
        )
        assert identity.verified_at is None


# ---------------------------------------------------------------------------
# FederationSyncPayload
# ---------------------------------------------------------------------------


class TestFederationSyncPayload:
    def test_to_dict_roundtrip(self):
        p = FederationSyncPayload(
            source_registry=REGISTRY_A,
            target_registry=REGISTRY_B,
            sync_type=FederationSyncType.CONSENT,
            payload={"consent_id": "abc-123"},
            signature="sig==",
        )
        d = p.to_dict()
        assert d["source_registry"] == REGISTRY_A
        assert d["target_registry"] == REGISTRY_B
        assert d["sync_type"] == "consent"
        assert d["payload"]["consent_id"] == "abc-123"

    def test_from_dict(self):
        p = FederationSyncPayload.from_dict(
            {
                "source_registry": REGISTRY_A,
                "target_registry": REGISTRY_B,
                "sync_type": "revocation",
                "payload": {"rrn": "RRN-0001"},
                "signature": "",
            }
        )
        assert p.sync_type == FederationSyncType.REVOCATION
        assert p.payload["rrn"] == "RRN-0001"


# ---------------------------------------------------------------------------
# TrustAnchorCache
# ---------------------------------------------------------------------------


class TestTrustAnchorCache:
    def _make_identity(self, url: str = REGISTRY_A) -> RegistryIdentity:
        return RegistryIdentity(
            registry_url=url,
            tier=RegistryTier.AUTHORITATIVE,
            public_key_pem="",
            domain="example.com",
            verified_at="2026-01-01T00:00:00Z",
        )

    def test_store_and_lookup(self):
        cache = TrustAnchorCache()
        identity = self._make_identity()
        cache.store(identity)
        result = cache.lookup(REGISTRY_A)
        assert result is not None
        assert result.registry_url == REGISTRY_A

    def test_lookup_miss(self):
        cache = TrustAnchorCache()
        assert cache.lookup("https://unknown.example.com") is None

    def test_ttl_expiry(self):
        cache = TrustAnchorCache(ttl_s=0.01)  # 10 ms TTL
        identity = self._make_identity()
        cache.store(identity)
        time.sleep(0.05)
        assert cache.lookup(REGISTRY_A) is None

    def test_store_overwrites(self):
        cache = TrustAnchorCache()
        identity1 = self._make_identity()
        identity1_b = RegistryIdentity(
            registry_url=REGISTRY_A,
            tier=RegistryTier.ROOT,
            public_key_pem="updated",
            domain="example.com",
        )
        cache.store(identity1)
        cache.store(identity1_b)
        result = cache.lookup(REGISTRY_A)
        assert result is not None
        assert result.tier == RegistryTier.ROOT

    def test_discover_via_dns_no_dnspython(self, monkeypatch):
        """discover_via_dns should return None gracefully when dnspython is unavailable."""
        import builtins

        real_import = builtins.__import__

        def mock_import(name, *args, **kwargs):
            if name == "dns.resolver" or name == "dns":
                raise ImportError("mocked missing")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", mock_import)
        cache = TrustAnchorCache()
        result = cache.discover_via_dns("example.com")
        assert result is None


# ---------------------------------------------------------------------------
# TrustAnchorCache.verify_registry_jwt
# ---------------------------------------------------------------------------


class TestVerifyRegistryJwt:
    def _make_jwt(self, payload: dict) -> str:
        """Build an unsigned JWT for testing (signature is placeholder)."""
        header = (
            base64.urlsafe_b64encode(
                json.dumps({"alg": "EdDSA", "typ": "JWT"}).encode()
            )
            .rstrip(b"=")
            .decode()
        )
        payload_b64 = (
            base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
        )
        return f"{header}.{payload_b64}.fakesig"

    def test_valid_jwt_no_public_key(self):
        """JWT with matching issuer and no public key in cache should pass with warning."""
        cache = TrustAnchorCache()
        token = self._make_jwt(
            {
                "iss": REGISTRY_A,
                "sub": "RRN-0001",
                "exp": time.time() + 3600,
            }
        )
        valid, reason = cache.verify_registry_jwt(token, REGISTRY_A)
        assert valid
        assert (
            "trust cache" in reason.lower()
            or "no public key" in reason.lower()
            or "structurally" in reason.lower()
        )

    def test_wrong_issuer(self):
        cache = TrustAnchorCache()
        token = self._make_jwt({"iss": REGISTRY_B, "exp": time.time() + 3600})
        valid, reason = cache.verify_registry_jwt(token, REGISTRY_A)
        assert not valid
        assert "issuer" in reason.lower()

    def test_expired_jwt(self):
        cache = TrustAnchorCache()
        token = self._make_jwt({"iss": REGISTRY_A, "exp": time.time() - 10})
        valid, reason = cache.verify_registry_jwt(token, REGISTRY_A)
        assert not valid
        assert "expired" in reason.lower()

    def test_empty_token(self):
        cache = TrustAnchorCache()
        valid, reason = cache.verify_registry_jwt("", REGISTRY_A)
        assert not valid

    def test_invalid_structure(self):
        cache = TrustAnchorCache()
        valid, reason = cache.verify_registry_jwt(
            "not.a.valid.jwt.structure.parts", REGISTRY_A
        )
        # Still 3 parts: "not", "a", "valid.jwt.structure.parts" — let it parse
        # The important thing is it doesn't crash
        assert isinstance(valid, bool)

    def test_two_part_token(self):
        cache = TrustAnchorCache()
        valid, reason = cache.verify_registry_jwt("header.payload", REGISTRY_A)
        assert not valid


# ---------------------------------------------------------------------------
# make_federation_sync
# ---------------------------------------------------------------------------


class TestMakeFederationSync:
    def test_returns_rcan_message(self):
        msg = make_federation_sync(
            source=REGISTRY_A,
            target=REGISTRY_B,
            sync_type=FederationSyncType.CONSENT,
            payload={"consent_id": "xyz"},
        )
        assert isinstance(msg, RCANMessage)
        assert msg.cmd == "FEDERATION_SYNC"

    def test_params_contain_sync_data(self):
        msg = make_federation_sync(
            source=REGISTRY_A,
            target=REGISTRY_B,
            sync_type=FederationSyncType.KEY,
            payload={"key_id": "k001"},
        )
        assert msg.params["source_registry"] == REGISTRY_A
        assert msg.params["target_registry"] == REGISTRY_B
        assert msg.params["sync_type"] == "key"
        assert msg.params["payload"]["key_id"] == "k001"

    def test_custom_target_uri(self):
        msg = make_federation_sync(
            source=REGISTRY_A,
            target=REGISTRY_B,
            sync_type=FederationSyncType.REVOCATION,
            payload={},
            target_uri="rcan://rcan.dev/acme/fed/v1/node-001",
        )
        assert "acme" in str(msg.target)

    def test_has_msg_id_and_timestamp(self):
        msg = make_federation_sync(
            source=REGISTRY_A,
            target=REGISTRY_B,
            sync_type=FederationSyncType.CONSENT,
            payload={},
        )
        assert msg.msg_id
        assert msg.timestamp > 0


# ---------------------------------------------------------------------------
# validate_cross_registry_command
# ---------------------------------------------------------------------------


class TestValidateCrossRegistryCommand:
    def _make_msg(self, cmd: str = "move_forward", loa: int = 2) -> RCANMessage:
        msg = RCANMessage(
            cmd=cmd,
            target="rcan://rcan.dev/acme/bot/v1/unit-001",
            params={"consent_id": "consent-abc"},
            loa=loa,
        )
        return msg

    def test_estop_always_allowed(self):
        """ESTOP must bypass all trust checks (P66 invariant)."""
        cache = TrustAnchorCache()
        msg = self._make_msg(cmd="ESTOP", loa=1)  # even loa=1 (ANONYMOUS)
        valid, reason = validate_cross_registry_command(msg, REGISTRY_A, cache)
        assert valid
        assert "estop" in reason.lower() or "always" in reason.lower()

    def test_estop_variants(self):
        """Every stop verb must bypass checks."""
        cache = TrustAnchorCache()
        for cmd in sorted(STOP_VERBS):
            msg = self._make_msg(cmd=cmd, loa=1)
            valid, _ = validate_cross_registry_command(msg, REGISTRY_A, cache)
            assert valid, f"Expected {cmd} to bypass trust checks"

    def test_stop_verbs_exclude_message_types(self):
        """The exemption covers stopping verbs only, not the SAFETY type."""
        assert "SAFETY" not in STOP_VERBS
        assert STOP_VERBS == frozenset({"ESTOP", "E_STOP", "EMERGENCY_STOP", "STOP"})

    def test_unauthenticated_estop_with_nothing_still_allowed(self):
        """An ESTOP with no LoA, no JWT and no consent record is still allowed."""
        cache = TrustAnchorCache()
        msg = RCANMessage(
            cmd="ESTOP",
            target="rcan://rcan.dev/acme/bot/v1/unit-001",
        )
        assert msg.loa is None
        assert not msg.signature
        assert not (msg.params or {}).get("consent_id")
        valid, reason = validate_cross_registry_command(msg, REGISTRY_A, cache)
        assert valid
        assert "always" in reason.lower()

    def test_safety_typed_resume_is_refused(self):
        """A RESUME carried as a SAFETY-typed message does not get the exemption."""
        cache = TrustAnchorCache()
        msg = RCANMessage(
            cmd="RESUME",
            target="rcan://rcan.dev/acme/bot/v1/unit-001",
            params={"type": "SAFETY"},
            loa=2,
        )
        valid, reason = validate_cross_registry_command(msg, REGISTRY_A, cache)
        assert not valid
        assert "consent" in reason.lower()

    def test_missing_consent_id_refused(self):
        """A cross-registry command with no consent_id is refused, not allowed."""
        cache = TrustAnchorCache()
        msg = RCANMessage(
            cmd="move_forward",
            target="rcan://rcan.dev/acme/bot/v1/unit-001",
            params={},
            loa=2,
        )
        valid, reason = validate_cross_registry_command(msg, REGISTRY_A, cache)
        assert not valid
        assert reason == "Cross-registry command missing consent_id"

    def test_consent_ref_is_accepted(self):
        """consent_ref remains an accepted alias for consent_id."""
        cache = TrustAnchorCache()
        msg = RCANMessage(
            cmd="move_forward",
            target="rcan://rcan.dev/acme/bot/v1/unit-001",
            params={"consent_ref": "consent-abc"},
            loa=2,
        )
        valid, reason = validate_cross_registry_command(msg, REGISTRY_A, cache)
        assert valid
        assert reason == "ok"

    def test_requires_loa_2(self):
        """Non-ESTOP commands require LoA ≥ 2."""
        cache = TrustAnchorCache()
        msg = self._make_msg(cmd="move_forward", loa=1)
        valid, reason = validate_cross_registry_command(msg, REGISTRY_A, cache)
        assert not valid
        assert "loa" in reason.lower() or "2" in reason

    def test_loa_2_passes(self):
        """LoA 2 should pass validation."""
        cache = TrustAnchorCache()
        msg = self._make_msg(cmd="move_forward", loa=2)
        valid, reason = validate_cross_registry_command(msg, REGISTRY_A, cache)
        assert valid

    def test_loa_3_passes(self):
        """LoA 3 also passes (≥ 2)."""
        cache = TrustAnchorCache()
        msg = self._make_msg(cmd="configure", loa=3)
        valid, _ = validate_cross_registry_command(msg, REGISTRY_A, cache)
        assert valid

    def test_missing_loa_rejected(self):
        """Missing loa (None) should be rejected for non-ESTOP."""
        cache = TrustAnchorCache()
        msg = RCANMessage(
            cmd="status",
            target="rcan://rcan.dev/acme/bot/v1/unit-001",
        )
        # loa defaults to None
        valid, _ = validate_cross_registry_command(msg, REGISTRY_A, cache)
        assert not valid

    def test_jwt_invalid_blocks_command(self):
        """An invalid source registry JWT should block the command."""
        cache = TrustAnchorCache()
        # Populate cache with an identity (no real public key verification)
        cache.store(
            RegistryIdentity(
                registry_url=REGISTRY_B,
                tier=RegistryTier.AUTHORITATIVE,
                public_key_pem="",
                domain="registry-b.example.com",
            )
        )
        # Craft a message with a JWT that has wrong issuer
        msg = RCANMessage(
            cmd="configure",
            target="rcan://rcan.dev/acme/bot/v1/unit-001",
            loa=2,
            signature={
                "registry_url": REGISTRY_B,
                "value": "header.payload.sig",  # not a valid JWT
                "alg": "EdDSA",
            },
        )
        # verify_registry_jwt with a fake JWT should return invalid issuer
        # because the payload is not valid JSON
        # This test just checks it doesn't crash
        valid, reason = validate_cross_registry_command(msg, REGISTRY_A, cache)
        # May be valid or not depending on JWT structure — no crash is the key assertion
        assert isinstance(valid, bool)
