"""Tests for rcan.node.NodeClient."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from rcan.exceptions import RCANNodeError
from rcan.node import NodeClient, _parse_rrn_prefix

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _mock_urlopen(response_data: dict | list, status: int = 200):
    """Return a context manager that yields a mock HTTP response."""
    raw = json.dumps(response_data).encode()

    cm = MagicMock()
    resp = MagicMock()
    resp.read.return_value = raw
    resp.status = status
    cm.__enter__ = MagicMock(return_value=resp)
    cm.__exit__ = MagicMock(return_value=False)
    return cm


VALID_MANIFEST = {
    "rcan_node_version": "1.0",
    "node_type": "authoritative",
    "operator": "continuon",
    "namespace_prefix": "BD",
    "public_key": "ed25519:abc123def456",
    "api_base": "https://bd.rcan.dev",
    "capabilities": ["resolve", "register"],
    "ttl_seconds": 3600,
}

ROOT_MANIFEST = {
    "rcan_node_version": "1.0",
    "node_type": "root",
    "operator": "continuon",
    "namespace_prefix": "",
    "public_key": "ed25519:root_key_xyz",
    "api_base": "https://rcan.dev",
    "capabilities": ["resolve", "register", "federation"],
    "ttl_seconds": 86400,
}

SAMPLE_ROBOT = {
    "rrn": "RRN-BD-00000001",
    "uri": "rcan://registry.rcan.dev/acme/arm/v1/unit-001",
    "manufacturer": "acme",
    "model": "arm",
    "version": "v1",
    "device_id": "unit-001",
    "verification_tier": "verified",
    "registered_at": "2025-01-01T00:00:00Z",
}


# ---------------------------------------------------------------------------
# _parse_rrn_prefix
# ---------------------------------------------------------------------------


class TestParseRrnPrefix:
    def test_prefixed_rrn(self):
        assert _parse_rrn_prefix("RRN-BD-00000001") == "BD"

    def test_prefixed_rrn_lowercase(self):
        assert _parse_rrn_prefix("rrn-eu-00000007") == "EU"

    def test_legacy_rrn(self):
        assert _parse_rrn_prefix("RRN-00000042") is None

    def test_invalid_rrn(self):
        with pytest.raises(RCANNodeError):
            _parse_rrn_prefix("NOTANRRN")

    def test_invalid_rrn_no_prefix(self):
        with pytest.raises(RCANNodeError):
            _parse_rrn_prefix("RRN--00000001")


# ---------------------------------------------------------------------------
# verify_node
# ---------------------------------------------------------------------------


class TestVerifyNode:
    def setup_method(self):
        self.client = NodeClient()

    def test_valid_manifest(self):
        assert self.client.verify_node(VALID_MANIFEST) is True

    def test_valid_root_manifest(self):
        assert self.client.verify_node(ROOT_MANIFEST) is True

    def test_missing_required_field(self):
        manifest = dict(VALID_MANIFEST)
        del manifest["public_key"]
        assert self.client.verify_node(manifest) is False

    def test_missing_rcan_node_version(self):
        manifest = dict(VALID_MANIFEST)
        del manifest["rcan_node_version"]
        assert self.client.verify_node(manifest) is False

    def test_missing_api_base(self):
        manifest = dict(VALID_MANIFEST)
        del manifest["api_base"]
        assert self.client.verify_node(manifest) is False

    def test_missing_node_type(self):
        manifest = dict(VALID_MANIFEST)
        del manifest["node_type"]
        assert self.client.verify_node(manifest) is False

    def test_bad_public_key_format(self):
        manifest = dict(VALID_MANIFEST)
        manifest["public_key"] = "rsa:abc123"
        assert self.client.verify_node(manifest) is False

    def test_http_api_base(self):
        manifest = dict(VALID_MANIFEST)
        manifest["api_base"] = "http://bd.rcan.dev"  # not https
        assert self.client.verify_node(manifest) is False

    def test_invalid_node_type(self):
        manifest = dict(VALID_MANIFEST)
        manifest["node_type"] = "supernode"
        assert self.client.verify_node(manifest) is False

    def test_all_valid_node_types(self):
        for nt in ("root", "authoritative", "resolver", "cache"):
            manifest = dict(VALID_MANIFEST)
            manifest["node_type"] = nt
            assert self.client.verify_node(manifest) is True, (
                f"Failed for node_type={nt}"
            )

    def test_non_dict_input(self):
        assert self.client.verify_node("not a dict") is False  # type: ignore[arg-type]

    def test_empty_dict(self):
        assert self.client.verify_node({}) is False


# ---------------------------------------------------------------------------
# get_node_manifest
# ---------------------------------------------------------------------------


class TestGetNodeManifest:
    def setup_method(self):
        self.client = NodeClient()

    @patch("urllib.request.urlopen")
    def test_success(self, mock_urlopen):
        mock_urlopen.return_value = _mock_urlopen(VALID_MANIFEST)
        result = self.client.get_node_manifest("https://bd.rcan.dev")
        assert result["node_type"] == "authoritative"
        assert result["public_key"] == "ed25519:abc123def456"

    @patch("urllib.request.urlopen")
    def test_url_construction(self, mock_urlopen):
        mock_urlopen.return_value = _mock_urlopen(VALID_MANIFEST)
        self.client.get_node_manifest("https://bd.rcan.dev/")
        call_args = mock_urlopen.call_args
        req = call_args[0][0]
        assert req.full_url == "https://bd.rcan.dev/.well-known/rcan-node.json"

    @patch("urllib.request.urlopen")
    def test_network_error_raises_node_error(self, mock_urlopen):
        import urllib.error

        mock_urlopen.side_effect = urllib.error.URLError("connection refused")
        with pytest.raises(RCANNodeError, match="Network error"):
            self.client.get_node_manifest("https://offline.rcan.dev")

    @patch("urllib.request.urlopen")
    def test_http_error_raises_node_error(self, mock_urlopen):
        import urllib.error

        mock_urlopen.side_effect = urllib.error.HTTPError(
            url="https://rcan.dev/.well-known/rcan-node.json",
            code=500,
            msg="Internal Server Error",
            hdrs=None,  # type: ignore[arg-type]
            fp=None,  # type: ignore[arg-type]
        )
        with pytest.raises(RCANNodeError, match="HTTP 500"):
            self.client.get_node_manifest("https://rcan.dev")

    @patch("urllib.request.urlopen")
    def test_invalid_json_raises_node_error(self, mock_urlopen):
        cm = MagicMock()
        resp = MagicMock()
        resp.read.return_value = b"not json {"
        cm.__enter__ = MagicMock(return_value=resp)
        cm.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = cm
        with pytest.raises(RCANNodeError, match="Invalid JSON"):
            self.client.get_node_manifest("https://rcan.dev")


# ---------------------------------------------------------------------------
# list_nodes
# ---------------------------------------------------------------------------


class TestListNodes:
    def setup_method(self):
        self.client = NodeClient()

    @patch("urllib.request.urlopen")
    def test_list_returns_nodes(self, mock_urlopen):
        payload = {"nodes": [VALID_MANIFEST, ROOT_MANIFEST]}
        mock_urlopen.return_value = _mock_urlopen(payload)
        nodes = self.client.list_nodes()
        assert len(nodes) == 2
        assert nodes[0]["namespace_prefix"] == "BD"

    @patch("urllib.request.urlopen")
    def test_bare_list_response(self, mock_urlopen):
        mock_urlopen.return_value = _mock_urlopen([VALID_MANIFEST])
        nodes = self.client.list_nodes()
        assert len(nodes) == 1

    @patch("urllib.request.urlopen")
    def test_network_failure(self, mock_urlopen):
        import urllib.error

        mock_urlopen.side_effect = urllib.error.URLError("no route to host")
        with pytest.raises(RCANNodeError):
            self.client.list_nodes()


# ---------------------------------------------------------------------------
# discover
# ---------------------------------------------------------------------------


class TestDiscover:
    def setup_method(self):
        self.client = NodeClient()

    @patch("urllib.request.urlopen")
    def test_discover_finds_matching_node(self, mock_urlopen):
        payload = {"nodes": [VALID_MANIFEST]}
        mock_urlopen.return_value = _mock_urlopen(payload)
        node = self.client.discover("RRN-BD-00000001")
        assert node["namespace_prefix"] == "BD"
        assert node["api_base"] == "https://bd.rcan.dev"

    @patch("urllib.request.urlopen")
    def test_discover_falls_back_to_root(self, mock_urlopen):
        """When no matching node found, falls back to root manifest."""
        nodes_payload = {"nodes": []}

        def side_effect(req, timeout=None):
            url = req.full_url
            if "nodes?" in url:
                return _mock_urlopen(nodes_payload)
            # .well-known request for root
            return _mock_urlopen(ROOT_MANIFEST)

        mock_urlopen.side_effect = side_effect
        node = self.client.discover("RRN-ZZ-99999999")
        assert node["node_type"] == "root"

    @patch("urllib.request.urlopen")
    def test_discover_legacy_rrn_returns_root(self, mock_urlopen):
        mock_urlopen.return_value = _mock_urlopen(ROOT_MANIFEST)
        node = self.client.discover("RRN-000000000042")
        assert node["node_type"] == "root"

    def test_discover_invalid_rrn(self):
        with pytest.raises(RCANNodeError):
            self.client.discover("INVALID")

    @patch("urllib.request.urlopen")
    def test_discover_network_failure(self, mock_urlopen):
        import urllib.error

        mock_urlopen.side_effect = urllib.error.URLError("offline")
        with pytest.raises(RCANNodeError):
            self.client.discover("RRN-BD-00000001")


# ---------------------------------------------------------------------------
# resolve
# ---------------------------------------------------------------------------


class TestResolve:
    def setup_method(self):
        self.client = NodeClient()

    @patch("urllib.request.urlopen")
    def test_resolve_via_root(self, mock_urlopen):
        """Root's /api/v1/resolve/{rrn} answers directly."""
        mock_urlopen.return_value = _mock_urlopen(SAMPLE_ROBOT)
        robot = self.client.resolve("RRN-BD-00000001")
        assert robot["rrn"] == "RRN-BD-00000001"
        assert robot["manufacturer"] == "acme"

    @patch("urllib.request.urlopen")
    def test_resolve_falls_back_to_authoritative(self, mock_urlopen):
        """Root returns 404; client discovers and fetches from authoritative node."""
        import urllib.error

        nodes_payload = {"nodes": [VALID_MANIFEST]}

        def side_effect(req, timeout=None):
            url = req.full_url
            if "/api/v1/resolve/" in url:
                raise urllib.error.HTTPError(url, 404, "Not Found", None, None)  # type: ignore[arg-type]
            if "/api/v1/nodes?" in url:
                return _mock_urlopen(nodes_payload)
            if url == "https://bd.rcan.dev/robots/RRN-BD-00000001":
                return _mock_urlopen(SAMPLE_ROBOT)
            return _mock_urlopen({})

        mock_urlopen.side_effect = side_effect
        robot = self.client.resolve("RRN-BD-00000001")
        assert robot["rrn"] == "RRN-BD-00000001"

    @patch("urllib.request.urlopen")
    def test_resolve_fallback_uses_api_base_as_given(self, mock_urlopen):
        """{api_base}/robots/{rrn}, without adding a second /api/v1 (rcan.dev's api_base ends in /api/v1)."""
        import urllib.error

        manifest = dict(VALID_MANIFEST, api_base="https://bd.rcan.dev/api/v1")
        seen = []

        def side_effect(req, timeout=None):
            url = req.full_url
            seen.append(url)
            if "/api/v1/resolve/" in url:
                raise urllib.error.HTTPError(url, 404, "Not Found", None, None)  # type: ignore[arg-type]
            if "/api/v1/nodes?" in url:
                return _mock_urlopen({"nodes": [manifest]})
            if url == "https://bd.rcan.dev/api/v1/robots/RRN-BD-00000001":
                return _mock_urlopen(SAMPLE_ROBOT)
            raise urllib.error.HTTPError(url, 404, "Not Found", None, None)  # type: ignore[arg-type]

        mock_urlopen.side_effect = side_effect
        robot = self.client.resolve("RRN-BD-00000001")
        assert robot["rrn"] == "RRN-BD-00000001"
        assert not any("/api/v1/api/v1/" in u for u in seen)

    @patch("urllib.request.urlopen")
    def test_resolve_not_found_raises(self, mock_urlopen):
        """Both root and authoritative return 404."""
        import urllib.error

        nodes_payload = {"nodes": [VALID_MANIFEST]}

        def side_effect(req, timeout=None):
            url = req.full_url
            if "/api/v1/nodes?" in url:
                return _mock_urlopen(nodes_payload)
            raise urllib.error.HTTPError(url, 404, "Not Found", None, None)  # type: ignore[arg-type]

        mock_urlopen.side_effect = side_effect
        with pytest.raises(RCANNodeError, match="not found"):
            self.client.resolve("RRN-BD-00000001")

    @patch("urllib.request.urlopen")
    def test_resolve_network_failure(self, mock_urlopen):
        import urllib.error

        mock_urlopen.side_effect = urllib.error.URLError("no route")
        with pytest.raises(RCANNodeError):
            self.client.resolve("RRN-BD-00000001")


# ---------------------------------------------------------------------------
# Import / __all__ smoke tests
# ---------------------------------------------------------------------------


class TestImports:
    def test_node_client_in_rcan_namespace(self):
        from rcan import NodeClient as NC

        assert NC is NodeClient

    def test_rcan_node_error_in_rcan_namespace(self):
        from rcan import RCANNodeError as RNE

        assert RNE is RCANNodeError

    def test_node_client_instantiation_defaults(self):
        client = NodeClient()
        assert client.root_url == "https://rcan.dev"
        assert client.timeout == 10

    def test_node_client_custom_root(self):
        client = NodeClient(root_url="https://eu.rcan.dev/", timeout=30)
        assert client.root_url == "https://eu.rcan.dev"
        assert client.timeout == 30
