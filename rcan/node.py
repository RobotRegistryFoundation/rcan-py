"""RCAN Distributed Registry Node client.

Provides :class:`NodeClient` for interacting with the RCAN federated registry
network without any third-party HTTP dependencies (uses ``urllib.request`` only).

Node manifest spec: ``/.well-known/rcan-node.json``

Example::

    from rcan.node import NodeClient

    client = NodeClient()
    node = client.discover("RRN-BD-00000001")
    robot = client.resolve("RRN-BD-00000001")
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Optional

from rcan.exceptions import RCANNodeError

__all__ = ["NodeClient"]

_VALID_NODE_TYPES = {"root", "authoritative", "resolver", "cache"}
_REQUIRED_NODE_FIELDS = {"rcan_node_version", "node_type", "public_key", "api_base"}

# Pattern: RRN-<PREFIX>-<SERIAL>  or legacy RRN-<SERIAL>
# PREFIX: [A-Z0-9]{2,8} (alphanumeric, up to 8 chars)
# SERIAL: [0-9]{8,16} (8–16 digits for 10^16 capacity per namespace)
_RRN_PREFIXED = re.compile(r"^RRN-([A-Z0-9]{2,8})-(\d{8,16})$", re.IGNORECASE)
_RRN_LEGACY = re.compile(r"^RRN-(\d{8,16})$", re.IGNORECASE)


def _http_get(url: str, timeout: int) -> dict[str, Any]:
    """Perform a simple GET request and return parsed JSON.

    Raises:
        RCANNodeError: On network error, timeout, or non-200 HTTP status.
    """
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "rcan-py/node-client", "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            return json.loads(raw)
    except urllib.error.HTTPError as exc:
        raise RCANNodeError(f"HTTP {exc.code} fetching {url}: {exc.reason}") from exc
    except urllib.error.URLError as exc:
        raise RCANNodeError(f"Network error fetching {url}: {exc.reason}") from exc
    except TimeoutError as exc:
        raise RCANNodeError(f"Timeout fetching {url}") from exc
    except json.JSONDecodeError as exc:
        raise RCANNodeError(f"Invalid JSON response from {url}: {exc}") from exc
    except Exception as exc:
        raise RCANNodeError(f"Unexpected error fetching {url}: {exc}") from exc


def _http_get_optional(url: str, timeout: int) -> Optional[dict[str, Any]]:
    """Like ``_http_get`` but returns ``None`` on 404."""
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "rcan-py/node-client", "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            return json.loads(raw)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        raise RCANNodeError(f"HTTP {exc.code} fetching {url}: {exc.reason}") from exc
    except urllib.error.URLError as exc:
        raise RCANNodeError(f"Network error fetching {url}: {exc.reason}") from exc
    except TimeoutError as exc:
        raise RCANNodeError(f"Timeout fetching {url}") from exc
    except json.JSONDecodeError as exc:
        raise RCANNodeError(f"Invalid JSON response from {url}: {exc}") from exc
    except Exception as exc:
        raise RCANNodeError(f"Unexpected error fetching {url}: {exc}") from exc


def _parse_rrn_prefix(rrn: str) -> Optional[str]:
    """Extract the namespace prefix from an RRN string.

    Examples::

        >>> _parse_rrn_prefix("RRN-BD-00000001")
        'BD'
        >>> _parse_rrn_prefix("RRN-000000000001")
        None
    """
    m = _RRN_PREFIXED.match(rrn)
    if m:
        return m.group(1).upper()
    if _RRN_LEGACY.match(rrn):
        return None
    raise RCANNodeError(
        f"Invalid RRN format: {rrn!r}. Expected RRN-<PREFIX>-<SERIAL> or RRN-<SERIAL>."
    )


class NodeClient:
    """Client for interacting with RCAN distributed registry nodes.

    Uses only ``urllib.request`` — no third-party dependencies.

    Args:
        root_url: Base URL of the root registry node (default: https://rcan.dev).
        timeout:  HTTP request timeout in seconds.

    Example::

        client = NodeClient()
        manifest = client.get_node_manifest("https://eu.rcan.dev")
        nodes = client.list_nodes()
        robot = client.resolve("RRN-EU-00000007")
    """

    ROOT_NODE_URL = "https://rcan.dev"

    def __init__(
        self,
        root_url: str = ROOT_NODE_URL,
        timeout: int = 10,
    ) -> None:
        self.root_url = root_url.rstrip("/")
        self.timeout = timeout

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_node_manifest(self, node_url: str) -> dict[str, Any]:
        """Fetch ``/.well-known/rcan-node.json`` from *node_url*.

        Args:
            node_url: Base URL of the registry node.

        Returns:
            Parsed node manifest dict.

        Raises:
            RCANNodeError: On network failure or bad response.
        """
        url = node_url.rstrip("/") + "/.well-known/rcan-node.json"
        return _http_get(url, self.timeout)

    def list_nodes(self) -> list[dict[str, Any]]:
        """Get list of known registry nodes from the root node.

        Returns:
            List of node manifest dicts.

        Raises:
            RCANNodeError: On network failure or bad response.
        """
        url = f"{self.root_url}/api/v1/nodes"
        data = _http_get(url, self.timeout)
        # API may return {"nodes": [...]} or a bare list
        if isinstance(data, list):
            return data
        return data.get("nodes", [])

    def discover(self, rrn: str) -> dict[str, Any]:
        """Find the authoritative registry node for *rrn*.

        Parses the namespace prefix from the RRN, queries the root node's
        ``/api/v1/nodes?prefix=<PREFIX>`` endpoint, and returns the matching
        node manifest.  Falls back to the root node manifest if no match is
        found.

        Args:
            rrn: Robot Registry Number, e.g. ``"RRN-BD-00000001"``.

        Returns:
            Registry node manifest dict.

        Raises:
            RCANNodeError: On invalid RRN format or network failure.
        """
        prefix = _parse_rrn_prefix(rrn)

        if prefix is None:
            # Legacy RRN with no prefix — root is authoritative
            return self.get_node_manifest(self.root_url)

        url = f"{self.root_url}/api/v1/nodes?prefix={urllib.parse.quote(prefix)}"
        data = _http_get(url, self.timeout)

        nodes: list[dict[str, Any]]
        if isinstance(data, list):
            nodes = data
        else:
            nodes = data.get("nodes", [])

        # Find a node whose namespace_prefix matches
        for node in nodes:
            np = (node.get("namespace_prefix") or "").upper()
            if np == prefix:
                return node

        # No specific match — fall back to root manifest
        return self.get_node_manifest(self.root_url)

    def resolve(self, rrn: str) -> dict[str, Any]:
        """Resolve an RRN to a robot record, following federation.

        Resolution strategy:

        1. Try ``{root}/api/v1/resolve/{rrn}`` — the root node may answer
           directly or proxy to the authoritative node.
        2. If that returns 404, call :meth:`discover` to find the authoritative
           node, then fetch ``{authoritative_node}/api/v1/robots/{rrn}``.

        Args:
            rrn: Robot Registry Number to resolve.

        Returns:
            Robot record dict.

        Raises:
            RCANNodeError: If the robot is not found or network fails.
        """
        resolve_url = (
            f"{self.root_url}/api/v1/resolve/{urllib.parse.quote(rrn, safe='')}"
        )
        result = _http_get_optional(resolve_url, self.timeout)
        if result is not None:
            return result

        # Root returned 404 — find the authoritative node and ask directly
        auth_node = self.discover(rrn)
        # api_base is the registry API's base URL, endpoints included (federation protocol:
        # GET {api_base}/robots/{rrn}); e.g. rcan.dev publishes "https://rcan.dev/api/v1".
        api_base = (auth_node.get("api_base") or f"{self.root_url}/api/v1").rstrip("/")
        robot_url = f"{api_base}/robots/{urllib.parse.quote(rrn, safe='')}"
        robot = _http_get_optional(robot_url, self.timeout)
        if robot is None:
            raise RCANNodeError(
                f"RRN not found: {rrn!r} — checked root and authoritative node at {api_base}"
            )
        return robot

    def verify_node(self, node_manifest: dict[str, Any]) -> bool:
        """Verify that *node_manifest* is well-formed.

        Checks:

        * All required fields are present (``rcan_node_version``, ``node_type``,
          ``public_key``, ``api_base``).
        * ``public_key`` starts with ``"ed25519:"``.
        * ``api_base`` starts with ``"https://"``.
        * ``node_type`` is one of ``root | authoritative | resolver | cache``.

        Args:
            node_manifest: Dict parsed from a node's ``/.well-known/rcan-node.json``.

        Returns:
            ``True`` if the manifest is valid, ``False`` otherwise.
        """
        if not isinstance(node_manifest, dict):
            return False

        # Required fields
        for field in _REQUIRED_NODE_FIELDS:
            if not node_manifest.get(field):
                return False

        # public_key format
        if not str(node_manifest.get("public_key", "")).startswith("ed25519:"):
            return False

        # api_base must be HTTPS
        if not str(node_manifest.get("api_base", "")).startswith("https://"):
            return False

        # node_type must be in valid set
        if node_manifest.get("node_type") not in _VALID_NODE_TYPES:
            return False

        return True
