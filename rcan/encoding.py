"""rcan.encoding — Canonical JSON serialization for RCAN wire formats.

This module provides the deterministic JSON serializer used by hybrid
signing (rcan.hybrid) and by any downstream consumer that needs
byte-stable output (e.g., content hashing, cross-language verification).

The format is RFC 8785 (JSON Canonicalization Scheme), as rcan-spec
``spec/audit-bundle-v1.md`` states it, pinned by
``rcan-spec/fixtures/canonical-json-v1.json``:

    - Members sorted by name at every nesting level, comparing names as
      UTF-16 code units (not code points); names that look like numbers are
      compared as strings
    - No whitespace anywhere in the output
    - Numbers are IEEE 754 binary64 values written the way ECMAScript's
      ``Number::toString`` writes them: ``50.0`` -> ``50``, ``-0.0`` -> ``0``,
      ``1e21`` -> ``1e+21``, ``1e-7`` -> ``1e-7``, ``0.000001`` -> ``0.000001``.
      Python ints are converted to the nearest binary64 value first, as every
      JavaScript reader does (``2**53 + 1`` -> ``9007199254740992``)
    - Strings escape only ``"``, ``\\`` and characters below U+0020;
      non-ASCII Unicode is emitted as raw UTF-8 bytes (NOT \\uXXXX escapes)
    - Empty object = {}, empty array = []
    - No trailing newline
    - NaN, Infinity and strings with unpaired surrogates have no canonical form
      and raise :class:`rcan.exceptions.RCANEncodingError`

Both rcan-py and rcan-ts MUST produce identical bytes for the same input.
The cross-language parity fixture is the authoritative test vector.
"""

from __future__ import annotations

import json
import math
import re
from typing import Any

from rcan.exceptions import RCANEncodingError

__all__ = ["canonical_json"]

# Any surrogate code point. Python keeps a valid surrogate pair from JSON text
# as one astral character, so a surrogate left in a str is always unpaired.
_SURROGATE = re.compile("[\ud800-\udfff]")


def _number(x: float) -> str:
    """Write a finite binary64 value as ECMAScript ``Number::toString`` does."""
    if x == 0:
        return "0"  # also -0.0
    sign = "-" if x < 0 else ""
    # repr() gives the shortest digits that round-trip, as ECMAScript requires;
    # only the layout differs, so take the digits and the exponent and lay
    # them out again.
    mantissa, _, exp_text = repr(abs(x)).partition("e")
    int_part, _, frac_part = mantissa.partition(".")
    digits = int_part + frac_part
    point = len(int_part) + (int(exp_text) if exp_text else 0)
    stripped = digits.lstrip("0")
    point -= len(digits) - len(stripped)
    s = stripped.rstrip("0")
    k, n = len(s), point  # value = 0.s * 10**n, s has k digits
    if k <= n <= 21:
        return sign + s + "0" * (n - k)
    if 0 < n <= 21:
        return sign + s[:n] + "." + s[n:]
    if -6 < n <= 0:
        return sign + "0." + "0" * (-n) + s
    e = n - 1
    exponent = ("+" if e >= 0 else "-") + str(abs(e))
    return sign + (s if k == 1 else s[0] + "." + s[1:]) + "e" + exponent


def _string(s: str) -> str:
    if _SURROGATE.search(s):
        raise RCANEncodingError(
            "invalid_string",
            "canonical_json: a string with an unpaired surrogate has no UTF-8 form (RFC 8785 § 3.2.2.2)",
        )
    # json.dumps escapes exactly what RFC 8785 asks for: " \\ and U+0000-U+001F
    # (\b \t \n \f \r by name, the rest as \u00xx in lowercase hex).
    return json.dumps(s, ensure_ascii=False)


def _utf16_key(name: str) -> bytes:
    # Big-endian UTF-16 bytes compare in the same order as the code units.
    return name.encode("utf-16-be")


def _write(v: Any, out: list[str]) -> None:
    if v is None:
        out.append("null")
    elif v is True:
        out.append("true")
    elif v is False:
        out.append("false")
    elif isinstance(v, (int, float)):
        try:
            x = float(v)
        except OverflowError:
            x = math.inf  # an int too large for binary64, as JavaScript reads it
        if not math.isfinite(x):
            raise RCANEncodingError(
                "non_finite_number",
                "canonical_json: NaN and Infinity have no canonical form (RFC 8785 § 3.2.2.3)",
            )
        out.append(_number(x))
    elif isinstance(v, str):
        out.append(_string(v))
    elif isinstance(v, (list, tuple)):
        out.append("[")
        for i, item in enumerate(v):
            if i:
                out.append(",")
            _write(item, out)
        out.append("]")
    elif isinstance(v, dict):
        for name in v:
            if not isinstance(name, str):
                raise TypeError(f"canonical_json: object keys must be strings, not {type(name).__name__}")
            if _SURROGATE.search(name):
                _string(name)  # raises
        out.append("{")
        for i, name in enumerate(sorted(v, key=_utf16_key)):
            if i:
                out.append(",")
            out.append(_string(name))
            out.append(":")
            _write(v[name], out)
        out.append("}")
    else:
        raise TypeError(f"canonical_json: {type(v).__name__} has no JSON form")


def canonical_json(body: dict[str, Any], *, exclude: str | None = None) -> bytes:
    """Return the canonical UTF-8 bytes of ``body``.

    Deterministic: calling this twice on equivalent inputs yields identical
    bytes. Used as the pre-image for hybrid signing in :mod:`rcan.hybrid`
    and as the serialization spine for cross-language wire-format parity.

    Numbers are written as binary64 values in ECMAScript's form, so a body
    containing ``50.0`` signs as ``{"x":50}`` here and in TS alike, and an
    int beyond 2**53 is written as the binary64 value a JavaScript reader
    would see.

    Args:
        body: A dict of JSON values (dict, list, tuple, str, int, float,
            bool, None). Keys MUST be strings.
        exclude: If set, a top-level key to drop from ``body`` before
            serializing. Used by audit-bundle / nested-envelope signing where
            the signature field must not cover itself. Only affects top-level
            keys; nested occurrences are preserved.

    Returns:
        Bytes (UTF-8 encoded).

    Raises:
        RCANEncodingError: ``code`` is ``"non_finite_number"`` for NaN or
            Infinity (including an int too large for binary64), or
            ``"invalid_string"`` for a string or key with an unpaired
            surrogate. RFC 8785 requires both to fail.
        TypeError: for a non-string key or a value that is not JSON.

    Example:
        >>> canonical_json({"b": 1, "a": 2})
        b'{"a":2,"b":1}'
        >>> canonical_json({"x": 50.0})
        b'{"x":50}'
        >>> canonical_json({"a": 1, "sig": "..."}, exclude="sig")
        b'{"a":1}'
    """
    if exclude is not None and isinstance(body, dict):
        body = {k: v for k, v in body.items() if k != exclude}
    out: list[str] = []
    _write(body, out)
    return "".join(out).encode("utf-8")
