"""Tests for rcan.encoding — canonical JSON serialization."""
from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from rcan.encoding import canonical_json


FIXTURE = Path(__file__).parent / "fixtures" / "canonical-json-v1.json"


def test_canonical_json_matches_fixture():
    """CRITICAL: rcan-py's canonical_json bytes MUST match the shared fixture exactly.

    If this test fails, either (a) the fixture was regenerated with different
    semantics, or (b) rcan-py drifted. Investigate immediately; do not edit
    the fixture or the test.
    """
    fixture = json.loads(FIXTURE.read_text())
    assert fixture["format"] == "rcan-canonical-json-v1"
    for case in fixture["cases"]:
        actual = canonical_json(case["input"])
        expected = base64.b64decode(case["expected_bytes_base64"])
        assert actual == expected, (
            f"canonical_json drift on case {case['name']!r}:\n"
            f"  expected: {expected!r}\n"
            f"  actual:   {actual!r}"
        )


def test_canonical_json_key_order():
    assert canonical_json({"b": 1, "a": 2}) == b'{"a":2,"b":1}'


def test_canonical_json_no_whitespace():
    assert canonical_json({"a": [1, 2, 3]}) == b'{"a":[1,2,3]}'


def test_canonical_json_unicode_raw_utf8():
    """Non-ASCII MUST be emitted as raw UTF-8 bytes, not \\uXXXX escape sequences."""
    out = canonical_json({"name": "Café"})
    assert out == '{"name":"Café"}'.encode("utf-8")
    assert b"\\u" not in out


def test_canonical_json_nested_sort():
    """Key ordering applies at every nesting level."""
    assert canonical_json({"z": {"b": 2, "a": 1}}) == b'{"z":{"a":1,"b":2}}'


def test_canonical_json_empty_containers():
    assert canonical_json({"a": {}, "b": []}) == b'{"a":{},"b":[]}'


def test_canonical_json_returns_bytes():
    """Return type MUST be bytes, not str — downstream hashes/signs it directly."""
    result = canonical_json({"a": 1})
    assert isinstance(result, bytes)


def test_canonical_json_fixture_error_cases():
    """Inputs with no canonical form (NaN, Infinity, unpaired surrogates) MUST raise."""
    from rcan.exceptions import RCANEncodingError

    fixture = json.loads(FIXTURE.read_text())
    assert fixture["error_cases"], "fixture has no error_cases"
    for case in fixture["error_cases"]:
        with pytest.raises(RCANEncodingError) as info:
            canonical_json(json.loads(case["input_json"]))
        assert info.value.code == case["expected_error"], case["name"]


def test_canonical_json_keys_sort_by_utf16_code_units():
    """U+1F600 is the pair D83D DE00, which sorts before U+E000 (code-point order puts it after)."""
    out = canonical_json({"": 1, "\U0001F600": 2})
    assert out == '{"\U0001F600":2,"":1}'.encode("utf-8")


def test_canonical_json_numbers_are_ecmascript_form():
    out = canonical_json({"n": [1e21, 1e-7, 1e16, 0.000001, 0.00005, 1.5e-10, -0.0, 50.0, 123.456]})
    assert out == b'{"n":[1e+21,1e-7,10000000000000000,0.000001,0.00005,1.5e-10,0,50,123.456]}'


def test_canonical_json_ints_are_binary64():
    """JavaScript reads every number as binary64, so Python ints are rounded the same way."""
    assert canonical_json({"n": [2**53 + 1, -(2**53 + 1)]}) == b'{"n":[9007199254740992,-9007199254740992]}'


def test_canonical_json_non_finite_and_surrogates_raise():
    from rcan.exceptions import RCANEncodingError

    for bad in ({"x": float("nan")}, {"x": [float("inf")]}, {"x": 10**400}, {"x": "\ud800"}, {"\udc00": 1}):
        with pytest.raises(RCANEncodingError):
            canonical_json(bad)
    # Also a ValueError, like json.dumps(..., allow_nan=False).
    with pytest.raises(ValueError):
        canonical_json({"x": float("inf")})


def test_canonical_json_rejects_non_string_keys():
    with pytest.raises(TypeError):
        canonical_json({1: "a"})
