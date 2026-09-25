"""Regression tests for AGE Cypher string-literal escaping."""

from __future__ import annotations

import json
from typing import Any, cast

from ci_platform.graph.age_client import AGEClient


def _serialize(value: Any) -> str:
    client = AGEClient(dsn="postgresql://example/test", graph_name="test_graph")
    return cast(str, client._S(value))


def _body(literal: str) -> str:
    assert literal.startswith("'") and literal.endswith("'")
    return literal[1:-1]


def _assert_no_unescaped_quotes(literal: str) -> None:
    body = _body(literal)
    index = 0
    while index < len(body):
        if body[index] == "\\":
            assert index + 1 < len(body), "escaped literal cannot end in a bare backslash"
            index += 2
            continue
        assert body[index] != "'", "string body contains an unescaped quote"
        index += 1


def _decode_body(literal: str) -> str:
    body = _body(literal)
    decoded: list[str] = []
    index = 0
    while index < len(body):
        if body[index] == "\\":
            assert index + 1 < len(body)
            decoded.append(body[index + 1])
            index += 2
        else:
            decoded.append(body[index])
            index += 1
    return "".join(decoded)


def _assert_string_roundtrip(value: str) -> str:
    literal = _serialize(value)
    _assert_no_unescaped_quotes(literal)
    assert _decode_body(literal) == value
    return literal


def test_normal_string() -> None:
    assert _assert_string_roundtrip("hello") == "'hello'"


def test_single_quote() -> None:
    assert _assert_string_roundtrip("it's") == "'it\\'s'"


def test_backslash() -> None:
    assert _assert_string_roundtrip("back\\") == "'back\\\\'"


def test_backslash_quote() -> None:
    literal = _assert_string_roundtrip("\\' injection")
    assert _body(literal).startswith("\\\\\\'")


def test_union_injection() -> None:
    payload = "\\\\' }) RETURN x UNION MATCH (x) RETURN x LIMIT 1 //"
    literal = _assert_string_roundtrip(payload)
    assert "UNION MATCH" in _decode_body(literal)


def test_drop_injection() -> None:
    payload = "'; DROP VERTEX --"
    literal = _assert_string_roundtrip(payload)
    assert _decode_body(literal) == payload


def test_nested_escapes() -> None:
    payload = "\\\\' test"
    literal = _assert_string_roundtrip(payload)
    assert _decode_body(literal) == payload


def test_empty_string() -> None:
    assert _assert_string_roundtrip("") == "''"


def test_none_handling() -> None:
    assert _serialize(None) == "null"


def test_unicode_and_structured_string_roundtrip() -> None:
    assert _assert_string_roundtrip("日本語") == "'日本語'"
    original = ["supplier\\'s invoice", "日本語"]
    literal = _serialize(original)
    _assert_no_unescaped_quotes(literal)
    assert json.loads(_decode_body(literal)) == original
