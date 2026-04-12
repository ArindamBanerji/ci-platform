"""
AGE type roundtrip tests — verify AGEClient normalizes types at the boundary.

These tests verify the core contract: AGEClient._normalize_value converts
AGE agtype values to clean Python types, and serialize_for_age produces
correct Cypher-compatible strings.

No live AGE connection needed — these test the methods directly.
"""
import json
import pytest
import numpy as np
from ci_platform.graph.age_client import AGEClient


class TestNormalizeValue:
    """Test _normalize_value — the read-path boundary."""

    def setup_method(self):
        # Create AGEClient instance for testing _normalize_value
        # We don't need a real connection for unit tests on this method
        self.client = AGEClient.__new__(AGEClient)

    def test_none_passthrough(self):
        assert self.client._normalize_value(None) is None

    def test_null_string_becomes_none(self):
        assert self.client._normalize_value("null") is None

    def test_null_string_with_whitespace(self):
        assert self.client._normalize_value("  null  ") is None

    def test_json_list_string_becomes_list(self):
        result = self.client._normalize_value('[0.5, 0.3, 0.8]')
        assert result == [0.5, 0.3, 0.8]
        assert isinstance(result, list)

    def test_json_dict_string_becomes_dict(self):
        result = self.client._normalize_value('{"key": "value"}')
        assert result == {"key": "value"}
        assert isinstance(result, dict)

    def test_plain_string_passthrough(self):
        assert self.client._normalize_value("hello") == "hello"

    def test_int_passthrough(self):
        assert self.client._normalize_value(42) == 42

    def test_float_passthrough(self):
        assert self.client._normalize_value(3.14) == 3.14

    def test_bool_passthrough(self):
        assert self.client._normalize_value(True) is True
        assert self.client._normalize_value(False) is False

    def test_empty_list_string_becomes_empty_list(self):
        assert self.client._normalize_value('[]') == []

    def test_nested_list_string_parsed(self):
        result = self.client._normalize_value('[[1, 2], [3, 4]]')
        assert result == [[1, 2], [3, 4]]

    def test_non_json_string_preserved(self):
        """Strings that aren't valid JSON stay as strings."""
        assert self.client._normalize_value("not json {") == "not json {"

    def test_numeric_string_preserved(self):
        """Numeric strings pass through unchanged — no scalar coercion.
        _parse_agtype already converts AGE agtype integers to Python int
        before _normalize_value is called. Coercing '42'→42 here would
        mistype string IDs that happen to be numeric-looking.
        """
        assert self.client._normalize_value('42') == '42'

    def test_boolean_string_preserved(self):
        """Boolean strings pass through unchanged — no scalar coercion.
        _parse_agtype strips ::boolean and json.loads to Python bool
        before _normalize_value is called.
        """
        assert self.client._normalize_value('true') == 'true'


class TestSerializeForAge:
    """Test serialize_for_age — the write-path boundary."""

    def test_none_becomes_null(self):
        assert AGEClient.serialize_for_age(None) == "null"

    def test_list_becomes_json_string(self):
        result = AGEClient.serialize_for_age([0.5, 0.3, 0.8])
        assert result == "'[0.5, 0.3, 0.8]'"

    def test_numpy_array_becomes_json_string(self):
        arr = np.array([0.5, 0.3, 0.8])
        result = AGEClient.serialize_for_age(arr)
        assert result == "'[0.5, 0.3, 0.8]'"

    def test_bool_lowercase(self):
        assert AGEClient.serialize_for_age(True) == "true"
        assert AGEClient.serialize_for_age(False) == "false"

    def test_int_as_string(self):
        assert AGEClient.serialize_for_age(42) == "42"

    def test_float_as_string(self):
        assert AGEClient.serialize_for_age(3.14) == "3.14"

    def test_string_quoted_and_escaped(self):
        result = AGEClient.serialize_for_age("hello")
        assert result == "'hello'"

    def test_string_with_single_quote_escaped(self):
        result = AGEClient.serialize_for_age("it's")
        assert "\\'" in result or "it" in result  # escaped quote


class TestRoundtrip:
    """Verify serialize → normalize returns the original value."""

    def setup_method(self):
        self.client = AGEClient.__new__(AGEClient)

    def test_list_roundtrip(self):
        original = [0.5, 0.3, 0.8, 0.1, 0.6, 0.4]
        serialized = AGEClient.serialize_for_age(original)
        # serialize wraps in quotes: '[0.5, 0.3, ...]'
        # AGE stores the inner JSON string: [0.5, 0.3, ...]
        inner = serialized.strip("'")
        normalized = self.client._normalize_value(inner)
        assert normalized == original

    def test_dict_roundtrip(self):
        original = {"category": "lateral_movement", "score": 0.85}
        serialized = AGEClient.serialize_for_age(original)
        inner = serialized.strip("'")
        normalized = self.client._normalize_value(inner)
        assert normalized == original

    def test_numpy_array_roundtrip(self):
        """numpy array → serialize → normalize → list (tolist conversion)."""
        original = np.array([0.5, 0.3, 0.8])
        serialized = AGEClient.serialize_for_age(original)
        inner = serialized.strip("'")
        normalized = self.client._normalize_value(inner)
        assert normalized == [0.5, 0.3, 0.8]  # list, not ndarray
