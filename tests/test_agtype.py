from __future__ import annotations

from ci_platform.graph.agtype import normalize_agtype_row, normalize_agtype_value


def test_plain_string():
    assert normalize_agtype_value('"trend_following"') == "trend_following"


def test_json_string():
    assert normalize_agtype_value('"{\\"key\\": 0.69}"') == '{"key": 0.69}'


def test_nested_quotes():
    assert normalize_agtype_value('"said \\"hello\\""') == 'said "hello"'


def test_number_int():
    assert normalize_agtype_value(42) == 42


def test_number_float():
    assert normalize_agtype_value(0.75) == 0.75


def test_boolean_true():
    assert normalize_agtype_value(True) is True


def test_boolean_false():
    assert normalize_agtype_value(False) is False


def test_none():
    assert normalize_agtype_value(None) is None


def test_unquoted_string():
    assert normalize_agtype_value("already_clean") == "already_clean"


def test_empty_quoted():
    assert normalize_agtype_value('""') == ""


def test_json_with_apostrophe():
    assert normalize_agtype_value('"{\\"name\\": \\"O\\\'Brien\\"}"') == '{"name": "O\'Brien"}'


def test_json_with_unicode():
    assert normalize_agtype_value('"{\\"text\\": \\"café ñ\\"}"') == '{"text": "café ñ"}'


def test_json_array():
    assert normalize_agtype_value('"[0.1, 0.2, 0.3]"') == "[0.1, 0.2, 0.3]"


def test_row_normalizes_all_values():
    row = ('"trend_following"', '"{\\"key\\": 0.69}"')
    assert normalize_agtype_row(row, ["category", "factors_json"]) == {
        "category": "trend_following",
        "factors_json": '{"key": 0.69}',
    }


def test_row_handles_mixed_types():
    row = ('"already"', 7, None)
    assert normalize_agtype_row(row, ["name", "count", "missing"]) == {
        "name": "already",
        "count": 7,
        "missing": None,
    }
