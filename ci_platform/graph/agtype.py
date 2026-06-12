"""AGE agtype read-side normalization.

AGE returns property values as agtype-encoded strings:
- Strings are double-quoted: "value" -> value
- Inner quotes are escaped: \" -> "
- JSON stored as TEXT gets double-encoded: "{\"k\": 1}" -> {"k": 1}
- Numbers, booleans, and None pass through unchanged.

This is the READ-side counterpart to AGEClient.serialize_for_age().
"""

from __future__ import annotations

import ast
import re
from typing import Any

_NUMBER_RE = re.compile(r"^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?$")


def _coerce_number(value: str) -> int | float | str:
    if not _NUMBER_RE.fullmatch(value.strip()):
        return value
    if any(char in value for char in ".eE"):
        return float(value)
    return int(value)


def normalize_agtype_value(raw: Any) -> Any:
    """Normalize a single AGE agtype value to a Python value."""
    if raw is None or isinstance(raw, (int, float, bool)):
        return raw
    if not isinstance(raw, str):
        return raw
    if len(raw) >= 2 and raw.startswith('"') and raw.endswith('"'):
        try:
            unquoted = ast.literal_eval(raw)
        except (SyntaxError, ValueError):
            unquoted = raw[1:-1].replace(r"\"", '"')
        if isinstance(unquoted, str):
            return _coerce_number(unquoted)
        return unquoted
    return raw


def normalize_agtype_row(row: tuple[Any, ...], columns: list[str]) -> dict[str, Any]:
    """Convert a psycopg row plus column names to a normalized dict."""
    return {
        column: normalize_agtype_value(row[index])
        for index, column in enumerate(columns)
    }
