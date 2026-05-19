"""Deterministic field transformers for enterprise connector profiles."""

from __future__ import annotations

import re
from typing import Any, Callable


def cmdb_criticality_to_float(value: Any) -> float:
    """Map common CMDB criticality labels or 1-5 levels to bounded floats."""
    if isinstance(value, bool):
        raise ValueError(f"Unsupported CMDB criticality: {value!r}")

    numeric_map = {
        1: 0.2,
        2: 0.4,
        3: 0.7,
        4: 1.0,
        5: 1.0,
    }
    if isinstance(value, (int, float)):
        key = int(value)
        if float(value) == float(key) and key in numeric_map:
            return numeric_map[key]
        raise ValueError(f"Unsupported CMDB criticality: {value!r}")

    text = str(value).strip().upper()
    label_map = {
        "LOW": 0.2,
        "MED": 0.4,
        "MEDIUM": 0.4,
        "HIGH": 0.7,
        "CRITICAL": 1.0,
    }
    if text in label_map:
        return label_map[text]
    if re.fullmatch(r"\d+(?:\.0+)?", text):
        return cmdb_criticality_to_float(float(text))
    raise ValueError(f"Unsupported CMDB criticality: {value!r}")


def yes_no_to_bool(value: Any) -> bool:
    """Convert common yes/no style values to bool."""
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    truthy = {"yes", "y", "true", "1"}
    falsey = {"no", "n", "false", "0"}
    if text in truthy:
        return True
    if text in falsey:
        return False
    raise ValueError(f"Unsupported boolean value: {value!r}")


def dn_to_username(value: Any) -> str:
    """Extract the first CN value, then uid value, from an LDAP DN-like string."""
    text = str(value or "").strip()
    if not text:
        return ""

    cn_match = re.search(r"(?:^|,)\s*CN=([^,]+)", text, flags=re.IGNORECASE)
    if cn_match:
        return cn_match.group(1).strip()

    uid_match = re.search(r"(?:^|,)\s*uid=([^,]+)", text, flags=re.IGNORECASE)
    if uid_match:
        return uid_match.group(1).strip()

    return text


def dn_list_to_names(value: Any) -> list[str]:
    """Convert a list/tuple or delimited DN string into extracted names."""
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return [dn_to_username(item) for item in value if str(item or "").strip()]

    text = str(value).strip()
    if not text:
        return []
    if ";" in text:
        parts = [part.strip() for part in text.split(";")]
        return [dn_to_username(part) for part in parts if part]

    starts = [match.start() for match in re.finditer(r"(?i)(?:^|,)\s*(?:CN|uid)=", text)]
    if len(starts) <= 1:
        return [dn_to_username(text)]

    dn_parts: list[str] = []
    for index, start in enumerate(starts):
        start = start + 1 if text[start] == "," else start
        end = starts[index + 1] if index + 1 < len(starts) else len(text)
        part = text[start:end].strip(" ,")
        if part:
            dn_parts.append(part)
    return [dn_to_username(part) for part in dn_parts]


TRANSFORMER_REGISTRY: dict[str, Callable[[Any], Any]] = {
    "cmdb_criticality_to_float": cmdb_criticality_to_float,
    "yes_no_to_bool": yes_no_to_bool,
    "dn_to_username": dn_to_username,
    "dn_list_to_names": dn_list_to_names,
}


def get_transformer(name: str) -> Callable[[Any], Any]:
    """Return a registered transformer by name."""
    try:
        return TRANSFORMER_REGISTRY[name]
    except KeyError as exc:
        raise ValueError(f"Unknown transformer: {name}") from exc
