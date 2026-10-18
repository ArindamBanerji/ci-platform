"""Primitive AGE bounded-query compiler and canonical Decision normalization.

This layer deliberately has no SDK imports. Identifiers come only from closed
manifests; all data literals are serialized by the supplied AGEClient._S.
"""
from __future__ import annotations

import json
import math
from copy import deepcopy
from datetime import datetime, timezone
from types import MappingProxyType
from typing import Any, Callable, Mapping

SUMMARY_FIELDS = (
    "decision_id", "domain", "category", "recommended_action", "status",
    "confidence", "created_at", "verified_at", "is_correct", "correct",
)
SCORING_FIELDS = SUMMARY_FIELDS + (
    "category_index", "recommended_index", "factor_vector", "factor_names",
    "factors", "probabilities", "actual_action", "actual_index", "source",
    "scorer_version", "preset_version", "factor_schema_version", "outcome",
    "verified_at_epoch", "quality_signal", "was_override", "analyst_action",
    "final_action", "learning_metadata",
)
JOURNAL_FIELDS = SUMMARY_FIELDS + (
    "trade_id", "entry_id", "ticker", "regime", "entry_time", "exit_time",
    "entry_price", "exit_price", "size", "pnl", "strategy_tag", "tags",
    "source", "reflection", "notes", "factors", "options_factors",
)
LEARNING_FIELDS = ("reward", "verifier", "override_reason", "variant_id", "regime_tag")
FIELDS = tuple(dict.fromkeys(SCORING_FIELDS + JOURNAL_FIELDS + ("tenant_id",)))
COLLECTIONS = MappingProxyType({
    "categories": "category", "actions": "recommended_action", "statuses": "status",
    "sources": "source", "regimes": "regime", "decision_ids": "decision_id",
})
GROUPS = MappingProxyType({"category": "category", "action": "recommended_action", "status": "status", "regime": "regime"})
METRICS = ("count", "correct_count", "avg_confidence")
JSON_FIELDS = frozenset({"factor_vector", "factor_names", "factors", "probabilities", "learning_metadata", "tags", "options_factors"})
VERIFIED = "coalesce(d.status, '') IN ['confirmed', 'overridden']"
ACTIVE = "(d.archived IS NULL OR d.archived <> true)"
Serializer = Callable[[Any], str]


class GenerationChanged(RuntimeError):
    def __init__(self, expected: int, actual: int) -> None:
        self.expected, self.actual = expected, actual
        super().__init__(f"Domain generation changed: expected {expected}, actual {actual}")


class CardinalityExceeded(RuntimeError):
    def __init__(self, count: int, limit: int = 1000) -> None:
        self.count, self.limit = count, limit
        super().__init__(f"Aggregate produced {count} groups, exceeding {limit}")


def integer(value: Any, name: str, minimum: int = 0, maximum: int | None = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum or (maximum is not None and value > maximum):
        raise ValueError(f"invalid {name}: {value!r}")
    return value


def timestamp(value: Any) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool):
        raise ValueError("ambiguous Boolean timestamp")
    if isinstance(value, str):
        try:
            value = float(value)
        except ValueError:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                raise ValueError("ambiguous timestamp without timezone")
            value = parsed.astimezone(timezone.utc).timestamp()
    result = float(value)
    if not math.isfinite(result):
        raise ValueError("timestamp must be finite")
    return result


def decode(value: Any) -> Any:
    if isinstance(value, str):
        try:
            return json.loads(value)
        except ValueError:
            return value
    return value


def number(value: Any) -> float | None:
    try:
        return None if value is None else float(value)
    except (TypeError, ValueError):
        return None


def normalize(decision: Mapping[str, Any], outcome: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Normalize same-graph evidence, preserving originals for full projections."""
    raw = {k: deepcopy(v) for k, v in decision.items() if not k.startswith("_bp_") and k not in {"_age_id", "_sequence", "_generation"}}
    for name in JSON_FIELDS | {"metadata"}:
        if name in raw:
            raw[name] = decode(raw[name])
    factors = raw.get("factors")
    factors = factors if isinstance(factors, dict) else {}
    nested = factors.get("metadata")
    metadata = raw.get("metadata")
    metadata = metadata if isinstance(metadata, dict) else {}
    journal_meta = {**(nested if isinstance(nested, dict) else {}), **metadata}

    def value(name: str) -> Any:
        v = raw.get(name)
        return metadata.get(name) if v is None else v

    def journal(name: str) -> Any:
        v = raw.get(name)
        return journal_meta.get(name) if v is None else v

    result = dict(raw)
    for name in FIELDS:
        result[name] = value(name)
    result["tenant_id"] = str(value("tenant_id") or "default")
    if result["ticker"] is not None:
        result["ticker"] = str(result["ticker"]).upper()
    if result["regime"] is None:
        result["regime"] = raw.get("market_regime") or metadata.get("market_regime")
    pnl = next((v for candidate in (raw.get("pnl"), journal_meta.get("pnl"), journal_meta.get("pnl_dollars")) if (v := number(candidate)) is not None), None)
    size = number(journal("size") if journal("size") is not None else journal_meta.get("shares"))
    result.update(pnl=0.0 if pnl is None else pnl, size=int(size) if size is not None and math.isfinite(size) else 0)
    tags = journal("tags")
    result["tags"] = sorted({str(t).strip() for t in tags if str(t).strip()}) if isinstance(tags, list) else []
    reflection = raw.get("reflection") or raw.get("notes") or journal_meta.get("reflection") or journal_meta.get("notes")
    notes = raw.get("notes") or journal_meta.get("notes") or reflection
    trade_id = raw.get("trade_id") or journal_meta.get("trade_id") or raw.get("decision_id") or journal_meta.get("decision_id")
    texts = {
        "reflection": reflection, "notes": notes, "trade_id": trade_id,
        "entry_id": raw.get("entry_id") or journal_meta.get("entry_id") or trade_id,
        "entry_time": raw.get("entry_time") or journal_meta.get("entry_time") or journal_meta.get("date"),
        "exit_time": raw.get("exit_time") or journal_meta.get("exit_time"),
    }
    result.update({k: None if v is None else str(v) for k, v in texts.items()})
    for name in ("entry_price", "exit_price"):
        result[name] = number(journal(name))
    result["strategy_tag"] = raw.get("strategy_tag") or journal_meta.get("strategy_tag") or journal_meta.get("strategy") or journal_meta.get("thesis_type")
    result["options_factors"] = next((v for v in (raw.get("options_factors"), journal_meta.get("options_factors"), factors.get("options_factors")) if isinstance(v, dict)), None)
    verified = raw.get("status") in {"confirmed", "overridden"}
    result["correct"] = result["is_correct"] = raw.get("correct") if verified else None
    result["created_at"] = timestamp(raw.get("created_at"))
    result["confidence"] = number(raw.get("confidence"))
    for name in ("actual_action", "actual_index", "verified_at"):
        result[name] = (outcome or {}).get(name) if verified else None
    result["verified_at"] = timestamp(result["verified_at"])
    result["outcome_metadata"] = decode((outcome or {}).get("metadata")) if verified else None
    return result


def project(record: Mapping[str, Any], projection: str) -> dict[str, Any]:
    if projection == "full":
        return deepcopy(dict(record))
    fields = {"summary": SUMMARY_FIELDS, "scoring": SCORING_FIELDS, "journal": JOURNAL_FIELDS}.get(projection)
    if fields is None:
        raise ValueError(f"invalid projection: {projection}")
    result = {k: deepcopy(record.get(k)) for k in fields}
    if projection == "scoring" and isinstance(result["learning_metadata"], dict):
        result["learning_metadata"] = {k: v for k, v in result["learning_metadata"].items() if k in LEARNING_FIELDS}
    return result


def validate_filters(filters: Mapping[str, Any], *, routing_only: bool = False) -> None:
    allowed = set(COLLECTIONS) | {"exclude_decision_ids", "ticker", "tenant_id", "verified", "correct", "exclude_legacy_signals", "confidence_min", "confidence_max", "created_from", "created_to", "verified_from", "verified_to"}
    if set(filters) - allowed:
        raise ValueError("unknown filter")
    for name, value in filters.items():
        default = () if name in set(COLLECTIONS) | {"exclude_decision_ids"} else None
        if routing_only and name not in {"tenant_id", "exclude_legacy_signals"} and value != default:
            raise ValueError("change feed accepts routing filters only")
        if name in set(COLLECTIONS) | {"exclude_decision_ids"}:
            if not isinstance(value, tuple) or not all(isinstance(v, str) for v in value):
                raise ValueError(f"{name} must be a tuple of strings")
        elif name in {"verified", "correct", "exclude_legacy_signals"}:
            if value is not None and not isinstance(value, bool):
                raise ValueError(f"{name} must be Boolean")
        elif name in {"ticker", "tenant_id"}:
            if value is not None and not isinstance(value, str):
                raise ValueError(f"{name} must be a string")
        elif value is not None and (isinstance(value, bool) or not isinstance(value, (float, int)) or not math.isfinite(value)):
            raise ValueError(f"{name} must be finite")


def predicates(domain: str, filters: Mapping[str, Any], S: Serializer) -> str:
    if not isinstance(domain, str) or not domain.strip():
        raise ValueError("domain must be a nonempty string")
    validate_filters(filters)
    clauses = [f"d.domain = {S(domain)}", ACTIVE]
    for name, field in COLLECTIONS.items():
        values = filters.get(name, ())
        if values:
            clauses.append(f"d._bp_{field} IN [" + ", ".join(S(v) for v in values) + "]")
    excluded = filters.get("exclude_decision_ids", ())
    if excluded:
        clauses.append("NOT (d.decision_id IN [" + ", ".join(S(v) for v in excluded) + "])")
    for name in ("tenant_id", "ticker"):
        v = filters.get(name)
        if v is not None:
            clauses.append(f"d._bp_{name} = {S(v.upper() if name == 'ticker' else v)}")
    if filters.get("exclude_legacy_signals"):
        clauses.append("d._bp_legacy = false")
    verified = filters.get("verified")
    if verified is not None:
        clauses.append(VERIFIED if verified else f"NOT ({VERIFIED})")
    if filters.get("correct") is not None:
        clauses.extend([VERIFIED, f"d.correct = {S(filters['correct'])}"])
    for name, op in (("confidence_min", ">="), ("confidence_max", "<=")):
        if filters.get(name) is not None:
            # AGE/PostgreSQL can total-order NaN; explicit canonical eligibility
            # is required in addition to positive inclusive comparisons.
            infinity = "positive_infinity" if name == "confidence_min" else "negative_infinity"
            clauses.append(f"(d._bp_confidence_kind = {S(infinity)} OR (d._bp_confidence_kind = {S('finite')} AND d._bp_confidence_number {op} {S(filters[name])}))")
    for field in ("created", "verified"):
        for suffix, op in (("from", ">="), ("to", "<")):
            v = filters.get(f"{field}_{suffix}")
            if v is not None:
                if field == "verified":
                    clauses.append(VERIFIED)
                clauses.append(f"d._bp_{field}_at {op} {S(v)}")
    return " AND ".join(clauses)


def query(domain: str, filters: Mapping[str, Any], S: Serializer, *, projection: str = "summary", order_by: str = "created_at", descending: bool = True, limit: int = 100, offset: int = 0, after: tuple[float, str] | None = None) -> str:
    integer(limit, "limit", 1)
    integer(offset, "offset")
    if order_by not in {"created_at", "verified_at"} or not isinstance(descending, bool):
        raise ValueError("invalid order")
    if after is not None and offset:
        raise ValueError("cursor and offset are mutually exclusive")
    fields = {"summary": SUMMARY_FIELDS, "scoring": SCORING_FIELDS, "journal": JOURNAL_FIELDS}.get(projection)
    if fields is None and projection != "full":
        raise ValueError("invalid projection")
    where = predicates(domain, filters, S)
    if order_by == "verified_at":
        where += " AND " + VERIFIED
    key = f"coalesce(d._bp_{order_by}, 0.0)"
    cursor = ""
    if after is not None:
        value, decision_id = after
        if timestamp(value) is None or not isinstance(decision_id, str) or not decision_id:
            raise ValueError("invalid cursor")
        op = "<" if descending else ">"
        cursor = f"WHERE (_sort {op} {S(value)} OR (_sort = {S(value)} AND d.decision_id {op} {S(decision_id)}))"
    selected = "properties(d) AS _decision, properties(o) AS _outcome" if fields is None else ", ".join(f"d._bp_{name} AS {name}" for name in fields)
    direction = "DESC" if descending else "ASC"
    join = "OPTIONAL MATCH (d)-[:HAS_OUTCOME]->(o:Outcome)" if fields is None else ""
    with_vars = "d, o" if fields is None else "d"
    return f"MATCH (d:Decision) WHERE {where} {join} WITH {with_vars}, {key} AS _sort {cursor} RETURN {selected}, _sort AS _cursor_value, d.decision_id AS _cursor_id ORDER BY _cursor_value {direction}, _cursor_id {direction} SKIP {S(offset)} LIMIT {S(limit + 1)}"


def aggregate(domain: str, filters: Mapping[str, Any], S: Serializer, group_by: tuple[str, ...], metrics: tuple[str, ...]) -> str:
    if not isinstance(group_by, tuple) or not isinstance(metrics, tuple):
        raise ValueError("group_by and metrics must be tuples")
    if len(set(group_by)) != len(group_by) or any(g not in GROUPS for g in group_by):
        raise ValueError("invalid or duplicate group dimension")
    if len(set(metrics)) != len(metrics) or any(m not in METRICS for m in metrics):
        raise ValueError("invalid or duplicate metric")
    expressions = [f"d._bp_{GROUPS[g]} AS {g}" for g in group_by]
    expressions += ["count(d) AS _count"]
    if "correct_count" in metrics:
        expressions.append(f"sum(CASE WHEN {VERIFIED} AND d.correct = true THEN 1 ELSE 0 END) AS correct_count")
    if "avg_confidence" in metrics:
        expressions.append("avg(coalesce(d._bp_confidence_number, 0.0)) AS avg_confidence")
        for kind in ("nan", "positive_infinity", "negative_infinity"):
            expressions.append(f"sum(CASE WHEN d._bp_confidence_kind = {S(kind)} THEN 1 ELSE 0 END) AS _{kind}")
    ordering = " ORDER BY " + ", ".join(group_by) if group_by else ""
    return f"MATCH (d:Decision) WHERE {predicates(domain, filters, S)} RETURN {', '.join(expressions)}{ordering} LIMIT {S(1001)}"
