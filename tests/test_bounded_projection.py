"""Compiler tests do not require an AGE server or the SDK at runtime."""
from dataclasses import asdict

import pytest

from ci_platform.graph import bounded_projection as bp
from ci_platform.graph.age_client import AGEClient
from copilot_sdk.graph.query import DecisionFilter


def S(value):
    return AGEClient._S(None, value)


@pytest.mark.parametrize("projection,fields", [("summary", bp.SUMMARY_FIELDS), ("scoring", bp.SCORING_FIELDS), ("journal", bp.JOURNAL_FIELDS)])
def test_projection_manifest_matches_shipped_contract(projection, fields):
    from copilot_sdk.graph import query
    assert fields == getattr(query, projection.upper() + "_FIELDS")
    compiled = bp.query("domain", {}, S, projection=projection)
    assert "properties(d)" not in compiled
    for name in fields:
        assert f"d._bp_{name} AS {name}" in compiled


def test_predicate_and_sort_compiler():
    query = bp.query("domain", {"categories": ("a", "b"), "actions": ("buy",), "confidence_min": 0, "confidence_max": 1, "created_from": 1, "created_to": 2}, S, order_by="verified_at", descending=False, after=(3, "id"), limit=7)
    assert "d._bp_category IN ['a', 'b']" in query
    assert "d._bp_recommended_action IN ['buy']" in query
    assert "d._bp_created_at >= 1" in query and "d._bp_created_at < 2" in query
    assert "d._bp_confidence_kind = 'finite'" in query
    assert "d._bp_confidence_number >= 0" in query and "d._bp_confidence_number <= 1" in query
    assert "coalesce(d._bp_verified_at, 0.0)" in query
    assert "ORDER BY _cursor_value ASC, _cursor_id ASC" in query and "LIMIT 8" in query
    assert "_sequence" not in query


@pytest.mark.parametrize("group_by,metrics", [(("bad",), ("count",)), (("category", "category"), ("count",)), ((), ("bad",)), ((), ("count", "count"))])
def test_aggregate_validation(group_by, metrics):
    with pytest.raises(ValueError):
        bp.aggregate("domain", {}, S, group_by, metrics)


def test_aggregate_is_native_and_capped():
    q = bp.aggregate("domain", {}, S, ("action",), ("count", "correct_count", "avg_confidence"))
    assert "d._bp_recommended_action AS action" in q
    assert "count(d)" in q and "avg(coalesce(d._bp_confidence_number, 0.0))" in q and "LIMIT 1001" in q


@pytest.mark.parametrize("filters", [DecisionFilter(verified=False), DecisionFilter(correct=False), DecisionFilter(confidence_min=0), DecisionFilter(categories=("x",))])
def test_feed_rejects_all_nondefault_nonrouting_filters(filters):
    with pytest.raises(ValueError, match="routing"):
        bp.validate_filters(asdict(filters), routing_only=True)


def test_empty_filters_and_normalization():
    assert bp.predicates("d", {}, S) == bp.predicates("d", asdict(DecisionFilter()), S)
    record = bp.normalize({"decision_id": "d", "metadata": {"pnl": "12.50", "size": "2", "tags": [" a ", "a", "b"], "notes": "reflection", "strategy": "s"}})
    assert (record["pnl"], record["size"], record["tags"], record["reflection"], record["strategy_tag"]) == (12.5, 2, ["a", "b"], "reflection", "s")


def test_compiler_manifests_are_read_only():
    with pytest.raises(TypeError):
        bp.COLLECTIONS["test"] = "fail"
    with pytest.raises(TypeError):
        bp.GROUPS["test"] = "fail"


@pytest.mark.parametrize("options", [{"limit": 0}, {"offset": -1}, {"order_by": "injected"}, {"after": (1, "id"), "offset": 1}, {"projection": "unknown"}])
def test_query_validation(options):
    with pytest.raises(ValueError):
        bp.query("domain", {}, S, **options)
