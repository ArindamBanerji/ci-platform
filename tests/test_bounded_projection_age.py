"""Live same-graph bounded contracts. Every test owns a disposable graph."""
from __future__ import annotations

import os
import uuid
from concurrent.futures import ThreadPoolExecutor

import psycopg
import pytest

from ci_platform.graph.age_graph_store import AGEGraphStore
from ci_platform.graph.age_sdk_adapter import BoundedAGEGraphStoreAdapter, AGEGraphStoreAdapter
from ci_platform.graph.bounded_projection_migration import migrate
from copilot_sdk.graph.protocol import BoundedProjectionStore
from copilot_sdk.graph.query import DecisionFilter, DecisionPageRequest, DecisionGenerationChanged

pytestmark = pytest.mark.skipif(not os.getenv("GRAPH_DSN"), reason="GRAPH_DSN not configured")
DOMAIN = "pytest_protocol_v2_bounded"


@pytest.fixture
def raw_store():
    dsn = os.environ["GRAPH_DSN"]
    graph = "protocol_v2_test_bounded_" + uuid.uuid4().hex[:12]
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute("LOAD 'age'")
        conn.execute("SET search_path = ag_catalog, public")
        conn.execute("SELECT create_graph(%s)", (graph,))
    store = AGEGraphStore(dsn=dsn, graph_name=graph)
    try:
        yield store
    finally:
        store.close()
        with psycopg.connect(dsn, autocommit=True) as conn:
            conn.execute("LOAD 'age'")
            conn.execute("SET search_path = ag_catalog, public")
            conn.execute("SELECT drop_graph(%s, true)", (graph,))


@pytest.fixture
def adapter(raw_store):
    migrate(raw_store, DOMAIN)
    return BoundedAGEGraphStoreAdapter(store=raw_store, domain=DOMAIN)


def write(adapter, decision_id, created=1, **metadata):
    adapter.write_governed_decision(
        decision_id, DOMAIN, "cat", 0, "buy", 0, 0.75,
        [0.75, 0.25], [0.2], ["risk"],
        metadata={"created_at": created, **metadata},
    )


def test_membership_empty_and_native_aggregates(adapter):
    assert isinstance(adapter, BoundedProjectionStore)
    assert not isinstance(AGEGraphStoreAdapter(store=adapter._store), BoundedProjectionStore)
    assert adapter.query_decisions(DOMAIN).items == ()
    assert adapter.count_decisions(DOMAIN) == 0
    rows = adapter.aggregate_decisions(DOMAIN, metrics=("count", "correct_count", "avg_confidence"))
    assert rows[0].values == {"count": 0, "correct_count": 0}
    assert adapter.aggregate_decisions(DOMAIN, group_by=("category",)) == ()


@pytest.mark.parametrize("descending", [False, True])
def test_fenced_cursor_pages_and_verification_order(adapter, descending):
    for name, created, verified in [("A", 1, 30), ("B", 2, 10), ("C", 3, 20)]:
        write(adapter, name, created)
        adapter.write_outcome(name, "buy", True, {"verified_at": verified}, domain=DOMAIN)
    generation = adapter.get_decision_changes(DOMAIN, after_generation=0).current_generation
    seen = []
    cursor = None
    while True:
        page = adapter.query_decisions(DOMAIN, page=DecisionPageRequest(limit=1, after=cursor, order_by="verified_at", descending=descending), as_of_generation=generation)
        seen.extend(row["decision_id"] for row in page.items)
        if not page.has_more:
            break
        cursor = page.next_cursor
    assert seen == (["A", "C", "B"] if descending else ["B", "C", "A"])
    write(adapter, "D", 4)
    with pytest.raises(DecisionGenerationChanged):
        adapter.query_decisions(DOMAIN, as_of_generation=generation)


@pytest.mark.parametrize("projection", ["summary", "scoring", "journal", "full"])
def test_projection_feed_parity_and_copy_safety(adapter, projection):
    from ci_platform.graph.bounded_projection import SUMMARY_FIELDS, SCORING_FIELDS, JOURNAL_FIELDS
    write(adapter, "d", pnl="12.50", size="2", tags=[" a ", "a"], strategy="s", notes="n", learning_metadata={"reward": 1, "secret": "hidden"})
    direct = adapter.query_decisions(DOMAIN, projection=projection).items[0]
    event = adapter.get_decision_changes(DOMAIN, after_generation=0, projection=projection).events[0]
    assert event["payload"] == direct
    if projection != "full":
        assert set(direct) == set({"summary": SUMMARY_FIELDS, "scoring": SCORING_FIELDS, "journal": JOURNAL_FIELDS}[projection])
    if projection == "journal":
        assert (direct["pnl"], direct["size"], direct["tags"], direct["reflection"], direct["strategy_tag"]) == (12.5, 2, ["a"], "n", "s")
    if projection == "scoring":
        assert direct["learning_metadata"] == {"reward": 1}
    event["payload"]["decision_id"] = "tampered"
    assert adapter.get_decision_changes(DOMAIN, after_generation=0).events[0]["payload"]["decision_id"] == "d"


@pytest.mark.parametrize("filters,expected", [
    (DecisionFilter(categories=("cat",)), 2), (DecisionFilter(actions=("sell",)), 0),
    (DecisionFilter(verified=True), 1), (DecisionFilter(correct=False), 1),
    (DecisionFilter(verified=False), 1), (DecisionFilter(correct=True), 0),
    (DecisionFilter(ticker="aapl"), 1), (DecisionFilter(tenant_id="one"), 1),
    (DecisionFilter(exclude_legacy_signals=True), 1), (DecisionFilter(sources=("score",)), 2),
    (DecisionFilter(regimes=("up",)), 1), (DecisionFilter(confidence_min=0.75, confidence_max=0.75), 2),
    (DecisionFilter(created_from=1, created_to=2), 1),
    (DecisionFilter(verified_from=10, verified_to=11), 1),
    (DecisionFilter(decision_ids=("a",), exclude_decision_ids=("a",)), 0),
])
def test_filters_consistent_for_query_count_aggregate(adapter, filters, expected):
    write(adapter, "a", 1, ticker="aapl", tenant_id="one", regime="up")
    write(adapter, "b", 2, signal_detail={}, signal_timestamp=2)
    adapter.write_outcome("a", "sell", False, {"verified_at": 10}, domain=DOMAIN)
    assert len(adapter.query_decisions(DOMAIN, filters=filters).items) == expected
    assert adapter.count_decisions(DOMAIN, filters=filters) == expected
    assert adapter.aggregate_decisions(DOMAIN, filters=filters)[0].values["count"] == expected


def test_feed_lifecycle_idempotency_archive_reset_and_routing(adapter):
    write(adapter, "a", tenant_id="one")
    write(adapter, "a", tenant_id="one")
    write(adapter, "b", 2, tenant_id="two")
    adapter.write_outcome("a", "buy", True, domain=DOMAIN)
    adapter.write_outcome("a", "buy", True, domain=DOMAIN)
    first = adapter.get_decision_changes(DOMAIN, after_generation=0, limit=2)
    assert first.has_more and first.next_generation == 2 and first.current_generation == 3
    assert adapter.archive_old_decisions(DOMAIN, keep_recent=1) == 1
    adapter.domain_scoped_reset(DOMAIN)
    page = adapter.get_decision_changes(DOMAIN, after_generation=first.next_generation)
    assert [e["event_type"] for e in page.events] == ["upsert", "delete", "delete"]
    assert page.current_generation == page.next_generation == 5
    tombstone = page.events[1]["payload"]
    assert tombstone == {"decision_id": "a", "domain": DOMAIN, "tenant_id": "one", "exclude_legacy_signals": False, "_removed": True}
    hidden = adapter.get_decision_changes(DOMAIN, after_generation=0, filters=DecisionFilter(tenant_id="absent"))
    assert hidden.events == () and hidden.next_generation == 5
    with pytest.raises(ValueError):
        adapter.get_decision_changes(DOMAIN, after_generation=6)


def test_retention_preserves_adversarial_ids_and_tombstones(adapter):
    adversarial_ids = ["null", "true", "false", "0", "1", "", "雪-決定"]
    for created, decision_id in enumerate(adversarial_ids, start=1):
        write(adapter, decision_id, created)
    write(adapter, "z-newest", len(adversarial_ids) + 1)

    assert adapter.archive_old_decisions(DOMAIN, keep_recent=1) == len(adversarial_ids)
    assert {
        row["decision_id"] for row in adapter.get_archived_decisions(DOMAIN)
    } == set(adversarial_ids)
    events = adapter.get_decision_changes(DOMAIN, after_generation=0).events
    assert {
        event["decision_id"] for event in events if event["event_type"] == "delete"
    } == set(adversarial_ids)


def test_concurrent_writes_have_no_generation_gaps(adapter):
    with ThreadPoolExecutor(max_workers=4) as executor:
        list(executor.map(lambda i: write(adapter, str(i), i), range(8)))
    page = adapter.get_decision_changes(DOMAIN, after_generation=0)
    assert [e["generation"] for e in page.events] == list(range(1, 9))
    assert len({e["decision_id"] for e in page.events}) == 8


def test_feed_failure_rolls_back_decision_and_generation(adapter, monkeypatch):
    from ci_platform.graph.age_client import AGETransaction
    original = AGETransaction.run_bounded_cypher
    def fail_event(self, query):
        if "CREATE (e:BoundedDecisionEvent" in query:
            raise RuntimeError("injected feed failure")
        return original(self, query)
    monkeypatch.setattr(AGETransaction, "run_bounded_cypher", fail_event)
    with pytest.raises(RuntimeError, match="injected"):
        write(adapter, "failed")
    assert adapter.count_decisions(DOMAIN) == 0
    assert adapter.get_decision_changes(DOMAIN, after_generation=0).current_generation == 0


def test_bound_text_does_not_escape_cypher_or_sql(adapter):
    text = "x' OR true // $$ $bounded$ \\\\"
    write(adapter, "normal", ticker=text)
    assert adapter.count_decisions(DOMAIN, filters=DecisionFilter(ticker=text)) == 1
    assert adapter.count_decisions(DOMAIN, filters=DecisionFilter(categories=(text,))) == 0


@pytest.mark.parametrize("governed", [False, True])
def test_nonfinite_confidence_filters_match_memory(adapter, governed):
    import math
    for i, confidence in enumerate([float("nan"), float("inf"), float("-inf"), 0.75]):
        if governed:
            adapter.write_governed_decision(str(i), DOMAIN, "cat", 0, "buy", 0, confidence, [], [], [])
        else:
            adapter.write_decision(DOMAIN, "cat", "buy", confidence, {})
    filters = DecisionFilter(confidence_min=0, confidence_max=1)
    rows = adapter.query_decisions(DOMAIN, filters=filters).items
    assert len(rows) == 1 and rows[0]["confidence"] == 0.75
    assert adapter.count_decisions(DOMAIN, filters=filters) == 1
    assert adapter.aggregate_decisions(DOMAIN, filters=filters, metrics=("avg_confidence",))[0].values == {"avg_confidence": 0.75}
    assert adapter.count_decisions(DOMAIN, filters=DecisionFilter(confidence_min=0)) == 2
    assert adapter.count_decisions(DOMAIN, filters=DecisionFilter(confidence_max=1)) == 2
    assert math.isnan(adapter.aggregate_decisions(DOMAIN, metrics=("avg_confidence",))[0].values["avg_confidence"])


def test_group_cardinality_and_missing_dimension(adapter):
    from copilot_sdk.graph.query import ProjectionCardinalityExceeded
    # Seed native canonical rows in one test transaction to exercise the server
    # aggregation ceiling without 1,001 separate network write round trips.
    def seed(tx):
        tx.run_bounded_cypher(f"UNWIND range(0, 1000) AS i CREATE (d:Decision {{domain: '{DOMAIN}', decision_id: toString(i), status: 'pending', _bp_category: toString(i)}}) RETURN count(d) AS cnt")
    adapter._store._run(adapter._store._client.run_transaction(seed))
    with pytest.raises(ProjectionCardinalityExceeded) as exc:
        adapter.aggregate_decisions(DOMAIN, group_by=("category",))
    assert exc.value.count == 1001
    missing = adapter.aggregate_decisions(DOMAIN, group_by=("regime",))
    assert missing[0].dimensions == {} and missing[0].values == {"count": 1001}


def test_status_archive_emits_tombstone(adapter):
    write(adapter, "d", 1)
    assert adapter.archive_decisions(DOMAIN, before=2) == 1
    assert adapter.count_decisions(DOMAIN) == 0
    page = adapter.get_decision_changes(DOMAIN, after_generation=0)
    assert [e["event_type"] for e in page.events] == ["upsert", "delete"]


@pytest.mark.parametrize("dimensions", [("category",), ("action",), ("status",), ("regime",), ("category", "status")])
def test_native_group_dimensions_and_metrics(adapter, dimensions):
    write(adapter, "a", regime="up")
    write(adapter, "b", 2)
    adapter.write_outcome("a", "sell", False, domain=DOMAIN)
    groups = adapter.aggregate_decisions(DOMAIN, group_by=dimensions, metrics=("count", "correct_count", "avg_confidence"))
    assert sum(g.values["count"] for g in groups) == 2
    assert sum(g.values["correct_count"] for g in groups) == 0
    assert all(g.values["avg_confidence"] == 0.75 for g in groups)
    if dimensions == ("action",):
        assert groups[0].dimensions == {"action": "buy"}
    if dimensions == ("regime",):
        assert [g.dimensions for g in groups] == [{}, {"regime": "up"}]
