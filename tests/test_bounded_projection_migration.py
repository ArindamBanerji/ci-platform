"""Migration and activation contracts against disposable AGE graphs."""
import os

import pytest

from ci_platform.graph.age_sdk_adapter import BoundedAGEGraphStoreAdapter
from ci_platform.graph.bounded_projection_migration import migrate, deactivate
from copilot_sdk.graph.namespace import BoundedGraphStoreNamespace
from copilot_sdk.graph.query import DecisionPageRequest, DecisionFilter
from tests.test_bounded_projection_age import raw_store, DOMAIN, write

pytestmark = pytest.mark.skipif(not os.getenv("GRAPH_DSN"), reason="GRAPH_DSN not configured")


def test_activation_guard_backfill_idempotency_and_rollback(raw_store):
    with pytest.raises(ValueError, match="not activated"):
        BoundedAGEGraphStoreAdapter(store=raw_store, domain=DOMAIN)
    raw_store.write_decision(DOMAIN, "cat", "buy", 0.75, {}, {"decision_id": "old", "tenant_id": "t"})
    assert migrate(raw_store, DOMAIN) == {"scanned": 1, "events_created": 1, "generation": 1}
    adapter = BoundedAGEGraphStoreAdapter(store=raw_store, domain=DOMAIN)
    write(adapter, "new")
    assert migrate(raw_store, DOMAIN) == {"scanned": 2, "events_created": 0, "generation": 2}
    deactivate(raw_store, DOMAIN)
    with pytest.raises(ValueError, match="not activated"):
        adapter.count_decisions(DOMAIN)
    # Legacy writes still track feed changes while activation is withdrawn.
    raw_store.write_decision(DOMAIN, "cat", "buy", 0.5, {}, {"decision_id": "later"})
    assert migrate(raw_store, DOMAIN)["generation"] == 3
    assert adapter.count_decisions(DOMAIN) == 3
    assert len(adapter.get_decision_changes(DOMAIN, after_generation=0).events) == 3


@pytest.mark.parametrize("conflict", ["duplicate", "tenant", "timestamp"])
def test_conflicts_prevent_activation_and_partial_backfill(raw_store, conflict):
    S = raw_store._S
    props = f"decision_id: 'd', domain: {S(DOMAIN)}, status: 'pending', created_at: 1"
    if conflict == "tenant":
        metadata = S('{"tenant_id":"two"}')
        props += f", tenant_id: 'one', metadata: {metadata}"
    elif conflict == "timestamp":
        props = props.replace("created_at: 1", "created_at: '2024-01-01'")
    def seed(tx):
        tx.run_bounded_cypher(f"CREATE (d:Decision {{{props}}}) RETURN d")
        if conflict == "duplicate":
            tx.run_bounded_cypher(f"CREATE (d:Decision {{{props}}}) RETURN d")
    raw_store._run(raw_store._client.run_transaction(seed))
    with pytest.raises(ValueError):
        migrate(raw_store, DOMAIN)
    with pytest.raises(ValueError, match="not activated"):
        BoundedAGEGraphStoreAdapter(store=raw_store, domain=DOMAIN)


def test_missing_created_times_keep_real_id_and_verified_missing_raises(raw_store):
    def seed(tx):
        for name, created in [("a", "null"), ("b", "0"), ("c", "null")]:
            tx.run_bounded_cypher(f"CREATE (d:Decision {{decision_id: '{name}', domain: '{DOMAIN}', status: 'pending', created_at: {created}}}) RETURN d")
        tx.run_bounded_cypher(f"CREATE (d:Decision {{decision_id: 'v', domain: '{DOMAIN}', status: 'confirmed', created_at: 2, correct: true}}) RETURN d")
    raw_store._run(raw_store._client.run_transaction(seed))
    migrate(raw_store, DOMAIN)
    adapter = BoundedAGEGraphStoreAdapter(store=raw_store, domain=DOMAIN)
    first = adapter.query_decisions(DOMAIN, filters=DecisionFilter(verified=False), page=DecisionPageRequest(limit=2, descending=False))
    second = adapter.query_decisions(DOMAIN, filters=DecisionFilter(verified=False), page=DecisionPageRequest(limit=2, descending=False, after=first.next_cursor))
    assert [r["decision_id"] for r in first.items + second.items] == ["a", "b", "c"]
    with pytest.raises(ValueError, match="missing verified_at"):
        adapter.query_decisions(DOMAIN, page=DecisionPageRequest(order_by="verified_at"))


def test_generation_independent_by_domain(raw_store):
    for domain in (DOMAIN, "other"):
        migrate(raw_store, domain)
    adapter = BoundedAGEGraphStoreAdapter(store=raw_store, domain=DOMAIN)
    write(adapter, "a")
    adapter.write_decision("other", "cat", "buy", 0.5, {})
    write(adapter, "b")
    assert adapter.get_decision_changes(DOMAIN, after_generation=0).current_generation == 2
    assert adapter.get_decision_changes("other", after_generation=0).current_generation == 1


def test_base_activation_composes_with_namespaced_age_domains(raw_store):
    migrate(raw_store, DOMAIN)
    adapter = BoundedAGEGraphStoreAdapter(store=raw_store, domain=DOMAIN)
    arm = BoundedGraphStoreNamespace(adapter, "arm")
    hand = BoundedGraphStoreNamespace(adapter, "hand")

    arm_id = arm.write_decision(DOMAIN, "cat", "buy", 0.75, {})
    hand_id = hand.write_decision(DOMAIN, "cat", "sell", 0.65, {})

    assert [row["decision_id"] for row in arm.query_decisions(DOMAIN).items] == [arm_id]
    assert [row["decision_id"] for row in hand.query_decisions(DOMAIN).items] == [hand_id]
    arm_feed = arm.get_decision_changes(DOMAIN, after_generation=0)
    hand_feed = hand.get_decision_changes(DOMAIN, after_generation=0)
    assert arm_feed.current_generation == hand_feed.current_generation == 1
    assert arm_feed.events[0]["decision_id"] == arm_id
    assert hand_feed.events[0]["decision_id"] == hand_id
