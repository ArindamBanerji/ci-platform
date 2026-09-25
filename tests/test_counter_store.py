from __future__ import annotations

import asyncio
from typing import Any

import pytest

from ci_platform.copilot_core.counters import (
    AGECounterStore,
    CounterDef,
    soc_cross_category_counter_def,
    soc_sequence_counter_def,
)


def _run(coro: Any) -> Any:
    return asyncio.run(coro)


def _counter_store(age_store: Any) -> AGECounterStore:
    return AGECounterStore(age_store._client)


def _seed_user_and_category(
    age_store: Any, user_id: str = "U1", category_id: str = "credential_access"
) -> None:
    _run(
        age_store._client.run_query(
            """
            CREATE (u:User {id: $user_id, domain: 'soc'})
            CREATE (c:Category {id: $category_id, domain: 'soc'})
            RETURN u, c
            """,
            {"user_id": user_id, "category_id": category_id},
        )
    )


def _user(age_store: Any, user_id: str = "U1") -> dict[str, Any]:
    rows = _run(
        age_store._client.run_query(
            "MATCH (u:User {id: $user_id}) RETURN u",
            {"user_id": user_id},
        )
    )
    assert rows
    return age_store._node_to_dict(rows[0]["u"])


def test_counter_def_creates_explicit_entity_property_definition() -> None:
    counter = CounterDef(
        domain="soc",
        node_label="User",
        key_prop="id",
        key_value="U1",
        counter_prop="sequence_count",
    )

    assert counter.lock_key == "soc:User:id:U1:counters"
    assert counter.mode == "cumulative"


def test_counter_def_rejects_unsafe_cypher_identifiers() -> None:
    with pytest.raises(ValueError):
        CounterDef(
            domain="soc",
            node_label="User) CREATE (:Bad",
            key_prop="id",
            key_value="U1",
            counter_prop="sequence_count",
        )


@pytest.mark.age
@pytest.mark.asyncio
async def test_existing_trusted_counter_bypasses_graph_truth_fallback(age_store: Any) -> None:
    _seed_user_and_category(age_store)
    await age_store._client.run_query(
        "MATCH (u:User {id: 'U1'}) SET u.sequence_count = 3 RETURN u"
    )
    store = _counter_store(age_store)
    counter = soc_sequence_counter_def("U1")

    read = await store.get_counter_or_graph_truth(
        counter, "MATCH (n) RETURN count(n) AS cnt"
    )

    assert read.value == 3
    assert read.status == "materialized_property"
    assert read.source == "entity_property"


@pytest.mark.age
@pytest.mark.asyncio
async def test_cumulative_counter_updates_entity_property_under_advisory_lock(
    age_store: Any,
) -> None:
    _seed_user_and_category(age_store)
    store = _counter_store(age_store)
    counter = soc_sequence_counter_def("U1")

    read = await store.increment_cumulative(counter)

    assert read.value == 1
    assert _user(age_store)["sequence_count"] == 1
    assert read.status == "materialized_property"


@pytest.mark.age
@pytest.mark.asyncio
async def test_missing_entity_returns_untrusted_and_falls_back_to_graph_truth(
    age_store: Any,
) -> None:
    _seed_user_and_category(age_store)
    store = _counter_store(age_store)
    counter = soc_sequence_counter_def("MISSING")

    read = await store.read_counter(counter)
    fallback = await store.get_counter_or_graph_truth(
        counter,
        "MATCH (u:User) RETURN count(u) AS cnt",
    )

    assert read.status == "missing_entity"
    assert read.trusted is False
    assert fallback.value == 1
    assert fallback.source == "graph_truth_fallback"
    assert fallback.metadata["counter_status"] == "missing_entity"


@pytest.mark.age
@pytest.mark.asyncio
async def test_missing_property_falls_back_to_graph_truth(age_store: Any) -> None:
    _seed_user_and_category(age_store)
    store = _counter_store(age_store)
    counter = soc_sequence_counter_def("U1")

    read = await store.read_counter(counter)
    fallback = await store.get_counter_or_graph_truth(
        counter,
        "MATCH (u:User) RETURN count(u) AS cnt",
    )

    assert read.status == "missing_property"
    assert read.trusted is False
    assert fallback.value == 1
    assert fallback.source == "graph_truth_fallback"


@pytest.mark.age
@pytest.mark.asyncio
async def test_distinct_counter_creates_only_missing_seen_edge(age_store: Any) -> None:
    _seed_user_and_category(age_store)
    store = _counter_store(age_store)
    counter = soc_cross_category_counter_def("U1")

    first = await store.increment_distinct(counter, "credential_access")
    second = await store.increment_distinct(counter, "credential_access")
    rows = await age_store._client.run_query(
        """
        MATCH (:User {id: 'U1'})-[r:SEEN_CATEGORY]->(:Category {id: 'credential_access'})
        RETURN count(r) AS cnt
        """
    )

    assert first.value == 1
    assert second.value == 1
    assert int(rows[0]["cnt"]) == 1


@pytest.mark.age
@pytest.mark.asyncio
async def test_transaction_failure_rolls_back_counter_update(age_store: Any) -> None:
    _seed_user_and_category(age_store)
    store = _counter_store(age_store)
    counter = soc_sequence_counter_def("U1")

    with pytest.raises(ValueError):
        await store.increment_cumulative(soc_sequence_counter_def("MISSING"))

    assert "sequence_count" not in _user(age_store)
    read = await store.read_counter(counter)
    assert read.status == "missing_property"


@pytest.mark.age
@pytest.mark.asyncio
async def test_reconciliation_corrects_entity_property_from_graph_truth(age_store: Any) -> None:
    _seed_user_and_category(age_store)
    await age_store._client.run_query(
        "MATCH (u:User {id: 'U1'}) SET u.sequence_count = 2 RETURN u"
    )
    store = _counter_store(age_store)
    counter = soc_sequence_counter_def("U1")

    reconciliation = await store.reconcile_counter(
        counter,
        "MATCH (u:User) RETURN count(u) AS cnt",
    )

    assert reconciliation.counter_value == 2
    assert reconciliation.graph_truth_value == 1
    assert reconciliation.status == "reconciled_corrected"
    assert reconciliation.read.value == 1
    assert _user(age_store)["sequence_count"] == 1


def test_disabled_feature_flag_status_does_not_adopt_route_path(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("USE_MATERIALIZED_COUNTERS", raising=False)

    class GraphStatusProbe:
        connection_mode = "warm_fallback"
        pool_available = False

    store = AGECounterStore(GraphStatusProbe())

    status = store.get_status()

    assert status.enabled is False
    assert status.backend == "age"
    assert status.connection_mode == "warm_fallback"


def test_soc_counter_defs_are_explicit_and_domain_scoped() -> None:
    sequence = soc_sequence_counter_def("U1")
    cross_category = soc_cross_category_counter_def("U1")

    assert sequence.domain == "soc"
    assert sequence.node_label == "User"
    assert sequence.counter_prop == "sequence_count"
    assert cross_category.mode == "distinct"
    assert cross_category.edge_label == "SEEN_CATEGORY"
