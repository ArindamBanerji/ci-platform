from __future__ import annotations

import copy
import os
import uuid

import pytest

from ci_platform.copilot_core.counters import (
    AGECounterStore,
    CounterDef,
    soc_cross_category_counter_def,
    soc_sequence_counter_def,
)


class FakeTransaction:
    def __init__(self, client: "FakeGraphClient") -> None:
        self.client = client

    def execute_sql(self, sql, parameters=None):
        self.client.sql_calls.append((sql, parameters))
        return None

    def run_cypher(self, query, parameters=None):
        return self.client.run_query_sync(query, parameters or {})


class FakeGraphClient:
    connection_mode = "warm_fallback"
    pool_available = False

    def __init__(self) -> None:
        self.entities = {
            ("User", "id", "U1"): {"id": "U1"},
        }
        self.distinct_nodes = {
            ("Category", "id", "credential_access"): {"id": "credential_access"},
        }
        self.edges = set()
        self.graph_truth = 0
        self.queries = []
        self.sql_calls = []
        self.transaction_count = 0
        self.fail_on_counter_set = False

    async def run_query(self, query, parameters=None):
        return self.run_query_sync(query, parameters or {})

    def run_query_sync(self, query, parameters=None):
        parameters = parameters or {}
        self.queries.append((query, dict(parameters)))
        assert "MERGE" not in query
        assert "CopilotCounter" not in query
        assert "CopilotCounterEvent" not in query
        if "MATCH (n:User {id: $key_value})" in query:
            return self._handle_user_query(query, parameters)
        if "RETURN count(n) AS cnt" in query:
            return [{"cnt": self.graph_truth}]
        raise AssertionError(f"Unexpected query: {query}")

    def _handle_user_query(self, query, parameters):
        entity_key = ("User", "id", parameters["key_value"])
        entity = self.entities.get(entity_key)
        if entity is None:
            return []
        if "MATCH (d:Category {id: $distinct_key_value})" in query:
            category_key = ("Category", "id", parameters["distinct_key_value"])
            if category_key not in self.distinct_nodes:
                return []
            edge_key = (parameters["key_value"], parameters["distinct_key_value"])
            if "OPTIONAL MATCH" in query:
                return [{"edge_exists": edge_key in self.edges}]
            if "CREATE (n)-[:SEEN_CATEGORY]->(d)" in query:
                self.edges.add(edge_key)
                return [{"created": 1}]
        if "MATCH (n:User {id: $key_value})-[:SEEN_CATEGORY]->" in query:
            count = sum(1 for user_id, _cat in self.edges if user_id == parameters["key_value"])
            return [{"value": count}]
        if "SET n.cross_category_count = $value" in query:
            entity["cross_category_count"] = parameters["value"]
            entity["cross_category_count_updated_at"] = parameters.get("updated_at")
            return [{"value": entity["cross_category_count"]}]
        if "SET n.sequence_count = $value" in query:
            entity["sequence_count"] = parameters["value"]
            entity["sequence_count_last_reconciled"] = parameters.get("last_reconciled")
            entity["sequence_count_reconciliation_status"] = parameters.get(
                "reconciliation_status"
            )
            return [{"value": entity["sequence_count"]}]
        if "SET n.sequence_count" in query:
            if self.fail_on_counter_set:
                raise RuntimeError("injected counter set failure")
            entity["sequence_count"] = entity.get("sequence_count", 0) + parameters["delta"]
            entity["sequence_count_updated_at"] = parameters.get("updated_at")
            return [{"value": entity["sequence_count"]}]
        if "RETURN n.sequence_count AS value" in query:
            return [
                {
                    "value": entity.get("sequence_count"),
                    "last_reconciled": entity.get("sequence_count_last_reconciled"),
                    "updated_at": entity.get("sequence_count_updated_at"),
                }
            ]
        if "RETURN n.cross_category_count AS value" in query:
            return [
                {
                    "value": entity.get("cross_category_count"),
                    "last_reconciled": entity.get("cross_category_count_last_reconciled"),
                    "updated_at": entity.get("cross_category_count_updated_at"),
                }
            ]
        raise AssertionError(f"Unexpected User query: {query}")

    async def run_transaction(self, operation):
        self.transaction_count += 1
        entities = copy.deepcopy(self.entities)
        edges = set(self.edges)
        sql_calls = list(self.sql_calls)
        try:
            return operation(FakeTransaction(self))
        except Exception:
            self.entities = entities
            self.edges = edges
            self.sql_calls = sql_calls
            raise


def test_counter_def_creates_explicit_entity_property_definition():
    counter = CounterDef(
        domain="soc",
        node_label="User",
        key_prop="id",
        key_value="U1",
        counter_prop="sequence_count",
    )

    assert counter.lock_key == "soc:User:id:U1:counters"
    assert counter.mode == "cumulative"


def test_counter_def_rejects_unsafe_cypher_identifiers():
    with pytest.raises(ValueError):
        CounterDef(
            domain="soc",
            node_label="User) CREATE (:Bad",
            key_prop="id",
            key_value="U1",
            counter_prop="sequence_count",
        )


@pytest.mark.asyncio
async def test_existing_trusted_counter_bypasses_graph_truth_fallback():
    graph = FakeGraphClient()
    graph.graph_truth = 99
    graph.entities[("User", "id", "U1")]["sequence_count"] = 3
    store = AGECounterStore(graph)
    counter = soc_sequence_counter_def("U1")

    read = await store.get_counter_or_graph_truth(
        counter, "MATCH (n) RETURN count(n) AS cnt"
    )

    assert read.value == 3
    assert read.status == "materialized_property"
    assert not any("RETURN count(n) AS cnt" in query for query, _params in graph.queries)


@pytest.mark.asyncio
async def test_cumulative_counter_updates_entity_property_under_advisory_lock():
    graph = FakeGraphClient()
    store = AGECounterStore(graph)
    counter = soc_sequence_counter_def("U1")

    read = await store.increment_cumulative(counter)

    assert read.value == 1
    assert graph.entities[("User", "id", "U1")]["sequence_count"] == 1
    assert graph.sql_calls[0][0] == "SELECT pg_advisory_xact_lock(hashtext(%s))"
    assert graph.sql_calls[0][1] == ("soc:User:id:U1:counters",)
    assert all("CopilotCounter" not in query for query, _params in graph.queries)


@pytest.mark.asyncio
async def test_missing_entity_returns_untrusted_and_falls_back_to_graph_truth():
    graph = FakeGraphClient()
    graph.graph_truth = 8
    store = AGECounterStore(graph)
    counter = soc_sequence_counter_def("MISSING")

    read = await store.read_counter(counter)
    fallback = await store.get_counter_or_graph_truth(
        counter, "MATCH (n) RETURN count(n) AS cnt"
    )

    assert read.status == "missing_entity"
    assert read.trusted is False
    assert fallback.value == 8
    assert fallback.source == "graph_truth_fallback"
    assert fallback.metadata["counter_status"] == "missing_entity"


@pytest.mark.asyncio
async def test_missing_property_falls_back_to_graph_truth():
    graph = FakeGraphClient()
    graph.graph_truth = 8
    store = AGECounterStore(graph)
    counter = soc_sequence_counter_def("U1")

    read = await store.read_counter(counter)
    fallback = await store.get_counter_or_graph_truth(
        counter, "MATCH (n) RETURN count(n) AS cnt"
    )

    assert read.status == "missing_property"
    assert read.trusted is False
    assert fallback.value == 8
    assert fallback.source == "graph_truth_fallback"
    assert fallback.metadata["counter_status"] == "missing_property"


@pytest.mark.asyncio
async def test_distinct_counter_creates_only_missing_seen_edge():
    graph = FakeGraphClient()
    store = AGECounterStore(graph)
    counter = soc_cross_category_counter_def("U1")

    first = await store.increment_distinct(counter, "credential_access")
    second = await store.increment_distinct(counter, "credential_access")

    assert first.value == 1
    assert second.value == 1
    assert graph.edges == {("U1", "credential_access")}
    create_queries = [
        query for query, _params in graph.queries if "CREATE (n)-[:SEEN_CATEGORY]->(d)" in query
    ]
    assert len(create_queries) == 1


@pytest.mark.asyncio
async def test_transaction_failure_rolls_back_counter_update():
    graph = FakeGraphClient()
    graph.fail_on_counter_set = True
    store = AGECounterStore(graph)
    counter = soc_sequence_counter_def("U1")

    with pytest.raises(RuntimeError):
        await store.increment_cumulative(counter)

    assert "sequence_count" not in graph.entities[("User", "id", "U1")]
    assert graph.sql_calls == []


@pytest.mark.asyncio
async def test_reconciliation_corrects_entity_property_from_graph_truth():
    graph = FakeGraphClient()
    graph.entities[("User", "id", "U1")]["sequence_count"] = 2
    graph.graph_truth = 5
    store = AGECounterStore(graph)
    counter = soc_sequence_counter_def("U1")

    reconciliation = await store.reconcile_counter(
        counter, "MATCH (n) RETURN count(n) AS cnt"
    )

    assert reconciliation.counter_value == 2
    assert reconciliation.graph_truth_value == 5
    assert reconciliation.status == "reconciled_corrected"
    assert reconciliation.read.value == 5
    assert graph.entities[("User", "id", "U1")]["sequence_count"] == 5


@pytest.mark.asyncio
async def test_disabled_feature_flag_status_does_not_adopt_route_path(monkeypatch):
    monkeypatch.delenv("USE_MATERIALIZED_COUNTERS", raising=False)
    graph = FakeGraphClient()
    store = AGECounterStore(graph)

    status = store.get_status()

    assert status.enabled is False
    assert status.backend == "age"
    assert status.connection_mode == "warm_fallback"


def test_soc_counter_defs_are_explicit_and_domain_scoped():
    sequence = soc_sequence_counter_def("U1")
    cross_category = soc_cross_category_counter_def("U1")

    assert sequence.domain == "soc"
    assert sequence.node_label == "User"
    assert sequence.counter_prop == "sequence_count"
    assert cross_category.mode == "distinct"
    assert cross_category.edge_label == "SEEN_CATEGORY"
    assert cross_category.distinct_label == "Category"


AGE_INTEGRATION = os.getenv("AGE_INTEGRATION", "0") == "1"


@pytest.mark.skipif(
    not AGE_INTEGRATION,
    reason="AGE_INTEGRATION != 1; skipping live AGE counter compatibility test",
)
@pytest.mark.asyncio
async def test_live_age_entity_property_counter_shapes():
    from ci_platform.graph.age_client import AGEClient

    graph_name = os.getenv("AGE_GRAPH_NAME", "soc_graph")
    client = AGEClient(graph_name=graph_name)
    await client.ensure_graph()
    store = AGECounterStore(client)
    run_id = f"counter-store-live-{uuid.uuid4().hex}"
    user_id = f"user-{run_id}"
    category_id = f"category-{run_id}"
    sequence = soc_sequence_counter_def(user_id)
    cross_category = soc_cross_category_counter_def(user_id)

    try:
        await client.run_query(
            """
            CREATE (u:User {id: $user_id, counter_store_run_id: $run_id})
            RETURN u.id AS id
            """,
            {"user_id": user_id, "run_id": run_id},
        )
        await client.run_query(
            """
            CREATE (c:Category {id: $category_id, counter_store_run_id: $run_id})
            RETURN c.id AS id
            """,
            {"category_id": category_id, "run_id": run_id},
        )

        first = await store.increment_cumulative(sequence)
        second = await store.increment_cumulative(sequence)
        distinct_first = await store.increment_distinct(cross_category, category_id)
        distinct_second = await store.increment_distinct(cross_category, category_id)

        await client.run_query(
            """
            MATCH (u:User {id: $user_id})
            SET u.sequence_count = 99
            RETURN u.sequence_count AS value
            """,
            {"user_id": user_id},
        )
        reconciliation = await store.reconcile_counter(
            sequence,
            "MATCH (u:User {id: $user_id}) RETURN count(u) AS cnt",
            {"user_id": user_id},
        )

        assert first.value == 1
        assert second.value == 2
        assert distinct_first.value == 1
        assert distinct_second.value == 1
        assert reconciliation.graph_truth_value == 1
        assert reconciliation.read.value == 1
    finally:
        await client.run_query(
            """
            MATCH (u:User {id: $user_id})-[r:SEEN_CATEGORY]->(c:Category {id: $category_id})
            DELETE r
            RETURN 1 AS deleted
            """,
            {"user_id": user_id, "category_id": category_id},
        )
        await client.run_query(
            """
            MATCH (u:User {id: $user_id})
            DELETE u
            RETURN 1 AS deleted
            """,
            {"user_id": user_id},
        )
        await client.run_query(
            """
            MATCH (c:Category {id: $category_id})
            DELETE c
            RETURN 1 AS deleted
            """,
            {"category_id": category_id},
        )
