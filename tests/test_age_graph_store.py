import os
import re
import inspect

import pytest


class FakeTransaction:
    def __init__(self):
        self.cypher = []

    def run_cypher(self, query):
        self.cypher.append(query)
        return []


class FakeAGEClient:
    instances = []

    def __init__(self, dsn=None, graph_name=None):
        self.dsn = dsn
        self.graph_name = graph_name
        self._graph = graph_name
        self.queries = []
        self.responses = []
        self.transactions = []
        self.closed = False
        self.s_calls = []
        FakeAGEClient.instances.append(self)

    def _S(self, value):
        self.s_calls.append(value)
        if value is None:
            return "null"
        if isinstance(value, bool):
            return str(value).lower()
        if isinstance(value, (int, float)):
            return str(value)
        return "'" + str(value).replace("'", "\\'") + "'"

    async def run_query(self, query, parameters=None):
        self.queries.append((query, parameters))
        if self.responses:
            return self.responses.pop(0)
        return []

    async def run_transaction(self, fn):
        tx = FakeTransaction()
        result = fn(tx)
        self.transactions.append(tx)
        return result

    async def close(self):
        self.closed = True


@pytest.fixture
def fake_age_client(monkeypatch):
    FakeAGEClient.instances = []
    monkeypatch.setattr("ci_platform.graph.age_graph_store.AGEClient", FakeAGEClient)
    return FakeAGEClient


def _new_store(fake_age_client):
    from ci_platform.graph.age_graph_store import AGEGraphStore

    return AGEGraphStore(dsn="postgresql://example/test", graph_name="test_graph")


def _conservation_payload(**overrides):
    payload = {
        "domain": "soc",
        "status": "GREEN",
        "alpha": 0.25,
        "q": 0.8,
        "V": 42,
        "theta_min": 23.53,
        "product": 18.824,
        "categories_total": 6,
        "categories_with_data": 4,
        "baseline_product": 20.0,
        "relative_threshold": 0.9412,
        "complacency_flag": "false",
        "caused_by_decision_id": "DEC-1",
        "old_status": "AMBER",
    }
    payload.update(overrides)
    return payload


def _conservation_row(**overrides):
    row = {
        "id": "soc:conservation:1",
        "domain": "soc",
        "status": "GREEN",
        "alpha": 0.25,
        "q": 0.8,
        "V": 42,
        "theta_min": 23.53,
        "product": 18.824,
        "categories_total": 6,
        "categories_with_data": 4,
        "baseline_product": 20.0,
        "relative_threshold": 0.9412,
        "complacency_flag": "false",
        "caused_by_decision_id": "DEC-1",
        "old_status": "AMBER",
        "updated_at": "2026-06-05T00:00:00Z",
    }
    row.update(overrides)
    return row


def test_age_graph_store_importable():
    from ci_platform.graph import AGEGraphStore

    assert AGEGraphStore is not None


def test_age_graph_store_has_graphstore_methods():
    from ci_platform.graph import AGEGraphStore

    for name in [
        "write_decision",
        "write_outcome",
        "get_decision",
        "get_decisions",
        "get_verified_decisions",
        "count_verified",
        "count_correct",
        "count_decisions",
        "count_categories_with_n",
        "update_dk_weights",
        "get_dk_weights",
        "get_all_decisions",
        "save_centroids",
        "load_latest_centroids",
        "get_centroid_checkpoints",
        "save_evolution_event",
        "get_evolution_events",
        "archive_old_decisions",
        "count_archived",
        "link_decision_to_entity",
        "get_decision_links",
        "close",
        "query_context",
        "query_similar",
    ]:
        assert hasattr(AGEGraphStore, name)


def test_age_graph_store_has_centroid_methods():
    from ci_platform.graph import AGEGraphStore

    assert hasattr(AGEGraphStore, "save_centroids")
    assert hasattr(AGEGraphStore, "get_centroid_checkpoints")


def test_save_evolution_event_method_exists():
    from ci_platform.graph import AGEGraphStore

    assert hasattr(AGEGraphStore, "save_evolution_event")


def test_save_evolution_event_signature():
    pytest.importorskip("copilot_sdk.graph")
    pytest.importorskip("copilot_sdk.evolution.protocol")
    from ci_platform.graph import AGEGraphStore
    from copilot_sdk.graph import GraphStore
    from copilot_sdk.evolution.protocol import EvolutionStore

    assert not hasattr(GraphStore, "save_evolution_event")
    protocol_signature = inspect.signature(EvolutionStore.save_evolution_event)
    age_signature = inspect.signature(AGEGraphStore.save_evolution_event)

    assert list(age_signature.parameters) == list(protocol_signature.parameters)
    for name, parameter in protocol_signature.parameters.items():
        assert age_signature.parameters[name].default == parameter.default


def test_all_protocol_methods_present():
    pytest.importorskip("copilot_sdk.graph")
    from ci_platform.graph import AGEGraphStore
    from copilot_sdk.graph import GraphStore

    protocol_methods = [
        name for name in dir(GraphStore) if not name.startswith("_")
    ]

    missing = [name for name in protocol_methods if not hasattr(AGEGraphStore, name)]
    assert missing == []


def test_protocol_method_signatures_match():
    pytest.importorskip("copilot_sdk.graph")
    from ci_platform.graph import AGEGraphStore
    from copilot_sdk.graph import GraphStore

    protocol_methods = [
        name for name in dir(GraphStore) if not name.startswith("_")
    ]

    for method_name in protocol_methods:
        protocol_signature = inspect.signature(getattr(GraphStore, method_name))
        age_signature = inspect.signature(getattr(AGEGraphStore, method_name))
        assert list(age_signature.parameters) == list(protocol_signature.parameters)
        for name, parameter in protocol_signature.parameters.items():
            assert age_signature.parameters[name].default == parameter.default


def test_age_client_exposes_s_helper():
    from ci_platform.graph.age_client import AGEClient

    assert hasattr(AGEClient, "_S")


def test_age_client_s_matches_serialize_for_age_for_strings():
    from ci_platform.graph.age_client import AGEClient

    client = AGEClient(dsn="postgresql://example/test", graph_name="test_graph")

    for value in ["plain", "supplier's invoice", None, True, 3.14, {"a": 1}]:
        assert client._S(value) == AGEClient.serialize_for_age(value)


def test_age_graph_store_satisfies_sdk_protocol_when_available(fake_age_client):
    pytest.importorskip("copilot_sdk.graph")
    from copilot_sdk.graph import GraphStore

    store = _new_store(fake_age_client)

    assert isinstance(store, GraphStore)


def test_node_to_dict_parses_json_strings(fake_age_client):
    store = _new_store(fake_age_client)

    node = store._node_to_dict(
        {
            "properties": {
                "decision_id": "DEC-1",
                "factors": '{"risk": 0.7}',
                "metadata": '{"source": "unit"}',
            },
            "id": 42,
        }
    )

    assert node["decision_id"] == "DEC-1"
    assert node["factors"] == {"risk": 0.7}
    assert node["metadata"] == {"source": "unit"}
    assert node["_age_id"] == 42


def test_node_to_dict_handles_non_dict(fake_age_client):
    store = _new_store(fake_age_client)

    assert store._node_to_dict("plain") == {"value": "plain"}
    assert store._node_to_dict(None) == {}


def test_query_limits_are_sanitized(fake_age_client):
    store = _new_store(fake_age_client)

    store.get_decisions("soc", limit=-1)
    store.query_context("ENT-1", hops=99)
    store.query_similar("DEC-1", limit=0)

    queries = "\n".join(query for query, _ in FakeAGEClient.instances[0].queries)
    assert "LIMIT -1" not in queries
    assert "[*1..99]" not in queries
    assert "LIMIT 0" not in queries
    assert "[*1..5]" in queries


def test_write_decision_uses_no_param_placeholders(fake_age_client):
    store = _new_store(fake_age_client)

    decision_id = store.write_decision(
        "soc",
        category="duplicate_risk",
        action="flag_leakage",
        confidence=0.91,
        factors={"duplicate_score": 0.8},
        metadata={"source": "unit", "entity_id": "ENT-1"},
    )

    assert re.match(r"DEC-[0-9a-f]{8}", decision_id)
    query, parameters = FakeAGEClient.instances[0].queries[0]
    assert parameters is None
    assert "$" not in query
    assert "ON CREATE SET" not in query
    assert "MERGE" not in query


def test_age_graph_store_uses_client_s_directly(fake_age_client):
    store = _new_store(fake_age_client)

    store.write_decision(
        "soc",
        category="duplicate_risk",
        action="flag_leakage",
        confidence=0.91,
        factors={"duplicate_score": 0.8},
        metadata={"source": "unit", "entity_id": "ENT-1"},
    )

    calls = FakeAGEClient.instances[0].s_calls
    assert "ENT-1" in calls
    assert "duplicate_risk" in calls
    assert "flag_leakage" in calls
    assert any(str(value).startswith("DEC-") for value in calls)
    assert any("duplicate_score" in str(value) for value in calls)
    assert any("source" in str(value) for value in calls)


def test_age_graph_store_fails_if_client_missing_s(monkeypatch):
    class MissingSClient:
        def __init__(self, dsn=None, graph_name=None):
            pass

        async def run_query(self, query, parameters=None):
            return []

    monkeypatch.setattr("ci_platform.graph.age_graph_store.AGEClient", MissingSClient)
    from ci_platform.graph.age_graph_store import AGEGraphStore

    store = AGEGraphStore(dsn="postgresql://example/test", graph_name="test_graph")
    with pytest.raises(AttributeError):
        store.write_decision("soc", "duplicate_risk", "flag_leakage", 0.9, {})


def test_write_decision_no_entity_falls_back_to_standalone(fake_age_client):
    store = _new_store(fake_age_client)

    store.write_decision(
        "soc",
        "price_variance",
        "hold_for_review",
        0.7,
        {},
    )

    queries = [query for query, _ in FakeAGEClient.instances[0].queries]
    assert len(queries) == 1
    assert "MATCH (e {entity_id:" not in queries[0]
    assert "CREATE (d:Decision" in queries[0]
    assert "DECIDED_ON" not in queries[0]


def test_write_decision_with_entity_creates_edge_in_same_query(fake_age_client):
    store = _new_store(fake_age_client)
    FakeAGEClient.instances[0].responses.append([{"d": {"decision_id": "DEC-existing"}}])

    store.write_decision(
        "soc",
        "duplicate_risk",
        "flag_leakage",
        0.9,
        {},
        metadata={"entity_id": "ENT-1"},
    )

    queries = [query for query, _ in FakeAGEClient.instances[0].queries]
    assert len(queries) == 1
    assert "CREATE (d:Decision" in queries[0]
    assert "CREATE (d)-[:DECIDED_ON]->(e)" in queries[0]


def test_get_verified_decisions_merges_outcome(fake_age_client):
    store = _new_store(fake_age_client)
    FakeAGEClient.instances[0].responses.append(
        [
            {
                "d": {"decision_id": "DEC-1", "category": "duplicate_risk"},
                "o": {"actual_action": "flag_leakage", "is_correct": True},
            }
        ]
    )

    rows = store.get_verified_decisions("soc")

    assert rows == [
        {
            "decision_id": "DEC-1",
            "category": "duplicate_risk",
            "actual_action": "flag_leakage",
            "is_correct": True,
        }
    ]


def test_count_methods_parse_ints(fake_age_client):
    store = _new_store(fake_age_client)
    FakeAGEClient.instances[0].responses.extend([[{"cnt": "2"}], [{"cnt": 1}]])

    assert store.count_verified("soc") == 2
    assert store.count_correct("soc") == 1


def test_count_decisions_parses_int(fake_age_client):
    store = _new_store(fake_age_client)
    FakeAGEClient.instances[0].responses.append([{"cnt": "3"}])

    assert store.count_decisions("soc") == 3


def test_count_categories_with_n_queries_domain_threshold_and_returns_int(fake_age_client):
    store = _new_store(fake_age_client)
    FakeAGEClient.instances[0].responses.append([{"cnt": "2"}])

    assert store.count_categories_with_n("soc", n=3) == 2

    query, parameters = FakeAGEClient.instances[0].queries[0]
    assert parameters is None
    assert "MATCH (d:Decision)-[:HAS_OUTCOME]->(o:Outcome)" in query
    assert "d.domain = 'soc'" in query
    assert "outcome_count >= 3" in query
    assert "RETURN count(category) AS cnt" in query
    assert "MERGE" not in query
    assert "$" not in query


def test_count_categories_with_n_no_rows_returns_zero(fake_age_client):
    store = _new_store(fake_age_client)

    assert store.count_categories_with_n("soc", n=2) == 0


def test_update_dk_weights_first_write_creates_current_without_merge(fake_age_client):
    store = _new_store(fake_age_client)

    store.update_dk_weights("soc", [[0.1, 0.2], [0.3, 0.4]], 7, 123.5)

    client = FakeAGEClient.instances[0]
    queries = [query for query, _ in client.queries]
    tx_queries = client.transactions[0].cypher
    joined = "\n".join(queries + tx_queries)
    assert len(client.transactions) == 1
    assert "MATCH (w:L5DKWeight)" in queries[0]
    assert "WHERE w.domain = 'soc'" in queries[0]
    assert len(tx_queries) == 2
    assert "DELETE w" in tx_queries[0]
    assert "CREATE (w:L5DKWeight" in tx_queries[1]
    assert "L5DKWeightArchive" not in joined
    assert "SUPERSEDES" not in joined
    assert "weight_json: '[[0.1,0.2],[0.3,0.4]]'" in tx_queries[1]
    assert "n_decisions_used: 7" in tx_queries[1]
    assert "computed_at: 123.5" in tx_queries[1]
    assert "supersedes_id: null" in tx_queries[1]
    assert "$" not in joined
    assert "MERGE" not in joined
    assert "confirmed_mean" not in joined
    assert "m2_confirmed" not in joined


def test_update_dk_weights_second_write_archives_and_supersedes(fake_age_client):
    store = _new_store(fake_age_client)
    FakeAGEClient.instances[0].responses.append(
        [
            {
                "w": {
                    "properties": {
                        "dk_weight_id": "soc:dkw:old",
                        "domain": "soc",
                        "weight_json": "[[0.9,0.8]]",
                        "n_decisions_used": 5,
                        "computed_at": 11.0,
                        "created_at": 22.0,
                    }
                }
            }
        ]
    )

    store.update_dk_weights("soc", [[0.1, 0.2]], 8, 124.5)

    tx_queries = FakeAGEClient.instances[0].transactions[0].cypher
    joined = "\n".join(tx_queries)
    assert len(tx_queries) == 5
    assert "CREATE (a:L5DKWeightArchive" in tx_queries[0]
    assert "archive_id:" in tx_queries[0]
    assert "dk_weight_id: 'soc:dkw:old'" in tx_queries[0]
    assert "weight_json: '[[0.9,0.8]]'" in tx_queries[0]
    assert "MATCH (w:L5DKWeight)-[r:SUPERSEDES]->()" in tx_queries[1]
    assert "WHERE w.domain = 'soc'" in tx_queries[1]
    assert "DELETE r" in tx_queries[1]
    assert "DELETE w" in tx_queries[2]
    assert "CREATE (w:L5DKWeight" in tx_queries[3]
    assert "supersedes_id: 'soc:dkw_archive:" in tx_queries[3]
    assert "CREATE (w)-[:SUPERSEDES]->(a)" in tx_queries[4]
    assert tx_queries[0].index("L5DKWeightArchive") < joined.index("DELETE r")
    assert joined.index("DELETE r") < joined.index("DELETE w")
    assert joined.index("DELETE w") < joined.index("CREATE (w:L5DKWeight")
    assert joined.index("CREATE (w:L5DKWeight") < joined.index("CREATE (w)-[:SUPERSEDES]->(a)")
    assert "DKWeightArchive" not in joined.replace("L5DKWeightArchive", "")
    assert "MERGE" not in joined


def test_update_dk_weights_third_write_deletes_existing_supersedes_before_current_node(fake_age_client):
    store = _new_store(fake_age_client)
    FakeAGEClient.instances[0].responses.append(
        [
            {
                "w": {
                    "properties": {
                        "dk_weight_id": "soc:dkw:second",
                        "domain": "soc",
                        "weight_json": "[[0.7,0.6]]",
                        "n_decisions_used": 6,
                        "computed_at": 12.0,
                        "created_at": 23.0,
                        "supersedes_id": "soc:dkw_archive:first",
                    }
                }
            }
        ]
    )

    store.update_dk_weights("soc", [[0.1, 0.2]], 9, 125.5)

    tx_queries = FakeAGEClient.instances[0].transactions[0].cypher
    joined = "\n".join(tx_queries)
    assert len(tx_queries) == 5
    assert "CREATE (a:L5DKWeightArchive" in tx_queries[0]
    assert "dk_weight_id: 'soc:dkw:second'" in tx_queries[0]
    assert "MATCH (w:L5DKWeight)-[r:SUPERSEDES]->()" in tx_queries[1]
    assert "WHERE w.domain = 'soc'" in tx_queries[1]
    assert "DELETE r" in tx_queries[1]
    assert "DELETE w" in tx_queries[2]
    assert "CREATE (w:L5DKWeight" in tx_queries[3]
    assert "CREATE (w)-[:SUPERSEDES]->(a)" in tx_queries[4]
    assert joined.index("CREATE (a:L5DKWeightArchive") < joined.index("DELETE r")
    assert joined.index("DELETE r") < joined.index("DELETE w")
    assert joined.index("DELETE w") < joined.index("CREATE (w:L5DKWeight")
    assert joined.index("CREATE (w:L5DKWeight") < joined.index("CREATE (w)-[:SUPERSEDES]->(a)")
    assert "MATCH ()-[r:SUPERSEDES]->()" not in joined
    assert "MERGE" not in joined


def test_update_dk_weights_transaction_failure_propagates(monkeypatch):
    class FailingClient(FakeAGEClient):
        async def run_transaction(self, fn):
            raise RuntimeError("write failed")

    monkeypatch.setattr("ci_platform.graph.age_graph_store.AGEClient", FailingClient)
    from ci_platform.graph.age_graph_store import AGEGraphStore

    store = AGEGraphStore(dsn="postgresql://example/test", graph_name="test_graph")
    with pytest.raises(RuntimeError, match="write failed"):
        store.update_dk_weights("soc", [[0.1]], 1, 1.0)


def test_get_dk_weights_reads_current_and_decodes_tensor(fake_age_client):
    store = _new_store(fake_age_client)
    FakeAGEClient.instances[0].responses.append(
        [
            {
                "domain": "soc",
                "weight_json": "[[0.1,0.2],[0.3,0.4]]",
                "n_decisions_used": 7,
                "computed_at": 123.5,
                "created_at": 456.0,
                "supersedes_id": "soc:dkw_archive:old",
            }
        ]
    )

    row = store.get_dk_weights("soc")

    assert row == {
        "domain": "soc",
        "weight_json": [[0.1, 0.2], [0.3, 0.4]],
        "n_decisions_used": 7,
        "computed_at": 123.5,
        "created_at": 456.0,
        "supersedes_id": "soc:dkw_archive:old",
    }
    query = FakeAGEClient.instances[0].queries[0][0]
    assert "MATCH (w:L5DKWeight)" in query
    assert "WHERE w.domain = 'soc'" in query
    assert "L5DKWeightArchive" not in query
    assert "ORDER BY created_at DESC, dk_weight_id DESC" in query
    assert "LIMIT 1" in query
    assert "MERGE" not in query


def test_age_dk_weight_duplicate_returns_latest(fake_age_client):
    store = _new_store(fake_age_client)
    FakeAGEClient.instances[0].responses.append(
        [
            {
                "domain": "soc",
                "dk_weight_id": "soc:dkw:old",
                "weight_json": "[[0.1]]",
                "n_decisions_used": 1,
                "computed_at": 100.0,
                "created_at": 100.0,
                "supersedes_id": None,
            },
            {
                "domain": "soc",
                "dk_weight_id": "soc:dkw:new",
                "weight_json": "[[0.9]]",
                "n_decisions_used": 9,
                "computed_at": 200.0,
                "created_at": 200.0,
                "supersedes_id": "soc:dkw_archive:old",
            },
        ]
    )

    row = store.get_dk_weights("soc")

    query = FakeAGEClient.instances[0].queries[0][0]
    assert "MATCH (w:L5DKWeight)" in query
    assert "WHERE w.domain = 'soc'" in query
    assert "L5DKWeightArchive" not in query
    assert "ORDER BY created_at DESC, dk_weight_id DESC" in query
    assert "LIMIT 1" in query
    assert "MERGE" not in query
    assert row["weight_json"] == [[0.9]]
    assert row["created_at"] == 200.0
    assert row["supersedes_id"] == "soc:dkw_archive:old"


def test_get_dk_weights_returns_none_for_no_current(fake_age_client):
    store = _new_store(fake_age_client)

    assert store.get_dk_weights("soc") is None


def test_get_dk_weights_revalidates_corrupt_stored_tensor(fake_age_client):
    store = _new_store(fake_age_client)
    FakeAGEClient.instances[0].responses.append(
        [
            {
                "domain": "soc",
                "weight_json": "[[0.1],[0.2,0.3]]",
                "n_decisions_used": 7,
                "computed_at": 123.5,
                "created_at": 456.0,
                "supersedes_id": None,
            }
        ]
    )

    with pytest.raises((TypeError, ValueError)):
        store.get_dk_weights("soc")


@pytest.mark.parametrize(
    "bad_tensor",
    [
        [0.1, 0.2],
        [],
        [[]],
        [[1.0], [2.0, 3.0]],
        "12",
        b"12",
        {"row": [1.0]},
        ["12"],
        [b"12"],
        [{"row": 1.0}],
        object(),
        [[1.0, "bad"]],
    ],
)
def test_update_dk_weights_rejects_bad_tensors(fake_age_client, bad_tensor):
    store = _new_store(fake_age_client)

    with pytest.raises((TypeError, ValueError)):
        store.update_dk_weights("soc", bad_tensor, 1, 1.0)


def test_update_dk_weights_rejects_bad_scalars(fake_age_client):
    store = _new_store(fake_age_client)

    with pytest.raises((TypeError, ValueError)):
        store.update_dk_weights("soc", [[1.0]], -1, 1.0)
    with pytest.raises((TypeError, ValueError)):
        store.update_dk_weights("soc", [[1.0]], 1, "bad-time")


def test_update_conservation_state_creates_l5_state_without_merge_or_initial_edge(fake_age_client):
    store = _new_store(fake_age_client)

    state_id = store.update_conservation_state(**_conservation_payload(old_status=None))

    queries = [query for query, _ in FakeAGEClient.instances[0].queries]
    joined = "\n".join(queries)
    assert state_id.startswith("soc:conservation:")
    assert len(queries) == 3
    assert "MATCH (cs:L5ConservationState)-[r:TRIGGERED_BY]->()" in queries[0]
    assert "DELETE r" in queries[0]
    assert "MATCH (cs:L5ConservationState)" in queries[1]
    assert "DELETE cs" in queries[1]
    assert "CREATE (cs:L5ConservationState" in queries[2]
    assert "status: 'GREEN'" in queries[2]
    assert "alpha: 0.25" in queries[2]
    assert "q: 0.8" in queries[2]
    assert "V: 42" in queries[2]
    assert "theta_min: 23.53" in queries[2]
    assert "product: 18.824" in queries[2]
    assert "baseline_product: 20.0" in queries[2]
    assert "relative_threshold: 0.9412" in queries[2]
    assert "complacency_flag: 'false'" in queries[2]
    assert "TRIGGERED_BY {" not in joined
    assert "MERGE" not in joined


def test_update_conservation_state_same_status_creates_no_triggered_by(fake_age_client):
    store = _new_store(fake_age_client)

    store.update_conservation_state(**_conservation_payload(status="GREEN", old_status="GREEN"))

    queries = [query for query, _ in FakeAGEClient.instances[0].queries]
    assert len(queries) == 3
    assert "TRIGGERED_BY {" not in "\n".join(queries)


def test_update_conservation_state_transition_creates_triggered_by(fake_age_client):
    store = _new_store(fake_age_client)
    FakeAGEClient.instances[0].responses = [[], [], [], [{"cs": {}, "d": {}}]]

    store.update_conservation_state(**_conservation_payload(status="RED", old_status="GREEN"))

    queries = [query for query, _ in FakeAGEClient.instances[0].queries]
    joined = "\n".join(queries)
    assert len(queries) == 4
    assert "CREATE (cs)-[:TRIGGERED_BY" in queries[3]
    assert "old_status: 'GREEN'" in queries[3]
    assert "new_status: 'RED'" in queries[3]
    assert "MATCH (d:Decision {decision_id: 'DEC-1'})" in queries[3]
    assert "WHERE d.domain = 'soc'" in queries[3]
    assert "MERGE" not in joined


def test_update_conservation_state_transition_without_decision_id_creates_no_edge(fake_age_client):
    store = _new_store(fake_age_client)

    store.update_conservation_state(
        **_conservation_payload(status="RED", old_status="GREEN", caused_by_decision_id=None)
    )

    queries = [query for query, _ in FakeAGEClient.instances[0].queries]
    assert len(queries) == 3
    assert "TRIGGERED_BY {" not in "\n".join(queries)


def test_update_conservation_state_missing_decision_is_non_fatal(fake_age_client):
    store = _new_store(fake_age_client)

    state_id = store.update_conservation_state(
        **_conservation_payload(status="RED", old_status="GREEN")
    )

    assert state_id.startswith("soc:conservation:")
    assert len(FakeAGEClient.instances[0].queries) == 4


def test_update_conservation_state_edge_failure_is_non_fatal(fake_age_client, monkeypatch):
    store = _new_store(fake_age_client)
    queries = []

    def fake_run_query(query):
        queries.append(query)
        if "CREATE (cs)-[:TRIGGERED_BY" in query:
            raise RuntimeError("edge failure")
        return []

    monkeypatch.setattr(store, "_run_query", fake_run_query)

    state_id = store.update_conservation_state(
        **_conservation_payload(status="RED", old_status="GREEN")
    )

    assert state_id.startswith("soc:conservation:")
    assert any("CREATE (cs:L5ConservationState" in query for query in queries)
    assert any("CREATE (cs)-[:TRIGGERED_BY" in query for query in queries)


def test_update_conservation_state_write_failure_propagates(fake_age_client, monkeypatch):
    store = _new_store(fake_age_client)

    def fake_run_query(query):
        if "CREATE (cs:L5ConservationState" in query:
            raise RuntimeError("write failure")
        return []

    monkeypatch.setattr(store, "_run_query", fake_run_query)

    with pytest.raises(RuntimeError):
        store.update_conservation_state(**_conservation_payload(old_status=None))


def test_get_conservation_state_reads_l5_state(fake_age_client):
    store = _new_store(fake_age_client)
    FakeAGEClient.instances[0].responses.append([_conservation_row()])

    row = store.get_conservation_state("soc")

    query = FakeAGEClient.instances[0].queries[0][0]
    assert "MATCH (cs:L5ConservationState)" in query
    assert "WHERE cs.domain = 'soc'" in query
    assert "ORDER BY updated_at DESC, id DESC" in query
    assert "LIMIT 1" in query
    assert row == {
        "id": "soc:conservation:1",
        "domain": "soc",
        "status": "GREEN",
        "alpha": 0.25,
        "q": 0.8,
        "V": 42,
        "theta_min": 23.53,
        "product": 18.824,
        "categories_total": 6,
        "categories_with_data": 4,
        "baseline_product": 20.0,
        "relative_threshold": 0.9412,
        "complacency_flag": "false",
        "caused_by_decision_id": "DEC-1",
        "old_status": "AMBER",
        "updated_at": "2026-06-05T00:00:00Z",
    }


def test_age_conservation_duplicate_returns_latest(fake_age_client):
    store = _new_store(fake_age_client)
    FakeAGEClient.instances[0].responses.append(
        [
            _conservation_row(
                id="soc:conservation:old",
                status="AMBER",
                updated_at="2026-06-05T00:00:00Z",
            ),
            _conservation_row(
                id="soc:conservation:new",
                status="RED",
                updated_at="2026-06-05T01:00:00Z",
            ),
        ]
    )

    row = store.get_conservation_state("soc")

    query = FakeAGEClient.instances[0].queries[0][0]
    assert "MATCH (cs:L5ConservationState)" in query
    assert "WHERE cs.domain = 'soc'" in query
    assert "ORDER BY updated_at DESC, id DESC" in query
    assert "LIMIT 1" in query
    assert row["id"] == "soc:conservation:new"
    assert row["status"] == "RED"
    assert row["updated_at"] == "2026-06-05T01:00:00Z"


def test_get_conservation_state_returns_none_for_unknown_domain(fake_age_client):
    store = _new_store(fake_age_client)

    assert store.get_conservation_state("soc") is None


@pytest.mark.parametrize("missing_field", ["theta_min", "q", "V"])
def test_get_conservation_state_rejects_missing_required_numeric_fields(
    fake_age_client, missing_field
):
    store = _new_store(fake_age_client)
    row = _conservation_row()
    row.pop(missing_field)
    FakeAGEClient.instances[0].responses.append([row])

    with pytest.raises((TypeError, ValueError)):
        store.get_conservation_state("soc")


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("theta_min", "not-numeric"),
        ("status", "BLUE"),
        ("complacency_flag", "TRUE"),
        ("categories_with_data", 7),
    ],
)
def test_get_conservation_state_rejects_malformed_required_fields(
    fake_age_client, field, value
):
    store = _new_store(fake_age_client)
    FakeAGEClient.instances[0].responses.append([_conservation_row(**{field: value})])

    with pytest.raises((TypeError, ValueError)):
        store.get_conservation_state("soc")


def test_get_conservation_state_allows_missing_optional_fields(fake_age_client):
    store = _new_store(fake_age_client)
    row = _conservation_row()
    row.pop("caused_by_decision_id")
    row.pop("old_status")
    FakeAGEClient.instances[0].responses.append([row])

    state = store.get_conservation_state("soc")

    assert state is not None
    assert state["caused_by_decision_id"] is None
    assert state["old_status"] is None


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("domain", ""),
        ("status", "BLUE"),
        ("alpha", -0.1),
        ("alpha", 1.1),
        ("q", -0.1),
        ("q", 1.1),
        ("V", -1),
        ("theta_min", 0.0),
        ("categories_total", -1),
        ("categories_with_data", -1),
        ("categories_with_data", 7),
        ("complacency_flag", "TRUE"),
        ("complacency_flag", True),
        ("old_status", "BLUE"),
    ],
)
def test_update_conservation_state_rejects_bad_values(fake_age_client, field, value):
    store = _new_store(fake_age_client)

    with pytest.raises((TypeError, ValueError)):
        store.update_conservation_state(**_conservation_payload(**{field: value}))


def test_domain_scoped_reset_removes_l5_centroids_and_shaped_by_edges(fake_age_client):
    store = _new_store(fake_age_client)
    client = FakeAGEClient.instances[0]
    client._graph = "protocol_v2_test_graph"

    store.domain_scoped_reset("pytest_protocol_v2_soc")

    cypher = "\n".join(client.transactions[0].cypher)
    assert "MATCH (c:L5Centroid)-[r:SHAPED_BY]->(d:Decision)" in cypher
    assert "MATCH (w:L5DKWeight)-[r:SUPERSEDES]->(a:L5DKWeightArchive)" in cypher
    assert "MATCH (cs:L5ConservationState)-[r:TRIGGERED_BY]->(d:Decision)" in cypher
    assert "MATCH (n:L5Centroid)" in cypher
    assert "MATCH (n:L5DKWeight)" in cypher
    assert "MATCH (n:L5DKWeightArchive)" in cypher
    assert "MATCH (n:L5ConservationState)" in cypher
    assert "DELETE r" in cypher
    assert "DELETE n" in cypher
    assert "MERGE" not in cypher


def test_update_centroid_deletes_and_creates_l5_centroid(fake_age_client):
    store = _new_store(fake_age_client)

    store.update_centroid(
        "soc",
        "duplicate_risk",
        "hold_for_review",
        [1, 2.5],
        0.42,
        caused_by_decision_id="DEC-1",
    )

    queries = [query for query, _ in FakeAGEClient.instances[0].queries]
    joined = "\n".join(queries)
    assert len(queries) == 3
    assert "MERGE" not in joined
    assert "CentroidCheckpoint" not in joined
    assert "MATCH (c:L5Centroid)" in queries[0]
    assert "DELETE c" in queries[0]
    assert "c.domain = 'soc'" in queries[0]
    assert "c.category = 'duplicate_risk'" in queries[0]
    assert "c.action = 'hold_for_review'" in queries[0]
    assert "CREATE (c:L5Centroid" in queries[1]
    assert "domain: 'soc'" in queries[1]
    assert "category: 'duplicate_risk'" in queries[1]
    assert "action: 'hold_for_review'" in queries[1]
    assert "vector_json: '[1.0,2.5]'" in queries[1]
    assert "delta_norm: 0.42" in queries[1]
    assert "caused_by_decision_id: 'DEC-1'" in queries[1]
    assert "updated_at_epoch:" in queries[1]
    assert "CREATE (c)-[:SHAPED_BY]->(d)" in queries[2]
    assert "MATCH (d:Decision {decision_id: 'DEC-1'})" in queries[2]


def test_update_centroid_without_decision_id_does_not_create_edge(fake_age_client):
    store = _new_store(fake_age_client)

    store.update_centroid("soc", "cat", "act", [0.1], 0.2)

    queries = [query for query, _ in FakeAGEClient.instances[0].queries]
    assert len(queries) == 2
    assert "SHAPED_BY" not in "\n".join(queries)
    assert "MERGE" not in "\n".join(queries)


def test_update_centroid_edge_failure_is_non_fatal(fake_age_client, monkeypatch):
    store = _new_store(fake_age_client)
    calls = []

    def fake_run_query(query):
        calls.append(query)
        if "SHAPED_BY" in query:
            raise RuntimeError("missing decision")
        return []

    monkeypatch.setattr(store, "_run_query", fake_run_query)

    store.update_centroid("soc", "cat", "act", [0.1], 0.2, caused_by_decision_id="DEC-1")

    assert len(calls) == 3
    assert "CREATE (c:L5Centroid" in calls[1]
    assert "SHAPED_BY" in calls[2]


def test_update_centroid_write_failure_propagates(fake_age_client, monkeypatch):
    store = _new_store(fake_age_client)

    def fake_run_query(query):
        if "CREATE (c:L5Centroid" in query:
            raise RuntimeError("write failed")
        return []

    monkeypatch.setattr(store, "_run_query", fake_run_query)

    with pytest.raises(RuntimeError, match="write failed"):
        store.update_centroid("soc", "cat", "act", [0.1], 0.2)


def test_get_centroids_reads_l5_centroids_and_decodes_vector(fake_age_client):
    store = _new_store(fake_age_client)
    FakeAGEClient.instances[0].responses.append(
        [
            {
                "category": "alpha",
                "action": "approve",
                "vector_json": "[1.0,2.5]",
                "delta_norm": 0.3,
                "caused_by_decision_id": "DEC-1",
                "updated_at_epoch": 123.4,
            }
        ]
    )

    rows = store.get_centroids("soc")

    query, parameters = FakeAGEClient.instances[0].queries[0]
    assert parameters is None
    assert "MATCH (c:L5Centroid)" in query
    assert "WHERE c.domain = 'soc'" in query
    assert "ORDER BY category, action, updated_at_epoch DESC" in query
    assert "MERGE" not in query
    assert rows == [
        {
            "category": "alpha",
            "action": "approve",
            "vector_json": [1.0, 2.5],
            "delta_norm": 0.3,
            "caused_by_decision_id": "DEC-1",
            "updated_at": 123.4,
        }
    ]


def test_age_centroid_duplicate_returns_latest(fake_age_client):
    store = _new_store(fake_age_client)
    FakeAGEClient.instances[0].responses.append(
        [
            {
                "category": "alpha",
                "action": "approve",
                "vector_json": "[1.0]",
                "delta_norm": 0.1,
                "caused_by_decision_id": "DEC-OLD",
                "updated_at_epoch": 100.0,
            },
            {
                "category": "beta",
                "action": "review",
                "vector_json": "[3.0]",
                "delta_norm": 0.3,
                "caused_by_decision_id": "DEC-BETA",
                "updated_at_epoch": 150.0,
            },
            {
                "category": "alpha",
                "action": "approve",
                "vector_json": "[2.0]",
                "delta_norm": 0.2,
                "caused_by_decision_id": "DEC-NEW",
                "updated_at_epoch": 200.0,
            },
        ]
    )

    rows = store.get_centroids("soc")

    query = FakeAGEClient.instances[0].queries[0][0]
    identities = [(row["category"], row["action"]) for row in rows]
    assert "ORDER BY category, action, updated_at_epoch DESC" in query
    assert len(identities) == len(set(identities))
    assert rows == [
        {
            "category": "alpha",
            "action": "approve",
            "vector_json": [2.0],
            "delta_norm": 0.2,
            "caused_by_decision_id": "DEC-NEW",
            "updated_at": 200.0,
        },
        {
            "category": "beta",
            "action": "review",
            "vector_json": [3.0],
            "delta_norm": 0.3,
            "caused_by_decision_id": "DEC-BETA",
            "updated_at": 150.0,
        },
    ]


def test_get_centroids_empty_result_returns_empty_list(fake_age_client):
    store = _new_store(fake_age_client)

    assert store.get_centroids("soc") == []


def test_get_centroids_malformed_vector_json_raises(fake_age_client):
    store = _new_store(fake_age_client)
    FakeAGEClient.instances[0].responses.append(
        [{"category": "cat", "action": "act", "vector_json": "not-json"}]
    )

    with pytest.raises(ValueError):
        store.get_centroids("soc")


@pytest.mark.parametrize("bad_vector", ["123", b"123", {"a": 1}, object(), [1, "bad"]])
def test_update_centroid_rejects_bad_vectors(fake_age_client, bad_vector):
    store = _new_store(fake_age_client)

    with pytest.raises((TypeError, ValueError)):
        store.update_centroid("soc", "cat", "act", bad_vector, 0.1)


def test_update_centroid_rejects_bad_delta_norm(fake_age_client):
    store = _new_store(fake_age_client)

    with pytest.raises((TypeError, ValueError)):
        store.update_centroid("soc", "cat", "act", [0.1], "bad")


def test_save_centroids_creates_node(fake_age_client):
    store = _new_store(fake_age_client)

    store.save_centroids(
        "soc",
        "duplicate_risk",
        [[0.1, 0.2], [0.3, 0.4]],
        metadata={"iks": 0.42},
        decision_id="DEC-1",
    )

    query, parameters = FakeAGEClient.instances[0].queries[0]
    assert parameters is None
    assert "CentroidCheckpoint" in query
    assert "HAS_CENTROID_CHECKPOINT" in query
    assert "$" not in query
    assert "ON CREATE SET" not in query
    assert "MERGE" not in query
    assert "DEC-1" in query
    assert "duplicate_risk" in query
    assert "0.42" in query


def test_save_centroids_without_metadata(fake_age_client):
    store = _new_store(fake_age_client)

    store.save_centroids("soc", "price_variance", [[0.5]], decision_id="DEC-1")

    query = FakeAGEClient.instances[0].queries[0][0]
    assert "CentroidCheckpoint" in query
    assert "{}" in query


def test_save_centroids_handles_numpy_like(fake_age_client):
    class ArrayLike:
        def tolist(self):
            return [[0.1, 0.2]]

    store = _new_store(fake_age_client)

    store.save_centroids("soc", "duplicate_risk", ArrayLike(), decision_id="DEC-1")

    calls = FakeAGEClient.instances[0].s_calls
    assert any("[[0.1, 0.2]]" in str(value) for value in calls)


def test_save_evolution_event_creates_node(fake_age_client):
    store = _new_store(fake_age_client)

    store.save_evolution_event(
        "soc",
        "variant_generated",
        "threshold_rule",
        "variant-1",
        metadata={"seed": 42},
    )

    query, parameters = FakeAGEClient.instances[0].queries[0]
    assert parameters is None
    assert "EvolutionEvent" in query
    assert "event_type" in query
    assert "variant_generated" in query
    assert "rule_name" in query
    assert "threshold_rule" in query
    assert "variant_id" in query
    assert "variant-1" in query
    assert "metadata" in query
    assert "seed" in query
    assert "timestamp" in query
    assert "$" not in query
    assert "ON CREATE SET" not in query
    assert "MERGE" not in query


def test_save_evolution_event_without_metadata(fake_age_client):
    store = _new_store(fake_age_client)

    store.save_evolution_event("soc", "rejected", "factor_rule", "variant-2")

    query = FakeAGEClient.instances[0].queries[0][0]
    assert "EvolutionEvent" in query
    assert "{}" in query


def test_link_decision_to_entity_creates_relationship_when_entity_exists(fake_age_client):
    store = _new_store(fake_age_client)
    FakeAGEClient.instances[0].responses.append([{"d": {"decision_id": "DEC-1"}}])

    store.link_decision_to_entity("DEC-1", "ENT-1")

    queries = [query for query, _ in FakeAGEClient.instances[0].queries]
    assert len(queries) == 1
    assert "MATCH (d:Decision {decision_id:" in queries[0]
    assert "MATCH (e {entity_id:" in queries[0]
    assert "CREATE (d)-[:DECIDED_ON" in queries[0]
    assert "DecisionEntityLink" not in queries[0]
    assert "$" not in queries[0]
    assert "MERGE" not in queries[0]


def test_link_decision_to_entity_falls_back_to_link_node(fake_age_client):
    store = _new_store(fake_age_client)

    store.link_decision_to_entity("DEC-1", "ENT-1", edge_type="REVIEWS")

    queries = [query for query, _ in FakeAGEClient.instances[0].queries]
    assert len(queries) == 2
    assert "CREATE (d)-[:REVIEWS" in queries[0]
    assert "CREATE (l:DecisionEntityLink" in queries[1]
    assert "REVIEWS" in queries[1]
    assert "$" not in queries[1]
    assert "MERGE" not in queries[1]


def test_link_decision_to_entity_rejects_unsafe_edge_type(fake_age_client):
    store = _new_store(fake_age_client)

    with pytest.raises(ValueError, match="Invalid edge_type"):
        store.link_decision_to_entity("DEC-1", "ENT-1", edge_type="BAD EDGE")


def test_get_decision_links_reads_relationships_and_link_nodes(fake_age_client):
    store = _new_store(fake_age_client)
    FakeAGEClient.instances[0].responses.extend(
        [
            [
                {
                    "decision_id": "DEC-1",
                    "entity_id": "ENT-1",
                    "edge_type": "DECIDED_ON",
                    "created_at": "2026-01-01T00:00:00+00:00",
                }
            ],
            [
                {
                    "l": {
                        "properties": {
                            "decision_id": "DEC-2",
                            "entity_id": "ENT-2",
                            "edge_type": "REVIEWS",
                            "created_at": "2026-01-02T00:00:00+00:00",
                        }
                    }
                }
            ],
        ]
    )

    links = store.get_decision_links("DEC-1")

    assert links == [
        {
            "decision_id": "DEC-1",
            "entity_id": "ENT-1",
            "edge_type": "DECIDED_ON",
            "created_at": "2026-01-01T00:00:00+00:00",
        },
        {
            "decision_id": "DEC-2",
            "entity_id": "ENT-2",
            "edge_type": "REVIEWS",
            "created_at": "2026-01-02T00:00:00+00:00",
        },
    ]
    queries = [query for query, _ in FakeAGEClient.instances[0].queries]
    assert "WHERE d.decision_id = 'DEC-1'" in queries[0]
    assert "WHERE l.decision_id = 'DEC-1'" in queries[1]
    assert "$" not in "\n".join(queries)
    assert "MERGE" not in "\n".join(queries)


def test_get_centroid_checkpoints_returns_list(fake_age_client):
    store = _new_store(fake_age_client)
    FakeAGEClient.instances[0].responses.append(
        [
            {
                "c": {
                    "properties": {
                        "decision_id": "DEC-2",
                        "category": "price_variance",
                        "centroids": "[[0.3, 0.4]]",
                        "metadata": '{"iks": 0.6}',
                        "created_at": "2026-01-02T00:00:00+00:00",
                    }
                }
            },
            {
                "c": {
                    "properties": {
                        "decision_id": "DEC-1",
                        "category": "duplicate_risk",
                        "centroids": "[[0.1, 0.2]]",
                        "metadata": '{"iks": 0.4}',
                        "created_at": "2026-01-01T00:00:00+00:00",
                    }
                }
            },
        ]
    )

    checkpoints = store.get_centroid_checkpoints("soc", limit=2)

    assert [checkpoint["decision_id"] for checkpoint in checkpoints] == ["DEC-1", "DEC-2"]
    assert checkpoints[0]["centroids"] == [[0.1, 0.2]]
    assert checkpoints[0]["metadata"] == {"iks": 0.4}


def test_get_centroid_checkpoints_limit_clamped(fake_age_client):
    store = _new_store(fake_age_client)

    store.get_centroid_checkpoints("soc", limit=-1)
    store.get_centroid_checkpoints("soc", limit=2000)

    queries = "\n".join(query for query, _ in FakeAGEClient.instances[0].queries)
    assert "LIMIT -1" not in queries
    assert "LIMIT 2000" not in queries
    assert "LIMIT 1" in queries
    assert "LIMIT 1000" in queries


def test_get_centroid_checkpoints_parses_json_strings(fake_age_client):
    store = _new_store(fake_age_client)
    FakeAGEClient.instances[0].responses.append(
        [
            {
                "c": {
                    "decision_id": "DEC-1",
                    "category": "duplicate_risk",
                    "centroids": "[[0.7]]",
                    "metadata": "not-json",
                }
            }
        ]
    )

    checkpoints = store.get_centroid_checkpoints("soc")

    assert checkpoints == [
        {
            "decision_id": "DEC-1",
            "category": "duplicate_risk",
            "centroids": [[0.7]],
            "metadata": {},
        }
    ]


def test_load_latest_centroids_returns_numpy_payload(fake_age_client):
    store = _new_store(fake_age_client)
    FakeAGEClient.instances[0].responses.append(
        [{"c": {"properties": {"centroids": "[[0.1, 0.2]]"}}}]
    )

    centroids = store.load_latest_centroids("soc")

    assert centroids.tolist() == [[0.1, 0.2]]


def test_get_evolution_events_filters_domain_and_metadata(fake_age_client):
    store = _new_store(fake_age_client)
    FakeAGEClient.instances[0].responses.append(
        [{"e": {"properties": {"event_type": "variant_generated", "metadata": '{"seed": 42}'}}}]
    )

    events = store.get_evolution_events("soc", event_type="variant_generated", limit=5)

    query = FakeAGEClient.instances[0].queries[0][0]
    assert "e.domain = 'soc'" in query
    assert "e.event_type = 'variant_generated'" in query
    assert events == [{"event_type": "variant_generated", "metadata": {"seed": 42}}]


def test_archive_methods_are_explicit_noops(fake_age_client):
    store = _new_store(fake_age_client)

    assert store.archive_old_decisions("soc") == 0
    assert store.count_archived("soc") == 0


def test_close_swallows_exceptions(fake_age_client, monkeypatch):
    store = _new_store(fake_age_client)

    async def boom():
        raise RuntimeError("close failed")

    FakeAGEClient.instances[0].close = boom
    store.close()


GRAPH_DSN = os.getenv("GRAPH_DSN")


@pytest.mark.skipif(not GRAPH_DSN, reason="GRAPH_DSN missing; skipping live AGE tests")
class TestAGEGraphStoreLive:
    def test_live_write_decision_returns_id(self):
        from ci_platform.graph import AGEGraphStore

        store = AGEGraphStore(dsn=GRAPH_DSN, graph_name="test_graph")
        decision_id = store.write_decision(
            "soc",
            "duplicate_risk",
            "flag_leakage",
            0.9,
            {"duplicate_score": 0.8},
            metadata={"entity_id": "LIVE-ENT-1"},
        )
        assert decision_id.startswith("DEC-")
        store.close()

    def test_live_outcome_and_counts(self):
        from ci_platform.graph import AGEGraphStore

        store = AGEGraphStore(dsn=GRAPH_DSN, graph_name="test_graph")
        decision_id = store.write_decision(
            "soc",
            "price_variance",
            "hold_for_review",
            0.7,
            {},
            metadata={"entity_id": "LIVE-ENT-2"},
        )
        store.write_outcome(decision_id, "hold_for_review", True)
        assert store.count_verified("soc") >= 1
        assert store.count_correct("soc") >= 1
        store.close()

    def test_live_save_evolution_event_no_crash(self):
        from ci_platform.graph import AGEGraphStore

        store = AGEGraphStore(dsn=GRAPH_DSN, graph_name="test_graph")
        store.save_evolution_event(
            "soc",
            "variant_generated",
            "threshold_rule",
            "variant-live",
            metadata={"source": "live-test"},
        )
        store.save_evolution_event("soc", "rejected", "factor_rule", "variant-live-empty")
        store.close()
