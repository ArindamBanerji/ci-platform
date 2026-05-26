import os
import re
import inspect

import pytest


class FakeAGEClient:
    instances = []

    def __init__(self, dsn=None, graph_name=None):
        self.dsn = dsn
        self.graph_name = graph_name
        self.queries = []
        self.responses = []
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
    from ci_platform.graph import AGEGraphStore
    from copilot_sdk.graph import GraphStore

    protocol_signature = inspect.signature(GraphStore.save_evolution_event)
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
