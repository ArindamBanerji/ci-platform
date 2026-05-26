import inspect
import os
from pathlib import Path

import pytest


class FakeGraphStore:
    def __init__(self):
        self.calls = []
        self.closed = False
        self.decisions = {
            "DEC-1": {
                "decision_id": "DEC-1",
                "entity_id": "ENT-1",
                "category": "price_variance",
                "recommended_action": "hold_for_review",
                "confidence": 0.8,
                "factors": {"amount_variance_ratio": 0.2},
            }
        }
        self.verified = [
            {
                "decision_id": "DEC-1",
                "category": "price_variance",
                "recommended_action": "hold_for_review",
                "actual_action": "hold_for_review",
                "is_correct": True,
                "factors": {"amount_variance_ratio": 0.2},
            }
        ]

    def write_decision(self, domain, category, action, confidence, factors, metadata=None):
        self.calls.append(("write_decision", domain, category, action, confidence, factors, metadata))
        return "DEC-2"

    def write_outcome(self, decision_id, actual_action, is_correct, metadata=None):
        self.calls.append(("write_outcome", decision_id, actual_action, is_correct, metadata))

    def get_decision(self, decision_id):
        self.calls.append(("get_decision", decision_id))
        return self.decisions.get(decision_id)

    def get_decisions(self, domain, category=None, limit=400):
        self.calls.append(("get_decisions", domain, category, limit))
        return list(self.decisions.values())[:limit]

    def get_verified_decisions(self, domain):
        self.calls.append(("get_verified_decisions", domain))
        return list(self.verified)

    def get_all_decisions(self, domain):
        self.calls.append(("get_all_decisions", domain))
        return list(self.decisions.values())

    def count_verified(self, domain):
        self.calls.append(("count_verified", domain))
        return len(self.verified)

    def count_correct(self, domain):
        self.calls.append(("count_correct", domain))
        return sum(1 for row in self.verified if row["is_correct"])

    def count_decisions(self, domain):
        self.calls.append(("count_decisions", domain))
        return len(self.decisions)

    def save_centroids(self, domain, category, centroids, metadata=None, **kwargs):
        self.calls.append(("save_centroids", domain, category, centroids, metadata, kwargs))

    def load_latest_centroids(self, domain):
        self.calls.append(("load_latest_centroids", domain))
        return [[0.1]]

    def get_centroid_checkpoints(self, domain, **kwargs):
        self.calls.append(("get_centroid_checkpoints", domain, kwargs))
        return [{"decision_id": "DEC-1", "category": "price_variance"}]

    def save_evolution_event(self, domain, event_type, rule_name="", variant_id="", metadata=None):
        self.calls.append(("save_evolution_event", domain, event_type, rule_name, variant_id, metadata))

    def get_evolution_events(self, domain, **kwargs):
        self.calls.append(("get_evolution_events", domain, kwargs))
        return [{"event_type": "variant_generated"}]

    def archive_old_decisions(self, domain, keep_recent=800):
        self.calls.append(("archive_old_decisions", domain, keep_recent))
        return 0

    def count_archived(self, domain):
        self.calls.append(("count_archived", domain))
        return 0

    def link_decision_to_entity(self, decision_id, entity_id, edge_type="DECIDED_ON"):
        self.calls.append(("link_decision_to_entity", decision_id, entity_id, edge_type))

    def get_decision_links(self, decision_id=None):
        self.calls.append(("get_decision_links", decision_id))
        return [
            {
                "decision_id": decision_id or "DEC-1",
                "entity_id": "ENT-1",
                "edge_type": "DECIDED_ON",
            }
        ]

    def close(self):
        self.calls.append(("close",))
        self.closed = True


def test_adapter_importable():
    from ci_platform.graph.age_sdk_adapter import AGEGraphStoreAdapter

    assert AGEGraphStoreAdapter is not None


def test_adapter_exported_from_graph_package():
    from ci_platform.graph import AGEGraphStoreAdapter

    assert AGEGraphStoreAdapter is not None


def test_adapter_has_all_protocol_methods():
    pytest.importorskip("copilot_sdk.graph")
    from ci_platform.graph.age_sdk_adapter import AGEGraphStoreAdapter
    from copilot_sdk.graph import GraphStore

    protocol_methods = [name for name in dir(GraphStore) if not name.startswith("_")]
    missing = [name for name in protocol_methods if not hasattr(AGEGraphStoreAdapter, name)]

    assert missing == []


def test_adapter_method_signatures_match_protocol():
    pytest.importorskip("copilot_sdk.graph")
    from ci_platform.graph.age_sdk_adapter import AGEGraphStoreAdapter
    from copilot_sdk.graph import GraphStore

    protocol_methods = [name for name in dir(GraphStore) if not name.startswith("_")]
    for method_name in protocol_methods:
        protocol_signature = inspect.signature(getattr(GraphStore, method_name))
        adapter_signature = inspect.signature(getattr(AGEGraphStoreAdapter, method_name))
        assert list(adapter_signature.parameters) == list(protocol_signature.parameters)
        for name, parameter in protocol_signature.parameters.items():
            assert adapter_signature.parameters[name].default == parameter.default


def test_adapter_satisfies_sdk_protocol_with_fake_store():
    pytest.importorskip("copilot_sdk.graph")
    from ci_platform.graph.age_sdk_adapter import AGEGraphStoreAdapter
    from copilot_sdk.graph import GraphStore

    adapter = AGEGraphStoreAdapter(store=FakeGraphStore())

    assert isinstance(adapter, GraphStore)


def test_adapter_requires_dsn_without_store():
    from ci_platform.graph.age_sdk_adapter import AGEGraphStoreAdapter

    with pytest.raises(ValueError, match="dsn is required"):
        AGEGraphStoreAdapter()


def test_adapter_delegates_decision_and_outcome_methods():
    from ci_platform.graph.age_sdk_adapter import AGEGraphStoreAdapter

    store = FakeGraphStore()
    adapter = AGEGraphStoreAdapter(store=store)

    decision_id = adapter.write_decision(
        "soc",
        category="duplicate_risk",
        action="flag_leakage",
        confidence=0.91,
        factors={"duplicate_score": 0.8},
        metadata={"source": "unit", "entity_id": "ENT-2"},
    )
    adapter.write_outcome(decision_id, "flag_leakage", True, metadata={"verified_by": "unit"})

    assert decision_id == "DEC-2"
    assert store.calls[0] == (
        "write_decision",
        "soc",
        "duplicate_risk",
        "flag_leakage",
        0.91,
        {"duplicate_score": 0.8},
        {"source": "unit", "entity_id": "ENT-2"},
    )
    assert store.calls[1] == (
        "write_outcome",
        "DEC-2",
        "flag_leakage",
        True,
        {"verified_by": "unit"},
    )


def test_adapter_get_verified_decisions_shape_for_sdk_shadow_runner():
    from ci_platform.graph.age_sdk_adapter import AGEGraphStoreAdapter

    adapter = AGEGraphStoreAdapter(store=FakeGraphStore())

    verified = adapter.get_verified_decisions("soc")

    assert verified
    row = verified[0]
    for key in ("decision_id", "recommended_action", "actual_action", "is_correct", "factors", "category"):
        assert key in row


def test_adapter_delegates_counts_and_reads():
    from ci_platform.graph.age_sdk_adapter import AGEGraphStoreAdapter

    store = FakeGraphStore()
    adapter = AGEGraphStoreAdapter(store=store)

    assert adapter.get_decision("DEC-1")["decision_id"] == "DEC-1"
    assert adapter.get_decisions("soc", category="price_variance", limit=10)
    assert adapter.get_all_decisions("soc")
    assert adapter.count_verified("soc") == 1
    assert adapter.count_correct("soc") == 1
    assert adapter.count_decisions("soc") == 1


def test_adapter_delegates_centroids_and_evolution_events():
    from ci_platform.graph.age_sdk_adapter import AGEGraphStoreAdapter

    store = FakeGraphStore()
    adapter = AGEGraphStoreAdapter(store=store)

    adapter.save_centroids("soc", "price_variance", [[0.1]], metadata={"iks": 0.5}, decision_id="DEC-1")
    latest = adapter.load_latest_centroids("soc")
    checkpoints = adapter.get_centroid_checkpoints("soc", limit=5)
    adapter.save_evolution_event("soc", "variant_generated", "threshold_rule", "variant-1", metadata={"seed": 42})
    events = adapter.get_evolution_events("soc", event_type="variant_generated")
    archived = adapter.archive_old_decisions("soc", keep_recent=800)
    archive_count = adapter.count_archived("soc")

    assert latest == [[0.1]]
    assert checkpoints == [{"decision_id": "DEC-1", "category": "price_variance"}]
    assert events == [{"event_type": "variant_generated"}]
    assert archived == 0
    assert archive_count == 0
    assert ("save_centroids", "soc", "price_variance", [[0.1]], {"iks": 0.5}, {"decision_id": "DEC-1"}) in store.calls
    assert ("load_latest_centroids", "soc") in store.calls
    assert ("get_centroid_checkpoints", "soc", {"limit": 5}) in store.calls
    assert (
        "save_evolution_event",
        "soc",
        "variant_generated",
        "threshold_rule",
        "variant-1",
        {"seed": 42},
    ) in store.calls
    assert ("get_evolution_events", "soc", {"event_type": "variant_generated"}) in store.calls
    assert ("archive_old_decisions", "soc", 800) in store.calls
    assert ("count_archived", "soc") in store.calls


def test_adapter_delegates_decision_entity_links():
    from ci_platform.graph.age_sdk_adapter import AGEGraphStoreAdapter

    store = FakeGraphStore()
    adapter = AGEGraphStoreAdapter(store=store)

    adapter.link_decision_to_entity("DEC-1", "ENT-1", edge_type="REVIEWS")
    links = adapter.get_decision_links("DEC-1")

    assert ("link_decision_to_entity", "DEC-1", "ENT-1", "REVIEWS") in store.calls
    assert ("get_decision_links", "DEC-1") in store.calls
    assert links == [
        {
            "decision_id": "DEC-1",
            "entity_id": "ENT-1",
            "edge_type": "DECIDED_ON",
        }
    ]


def test_adapter_close_delegates_to_store():
    from ci_platform.graph.age_sdk_adapter import AGEGraphStoreAdapter

    store = FakeGraphStore()
    adapter = AGEGraphStoreAdapter(store=store)

    adapter.close()

    assert store.closed is True


def test_adapter_source_has_no_forbidden_imports_or_vocab():
    source = Path("ci_platform/graph/age_sdk_adapter.py").read_text(encoding="utf-8")

    forbidden = (
        "from apps.",
        "from copilot_sdk.backend",
        "from copilot_sdk.scoring",
        "from copilot_sdk.evolution",
        "from app.domains.soc",
        "credential_access",
        "lateral_movement",
        "threat_intel",
    )
    for token in forbidden:
        assert token not in source


GRAPH_DSN = os.getenv("GRAPH_DSN")


@pytest.mark.skipif(not GRAPH_DSN, reason="GRAPH_DSN missing; skipping live AGE tests")
class TestAGEGraphStoreAdapterLive:
    def test_live_write_read_decision_and_outcome(self):
        from ci_platform.graph.age_sdk_adapter import AGEGraphStoreAdapter

        adapter = AGEGraphStoreAdapter(dsn=GRAPH_DSN, graph_name="test_graph")
        decision_id = adapter.write_decision(
            "soc",
            "price_variance",
            "hold_for_review",
            0.74,
            {"amount_variance_ratio": 0.2},
            metadata={"entity_id": "LIVE-SDK-ENT-1"},
        )
        decision = adapter.get_decision(decision_id)
        adapter.write_outcome(decision_id, "hold_for_review", True)
        verified = adapter.get_verified_decisions("soc")

        assert decision_id.startswith("DEC-")
        assert decision is None or decision.get("decision_id") == decision_id
        assert any(row.get("decision_id") == decision_id for row in verified)
        assert adapter.count_verified("soc") >= 1
        assert adapter.count_correct("soc") >= 1
        adapter.close()

    def test_live_evolution_and_centroids_no_crash(self):
        from ci_platform.graph.age_sdk_adapter import AGEGraphStoreAdapter

        adapter = AGEGraphStoreAdapter(dsn=GRAPH_DSN, graph_name="test_graph")
        adapter.save_evolution_event("soc", "variant_generated", "threshold_rule", "variant-live")
        adapter.save_centroids("soc", "price_variance", [[0.1, 0.2]], decision_id="DEC-live")
        adapter.close()
