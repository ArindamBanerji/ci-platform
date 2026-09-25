"""G040 negative authorization checks and actual AGE collision witnesses."""
from __future__ import annotations

import json
from typing import Any
from unittest.mock import Mock

import pytest

from ci_platform.graph.age_graph_store import AGEGraphStore, CrossDomainQueryRequest


@pytest.mark.parametrize("domain", [None, "", " ", 42, "soc' OR true"])
def test_g040_missing_or_invalid_write_domain_fails_before_io(domain: Any) -> None:
    store = AGEGraphStore("postgresql://unused/test")
    query = Mock()
    setattr(store, "_run_query", query)
    with pytest.raises(ValueError, match="domain"):
        store.write_decision(domain, "risk", "review", 0.8, {})
    query.assert_not_called()


def test_g040_conflicting_metadata_domain_rejected() -> None:
    store = AGEGraphStore("postgresql://unused/test")
    query = Mock()
    setattr(store, "_run_query", query)
    with pytest.raises(ValueError, match="domain"):
        store.write_decision("soc", "risk", "review", 0.8, {}, {"domain": "trading"})
    query.assert_not_called()


@pytest.mark.parametrize("domain", [None, "", " "])
def test_g040_governed_write_also_requires_domain(domain: Any) -> None:
    store = AGEGraphStore("postgresql://unused/test")
    query = Mock()
    setattr(store, "_run_query", query)
    with pytest.raises(ValueError, match="domain"):
        store.write_governed_decision(
            decision_id="same", domain=domain, category="risk", category_index=0,
            recommended_action="review", recommended_index=0, confidence=0.8,
            probabilities=[1.0], factor_vector=[0.5], factor_names=["risk"],
        )
    query.assert_not_called()


@pytest.mark.parametrize("domain", [None, "", " "])
def test_g040_missing_read_domain_rejected(domain: Any) -> None:
    store = AGEGraphStore("postgresql://unused/test")
    query = Mock()
    setattr(store, "_run_query", query)
    with pytest.raises(ValueError, match="domain"):
        store.query_context("same", domain=domain)
    query.assert_not_called()


def test_g040_cross_domain_default_denial_and_review_required() -> None:
    store = AGEGraphStore("postgresql://unused/test")
    query = Mock()
    setattr(store, "_run_query", query)
    with pytest.raises(PermissionError):
        store.query_cross_domain_context("same", source_domain="soc", target_domain="trading", principal="reviewer")
    with pytest.raises(ValueError, match="catalogue"):
        store.query_cross_domain_context("same", source_domain="soc", target_domain="trading", principal="reviewer", query_id="MATCH (n) RETURN n")
    with pytest.raises(ValueError, match="domain"):
        store.query_cross_domain_context("same", source_domain="soc", target_domain="", principal="reviewer")
    query.assert_not_called()


def test_g040_write_and_read_same_bare_identifiers(age_test_graph: Any) -> None:
    dsn, graph = age_test_graph
    store = AGEGraphStore(dsn, graph)
    try:
        store._run_query("CREATE (:Entity {entity_id: 'collision', domain: 'trading'}), (:Entity {entity_id: 'collision', domain: 'soc'})")
        for domain in ("soc", "trading"):
            store.write_decision(domain, domain + "_risk", "review", 0.8, {}, {"decision_id": "same_decision", "entity_id": "collision"})
            decision = store.get_decision("same_decision", domain)
            assert decision is not None and decision["category"] == domain + "_risk"
        rows = store._run_query("MATCH (d:Decision)-[:DECIDED_ON]->(e) WHERE d.decision_id = 'same_decision' RETURN d.domain AS d, e.domain AS e")
        assert sorted((r["d"], r["e"]) for r in rows) == [("soc", "soc"), ("trading", "trading")]
    finally:
        store.close()


def test_g040_normal_context_excludes_foreign_roots_and_intermediates(age_test_graph: Any) -> None:
    dsn, graph = age_test_graph
    store = AGEGraphStore(dsn, graph)
    try:
        store._run_query("""
        CREATE (s:Entity {entity_id: 'context_collision', domain: 'soc'}),
               (t:Entity {entity_id: 'context_collision', domain: 'trading'}),
               (ok:Decision {decision_id: 'own_visible', domain: 'soc'}),
               (wrong_root:Decision {decision_id: 'foreign_root_leak', domain: 'soc'}),
               (foreign:Entity {entity_id: 'foreign_bridge', domain: 'trading'}),
               (legacy:Entity {entity_id: 'unscoped_bridge'}),
               (hidden:Decision {decision_id: 'foreign_intermediate_leak', domain: 'soc'}),
               (s)-[:RELATED]->(ok), (t)-[:RELATED]->(wrong_root),
               (s)-[:RELATED]->(foreign), (foreign)-[:RELATED]->(hidden),
               (s)-[:RELATED]->(legacy), (legacy)-[:RELATED]->(hidden)
        """)
        rows = store.query_context("context_collision", hops=2, domain="soc")
        assert len(rows) == 1
        witness = json.dumps(rows)
        assert "own_visible" in witness
        assert "leak" not in witness and "trading" not in witness and "unscoped_bridge" not in witness
    finally:
        store.close()


def test_g040_reviewed_cross_domain_returns_exact_authorized_pair(age_test_graph: Any) -> None:
    dsn, graph = age_test_graph
    grant = CrossDomainQueryRequest("reviewer", "entity_context_v1", "soc", "trading")
    store = AGEGraphStore(dsn, graph, cross_domain_authorizer=lambda request: request == grant)
    try:
        store._run_query("""
        CREATE (s:Entity {entity_id: 'authorized_root', domain: 'soc'}),
               (t:Decision {decision_id: 'authorized_target', domain: 'trading'}),
               (x:Entity {entity_id: 'third_domain', domain: 'dataops'}),
               (leak:Decision {decision_id: 'third_domain_bridge_leak', domain: 'trading'}),
               (wrong:Entity {entity_id: 'authorized_root', domain: 'dataops'}),
               (s)-[:RELATED]->(t), (s)-[:RELATED]->(x),
               (x)-[:RELATED]->(leak), (wrong)-[:RELATED]->(t)
        """)
        rows = store.query_cross_domain_context("authorized_root", source_domain="soc", target_domain="trading", principal="reviewer")
        assert len(rows) == 1
        witness = json.dumps(rows)
        assert "authorized_target" in witness and "dataops" not in witness and "leak" not in witness
        for source, target, principal in (("soc", "dataops", "reviewer"), ("trading", "soc", "reviewer"), ("soc", "trading", "outsider"), ("soc", "trading", "")):
            with pytest.raises(PermissionError):
                store.query_cross_domain_context("authorized_root", source_domain=source, target_domain=target, principal=principal)
    finally:
        store.close()
