"""Conformance tests for canonical JM topology edges."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest
from copilot_sdk.testing import age_available


pytestmark = pytest.mark.skipif(not age_available(), reason="AGE not reachable")


def _store(age_test_graph):
    from ci_platform.graph.age_graph_store import AGEGraphStore

    dsn, graph_name = age_test_graph
    return AGEGraphStore(dsn=dsn, graph_name=graph_name)


def test_write_decision_creates_in_domain_edge(age_test_graph):
    store = _store(age_test_graph)
    try:
        decision_id = store.write_decision(
            "test",
            category="topology",
            action="inspect",
            confidence=0.9,
            factors={"risk": 0.4},
        )
        rows = store._run_query(
            f"""
            MATCH (d:Decision {{decision_id: {store._S(decision_id)}}})
                  -[:IN_DOMAIN]->(domain:Domain)
            RETURN d.domain AS decision_domain, domain.domain_id AS domain_id
            """
        )
        assert rows
        assert rows[0]["decision_domain"] == "test"
        assert rows[0]["domain_id"] == "test"
    finally:
        store.close()


def test_write_decision_creates_factor_vector_node(age_test_graph):
    store = _store(age_test_graph)
    try:
        decision_id = store.write_decision(
            "test",
            category="topology",
            action="inspect",
            confidence=0.9,
            factors={"risk": 0.4, "impact": 0.8},
        )
        rows = store._run_query(
            f"""
            MATCH (d:Decision {{decision_id: {store._S(decision_id)}}})
                  -[:HAS_FACTOR_VECTOR]->(vector:FactorVector)
            RETURN vector.vector_id AS vector_id,
                   vector.decision_id AS decision_id,
                   vector.domain AS domain,
                   vector.dimension AS dimension,
                   vector.factor_names AS factor_names,
                   vector.factor_values AS factor_values,
                   vector.factor_names_hash AS factor_names_hash,
                   vector.shape AS shape,
                   vector.created_at AS created_at
            """
        )
        assert rows
        row = rows[0]
        assert row["vector_id"] == f"{decision_id}:fv"
        assert row["decision_id"] == decision_id
        assert row["domain"] == "test"
        assert int(row["dimension"]) == 2
        assert "impact" in str(row["factor_names"])
        assert "risk" in str(row["factor_names"])
        assert '0.4' in str(row["factor_values"])
        assert '0.8' in str(row["factor_values"])
        assert row["factor_names_hash"]
        assert row["shape"]
        assert row["created_at"]
    finally:
        store.close()


def test_factor_vector_failure_does_not_block_decision(age_test_graph, caplog):
    from ci_platform.graph.age_graph_store import AGEGraphStore

    class FailingFactorVectorStore(AGEGraphStore):
        def _create_factor_vector_node(self, **kwargs):
            raise RuntimeError("injected FactorVector failure")

    dsn, graph_name = age_test_graph
    store = FailingFactorVectorStore(dsn=dsn, graph_name=graph_name)
    try:
        decision_id = store.write_decision(
            "test",
            category="topology",
            action="inspect",
            confidence=0.9,
            factors={"risk": 0.4},
        )
        rows = store._run_query(
            f"MATCH (d:Decision {{decision_id: {store._S(decision_id)}}}) RETURN d"
        )
        assert rows
        assert "injected FactorVector failure" in caplog.text
    finally:
        store.close()


def test_backfill_script_dry_run():
    script_path = Path(__file__).parents[2] / "copilot-sdk" / "scripts" / "backfill_jm_edges.py"
    spec = importlib.util.spec_from_file_location("backfill_jm_edges", script_path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    calls: list[str] = []

    def fake_query(connection, graph_name, body, columns):
        calls.append(body)
        if "RETURN count(d) AS missing" in body:
            return [(3,)]
        raise AssertionError("dry-run must not request mutation candidates")

    report = module.run_backfill(
        object(),
        "test_graph",
        apply=False,
        query=fake_query,
    )
    assert report["in_domain_missing"] == 3
    assert report["has_factor_vector_missing"] == 3
    assert report["in_domain_created"] == 0
    assert report["has_factor_vector_created"] == 0
    assert calls
    assert all("CREATE" not in body for body in calls)
