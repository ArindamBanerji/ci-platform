from __future__ import annotations

import os
import uuid
from collections.abc import Iterator

import pytest

from ci_platform.graph.age_graph_store import AGEGraphStore


GRAPH_DSN = os.getenv("GRAPH_DSN")


@pytest.fixture
def age_graph() -> Iterator[str]:
    if not GRAPH_DSN:
        pytest.skip("GRAPH_DSN is not configured")
    import psycopg

    graph_name = f"protocol_v2_test_evolution_{uuid.uuid4().hex[:12]}"
    try:
        with psycopg.connect(GRAPH_DSN, autocommit=True) as conn:
            conn.execute("LOAD 'age'")
            conn.execute("SET search_path = ag_catalog, '$user', public")
            conn.execute("SELECT create_graph(%s)", (graph_name,))
    except Exception as exc:
        pytest.skip(f"AGE disposable graph unavailable: {exc}")
    try:
        yield graph_name
    finally:
        with psycopg.connect(GRAPH_DSN, autocommit=True) as conn:
            conn.execute("LOAD 'age'")
            conn.execute("SET search_path = ag_catalog, '$user', public")
            conn.execute("SELECT drop_graph(%s, true)", (graph_name,))


@pytest.mark.skipif(not GRAPH_DSN, reason="GRAPH_DSN is not configured")
def test_age_evolution_event_links_to_triggering_decision(age_graph: str) -> None:
    assert GRAPH_DSN is not None
    domain = f"pytest_protocol_v2_evolution_{uuid.uuid4().hex[:12]}"
    decision_id: str | None = None
    event_id = f"event-{uuid.uuid4().hex[:12]}"
    store = AGEGraphStore(dsn=GRAPH_DSN, graph_name=age_graph)
    try:
        decision_id = store.write_decision(
            domain,
            category="quality",
            action="approve",
            confidence=0.9,
            factors={"risk": 0.1},
        )
        store.write_evolution_event(
            event_id=event_id,
            domain=domain,
            event_type="variant_created",
            rule_name="quality-rule",
            variant_id="variant-1",
            decision_id=decision_id,
        )

        rows = store._run_query(
            f"""
            MATCH (d:Decision {{decision_id: {store._S(decision_id)}}})
            WHERE d.domain = {store._S(domain)}
            MATCH (d)-[:TRIGGERED_EVOLUTION]->(e:EvolutionEvent {{event_id: {store._S(event_id)}}})
            WHERE e.domain = {store._S(domain)}
            RETURN count(e) AS cnt
            """
        )
        assert rows
        assert int(rows[0]["cnt"]) == 1
    finally:
        store.close()
