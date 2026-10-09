"""Real AGE regression tests for atomic control-plane state replacement."""
from __future__ import annotations

import psycopg
import pytest
from psycopg import sql

from ci_platform.graph.age_graph_store import AGEGraphStore


def test_platform_state_replacement_publishes_one_complete_value(
    age_store: AGEGraphStore,
) -> None:
    age_store.save_evolution("trading", "learning_state", {"revision": 1, "weights": [0.1]})
    age_store.save_evolution("purchasing", "learning_state", {"revision": 7})
    replacement = {"revision": 2, "weights": [0.2, 0.3]}
    age_store.save_evolution("trading", "learning_state", replacement)
    reader = AGEGraphStore(dsn=age_store._client._dsn, graph_name=age_store._client._graph)
    try:
        assert reader.get_evolution("trading", "learning_state") == replacement
        assert reader.get_evolution("purchasing", "learning_state") == {"revision": 7}
        rows = reader._run_query(
            "MATCH (n:EvolutionState {domain: 'trading', state_key: 'learning_state'}) "
            "RETURN count(n) AS cnt"
        )
        assert int(rows[0]["cnt"]) == 1
    finally:
        reader.close()


def test_failed_platform_state_replacement_preserves_old_value(
    age_store: AGEGraphStore,
) -> None:
    previous = {"revision": 1, "weights": [0.75]}
    age_store.save_evolution("trading", "learning_state", previous)
    # Fail the actual INSERT after DELETE, without replacing any store/client method.
    graph_name = age_store._client._graph
    assert graph_name.startswith("ci_auto_test_")
    with psycopg.connect(age_store._client._dsn, autocommit=True) as connection:
        connection.execute(sql.SQL(
            "ALTER TABLE {}.{} ADD CONSTRAINT step9_reject_replacement "
            "CHECK (((properties::text)::jsonb ->> 'payload') NOT LIKE '%reject-step9%')"
        ).format(sql.Identifier(graph_name), sql.Identifier("EvolutionState")))
    # AGE versions differ in how they surface PostgreSQL constraint failures.
    with pytest.raises(psycopg.Error):
        age_store.save_evolution("trading", "learning_state", {"marker": "reject-step9"})
    assert age_store.get_evolution("trading", "learning_state") == previous


def test_domain_reset_removes_platform_authorities_only_in_requested_domain(
    age_dsn: str,
) -> None:
    import asyncio
    import uuid
    from ci_platform.graph.age_client import AGEClient

    graph_name = f"protocol_v2_test_step9_{uuid.uuid4().hex[:12]}"
    client = AGEClient(dsn=age_dsn, graph_name=graph_name)
    asyncio.run(client.ensure_graph())
    asyncio.run(client.close())
    store = AGEGraphStore(dsn=age_dsn, graph_name=graph_name)
    reset_domain = "pytest_protocol_v2_step9_reset"
    preserved_domain = "pytest_protocol_v2_step9_preserved"
    try:
        for domain in (reset_domain, preserved_domain):
            for save in (
                store.save_evolution, store.save_posterior, store.save_promotion,
                store.save_ledger, store.save_governance,
            ):
                save(domain, "state", {"owner": domain})
        store.domain_scoped_reset(reset_domain)
        for read in (
            store.get_evolution, store.get_posterior, store.get_promotion,
            store.get_ledger, store.get_governance,
        ):
            assert read(reset_domain, "state") is None
            assert read(preserved_domain, "state") == {"owner": preserved_domain}
    finally:
        store.close()
        with psycopg.connect(age_dsn, autocommit=True) as connection:
            connection.execute("LOAD 'age'")
            connection.execute("SET search_path = ag_catalog, '$user', public")
            connection.execute("SELECT drop_graph(%s, true)", (graph_name,))
