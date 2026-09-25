"""Shared live AGE test availability and disposable graph fixtures."""

from __future__ import annotations

import asyncio
import os
import uuid

import pytest


def _configured_age_dsn() -> str:
    return os.getenv(
        "GRAPH_DSN",
        os.getenv(
            "AGE_TEST_DSN",
            "host=localhost port=5433 dbname=soc_copilot user=postgres password=postgres",
        ),
    )


def age_available() -> bool:
    try:
        import psycopg

        dsn = _configured_age_dsn()
        with psycopg.connect(dsn, connect_timeout=3, autocommit=True) as conn:
            conn.execute("LOAD 'age'")
            conn.execute('SET search_path = ag_catalog, "$user", public')
            conn.execute("SELECT 1")
        return True
    except Exception:
        return False


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line("markers", "age: requires a live Apache AGE connection")


@pytest.fixture
def memory_store():
    from copilot_sdk.graph.memory_store import InMemoryGraphStore

    return InMemoryGraphStore(domain="test")


@pytest.fixture
def age_dsn() -> str:
    dsn = os.environ.get("GRAPH_DSN")
    if not dsn:
        pytest.skip("GRAPH_DSN not set")
    return dsn


@pytest.fixture(scope="session")
def age_test_graph():
    if not age_available():
        pytest.skip("AGE not reachable")
    import psycopg

    dsn = _configured_age_dsn()
    graph = f"ci_auto_test_{uuid.uuid4().hex[:8]}"
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute("LOAD 'age'")
        conn.execute('SET search_path = ag_catalog, "$user", public')
        conn.execute("SELECT create_graph(%s)", (graph,))
    try:
        yield dsn, graph
    finally:
        with psycopg.connect(dsn, autocommit=True) as conn:
            conn.execute("LOAD 'age'")
            conn.execute('SET search_path = ag_catalog, "$user", public')
            conn.execute("SELECT drop_graph(%s, true)", (graph,))


@pytest.fixture
def age_store(age_dsn: str):
    from ci_platform.graph.age_client import AGEClient
    from ci_platform.graph.age_graph_store import AGEGraphStore

    graph_name = f"ci_auto_test_{uuid.uuid4().hex[:8]}"
    client = AGEClient(dsn=age_dsn, graph_name=graph_name)
    asyncio.run(client.ensure_graph())
    asyncio.run(client.close())
    store = AGEGraphStore(dsn=age_dsn, graph_name=graph_name)
    try:
        yield store
    finally:
        store.close()
        import psycopg

        with psycopg.connect(age_dsn, autocommit=True) as conn:
            conn.execute("LOAD 'age'")
            conn.execute('SET search_path = ag_catalog, "$user", public')
            conn.execute("SELECT drop_graph(%s, true)", (graph_name,))
