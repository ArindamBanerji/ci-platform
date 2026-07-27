"""Shared live AGE test availability and disposable graph fixtures."""

from __future__ import annotations

import os
import uuid

import pytest


def age_available() -> bool:
    try:
        import psycopg

        dsn = os.getenv(
            "AGE_TEST_DSN",
            "host=localhost port=5433 dbname=soc_copilot user=postgres password=postgres",
        )
        with psycopg.connect(dsn, connect_timeout=3, autocommit=True) as conn:
            conn.execute("LOAD 'age'")
            conn.execute('SET search_path = ag_catalog, "$user", public')
            conn.execute("SELECT 1")
        return True
    except Exception:
        return False


@pytest.fixture(scope="session")
def age_test_graph():
    if not age_available():
        pytest.skip("AGE not reachable")
    import psycopg

    dsn = os.getenv(
        "AGE_TEST_DSN",
        "host=localhost port=5433 dbname=soc_copilot user=postgres password=postgres",
    )
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
