"""
ci-platform Block 8.5 AGE client tests.

Unit tests run without a live DB (import + interface only).
Integration tests skip unless AGE_INTEGRATION=1 is set.
"""
import asyncio
import inspect
import json
import os
import re

import pytest

AGE_INTEGRATION = os.getenv("AGE_INTEGRATION", "0") == "1"
INTEGRATION_SKIP = pytest.mark.skipif(
    not AGE_INTEGRATION,
    reason="AGE_INTEGRATION != 1 — skipping live DB tests",
)


# ── Unit tests (no DB required) ───────────────────────────────────────────────

def test_age_client_imports_cleanly():
    """AGEClient importable without psycopg installed."""
    from ci_platform.graph.age_client import AGEClient
    assert AGEClient is not None


def test_get_graph_client_returns_singleton():
    """get_graph_client() returns same instance on repeated calls."""
    import ci_platform.graph.age_client as mod
    mod._client = None  # Reset singleton for test isolation
    c1 = mod.get_graph_client()
    c2 = mod.get_graph_client()
    assert c1 is c2
    mod._client = None  # Cleanup


def test_extract_columns_simple():
    """Column extraction handles simple RETURN n."""
    from ci_platform.graph.age_client import AGEClient
    client = AGEClient.__new__(AGEClient)
    cols = client._extract_columns("MATCH (n:Alert) RETURN n")
    assert cols == ["n"]


def test_extract_columns_alias():
    """Column extraction handles RETURN count(n) AS cnt."""
    from ci_platform.graph.age_client import AGEClient
    client = AGEClient.__new__(AGEClient)
    cols = client._extract_columns("MATCH (n) RETURN count(n) AS cnt")
    assert "cnt" in cols


def test_parse_agtype_node():
    """_parse_agtype unwraps AGE node envelope to properties dict."""
    from ci_platform.graph.age_client import AGEClient
    client = AGEClient.__new__(AGEClient)

    node_json = json.dumps({
        "id": 12345,
        "label": "Alert",
        "properties": {
            "alert_id": "ALT-001",
            "category": "lateral_movement",
        },
    })
    result = client._parse_agtype(node_json)
    assert result["alert_id"] == "ALT-001"
    assert result["category"] == "lateral_movement"


def test_sequence_count_uses_python_timedelta_not_duration():
    """
    get_sequence_count must compute the cutoff in Python (timedelta),
    not via the AGE-unsupported duration() Cypher function.
    This is the fix for the 9 duration() FAIL queries.
    """
    from ci_platform.graph.age_client import AGEClient
    src = inspect.getsource(AGEClient.get_sequence_count)
    assert "duration(" not in src, (
        "get_sequence_count must NOT use duration() Cypher function"
    )
    assert "timedelta" in src, (
        "get_sequence_count must use Python timedelta"
    )


def test_run_query_no_datetime_in_cypher():
    """
    Cypher datetime() must not appear anywhere in age_client source.
    This is the fix for the 28 datetime() FAIL queries.
    Python's datetime class is fine; the Cypher datetime() function is not.
    """
    from ci_platform.graph import age_client as mod
    source = inspect.getsource(mod)
    # Cypher datetime() appears as datetime() — zero args, standalone call
    cypher_datetime_calls = re.findall(r'\bdatetime\(\)', source)
    assert len(cypher_datetime_calls) == 0, (
        f"Found {len(cypher_datetime_calls)} Cypher datetime() call(s) — must be 0"
    )
