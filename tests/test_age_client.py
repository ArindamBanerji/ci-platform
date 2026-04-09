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


# ── Integration tests (require AGE_INTEGRATION=1 + live DB) ──────────────────

INTEGRATION_SKIP = pytest.mark.skipif(
    os.getenv("AGE_INTEGRATION", "0") != "1",
    reason="AGE_INTEGRATION != 1 — skipping live DB tests"
)


def run_async(coro):
    import asyncio
    if hasattr(asyncio, 'WindowsSelectorEventLoopPolicy'):
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    return asyncio.get_event_loop().run_until_complete(coro)


@INTEGRATION_SKIP
def test_age_graph_queryable():
    from ci_platform.graph.age_client import AGEClient
    client = AGEClient()
    run_async(client.ensure_graph())
    results = run_async(client.run_query(
        "MATCH (n) RETURN count(n) AS cnt"
    ))
    assert results is not None
    assert isinstance(results[0].get("cnt", 0), int)


@INTEGRATION_SKIP
def test_age_entity_node_merge_idempotent():
    from ci_platform.graph.age_client import AGEClient
    client = AGEClient()
    for _ in range(3):
        run_async(client.run_query(
            "MERGE (e:Entity {entity_id: $eid}) RETURN e",
            parameters={"eid": "TEST-AGE-ENT-001"}
        ))
    results = run_async(client.run_query(
        "MATCH (e:Entity {entity_id: $eid}) RETURN count(e) AS cnt",
        parameters={"eid": "TEST-AGE-ENT-001"}
    ))
    assert int(results[0]["cnt"]) == 1


@INTEGRATION_SKIP
def test_age_triggered_evolution_traversal():
    from ci_platform.graph.age_client import AGEClient
    client = AGEClient()
    run_async(client.run_query(
        "MERGE (a:Alert {alert_id: $aid}) RETURN a",
        parameters={"aid": "TEST-AGE-ALT-001"}
    ))
    run_async(client.run_query(
        "MERGE (e:Entity {entity_id: $eid}) RETURN e",
        parameters={"eid": "TEST-AGE-ENT-TEV"}
    ))
    run_async(client.create_evolution_event(
        "TEST-AGE-ALT-001", "TEST-AGE-ENT-TEV", "escalate", True
    ))
    results = run_async(client.run_query(
        """MATCH (a:Alert {alert_id: $aid})-[r:TRIGGERED_EVOLUTION]->(e:Entity)
           RETURN count(r) AS cnt""",
        parameters={"aid": "TEST-AGE-ALT-001"}
    ))
    assert int(results[0]["cnt"]) >= 1


@INTEGRATION_SKIP
def test_age_campaign_entity():
    from ci_platform.graph.age_client import AGEClient
    client = AGEClient()
    run_async(client.run_query(
        "MERGE (c:Campaign {campaign_id: $cid}) RETURN c",
        parameters={"cid": "TEST-CAMP-001"}
    ))
    run_async(client.run_query(
        "MERGE (a:Alert {alert_id: $aid}) RETURN a",
        parameters={"aid": "TEST-ALT-CAMP-001"}
    ))
    run_async(client.create_evolution_event(
        "TEST-ALT-CAMP-001", "TEST-CAMP-001", "investigate", True
    ))
    results = run_async(client.run_query(
        "MATCH (c:Campaign {campaign_id: $cid}) RETURN c",
        parameters={"cid": "TEST-CAMP-001"}
    ))
    assert len(results) >= 1


@INTEGRATION_SKIP
def test_backlog015_decision_distance_log():
    import json
    from ci_platform.graph.age_client import AGEClient
    client = AGEClient()
    run_async(client.log_decision_distance(
        decision_id="TEST-B015-001",
        centroid_distance_to_canonical=2.847,
        pattern_history_value=0.423,
        alert_category_distribution={"credential_access": 0.35, "lateral_movement": 0.25},
    ))
    results = run_async(client.run_query(
        "MATCH (d:DecisionDistanceLog {decision_id: $did}) RETURN d",
        parameters={"did": "TEST-B015-001"}
    ))
    assert len(results) == 1
    assert float(results[0]["d"]["centroid_distance_to_canonical"]) == pytest.approx(2.847)


@INTEGRATION_SKIP
def test_age_merge_idempotent():
    from ci_platform.graph.age_client import AGEClient
    client = AGEClient()
    for _ in range(3):
        run_async(client.run_query(
            "MERGE (t:ThreatIndicator {value: $val}) RETURN t",
            parameters={"val": "192.168.1.1"}
        ))
    results = run_async(client.run_query(
        "MATCH (t:ThreatIndicator {value: $val}) RETURN count(t) AS cnt",
        parameters={"val": "192.168.1.1"}
    ))
    assert int(results[0]["cnt"]) == 1
