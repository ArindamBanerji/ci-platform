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


def test_age_client_default_connection_mode_is_fresh(monkeypatch):
    """Fresh per-query connections remain the default behavior."""
    monkeypatch.delenv("AGE_USE_POOL", raising=False)
    from ci_platform.graph.age_client import AGEClient

    client = AGEClient(dsn="postgresql://localhost:5432/test", graph_name="g")

    assert client.connection_mode == "fresh"


def test_age_client_pool_flag_falls_back_to_warm_connection(monkeypatch):
    """Opt-in pool mode uses warm fallback when psycopg_pool is unavailable."""
    import ci_platform.graph.age_client as mod

    monkeypatch.setattr(mod, "_PSYCOPG_POOL_AVAILABLE", False)

    client = mod.AGEClient(
        dsn="postgresql://localhost:5432/test",
        graph_name="g",
        use_pool=True,
    )

    assert client.connection_mode == "warm_fallback"
    assert client.pool_available is False


def test_age_client_pooled_mode_uses_psycopg_pool_when_available(monkeypatch):
    """When psycopg_pool is installed, pooled mode uses ConnectionPool."""
    import sys
    import types
    import ci_platform.graph.age_client as mod

    class FakePool:
        instances = []

        def __init__(self, **kwargs):
            self.kwargs = kwargs
            self.conn = _mock_conn()
            self.closed = False
            configure = kwargs.get("configure")
            if configure:
                configure(self.conn)
            FakePool.instances.append(self)

        def connection(self):
            return self.conn

        def close(self):
            self.closed = True

    fake_module = types.ModuleType("psycopg_pool")
    fake_module.ConnectionPool = FakePool
    monkeypatch.setitem(sys.modules, "psycopg_pool", fake_module)
    monkeypatch.setattr(mod, "_PSYCOPG_POOL_AVAILABLE", True)

    client = mod.AGEClient(
        dsn="postgresql://localhost:5432/test",
        graph_name="g",
        use_pool=True,
        pool_min_size=1,
        pool_max_size=2,
    )

    asyncio.run(client.run_query("MATCH (n) RETURN n"))
    asyncio.run(client.close())

    assert client.connection_mode == "pooled"
    assert len(FakePool.instances) == 1
    pool = FakePool.instances[0]
    assert pool.kwargs["min_size"] == 1
    assert pool.kwargs["max_size"] == 2
    assert pool.kwargs["kwargs"]["autocommit"] is True
    calls = [call[0][0] for call in pool.conn.execute.call_args_list]
    assert calls[0] == "LOAD 'age'"
    assert calls[1].startswith("SET search_path")
    assert any(str(sql).startswith("SELECT * FROM cypher") for sql in calls)
    assert pool.closed is True


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


def test_rejects_destructive_set():
    """SET n = {} is forbidden — it wipes all properties."""
    from ci_platform.graph.age_client import AGEClient
    client = AGEClient()
    with pytest.raises(ValueError, match="replaces ALL properties"):
        asyncio.run(client.run_query("MATCH (t:Test) SET t = {a: 1}"))


def test_allows_safe_set_patterns():
    """SET n.prop = val and SET n += {} are allowed by the guard."""
    from ci_platform.graph.age_client import _check_safe_cypher
    _check_safe_cypher("MATCH (t:Test) SET t.category = 'x'")   # no raise
    _check_safe_cypher("MATCH (t:Test) SET t += {a: 1, b: 2}")  # no raise


def test_rejects_merge_node_label():
    """MERGE (n:Label {prop: val}) is rejected — AGE does not support MERGE."""
    from ci_platform.graph.age_client import AGEClient
    client = AGEClient()
    with pytest.raises(ValueError, match="MERGE is not supported"):
        asyncio.run(client.run_query("MERGE (n:Decision {decision_id: 'x'}) RETURN n"))


def test_rejects_merge_relationship():
    """MERGE (a)-[:REL]->(b) is rejected — AGE does not support MERGE."""
    from ci_platform.graph.age_client import _check_safe_cypher
    with pytest.raises(ValueError, match="MERGE is not supported"):
        _check_safe_cypher("MATCH (a) MERGE (a)-[:REL]->(b:Node) RETURN b")


def test_merge_in_property_name_does_not_raise():
    """'merge' as part of a property name or string value does not trigger MERGE guard."""
    from ci_platform.graph.age_client import _check_safe_cypher
    _check_safe_cypher("MATCH (n) WHERE n.merge_count > 0 RETURN n")          # no raise
    _check_safe_cypher("MATCH (n) WHERE n.action = 'merge results' RETURN n") # no raise


def _mock_conn():
    """Return (mock_ctx, mock_conn) for patching psycopg.connect."""
    from unittest.mock import MagicMock
    cur = MagicMock()
    cur.fetchall.return_value = []
    conn = MagicMock()
    conn.closed = False
    conn.__enter__ = MagicMock(return_value=conn)
    conn.__exit__ = MagicMock(return_value=False)
    conn.execute.return_value = cur
    return conn


def test_run_query_fresh_mode_configures_age_each_query():
    """Fresh mode preserves one connection/session setup per run_query call."""
    from ci_platform.graph.age_client import AGEClient
    from unittest.mock import patch

    client = AGEClient(dsn="postgresql://localhost:5432/test", graph_name="test_graph")
    conn1 = _mock_conn()
    conn2 = _mock_conn()

    with patch(
        "ci_platform.graph.age_client.psycopg.connect",
        side_effect=[conn1, conn2],
    ) as connect:
        asyncio.run(client.run_query("MATCH (n) RETURN n"))
        asyncio.run(client.run_query("MATCH (n) RETURN n"))

    assert connect.call_count == 2
    assert conn1.execute.call_args_list[0][0][0] == "LOAD 'age'"
    assert conn1.execute.call_args_list[1][0][0].startswith("SET search_path")
    assert conn2.execute.call_args_list[0][0][0] == "LOAD 'age'"
    assert conn2.execute.call_args_list[1][0][0].startswith("SET search_path")


def test_run_query_warm_fallback_reuses_configured_connection(monkeypatch):
    """Warm fallback configures AGE once and reuses the connection for queries."""
    import ci_platform.graph.age_client as mod
    from unittest.mock import patch

    monkeypatch.setattr(mod, "_PSYCOPG_POOL_AVAILABLE", False)
    client = mod.AGEClient(
        dsn="postgresql://localhost:5432/test",
        graph_name="test_graph",
        use_pool=True,
    )
    conn = _mock_conn()

    with patch("ci_platform.graph.age_client.psycopg.connect", return_value=conn) as connect:
        asyncio.run(client.run_query("MATCH (n) RETURN n"))
        asyncio.run(client.run_query("MATCH (n) RETURN n"))
        asyncio.run(client.close())

    assert connect.call_count == 1
    calls = [call[0][0] for call in conn.execute.call_args_list]
    assert calls[0] == "LOAD 'age'"
    assert calls[1].startswith("SET search_path")
    assert len([sql for sql in calls if sql == "LOAD 'age'"]) == 1
    assert len([sql for sql in calls if str(sql).startswith("SELECT * FROM cypher")]) == 2
    conn.close.assert_called_once()


def test_run_query_same_result_shape_in_fresh_and_warm_fallback(monkeypatch):
    """Connection mode does not change run_query's list-of-dicts result shape."""
    import ci_platform.graph.age_client as mod
    from unittest.mock import MagicMock, patch

    monkeypatch.setattr(mod, "_PSYCOPG_POOL_AVAILABLE", False)

    def make_conn():
        cur = MagicMock()
        cur.fetchall.return_value = [(7,)]
        conn = _mock_conn()
        conn.execute.return_value = cur
        return conn

    fresh = mod.AGEClient(dsn="postgresql://localhost:5432/test", graph_name="test_graph")
    warm = mod.AGEClient(
        dsn="postgresql://localhost:5432/test",
        graph_name="test_graph",
        use_pool=True,
    )

    with patch("ci_platform.graph.age_client.psycopg.connect", return_value=make_conn()):
        fresh_result = asyncio.run(fresh.run_query("MATCH (n) RETURN count(n) AS cnt"))
    with patch("ci_platform.graph.age_client.psycopg.connect", return_value=make_conn()):
        warm_result = asyncio.run(warm.run_query("MATCH (n) RETURN count(n) AS cnt"))

    assert fresh_result == [{"cnt": 7}]
    assert warm_result == [{"cnt": 7}]


def test_transaction_commit_and_rollback_still_use_fresh_connection():
    """Package 1 preserves existing transaction commit/rollback semantics."""
    from ci_platform.graph.age_client import AGEClient
    from unittest.mock import patch

    client = AGEClient(dsn="postgresql://localhost:5432/test", graph_name="test_graph", use_pool=True)
    conn = _mock_conn()

    with patch("ci_platform.graph.age_client.psycopg.connect", return_value=conn):
        result = asyncio.run(client.run_transaction(lambda tx: "ok"))

    assert result == "ok"
    conn.commit.assert_called_once()
    conn.rollback.assert_not_called()

    conn = _mock_conn()

    def fail(_tx):
        raise RuntimeError("boom")

    with patch("ci_platform.graph.age_client.psycopg.connect", return_value=conn):
        with pytest.raises(RuntimeError, match="boom"):
            asyncio.run(client.run_transaction(fail))

    conn.rollback.assert_called_once()


def test_redact_dsn_hides_password_values():
    """Diagnostic DSN strings must not leak passwords."""
    from ci_platform.graph.age_client import redact_dsn

    keyword = "host=localhost port=5433 dbname=x user=u password=secret"
    url = "postgresql://user:secret@localhost:5433/db"

    assert "secret" not in redact_dsn(keyword)
    assert "password=***" in redact_dsn(keyword)
    assert "secret" not in redact_dsn(url)
    assert ":***@" in redact_dsn(url)


def test_param_no_collision_source_source_type():
    """$source_type must not be corrupted by $source substitution."""
    from ci_platform.graph.age_client import AGEClient
    from unittest.mock import patch

    client = AGEClient.__new__(AGEClient)
    client._dsn = "postgresql://localhost:5432/test"
    client._graph = "test_graph"

    conn = _mock_conn()
    with patch("ci_platform.graph.age_client.psycopg.connect", return_value=conn):
        asyncio.run(client.run_query(
            "MATCH (n) WHERE n.s = $source AND n.t = $source_type RETURN n",
            {"source": "siem", "source_type": "alert"},
        ))

    # call_args_list: [LOAD 'age', SET search_path, actual SQL]
    sql = conn.execute.call_args_list[2][0][0]
    assert "'siem'" in sql,  f"$source not substituted correctly in: {sql}"
    assert "'alert'" in sql, f"$source_type not substituted correctly in: {sql}"
    assert "$source" not in sql, f"Unsubstituted params remain in: {sql}"


def test_param_no_collision_analyst_analyst_action():
    """$analyst_action must not be corrupted by $analyst substitution."""
    from ci_platform.graph.age_client import AGEClient
    from unittest.mock import patch

    client = AGEClient.__new__(AGEClient)
    client._dsn = "postgresql://localhost:5432/test"
    client._graph = "test_graph"

    conn = _mock_conn()
    with patch("ci_platform.graph.age_client.psycopg.connect", return_value=conn):
        asyncio.run(client.run_query(
            "MATCH (n {analyst: $analyst, action: $analyst_action}) RETURN n",
            {"analyst": "alice", "analyst_action": "triage"},
        ))

    sql = conn.execute.call_args_list[2][0][0]
    assert "'alice'" in sql,  f"$analyst not substituted correctly in: {sql}"
    assert "'triage'" in sql, f"$analyst_action not substituted correctly in: {sql}"
    assert "$analyst" not in sql, f"Unsubstituted params remain in: {sql}"


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
def test_age_entity_node_create_idempotent():
    from ci_platform.graph.age_client import AGEClient
    client = AGEClient()
    for _ in range(3):
        existing = run_async(client.run_query(
            "MATCH (e:Entity {entity_id: $eid}) RETURN e",
            parameters={"eid": "TEST-AGE-ENT-001"}
        ))
        if not existing:
            run_async(client.run_query(
                "CREATE (e:Entity {entity_id: $eid}) RETURN e",
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
    if not run_async(client.run_query(
        "MATCH (a:Alert {alert_id: $aid}) RETURN a",
        parameters={"aid": "TEST-AGE-ALT-001"}
    )):
        run_async(client.run_query(
            "CREATE (a:Alert {alert_id: $aid}) RETURN a",
            parameters={"aid": "TEST-AGE-ALT-001"}
        ))
    if not run_async(client.run_query(
        "MATCH (e:Entity {entity_id: $eid}) RETURN e",
        parameters={"eid": "TEST-AGE-ENT-TEV"}
    )):
        run_async(client.run_query(
            "CREATE (e:Entity {entity_id: $eid}) RETURN e",
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
    if not run_async(client.run_query(
        "MATCH (c:Campaign {campaign_id: $cid}) RETURN c",
        parameters={"cid": "TEST-CAMP-001"}
    )):
        run_async(client.run_query(
            "CREATE (c:Campaign {campaign_id: $cid}) RETURN c",
            parameters={"cid": "TEST-CAMP-001"}
        ))
    if not run_async(client.run_query(
        "MATCH (a:Alert {alert_id: $aid}) RETURN a",
        parameters={"aid": "TEST-ALT-CAMP-001"}
    )):
        run_async(client.run_query(
            "CREATE (a:Alert {alert_id: $aid}) RETURN a",
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
def test_age_create_idempotent():
    from ci_platform.graph.age_client import AGEClient
    client = AGEClient()
    for _ in range(3):
        existing = run_async(client.run_query(
            "MATCH (t:ThreatIndicator {value: $val}) RETURN t",
            parameters={"val": "192.168.1.1"}
        ))
        if not existing:
            run_async(client.run_query(
                "CREATE (t:ThreatIndicator {value: $val}) RETURN t",
                parameters={"val": "192.168.1.1"}
            ))
    results = run_async(client.run_query(
        "MATCH (t:ThreatIndicator {value: $val}) RETURN count(t) AS cnt",
        parameters={"val": "192.168.1.1"}
    ))
    assert int(results[0]["cnt"]) == 1
