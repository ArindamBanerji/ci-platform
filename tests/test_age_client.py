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
import threading

import pytest
from copilot_sdk.testing import age_available

INTEGRATION_SKIP = pytest.mark.skipif(
    not age_available(), reason="AGE not reachable",
)
LIVE_DSN = os.getenv("AGE_TEST_DSN", "host=localhost port=5433 dbname=soc_copilot user=postgres password=postgres")
LIVE_GRAPH = os.getenv("AGE_TEST_GRAPH", "ci_age_client")


# ── Unit tests (no DB required) ───────────────────────────────────────────────

def test_age_client_imports_cleanly():
    """AGEClient importable without psycopg installed."""
    from ci_platform.graph.age_client import AGEClient
    assert AGEClient is not None


def test_age_client_requires_explicit_connection_configuration():
    from ci_platform.graph.age_client import AGEClient

    with pytest.raises(ValueError, match="explicit dsn"):
        AGEClient()

    with pytest.raises(ValueError, match="explicit graph_name"):
        AGEClient(dsn="postgresql://localhost:5432/test")


def test_get_graph_client_is_keyed_by_dsn_and_graph():
    """Repeated keys reuse clients while distinct graph keys stay isolated."""
    import ci_platform.graph.age_client as mod
    mod.reset_graph_clients()
    c1 = mod.get_graph_client(
        dsn="postgresql://localhost:5432/test", graph_name="test_graph"
    )
    c2 = mod.get_graph_client(
        dsn="postgresql://localhost:5432/test", graph_name="test_graph"
    )
    c3 = mod.get_graph_client(
        dsn="postgresql://localhost:5432/test", graph_name="other_graph"
    )
    assert c1 is c2
    assert c3 is not c1
    assert c1._pool_requested is True
    assert len(mod._clients) == 2
    mod.reset_graph_clients()


def test_get_graph_client_explicit_fresh_mode_stays_out_of_registry(monkeypatch):
    import ci_platform.graph.age_client as mod

    mod.reset_graph_clients()
    monkeypatch.setenv("AGE_USE_POOL", "0")

    first = mod.get_graph_client(
        dsn="postgresql://localhost:5432/test", graph_name="fresh_graph"
    )
    second = mod.get_graph_client(
        dsn="postgresql://localhost:5432/test", graph_name="fresh_graph"
    )

    assert first is not second
    assert first.connection_mode == "fresh"
    assert second.connection_mode == "fresh"
    assert mod._clients == {}


def test_reset_graph_client_closes_only_requested_key():
    import ci_platform.graph.age_client as mod

    mod.reset_graph_clients()
    first = mod.get_graph_client(
        dsn="postgresql://localhost:5432/test", graph_name="first_graph"
    )
    second = mod.get_graph_client(
        dsn="postgresql://localhost:5432/test", graph_name="second_graph"
    )

    mod.reset_graph_client(
        "postgresql://localhost:5432/test", "first_graph"
    )

    assert first._closed is True
    assert second._closed is False
    assert len(mod._clients) == 1
    mod.reset_graph_clients()


def test_age_client_default_connection_mode_is_fresh(monkeypatch):
    """Fresh per-query connections remain the default behavior."""
    monkeypatch.delenv("AGE_USE_POOL", raising=False)
    from ci_platform.graph.age_client import AGEClient

    client = AGEClient(dsn="postgresql://localhost:5432/test", graph_name="g")

    assert client.connection_mode == "fresh"


def test_age_client_pool_flag_fails_closed_when_pool_unavailable(monkeypatch):
    """Requested pool mode is explicit and never silently falls back."""
    import ci_platform.graph.age_client as mod

    monkeypatch.setattr(mod, "_PSYCOPG_POOL_AVAILABLE", False)

    client = mod.AGEClient(
        dsn="postgresql://localhost:5432/test",
        graph_name="g",
        use_pool=True,
    )

    assert client.connection_mode == "pool_unavailable"
    assert client.pool_available is False
    with pytest.raises(RuntimeError, match="psycopg_pool is unavailable"):
        asyncio.run(client.connect())


def test_age_client_pooled_mode_uses_psycopg_pool_when_available(monkeypatch):
    """When psycopg_pool is installed, pooled mode uses ConnectionPool."""
    import sys
    import types
    from psycopg_pool import PoolClosed
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

        def connection(self, timeout=None):
            return self.conn

        def wait(self, timeout=None):
            return None

        def get_stats(self):
            return {"pool_size": 2, "pool_available": 1, "requests_waiting": 0}

        def close(self):
            self.closed = True

    fake_module = types.ModuleType("psycopg_pool")
    fake_module.ConnectionPool = FakePool
    fake_module.PoolClosed = PoolClosed
    monkeypatch.setitem(sys.modules, "psycopg_pool", fake_module)
    monkeypatch.setattr(mod, "_PSYCOPG_POOL_AVAILABLE", True)

    client = mod.AGEClient(
        dsn="postgresql://localhost:5432/test",
        graph_name="g",
        use_pool=True,
        pool_min_size=1,
        pool_max_size=2,
    )

    for _ in range(3):
        asyncio.run(client.run_query("MATCH (n) RETURN n"))
    asyncio.run(client.close())

    assert client.connection_mode == "pooled"
    assert len(FakePool.instances) == 1
    pool = FakePool.instances[0]
    assert pool.kwargs["min_size"] == 1
    assert pool.kwargs["max_size"] == 2
    assert pool.kwargs["max_idle"] == 60
    assert pool.kwargs["max_lifetime"] == 300
    assert pool.kwargs["reconnect_timeout"] == 300
    assert callable(pool.kwargs["reconnect_failed"])
    assert pool.kwargs["kwargs"]["autocommit"] is True
    assert pool.kwargs["kwargs"]["connect_timeout"] == 3
    assert pool.kwargs["kwargs"]["prepare_threshold"] is None
    assert pool.kwargs["timeout"] == 5.0
    assert callable(pool.kwargs["reset"])
    calls = [call[0][0] for call in pool.conn.execute.call_args_list]
    assert calls[0] == "LOAD 'age'"
    assert calls[1].startswith("SET search_path")
    assert "statement_timeout = '8000ms'" in calls[1]
    assert calls.count("LOAD 'age'") == 1
    assert sum(str(sql).startswith("SET search_path") for sql in calls) == 1
    assert sum(str(sql).startswith("SELECT * FROM cypher") for sql in calls) == 3
    assert pool.closed is True


def test_pool_wait_failure_closes_partially_initialized_pool(monkeypatch):
    """A failed readiness wait must not orphan the newly created pool."""
    import sys
    import types

    from psycopg_pool import PoolClosed

    import ci_platform.graph.age_client as mod

    class WaitFailPool:
        instances = []

        def __init__(self, **_kwargs):
            self.closed = False
            self.instances.append(self)

        def wait(self, timeout=None):
            raise TimeoutError("pool readiness failed")

        def close(self):
            self.closed = True

    fake_module = types.ModuleType("psycopg_pool")
    fake_module.ConnectionPool = WaitFailPool
    fake_module.PoolClosed = PoolClosed
    monkeypatch.setitem(sys.modules, "psycopg_pool", fake_module)
    monkeypatch.setattr(mod, "_PSYCOPG_POOL_AVAILABLE", True)

    client = mod.AGEClient(
        dsn="postgresql://localhost:5432/test",
        graph_name="g",
        use_pool=True,
    )
    with pytest.raises(RuntimeError, match="initialization failed"):
        client._ensure_pool()

    assert len(WaitFailPool.instances) == 1
    assert WaitFailPool.instances[0].closed is True
    assert client._pool is None


def test_pool_reset_restores_session_defaults() -> None:
    """Reset uses one round trip while restoring AGE session defaults."""
    from unittest.mock import Mock

    from ci_platform.graph.age_client import AGEClient

    client = AGEClient(
        dsn="postgresql://localhost:5432/test",
        graph_name="g",
        use_pool=True,
    )
    connection = Mock()

    client._reset_age_session(connection)

    calls = [call.args[0] for call in connection.execute.call_args_list]
    assert len(calls) == 1
    assert calls[0].startswith("RESET ALL; SET search_path")
    assert "statement_timeout = '8000ms'" in calls[0]
    assert client.get_pool_diagnostics()["resets_on_return"] == 1


def test_pool_return_resets_borrower_session_state() -> None:
    """A pool checkout boundary resets borrower state on the returned connection."""
    from contextlib import contextmanager

    from ci_platform.graph.age_client import AGEClient

    class Cursor:
        def __init__(self, value: str) -> None:
            self._value = value

        def fetchone(self):
            return (self._value,)

    class Connection:
        def __init__(self) -> None:
            self.work_mem = "4MB"

        def execute(self, sql: str):
            if sql.startswith("SET work_mem"):
                self.work_mem = "64MB"
            elif sql.startswith("RESET ALL"):
                self.work_mem = "4MB"
            if sql == "SHOW work_mem":
                return Cursor(self.work_mem)
            return Cursor("")

    client = AGEClient(
        dsn="postgresql://localhost:5432/test",
        graph_name="g",
        use_pool=True,
    )
    connection = Connection()

    class Pool:
        @contextmanager
        def connection(self, timeout=None):
            try:
                yield connection
            finally:
                client._reset_age_session(connection)

    setattr(client, "_pool", Pool())
    client._pool_available = True
    with client._pooled_connection() as borrowed:
        borrowed.execute("SET work_mem = '64MB'")
    with client._pooled_connection() as borrowed:
        assert borrowed.execute("SHOW work_mem").fetchone()[0] == "4MB"


def test_closed_client_cannot_reopen_or_borrow(monkeypatch) -> None:
    import ci_platform.graph.age_client as mod

    client = mod.AGEClient(
        dsn="postgresql://localhost:5432/test",
        graph_name="closed_graph",
        use_pool=True,
    )
    client.close_sync()

    with pytest.raises(RuntimeError, match="closed and cannot be reused"):
        client._ensure_pool()
    with pytest.raises(RuntimeError, match="closed and cannot be reused"):
        asyncio.run(client.run_query("MATCH (n) RETURN n"))
    with pytest.raises(RuntimeError, match="closed and cannot be reused"):
        asyncio.run(client.run_transaction(lambda transaction: None))


def test_pool_closed_converts_to_runtime_error(monkeypatch):
    import psycopg_pool
    from ci_platform.graph.age_client import AGEClient

    # Zero initial connections allow a real pool lifecycle without a database.
    pool = psycopg_pool.ConnectionPool(min_size=0, max_size=1, open=True)
    monkeypatch.setattr(psycopg_pool, "ConnectionPool", lambda **kwargs: pool)
    client = AGEClient(
        dsn="postgresql://localhost/unused", graph_name="r6_closed",
        use_pool=True,
    )
    try:
        assert client._ensure_pool() is pool
        pool.close()
        assert client._closed is False
        with pytest.raises(RuntimeError, match="^AGE client is closed$") as caught:
            with client._pooled_connection():
                pytest.fail("Checkout unexpectedly succeeded")
        assert type(caught.value) is RuntimeError
        assert isinstance(caught.value.__cause__, psycopg_pool.PoolClosed)
        assert client._pool is pool
    finally:
        client.close_sync()


def test_close_then_query_consistent_error():
    from ci_platform.graph.age_client import AGEClient

    client = AGEClient(
        dsn="postgresql://localhost/unused", graph_name="r6_closed",
        use_pool=True,
    )
    asyncio.run(client.close())
    with pytest.raises(RuntimeError, match="closed"):
        asyncio.run(client.run_query("RETURN 1 AS value"))
    assert client._pool is None


@pytest.mark.parametrize("phase", ["query", "return"])
def test_pool_closed_after_checkout_is_not_converted(phase):
    from contextlib import contextmanager
    from unittest.mock import Mock
    from psycopg_pool import PoolClosed
    from ci_platform.graph.age_client import AGEClient

    error = PoolClosed("failure after checkout")

    @contextmanager
    def connection(**kwargs):
        yield object()
        if phase == "return":
            raise error

    pool = Mock()
    pool.connection.side_effect = connection
    client = AGEClient(
        dsn="postgresql://localhost/unused", graph_name="r6_borrowed",
        use_pool=True,
    )
    client._pool = pool
    try:
        with pytest.raises(PoolClosed) as caught:
            with client._pooled_connection():
                if phase == "query":
                    raise error
        assert caught.value is error
        assert client._total_checkouts == client._total_returns == 1
    finally:
        client.close_sync()


def test_close_and_ensure_pool_share_one_atomic_lock(monkeypatch) -> None:
    """A close queued behind pool access cannot be followed by pool recreation."""
    import ci_platform.graph.age_client as mod

    class Pool:
        def __init__(self) -> None:
            self.closed = False

        def close(self) -> None:
            self.closed = True

    client = mod.AGEClient(
        dsn="postgresql://localhost:5432/test",
        graph_name="close_race_graph",
        use_pool=True,
    )
    pool = Pool()
    setattr(client, "_pool", pool)
    check_entered = threading.Event()
    release_check = threading.Event()
    close_started = threading.Event()
    original_ensure_open = client._ensure_open
    first_check = True

    def gated_ensure_open() -> None:
        nonlocal first_check
        original_ensure_open()
        if first_check:
            first_check = False
            check_entered.set()
            assert release_check.wait(timeout=2)

    monkeypatch.setattr(client, "_ensure_open", gated_ensure_open)
    ensured: list[object] = []

    ensure_thread = threading.Thread(
        target=lambda: ensured.append(client._ensure_pool()),
    )

    def close_client() -> None:
        close_started.set()
        client.close_sync()

    close_thread = threading.Thread(target=close_client)
    ensure_thread.start()
    assert check_entered.wait(timeout=2)
    close_thread.start()
    assert close_started.wait(timeout=2)
    release_check.set()
    ensure_thread.join(timeout=2)
    close_thread.join(timeout=2)

    assert not ensure_thread.is_alive()
    assert not close_thread.is_alive()
    assert ensured == [pool]
    assert pool.closed is True
    assert client._closed is True
    assert client._pool is None
    with pytest.raises(RuntimeError, match="closed and cannot be reused"):
        client._ensure_pool()


def test_shared_client_registry_is_bounded_and_close_all_drains(monkeypatch) -> None:
    import ci_platform.graph.age_client as mod

    mod.close_all_graph_clients()
    monkeypatch.setattr(mod, "MAX_CLIENTS", 2)
    first = mod.get_graph_client("postgresql://localhost:5432/a", "g")
    second = mod.get_graph_client("postgresql://localhost:5432/b", "g")

    with pytest.raises(RuntimeError, match=r"registry full \(2 clients\)"):
        mod.get_graph_client("postgresql://localhost:5432/c", "g")

    mod.close_all_graph_clients()
    assert mod._clients == {}
    assert first._closed is True
    assert second._closed is True


class _ProbeConnection:
    def __init__(self, identifier):
        self.identifier = identifier
        self.closed = False

    def close(self):
        self.closed = True


class _ProbeConnectionContext:
    def __init__(self, pool, connection):
        self.pool = pool
        self.connection_value = connection

    def __enter__(self):
        return self.connection_value

    def __exit__(self, exc_type, exc_value, traceback):
        self.pool.active -= 1
        if not self.connection_value.closed:
            self.pool.idle.append(self.connection_value)


class _ProbePool:
    def __init__(self, max_size=2):
        self.max_size = max_size
        self.active = 0
        self.created = 0
        self.idle = []
        self.closed = False

    def connection(self):
        if self.active >= self.max_size:
            raise RuntimeError("pool exhausted")
        self.active += 1
        if self.idle:
            connection = self.idle.pop()
        else:
            self.created += 1
            connection = _ProbeConnection(self.created)
        return _ProbeConnectionContext(self, connection)

    def close(self):
        self.closed = True


def test_pool_connection_reuse():
    pool = _ProbePool(max_size=2)
    with pool.connection() as first:
        first_id = first.identifier
    with pool.connection() as second:
        assert second.identifier == first_id


def test_pool_max_size():
    pool = _ProbePool(max_size=2)
    first = pool.connection()
    second = pool.connection()
    first.__enter__()
    second.__enter__()
    try:
        with pytest.raises(RuntimeError, match="pool exhausted"):
            pool.connection()
    finally:
        first.__exit__(None, None, None)
        second.__exit__(None, None, None)


def test_client_pool_exhaustion_returns_clear_error():
    from ci_platform.graph.age_client import AGEClient

    class PoolTimeout(Exception):
        pass

    class ExhaustedPool:
        def connection(self, timeout=None):
            raise PoolTimeout("busy")

    client = AGEClient(
        dsn="postgresql://localhost:5432/test", graph_name="g", use_pool=False
    )
    client._pool_requested = True
    client._pool_available = True
    client._connection_mode = "pooled"
    client._pool = ExhaustedPool()
    with pytest.raises(RuntimeError, match="pool acquisition timeout after 5.0s"):
        client._sync_execute("MATCH (n) RETURN n")


def test_pool_recovery_after_disconnect():
    pool = _ProbePool(max_size=1)
    with pool.connection() as first:
        first.close()
    with pool.connection() as recovered:
        assert recovered.closed is False
        assert recovered.identifier != first.identifier


def test_pool_cleanup_on_shutdown():
    pool = _ProbePool(max_size=1)
    from ci_platform.graph.age_client import AGEClient

    client = AGEClient.__new__(AGEClient)
    client._pool = pool
    client._warm_conn = None
    client._closed = False
    client._sync_close()

    assert pool.closed is True
    assert client._pool is None


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
    client = AGEClient(dsn=LIVE_DSN, graph_name=LIVE_GRAPH)
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
    client = AGEClient(dsn=LIVE_DSN, graph_name=LIVE_GRAPH)
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

    client = AGEClient(dsn=LIVE_DSN, graph_name=LIVE_GRAPH)
    conn1 = _mock_conn()
    conn2 = _mock_conn()

    with patch(
        "ci_platform.graph.age_client.psycopg.connect",
        side_effect=[conn1, conn2],
    ) as connect:
        asyncio.run(client.run_query("MATCH (n) RETURN n"))
        asyncio.run(client.run_query("MATCH (n) RETURN n"))

    assert connect.call_count == 2
    assert all(call.kwargs["prepare_threshold"] is None for call in connect.call_args_list)
    assert conn1.execute.call_args_list[0][0][0] == "LOAD 'age'"
    assert conn1.execute.call_args_list[1][0][0].startswith("SET search_path")
    assert conn2.execute.call_args_list[0][0][0] == "LOAD 'age'"
    assert conn2.execute.call_args_list[1][0][0].startswith("SET search_path")


def test_run_query_pool_unavailable_returns_clear_error(monkeypatch):
    """A requested unavailable pool fails quickly instead of hanging."""
    import ci_platform.graph.age_client as mod
    from unittest.mock import patch

    monkeypatch.setattr(mod, "_PSYCOPG_POOL_AVAILABLE", False)
    client = mod.AGEClient(
        dsn="postgresql://localhost:5432/test",
        graph_name="test_graph",
        use_pool=True,
    )
    with pytest.raises(RuntimeError, match="psycopg_pool is unavailable"):
        asyncio.run(client.run_query("MATCH (n) RETURN n"))


def test_connection_diagnostics_report_latency_budget_and_pool_stats(monkeypatch):
    """Health diagnostics expose connection mode, budgets, and saturation."""
    import ci_platform.graph.age_client as mod
    from unittest.mock import MagicMock, patch

    monkeypatch.setattr(mod, "_PSYCOPG_POOL_AVAILABLE", True)
    client = mod.AGEClient(
        dsn="postgresql://localhost:5432/test",
        graph_name="test_graph",
        use_pool=True,
    )
    client._pool = MagicMock()
    client._pool.get_stats.return_value = {
        "pool_size": 8, "pool_available": 2, "requests_waiting": 3,
    }
    diagnostics = client.connection_diagnostics()
    assert diagnostics["connection_mode"] == "pooled"
    assert diagnostics["statement_timeout_ms"] == 8000
    assert diagnostics["pool_timeout_seconds"] == 5.0
    assert diagnostics["pool_size"] == 8
    assert diagnostics["pool_available_connections"] == 2
    assert diagnostics["pool_requests_waiting"] == 3


def test_transaction_commit_and_rollback_in_explicit_fresh_mode():
    """Offline fresh mode preserves transaction commit/rollback semantics."""
    from ci_platform.graph.age_client import AGEClient
    from unittest.mock import patch

    client = AGEClient(dsn="postgresql://localhost:5432/test", graph_name="test_graph", use_pool=False)
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
    not age_available(), reason="AGE not reachable"
)


def run_async(coro):
    import asyncio
    if hasattr(asyncio, 'WindowsSelectorEventLoopPolicy'):
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    return asyncio.get_event_loop().run_until_complete(coro)


@INTEGRATION_SKIP
def test_age_graph_queryable():
    from ci_platform.graph.age_client import AGEClient
    client = AGEClient(dsn=LIVE_DSN, graph_name=LIVE_GRAPH)
    run_async(client.ensure_graph())
    results = run_async(client.run_query(
        "MATCH (n) RETURN count(n) AS cnt"
    ))
    assert results is not None
    assert isinstance(results[0].get("cnt", 0), int)


@INTEGRATION_SKIP
def test_age_entity_node_create_idempotent():
    from ci_platform.graph.age_client import AGEClient
    client = AGEClient(dsn=LIVE_DSN, graph_name=LIVE_GRAPH)
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
    client = AGEClient(dsn=LIVE_DSN, graph_name=LIVE_GRAPH)
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
    client = AGEClient(dsn=LIVE_DSN, graph_name=LIVE_GRAPH)
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
    client = AGEClient(dsn=LIVE_DSN, graph_name=LIVE_GRAPH)
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
    client = AGEClient(dsn=LIVE_DSN, graph_name=LIVE_GRAPH)
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

