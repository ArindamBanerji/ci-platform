"""Behavioral D2 verified-decision tests for SOC AGE count readers."""

from __future__ import annotations

import asyncio
import importlib.util
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest


@dataclass
class _Decision:
    decision_id: str
    domain: str | None
    status: str | None
    outcome: str | None = None
    correct: bool = False
    outcome_is_correct: bool | None = None
    archived: bool = False


class _InMemoryAGE:
    """Small behavioral AGE fixture for the D2 query shapes used by count readers."""

    def __init__(self) -> None:
        self.queries: list[str] = []
        self.decisions = [
            _Decision("SOC-CONFIRMED", "soc", "confirmed", outcome_is_correct=True),
            _Decision("SOC-OVERRIDDEN", "soc", "overridden", outcome_is_correct=False),
            _Decision("SOC-CONFIRMED-OUTCOME", "soc", "confirmed", "correct", True, True),
            _Decision("SOC-LEGACY", None, None, "correct", True),
            _Decision("SOC-PENDING", "soc", "pending", "correct", True),
            _Decision("SOC-ARCHIVED", "soc", "confirmed", "correct", True, True, True),
            _Decision("OTHER-CONFIRMED", "trading", "confirmed", outcome_is_correct=True),
        ]

    @staticmethod
    def _S(value: object) -> str:
        if value is None:
            return "null"
        if isinstance(value, bool):
            return str(value).lower()
        if isinstance(value, (int, float)):
            return str(value)
        return "'" + str(value).replace("'", "\\'") + "'"

    def _soc_rows(self, query: str) -> list[_Decision]:
        assert "(d.domain = 'soc' OR d.domain IS NULL)" in query
        return [decision for decision in self.decisions if decision.domain in ("soc", None)]

    @staticmethod
    def _verified(decision: _Decision, query: str) -> bool:
        branch_1 = (
            "d.status IS NOT NULL AND d.status IN ['confirmed', 'overridden']" in query
            and decision.status in ("confirmed", "overridden")
        )
        branch_2 = (
            "d.status IS NULL AND d.outcome IS NOT NULL" in query
            and decision.status is None
            and decision.outcome is not None
        )
        is_active = (
            "d.archived IS NULL OR d.archived <> true" not in query
            or not decision.archived
        )
        return is_active and (branch_1 or branch_2)

    def run(self, query: str) -> list[dict[str, object]]:
        self.queries.append(query)
        if "CREATE (o:Outcome" in query:
            match = re.search(r"MATCH \(d:Decision \{decision_id: '([^']+)'\}\)", query)
            assert match is not None
            decision = next(item for item in self.decisions if item.decision_id == match.group(1))
            decision.status = "confirmed"
            decision.outcome_is_correct = True
            return [{"status": "confirmed", "o": {}}]
        rows = self._soc_rows(query)
        if "o.is_correct = true" in query:
            total = sum(
                1
                for decision in rows
                if (
                    "d.archived IS NULL OR d.archived <> true" not in query
                    or not decision.archived
                )
                and (
                    (
                        decision.status in ("confirmed", "overridden")
                        and decision.outcome_is_correct is True
                    )
                    or (decision.status is None and decision.correct is True)
                )
            )
            return [{"cnt": total}]
        if "d.correct = true" in query:
            total = sum(
                1
                for decision in rows
                if (
                    "d.archived IS NULL OR d.archived <> true" not in query
                    or not decision.archived
                )
                and decision.status is None
                and decision.correct is True
            )
            return [{"cnt": total}]
        if "RETURN DISTINCT properties(d) AS d, properties(o) AS o" in query:
            return [
                {
                    "d": {
                        "decision_id": decision.decision_id,
                        "domain": decision.domain,
                        "status": decision.status,
                        "outcome": decision.outcome,
                    },
                    "o": (
                        {"actual_action": "verified", "is_correct": decision.outcome_is_correct}
                        if decision.outcome_is_correct is not None
                        else None
                    ),
                }
                for decision in rows
                if self._verified(decision, query)
            ]
        total = sum(1 for decision in rows if self._verified(decision, query))
        return [{"v" if " AS v" in query else "cnt": total}]


class _FakeAGEClient:
    instances: list["_FakeAGEClient"] = []
    fixture: _InMemoryAGE | None = None

    def __init__(self, dsn: str | None = None, graph_name: str | None = None) -> None:
        self._graph = graph_name
        _FakeAGEClient.instances.append(self)

    _S = staticmethod(_InMemoryAGE._S)

    async def run_query(self, query: str, parameters: Any = None) -> list[dict[str, object]]:
        assert self.fixture is not None
        return self.fixture.run(query)


@pytest.fixture
def fixture_graph() -> _InMemoryAGE:
    return _InMemoryAGE()


@pytest.fixture
def store(monkeypatch, fixture_graph):
    from ci_platform.graph.age_graph_store import AGEGraphStore

    _FakeAGEClient.instances = []
    _FakeAGEClient.fixture = fixture_graph
    monkeypatch.setattr("ci_platform.graph.age_graph_store.AGEClient", _FakeAGEClient)
    return AGEGraphStore(dsn="postgresql://example/test", graph_name="d2_test_graph")


def _soc_neo4j_client_class():
    module_path = (
        Path(__file__).resolve().parents[2]
        / "gen-ai-roi-demo-v4-v50"
        / "backend"
        / "app"
        / "db"
        / "neo4j.py"
    )
    spec = importlib.util.spec_from_file_location("soc_neo4j_d2_test", module_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.Neo4jClient


def test_confirmed_and_overridden_status_rows_are_counted(store):
    assert store.count_verified("soc") == 4


def test_legacy_embedded_outcome_row_is_counted(store):
    assert store.count_verified_decisions("soc") == 4


def test_confirmed_row_with_outcome_is_not_double_counted(store):
    assert store.count_verified("soc") == 4


def test_pending_row_with_outcome_is_excluded(store, fixture_graph):
    assert store.count_verified("soc") == 4
    assert "SOC-PENDING" in {item.decision_id for item in fixture_graph.decisions}


def test_other_domain_row_is_excluded(store):
    assert store.count_verified("soc") == 4


def test_archived_confirmed_row_is_excluded_from_d2(store):
    assert store.count_verified("soc") == 4
    assert store.count_verified_decisions("soc") == 4
    assert store.count_correct("soc") == 3
    assert "SOC-ARCHIVED" not in {
        row["decision_id"] for row in store.get_verified_decisions("soc")
    }


def test_count_correct_uses_branch_1_outcome_and_branch_2_property(store):
    assert store.count_correct("soc") == 3


def test_get_verified_decisions_returns_d2_decision_fields(store):
    verified = store.get_verified_decisions("soc")

    assert {row["decision_id"] for row in verified} == {
        "SOC-CONFIRMED",
        "SOC-OVERRIDDEN",
        "SOC-CONFIRMED-OUTCOME",
        "SOC-LEGACY",
    }
    confirmed = next(row for row in verified if row["decision_id"] == "SOC-CONFIRMED")
    assert confirmed["domain"] == "soc"
    assert confirmed["status"] == "confirmed"


def test_pending_to_outcome_transition_increments_v(store, fixture_graph):
    pending = next(item for item in fixture_graph.decisions if item.decision_id == "SOC-PENDING")
    pending.outcome = None
    pending.correct = False
    assert store.count_verified("soc") == 4
    store.write_outcome("SOC-PENDING", "approve", True)
    assert store.count_verified("soc") == 5


def test_mixed_branch_parity_across_all_soc_count_readers(store, fixture_graph, monkeypatch):
    from ci_platform.graph.age_client import AGEClient

    async def run_query(query: str, parameters: Any = None) -> list[dict[str, object]]:
        return fixture_graph.run(query)

    age_client = AGEClient(dsn="postgresql://example/test", graph_name="d2_test_graph")
    monkeypatch.setattr(age_client, "run_query", run_query)
    soc_client = _soc_neo4j_client_class()()
    monkeypatch.setattr(soc_client, "run_query", run_query)

    expected = store.count_verified("soc")
    assert expected == 4
    assert asyncio.run(age_client.count_verified_decisions()) == expected
    assert asyncio.run(age_client.count_correct_decisions()) == 1
    assert asyncio.run(soc_client.count_verified_decisions()) == expected


def test_invalid_domain_fails_before_cypher(store, fixture_graph):
    with pytest.raises(ValueError, match="unsupported graph domain"):
        store.count_verified("soc' OR 1=1")
    assert fixture_graph.queries == []


def test_protocol_v2_test_domain_is_accepted(store):
    domain = "pytest_protocol_v2_test_age_write_outcome_confirmed_b6bc3333"

    assert store._validated_domain(domain) == domain


def test_sqlite_d2_lifecycle_parity_in_memory():
    from copilot_sdk.graph.sqlite_store import SQLiteGraphStore

    sqlite_store = SQLiteGraphStore(":memory:", domain="soc")
    try:
        confirmed_id = sqlite_store.write_decision(
            "soc", "price_variance", "hold_for_review", 0.7, {"variance": 0.2}
        )
        sqlite_store.write_outcome(confirmed_id, "hold_for_review", True)
        sqlite_store.write_decision(
            "soc", "price_variance", "hold_for_review", 0.6, {"variance": 0.1}
        )

        assert sqlite_store.count_verified("soc") == 1
        assert sqlite_store.count_verified_decisions("soc") == 1
        assert sqlite_store.count_correct("soc") == 1
        assert [row["decision_id"] for row in sqlite_store.get_verified_decisions("soc")] == [
            confirmed_id
        ]
    finally:
        sqlite_store.close()


def test_live_soc_gate():
    dsn = os.getenv("GRAPH_DSN")
    if not (dsn and os.getenv("AGE_D2_LIVE_GATE") == "1"):
        pytest.skip("set GRAPH_DSN and AGE_D2_LIVE_GATE=1 to run the live SOC gate")

    from ci_platform.graph.age_client import AGEClient
    from ci_platform.graph.age_graph_store import AGEGraphStore

    store = AGEGraphStore(dsn=dsn, graph_name="soc_graph")
    client = AGEClient(dsn=dsn, graph_name="soc_graph")
    try:
        rows = asyncio.run(
            client.run_query(
                "MATCH (d:Decision) "
                "WHERE (d.domain = 'soc' OR d.domain IS NULL) "
                "AND (d.archived IS NULL OR d.archived <> true) "
                "AND ("
                "(d.status IS NOT NULL AND d.status IN ['confirmed', 'overridden']) "
                "OR (d.status IS NULL AND d.outcome IS NOT NULL)"
                ") "
                "RETURN count(DISTINCT d.decision_id) AS v"
            )
        )
        raw_count = int(rows[0]["v"]) if rows else 0
        function_count = store.count_verified("soc")

        assert function_count == raw_count
        assert function_count > 0
    finally:
        store.close()
        asyncio.run(client.close())


def test_trading_gate_after_phase_3():
    pytest.skip("Phase 3 gate: assert count_verified(store, 'trading') >= 150 after migration")
