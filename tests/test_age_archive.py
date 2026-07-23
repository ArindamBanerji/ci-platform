from __future__ import annotations

import re
from typing import Any

import pytest

from ci_platform.graph.age_graph_store import AGEGraphStore


class FakeArchiveStore(AGEGraphStore):
    """In-memory AGE query double for the retention query shapes only."""

    def __init__(self, decisions: list[dict[str, Any]], outcomes: dict[str, dict[str, Any]] | None = None) -> None:
        self.decisions = decisions
        self.outcomes = outcomes or {}
        self.edges = {(decision_id, decision_id) for decision_id in self.outcomes}
        self.queries: list[str] = []

    @staticmethod
    def _S(value: Any) -> str:
        if isinstance(value, str):
            return "'" + value.replace("'", "\\'") + "'"
        if isinstance(value, bool):
            return str(value).lower()
        return str(value)

    @staticmethod
    def _domain(query: str) -> str:
        match = re.search(r"d\.domain = '([^']+)'", query)
        assert match is not None
        return match.group(1)

    @staticmethod
    def _ids(query: str) -> list[str]:
        match = re.search(r"d\.decision_id IN \[([^]]*)\]", query)
        assert match is not None
        return re.findall(r"'([^']+)'", match.group(1))

    def _active(self, domain: str) -> list[dict[str, Any]]:
        return [
            decision
            for decision in self.decisions
            if decision["domain"] == domain and decision.get("archived") is not True
        ]

    def _run_query(self, cypher: str) -> list[dict[str, Any]]:
        self.queries.append(cypher)
        query = " ".join(cypher.split())
        domain = self._domain(query)

        if "SET d.archived = true" in query:
            matched = 0
            for decision in self._active(domain):
                if decision["decision_id"] not in self._ids(query):
                    continue
                decision.update(
                    {
                        "archived": True,
                        "archive_reason": "retention_window",
                        "archive_status": "archived",
                        "archived_from_status": decision.get("status"),
                    }
                )
                matched += 1
            return [{"cnt": matched}]

        if "RETURN d.decision_id AS decision_id" in query:
            decisions = sorted(
                self._active(domain),
                key=lambda decision: (decision["created_at"], decision["decision_id"]),
                reverse=True,
            )
            return [{"decision_id": decision["decision_id"]} for decision in decisions]

        if "RETURN count(DISTINCT d.decision_id) AS v" in query:
            total = sum(
                decision.get("status") in {"confirmed", "overridden"}
                for decision in self._active(domain)
            )
            return [{"v": total}]

        if "RETURN count(d) AS cnt" in query:
            return [{"cnt": len(self._active(domain))}]

        if "d.archived = true" in query and "OPTIONAL MATCH" in query:
            archived = sorted(
                (
                    decision
                    for decision in self.decisions
                    if decision["domain"] == domain and decision.get("archived") is True
                ),
                key=lambda decision: (decision["created_at"], decision["decision_id"]),
            )
            return [
                {"d": decision, "o": self.outcomes.get(decision["decision_id"])}
                for decision in archived
            ]

        if "RETURN d" in query:
            return [{"d": decision} for decision in self._active(domain)]
        raise AssertionError(f"Unexpected query: {query}")


def _decisions(count: int, domain: str = "trading", *, created_at: float = 0.0) -> list[dict[str, Any]]:
    return [
        {
            "decision_id": f"{domain.upper()}-{index:04}",
            "domain": domain,
            "category": "trend",
            "category_index": 0,
            "recommended_action": "buy",
            "recommended_index": 0,
            "confidence": 0.8,
            "factor_vector": [0.1, 0.2],
            "probabilities": [0.8, 0.2],
            "created_at": created_at + index,
            "status": "confirmed" if index == 0 else "pending",
        }
        for index in range(count)
    ]


@pytest.mark.parametrize(("count", "keep_recent"), [(0, 800), (1, 1), (800, 800)])
def test_archive_returns_zero_when_active_population_fits_window(count: int, keep_recent: int) -> None:
    store = FakeArchiveStore(_decisions(count))

    assert store.archive_old_decisions("trading", keep_recent=keep_recent) == 0
    assert not any("SET d.archived = true" in query for query in store.queries)


def test_archive_801_retains_newest_800_and_archives_oldest() -> None:
    store = FakeArchiveStore(_decisions(801))

    assert store.archive_old_decisions("trading", keep_recent=800) == 1
    assert store.decisions[0]["archived"] is True
    assert "archived" not in store.decisions[-1]


def test_archive_900_archives_100() -> None:
    store = FakeArchiveStore(_decisions(900))

    assert store.archive_old_decisions("trading", keep_recent=800) == 100
    assert sum(decision.get("archived") is True for decision in store.decisions) == 100


def test_archive_tie_break_retains_descending_decision_id() -> None:
    decisions = _decisions(2, created_at=7.0)
    decisions[1]["created_at"] = decisions[0]["created_at"]
    store = FakeArchiveStore(decisions)

    assert store.archive_old_decisions("trading", keep_recent=1) == 1
    assert decisions[0]["archived"] is True
    assert decisions[1].get("archived") is not True


def test_archive_batches_more_than_100_candidates() -> None:
    store = FakeArchiveStore(_decisions(950))

    assert store.archive_old_decisions("trading", keep_recent=800) == 150
    updates = [query for query in store.queries if "SET d.archived = true" in query]
    assert len(updates) == 2
    assert [len(FakeArchiveStore._ids(query)) for query in updates] == [100, 50]


def test_archive_retry_is_idempotent() -> None:
    store = FakeArchiveStore(_decisions(10))

    assert store.archive_old_decisions("trading", keep_recent=0) == 10
    assert store.archive_old_decisions("trading", keep_recent=0) == 0


def test_active_reads_and_d2_counts_exclude_archived_decisions() -> None:
    store = FakeArchiveStore(_decisions(5))
    store.archive_old_decisions("trading", keep_recent=3)

    assert len(store.get_all_decisions("trading")) == 3
    assert store.count_verified("trading") == 0


def test_archive_reader_merges_outcomes_and_sorts_by_decision_time() -> None:
    decisions = _decisions(3)
    outcomes = {
        decisions[0]["decision_id"]: {
            "decision_id": decisions[0]["decision_id"],
            "actual_action": "buy",
            "actual_index": 0,
            "is_correct": True,
            "verified_at": 50.0,
        }
    }
    store = FakeArchiveStore(decisions, outcomes)
    store.archive_old_decisions("trading", keep_recent=0)

    archived = store.get_archived_decisions("trading")

    assert [record["decision_id"] for record in archived] == [decision["decision_id"] for decision in decisions]
    assert archived[0]["actual_action"] == "buy"
    assert archived[0]["actual_index"] == 0
    assert archived[0]["is_correct"] is True
    assert archived[0]["verified_at"] == 50.0


def test_archive_is_domain_scoped() -> None:
    trading = _decisions(5, "trading")
    soc = _decisions(5, "soc")
    store = FakeArchiveStore(trading + soc)

    assert store.archive_old_decisions("trading", keep_recent=3) == 2
    assert sum(decision.get("archived") is True for decision in trading) == 2
    assert not any(decision.get("archived") is True for decision in soc)


def test_archive_preserves_outcome_nodes_and_edges() -> None:
    decisions = _decisions(2)
    decision_id = decisions[0]["decision_id"]
    outcomes = {decision_id: {"decision_id": decision_id, "actual_action": "buy", "is_correct": True}}
    store = FakeArchiveStore(decisions, outcomes)

    assert store.archive_old_decisions("trading", keep_recent=1) == 1
    assert decision_id in store.outcomes
    assert (decision_id, decision_id) in store.edges
