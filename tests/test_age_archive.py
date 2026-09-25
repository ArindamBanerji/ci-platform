from __future__ import annotations

from typing import Any

import pytest


pytestmark = pytest.mark.age


def _write_decisions(
    store: Any,
    count: int,
    domain: str = "trading",
    *,
    created_at: float = 1_700_000_000.0,
) -> list[str]:
    decision_ids: list[str] = []
    for index in range(count):
        decision_id = f"{domain.upper()}-{index:04}"
        decision_ids.append(decision_id)
        store.write_decision(
            domain,
            "trend",
            "buy",
            0.8,
            {"signal": float(index)},
            metadata={
                "decision_id": decision_id,
                "created_at": created_at + index,
                "category_index": 0,
                "recommended_index": 0,
                "probabilities": [0.8, 0.2],
            },
        )
    return decision_ids


@pytest.mark.parametrize(("count", "keep_recent"), [(0, 800), (1, 1), (20, 20)])
def test_archive_returns_zero_when_active_population_fits_window(
    age_store: Any, count: int, keep_recent: int
) -> None:
    _write_decisions(age_store, count)

    assert age_store.archive_old_decisions("trading", keep_recent=keep_recent) == 0
    assert len(age_store.get_all_decisions("trading")) == count


def test_archive_retains_newest_and_archives_oldest(age_store: Any) -> None:
    ids = _write_decisions(age_store, 6)

    assert age_store.archive_old_decisions("trading", keep_recent=5) == 1
    active_ids = {row["decision_id"] for row in age_store.get_all_decisions("trading")}
    archived_ids = {row["decision_id"] for row in age_store.get_archived_decisions("trading")}

    assert ids[0] in archived_ids
    assert ids[-1] in active_ids
    assert len(active_ids) == 5


def test_archive_archives_all_over_window(age_store: Any) -> None:
    _write_decisions(age_store, 12)

    assert age_store.archive_old_decisions("trading", keep_recent=5) == 7
    assert len(age_store.get_all_decisions("trading")) == 5
    assert len(age_store.get_archived_decisions("trading")) == 7


def test_archive_tie_break_retains_descending_decision_id(age_store: Any) -> None:
    _write_decisions(age_store, 2, created_at=7.0)

    assert age_store.archive_old_decisions("trading", keep_recent=1) == 1
    active_ids = [row["decision_id"] for row in age_store.get_all_decisions("trading")]
    archived_ids = [row["decision_id"] for row in age_store.get_archived_decisions("trading")]

    assert active_ids == ["TRADING-0001"]
    assert archived_ids == ["TRADING-0000"]


def test_archive_batches_more_than_100_candidates(age_store: Any) -> None:
    _write_decisions(age_store, 125)

    assert age_store.archive_old_decisions("trading", keep_recent=20) == 105
    assert len(age_store.get_archived_decisions("trading")) == 105


def test_archive_retry_is_idempotent(age_store: Any) -> None:
    _write_decisions(age_store, 10)

    assert age_store.archive_old_decisions("trading", keep_recent=0) == 10
    assert age_store.archive_old_decisions("trading", keep_recent=0) == 0


def test_active_reads_and_d2_counts_exclude_archived_decisions(age_store: Any) -> None:
    ids = _write_decisions(age_store, 5)
    age_store.write_outcome(ids[-1], "buy", True, domain="trading")

    assert age_store.archive_old_decisions("trading", keep_recent=3) == 2
    assert len(age_store.get_all_decisions("trading")) == 3
    assert len(age_store.get_decisions("trading")) == 3
    assert age_store.count_verified("trading") == 1


def test_archive_reader_merges_outcomes_and_sorts_by_decision_time(age_store: Any) -> None:
    ids = _write_decisions(age_store, 3)
    age_store.write_outcome(ids[0], "buy", True, domain="trading")
    age_store.archive_old_decisions("trading", keep_recent=0)

    archived = age_store.get_archived_decisions("trading")

    assert [record["decision_id"] for record in archived] == ids
    assert archived[0]["actual_action"] == "buy"
    assert archived[0]["is_correct"] is True


def test_archive_is_domain_scoped(age_store: Any) -> None:
    _write_decisions(age_store, 5, "trading")
    _write_decisions(age_store, 5, "soc")

    assert age_store.archive_old_decisions("trading", keep_recent=3) == 2
    assert len(age_store.get_archived_decisions("trading")) == 2
    assert len(age_store.get_archived_decisions("soc")) == 0
    assert len(age_store.get_all_decisions("soc")) == 5


def test_archive_preserves_outcome_nodes_and_edges(age_store: Any) -> None:
    ids = _write_decisions(age_store, 2)
    age_store.write_outcome(ids[0], "buy", True, domain="trading")

    assert age_store.archive_old_decisions("trading", keep_recent=1) == 1

    archived = age_store.get_archived_decisions("trading")
    assert archived[0]["decision_id"] == ids[0]
    assert archived[0]["actual_action"] == "buy"
    assert archived[0]["is_correct"] is True
