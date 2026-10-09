"""Behavioral D2 verified-decision tests for SOC AGE count readers."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from ci_platform.graph.age_graph_store import AGEGraphStore


pytestmark = pytest.mark.age


def _write(
    store: AGEGraphStore,
    decision_id: str,
    domain: str = "soc",
    *,
    category: str = "credential_access",
) -> str:
    decision = store.write_decision(
        domain,
        category,
        "investigate",
        0.8,
        {"signal": 1.0},
        metadata={"decision_id": decision_id},
    )
    assert isinstance(decision, str)
    return decision


def _seed_verified_fixture(store: Any) -> dict[str, str]:
    # Archive the genuinely oldest record, not the lexically first ID.
    ids = {
        "archived": _write(store, "SOC-ARCHIVED"),
        "confirmed": _write(store, "SOC-CONFIRMED"),
        "overridden": _write(store, "SOC-OVERRIDDEN"),
        "confirmed_outcome": _write(store, "SOC-CONFIRMED-OUTCOME"),
        "pending": _write(store, "SOC-PENDING"),
        "other": _write(store, "OTHER-CONFIRMED", "trading"),
    }
    store.write_outcome(ids["confirmed"], "investigate", True, domain="soc")
    store.write_outcome(ids["overridden"], "triage_elsewhere", False, domain="soc")
    store.write_outcome(ids["confirmed_outcome"], "investigate", True, domain="soc")
    store.write_outcome(ids["archived"], "investigate", True, domain="soc")
    store.write_outcome(ids["other"], "investigate", True, domain="trading")
    store.archive_old_decisions("soc", keep_recent=4)
    return ids


def test_confirmed_and_overridden_status_rows_are_counted(age_store: Any) -> None:
    _seed_verified_fixture(age_store)

    assert age_store.count_verified("soc") == 3


def test_count_verified_alias_matches_canonical_method(age_store: Any) -> None:
    _seed_verified_fixture(age_store)

    assert age_store.count_verified("soc") == age_store.count_verified_decisions("soc")


def test_pending_row_with_outcome_is_excluded(age_store: Any) -> None:
    ids = _seed_verified_fixture(age_store)

    verified_ids = {row["decision_id"] for row in age_store.get_verified_decisions("soc")}
    assert ids["pending"] not in verified_ids
    assert age_store.count_verified("soc") == 3


def test_other_domain_row_is_excluded(age_store: Any) -> None:
    _seed_verified_fixture(age_store)

    assert age_store.count_verified("soc") == 3
    assert age_store.count_verified("trading") == 1


def test_archived_confirmed_row_is_excluded_from_d2(age_store: Any) -> None:
    ids = _seed_verified_fixture(age_store)

    verified_ids = {row["decision_id"] for row in age_store.get_verified_decisions("soc")}
    assert ids["archived"] not in verified_ids
    assert age_store.count_verified_decisions("soc") == 3
    assert age_store.count_correct("soc") == 2


def test_get_verified_decisions_returns_d2_decision_fields(age_store: Any) -> None:
    _seed_verified_fixture(age_store)

    verified = age_store.get_verified_decisions("soc")

    assert {row["decision_id"] for row in verified} == {
        "SOC-CONFIRMED",
        "SOC-OVERRIDDEN",
        "SOC-CONFIRMED-OUTCOME",
    }
    confirmed = next(row for row in verified if row["decision_id"] == "SOC-CONFIRMED")
    assert confirmed["domain"] == "soc"
    assert confirmed["status"] == "confirmed"


def test_pending_to_outcome_transition_increments_v(age_store: Any) -> None:
    decision_id = _write(age_store, "SOC-PENDING")

    assert age_store.count_verified("soc") == 0
    age_store.write_outcome(decision_id, "investigate", True, domain="soc")
    assert age_store.count_verified("soc") == 1


def test_mixed_branch_parity_across_all_soc_count_readers(age_store: Any, age_dsn: str) -> None:
    from ci_platform.graph.age_client import AGEClient

    _seed_verified_fixture(age_store)
    graph_name = age_store._client._graph
    age_client = AGEClient(dsn=age_dsn, graph_name=graph_name)
    try:
        expected = age_store.count_verified("soc")
        assert expected == 3
        assert asyncio.run(age_client.count_verified_decisions()) == expected
        assert asyncio.run(age_client.count_correct_decisions()) == 2
    finally:
        asyncio.run(age_client.close())


def test_invalid_domain_fails_before_cypher(age_store: Any) -> None:
    with pytest.raises(ValueError, match="unsupported graph domain"):
        age_store.count_verified("soc' OR 1=1")


def test_protocol_v2_test_domain_is_accepted(age_store: Any) -> None:
    domain = "pytest_protocol_v2_test_age_write_outcome_confirmed_b6bc3333"

    assert age_store._validated_domain(domain) == domain


def test_get_decision_links_limit_is_global(monkeypatch: pytest.MonkeyPatch) -> None:
    from ci_platform.graph.age_graph_store import AGEGraphStore

    store = object.__new__(AGEGraphStore)
    monkeypatch.setattr(store, "_S", lambda value: f"'{value}'" if isinstance(value, str) else str(value))
    rows = [
        {"decision_id": f"D-{index}", "entity_id": f"E-{index}", "edge_type": "DECIDED_ON"}
        for index in range(8)
    ]
    calls = iter((rows, rows))
    monkeypatch.setattr(store, "_run_query", lambda query: next(calls))
    assert len(store.get_decision_links(limit=5, domain="soc")) <= 5


def test_in_memory_d2_lifecycle_contract() -> None:
    from copilot_sdk.graph import InMemoryGraphStore

    store = InMemoryGraphStore(domain="soc")
    try:
        confirmed_id = store.write_decision(
            "soc", "price_variance", "hold_for_review", 0.7, {"variance": 0.2}
        )
        store.write_outcome(confirmed_id, "hold_for_review", True, domain="soc")
        store.write_decision(
            "soc", "price_variance", "hold_for_review", 0.6, {"variance": 0.1}
        )

        assert store.count_verified("soc") == 1
        assert store.count_verified_decisions("soc") == 1
        assert store.count_correct("soc") == 1
        assert [row["decision_id"] for row in store.get_verified_decisions("soc")] == [
            confirmed_id
        ]
    finally:
        store.close()
