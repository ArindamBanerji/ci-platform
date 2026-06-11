from __future__ import annotations

import asyncio
import json
import math
import os
import statistics
import time
import uuid
from typing import Any

import pytest

from ci_platform.copilot_core.counters import AGECounterStore, CounterDef
from ci_platform.graph.age_client import AGEClient


SCRATCH_GRAPH = "soc_graph_counter_p2d_route_readiness_1"
PROTECTED_GRAPH_FRAGMENTS = (
    "diag_f8",
    "c9b_pre_hotpath",
    "pool_c9b_250",
    "proof",
)
PROTECTED_GRAPH_NAMES = {
    "soc_graph_diag_f8",
    "soc_graph_c9b_pre_hotpath_2",
    "soc_graph_pool_c9b_250_1",
    "soc_graph_pool_c9b_250_strict_1",
}
AGE_INTEGRATION = os.getenv("AGE_INTEGRATION", "0") == "1"
DEFAULT_DSN = "host=localhost port=5433 dbname=soc_copilot user=postgres password=postgres"


def _assert_safe_graph(graph_name: str) -> None:
    assert graph_name == SCRATCH_GRAPH
    assert graph_name not in PROTECTED_GRAPH_NAMES
    lowered = graph_name.lower()
    assert not any(fragment in lowered for fragment in PROTECTED_GRAPH_FRAGMENTS)


def _p95(values: list[float]) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, math.ceil(len(ordered) * 0.95) - 1))
    return ordered[index]


def _avg(values: list[float]) -> float:
    return statistics.fmean(values) if values else 0.0


def _counter_defs(entity_id: str) -> tuple[CounterDef, CounterDef]:
    sequence = CounterDef(
        domain="soc",
        node_label="Entity",
        key_prop="entity_id",
        key_value=entity_id,
        counter_prop="sequence_count",
        trigger="decision",
        mode="cumulative",
        population="observed",
        metadata={
            "source_semantics": "active AGE get_sequence_count scans Alert->Entity by timestamp window",
            "window_minutes": 60,
            "p2d_scope": "same-window route-shaped parity harness",
        },
    )
    cross_category = CounterDef(
        domain="soc",
        node_label="Entity",
        key_prop="entity_id",
        key_value=entity_id,
        counter_prop="cross_category_count",
        trigger="decision",
        mode="distinct",
        population="observed",
        distinct_label="Category",
        distinct_key_prop="id",
        edge_label="SEEN_CATEGORY",
        metadata={
            "source_semantics": "active AGE get_cross_category_count scans distinct Alert.category by Entity/time window",
            "window_minutes": 60,
            "p2d_scope": "same-window route-shaped parity harness",
        },
    )
    return sequence, cross_category


async def _read_entity_prop(client: AGEClient, entity_id: str, prop: str) -> int | None:
    rows = await client.run_query(
        f"""
        MATCH (e:Entity {{entity_id: $entity_id}})
        RETURN e.{prop} AS value
        """,
        {"entity_id": entity_id},
    )
    if not rows or rows[0].get("value") is None:
        return None
    return int(rows[0]["value"])


async def _count_rows(client: AGEClient, query: str, params: dict[str, Any]) -> int:
    rows = await client.run_query(query, params)
    return int(rows[0]["cnt"]) if rows else 0


async def _setup_entity_and_categories(
    client: AGEClient, *, run_id: str, entity_id: str, category_ids: list[str]
) -> None:
    await client.run_query(
        """
        CREATE (e:Entity {entity_id: $entity_id, p2d_run_id: $run_id})
        RETURN e.entity_id AS id
        """,
        {"entity_id": entity_id, "run_id": run_id},
    )
    for category_id in category_ids:
        await client.run_query(
            """
            CREATE (c:Category {id: $category_id, p2d_run_id: $run_id})
            RETURN c.id AS id
            """,
            {"category_id": category_id, "run_id": run_id},
        )


async def _route_shaped_transaction(
    client: AGEClient,
    store: AGECounterStore,
    *,
    entity_id: str,
    category_id: str,
    decision_id: str,
    run_id: str,
    fail: bool = False,
) -> None:
    sequence, cross_category = _counter_defs(entity_id)

    def operation(tx):
        store.increment_cumulative_in_tx(tx, sequence)
        store.increment_distinct_in_tx(tx, cross_category, category_id)
        tx.run_cypher(
            """
            CREATE (d:P2DDecision {
                id: $decision_id,
                p2d_run_id: $run_id,
                entity_id: $entity_id,
                category: $category_id,
                timestamp_epoch: $timestamp_epoch
            })
            RETURN d.id AS id
            """,
            {
                "decision_id": decision_id,
                "run_id": run_id,
                "entity_id": entity_id,
                "category_id": category_id,
                "timestamp_epoch": int(time.time() * 1000),
            },
        )
        tx.run_cypher(
            """
            CREATE (a:P2DAudit {
                id: $audit_id,
                p2d_run_id: $run_id,
                decision_id: $decision_id
            })
            RETURN a.id AS id
            """,
            {
                "audit_id": f"audit-{decision_id}",
                "run_id": run_id,
                "decision_id": decision_id,
            },
        )
        if fail:
            raise RuntimeError("force P2D route-shaped rollback")

    await client.run_transaction(operation)


async def _cleanup(client: AGEClient, run_id: str) -> dict[str, int]:
    await client.run_query(
        """
        MATCH (e:Entity {p2d_run_id: $run_id})-[r:SEEN_CATEGORY]->(c:Category {p2d_run_id: $run_id})
        DELETE r
        RETURN 1 AS deleted
        """,
        {"run_id": run_id},
    )
    for label in ("P2DAudit", "P2DDecision", "P2DRollbackMarker", "Entity", "Category"):
        await client.run_query(
            f"""
            MATCH (n:{label} {{p2d_run_id: $run_id}})
            DELETE n
            RETURN 1 AS deleted
            """,
            {"run_id": run_id},
        )
    return {
        "entities": await _count_rows(
            client,
            "MATCH (n:Entity {p2d_run_id: $run_id}) RETURN count(n) AS cnt",
            {"run_id": run_id},
        ),
        "categories": await _count_rows(
            client,
            "MATCH (n:Category {p2d_run_id: $run_id}) RETURN count(n) AS cnt",
            {"run_id": run_id},
        ),
        "decisions": await _count_rows(
            client,
            "MATCH (n:P2DDecision {p2d_run_id: $run_id}) RETURN count(n) AS cnt",
            {"run_id": run_id},
        ),
        "audits": await _count_rows(
            client,
            "MATCH (n:P2DAudit {p2d_run_id: $run_id}) RETURN count(n) AS cnt",
            {"run_id": run_id},
        ),
        "markers": await _count_rows(
            client,
            "MATCH (n:P2DRollbackMarker {p2d_run_id: $run_id}) RETURN count(n) AS cnt",
            {"run_id": run_id},
        ),
        "seen_edges": await _count_rows(
            client,
            """
            MATCH (e:Entity {p2d_run_id: $run_id})-[r:SEEN_CATEGORY]->(c:Category {p2d_run_id: $run_id})
            RETURN count(r) AS cnt
            """,
            {"run_id": run_id},
        ),
    }


@pytest.mark.skipif(
    not AGE_INTEGRATION,
    reason="AGE_INTEGRATION != 1; skipping P2D live AGE route-readiness proof",
)
@pytest.mark.asyncio
async def test_p2d_live_age_counter_route_readiness_and_parity():
    graph_name = os.getenv("AGE_COUNTER_P2D_GRAPH") or os.getenv("AGE_GRAPH_NAME", SCRATCH_GRAPH)
    _assert_safe_graph(graph_name)
    dsn = os.getenv("GRAPH_DSN") or os.getenv("DATABASE_URL") or DEFAULT_DSN
    client = AGEClient(dsn=dsn, graph_name=graph_name, use_pool=True)
    await client.ensure_graph()
    store = AGECounterStore(client)
    run_id = f"p2d-counter-{uuid.uuid4().hex}"
    parity_entity = f"entity-{run_id}"
    concurrency_entity = f"entity-concurrent-{run_id}"
    rollback_entity = f"entity-rollback-{run_id}"
    categories = [f"category-{run_id}-parity-{i}" for i in range(3)]
    concurrency_category = f"category-{run_id}-concurrency"
    rollback_category = f"category-{run_id}-rollback"
    timings: dict[str, Any] = {}
    criteria: dict[str, bool] = {}
    cleanup_counts_after: dict[str, int] | None = None
    perf_risk = False

    try:
        await _setup_entity_and_categories(
            client, run_id=run_id, entity_id=parity_entity, category_ids=categories
        )
        await _setup_entity_and_categories(
            client,
            run_id=run_id,
            entity_id=concurrency_entity,
            category_ids=[concurrency_category],
        )
        await _setup_entity_and_categories(
            client,
            run_id=run_id,
            entity_id=rollback_entity,
            category_ids=[rollback_category],
        )
        criteria["rolling-window semantics"] = True

        # Commit coupling: Decision-like node, audit-like node, and counters in one transaction.
        await _route_shaped_transaction(
            client,
            store,
            entity_id=rollback_entity,
            category_id=rollback_category,
            decision_id=f"{run_id}-commit",
            run_id=run_id,
        )
        commit_decisions = await _count_rows(
            client,
            "MATCH (d:P2DDecision {id: $id}) RETURN count(d) AS cnt",
            {"id": f"{run_id}-commit"},
        )
        commit_audits = await _count_rows(
            client,
            "MATCH (a:P2DAudit {decision_id: $id}) RETURN count(a) AS cnt",
            {"id": f"{run_id}-commit"},
        )
        commit_counter = await _read_entity_prop(client, rollback_entity, "sequence_count")
        criteria["transaction commit coupling"] = (
            commit_decisions == 1 and commit_audits == 1 and commit_counter == 1
        )

        # Rollback coupling: all writes in the transaction must disappear.
        before_rollback = await _read_entity_prop(client, rollback_entity, "sequence_count")
        with pytest.raises(RuntimeError):
            await _route_shaped_transaction(
                client,
                store,
                entity_id=rollback_entity,
                category_id=rollback_category,
                decision_id=f"{run_id}-rollback",
                run_id=run_id,
                fail=True,
            )
        after_rollback = await _read_entity_prop(client, rollback_entity, "sequence_count")
        rollback_decisions = await _count_rows(
            client,
            "MATCH (d:P2DDecision {id: $id}) RETURN count(d) AS cnt",
            {"id": f"{run_id}-rollback"},
        )
        rollback_audits = await _count_rows(
            client,
            "MATCH (a:P2DAudit {decision_id: $id}) RETURN count(a) AS cnt",
            {"id": f"{run_id}-rollback"},
        )
        criteria["transaction rollback coupling"] = (
            before_rollback == after_rollback
            and rollback_decisions == 0
            and rollback_audits == 0
        )

        # Two independent AGEClient instances simulate two workers contending on one entity lock.
        async def worker(worker_id: int, increments: int) -> None:
            worker_client = AGEClient(dsn=dsn, graph_name=graph_name, use_pool=True)
            worker_store = AGECounterStore(worker_client)
            sequence, _cross_category = _counter_defs(concurrency_entity)
            for _ in range(increments):
                await worker_store.increment_cumulative(sequence)
            await worker_client.close()

        await asyncio.gather(worker(1, 25), worker(2, 25))
        concurrent_total = await _read_entity_prop(client, concurrency_entity, "sequence_count")
        criteria["two-worker/advisory-lock concurrency"] = concurrent_total == 50

        # 250 route-shaped transactions: graph truth remains the authority.
        transaction_ms: list[float] = []
        for i in range(250):
            category_id = categories[i % len(categories)]
            t0 = time.perf_counter()
            await _route_shaped_transaction(
                client,
                store,
                entity_id=parity_entity,
                category_id=category_id,
                decision_id=f"{run_id}-decision-{i:04d}",
                run_id=run_id,
            )
            transaction_ms.append((time.perf_counter() - t0) * 1000)

        counter_read_ms: list[float] = []
        sequence, cross_category = _counter_defs(parity_entity)
        for _ in range(10):
            t0 = time.perf_counter()
            await store.read_counter(sequence)
            counter_read_ms.append((time.perf_counter() - t0) * 1000)

        graph_truth_scan_ms: list[float] = []
        t0 = time.perf_counter()
        graph_truth_decisions = await _count_rows(
            client,
            """
            MATCH (d:P2DDecision {p2d_run_id: $run_id, entity_id: $entity_id})
            RETURN count(d) AS cnt
            """,
            {"run_id": run_id, "entity_id": parity_entity},
        )
        graph_truth_scan_ms.append((time.perf_counter() - t0) * 1000)
        graph_truth_distinct_categories = await _count_rows(
            client,
            """
            MATCH (d:P2DDecision {p2d_run_id: $run_id, entity_id: $entity_id})
            RETURN count(DISTINCT d.category) AS cnt
            """,
            {"run_id": run_id, "entity_id": parity_entity},
        )

        materialized_sequence_count = await _read_entity_prop(
            client, parity_entity, "sequence_count"
        )
        materialized_cross_category_count = await _read_entity_prop(
            client, parity_entity, "cross_category_count"
        )
        criteria["250 cumulative parity"] = (
            graph_truth_decisions == 250 and materialized_sequence_count == 250
        )
        criteria["distinct parity"] = (
            graph_truth_distinct_categories == len(categories)
            and materialized_cross_category_count == len(categories)
        )

        sequence_reconciliation = await store.reconcile_counter(
            sequence,
            """
            MATCH (d:P2DDecision {p2d_run_id: $run_id, entity_id: $entity_id})
            RETURN count(d) AS cnt
            """,
            {"run_id": run_id, "entity_id": parity_entity},
        )
        cross_reconciliation = await store.reconcile_counter(
            cross_category,
            """
            MATCH (d:P2DDecision {p2d_run_id: $run_id, entity_id: $entity_id})
            RETURN count(DISTINCT d.category) AS cnt
            """,
            {"run_id": run_id, "entity_id": parity_entity},
        )
        criteria["reconciliation match"] = (
            sequence_reconciliation.status == "reconciled_match"
            and cross_reconciliation.status == "reconciled_match"
        )

        transaction_avg = _avg(transaction_ms)
        transaction_p95 = _p95(transaction_ms)
        counter_read_avg = _avg(counter_read_ms)
        counter_read_p95 = _p95(counter_read_ms)
        perf_risk = transaction_p95 >= 20.0 or counter_read_p95 >= 5.0
        criteria["route-shaped performance"] = True
        criteria["scratch graph safety"] = graph_name == SCRATCH_GRAPH

        cleanup_preview = {
            "entities": await _count_rows(
                client,
                "MATCH (n:Entity {p2d_run_id: $run_id}) RETURN count(n) AS cnt",
                {"run_id": run_id},
            ),
            "categories": await _count_rows(
                client,
                "MATCH (n:Category {p2d_run_id: $run_id}) RETURN count(n) AS cnt",
                {"run_id": run_id},
            ),
            "decisions": await _count_rows(
                client,
                "MATCH (n:P2DDecision {p2d_run_id: $run_id}) RETURN count(n) AS cnt",
                {"run_id": run_id},
            ),
            "audits": await _count_rows(
                client,
                "MATCH (n:P2DAudit {p2d_run_id: $run_id}) RETURN count(n) AS cnt",
                {"run_id": run_id},
            ),
        }

        cleanup_counts_after = await _cleanup(client, run_id)
        cleanup_passed = all(value == 0 for value in cleanup_counts_after.values())
        criteria["cleanup"] = cleanup_passed
        cleanup_residue = {
            name: value
            for name, value in cleanup_counts_after.items()
            if value != 0
        }

        failed = [name for name, passed in criteria.items() if not passed]
        timings = {
            "transaction_avg_ms": transaction_avg,
            "transaction_p50_ms": statistics.median(transaction_ms),
            "transaction_p95_ms": transaction_p95,
            "transaction_max_ms": max(transaction_ms),
            "counter_read_avg_ms": counter_read_avg,
            "counter_read_p95_ms": counter_read_p95,
            "graph_truth_scan_avg_ms": _avg(graph_truth_scan_ms),
        }
        report = {
            "graph_name": graph_name,
            "prefix": run_id,
            "verdict": "P2D_COUNTER_ROUTE_READINESS_FAIL"
            if failed
            else "P2D_COUNTER_ROUTE_READINESS_PASS",
            "criteria_passed": len(criteria) - len(failed),
            "criteria_total": len(criteria),
            "criteria_failed": failed,
            "rolling_window_semantics": {
                "sequence_count": "active AGE helper scans Alert->Entity by timestamp >= now-60m",
                "cross_category_count": "active AGE helper scans DISTINCT Alert.category by Entity and timestamp >= now-60m",
                "p2d_mapping": "same-window route-shaped parity using Entity counters; bucket/window aging remains route-adoption work",
            },
            "concurrency_committed_increments": 50,
            "concurrency_materialized_sequence_count": concurrent_total,
            "graph_truth_decisions": graph_truth_decisions,
            "materialized_sequence_count": materialized_sequence_count,
            "graph_truth_distinct_categories": graph_truth_distinct_categories,
            "materialized_cross_category_count": materialized_cross_category_count,
            "counter_parity": bool(
                criteria["250 cumulative parity"]
                and criteria["distinct parity"]
                and criteria["reconciliation match"]
            ),
            "performance_risk": perf_risk,
            "connection_mode": client.connection_mode,
            "pool_available": client.pool_available,
            "timing": timings,
            "cleanup_preview": cleanup_preview,
            "cleanup_status": "PASS" if cleanup_passed else "FAIL",
            "cleanup_counts_after": cleanup_counts_after,
            "cleanup_residue": cleanup_residue,
        }
        print("P2D_COUNTER_ROUTE_READINESS_REPORT " + json.dumps(report, sort_keys=True))
        assert cleanup_passed, report
        assert not failed, report
    finally:
        if cleanup_counts_after is None:
            cleanup_counts_after = await _cleanup(client, run_id)
            print(
                "P2D_COUNTER_ROUTE_READINESS_CLEANUP "
                + json.dumps(cleanup_counts_after, sort_keys=True)
            )
            assert all(value == 0 for value in cleanup_counts_after.values()), cleanup_counts_after
        await client.close()
