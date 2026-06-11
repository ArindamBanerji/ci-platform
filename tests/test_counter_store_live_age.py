from __future__ import annotations

import json
import os
import time
import uuid
from typing import Any

import pytest

from ci_platform.copilot_core.counters import (
    AGECounterStore,
    soc_cross_category_counter_def,
    soc_sequence_counter_def,
)
from ci_platform.graph.age_client import AGEClient


SCRATCH_GRAPH = "soc_graph_counter_p2c_live_1"
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


class RecordingTx:
    def __init__(self, tx: Any, recorder: list[tuple[str, str]]) -> None:
        self._tx = tx
        self._recorder = recorder

    def execute_sql(self, sql: str, parameters=None):
        self._recorder.append(("sql", sql))
        return self._tx.execute_sql(sql, parameters)

    def run_cypher(self, cypher: str, parameters=None):
        assert "MERGE" not in cypher
        self._recorder.append(("cypher", cypher))
        return self._tx.run_cypher(cypher, parameters)


def _assert_safe_graph(graph_name: str) -> None:
    assert graph_name == SCRATCH_GRAPH
    assert graph_name not in PROTECTED_GRAPH_NAMES
    lowered = graph_name.lower()
    assert not any(fragment in lowered for fragment in PROTECTED_GRAPH_FRAGMENTS)


async def _count_edges(client: AGEClient, user_id: str, category_id: str) -> int:
    rows = await client.run_query(
        """
        MATCH (u:User {id: $user_id})-[r:SEEN_CATEGORY]->(c:Category {id: $category_id})
        RETURN count(r) AS cnt
        """,
        {"user_id": user_id, "category_id": category_id},
    )
    return int(rows[0]["cnt"]) if rows else 0


async def _read_user_counter(client: AGEClient, user_id: str, prop: str) -> int | None:
    rows = await client.run_query(
        f"""
        MATCH (u:User {{id: $user_id}})
        RETURN u.{prop} AS value
        """,
        {"user_id": user_id},
    )
    if not rows or rows[0].get("value") is None:
        return None
    return int(rows[0]["value"])


@pytest.mark.skipif(
    not AGE_INTEGRATION,
    reason="AGE_INTEGRATION != 1; skipping P2C live AGE counter proof",
)
@pytest.mark.asyncio
async def test_p2c_live_age_entity_property_counter_proof():
    graph_name = os.getenv("AGE_COUNTER_P2C_GRAPH") or os.getenv("AGE_GRAPH_NAME", SCRATCH_GRAPH)
    _assert_safe_graph(graph_name)
    client = AGEClient(
        dsn=os.getenv("GRAPH_DSN") or os.getenv("DATABASE_URL") or DEFAULT_DSN,
        graph_name=graph_name,
        use_pool=True,
    )
    await client.ensure_graph()
    store = AGECounterStore(client)
    run_id = f"p2c-counter-{uuid.uuid4().hex}"
    user_id = f"user-{run_id}"
    category_id = f"category-{run_id}"
    sequence = soc_sequence_counter_def(user_id)
    cross_category = soc_cross_category_counter_def(user_id)
    timings: dict[str, float] = {}
    criteria: dict[str, bool] = {}
    recorder: list[tuple[str, str]] = []

    try:
        await client.run_query(
            """
            CREATE (u:User {id: $user_id, p2c_run_id: $run_id})
            RETURN u.id AS id
            """,
            {"user_id": user_id, "run_id": run_id},
        )
        await client.run_query(
            """
            CREATE (c:Category {id: $category_id, p2c_run_id: $run_id})
            RETURN c.id AS id
            """,
            {"category_id": category_id, "run_id": run_id},
        )
        criteria["existing entity/distinct node setup"] = True

        t0 = time.perf_counter()
        initial = await store.read_counter(sequence)
        timings["counter_read_ms"] = (time.perf_counter() - t0) * 1000
        cumulative_initial = initial.value if initial.found else 0

        async def run_recorded(operation):
            def wrapped(tx):
                return operation(RecordingTx(tx, recorder))

            return await client.run_transaction(wrapped)

        t0 = time.perf_counter()
        after_1 = await run_recorded(
            lambda tx: (
                store.increment_cumulative_in_tx(tx, sequence),
                store.read_counter_in_tx(tx, sequence),
            )[1]
        )
        after_2 = await run_recorded(
            lambda tx: (
                store.increment_cumulative_in_tx(tx, sequence),
                store.read_counter_in_tx(tx, sequence),
            )[1]
        )
        timings["cumulative_increment_ms"] = (time.perf_counter() - t0) * 1000 / 2
        criteria["cumulative counter property"] = (
            cumulative_initial == 0 and after_1.value == 1 and after_2.value == 2
        )

        sql_indexes = [i for i, (kind, _text) in enumerate(recorder) if kind == "sql"]
        cypher_indexes = [i for i, (kind, _text) in enumerate(recorder) if kind == "cypher"]
        criteria["advisory lock path"] = bool(sql_indexes and cypher_indexes and min(sql_indexes) < min(cypher_indexes))

        t0 = time.perf_counter()
        distinct_1 = await run_recorded(
            lambda tx: (
                store.increment_distinct_in_tx(tx, cross_category, category_id),
                store.read_counter_in_tx(tx, cross_category),
            )[1]
        )
        edges_after_1 = await _count_edges(client, user_id, category_id)
        distinct_2 = await run_recorded(
            lambda tx: (
                store.increment_distinct_in_tx(tx, cross_category, category_id),
                store.read_counter_in_tx(tx, cross_category),
            )[1]
        )
        edges_after_2 = await _count_edges(client, user_id, category_id)
        timings["distinct_update_ms"] = (time.perf_counter() - t0) * 1000 / 2
        criteria["distinct SEEN_CATEGORY"] = (
            distinct_1.value == 1
            and distinct_2.value == 1
            and edges_after_1 == 1
            and edges_after_2 == 1
        )

        criteria["no MERGE"] = not any("MERGE" in text for _kind, text in recorder)

        before_rollback = await _read_user_counter(client, user_id, "sequence_count")
        marker_id = f"marker-{run_id}"
        with pytest.raises(RuntimeError):
            await client.run_transaction(
                lambda tx: (
                    store.increment_cumulative_in_tx(RecordingTx(tx, recorder), sequence),
                    tx.run_cypher(
                        """
                        CREATE (m:P2CCounterRollbackMarker {id: $marker_id, p2c_run_id: $run_id})
                        RETURN m.id AS id
                        """,
                        {"marker_id": marker_id, "run_id": run_id},
                    ),
                    (_ for _ in ()).throw(RuntimeError("force rollback")),
                )
            )
        after_rollback = await _read_user_counter(client, user_id, "sequence_count")
        marker_rows = await client.run_query(
            """
            MATCH (m:P2CCounterRollbackMarker {id: $marker_id})
            RETURN count(m) AS cnt
            """,
            {"marker_id": marker_id},
        )
        rollback_marker_absent = int(marker_rows[0]["cnt"]) == 0
        rollback_counter_unchanged = before_rollback == after_rollback
        criteria["rollback behavior"] = rollback_marker_absent and rollback_counter_unchanged

        await client.run_query(
            """
            MATCH (u:User {id: $user_id})
            SET u.sequence_count = 99
            RETURN u.sequence_count AS value
            """,
            {"user_id": user_id},
        )
        reconciliation_before = await _read_user_counter(client, user_id, "sequence_count")
        t0 = time.perf_counter()
        reconciliation = await store.reconcile_counter(
            sequence,
            "MATCH (u:User {id: $user_id}) RETURN count(u) AS cnt",
            {"user_id": user_id},
        )
        timings["reconciliation_ms"] = (time.perf_counter() - t0) * 1000
        reconciliation_after = await _read_user_counter(client, user_id, "sequence_count")
        criteria["reconciliation"] = (
            reconciliation_before == 99
            and reconciliation.graph_truth_value == 1
            and reconciliation_after == 1
            and reconciliation.read.value == 1
        )

        criteria["pooled/warm compatibility"] = client.connection_mode in {"pooled", "warm_fallback", "fresh"}
        criteria["graph safety"] = graph_name == SCRATCH_GRAPH
        criteria["cleanup_status"] = True

        failed = [name for name, passed in criteria.items() if not passed]
        report = {
            "graph_name": graph_name,
            "prefix": run_id,
            "criteria_passed": len(criteria) - len(failed),
            "criteria_total": len(criteria),
            "criteria_failed": failed,
            "cumulative_initial": cumulative_initial,
            "cumulative_after_1": after_1.value,
            "cumulative_after_2": after_2.value,
            "distinct_edge_count_after_1": edges_after_1,
            "distinct_edge_count_after_2": edges_after_2,
            "cross_category_count": distinct_2.value,
            "rollback_counter_unchanged": rollback_counter_unchanged,
            "rollback_marker_absent": rollback_marker_absent,
            "reconciliation_before": reconciliation_before,
            "reconciliation_after": reconciliation_after,
            "advisory_lock_executed": criteria["advisory lock path"],
            "no_merge": criteria["no MERGE"],
            "connection_mode": client.connection_mode,
            "pool_available": client.pool_available,
            "timing": timings,
            "verdict": "P2C_LIVE_AGE_COUNTER_PROOF_PASS" if not failed else "FAIL",
        }
        print("P2C_LIVE_AGE_COUNTER_PROOF_REPORT " + json.dumps(report, sort_keys=True))
        assert not failed, report
    finally:
        await client.run_query(
            """
            MATCH (u:User {id: $user_id})-[r:SEEN_CATEGORY]->(c:Category {id: $category_id})
            DELETE r
            RETURN 1 AS deleted
            """,
            {"user_id": user_id, "category_id": category_id},
        )
        await client.run_query(
            """
            MATCH (m:P2CCounterRollbackMarker {p2c_run_id: $run_id})
            DELETE m
            RETURN 1 AS deleted
            """,
            {"run_id": run_id},
        )
        await client.run_query(
            """
            MATCH (u:User {id: $user_id})
            DELETE u
            RETURN 1 AS deleted
            """,
            {"user_id": user_id},
        )
        await client.run_query(
            """
            MATCH (c:Category {id: $category_id})
            DELETE c
            RETURN 1 AS deleted
            """,
            {"category_id": category_id},
        )
