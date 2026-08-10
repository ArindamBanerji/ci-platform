from __future__ import annotations

import os
import uuid

import pytest
from copilot_sdk.testing import age_available

from ci_platform.graph.age_graph_store import AGEGraphStore


pytestmark = pytest.mark.skipif(not age_available(), reason="AGE not reachable")

DEFAULT_DSN = "host=localhost port=5433 dbname=soc_copilot user=postgres password=postgres"
GRAPH_NAME = "soc_graph_atomic_outcome_checkpoint"


def _store() -> AGEGraphStore:
    return AGEGraphStore(
        dsn=os.getenv("GRAPH_DSN") or os.getenv("DATABASE_URL") or DEFAULT_DSN,
        graph_name=GRAPH_NAME,
    )


def _outcome(decision_id: str) -> dict:
    return {
        "decision_id": decision_id,
        "actual_action": "allow",
        "is_correct": True,
        "domain": "soc",
        "outcome": "correct",
        "metadata": {"verified_at": 1.0},
    }


def _checkpoint(decision_id: str, checkpoint_id: str) -> dict:
    return {
        "checkpoint_id": checkpoint_id,
        "domain": "soc",
        "category": "credential_access",
        "action": "allow",
        "centroids": [[[0.1, 0.2]]],
        "decisions_count": 1,
        "verified_count": 1,
        "iks": 0.1,
        "shape": [1, 1, 2],
        "factor_names_hash": "atomic-test",
        "metadata": {"decision_id": decision_id},
        "decision_id": decision_id,
    }


def _create_decision(store: AGEGraphStore, decision_id: str) -> None:
    store.write_decision(
        domain="soc",
        category="credential_access",
        action="allow",
        confidence=0.9,
        factors={"risk": 0.1},
        metadata={"decision_id": decision_id},
    )


@pytest.mark.asyncio
async def test_soc_outcome_checkpoint_atomic_success():
    store = _store()
    await store._client.ensure_graph()
    decision_id = f"atomic-success-{uuid.uuid4().hex}"
    checkpoint_id = f"checkpoint-{decision_id}"
    _create_decision(store, decision_id)

    try:
        def operation(transaction) -> None:
            transaction.write_outcome(**_outcome(decision_id))
            transaction.write_centroid_checkpoint(**_checkpoint(decision_id, checkpoint_id))

        await store.run_transaction(operation)

        assert store.get_decision(decision_id, domain="soc")["status"] == "confirmed"
        assert store.get_centroid_checkpoints("soc", include_v2=True, limit=None)
        assert store.get_decision_checkpoints("soc", decision_id)
    finally:
        await store._client.run_query(
            f"MATCH (d:Decision {{decision_id: '{decision_id}'}}) DETACH DELETE d"
        )
        await store._client.run_query(
            f"MATCH (c:CentroidCheckpoint {{checkpoint_id: '{checkpoint_id}'}}) DETACH DELETE c"
        )


@pytest.mark.asyncio
async def test_soc_outcome_checkpoint_atomic_failure_rolls_back_both():
    store = _store()
    await store._client.ensure_graph()
    decision_id = f"atomic-failure-{uuid.uuid4().hex}"
    checkpoint_id = f"checkpoint-{decision_id}"
    _create_decision(store, decision_id)

    try:
        def operation(transaction) -> None:
            transaction.write_outcome(**_outcome(decision_id))
            transaction.write_centroid_checkpoint(**_checkpoint(decision_id, checkpoint_id))
            raise RuntimeError("forced checkpoint failure")

        with pytest.raises(RuntimeError, match="forced checkpoint failure"):
            await store.run_transaction(operation)

        assert store.get_decision(decision_id, domain="soc")["status"] == "pending"
        assert not store.get_decision_checkpoints("soc", decision_id)
    finally:
        await store._client.run_query(
            f"MATCH (d:Decision {{decision_id: '{decision_id}'}}) DETACH DELETE d"
        )
        await store._client.run_query(
            f"MATCH (c:CentroidCheckpoint {{checkpoint_id: '{checkpoint_id}'}}) DETACH DELETE c"
        )


@pytest.mark.asyncio
async def test_transaction_rollback_leaves_no_snapshot_edges():
    store = _store()
    await store._client.ensure_graph()
    decision_id = f"atomic-edge-rollback-{uuid.uuid4().hex}"
    checkpoint_id = f"checkpoint-{decision_id}"
    _create_decision(store, decision_id)

    try:
        def operation(transaction) -> None:
            transaction.write_outcome(**_outcome(decision_id))
            transaction.write_centroid_checkpoint(**_checkpoint(decision_id, checkpoint_id))
            assert transaction is not None
            raise RuntimeError("forced edge rollback")

        with pytest.raises(RuntimeError, match="forced edge rollback"):
            await store.run_transaction(operation)

        assert not store.get_decision_checkpoints("soc", decision_id)
        rows = await store._client.run_query(
            f"""
            MATCH (d:Decision {{decision_id: '{decision_id}'}})-[r:SNAPSHOT_AFTER]->(c:CentroidCheckpoint)
            RETURN count(r) AS cnt
            """
        )
        assert int(rows[0]["cnt"]) == 0
    finally:
        await store._client.run_query(
            f"MATCH (d:Decision {{decision_id: '{decision_id}'}}) DETACH DELETE d"
        )
        await store._client.run_query(
            f"MATCH (c:CentroidCheckpoint {{checkpoint_id: '{checkpoint_id}'}}) DETACH DELETE c"
        )
