"""Legacy checkpoint count persistence using disposable AGE graphs."""

from collections.abc import Iterator
from typing import Any
import uuid

import pytest

from ci_platform.graph.age_graph_store import AGEGraphStore


@pytest.fixture
def checkpoint_store(age_test_graph: tuple[str, str]) -> Iterator[tuple[AGEGraphStore, str]]:
    dsn, graph = age_test_graph
    store = AGEGraphStore(dsn=dsn, graph_name=graph)
    domain = f"checkpoint_count_{uuid.uuid4().hex}"
    try:
        yield store, domain
    finally:
        store.close()


def _decision_for_path(store: AGEGraphStore, domain: str, path: str) -> str:
    if path == "linked":
        return store.write_decision(domain, "category", "review", 0.8, {})
    return "missing-decision" if path == "missing_link" else ""


@pytest.mark.age
@pytest.mark.parametrize("path", ["standalone", "linked", "missing_link"])
@pytest.mark.parametrize("count", [42, 0])
def test_save_centroids_persists_decisions_count(
    checkpoint_store: tuple[AGEGraphStore, str], path: str, count: int,
) -> None:
    store, domain = checkpoint_store
    decision_id = _decision_for_path(store, domain, path)
    store.save_centroids(
        domain, "category", [[0.2, 0.8]], {"source": "count-test"},
        decision_id=decision_id, decisions_count=count,
    )

    checkpoints = store.get_centroid_checkpoints(domain)
    assert len(checkpoints) == 1
    checkpoint = checkpoints[0]
    assert checkpoint["decisions_count"] == count
    assert type(checkpoint["decisions_count"]) is int
    assert checkpoint["decision_id"] == decision_id
    assert checkpoint["centroids"] == [[0.2, 0.8]]
    assert checkpoint["metadata"] == {"source": "count-test"}
    if path == "linked":
        rows = store._run_query(
            "MATCH (d:Decision)-[:HAS_CENTROID_CHECKPOINT]->(c:CentroidCheckpoint) "
            f"WHERE d.domain = {store._S(domain)} AND c.domain = {store._S(domain)} "
            "RETURN c"
        )
        assert len(rows) == 1
        assert store._node_to_dict(rows[0]["c"])["decisions_count"] == count


@pytest.mark.age
@pytest.mark.parametrize("path", ["standalone", "linked", "missing_link"])
@pytest.mark.parametrize("explicit_none", [False, True])
def test_save_centroids_without_count_preserves_checkpoint(
    checkpoint_store: tuple[AGEGraphStore, str], path: str, explicit_none: bool,
) -> None:
    store, domain = checkpoint_store
    decision_id = _decision_for_path(store, domain, path)
    kwargs: dict[str, Any] = {"decision_id": decision_id}
    if explicit_none:
        kwargs["decisions_count"] = None
    store.save_centroids(domain, "category", [[0.5]], {"source": "old-caller"}, **kwargs)

    checkpoints = store.get_centroid_checkpoints(domain)
    assert len(checkpoints) == 1
    checkpoint = checkpoints[0]
    assert checkpoint["domain"] == domain
    assert checkpoint["category"] == "category"
    assert checkpoint["decision_id"] == decision_id
    assert checkpoint["centroids"] == [[0.5]]
    assert checkpoint["metadata"] == {"source": "old-caller"}
    assert checkpoint.get("decisions_count") is None
    assert "decisions_count" not in checkpoint


@pytest.mark.age
def test_historical_checkpoint_count_remains_absent(
    checkpoint_store: tuple[AGEGraphStore, str],
) -> None:
    store, domain = checkpoint_store
    store._run_query(
        "CREATE (c:CentroidCheckpoint {"
        f"domain: {store._S(domain)}, category: 'historical', "
        "centroids: '[[0.1]]', metadata: '{}', created_at: 1.0}) RETURN c"
    )
    before = store.get_centroid_checkpoints(domain)[0]
    store.save_centroids(domain, "new", [[0.9]], decisions_count=42)
    checkpoints = store.get_centroid_checkpoints(domain)
    assert len(checkpoints) == 2
    historical = next(row for row in checkpoints if row["category"] == "historical")
    assert historical == before
    assert historical.get("decisions_count") is None
    assert int(historical.get("verified_count") or historical.get("decisions_count") or 0) == 0
    assert next(row for row in checkpoints if row["category"] == "new")["decisions_count"] == 42


@pytest.mark.parametrize("path", ["standalone", "linked", "missing_link"])
def test_omitted_count_keeps_original_cypher(
    monkeypatch: pytest.MonkeyPatch, path: str,
) -> None:
    """Capture real serialized queries without opening a database connection."""
    store = AGEGraphStore(dsn="postgresql://example/test", graph_name="test_graph")
    queries: list[str] = []

    def capture(query: str) -> list[dict[str, Any]]:
        queries.append(query)
        return [{"c": {}}] if path == "linked" else []

    monkeypatch.setattr(store, "_run_query", capture)
    monkeypatch.setattr("ci_platform.graph.age_graph_store.time.time", lambda: 123.0)
    decision_id = "DEC-1" if path != "standalone" else ""
    props = (
        "{"
        f"decision_id: '{decision_id}', domain: 'test', category: 'category', "
        "centroids: '[[0.5]]', metadata: '{}', created_at: 123.0}"
    )
    standalone = f"CREATE (c:CentroidCheckpoint {props}) RETURN c"
    linked = f"""
            MATCH (d:Decision {{decision_id: 'DEC-1'}})
            WHERE d.domain = 'test'
            WITH d LIMIT 1
            CREATE (c:CentroidCheckpoint {props})
            CREATE (d)-[:HAS_CENTROID_CHECKPOINT]->(c)
            RETURN c
            """
    expected = ([standalone] if path == "standalone" else
                [linked] if path == "linked" else [linked, standalone])
    count_options: list[dict[str, Any]] = [{}, {"decisions_count": None}]
    for kwargs in count_options:
        queries.clear()
        store.save_centroids("test", "category", [[0.5]], decision_id=decision_id, **kwargs)
        assert queries == expected
