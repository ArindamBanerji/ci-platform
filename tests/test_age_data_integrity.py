"""Database-free regressions for AGE retention identities and activation state."""

from __future__ import annotations

from typing import Any, cast

import pytest

from ci_platform.graph.age_client import AGEClient
from ci_platform.graph.age_graph_store import AGEGraphStore
from ci_platform.graph.bounded_projection_migration import (
    ActivationAbsentError,
    ActivationCorruptError,
    VERSION,
    ready,
)


@pytest.mark.parametrize("decision_id", ["null", "true", "false", "0", "1", "", "雪-決定"])
def test_identity_decoder_preserves_adversarial_string_ids(decision_id: str) -> None:
    client = AGEClient.__new__(AGEClient)

    assert client._normalize_value(decision_id, preserve_strings=True) == decision_id


class _RetentionTransaction:
    def __init__(self, ordered_ids: list[str]) -> None:
        self.ordered_ids = ordered_ids
        self.candidate_preserve_strings: bool | None = None
        self.archive_queries: list[str] = []

    def execute_sql(self, sql: str, parameters: tuple[Any, ...] | None = None) -> None:
        return None

    def run_cypher(
        self,
        cypher: str,
        parameters: dict[str, Any] | None = None,
        *,
        preserve_strings: bool = False,
    ) -> list[dict[str, Any]]:
        if "MATCH (s:BoundedDomain)" in cypher:
            return []
        if "RETURN count(d) AS cnt" in cypher and "SET d.archived" not in cypher:
            return [{"cnt": len(self.ordered_ids)}]
        if "RETURN d.decision_id AS decision_id" in cypher:
            self.candidate_preserve_strings = preserve_strings
            return [{"decision_id": value} for value in self.ordered_ids]
        if "SET d.archived = true" in cypher:
            self.archive_queries.append(cypher)
            return [{"cnt": len(self.ordered_ids) - 1}]
        raise AssertionError(f"unexpected retention query: {cypher}")


class _RetentionClient:
    def __init__(self, transaction: _RetentionTransaction) -> None:
        self.transaction = transaction
        self._graph = "test_graph"

    @staticmethod
    def _S(value: Any) -> str:
        return AGEClient.serialize_for_age(value)

    async def run_transaction(self, operation: Any) -> Any:
        return operation(self.transaction)


@pytest.mark.parametrize(
    "ordered_ids",
    [
        ["z", "null"],
        ["z", "null", "true", "false", "0", "1", "", "雪-決定"],
    ],
)
def test_retention_preserves_candidate_identities(ordered_ids: list[str]) -> None:
    transaction = _RetentionTransaction(ordered_ids)
    store = AGEGraphStore.__new__(AGEGraphStore)
    store._client = cast(Any, _RetentionClient(transaction))

    archived = store.archive_old_decisions("trading", keep_recent=1)

    assert archived == len(ordered_ids) - 1
    assert transaction.candidate_preserve_strings is True
    archive_query = "\n".join(transaction.archive_queries)
    for decision_id in ordered_ids[1:]:
        assert store._S(decision_id) in archive_query


class _ActivationStore:
    @staticmethod
    def _S(value: Any) -> str:
        return repr(value)

    @staticmethod
    def _node_to_dict(value: Any) -> dict[str, Any]:
        return dict(value)


class _ActivationTransaction:
    def __init__(
        self,
        *,
        anchors: list[dict[str, Any]],
        markers: list[dict[str, Any]],
    ) -> None:
        self.anchors = anchors
        self.markers = markers

    def run_cypher(self, cypher: str) -> list[dict[str, Any]]:
        return [{"s": anchor} for anchor in self.anchors]

    def run_bounded_cypher(self, cypher: str) -> list[dict[str, Any]]:
        return [{"a": marker} for marker in self.markers]


def test_duplicate_activation_markers_raise_corrupt_error() -> None:
    transaction = _ActivationTransaction(
        anchors=[{"domain": "s2p", "version": VERSION}],
        markers=[{"domain": "s2p"}, {"domain": "s2p"}],
    )

    with pytest.raises(ActivationCorruptError, match="duplicate bounded activation"):
        ready(cast(Any, _ActivationStore()), cast(Any, transaction), "s2p")


def test_missing_activation_marker_raises_absent_error() -> None:
    transaction = _ActivationTransaction(
        anchors=[{"domain": "s2p", "version": VERSION}],
        markers=[],
    )

    with pytest.raises(ActivationAbsentError, match="not activated"):
        ready(cast(Any, _ActivationStore()), cast(Any, transaction), "s2p")
