"""SDK GraphStore adapter for AGEGraphStore."""

from __future__ import annotations

from typing import Any

from ci_platform.graph.age_graph_store import AGEGraphStore


class AGEGraphStoreAdapter:
    """Transitional SDK GraphStore-compatible wrapper around AGEGraphStore."""

    def __init__(
        self,
        dsn: str | None = None,
        graph_name: str = "soc_graph",
        store: AGEGraphStore | None = None,
    ) -> None:
        if store is None:
            if dsn is None:
                raise ValueError("dsn is required when store is not provided")
            store = AGEGraphStore(dsn=dsn, graph_name=graph_name)
        self._store = store

    def write_decision(
        self,
        entity_id: str,
        category: str,
        action: str,
        confidence: float,
        factors: dict[str, Any],
        metadata: dict[str, Any] | None = None,
    ) -> str:
        return self._store.write_decision(
            entity_id=entity_id,
            category=category,
            action=action,
            confidence=confidence,
            factors=factors,
            metadata=metadata,
        )

    def write_outcome(
        self,
        decision_id: str,
        actual_action: str,
        is_correct: bool,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        self._store.write_outcome(
            decision_id=decision_id,
            actual_action=actual_action,
            is_correct=is_correct,
            metadata=metadata,
        )

    def get_decision(self, decision_id: str) -> dict[str, Any] | None:
        return self._store.get_decision(decision_id)

    def get_decisions(
        self,
        category: str | None = None,
        limit: int = 400,
    ) -> list[dict[str, Any]]:
        return self._store.get_decisions(category=category, limit=limit)

    def get_verified_decisions(self) -> list[dict[str, Any]]:
        return self._store.get_verified_decisions()

    def get_all_decisions(self) -> list[dict[str, Any]]:
        return self._store.get_all_decisions()

    def count_verified(self) -> int:
        return self._store.count_verified()

    def count_correct(self) -> int:
        return self._store.count_correct()

    def save_centroids(
        self,
        decision_id: str,
        category: str,
        centroids: Any,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        self._store.save_centroids(
            decision_id=decision_id,
            category=category,
            centroids=centroids,
            metadata=metadata,
        )

    def get_centroid_checkpoints(self, limit: int = 50) -> list[dict[str, Any]]:
        return self._store.get_centroid_checkpoints(limit=limit)

    def save_evolution_event(
        self,
        event_type: str,
        rule_name: str,
        variant_id: str,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        self._store.save_evolution_event(
            event_type=event_type,
            rule_name=rule_name,
            variant_id=variant_id,
            metadata=metadata,
        )

    def link_decision_to_entity(
        self,
        decision_id: str,
        entity_id: str,
        edge_type: str = "DECIDED_ON",
    ) -> None:
        self._store.link_decision_to_entity(
            decision_id=decision_id,
            entity_id=entity_id,
            edge_type=edge_type,
        )

    def get_decision_links(self, decision_id: str | None = None) -> list[dict[str, Any]]:
        return self._store.get_decision_links(decision_id=decision_id)

    def close(self) -> None:
        self._store.close()
