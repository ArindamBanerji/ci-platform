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
        domain: str,
        category: str,
        action: str,
        confidence: float,
        factors: dict[str, Any],
        metadata: dict[str, Any] | None = None,
    ) -> str:
        return self._store.write_decision(
            domain=domain,
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
        domain: str,
        category: str | None = None,
        limit: int = 400,
    ) -> list[dict[str, Any]]:
        return self._store.get_decisions(domain=domain, category=category, limit=limit)

    def get_verified_decisions(self, domain: str) -> list[dict[str, Any]]:
        return self._store.get_verified_decisions(domain)

    def get_all_decisions(self, domain: str) -> list[dict[str, Any]]:
        return self._store.get_all_decisions(domain)

    def count_verified(self, domain: str) -> int:
        return self._store.count_verified(domain)

    def count_correct(self, domain: str) -> int:
        return self._store.count_correct(domain)

    def count_decisions(self, domain: str) -> int:
        return self._store.count_decisions(domain)

    def save_centroids(
        self,
        domain: str,
        category: str,
        centroids: Any,
        metadata: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> None:
        self._store.save_centroids(
            domain=domain,
            category=category,
            centroids=centroids,
            metadata=metadata,
            **kwargs,
        )

    def load_latest_centroids(self, domain: str) -> Any | None:
        return self._store.load_latest_centroids(domain)

    def get_centroid_checkpoints(self, domain: str, **kwargs: Any) -> list[dict[str, Any]]:
        return self._store.get_centroid_checkpoints(domain, **kwargs)

    def save_evolution_event(
        self,
        domain: str,
        event_type: str,
        rule_name: str = "",
        variant_id: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> None:
        self._store.save_evolution_event(
            domain=domain,
            event_type=event_type,
            rule_name=rule_name,
            variant_id=variant_id,
            metadata=metadata,
        )

    def get_evolution_events(self, domain: str, **kwargs: Any) -> list[dict[str, Any]]:
        return self._store.get_evolution_events(domain, **kwargs)

    def archive_old_decisions(self, domain: str, keep_recent: int = 800) -> int:
        return self._store.archive_old_decisions(domain, keep_recent=keep_recent)

    def count_archived(self, domain: str) -> int:
        return self._store.count_archived(domain)

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
