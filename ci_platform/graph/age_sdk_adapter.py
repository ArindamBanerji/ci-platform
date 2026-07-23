"""SDK GraphStore adapter for AGEGraphStore."""

from __future__ import annotations

import uuid
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

    def generate_decision_id(self, domain: str) -> str:
        """Generate a bare AGE decision ID; the primary owns prefix policy."""
        return uuid.uuid4().hex[:12]

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

    def write_governed_decision(
        self,
        decision_id: str,
        domain: str,
        category: str,
        category_index: int,
        recommended_action: str,
        recommended_index: int,
        confidence: float,
        probabilities: list[float],
        factor_vector: list[float],
        factor_names: list[str],
        source: str = "score",
        scorer_version: str = "",
        preset_version: str = "",
        factor_schema_version: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> None:
        self._store.write_governed_decision(
            decision_id=decision_id,
            domain=domain,
            category=category,
            category_index=category_index,
            recommended_action=recommended_action,
            recommended_index=recommended_index,
            confidence=confidence,
            probabilities=probabilities,
            factor_vector=factor_vector,
            factor_names=factor_names,
            source=source,
            scorer_version=scorer_version,
            preset_version=preset_version,
            factor_schema_version=factor_schema_version,
            metadata=metadata,
        )

    def write_outcome(
        self,
        decision_id: str,
        actual_action: str,
        is_correct: bool,
        metadata: dict[str, Any] | None = None,
        domain: str | None = None,
    ) -> None:
        kwargs: dict[str, Any] = {
            "decision_id": decision_id,
            "actual_action": actual_action,
            "is_correct": is_correct,
            "metadata": metadata,
        }
        if domain is not None:
            kwargs["domain"] = domain
        self._store.write_outcome(**kwargs)

    def write_observation(
        self,
        observation_id: str,
        domain: str,
        category: str,
        recommended_action: str,
        confidence: float,
        source_route: str,
        scorer_version: str,
        factor_schema_version: str,
        entity_id: str | None = None,
        factor_vector: list[float] | None = None,
        factor_names: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        self._store.write_observation(
            observation_id=observation_id,
            domain=domain,
            category=category,
            recommended_action=recommended_action,
            confidence=confidence,
            source_route=source_route,
            scorer_version=scorer_version,
            factor_schema_version=factor_schema_version,
            entity_id=entity_id,
            factor_vector=factor_vector,
            factor_names=factor_names,
            metadata=metadata,
        )

    def write_conservation_status(
        self,
        status_id: str,
        domain: str,
        V: int,
        q: float,
        alpha: float,
        theta_min: float,
        verified_count: int,
        correct_count: int,
        status: str,
        policy_version: str,
    ) -> None:
        self._store.write_conservation_status(
            status_id=status_id,
            domain=domain,
            V=V,
            q=q,
            alpha=alpha,
            theta_min=theta_min,
            verified_count=verified_count,
            correct_count=correct_count,
            status=status,
            policy_version=policy_version,
        )

    def append_evidence_receipt(
        self,
        receipt_intent_id: str,
        domain: str,
        decision_id: str,
        canonical_payload: dict[str, Any],
        actor: str,
        source_route: str,
        metadata: dict[str, Any] | None = None,
    ) -> tuple[int, str]:
        return self._store.append_evidence_receipt(
            receipt_intent_id=receipt_intent_id,
            domain=domain,
            decision_id=decision_id,
            canonical_payload=canonical_payload,
            actor=actor,
            source_route=source_route,
            metadata=metadata,
        )

    def write_fingerprint(
        self,
        fingerprint_id: str,
        domain: str,
        factor_names: list[str],
        factor_stats: dict[str, Any],
        skipped_incompatible: int,
        window: int,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        self._store.write_fingerprint(
            fingerprint_id=fingerprint_id,
            domain=domain,
            factor_names=factor_names,
            factor_stats=factor_stats,
            skipped_incompatible=skipped_incompatible,
            window=window,
            metadata=metadata,
        )

    def write_centroid_checkpoint(
        self,
        checkpoint_id: str,
        domain: str,
        category: str,
        action: str,
        centroids: Any,
        decisions_count: int,
        verified_count: int,
        iks: float,
        shape: list[int],
        factor_names_hash: str,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        self._store.write_centroid_checkpoint(
            checkpoint_id=checkpoint_id,
            domain=domain,
            category=category,
            action=action,
            centroids=centroids,
            decisions_count=decisions_count,
            verified_count=verified_count,
            iks=iks,
            shape=shape,
            factor_names_hash=factor_names_hash,
            metadata=metadata,
        )

    def write_evolution_event(
        self,
        event_id: str,
        domain: str,
        event_type: str,
        rule_name: str,
        variant_id: str,
        source_copilot: str | None = None,
        source_rule: str | None = None,
        metric: float | None = None,
        shadow_batch_size: int | None = None,
        min_shadow_batches: int | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        self._store.write_evolution_event(
            event_id=event_id,
            domain=domain,
            event_type=event_type,
            rule_name=rule_name,
            variant_id=variant_id,
            source_copilot=source_copilot,
            source_rule=source_rule,
            metric=metric,
            shadow_batch_size=shadow_batch_size,
            min_shadow_batches=min_shadow_batches,
            metadata=metadata,
        )

    def link_entity(
        self,
        decision_id: str,
        entity_id: str,
        entity_type: str,
        domain: str,
    ) -> None:
        self._store.link_entity(
            decision_id=decision_id,
            entity_id=entity_id,
            entity_type=entity_type,
            domain=domain,
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

    def count_verified_decisions(self, domain: str) -> int:
        return self._store.count_verified_decisions(domain)

    def count_correct(self, domain: str) -> int:
        return self._store.count_correct(domain)

    def count_decisions(self, domain: str) -> int:
        return self._store.count_decisions(domain)

    def count_categories_with_n(self, domain: str, n: int = 1) -> int:
        return self._store.count_categories_with_n(domain, n=n)

    def update_centroid(
        self,
        domain: str,
        category: str,
        action: str,
        centroid_vector: list[float],
        delta_norm: float,
        caused_by_decision_id: str | None = None,
    ) -> None:
        self._store.update_centroid(
            domain=domain,
            category=category,
            action=action,
            centroid_vector=centroid_vector,
            delta_norm=delta_norm,
            caused_by_decision_id=caused_by_decision_id,
        )

    def get_centroids(self, domain: str) -> list[dict[str, object]]:
        return self._store.get_centroids(domain)

    def update_dk_weights(
        self,
        domain: str,
        weight_tensor: list[list[float]],
        n_decisions_used: int,
        computed_at: float,
        *,
        welford_state: dict[str, object] | None = None,
        n_confirmed: int | None = None,
        n_overridden: int | None = None,
        entity_group: str | None = None,
    ) -> None:
        self._store.update_dk_weights(
            domain=domain,
            weight_tensor=weight_tensor,
            n_decisions_used=n_decisions_used,
            computed_at=computed_at,
            welford_state=welford_state,
            n_confirmed=n_confirmed,
            n_overridden=n_overridden,
            entity_group=entity_group,
        )

    def get_dk_weights(self, domain: str) -> dict[str, object] | None:
        return self._store.get_dk_weights(domain)

    def update_conservation_state(
        self,
        domain: str,
        status: str,
        alpha: float,
        q: float,
        V: int,
        theta_min: float,
        product: float,
        categories_total: int,
        categories_with_data: int,
        baseline_product: float,
        relative_threshold: float,
        complacency_flag: str,
        caused_by_decision_id: str | None = None,
        old_status: str | None = None,
    ) -> str:
        return self._store.update_conservation_state(
            domain=domain,
            status=status,
            alpha=alpha,
            q=q,
            V=V,
            theta_min=theta_min,
            product=product,
            categories_total=categories_total,
            categories_with_data=categories_with_data,
            baseline_product=baseline_product,
            relative_threshold=relative_threshold,
            complacency_flag=complacency_flag,
            caused_by_decision_id=caused_by_decision_id,
            old_status=old_status,
        )

    def get_conservation_state(self, domain: str) -> dict[str, object] | None:
        return self._store.get_conservation_state(domain)

    def archive_decisions(
        self,
        domain: str,
        before: float,
        status_filter: str = "pending",
        confirm_verified: bool = False,
    ) -> int:
        return self._store.archive_decisions(
            domain=domain,
            before=before,
            status_filter=status_filter,
            confirm_verified=confirm_verified,
        )

    def domain_scoped_reset(self, domain: str) -> None:
        self._store.domain_scoped_reset(domain)

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

    def query_context(self, entity_id: str, max_depth: int) -> list[dict[str, Any]]:
        return self._store.query_context(entity_id=str(entity_id), hops=int(max_depth))

    def query_similar(self, entity_id: str, limit: int) -> list[dict[str, Any]]:
        return self._store.query_similar(decision_id=str(entity_id), limit=int(limit))

    def write_entity_enrichment(
        self,
        *,
        domain: str,
        entity_type: str,
        entity_id: str,
        namespace: str,
        metrics: dict[str, Any],
        computed_from: Any,
        dry_run: bool = False,
        idempotency_key: str | None = None,
    ) -> Any:
        raise NotImplementedError(
            "AGEGraphStoreAdapter does not support entity enrichment writes in P39A; "
            "durable AGE enrichment is deferred"
        )

    def read_entity_enrichment(
        self,
        *,
        domain: str,
        entity_type: str,
        entity_id: str,
        namespace: str | None = None,
    ) -> dict[str, Any]:
        return {}

    def list_entity_enrichments(
        self,
        *,
        domain: str,
        entity_type: str | None = None,
        namespace: str | None = None,
        limit: int = 500,
    ) -> list[Any]:
        return []

    def close(self) -> None:
        self._store.close()
