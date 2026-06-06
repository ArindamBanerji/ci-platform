"""GraphStore-compatible adapter for Apache AGE."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
import threading
import time
import uuid
from collections.abc import Iterable, Mapping
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, cast

import numpy as np

from ci_platform.graph.age_client import AGEClient


log = logging.getLogger(__name__)


class AGEGraphStore:
    """Synchronous GraphStore adapter backed by AGEClient."""

    def __init__(self, dsn: str, graph_name: str = "soc_graph") -> None:
        self._client = AGEClient(dsn=dsn, graph_name=graph_name)

    def _run(self, coro):
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(coro)

        result: Dict[str, Any] = {}

        def _target() -> None:
            try:
                result["value"] = asyncio.run(coro)
            except Exception as exc:  # pragma: no cover - defensive bridge
                result["error"] = exc

        thread = threading.Thread(target=_target, daemon=True)
        thread.start()
        thread.join()
        if "error" in result:
            raise result["error"]
        return result.get("value")

    def _S(self, value: Any) -> str:
        return self._client._S(value)

    @staticmethod
    def _safe_limit(limit: int, default: int = 400) -> int:
        try:
            value = int(limit)
        except (TypeError, ValueError):
            return default
        return max(1, min(value, 1000))

    @staticmethod
    def _safe_hops(hops: int) -> int:
        try:
            value = int(hops)
        except (TypeError, ValueError):
            return 2
        return max(1, min(value, 5))

    @staticmethod
    def _as_int(
        value: int | float | str | bytes | bytearray | bool | None,
        default: int = 0,
    ) -> int:
        if value is None:
            return default
        return int(value)

    @staticmethod
    def _as_float(
        value: Any,
        default: float = 0.0,
    ) -> float:
        if value is None:
            return default
        return float(value)

    @staticmethod
    def _normalize_centroid_vector(centroid_vector: Any) -> List[float]:
        if isinstance(centroid_vector, (str, bytes, bytearray)):
            raise TypeError("centroid_vector must be a non-string iterable of numeric values")
        if isinstance(centroid_vector, Mapping):
            raise TypeError("centroid_vector must be a non-mapping iterable of numeric values")
        if not isinstance(centroid_vector, Iterable):
            raise TypeError("centroid_vector must be an iterable of numeric values")
        try:
            return [float(value) for value in centroid_vector]
        except (TypeError, ValueError) as error:
            raise TypeError("centroid_vector must contain only numeric values") from error

    @staticmethod
    def _normalize_dk_weight_tensor(weight_tensor: Any) -> List[List[float]]:
        if isinstance(weight_tensor, (str, bytes, bytearray)):
            raise TypeError("weight_tensor must be a non-string 2D numeric iterable")
        if isinstance(weight_tensor, Mapping):
            raise TypeError("weight_tensor must be a non-mapping 2D numeric iterable")
        if not isinstance(weight_tensor, Iterable):
            raise TypeError("weight_tensor must be a 2D numeric iterable")
        rows: List[List[float]] = []
        expected_width: int | None = None
        for row in weight_tensor:
            if isinstance(row, (str, bytes, bytearray)):
                raise TypeError("weight_tensor rows must be non-string numeric iterables")
            if isinstance(row, Mapping):
                raise TypeError("weight_tensor rows must be non-mapping numeric iterables")
            if not isinstance(row, Iterable):
                raise TypeError("weight_tensor must be 2D, not a 1D iterable")
            try:
                normalized_row = [float(value) for value in row]
            except (TypeError, ValueError) as error:
                raise TypeError("weight_tensor must contain only numeric values") from error
            if not normalized_row:
                raise ValueError("weight_tensor rows must be non-empty")
            if expected_width is None:
                expected_width = len(normalized_row)
            elif len(normalized_row) != expected_width:
                raise ValueError("weight_tensor rows must be rectangular")
            rows.append(normalized_row)
        if not rows:
            raise ValueError("weight_tensor must be non-empty")
        return rows

    @staticmethod
    def _normalize_n_decisions_used(n_decisions_used: Any) -> int:
        try:
            value = int(n_decisions_used)
        except (TypeError, ValueError) as error:
            raise TypeError("n_decisions_used must be an integer") from error
        if value < 0:
            raise ValueError("n_decisions_used must be non-negative")
        return value

    @staticmethod
    def _normalize_computed_at(computed_at: Any) -> float:
        try:
            return float(computed_at)
        except (TypeError, ValueError) as error:
            raise TypeError("computed_at must be numeric") from error

    @staticmethod
    def _sort_key(value: Any) -> tuple[int, Any]:
        if value is None:
            return (0, "")
        try:
            return (1, float(value))
        except (TypeError, ValueError):
            return (1, str(value))

    @classmethod
    def _latest_row(cls, rows: List[Dict[str, Any]], *keys: str) -> Dict[str, Any] | None:
        if not rows:
            return None
        return max(rows, key=lambda row: tuple(cls._sort_key(row.get(key)) for key in keys))

    @staticmethod
    def _normalize_domain(domain: Any) -> str:
        if not isinstance(domain, str) or not domain.strip():
            raise ValueError("domain must be a non-empty string")
        return domain

    @staticmethod
    def _normalize_conservation_status(status: Any, field_name: str = "status") -> str:
        if not isinstance(status, str) or status not in {"GREEN", "AMBER", "RED"}:
            raise ValueError(f"{field_name} must be one of GREEN, AMBER, RED")
        return status

    @classmethod
    def _normalize_optional_conservation_status(cls, old_status: Any) -> str | None:
        if old_status is None:
            return None
        return cls._normalize_conservation_status(old_status, field_name="old_status")

    @staticmethod
    def _normalize_bounded_float(value: Any, field_name: str) -> float:
        try:
            normalized = float(value)
        except (TypeError, ValueError) as error:
            raise TypeError(f"{field_name} must be numeric") from error
        if normalized < 0.0 or normalized > 1.0:
            raise ValueError(f"{field_name} must be between 0.0 and 1.0")
        return normalized

    @staticmethod
    def _normalize_float(value: Any, field_name: str) -> float:
        try:
            return float(value)
        except (TypeError, ValueError) as error:
            raise TypeError(f"{field_name} must be numeric") from error

    @classmethod
    def _normalize_positive_float(cls, value: Any, field_name: str) -> float:
        normalized = cls._normalize_float(value, field_name)
        if normalized <= 0.0:
            raise ValueError(f"{field_name} must be greater than 0")
        return normalized

    @staticmethod
    def _normalize_non_negative_int(value: Any, field_name: str) -> int:
        if isinstance(value, bool):
            raise TypeError(f"{field_name} must be an integer")
        try:
            normalized = int(value)
        except (TypeError, ValueError) as error:
            raise TypeError(f"{field_name} must be an integer") from error
        if normalized < 0:
            raise ValueError(f"{field_name} must be non-negative")
        return normalized

    @staticmethod
    def _normalize_complacency_flag(complacency_flag: Any) -> str:
        if not isinstance(complacency_flag, str) or complacency_flag not in {"true", "false"}:
            raise ValueError("complacency_flag must be exactly 'true' or 'false'")
        return complacency_flag

    @staticmethod
    def _normalize_optional_string(value: Any, field_name: str) -> str | None:
        if value is None:
            return None
        if not isinstance(value, str):
            raise TypeError(f"{field_name} must be a string or None")
        return value

    @staticmethod
    def _require_field(row: Dict[str, object], key: str) -> object:
        if key not in row or row[key] is None:
            raise ValueError(f"L5ConservationState missing required field: {key}")
        return row[key]

    @classmethod
    def _normalize_conservation_state_values(
        cls,
        *,
        domain: Any,
        status: Any,
        alpha: Any,
        q: Any,
        V: Any,
        theta_min: Any,
        product: Any,
        categories_total: Any,
        categories_with_data: Any,
        baseline_product: Any,
        relative_threshold: Any,
        complacency_flag: Any,
        caused_by_decision_id: Any,
        old_status: Any,
    ) -> Dict[str, object]:
        categories_total_value = cls._normalize_non_negative_int(
            categories_total, "categories_total"
        )
        categories_with_data_value = cls._normalize_non_negative_int(
            categories_with_data, "categories_with_data"
        )
        if categories_with_data_value > categories_total_value:
            raise ValueError("categories_with_data must be less than or equal to categories_total")
        return {
            "domain": cls._normalize_domain(domain),
            "status": cls._normalize_conservation_status(status),
            "alpha": cls._normalize_bounded_float(alpha, "alpha"),
            "q": cls._normalize_bounded_float(q, "q"),
            "V": cls._normalize_non_negative_int(V, "V"),
            "theta_min": cls._normalize_positive_float(theta_min, "theta_min"),
            "product": cls._normalize_float(product, "product"),
            "categories_total": categories_total_value,
            "categories_with_data": categories_with_data_value,
            "baseline_product": cls._normalize_float(baseline_product, "baseline_product"),
            "relative_threshold": cls._normalize_float(
                relative_threshold, "relative_threshold"
            ),
            "complacency_flag": cls._normalize_complacency_flag(complacency_flag),
            "caused_by_decision_id": cls._normalize_optional_string(
                caused_by_decision_id, "caused_by_decision_id"
            ),
            "old_status": cls._normalize_optional_conservation_status(old_status),
        }

    def _run_query(self, cypher: str) -> List[Dict[str, Any]]:
        return self._run(self._client.run_query(cypher, None)) or []

    def write_decision(
        self,
        domain: str,
        category: str,
        action: str,
        confidence: float,
        factors: Dict[str, Any],
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        decision_id = f"DEC-{uuid.uuid4().hex[:8]}"
        confidence_value = float(confidence)
        metadata_dict = dict(metadata or {})
        entity_id = str(metadata_dict.get("entity_id") or "")
        factors_json = json.dumps(factors or {}, sort_keys=True)
        metadata_json = json.dumps(metadata_dict, sort_keys=True)

        props = self._decision_props(
            decision_id,
            domain,
            entity_id,
            category,
            action,
            confidence_value,
            factors_json,
            metadata_json,
        )
        if not entity_id:
            self._run_query(f"CREATE (d:Decision {props}) RETURN d")
            return decision_id

        entity_query = f"""
        MATCH (e {{entity_id: {self._S(entity_id)}}})
        WITH e LIMIT 1
        CREATE (d:Decision {props})
        CREATE (d)-[:DECIDED_ON]->(e)
        RETURN d
        """
        rows = self._run_query(entity_query)
        if not rows:
            self._run_query(f"CREATE (d:Decision {props}) RETURN d")
        return decision_id

    def write_governed_decision(
        self,
        decision_id: str,
        domain: str,
        category: str,
        category_index: int,
        recommended_action: str,
        recommended_index: int,
        confidence: float,
        probabilities: List[float],
        factor_vector: List[float],
        factor_names: List[str],
        source: str = "score",
        scorer_version: str = "",
        preset_version: str = "",
        factor_schema_version: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        metadata_dict = dict(metadata or {})
        metadata_dict["decision_id"] = str(decision_id)
        metadata_dict["source"] = source
        metadata_dict["scorer_version"] = scorer_version
        metadata_dict["preset_version"] = preset_version
        metadata_dict["factor_schema_version"] = factor_schema_version
        metadata_dict["factor_names"] = list(factor_names)
        metadata_dict["factor_vector"] = [float(value) for value in factor_vector]
        metadata_dict["probabilities"] = [float(value) for value in probabilities]
        metadata_dict["category_index"] = int(category_index)
        metadata_dict["recommended_index"] = int(recommended_index)
        expected_payload = self._governed_decision_payload(
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
            metadata=metadata_dict,
        )
        existing_rows = self._run_query(
            f"""
            MATCH (d:Decision {{decision_id: {self._S(str(decision_id))}}})
            WHERE d.domain = {self._S(str(domain))}
            RETURN d
            """
        )
        if existing_rows:
            if len(existing_rows) > 1:
                raise ValueError(f"duplicate governed decision_id in domain: {decision_id}")
            existing_payload = self._governed_decision_payload_from_node(existing_rows[0]["d"])
            if existing_payload == expected_payload:
                return
            raise ValueError(f"conflicting governed decision_id in domain: {decision_id}")

        created_at = metadata_dict.get("created_at")
        if created_at is None:
            created_at = datetime.now(timezone.utc).timestamp()
        props = (
            "{"
            f"decision_id: {self._S(str(decision_id))}, "
            f"domain: {self._S(str(domain))}, "
            f"category: {self._S(str(category))}, "
            f"category_index: {int(category_index)}, "
            f"recommended_action: {self._S(str(recommended_action))}, "
            f"recommended_index: {int(recommended_index)}, "
            f"confidence: {float(confidence)}, "
            f"probabilities: {self._S(json.dumps(metadata_dict['probabilities'], sort_keys=True))}, "
            f"factor_vector: {self._S(json.dumps(metadata_dict['factor_vector'], sort_keys=True))}, "
            f"factor_names: {self._S(json.dumps(metadata_dict['factor_names'], sort_keys=True))}, "
            f"source: {self._S(str(source))}, "
            f"scorer_version: {self._S(str(scorer_version))}, "
            f"preset_version: {self._S(str(preset_version))}, "
            f"factor_schema_version: {self._S(str(factor_schema_version))}, "
            f"metadata: {self._S(json.dumps(metadata_dict, sort_keys=True))}, "
            "status: 'pending', "
            f"created_at: {float(created_at)}"
            "}"
        )
        self._run_query(f"CREATE (d:Decision {props}) RETURN d")

    def _governed_decision_payload(
        self,
        *,
        decision_id: str,
        domain: str,
        category: str,
        category_index: int,
        recommended_action: str,
        recommended_index: int,
        confidence: float,
        probabilities: List[float],
        factor_vector: List[float],
        factor_names: List[str],
        source: str,
        scorer_version: str,
        preset_version: str,
        factor_schema_version: str,
        metadata: Optional[Dict[str, Any]],
    ) -> Dict[str, Any]:
        metadata_identity = dict(metadata or {})
        metadata_identity.pop("created_at", None)
        return {
            "decision_id": str(decision_id),
            "domain": str(domain),
            "category": str(category),
            "category_index": int(category_index),
            "recommended_action": str(recommended_action),
            "recommended_index": int(recommended_index),
            "confidence": float(confidence),
            "probabilities": [float(value) for value in list(probabilities)],
            "factor_vector": [float(value) for value in list(factor_vector)],
            "factor_names": [str(value) for value in list(factor_names)],
            "source": str(source),
            "scorer_version": str(scorer_version),
            "preset_version": str(preset_version),
            "factor_schema_version": str(factor_schema_version),
            "metadata": metadata_identity,
            "status": "pending",
        }

    def _governed_decision_payload_from_node(self, node: Any) -> Dict[str, Any]:
        data = self._node_to_dict(node)
        metadata = data.get("metadata") or {}
        if not isinstance(metadata, dict):
            metadata = {}
        payload = self._governed_decision_payload(
            decision_id=data.get("decision_id", ""),
            domain=data.get("domain", ""),
            category=data.get("category", ""),
            category_index=data.get("category_index", 0),
            recommended_action=data.get("recommended_action", ""),
            recommended_index=data.get("recommended_index", 0),
            confidence=data.get("confidence", 0.0),
            probabilities=data.get("probabilities") or [],
            factor_vector=data.get("factor_vector") or [],
            factor_names=data.get("factor_names") or [],
            source=data.get("source", ""),
            scorer_version=data.get("scorer_version", ""),
            preset_version=data.get("preset_version", ""),
            factor_schema_version=data.get("factor_schema_version", ""),
            metadata=metadata,
        )
        payload["status"] = str(data.get("status", ""))
        return payload

    def _decision_props(
        self,
        decision_id: str,
        domain: str,
        entity_id: str,
        category: str,
        action: str,
        confidence: float,
        factors_json: str,
        metadata_json: str,
    ) -> str:
        return (
            "{"
            f"decision_id: {self._S(decision_id)}, "
            f"domain: {self._S(domain)}, "
            f"entity_id: {self._S(entity_id)}, "
            f"category: {self._S(category)}, "
            f"recommended_action: {self._S(action)}, "
            f"confidence: {confidence}, "
            f"factors: {self._S(factors_json)}, "
            f"metadata: {self._S(metadata_json)}"
            "}"
        )

    def write_outcome(
        self,
        decision_id: str,
        actual_action: str,
        is_correct: bool,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        metadata_dict = dict(metadata or {})
        actual_index = int(metadata_dict.get("actual_index", 0))
        reward = float(metadata_dict.get("reward", 0.0))
        verifier = str(metadata_dict.get("verifier", "analyst"))
        override_reason = metadata_dict.get("override_reason")
        verified_at = float(metadata_dict.get("verified_at", datetime.now(timezone.utc).timestamp()))
        created_at = float(metadata_dict.get("created_at", verified_at))
        metadata_json = json.dumps(metadata_dict, sort_keys=True)
        status = "confirmed" if bool(is_correct) else "overridden"
        query = f"""
        MATCH (d:Decision {{decision_id: {self._S(decision_id)}}})
        OPTIONAL MATCH (d)-[:HAS_OUTCOME]->(linked:Outcome)
        WITH d, count(linked) AS linked_outcome_count
        OPTIONAL MATCH (same:Outcome {{decision_id: {self._S(decision_id)}}})
        WITH d, linked_outcome_count, count(same) AS same_decision_outcome_count
        WHERE linked_outcome_count = 0
          AND same_decision_outcome_count = 0
          AND d.status = 'pending'
        SET d.status = {self._S(status)}
        CREATE (o:Outcome {{
            decision_id: {self._S(decision_id)},
            domain: d.domain,
            actual_action: {self._S(actual_action)},
            actual_index: {actual_index},
            is_correct: {str(bool(is_correct)).lower()},
            reward: {reward},
            verifier: {self._S(verifier)},
            override_reason: {self._S(override_reason)},
            metadata: {self._S(metadata_json)},
            verified_at: {verified_at},
            created_at: {created_at}
        }})
        CREATE (d)-[:HAS_OUTCOME {{
            decision_id: {self._S(decision_id)},
            created_at: {created_at}
        }}]->(o)
        RETURN d.status AS status, o AS o
        """
        rows = self._run_query(query)
        if rows:
            return
        self._raise_write_outcome_no_row(decision_id)

    def _raise_write_outcome_no_row(self, decision_id: str) -> None:
        decision_rows = self._run_query(
            f"""
            MATCH (d:Decision {{decision_id: {self._S(decision_id)}}})
            RETURN d.status AS status
            LIMIT 1
            """
        )
        if not decision_rows:
            raise KeyError(decision_id)
        linked_rows = self._run_query(
            f"""
            MATCH (d:Decision {{decision_id: {self._S(decision_id)}}})
            OPTIONAL MATCH (d)-[:HAS_OUTCOME]->(linked:Outcome)
            RETURN count(linked) AS cnt
            """
        )
        standalone_rows = self._run_query(
            f"""
            MATCH (o:Outcome {{decision_id: {self._S(decision_id)}}})
            RETURN count(o) AS cnt
            """
        )
        linked_count = self._int_from_rows(linked_rows, "cnt")
        standalone_count = self._int_from_rows(standalone_rows, "cnt")
        if linked_count > 0 or standalone_count > 0:
            raise ValueError(f"outcome already exists for decision_id: {decision_id}")
        status = decision_rows[0].get("status")
        if status != "pending":
            raise ValueError(f"decision status is not pending for decision_id: {decision_id}")
        raise RuntimeError(f"AGE write_outcome returned no rows for decision_id: {decision_id}")

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
        entity_id: Optional[str] = None,
        factor_vector: Optional[List[float]] = None,
        factor_names: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        metadata_dict = dict(metadata or {})
        created_at = float(metadata_dict.get("created_at", datetime.now(timezone.utc).timestamp()))
        vector = [float(value) for value in factor_vector] if factor_vector is not None else []
        names = list(factor_names or [])
        query = f"""
        OPTIONAL MATCH (existing:Observation {{observation_id: {self._S(str(observation_id))}}})
        WITH count(existing) AS existing_count
        WHERE existing_count = 0
        CREATE (o:Observation {{
            observation_id: {self._S(str(observation_id))},
            domain: {self._S(str(domain))},
            category: {self._S(str(category))},
            recommended_action: {self._S(str(recommended_action))},
            confidence: {float(confidence)},
            source_route: {self._S(str(source_route))},
            scorer_version: {self._S(str(scorer_version))},
            factor_schema_version: {self._S(str(factor_schema_version))},
            entity_id: {self._S(str(entity_id)) if entity_id is not None else "null"},
            factor_vector: {self._S(json.dumps(vector, sort_keys=True))},
            factor_names: {self._S(json.dumps(names, sort_keys=True))},
            metadata: {self._S(json.dumps(metadata_dict, sort_keys=True))},
            created_at: {created_at}
        }})
        RETURN o
        """
        self._run_query(query)

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
        payload = {
            "status_id": str(status_id),
            "snapshot_id": str(status_id),
            "domain": str(domain),
            "V": int(V),
            "q": float(q),
            "alpha": float(alpha),
            "theta_min": float(theta_min),
            "verified_count": int(verified_count),
            "correct_count": int(correct_count),
            "status": str(status),
            "policy_version": str(policy_version),
            "counts_scope": "verified_only",
        }
        existing = self._get_conservation_status_payload(str(status_id))
        if existing is not None:
            if existing == payload:
                return
            raise ValueError(f"conflicting conservation status_id: {status_id}")

        computed_at = datetime.now(timezone.utc).timestamp()
        props = (
            "{"
            f"status_id: {self._S(payload['status_id'])}, "
            f"snapshot_id: {self._S(payload['snapshot_id'])}, "
            f"domain: {self._S(payload['domain'])}, "
            f"V: {payload['V']}, "
            f"q: {payload['q']}, "
            f"alpha: {payload['alpha']}, "
            f"theta_min: {payload['theta_min']}, "
            f"verified_count: {payload['verified_count']}, "
            f"correct_count: {payload['correct_count']}, "
            f"status: {self._S(payload['status'])}, "
            f"policy_version: {self._S(payload['policy_version'])}, "
            f"counts_scope: {self._S(payload['counts_scope'])}, "
            f"computed_at: {float(computed_at)}"
            "}"
        )
        self._run_query(f"CREATE (c:ConservationStatus {props}) RETURN c")

    def _get_conservation_status_payload(self, status_id: str) -> Optional[Dict[str, Any]]:
        rows = self._run_query(
            f"""
            MATCH (c:ConservationStatus {{status_id: {self._S(status_id)}}})
            RETURN c
            LIMIT 1
            """
        )
        if not rows:
            return None
        node = self._node_to_dict(rows[0].get("c", rows[0]))
        return {
            "status_id": str(node.get("status_id")),
            "snapshot_id": str(node.get("snapshot_id") or node.get("status_id")),
            "domain": str(node.get("domain")),
            "V": self._as_int(node.get("V")),
            "q": self._as_float(node.get("q")),
            "alpha": self._as_float(node.get("alpha")),
            "theta_min": self._as_float(node.get("theta_min")),
            "verified_count": self._as_int(node.get("verified_count")),
            "correct_count": self._as_int(node.get("correct_count")),
            "status": str(node.get("status")),
            "policy_version": str(node.get("policy_version")),
            "counts_scope": str(node.get("counts_scope") or "verified_only"),
        }

    def write_fingerprint(
        self,
        fingerprint_id: str,
        domain: str,
        factor_names: List[str],
        factor_stats: Dict[str, Any],
        skipped_incompatible: int,
        window: int,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        payload = {
            "fingerprint_id": str(fingerprint_id),
            "domain": str(domain),
            "factor_names_json": json.dumps(list(factor_names), sort_keys=True),
            "factor_stats_json": json.dumps(dict(factor_stats), sort_keys=True),
            "skipped_incompatible": int(skipped_incompatible),
            "window": int(window),
            "metadata_json": json.dumps(dict(metadata or {}), sort_keys=True),
        }
        existing = self._get_fingerprint_payload(str(fingerprint_id))
        if existing is not None:
            if existing == payload:
                return
            raise ValueError(f"conflicting fingerprint_id: {fingerprint_id}")

        created_at = datetime.now(timezone.utc).timestamp()
        props = (
            "{"
            f"fingerprint_id: {self._S(payload['fingerprint_id'])}, "
            f"domain: {self._S(payload['domain'])}, "
            f"factor_names: {self._S(payload['factor_names_json'])}, "
            f"factor_stats: {self._S(payload['factor_stats_json'])}, "
            f"skipped_incompatible: {payload['skipped_incompatible']}, "
            f"window: {payload['window']}, "
            f"metadata: {self._S(payload['metadata_json'])}, "
            "schema_version: 'protocol_v2', "
            f"created_at: {float(created_at)}"
            "}"
        )
        self._run_query(f"CREATE (f:Fingerprint {props}) RETURN f")

    def _get_fingerprint_payload(self, fingerprint_id: str) -> Optional[Dict[str, Any]]:
        rows = self._run_query(
            f"""
            MATCH (f:Fingerprint {{fingerprint_id: {self._S(fingerprint_id)}}})
            RETURN f
            LIMIT 1
            """
        )
        if not rows:
            return None
        node = self._node_to_dict(rows[0].get("f", rows[0]))
        factor_names = self._json_field_value(node.get("factor_names"))
        factor_stats = self._json_field_value(node.get("factor_stats"))
        metadata = self._json_field_value(node.get("metadata"))
        return {
            "fingerprint_id": str(node.get("fingerprint_id")),
            "domain": str(node.get("domain")),
            "factor_names_json": json.dumps(factor_names, sort_keys=True),
            "factor_stats_json": json.dumps(factor_stats, sort_keys=True),
            "skipped_incompatible": self._as_int(node.get("skipped_incompatible")),
            "window": self._as_int(node.get("window")),
            "metadata_json": json.dumps(metadata, sort_keys=True),
        }

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
        shape: List[int],
        factor_names_hash: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        if hasattr(centroids, "tolist"):
            centroids = centroids.tolist()
        payload = {
            "checkpoint_id": str(checkpoint_id),
            "domain": str(domain),
            "category": str(category),
            "action": str(action),
            "centroids_json": json.dumps(centroids, sort_keys=True),
            "decisions_count": int(decisions_count),
            "verified_count": int(verified_count),
            "iks": float(iks),
            "shape_json": json.dumps([int(value) for value in shape], sort_keys=True),
            "factor_names_hash": str(factor_names_hash),
            "metadata_json": json.dumps(dict(metadata or {}), sort_keys=True),
        }
        existing = self._get_centroid_checkpoint_payload(str(checkpoint_id))
        if existing is not None:
            if existing == payload:
                return
            raise ValueError(f"conflicting checkpoint_id: {checkpoint_id}")

        created_at = datetime.now(timezone.utc).timestamp()
        props = (
            "{"
            f"checkpoint_id: {self._S(payload['checkpoint_id'])}, "
            f"domain: {self._S(payload['domain'])}, "
            f"category: {self._S(payload['category'])}, "
            f"action: {self._S(payload['action'])}, "
            f"centroids: {self._S(payload['centroids_json'])}, "
            f"decisions_count: {payload['decisions_count']}, "
            f"verified_count: {payload['verified_count']}, "
            f"iks: {payload['iks']}, "
            f"shape: {self._S(payload['shape_json'])}, "
            f"factor_names_hash: {self._S(payload['factor_names_hash'])}, "
            f"metadata: {self._S(payload['metadata_json'])}, "
            "schema_version: 'protocol_v2', "
            f"created_at: {float(created_at)}"
            "}"
        )
        self._run_query(f"CREATE (c:CentroidCheckpoint {props}) RETURN c")

    def _get_centroid_checkpoint_payload(self, checkpoint_id: str) -> Optional[Dict[str, Any]]:
        rows = self._run_query(
            f"""
            MATCH (c:CentroidCheckpoint {{checkpoint_id: {self._S(checkpoint_id)}}})
            RETURN c
            LIMIT 1
            """
        )
        if not rows:
            return None
        node = self._node_to_dict(rows[0].get("c", rows[0]))
        centroids = self._json_field_value(node.get("centroids"))
        shape = self._json_field_value(node.get("shape"))
        metadata = self._json_field_value(node.get("metadata"))
        return {
            "checkpoint_id": str(node.get("checkpoint_id")),
            "domain": str(node.get("domain")),
            "category": str(node.get("category")),
            "action": str(node.get("action")),
            "centroids_json": json.dumps(centroids, sort_keys=True),
            "decisions_count": self._as_int(node.get("decisions_count")),
            "verified_count": self._as_int(node.get("verified_count")),
            "iks": self._as_float(node.get("iks")),
            "shape_json": json.dumps(shape, sort_keys=True),
            "factor_names_hash": str(node.get("factor_names_hash")),
            "metadata_json": json.dumps(metadata, sort_keys=True),
        }

    @staticmethod
    def _json_field_value(value: Any) -> Any:
        if isinstance(value, str):
            try:
                return json.loads(value)
            except json.JSONDecodeError:
                return value
        return value

    @staticmethod
    def _json_default(value: Any) -> Any:
        if isinstance(value, np.ndarray):
            return value.tolist()
        if isinstance(value, np.integer):
            return int(value)
        if isinstance(value, np.floating):
            return float(value)
        raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")

    def _receipt_payload_hash(
        self,
        receipt_intent_id: str,
        domain: str,
        decision_id: str,
        canonical_payload: Dict[str, Any],
        actor: str,
        source_route: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        payload = {
            "receipt_intent_id": str(receipt_intent_id),
            "domain": str(domain),
            "decision_id": str(decision_id),
            "canonical_payload": dict(canonical_payload),
            "actor": actor,
            "source_route": source_route,
            "metadata": dict(metadata or {}),
        }
        encoded = json.dumps(
            payload,
            default=self._json_default,
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(encoded.encode("utf-8")).hexdigest()

    def append_evidence_receipt(
        self,
        receipt_intent_id: str,
        domain: str,
        decision_id: str,
        canonical_payload: Dict[str, Any],
        actor: str,
        source_route: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> tuple[int, str]:
        receipt_intent_id = str(receipt_intent_id)
        domain = str(domain)
        decision_id = str(decision_id)
        actor = str(actor)
        source_route = str(source_route)
        canonical_payload_dict = dict(canonical_payload)
        metadata_dict = dict(metadata or {})
        canonical_payload_json = json.dumps(
            canonical_payload_dict,
            default=self._json_default,
            sort_keys=True,
        )
        metadata_json = json.dumps(
            metadata_dict,
            default=self._json_default,
            sort_keys=True,
        )
        payload_hash = self._receipt_payload_hash(
            receipt_intent_id,
            domain,
            decision_id,
            canonical_payload_dict,
            actor,
            source_route,
            metadata_dict,
        )

        def persist(tx) -> tuple[int, str]:
            tx.execute_sql(
                """
                CREATE TABLE IF NOT EXISTS protocol_v2_receipt_locks (
                    domain TEXT PRIMARY KEY
                )
                """
            )
            tx.execute_sql(
                """
                INSERT INTO protocol_v2_receipt_locks(domain)
                VALUES (%s)
                ON CONFLICT DO NOTHING
                """,
                (domain,),
            )
            tx.execute_sql(
                """
                SELECT domain
                FROM protocol_v2_receipt_locks
                WHERE domain = %s
                FOR UPDATE
                """,
                (domain,),
            )

            decision_rows = tx.run_cypher(
                f"""
                MATCH (d:Decision {{decision_id: {self._S(decision_id)}}})
                WHERE d.domain = {self._S(domain)}
                RETURN d
                LIMIT 1
                """
            )
            if not decision_rows:
                raise KeyError(decision_id)

            existing_rows = tx.run_cypher(
                f"""
                MATCH (r:EvidenceReceipt {{receipt_intent_id: {self._S(receipt_intent_id)}}})
                WHERE r.domain = {self._S(domain)}
                RETURN r
                LIMIT 1
                """
            )
            if existing_rows:
                existing = self._node_to_dict(existing_rows[0].get("r", existing_rows[0]))
                if str(existing.get("payload_hash")) == payload_hash:
                    return self._as_int(existing.get("chain_index")), str(existing.get("payload_hash"))
                raise ValueError(f"conflicting evidence receipt_intent_id: {receipt_intent_id}")

            duplicate_index_rows = tx.run_cypher(
                f"""
                MATCH (r:EvidenceReceipt)
                WHERE r.domain = {self._S(domain)}
                WITH r.chain_index AS chain_index, count(r) AS cnt
                WHERE cnt > 1
                RETURN chain_index, cnt
                LIMIT 1
                """
            )
            if duplicate_index_rows:
                raise RuntimeError(f"corrupt EvidenceReceipt chain for domain: {domain}")

            latest_rows = tx.run_cypher(
                f"""
                MATCH (r:EvidenceReceipt)
                WHERE r.domain = {self._S(domain)}
                RETURN r
                ORDER BY r.chain_index DESC
                LIMIT 1
                """
            )
            if latest_rows:
                latest = self._node_to_dict(latest_rows[0].get("r", latest_rows[0]))
                if latest.get("chain_index") is None or not latest.get("payload_hash"):
                    raise RuntimeError(f"corrupt EvidenceReceipt chain for domain: {domain}")
                chain_index = int(latest["chain_index"]) + 1
                previous_hash = str(latest["payload_hash"])
            else:
                chain_index = 0
                previous_hash = "GENESIS"

            created_at = datetime.now(timezone.utc).timestamp()
            rows = tx.run_cypher(
                f"""
                MATCH (d:Decision {{decision_id: {self._S(decision_id)}}})
                WHERE d.domain = {self._S(domain)}
                CREATE (r:EvidenceReceipt {{
                    receipt_id: {self._S(receipt_intent_id)},
                    receipt_intent_id: {self._S(receipt_intent_id)},
                    domain: {self._S(domain)},
                    decision_id: {self._S(decision_id)},
                    chain_index: {chain_index},
                    previous_hash: {self._S(previous_hash)},
                    payload_hash: {self._S(payload_hash)},
                    actor: {self._S(actor)},
                    source_route: {self._S(source_route)},
                    canonical_payload: {self._S(canonical_payload_json)},
                    metadata: {self._S(metadata_json)},
                    schema_version: 'protocol_v2',
                    created_at: {float(created_at)}
                }})
                CREATE (d)-[:EMITTED_RECEIPT {{
                    receipt_intent_id: {self._S(receipt_intent_id)},
                    domain: {self._S(domain)},
                    decision_id: {self._S(decision_id)},
                    created_at: {float(created_at)}
                }}]->(r)
                RETURN r
                """
            )
            if not rows:
                raise RuntimeError(f"failed to create EvidenceReceipt for intent: {receipt_intent_id}")
            if getattr(self, "_protocol_v2_fail_after_receipt_create", None) == receipt_intent_id:
                raise RuntimeError("injected EvidenceReceipt failure after create")

            verify_rows = tx.run_cypher(
                f"""
                MATCH (d:Decision {{decision_id: {self._S(decision_id)}}})-[:EMITTED_RECEIPT]->(r:EvidenceReceipt)
                WHERE d.domain = {self._S(domain)}
                  AND r.domain = {self._S(domain)}
                  AND r.receipt_intent_id = {self._S(receipt_intent_id)}
                RETURN count(r) AS cnt
                """
            )
            if self._int_from_rows(verify_rows, "cnt") != 1:
                raise RuntimeError(f"failed to verify EvidenceReceipt edge for intent: {receipt_intent_id}")

            return chain_index, payload_hash

        result = self._run(self._client.run_transaction(persist))
        if not (
            isinstance(result, tuple)
            and len(result) == 2
            and isinstance(result[0], int)
            and isinstance(result[1], str)
        ):
            raise TypeError("append_evidence_receipt transaction returned invalid result")
        return cast(tuple[int, str], result)

    def write_evolution_event(
        self,
        event_id: str,
        domain: str,
        event_type: str,
        rule_name: str,
        variant_id: str,
        source_copilot: Optional[str] = None,
        source_rule: Optional[str] = None,
        metric: Optional[float] = None,
        shadow_batch_size: Optional[int] = None,
        min_shadow_batches: Optional[int] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        payload = {
            "event_id": str(event_id),
            "domain": str(domain),
            "event_type": str(event_type),
            "rule_name": str(rule_name),
            "variant_id": str(variant_id),
            "source_copilot": None if source_copilot is None else str(source_copilot),
            "source_rule": None if source_rule is None else str(source_rule),
            "metric": None if metric is None else float(metric),
            "shadow_batch_size": None if shadow_batch_size is None else int(shadow_batch_size),
            "min_shadow_batches": None if min_shadow_batches is None else int(min_shadow_batches),
            "metadata_json": json.dumps(dict(metadata or {}), sort_keys=True),
        }
        existing = self._get_evolution_event_payload(str(event_id))
        if existing is not None:
            if existing == payload:
                return
            raise ValueError(f"conflicting evolution event_id: {event_id}")

        created_at = datetime.now(timezone.utc).timestamp()
        props = (
            "{"
            f"event_id: {self._S(payload['event_id'])}, "
            f"domain: {self._S(payload['domain'])}, "
            f"event_type: {self._S(payload['event_type'])}, "
            f"rule_name: {self._S(payload['rule_name'])}, "
            f"variant_id: {self._S(payload['variant_id'])}, "
            f"source_copilot: {self._S(payload['source_copilot'])}, "
            f"source_rule: {self._S(payload['source_rule'])}, "
            f"metric: {self._S(payload['metric'])}, "
            f"shadow_batch_size: {self._S(payload['shadow_batch_size'])}, "
            f"min_shadow_batches: {self._S(payload['min_shadow_batches'])}, "
            f"metadata: {self._S(payload['metadata_json'])}, "
            "schema_version: 'protocol_v2', "
            f"created_at: {float(created_at)}"
            "}"
        )
        self._run_query(f"CREATE (e:EvolutionEvent {props}) RETURN e")

    def _get_evolution_event_payload(self, event_id: str) -> Optional[Dict[str, Any]]:
        rows = self._run_query(
            f"""
            MATCH (e:EvolutionEvent {{event_id: {self._S(event_id)}}})
            RETURN e
            LIMIT 1
            """
        )
        if not rows:
            return None
        node = self._node_to_dict(rows[0].get("e", rows[0]))
        metadata = self._json_field_value(node.get("metadata"))
        return {
            "event_id": str(node.get("event_id")),
            "domain": str(node.get("domain")),
            "event_type": str(node.get("event_type")),
            "rule_name": str(node.get("rule_name")),
            "variant_id": str(node.get("variant_id")),
            "source_copilot": None if node.get("source_copilot") is None else str(node.get("source_copilot")),
            "source_rule": None if node.get("source_rule") is None else str(node.get("source_rule")),
            "metric": None if node.get("metric") is None else self._as_float(node.get("metric")),
            "shadow_batch_size": None
            if node.get("shadow_batch_size") is None
            else self._as_int(node.get("shadow_batch_size")),
            "min_shadow_batches": None
            if node.get("min_shadow_batches") is None
            else self._as_int(node.get("min_shadow_batches")),
            "metadata_json": json.dumps(metadata, sort_keys=True),
        }

    def link_entity(
        self,
        decision_id: str,
        entity_id: str,
        entity_type: str,
        domain: str,
    ) -> None:
        decision_rows = self._run_query(
            f"""
            MATCH (d:Decision {{decision_id: {self._S(str(decision_id))}}})
            WHERE d.domain = {self._S(str(domain))}
            RETURN d
            LIMIT 1
            """
        )
        if not decision_rows:
            raise KeyError(decision_id)

        link_rows = self._run_query(
            f"""
            MATCH (d:Decision {{decision_id: {self._S(str(decision_id))}}})-[r:ABOUT]->(e:DomainContext)
            WHERE d.domain = {self._S(str(domain))}
              AND e.domain = {self._S(str(domain))}
              AND e.entity_id = {self._S(str(entity_id))}
            RETURN count(r) AS cnt
            """
        )
        if self._int_from_rows(link_rows, "cnt") > 0:
            return

        context_rows = self._run_query(
            f"""
            MATCH (e:DomainContext {{entity_id: {self._S(str(entity_id))}, domain: {self._S(str(domain))}}})
            RETURN e
            LIMIT 1
            """
        )
        if not context_rows:
            created_at = datetime.now(timezone.utc).timestamp()
            self._run_query(
                f"""
                CREATE (e:DomainContext {{
                    entity_id: {self._S(str(entity_id))},
                    natural_key: {self._S(str(entity_id))},
                    entity_type: {self._S(str(entity_type))},
                    domain: {self._S(str(domain))},
                    schema_version: 'protocol_v2',
                    created_at: {float(created_at)}
                }})
                RETURN e
                """
            )

        created_at = datetime.now(timezone.utc).timestamp()
        rows = self._run_query(
            f"""
            MATCH (d:Decision {{decision_id: {self._S(str(decision_id))}}})
            MATCH (e:DomainContext {{entity_id: {self._S(str(entity_id))}, domain: {self._S(str(domain))}}})
            WHERE d.domain = {self._S(str(domain))}
            OPTIONAL MATCH (d)-[existing:ABOUT]->(e)
            WITH d, e, count(existing) AS existing_count
            WHERE existing_count = 0
            CREATE (d)-[:ABOUT {{
                decision_id: {self._S(str(decision_id))},
                entity_id: {self._S(str(entity_id))},
                domain: {self._S(str(domain))},
                entity_type: {self._S(str(entity_type))},
                created_at: {float(created_at)}
            }}]->(e)
            RETURN d, e
            """
        )
        if rows:
            return
        # A concurrent duplicate can make the final guarded CREATE return no rows.
        duplicate_rows = self._run_query(
            f"""
            MATCH (d:Decision {{decision_id: {self._S(str(decision_id))}}})-[r:ABOUT]->(e:DomainContext)
            WHERE d.domain = {self._S(str(domain))}
              AND e.domain = {self._S(str(domain))}
              AND e.entity_id = {self._S(str(entity_id))}
            RETURN count(r) AS cnt
            """
        )
        if self._int_from_rows(duplicate_rows, "cnt") > 0:
            return
        raise RuntimeError(f"AGE link_entity returned no rows for decision_id: {decision_id}")

    def get_decision(self, decision_id: str) -> Optional[Dict[str, Any]]:
        rows = self._run_query(
            f"""
            MATCH (d:Decision {{decision_id: {self._S(decision_id)}}})
            RETURN d
            LIMIT 1
            """
        )
        if not rows:
            return None
        return self._node_to_dict(rows[0].get("d", rows[0]))

    def get_decisions(
        self, domain: str, category: Optional[str] = None, limit: int = 400
    ) -> List[Dict[str, Any]]:
        limit_value = self._safe_limit(limit)
        clauses = [f"d.domain = {self._S(domain)}"]
        if category is not None:
            clauses.append(f"d.category = {self._S(category)}")
        where_clause = "WHERE " + " AND ".join(clauses)
        rows = self._run_query(
            f"""
            MATCH (d:Decision)
            {where_clause}
            RETURN d
            LIMIT {limit_value}
            """
        )
        return [self._node_to_dict(row.get("d", row)) for row in rows]

    def get_verified_decisions(self, domain: str) -> List[Dict[str, Any]]:
        rows = self._run_query(
            f"""
            MATCH (d:Decision)-[:HAS_OUTCOME]->(o:Outcome)
            WHERE d.domain = {self._S(domain)}
            RETURN d, o
            """
        )
        return [self._merge_decision_outcome(row) for row in rows]

    def count_verified(self, domain: str) -> int:
        rows = self._run_query(
            f"""
            MATCH (d:Decision)-[:HAS_OUTCOME]->(o:Outcome)
            WHERE d.domain = {self._S(domain)}
            RETURN count(o) AS cnt
            """
        )
        return self._int_from_rows(rows, "cnt")

    def count_verified_decisions(self, domain: str) -> int:
        rows = self._run_query(
            f"""
            MATCH (d:Decision)
            WHERE d.domain = {self._S(domain)}
              AND (d.status = 'confirmed' OR d.status = 'overridden')
              AND (d.archived IS NULL OR d.archived = false)
            RETURN count(d) AS cnt
            """
        )
        return self._int_from_rows(rows, "cnt")

    def count_correct(self, domain: str) -> int:
        rows = self._run_query(
            f"""
            MATCH (d:Decision)-[:HAS_OUTCOME]->(o:Outcome)
            WHERE d.domain = {self._S(domain)} AND o.is_correct = true
            RETURN count(o) AS cnt
            """
        )
        return self._int_from_rows(rows, "cnt")

    def count_decisions(self, domain: str) -> int:
        rows = self._run_query(
            f"""
            MATCH (d:Decision)
            WHERE d.domain = {self._S(domain)}
              AND (d.archived IS NULL OR d.archived = false)
            RETURN count(d) AS cnt
            """
        )
        return self._int_from_rows(rows, "cnt")

    def count_categories_with_n(self, domain: str, n: int = 1) -> int:
        threshold = max(int(n), 0)
        rows = self._run_query(
            f"""
            MATCH (d:Decision)-[:HAS_OUTCOME]->(o:Outcome)
            WHERE d.domain = {self._S(domain)}
            WITH d.category AS category, count(o) AS outcome_count
            WHERE outcome_count >= {threshold}
            RETURN count(category) AS cnt
            """
        )
        return self._int_from_rows(rows, "cnt")

    def update_centroid(
        self,
        domain: str,
        category: str,
        action: str,
        centroid_vector: List[float],
        delta_norm: float,
        caused_by_decision_id: str | None = None,
    ) -> None:
        domain_value = str(domain)
        category_value = str(category)
        action_value = str(action)
        vector = self._normalize_centroid_vector(centroid_vector)
        delta_value = float(delta_norm)
        updated_at_epoch = time.time()
        vector_json = json.dumps(vector, separators=(",", ":"))
        caused_by_value = None if caused_by_decision_id is None else str(caused_by_decision_id)
        props = (
            "{"
            f"domain: {self._S(domain_value)}, "
            f"category: {self._S(category_value)}, "
            f"action: {self._S(action_value)}, "
            f"vector_json: {self._S(vector_json)}, "
            f"delta_norm: {delta_value}, "
            f"caused_by_decision_id: {self._S(caused_by_value)}, "
            f"updated_at_epoch: {updated_at_epoch}"
            "}"
        )
        self._run_query(
            f"""
            MATCH (c:L5Centroid)
            WHERE c.domain = {self._S(domain_value)}
              AND c.category = {self._S(category_value)}
              AND c.action = {self._S(action_value)}
            DELETE c
            """
        )
        self._run_query(f"CREATE (c:L5Centroid {props}) RETURN c")
        if caused_by_value:
            try:
                self._run_query(
                    f"""
                    MATCH (c:L5Centroid)
                    WHERE c.domain = {self._S(domain_value)}
                      AND c.category = {self._S(category_value)}
                      AND c.action = {self._S(action_value)}
                    MATCH (d:Decision {{decision_id: {self._S(caused_by_value)}}})
                    CREATE (c)-[:SHAPED_BY]->(d)
                    RETURN c, d
                    """
                )
            except Exception as exc:
                log.warning(
                    "L5Centroid SHAPED_BY edge creation failed for decision_id=%s: %s",
                    caused_by_value,
                    exc,
                )

    def get_centroids(self, domain: str) -> List[Dict[str, object]]:
        rows = self._run_query(
            f"""
            MATCH (c:L5Centroid)
            WHERE c.domain = {self._S(str(domain))}
            RETURN c.category AS category,
                   c.action AS action,
                   c.vector_json AS vector_json,
                   c.delta_norm AS delta_norm,
                   c.caused_by_decision_id AS caused_by_decision_id,
                   c.updated_at_epoch AS updated_at_epoch
            ORDER BY category, action, updated_at_epoch DESC, caused_by_decision_id DESC
            """
        )
        latest_by_identity: Dict[tuple[object, object], Dict[str, object]] = {}
        for row in rows:
            vector_json = row.get("vector_json")
            if vector_json is None and "c" in row:
                node = self._node_to_dict(row.get("c"))
                vector_json = node.get("vector_json")
                row = {
                    "category": node.get("category"),
                    "action": node.get("action"),
                    "vector_json": vector_json,
                    "delta_norm": node.get("delta_norm"),
                    "caused_by_decision_id": node.get("caused_by_decision_id"),
                    "updated_at_epoch": node.get("updated_at_epoch"),
                }
            identity = (row.get("category"), row.get("action"))
            current = latest_by_identity.get(identity)
            if current is not None and self._sort_key(current.get("updated_at_epoch")) >= self._sort_key(
                row.get("updated_at_epoch")
            ):
                continue
            latest_by_identity[identity] = row
        centroids: List[Dict[str, object]] = []
        for row in sorted(latest_by_identity.values(), key=lambda item: (str(item.get("category")), str(item.get("action")))):
            vector_json = row.get("vector_json")
            if not isinstance(vector_json, str):
                raise TypeError("L5Centroid vector_json must be a JSON string")
            vector = [float(value) for value in json.loads(vector_json)]
            centroids.append(
                {
                    "category": row.get("category"),
                    "action": row.get("action"),
                    "vector_json": vector,
                    "delta_norm": self._as_float(row.get("delta_norm")),
                    "caused_by_decision_id": row.get("caused_by_decision_id"),
                    "updated_at": row.get("updated_at_epoch"),
                }
            )
        return centroids

    def update_dk_weights(
        self,
        domain: str,
        weight_tensor: List[List[float]],
        n_decisions_used: int,
        computed_at: float,
    ) -> None:
        domain_value = str(domain)
        tensor = self._normalize_dk_weight_tensor(weight_tensor)
        decisions_used = self._normalize_n_decisions_used(n_decisions_used)
        computed_at_value = self._normalize_computed_at(computed_at)
        weight_json = json.dumps(tensor, separators=(",", ":"))
        created_at = time.time()
        dk_weight_id = f"{domain_value}:dkw:{uuid.uuid4().hex[:12]}"
        archive_id = f"{domain_value}:dkw_archive:{uuid.uuid4().hex[:12]}"
        current_rows = self._run_query(
            f"""
            MATCH (w:L5DKWeight)
            WHERE w.domain = {self._S(domain_value)}
            RETURN w
            LIMIT 1
            """
        )
        previous = self._node_to_dict(current_rows[0].get("w", current_rows[0])) if current_rows else None
        supersedes_id = archive_id if previous else None
        current_props = (
            "{"
            f"dk_weight_id: {self._S(dk_weight_id)}, "
            f"domain: {self._S(domain_value)}, "
            f"weight_json: {self._S(weight_json)}, "
            f"n_decisions_used: {decisions_used}, "
            f"computed_at: {computed_at_value}, "
            f"created_at: {created_at}, "
            f"supersedes_id: {self._S(supersedes_id)}"
            "}"
        )

        def persist(tx) -> None:
            if previous:
                archive_props = (
                    "{"
                    f"archive_id: {self._S(archive_id)}, "
                    f"domain: {self._S(str(previous.get('domain') or domain_value))}, "
                    f"dk_weight_id: {self._S(str(previous.get('dk_weight_id') or ''))}, "
                    f"weight_json: {self._S(str(previous.get('weight_json') or '[]'))}, "
                    f"n_decisions_used: {int(previous.get('n_decisions_used') or 0)}, "
                    f"computed_at: {float(previous.get('computed_at') or 0.0)}, "
                    f"created_at: {float(previous.get('created_at') or 0.0)}, "
                    f"archived_at_epoch: {created_at}"
                    "}"
                )
                tx.run_cypher(f"CREATE (a:L5DKWeightArchive {archive_props}) RETURN a")
                tx.run_cypher(
                    f"""
                    MATCH (w:L5DKWeight)-[r:SUPERSEDES]->()
                    WHERE w.domain = {self._S(domain_value)}
                    DELETE r
                    """
                )
                tx.run_cypher(
                    f"""
                    MATCH (w:L5DKWeight)
                    WHERE w.domain = {self._S(domain_value)}
                    DELETE w
                    """
                )
            else:
                tx.run_cypher(
                    f"""
                    MATCH (w:L5DKWeight)
                    WHERE w.domain = {self._S(domain_value)}
                    DELETE w
                    """
                )
            tx.run_cypher(f"CREATE (w:L5DKWeight {current_props}) RETURN w")
            if previous:
                tx.run_cypher(
                    f"""
                    MATCH (w:L5DKWeight {{dk_weight_id: {self._S(dk_weight_id)}}})
                    MATCH (a:L5DKWeightArchive {{archive_id: {self._S(archive_id)}}})
                    CREATE (w)-[:SUPERSEDES]->(a)
                    RETURN w, a
                    """
                )

        self._run(self._client.run_transaction(persist))

    def get_dk_weights(self, domain: str) -> Dict[str, object] | None:
        rows = self._run_query(
            f"""
            MATCH (w:L5DKWeight)
            WHERE w.domain = {self._S(str(domain))}
            RETURN w.domain AS domain,
                   w.dk_weight_id AS dk_weight_id,
                   w.weight_json AS weight_json,
                   w.n_decisions_used AS n_decisions_used,
                   w.computed_at AS computed_at,
                   w.created_at AS created_at,
                   w.supersedes_id AS supersedes_id
            ORDER BY created_at DESC, dk_weight_id DESC
            LIMIT 1
            """
        )
        row = self._latest_row(rows, "created_at", "dk_weight_id")
        if row is None:
            return None
        weight_json = row.get("weight_json")
        if weight_json is None and "w" in row:
            node = self._node_to_dict(row.get("w"))
            weight_json = node.get("weight_json")
            row = {
                "domain": node.get("domain"),
                "dk_weight_id": node.get("dk_weight_id"),
                "weight_json": weight_json,
                "n_decisions_used": node.get("n_decisions_used"),
                "computed_at": node.get("computed_at"),
                "created_at": node.get("created_at"),
                "supersedes_id": node.get("supersedes_id"),
            }
        if not isinstance(weight_json, str):
            raise TypeError("L5DKWeight weight_json must be a JSON string")
        tensor = self._normalize_dk_weight_tensor(json.loads(weight_json))
        return {
            "domain": row.get("domain"),
            "weight_json": tensor,
            "n_decisions_used": int(row.get("n_decisions_used") or 0),
            "computed_at": float(row.get("computed_at") or 0.0),
            "created_at": row.get("created_at"),
            "supersedes_id": row.get("supersedes_id"),
        }

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
        state = self._normalize_conservation_state_values(
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
        domain_value = cast(str, state["domain"])
        state_id = f"{domain_value}:conservation:{uuid.uuid4().hex[:12]}"
        updated_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        props = (
            "{"
            f"id: {self._S(state_id)}, "
            f"domain: {self._S(domain_value)}, "
            f"status: {self._S(state['status'])}, "
            f"alpha: {state['alpha']}, "
            f"q: {state['q']}, "
            f"V: {state['V']}, "
            f"theta_min: {state['theta_min']}, "
            f"product: {state['product']}, "
            f"categories_total: {state['categories_total']}, "
            f"categories_with_data: {state['categories_with_data']}, "
            f"baseline_product: {state['baseline_product']}, "
            f"relative_threshold: {state['relative_threshold']}, "
            f"complacency_flag: {self._S(state['complacency_flag'])}, "
            f"caused_by_decision_id: {self._S(state['caused_by_decision_id'])}, "
            f"old_status: {self._S(state['old_status'])}, "
            f"updated_at: {self._S(updated_at)}"
            "}"
        )
        self._run_query(
            f"""
            MATCH (cs:L5ConservationState)-[r:TRIGGERED_BY]->()
            WHERE cs.domain = {self._S(domain_value)}
            DELETE r
            """
        )
        self._run_query(
            f"""
            MATCH (cs:L5ConservationState)
            WHERE cs.domain = {self._S(domain_value)}
            DELETE cs
            """
        )
        self._run_query(f"CREATE (cs:L5ConservationState {props}) RETURN cs")
        old_status_value = cast(str | None, state["old_status"])
        caused_by_value = cast(str | None, state["caused_by_decision_id"])
        if old_status_value is not None and old_status_value != state["status"] and caused_by_value:
            try:
                rows = self._run_query(
                    f"""
                    MATCH (cs:L5ConservationState {{id: {self._S(state_id)}}})
                    MATCH (d:Decision {{decision_id: {self._S(caused_by_value)}}})
                    WHERE d.domain = {self._S(domain_value)}
                    CREATE (cs)-[:TRIGGERED_BY {{
                        old_status: {self._S(old_status_value)},
                        new_status: {self._S(state['status'])},
                        timestamp: {self._S(updated_at)}
                    }}]->(d)
                    RETURN cs, d
                    """
                )
                if not rows:
                    log.warning(
                        "L5ConservationState TRIGGERED_BY decision not found for domain=%s decision_id=%s",
                        domain_value,
                        caused_by_value,
                    )
            except Exception as exc:
                log.warning(
                    "L5ConservationState TRIGGERED_BY edge creation failed for domain=%s decision_id=%s: %s",
                    domain_value,
                    caused_by_value,
                    exc,
                )
        return state_id

    def get_conservation_state(self, domain: str) -> Dict[str, object] | None:
        rows = self._run_query(
            f"""
            MATCH (cs:L5ConservationState)
            WHERE cs.domain = {self._S(str(domain))}
            RETURN cs.id AS id,
                   cs.domain AS domain,
                   cs.status AS status,
                   cs.alpha AS alpha,
                   cs.q AS q,
                   cs.V AS V,
                   cs.theta_min AS theta_min,
                   cs.product AS product,
                   cs.categories_total AS categories_total,
                   cs.categories_with_data AS categories_with_data,
                   cs.baseline_product AS baseline_product,
                     cs.relative_threshold AS relative_threshold,
                     cs.complacency_flag AS complacency_flag,
                     cs.caused_by_decision_id AS caused_by_decision_id,
                     cs.old_status AS old_status,
                     cs.updated_at AS updated_at
              ORDER BY updated_at DESC, id DESC
              LIMIT 1
              """
        )
        row = self._latest_row(rows, "updated_at", "id")
        if row is None:
            return None
        if row.get("id") is None and "cs" in row:
            node = self._node_to_dict(row.get("cs"))
            row = node
        state = self._normalize_conservation_state_values(
            domain=self._require_field(row, "domain"),
            status=self._require_field(row, "status"),
            alpha=self._require_field(row, "alpha"),
            q=self._require_field(row, "q"),
            V=self._require_field(row, "V"),
            theta_min=self._require_field(row, "theta_min"),
            product=self._require_field(row, "product"),
            categories_total=self._require_field(row, "categories_total"),
            categories_with_data=self._require_field(row, "categories_with_data"),
            baseline_product=self._require_field(row, "baseline_product"),
            relative_threshold=self._require_field(row, "relative_threshold"),
            complacency_flag=self._require_field(row, "complacency_flag"),
            caused_by_decision_id=row.get("caused_by_decision_id"),
            old_status=row.get("old_status"),
        )
        updated_at = self._require_field(row, "updated_at")
        return {
            "id": None if row.get("id") is None else str(row.get("id")),
            "domain": state["domain"],
            "status": state["status"],
            "alpha": state["alpha"],
            "q": state["q"],
            "V": state["V"],
            "theta_min": state["theta_min"],
            "product": state["product"],
            "categories_total": state["categories_total"],
            "categories_with_data": state["categories_with_data"],
            "baseline_product": state["baseline_product"],
            "relative_threshold": state["relative_threshold"],
            "complacency_flag": state["complacency_flag"],
            "caused_by_decision_id": state["caused_by_decision_id"],
            "old_status": state["old_status"],
            "updated_at": str(updated_at),
        }

    def get_all_decisions(self, domain: str) -> List[Dict[str, Any]]:
        return self.get_decisions(domain)

    def save_centroids(
        self,
        domain: str,
        category: str,
        centroids: Any,
        metadata: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> None:
        decision_id = str(kwargs.get("decision_id") or (metadata or {}).get("decision_id") or "")
        if hasattr(centroids, "tolist"):
            centroids = centroids.tolist()
        centroids_json = json.dumps(centroids, sort_keys=True)
        metadata_json = json.dumps(metadata or {}, sort_keys=True)
        created_at = datetime.now(timezone.utc).isoformat()
        props = (
            "{"
            f"decision_id: {self._S(decision_id)}, "
            f"domain: {self._S(domain)}, "
            f"category: {self._S(category)}, "
            f"centroids: {self._S(centroids_json)}, "
            f"metadata: {self._S(metadata_json)}, "
            f"created_at: {self._S(created_at)}"
            "}"
        )
        if decision_id:
            query = f"""
            MATCH (d:Decision {{decision_id: {self._S(decision_id)}}})
            WITH d LIMIT 1
            CREATE (c:CentroidCheckpoint {props})
            CREATE (d)-[:HAS_CENTROID_CHECKPOINT]->(c)
            RETURN c
            """
            rows = self._run_query(query)
            if rows:
                return
        else:
            self._run_query(f"CREATE (c:CentroidCheckpoint {props}) RETURN c")
            return
        self._run_query(f"CREATE (c:CentroidCheckpoint {props}) RETURN c")

    def load_latest_centroids(self, domain: str) -> Any | None:
        rows = self._run_query(
            f"""
            MATCH (c:CentroidCheckpoint)
            WHERE c.domain = {self._S(domain)}
              AND c.checkpoint_id IS NULL
            RETURN c
            ORDER BY c.created_at DESC
            LIMIT 1
            """
        )
        if not rows:
            return None
        checkpoint = self._node_to_dict(rows[0].get("c", rows[0]))
        centroids = checkpoint.get("centroids")
        if centroids is None:
            return None
        return np.asarray(centroids, dtype=np.float64)

    def save_evolution_event(
        self,
        domain: str,
        event_type: str,
        rule_name: str,
        variant_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        metadata_json = json.dumps(metadata or {}, sort_keys=True)
        timestamp = datetime.now(timezone.utc).isoformat()
        props = (
            "{"
            f"domain: {self._S(domain)}, "
            f"event_type: {self._S(event_type)}, "
            f"rule_name: {self._S(rule_name)}, "
            f"variant_id: {self._S(variant_id)}, "
            f"metadata: {self._S(metadata_json)}, "
            f"timestamp: {self._S(timestamp)}"
            "}"
        )
        self._run_query(f"CREATE (e:EvolutionEvent {props}) RETURN e")

    def link_decision_to_entity(
        self,
        decision_id: str,
        entity_id: str,
        edge_type: str = "DECIDED_ON",
    ) -> None:
        edge_label = self._safe_edge_type(edge_type)
        created_at = datetime.now(timezone.utc).isoformat()
        props = self._link_props(decision_id, entity_id, edge_label, created_at)
        query = f"""
        MATCH (d:Decision {{decision_id: {self._S(decision_id)}}})
        MATCH (e {{entity_id: {self._S(entity_id)}}})
        WITH d, e LIMIT 1
        CREATE (d)-[:{edge_label} {{
            decision_id: {self._S(decision_id)},
            entity_id: {self._S(entity_id)},
            edge_type: {self._S(edge_label)},
            created_at: {self._S(created_at)}
        }}]->(e)
        RETURN d, e
        """
        rows = self._run_query(query)
        if not rows:
            self._run_query(f"CREATE (l:DecisionEntityLink {props}) RETURN l")

    def get_decision_links(self, decision_id: str | None = None) -> List[Dict[str, Any]]:
        where_relationship = (
            f"WHERE d.decision_id = {self._S(decision_id)}"
            if decision_id is not None
            else ""
        )
        relationship_rows = self._run_query(
            f"""
            MATCH (d:Decision)-[r]->(e)
            {where_relationship}
            RETURN d.decision_id AS decision_id,
                   e.entity_id AS entity_id,
                   type(r) AS edge_type,
                   r.created_at AS created_at
            """
        )
        where_link = (
            f"WHERE l.decision_id = {self._S(decision_id)}"
            if decision_id is not None
            else ""
        )
        link_rows = self._run_query(
            f"""
            MATCH (l:DecisionEntityLink)
            {where_link}
            RETURN l
            """
        )
        return [
            link
            for row in [*relationship_rows, *link_rows]
            if (link := self._link_row_to_dict(row))
        ]

    @staticmethod
    def _safe_edge_type(edge_type: str) -> str:
        value = str(edge_type or "DECIDED_ON").upper()
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", value):
            raise ValueError(f"Invalid edge_type: {edge_type!r}")
        return value

    def _link_props(
        self,
        decision_id: str,
        entity_id: str,
        edge_type: str,
        created_at: str,
    ) -> str:
        return (
            "{"
            f"decision_id: {self._S(decision_id)}, "
            f"entity_id: {self._S(entity_id)}, "
            f"edge_type: {self._S(edge_type)}, "
            f"created_at: {self._S(created_at)}"
            "}"
        )

    def _link_row_to_dict(self, row: Dict[str, Any]) -> Dict[str, Any]:
        link = self._node_to_dict(row.get("l", row))
        decision_id = link.get("decision_id")
        entity_id = link.get("entity_id")
        edge_type = link.get("edge_type")
        if not decision_id:
            decision = self._node_to_dict(row.get("d"))
            decision_id = decision.get("decision_id")
        if not entity_id:
            entity = self._node_to_dict(row.get("e"))
            entity_id = entity.get("entity_id")
        if not edge_type:
            edge_type = row.get("edge_type") or "DECIDED_ON"
        if not decision_id or not entity_id:
            return {}
        return {
            "decision_id": str(decision_id),
            "entity_id": str(entity_id),
            "edge_type": str(edge_type),
            "created_at": link.get("created_at") or row.get("created_at"),
        }

    def get_centroid_checkpoints(self, domain: str, **kwargs: Any) -> List[Dict[str, Any]]:
        limit = kwargs.pop("limit", 50)
        limit_value = self._safe_limit(limit, default=50)
        rows = self._run_query(
            f"""
            MATCH (c:CentroidCheckpoint)
            WHERE c.domain = {self._S(domain)}
              AND c.checkpoint_id IS NULL
            RETURN c
            ORDER BY c.created_at DESC
            LIMIT {limit_value}
            """
        )
        checkpoints = [self._node_to_dict(row.get("c", row)) for row in rows]
        return list(reversed(checkpoints))

    def get_evolution_events(self, domain: str, **kwargs: Any) -> List[Dict[str, Any]]:
        limit = self._safe_limit(kwargs.pop("limit", 100), default=100)
        clauses = [f"e.domain = {self._S(domain)}"]
        for key in ("event_type", "rule_name", "variant_id"):
            value = kwargs.get(key)
            if value is not None:
                clauses.append(f"e.{key} = {self._S(value)}")
        where_clause = "WHERE " + " AND ".join(clauses)
        rows = self._run_query(
            f"""
            MATCH (e:EvolutionEvent)
            {where_clause}
            RETURN e
            ORDER BY e.timestamp DESC
            LIMIT {limit}
            """
        )
        return [self._node_to_dict(row.get("e", row)) for row in rows]

    def archive_old_decisions(self, domain: str, keep_recent: int = 800) -> int:
        """AGE retention is managed externally; no in-graph archive is performed."""
        return 0

    def count_archived(self, domain: str) -> int:
        rows = self._run_query(
            f"""
            MATCH (d:Decision)
            WHERE d.domain = {self._S(str(domain))}
              AND d.archived = true
            RETURN count(d) AS cnt
            """
        )
        return self._int_from_rows(rows, "cnt")

    def archive_decisions(
        self,
        domain: str,
        before: float,
        status_filter: str = "pending",
        confirm_verified: bool = False,
    ) -> int:
        domain = str(domain)
        status_filter = str(status_filter)
        if status_filter not in {"pending", "confirmed", "overridden"}:
            raise ValueError(f"unsupported archive status_filter: {status_filter}")
        if status_filter in {"confirmed", "overridden"} and not confirm_verified:
            raise ValueError("Archiving verified decisions reduces active V; pass confirm_verified=True")

        cutoff = float(before)
        candidate_rows = self._run_query(
            f"""
            MATCH (d:Decision)
            WHERE d.domain = {self._S(domain)}
              AND d.status = {self._S(status_filter)}
              AND (d.archived IS NULL OR d.archived = false)
            RETURN d
            """
        )
        decision_ids: List[str] = []
        for row in candidate_rows:
            decision = self._node_to_dict(row.get("d", row))
            created_at = decision.get("created_at")
            if isinstance(created_at, bool):
                continue
            if not isinstance(created_at, (int, float)):
                continue
            if float(created_at) < cutoff and decision.get("decision_id"):
                decision_ids.append(str(decision["decision_id"]))

        if not decision_ids:
            return 0

        id_list = "[" + ", ".join(self._S(value) for value in sorted(set(decision_ids))) + "]"
        archived_at = datetime.now(timezone.utc).timestamp()
        rows = self._run_query(
            f"""
            MATCH (d:Decision)
            WHERE d.domain = {self._S(domain)}
              AND d.status = {self._S(status_filter)}
              AND (d.archived IS NULL OR d.archived = false)
              AND d.decision_id IN {id_list}
            SET d.archived = true,
                d.archived_at = {float(archived_at)},
                d.archive_reason = {self._S(f"protocol_v2_archive:{status_filter}")},
                d.archive_status = 'archived',
                d.archived_from_status = d.status
            RETURN count(d) AS cnt
            """
        )
        return self._int_from_rows(rows, "cnt")

    def domain_scoped_reset(self, domain: str) -> None:
        domain = str(domain)
        self._validate_protocol_v2_reset_scope(domain)

        def reset(tx) -> None:
            self._reset_domain_relationships(tx, domain)
            self._delete_domain_label(tx, "EvidenceReceipt", domain)
            self._delete_domain_label(tx, "Outcome", domain)
            self._delete_domain_contexts(tx, domain)
            for label in (
                "Decision",
                "Observation",
                "ConservationStatus",
                "Fingerprint",
                "CentroidCheckpoint",
                "L5Centroid",
                "L5DKWeight",
                "L5DKWeightArchive",
                "L5ConservationState",
                "EvolutionEvent",
            ):
                self._delete_domain_label(tx, label, domain)

        self._run(self._client.run_transaction(reset))

    def _validate_protocol_v2_reset_scope(self, domain: str) -> None:
        graph_name = str(getattr(self._client, "_graph", "") or "")
        if not graph_name or graph_name == "soc_graph":
            raise ValueError("domain_scoped_reset is forbidden for soc_graph or blank AGE graph")
        if not graph_name.startswith("protocol_v2_test"):
            raise ValueError("domain_scoped_reset is allowed only for protocol_v2_test* AGE graphs")
        if not domain.startswith("pytest_protocol_v2_"):
            raise ValueError("domain_scoped_reset is allowed only for pytest_protocol_v2_* domains")

    def _reset_domain_relationships(self, tx, domain: str) -> None:
        tx.run_cypher(
            f"""
            MATCH (d:Decision)-[r:EMITTED_RECEIPT]->(e:EvidenceReceipt)
            WHERE d.domain = {self._S(domain)}
               OR e.domain = {self._S(domain)}
            DELETE r
            """
        )
        tx.run_cypher(
            f"""
            MATCH (d:Decision)-[r:HAS_OUTCOME]->(o:Outcome)
            WHERE d.domain = {self._S(domain)}
               OR o.domain = {self._S(domain)}
            DELETE r
            """
        )
        tx.run_cypher(
            f"""
            MATCH (c:L5Centroid)-[r:SHAPED_BY]->(d:Decision)
            WHERE c.domain = {self._S(domain)}
               OR d.domain = {self._S(domain)}
            DELETE r
            """
        )
        tx.run_cypher(
            f"""
            MATCH (w:L5DKWeight)-[r:SUPERSEDES]->(a:L5DKWeightArchive)
            WHERE w.domain = {self._S(domain)}
               OR a.domain = {self._S(domain)}
            DELETE r
            """
        )
        tx.run_cypher(
            f"""
            MATCH (cs:L5ConservationState)-[r:TRIGGERED_BY]->(d:Decision)
            WHERE cs.domain = {self._S(domain)}
               OR d.domain = {self._S(domain)}
            DELETE r
            """
        )
        tx.run_cypher(
            f"""
            MATCH (d:Decision)-[r:ABOUT]->(e:DomainContext)
            WHERE d.domain = {self._S(domain)}
              AND e.domain = {self._S(domain)}
            DELETE r
            """
        )

    def _delete_domain_contexts(self, tx, domain: str) -> None:
        tx.run_cypher(
            f"""
            MATCH (e:DomainContext)
            WHERE e.domain = {self._S(domain)}
            OPTIONAL MATCH (other)-[r]->(e)
            WITH e, count(r) AS incoming_count
            WHERE incoming_count = 0
            DELETE e
            """
        )

    def _delete_domain_label(self, tx, label: str, domain: str) -> None:
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", label):
            raise ValueError(f"Invalid AGE label: {label!r}")
        tx.run_cypher(
            f"""
            MATCH (n:{label})
            WHERE n.domain = {self._S(domain)}
            DELETE n
            """
        )

    def query_context(self, entity_id: str, hops: int = 2) -> List[Dict[str, Any]]:
        hop_count = self._safe_hops(hops)
        rows = self._run_query(
            f"""
            MATCH p = (e {{entity_id: {self._S(entity_id)}}})-[*1..{hop_count}]-(n)
            RETURN p
            LIMIT 100
            """
        )
        return [self._node_to_dict(row) for row in rows]

    def query_similar(self, decision_id: str, limit: int = 5) -> List[Dict[str, Any]]:
        limit_value = self._safe_limit(limit, default=5)
        rows = self._run_query(
            f"""
            MATCH (d:Decision {{decision_id: {self._S(decision_id)}}})
            MATCH (s:Decision {{category: d.category}})
            WHERE s.decision_id <> d.decision_id
            RETURN s
            LIMIT {limit_value}
            """
        )
        return [self._node_to_dict(row.get("s", row)) for row in rows]

    def close(self) -> None:
        try:
            self._run(self._client.close())
        except Exception:
            pass

    def _node_to_dict(self, value: Any) -> Dict[str, Any]:
        if value is None:
            return {}
        if isinstance(value, dict):
            if "properties" in value and isinstance(value["properties"], dict):
                node = dict(value["properties"])
                if "id" in value:
                    node.setdefault("_age_id", value["id"])
            elif len(value) == 1 and isinstance(next(iter(value.values())), dict):
                node = self._node_to_dict(next(iter(value.values())))
            else:
                node = dict(value)
            for key in ("factors", "metadata", "centroids", "factor_vector", "factor_names", "probabilities"):
                if isinstance(node.get(key), str):
                    try:
                        node[key] = json.loads(node[key])
                    except json.JSONDecodeError:
                        if key == "metadata":
                            node[key] = {}
            return node
        if isinstance(value, str):
            try:
                parsed = json.loads(value)
            except json.JSONDecodeError:
                return {"value": value}
            return self._node_to_dict(parsed)
        return {"value": value}

    def _merge_decision_outcome(self, row: Dict[str, Any]) -> Dict[str, Any]:
        decision = self._node_to_dict(row.get("d", {}))
        outcome = self._node_to_dict(row.get("o", {}))
        merged = dict(decision)
        merged.update(
            {
                "actual_action": outcome.get("actual_action"),
                "is_correct": outcome.get("is_correct"),
            }
        )
        if "metadata" in outcome:
            merged["outcome_metadata"] = outcome["metadata"]
        return merged

    @staticmethod
    def _int_from_rows(rows: List[Dict[str, Any]], key: str) -> int:
        if not rows:
            return 0
        try:
            return int(rows[0].get(key) or 0)
        except (TypeError, ValueError):
            return 0
