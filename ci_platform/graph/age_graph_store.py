"""GraphStore-compatible adapter for Apache AGE."""

from __future__ import annotations

import asyncio
import json
import threading
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from ci_platform.graph.age_client import AGEClient


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

    def _run_query(self, cypher: str) -> List[Dict[str, Any]]:
        return self._run(self._client.run_query(cypher, None)) or []

    def write_decision(
        self,
        entity_id: str,
        category: str,
        action: str,
        confidence: float,
        factors: Dict[str, Any],
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        decision_id = f"DEC-{uuid.uuid4().hex[:8]}"
        confidence_value = float(confidence)
        factors_json = json.dumps(factors or {}, sort_keys=True)
        metadata_json = json.dumps(metadata or {}, sort_keys=True)

        props = self._decision_props(
            decision_id,
            entity_id,
            category,
            action,
            confidence_value,
            factors_json,
            metadata_json,
        )
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

    def _decision_props(
        self,
        decision_id: str,
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
        metadata_json = json.dumps(metadata or {}, sort_keys=True)
        query = f"""
        MATCH (d:Decision {{decision_id: {self._S(decision_id)}}})
        WITH d LIMIT 1
        CREATE (o:Outcome {{
            decision_id: {self._S(decision_id)},
            actual_action: {self._S(actual_action)},
            is_correct: {str(bool(is_correct)).lower()},
            metadata: {self._S(metadata_json)}
        }})
        CREATE (d)-[:HAS_OUTCOME]->(o)
        RETURN o
        """
        self._run_query(query)

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
        self, category: Optional[str] = None, limit: int = 400
    ) -> List[Dict[str, Any]]:
        limit_value = self._safe_limit(limit)
        where_clause = (
            f"WHERE d.category = {self._S(category)}"
            if category is not None
            else ""
        )
        rows = self._run_query(
            f"""
            MATCH (d:Decision)
            {where_clause}
            RETURN d
            LIMIT {limit_value}
            """
        )
        return [self._node_to_dict(row.get("d", row)) for row in rows]

    def get_verified_decisions(self) -> List[Dict[str, Any]]:
        rows = self._run_query(
            """
            MATCH (d:Decision)-[:HAS_OUTCOME]->(o:Outcome)
            RETURN d, o
            """
        )
        return [self._merge_decision_outcome(row) for row in rows]

    def count_verified(self) -> int:
        rows = self._run_query(
            """
            MATCH (d:Decision)-[:HAS_OUTCOME]->(o:Outcome)
            RETURN count(o) AS cnt
            """
        )
        return self._int_from_rows(rows, "cnt")

    def count_correct(self) -> int:
        rows = self._run_query(
            """
            MATCH (d:Decision)-[:HAS_OUTCOME]->(o:Outcome)
            WHERE o.is_correct = true
            RETURN count(o) AS cnt
            """
        )
        return self._int_from_rows(rows, "cnt")

    def get_all_decisions(self) -> List[Dict[str, Any]]:
        return self.get_decisions()

    def save_centroids(
        self,
        decision_id: str,
        category: str,
        centroids: Any,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        if hasattr(centroids, "tolist"):
            centroids = centroids.tolist()
        centroids_json = json.dumps(centroids, sort_keys=True)
        metadata_json = json.dumps(metadata or {}, sort_keys=True)
        created_at = datetime.now(timezone.utc).isoformat()
        props = (
            "{"
            f"decision_id: {self._S(decision_id)}, "
            f"category: {self._S(category)}, "
            f"centroids: {self._S(centroids_json)}, "
            f"metadata: {self._S(metadata_json)}, "
            f"created_at: {self._S(created_at)}"
            "}"
        )
        query = f"""
        MATCH (d:Decision {{decision_id: {self._S(decision_id)}}})
        WITH d LIMIT 1
        CREATE (c:CentroidCheckpoint {props})
        CREATE (d)-[:HAS_CENTROID_CHECKPOINT]->(c)
        RETURN c
        """
        rows = self._run_query(query)
        if not rows:
            self._run_query(f"CREATE (c:CentroidCheckpoint {props}) RETURN c")

    def save_evolution_event(
        self,
        event_type: str,
        rule_name: str,
        variant_id: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        metadata_json = json.dumps(metadata or {}, sort_keys=True)
        timestamp = datetime.now(timezone.utc).isoformat()
        props = (
            "{"
            f"event_type: {self._S(event_type)}, "
            f"rule_name: {self._S(rule_name)}, "
            f"variant_id: {self._S(variant_id)}, "
            f"metadata: {self._S(metadata_json)}, "
            f"timestamp: {self._S(timestamp)}"
            "}"
        )
        self._run_query(f"CREATE (e:EvolutionEvent {props}) RETURN e")

    def get_centroid_checkpoints(self, limit: int = 50) -> List[Dict[str, Any]]:
        limit_value = self._safe_limit(limit, default=50)
        rows = self._run_query(
            f"""
            MATCH (c:CentroidCheckpoint)
            RETURN c
            ORDER BY c.created_at DESC
            LIMIT {limit_value}
            """
        )
        checkpoints = [self._node_to_dict(row.get("c", row)) for row in rows]
        return list(reversed(checkpoints))

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
            for key in ("factors", "metadata", "centroids"):
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
