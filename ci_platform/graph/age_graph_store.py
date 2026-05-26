"""GraphStore-compatible adapter for Apache AGE."""

from __future__ import annotations

import asyncio
import json
import re
import threading
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import numpy as np

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
            RETURN count(d) AS cnt
            """
        )
        return self._int_from_rows(rows, "cnt")

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
        rule_name: str = "",
        variant_id: str = "",
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
        """AGE retention is managed externally; no archive count is tracked."""
        return 0

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
