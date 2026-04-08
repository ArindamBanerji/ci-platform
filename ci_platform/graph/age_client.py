"""
ci_platform/graph/age_client.py — Shared AGE/PostgreSQL graph client.

Apache AGE runs openCypher on PostgreSQL.
All copilots (SOC, S2P, fraud, etc.) import from here.
Never duplicate the graph client in domain repos.

Key AGE dialect differences from Neo4j:
  - Queries wrapped in: SELECT * FROM cypher('graph', $$ ... $$) AS (col agtype)
  - Parameters: $name in Cypher body, passed as dict → converted to %s positional
  - Cypher datetime/duration functions NOT supported → use Python datetime/timedelta
  - Return values are agtype (JSONB) → parse with json.loads()
  - MERGE ON CREATE SET → works same as Neo4j

Environment variables:
  DATABASE_URL    = postgresql://user:pass@host:5432/dbname
  AGE_GRAPH_NAME  = soc_graph (default)
  GRAPH_BACKEND   = age | neo4j (default: neo4j during transition)
"""

from __future__ import annotations

import json
import logging
import os
import re
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

GRAPH_NAME = os.getenv("AGE_GRAPH_NAME", "soc_graph")
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://localhost:5432/soc_copilot",
)

# Lazy import — psycopg only required when AGE backend is active
_psycopg = None


def _load_psycopg():
    global _psycopg
    if _psycopg is None:
        try:
            import psycopg  # noqa: F401
            _psycopg = psycopg
        except ImportError:
            raise ImportError(
                "psycopg[async] is required for AGE backend. "
                "Run: pip install 'ci-platform[graph]'"
            )
    return _psycopg


class AGEClient:
    """
    Async graph client for Apache AGE / PostgreSQL.
    Drop-in interface replacement for Neo4jClient.

    All domain copilots (SOC, S2P) use this via:
        from ci_platform.graph import get_graph_client
        graph = get_graph_client()
        results = await graph.run_query(cypher, params)
    """

    def __init__(
        self,
        dsn: Optional[str] = None,
        graph_name: Optional[str] = None,
    ) -> None:
        self._dsn = dsn or DATABASE_URL
        self._graph = graph_name or GRAPH_NAME

    # ── connection ────────────────────────────────────────────────────────────

    @asynccontextmanager
    async def _conn(self):
        """Async context manager: psycopg connection with AGE loaded."""
        psycopg = _load_psycopg()
        conn = await psycopg.AsyncConnection.connect(
            self._dsn,
            autocommit=True,
        )
        try:
            await conn.execute("LOAD 'age'")
            await conn.execute(
                "SET search_path = ag_catalog, '$user', public"
            )
            yield conn
        finally:
            await conn.close()

    # ── graph setup ───────────────────────────────────────────────────────────

    async def ensure_graph(self) -> None:
        """Create AGE graph if it doesn't exist. Idempotent."""
        async with self._conn() as conn:
            try:
                await conn.execute(
                    "SELECT create_graph(%s)", (self._graph,)
                )
                logger.info(f"Created AGE graph: {self._graph}")
            except Exception as e:
                if "already exists" not in str(e).lower():
                    raise

    # ── agtype parsing ────────────────────────────────────────────────────────

    def _parse_agtype(self, val: Any) -> Any:
        """
        Parse an agtype value returned from AGE.
        Nodes/edges: {id, label, properties:{...}} → unwrap to properties.
        Scalars: int, float, bool, str → return as-is.
        """
        if val is None:
            return None
        if isinstance(val, (int, float, bool)):
            return val
        try:
            parsed = json.loads(str(val))
            if isinstance(parsed, dict) and "properties" in parsed:
                props = parsed["properties"]
                if "id" in parsed:
                    props["_age_id"] = parsed["id"]
                return props
            return parsed
        except (json.JSONDecodeError, TypeError):
            return val

    # ── query building ────────────────────────────────────────────────────────

    def _extract_columns(self, cypher: str) -> List[str]:
        """
        Extract column names from the RETURN clause.
        Handles: RETURN n, RETURN n AS node, RETURN count(n) AS cnt
        """
        m = re.search(
            r'RETURN\s+(.+?)(?:\s+LIMIT\s|\s+ORDER\s|\s+SKIP\s|$)',
            cypher,
            re.IGNORECASE | re.DOTALL,
        )
        if not m:
            return ["result"]

        cols: List[str] = []
        for part in m.group(1).split(","):
            part = part.strip()
            if re.search(r'\s+AS\s+', part, re.IGNORECASE):
                alias = re.split(r'\s+AS\s+', part, flags=re.IGNORECASE)[-1].strip()
                cols.append(alias)
            else:
                token = re.split(r'[.()\s]', part)[0].strip()
                cols.append(token if token else "result")
        return cols or ["result"]

    def _build_sql(self, cypher: str, columns: List[str]) -> str:
        """Wrap Cypher in AGE SELECT … FROM cypher() wrapper."""
        as_clause = ", ".join(f'"{c}" agtype' for c in columns)
        return (
            f"SELECT * FROM cypher('{self._graph}', $$\n"
            f"    {cypher}\n"
            f"$$) AS ({as_clause})"
        )

    # ── core query execution ──────────────────────────────────────────────────

    async def run_query(
        self,
        query: str,
        parameters: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Execute a Cypher query against AGE.
        Returns List[Dict] — same shape as Neo4jClient.run_query().

        Parameter substitution:
          Write Cypher with $param_name placeholders.
          Pass parameters={"param_name": value}.
          Converts $name → %s positional for psycopg.

        Timestamp handling:
          Compute timestamps in Python, pass as ISO string parameter.
          AGE does not support the Cypher datetime/duration functions.
        """
        if not query.strip():
            return []

        columns = self._extract_columns(query)
        sql = self._build_sql(query, columns)

        # Convert $name → %s and collect ordered param values
        positional: List[Any] = []
        if parameters:
            def _sub(m: re.Match) -> str:
                positional.append(parameters.get(m.group(1)))
                return "%s"
            sql = re.sub(r'\$(\w+)', _sub, sql)

        async with self._conn() as conn:
            try:
                cur = await conn.execute(
                    sql,
                    positional if positional else None,
                )
                rows = await cur.fetchall()
                results: List[Dict[str, Any]] = []
                for row in rows:
                    row_dict: Dict[str, Any] = {}
                    for i, col in enumerate(columns):
                        raw = row[i] if i < len(row) else None
                        row_dict[col] = self._parse_agtype(raw)
                    results.append(row_dict)
                return results
            except Exception as e:
                logger.error(
                    "AGE query error: %s\nQuery: %.300s\nParams: %s",
                    e, query, parameters,
                )
                raise

    # ── convenience methods (Neo4jClient interface parity) ────────────────────

    async def get_security_context(self, alert_id: str) -> Dict:
        results = await self.run_query(
            """
            MATCH (a:Alert {alert_id: $alert_id})
            OPTIONAL MATCH (a)-[:INVOLVES]->(e:Entity)
            OPTIONAL MATCH (a)-[:PART_OF]->(c:Campaign)
            RETURN a, e, c
            """,
            {"alert_id": alert_id},
        )
        return results[0] if results else {}

    async def get_alert(self, alert_id: str) -> Optional[Dict]:
        results = await self.run_query(
            "MATCH (a:Alert {alert_id: $alert_id}) RETURN a",
            {"alert_id": alert_id},
        )
        return results[0].get("a") if results else None

    async def get_pattern_count(
        self, entity_id: str, action: str
    ) -> int:
        results = await self.run_query(
            """
            MATCH (:Alert)-[r:TRIGGERED_EVOLUTION {action: $action}]->
                  (:Entity {entity_id: $eid})
            RETURN count(r) AS cnt
            """,
            {"eid": entity_id, "action": action},
        )
        try:
            return int(results[0]["cnt"]) if results else 0
        except (TypeError, ValueError):
            return 0

    async def get_sequence_count(
        self, entity_id: str, window_minutes: int = 60
    ) -> int:
        """R2 referral rule. Cutoff computed with Python timedelta."""
        cutoff = (
            datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
        ).isoformat()
        results = await self.run_query(
            """
            MATCH (a:Alert)-[:INVOLVES]->(e:Entity {entity_id: $eid})
            WHERE a.timestamp >= $cutoff
            RETURN count(a) AS cnt
            """,
            {"eid": entity_id, "cutoff": cutoff},
        )
        try:
            return int(results[0]["cnt"]) if results else 0
        except (TypeError, ValueError):
            return 0

    async def get_cross_category_count(
        self, entity_id: str, window_minutes: int = 60
    ) -> int:
        """R7 referral rule. Cutoff computed with Python timedelta."""
        cutoff = (
            datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
        ).isoformat()
        results = await self.run_query(
            """
            MATCH (a:Alert)-[:INVOLVES]->(e:Entity {entity_id: $eid})
            WHERE a.timestamp >= $cutoff
            RETURN count(DISTINCT a.category) AS cnt
            """,
            {"eid": entity_id, "cutoff": cutoff},
        )
        try:
            return int(results[0]["cnt"]) if results else 0
        except (TypeError, ValueError):
            return 0

    async def create_decision_trace(
        self,
        decision_id: str,
        alert_id: str,
        action: str,
        confidence: float,
        category: str,
        factor_vector: Optional[List[float]] = None,
        **kwargs: Any,
    ) -> Dict:
        ts = datetime.now(timezone.utc).isoformat()
        results = await self.run_query(
            """
            MERGE (d:Decision {decision_id: $did})
            ON CREATE SET
                d.alert_id   = $alert_id,
                d.action     = $action,
                d.confidence = $confidence,
                d.category   = $category,
                d.created_at = $ts
            RETURN d
            """,
            {
                "did": decision_id,
                "alert_id": alert_id,
                "action": action,
                "confidence": confidence,
                "category": category,
                "ts": ts,
            },
        )
        return results[0].get("d", {}) if results else {}

    async def create_evolution_event(
        self,
        alert_id: str,
        entity_id: str,
        action: str,
        verified_correct: bool,
        **kwargs: Any,
    ) -> bool:
        ts = datetime.now(timezone.utc).isoformat()
        await self.run_query(
            """
            MATCH (a:Alert  {alert_id:  $aid})
            MATCH (e:Entity {entity_id: $eid})
            MERGE (a)-[r:TRIGGERED_EVOLUTION {action: $action}]->(e)
            ON CREATE SET r.verified_correct = $vc, r.created_at = $ts
            RETURN count(r) AS cnt
            """,
            {
                "aid": alert_id,
                "eid": entity_id,
                "action": action,
                "vc": verified_correct,
                "ts": ts,
            },
        )
        return True

    async def get_recent_evolution_events(
        self, limit: int = 10
    ) -> List[Dict]:
        return await self.run_query(
            """
            MATCH (a:Alert)-[r:TRIGGERED_EVOLUTION]->(e:Entity)
            RETURN a, r, e
            LIMIT $limit
            """,
            {"limit": limit},
        )

    async def log_decision_distance(
        self,
        decision_id: str,
        centroid_distance_to_canonical: float,
        pattern_history_value: float,
        alert_category_distribution: Dict,
    ) -> bool:
        """
        BACKLOG-015 EXP-G1 extension — log per verified decision.
        centroid_distance_to_canonical is the model-independent γ metric.
        """
        ts = datetime.now(timezone.utc).isoformat()
        await self.run_query(
            """
            MERGE (d:DecisionDistanceLog {decision_id: $did})
            ON CREATE SET
                d.centroid_distance_to_canonical = $dist,
                d.pattern_history_value          = $phv,
                d.alert_category_distribution    = $acd,
                d.timestamp                      = $ts
            RETURN d
            """,
            {
                "did": decision_id,
                "dist": float(centroid_distance_to_canonical),
                "phv": float(pattern_history_value),
                "acd": json.dumps(alert_category_distribution),
                "ts": ts,
            },
        )
        return True


# ── module-level singleton + factory ──────────────────────────────────────────

_client: Optional[AGEClient] = None


def get_graph_client(
    dsn: Optional[str] = None,
    graph_name: Optional[str] = None,
) -> AGEClient:
    """
    Return the shared AGEClient singleton.

    Usage in any copilot:
        from ci_platform.graph import get_graph_client
        graph = get_graph_client()
        results = await graph.run_query(cypher, params)

    During Block 8.5 transition in SOC repo:
        from ci_platform.graph import get_graph_client as _age_factory
        # Replaces: from backend.app.db.neo4j import neo4j_client
        neo4j_client = _age_factory()
    """
    global _client
    if _client is None:
        _client = AGEClient(dsn=dsn, graph_name=graph_name)
    return _client
