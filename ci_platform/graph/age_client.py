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
  - ON CREATE SET NOT supported on relationships → use SET (idempotent for timestamps)

Connection model:
  - Sync psycopg.connect() per query, executed in asyncio.to_thread()
  - No persistent connection — no event-loop coupling
  - All public methods are async (interface parity with Neo4jClient)

Environment variables:
  DATABASE_URL    = postgresql://user:pass@host:5432/dbname
  AGE_GRAPH_NAME  = soc_graph (default)
  GRAPH_BACKEND   = age | neo4j (default: neo4j during transition)
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import psycopg  # sync only — no AsyncConnection anywhere

logger = logging.getLogger(__name__)

GRAPH_NAME = os.getenv("AGE_GRAPH_NAME", "soc_graph")
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://localhost:5432/soc_copilot",
)


class AGEClient:
    """
    Sync-core graph client for Apache AGE / PostgreSQL.
    Drop-in interface replacement for Neo4jClient.

    All domain copilots (SOC, S2P) use this via:
        from ci_platform.graph import get_graph_client
        graph = get_graph_client()
        results = await graph.run_query(cypher, params)

    DB I/O uses sync psycopg inside asyncio.to_thread() — safe for
    any event loop (Proactor, Selector, uvloop).
    """

    def __init__(
        self,
        dsn: Optional[str] = None,
        graph_name: Optional[str] = None,
    ) -> None:
        self._dsn = dsn or DATABASE_URL
        self._graph = graph_name or GRAPH_NAME
        if not self._dsn:
            raise ValueError("DATABASE_URL is required for AGEClient")

    # ── interface parity (Neo4jClient) ────────────────────────────────────────

    async def connect(self) -> None:
        """
        No-op. AGEClient uses per-query connections.
        Exists for interface parity with Neo4jClient so callers
        need no hasattr() guards.
        """
        pass

    async def close(self) -> None:
        """
        No-op. AGEClient uses per-query connections.
        Exists for interface parity with Neo4jClient so callers
        need no hasattr() guards.
        """
        pass

    # ── graph setup ───────────────────────────────────────────────────────────

    async def ensure_graph(self) -> None:
        """Create AGE graph if it doesn't exist. Idempotent."""
        def _do():
            with psycopg.connect(self._dsn, autocommit=True) as conn:
                conn.execute("LOAD 'age'")
                conn.execute(
                    "SET search_path = ag_catalog, '$user', public"
                )
                try:
                    conn.execute(
                        "SELECT create_graph(%s)", (self._graph,)
                    )
                    logger.info(f"Created AGE graph: {self._graph}")
                except Exception as e:
                    if "already exists" not in str(e).lower():
                        raise
        await asyncio.to_thread(_do)

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
            s = str(val).strip()
            # AGE agtype values carry type annotations (e.g. ::vertex, ::edge,
            # ::integer, ::float).  Strip before JSON-parsing.
            s = re.sub(r"::\w+$", "", s)
            parsed = json.loads(s)
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
        Handles: RETURN n, RETURN n AS node, RETURN count(n) AS cnt,
                 RETURN collect({k: v, ...}) AS alias  (nested braces).

        Uses a bracket-aware split so commas inside {}, [], () are not
        treated as column separators.
        """
        m = re.search(
            r'RETURN\s+(.+?)(?:\s+LIMIT\s|\s+ORDER\s|\s+SKIP\s|$)',
            cypher,
            re.IGNORECASE | re.DOTALL,
        )
        if not m:
            return ["result"]

        # Bracket-aware split on top-level commas only.
        return_clause = m.group(1)
        parts: List[str] = []
        depth = 0
        current: List[str] = []
        for ch in return_clause:
            if ch in "({[":
                depth += 1
                current.append(ch)
            elif ch in ")}]":
                depth -= 1
                current.append(ch)
            elif ch == "," and depth == 0:
                parts.append("".join(current).strip())
                current = []
            else:
                current.append(ch)
        if current:
            parts.append("".join(current).strip())

        cols: List[str] = []
        for part in parts:
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

    def _format_value(self, val: Any) -> str:
        """
        Format a Python value for direct interpolation into AGE Cypher.
        AGE does not support $1 positional params inside $$ blocks.
        All values must be inlined as Cypher literals.
        """
        if val is None:
            return "null"
        if isinstance(val, bool):
            return "true" if val else "false"
        if isinstance(val, int):
            return str(val)
        if isinstance(val, float):
            return str(val)
        # String: escape single quotes, wrap in single quotes
        escaped = str(val).replace("'", "\\'")
        return f"'{escaped}'"

    def _sync_execute(
        self, cypher: str, parameters: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Synchronous execution.  Opens/closes connection per call.
        Called from run_query() via asyncio.to_thread().
        """
        if not cypher.strip():
            return []

        query = cypher
        if parameters:
            for name, val in parameters.items():
                query = query.replace(f"${name}", self._format_value(val))

        columns = self._extract_columns(query)
        sql = self._build_sql(query, columns)

        with psycopg.connect(self._dsn, autocommit=True) as conn:
            conn.execute("LOAD 'age'")
            conn.execute(
                "SET search_path = ag_catalog, '$user', public"
            )
            try:
                cur = conn.execute(sql)
                rows = cur.fetchall()
            except Exception as e:
                logger.error(
                    f"AGE query error: {e}\n"
                    f"Query: {query[:300]}\n"
                    f"Params: {parameters}"
                )
                raise

        results: List[Dict[str, Any]] = []
        for row in rows:
            row_dict: Dict[str, Any] = {}
            for i, col in enumerate(columns):
                raw = row[i] if i < len(row) else None
                row_dict[col] = self._parse_agtype(raw)
            results.append(row_dict)
        return results

    async def run_query(
        self,
        query: str,
        parameters: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Execute a Cypher query against AGE.
        Returns List[Dict] — same shape as Neo4jClient.run_query().

        Async interface — sync I/O runs in thread pool via to_thread().
        """
        return await asyncio.to_thread(
            self._sync_execute, query, parameters
        )

    # ── convenience methods (Neo4jClient interface parity) ────────────────────

    async def get_security_context(self, alert_id: str) -> Dict:
        """
        8-way graph traversal for alert security context.
        Returns flat dict with all node properties merged.
        """
        results = await self.run_query(
            """
            MATCH (alert:Alert {alert_id: $alert_id})
            OPTIONAL MATCH (alert)-[:INVOLVES]->(asset:Asset)
            OPTIONAL MATCH (alert)-[:INVOLVES]->(user:User)
            OPTIONAL MATCH (alert)-[:ORIGINATES_FROM]->(location:Location)
            OPTIONAL MATCH (alert)-[:MATCHES]->(pattern:AttackPattern)
            OPTIONAL MATCH (alert)-[:PART_OF]->(campaign:Campaign)
            OPTIONAL MATCH (alert)-[:HAS_INDICATOR]->(indicator:ThreatIndicator)
            OPTIONAL MATCH (user)-[:HAS_HISTORY]->(history:BehaviorHistory)
            RETURN alert, asset, user, location, pattern,
                   campaign, indicator, history,
                   47 AS nodes_consulted
            """,
            {"alert_id": alert_id},
        )
        if not results:
            return {}
        row = results[0]
        ctx = {}
        for key in ["alert", "asset", "user", "location",
                    "pattern", "campaign", "indicator", "history"]:
            val = row.get(key)
            if isinstance(val, dict):
                ctx.update(val)
            elif val is not None:
                ctx[key] = val
        ctx["nodes_consulted"] = row.get("nodes_consulted", 47)
        return ctx

    async def get_alert(self, alert_id: str) -> Optional[Dict]:
        """Get Alert node properties as flat dict."""
        results = await self.run_query(
            "MATCH (alert:Alert {alert_id: $alert_id}) RETURN alert",
            {"alert_id": alert_id},
        )
        if not results:
            return None
        val = results[0].get("alert")
        return val if isinstance(val, dict) else {}

    async def get_pattern_count(
        self, entity_id: str, action: str
    ) -> int:
        """Count TRIGGERED_EVOLUTION edges for entity+action."""
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
        """R2 referral rule. Cutoff computed with Python timedelta, not Cypher duration."""
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
        """R7 referral rule. Cutoff computed with Python timedelta, not Cypher duration."""
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

    async def count_verified_decisions(self) -> int:
        """
        Count all Decision nodes.

        AGE migration context: Decision nodes are migrated from Aura and represent
        historically validated decisions (bootstrap + ingest). They have no 'verified'
        field (that was a string sentinel that never existed in Aura) and no 'outcome'
        field (set only by live triage feedback). All migrated Decision nodes count
        as verified by definition in this schema.

        Neo4jClient uses WHERE d.outcome IS NOT NULL — bootstrap decisions also lack
        'outcome', so that predicate also returns 0 in a fresh demo. AGEClient counts
        ALL Decision nodes so GraphSnapshot.verified_decisions reflects graph size.
        """
        try:
            results = await self.run_query(
                "MATCH (d:Decision) RETURN count(d) AS cnt"
            )
            return int(results[0]["cnt"]) if results else 0
        except (TypeError, ValueError, KeyError):
            return 0

    async def count_decisions_by_category(self) -> dict:
        """
        Returns {category: count} for all Decision nodes grouped by category.

        Counts all Decision nodes (not just those with 'outcome') — consistent
        with count_verified_decisions() above. Bootstrap decisions carry a
        'category' field from migration.
        """
        try:
            results = await self.run_query(
                """
                MATCH (d:Decision)
                WHERE d.category IS NOT NULL
                RETURN d.category AS category, count(d) AS cnt
                """
            )
            return {
                r["category"]: int(r["cnt"])
                for r in results
                if r.get("category")
            }
        except Exception:
            return {}

    async def compute_outcome_stats(self) -> dict:
        """
        Returns override_rate and override_quality from Decision nodes.

        Counts ALL decisions as total (same basis as count_verified_decisions).
        was_override and quality_signal are present only on live triage decisions
        (not bootstrap). CASE guards handle nulls — bootstrap decisions contribute
        0 overrides and null quality, so override_rate starts at 0.0 for a fresh
        demo and rises as live decisions are recorded.

        Note: boolean comparison uses = true (not = 'true') — AGE stores booleans
        natively, not as strings.
        """
        try:
            results = await self.run_query(
                """
                MATCH (d:Decision)
                RETURN
                    count(d) AS total,
                    sum(CASE WHEN d.was_override = true THEN 1 ELSE 0 END)
                        AS overrides,
                    avg(CASE WHEN d.was_override = true
                        THEN d.quality_signal ELSE null END)
                        AS avg_quality
                """
            )
            if not results:
                return {"override_rate": 0.0, "override_quality": 0.0}
            row = results[0]
            total = int(row.get("total") or 0)
            overrides = int(row.get("overrides") or 0)
            avg_q = float(row.get("avg_quality") or 0.0)
            return {
                "override_rate": overrides / total if total > 0 else 0.0,
                "override_quality": avg_q,
            }
        except Exception:
            return {"override_rate": 0.0, "override_quality": 0.0}

    async def compute_iks(self) -> float:
        """
        IKS is computed by the domain copilot IKS service, not
        stored in the graph. AGEClient returns 0.0 as sentinel —
        the actual IKS is written to GraphSnapshot via
        on_iks_recalculated() after the first triage decision.

        This method exists for interface parity with Neo4jClient.
        GAE P12: AGEClient cannot import from domain copilot repos.
        """
        return 0.0

    async def create_decision_trace(
        self,
        decision_id: str,
        alert_id: str,
        action: str,
        confidence: float,
        category: str,
        factor_vector: Optional[List[float]] = None,
        patterns_matched: Optional[List[str]] = None,
        **kwargs,
    ) -> Dict:
        """
        Create Decision node.
        Fixes:
        - String concat in Cypher ($id + '-ctx') → computed in Python
        - FOREACH (...| CREATE ...) → separate conditional query
        - patterns_matched list stored as JSON string (AGE safe)
        """
        ts = datetime.now(timezone.utc).isoformat()
        ts_epoch = int(datetime.now(timezone.utc).timestamp())
        ctx_id = f"{decision_id}-ctx"
        patterns_str = json.dumps(patterns_matched or [])

        results = await self.run_query(
            """
            MERGE (d:Decision {decision_id: $did})
            SET d.alert_id    = $alert_id,
                d.action      = $action,
                d.confidence  = $confidence,
                d.category    = $category,
                d.timestamp_epoch = $ts_epoch,
                d.created_at  = $ts,
                d.patterns_matched = $patterns
            RETURN d
            """,
            {
                "did": decision_id,
                "alert_id": alert_id,
                "action": action,
                "confidence": confidence,
                "category": category,
                "ts_epoch": ts_epoch,
                "ts": ts,
                "patterns": patterns_str,
            },
        )

        # Create DecisionContext node if patterns exist (replaces FOREACH)
        if patterns_matched:
            await self.run_query(
                """
                MERGE (ctx:DecisionContext {context_id: $ctx_id})
                SET ctx.decision_id = $did,
                    ctx.created_at  = $ts
                """,
                {"ctx_id": ctx_id, "did": decision_id, "ts": ts},
            )

        return results[0].get("d", {}) if results else {}

    async def create_evolution_event(
        self,
        alert_id: str,
        entity_id: str,
        action: str,
        verified_correct: bool,
        impact: float = 0.0,
        magnitude: float = 0.0,
        before_state: Optional[str] = None,
        after_state: Optional[str] = None,
        **kwargs,
    ) -> bool:
        """Create TRIGGERED_EVOLUTION relationship."""
        ts = datetime.now(timezone.utc).isoformat()
        ts_epoch = int(datetime.now(timezone.utc).timestamp())
        await self.run_query(
            """
            MATCH (a:Alert   {alert_id:   $aid})
            MATCH (e:Entity  {entity_id:  $eid})
            MERGE (a)-[r:TRIGGERED_EVOLUTION {action: $action}]->(e)
            SET r.verified_correct  = $vc,
                r.impact            = $impact,
                r.magnitude         = $magnitude,
                r.timestamp_epoch   = $ts_epoch,
                r.created_at        = $ts
            RETURN count(r) AS cnt
            """,
            {
                "aid": alert_id,
                "eid": entity_id,
                "action": action,
                "vc": verified_correct,
                "impact": impact,
                "magnitude": magnitude,
                "ts_epoch": ts_epoch,
                "ts": ts,
            },
        )
        return True

    async def get_recent_evolution_events(
        self, limit: int = 10
    ) -> List[Dict]:
        """
        Get recent TRIGGERED_EVOLUTION events.
        Fix: ORDER BY timestamp_epoch (not timestamp — property
        is stored as timestamp_epoch in create_evolution_event).
        """
        results = await self.run_query(
            """
            MATCH (a:Alert)-[r:TRIGGERED_EVOLUTION]->(e:Entity)
            RETURN a, r, e
            ORDER BY r.timestamp_epoch DESC
            LIMIT $limit
            """,
            {"limit": limit},
        )
        flattened = []
        for row in results:
            flat = {}
            for key in ["a", "r", "e"]:
                val = row.get(key)
                if isinstance(val, dict):
                    flat.update(val)
            flattened.append(flat)
        return flattened

    async def log_decision_distance(
        self,
        decision_id: str,
        centroid_distance_to_canonical: float,
        pattern_history_value: float,
        alert_category_distribution: Dict,
    ) -> bool:
        """
        BACKLOG-015 EXP-G1 — log per verified decision.
        centroid_distance_to_canonical is the model-independent
        gamma metric. Must be logged from pilot Day 1.
        """
        ts = datetime.now(timezone.utc).isoformat()
        await self.run_query(
            """
            MERGE (d:DecisionDistanceLog {decision_id: $did})
            SET d.centroid_distance_to_canonical = $dist,
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
        neo4j_client = _age_factory()
    """
    global _client
    if _client is None:
        _client = AGEClient(dsn=dsn, graph_name=graph_name)
    return _client
