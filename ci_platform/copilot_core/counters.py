"""Materialized entity-property counters for copilot hot paths.

Counters are AGE-authoritative read models stored on existing entity nodes.
They are not proof authority until parity proof promotes them. Counter
mutations are designed to run inside the same AGE transaction as the decision
and audit writes that they summarize.
"""

from __future__ import annotations

import inspect
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping, Optional, Protocol, cast


# Infrastructure default only. Store mutation methods intentionally do not
# enforce this flag; route adoption must gate materialized-counter reads/writes
# until live AGE and parity proof promote counters for that route.
USE_MATERIALIZED_COUNTERS = (
    os.getenv("USE_MATERIALIZED_COUNTERS", "").strip().lower()
    in {"1", "true", "yes", "on"}
)

_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _identifier(value: str, field_name: str) -> str:
    if not isinstance(value, str) or not _IDENTIFIER_RE.fullmatch(value):
        raise ValueError(f"Invalid Cypher identifier for {field_name}: {value!r}")
    return value


def _first_int(rows: list[dict[str, Any]], *names: str) -> Optional[int]:
    if not rows:
        return None
    row = rows[0]
    for name in names:
        if name in row and row[name] is not None:
            try:
                return int(row[name])
            except (TypeError, ValueError):
                return None
    for value in row.values():
        if value is not None:
            try:
                return int(value)
            except (TypeError, ValueError):
                continue
    return None


def _first_bool(rows: list[dict[str, Any]], name: str) -> bool:
    if not rows:
        return False
    value = rows[0].get(name)
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"true", "1", "yes"}
    return bool(value)


@dataclass(frozen=True)
class CounterDef:
    """A v3.2 entity-property counter definition."""

    domain: str
    node_label: str
    key_prop: str
    key_value: str
    counter_prop: str
    trigger: str = "decision"
    mode: str = "cumulative"
    population: str = "observed"
    distinct_label: Optional[str] = None
    distinct_key_prop: Optional[str] = None
    edge_label: Optional[str] = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.mode not in {"cumulative", "distinct"}:
            raise ValueError("CounterDef.mode must be cumulative or distinct")
        if self.trigger not in {"decision", "outcome"}:
            raise ValueError("CounterDef.trigger must be decision or outcome")
        if self.population not in {"observed", "verified"}:
            raise ValueError("CounterDef.population must be observed or verified")
        for field_name in ("domain", "key_value"):
            if not str(getattr(self, field_name, "")).strip():
                raise ValueError(f"CounterDef.{field_name} must be non-empty")
        _identifier(self.node_label, "node_label")
        _identifier(self.key_prop, "key_prop")
        _identifier(self.counter_prop, "counter_prop")
        if self.mode == "distinct":
            if not self.distinct_label or not self.distinct_key_prop or not self.edge_label:
                raise ValueError(
                    "Distinct counters require distinct_label, distinct_key_prop, and edge_label"
                )
            _identifier(self.distinct_label, "distinct_label")
            _identifier(self.distinct_key_prop, "distinct_key_prop")
            _identifier(self.edge_label, "edge_label")

    @property
    def lock_key(self) -> str:
        return (
            f"{self.domain}:{self.node_label}:{self.key_prop}:"
            f"{self.key_value}:counters"
        )


@dataclass(frozen=True)
class CounterKey:
    """Legacy logical key retained for non-authoritative helper compatibility.

    v3.2 route-authoritative counters use CounterDef entity properties instead.
    """

    domain: str
    name: str
    scope: str = "global"

    @property
    def value(self) -> str:
        return f"{self.domain}:{self.name}:{self.scope}"


@dataclass(frozen=True)
class CounterRead:
    key: str
    value: int
    found: bool
    trusted: bool
    source: str
    status: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class CounterReconciliation:
    key: str
    counter_value: Optional[int]
    graph_truth_value: int
    status: str
    updated: bool
    read: CounterRead


@dataclass(frozen=True)
class CounterStatus:
    enabled: bool
    backend: str
    connection_mode: Optional[str] = None
    pool_available: Optional[bool] = None
    fallback: str = "graph_truth"


class CounterStore(Protocol):
    async def read_counter(self, counter: CounterDef) -> CounterRead:
        ...

    async def increment_cumulative(
        self, counter: CounterDef, delta: int = 1
    ) -> CounterRead:
        ...

    async def increment_distinct(
        self, counter: CounterDef, distinct_key_value: str
    ) -> CounterRead:
        ...

    async def reconcile_counter(
        self,
        counter: CounterDef,
        graph_truth_query: str,
        parameters: Optional[Mapping[str, Any]] = None,
    ) -> CounterReconciliation:
        ...

    def get_status(self) -> CounterStatus:
        ...


class AGECounterStore:
    """AGE implementation of v3.2 entity-property counters."""

    def __init__(
        self,
        graph_client: Any,
        *,
        enabled: bool = True,
        source: str = "copilot_core.counter_store",
    ) -> None:
        self._graph = graph_client
        self._enabled = bool(enabled)
        self._source = source

    def get_status(self) -> CounterStatus:
        return CounterStatus(
            enabled=self._enabled and USE_MATERIALIZED_COUNTERS,
            backend="age",
            connection_mode=getattr(self._graph, "connection_mode", None),
            pool_available=getattr(self._graph, "pool_available", None),
        )

    def advisory_lock_sql(self, counter: CounterDef) -> tuple[str, tuple[str]]:
        return "SELECT pg_advisory_xact_lock(hashtext(%s))", (counter.lock_key,)

    def _lock_entity_counters(self, tx: Any, counter: CounterDef) -> None:
        sql, params = self.advisory_lock_sql(counter)
        tx.execute_sql(sql, params)

    async def read_counter(self, counter: CounterDef) -> CounterRead:
        label = _identifier(counter.node_label, "node_label")
        key_prop = _identifier(counter.key_prop, "key_prop")
        counter_prop = _identifier(counter.counter_prop, "counter_prop")
        rows = await self._graph.run_query(
            f"""
            MATCH (n:{label} {{{key_prop}: $key_value}})
            RETURN n.{counter_prop} AS value,
                   n.{counter_prop}_last_reconciled AS last_reconciled,
                   n.{counter_prop}_updated_at AS updated_at
            """,
            {"key_value": counter.key_value},
        )
        if not rows:
            return CounterRead(
                key=counter.lock_key,
                value=0,
                found=False,
                trusted=False,
                source="entity_property",
                status="missing_entity",
            )
        value = _first_int(rows, "value")
        if value is None:
            return CounterRead(
                key=counter.lock_key,
                value=0,
                found=True,
                trusted=False,
                source="entity_property",
                status="missing_property",
                metadata=dict(rows[0]),
            )
        return CounterRead(
            key=counter.lock_key,
            value=value,
            found=True,
            trusted=True,
            source="entity_property",
            status="materialized_property",
            metadata=dict(rows[0]),
        )

    async def increment_cumulative(
        self, counter: CounterDef, delta: int = 1
    ) -> CounterRead:
        if counter.mode != "cumulative":
            raise ValueError("increment_cumulative requires a cumulative CounterDef")

        def operation(tx: Any) -> CounterRead:
            self.increment_cumulative_in_tx(tx, counter, delta)
            return self.read_counter_in_tx(tx, counter)

        result = self._graph.run_transaction(operation)
        if inspect.isawaitable(result):
            return cast(CounterRead, await result)
        return cast(CounterRead, result)

    def increment_cumulative_in_tx(
        self, tx: Any, counter: CounterDef, delta: int = 1
    ) -> None:
        if counter.mode != "cumulative":
            raise ValueError("increment_cumulative_in_tx requires cumulative mode")
        self._lock_entity_counters(tx, counter)
        label = _identifier(counter.node_label, "node_label")
        key_prop = _identifier(counter.key_prop, "key_prop")
        counter_prop = _identifier(counter.counter_prop, "counter_prop")
        now = _utc_now_iso()
        rows = tx.run_cypher(
            f"""
            MATCH (n:{label} {{{key_prop}: $key_value}})
            SET n.{counter_prop} =
                    CASE WHEN n.{counter_prop} IS NULL
                         THEN $delta
                         ELSE n.{counter_prop} + $delta END,
                n.{counter_prop}_updated_at = $updated_at,
                n.{counter_prop}_source = $source
            RETURN n.{counter_prop} AS value
            """,
            {
                "key_value": counter.key_value,
                "delta": int(delta),
                "updated_at": now,
                "source": self._source,
            },
        )
        if not rows:
            raise ValueError(
                f"Counter entity not found: {counter.node_label}."
                f"{counter.key_prop}={counter.key_value}"
            )

    async def increment_distinct(
        self, counter: CounterDef, distinct_key_value: str
    ) -> CounterRead:
        if counter.mode != "distinct":
            raise ValueError("increment_distinct requires a distinct CounterDef")

        def operation(tx: Any) -> CounterRead:
            self.increment_distinct_in_tx(tx, counter, distinct_key_value)
            return self.read_counter_in_tx(tx, counter)

        result = self._graph.run_transaction(operation)
        if inspect.isawaitable(result):
            return cast(CounterRead, await result)
        return cast(CounterRead, result)

    def increment_distinct_in_tx(
        self,
        tx: Any,
        counter: CounterDef,
        distinct_key_value: str,
    ) -> None:
        if counter.mode != "distinct":
            raise ValueError("increment_distinct_in_tx requires distinct mode")
        if not distinct_key_value:
            raise ValueError("distinct_key_value must be non-empty")
        self._lock_entity_counters(tx, counter)
        label = _identifier(counter.node_label, "node_label")
        key_prop = _identifier(counter.key_prop, "key_prop")
        counter_prop = _identifier(counter.counter_prop, "counter_prop")
        distinct_label = _identifier(counter.distinct_label or "", "distinct_label")
        distinct_key_prop = _identifier(
            counter.distinct_key_prop or "", "distinct_key_prop"
        )
        edge_label = _identifier(counter.edge_label or "", "edge_label")
        exists_rows = tx.run_cypher(
            f"""
            MATCH (n:{label} {{{key_prop}: $key_value}})
            MATCH (d:{distinct_label} {{{distinct_key_prop}: $distinct_key_value}})
            OPTIONAL MATCH (n)-[e:{edge_label}]->(d)
            RETURN e IS NOT NULL AS edge_exists
            """,
            {
                "key_value": counter.key_value,
                "distinct_key_value": distinct_key_value,
            },
        )
        if not exists_rows:
            raise ValueError(
                "Distinct counter entity or distinct node not found: "
                f"{counter.node_label}/{counter.distinct_label}"
            )
        if not _first_bool(exists_rows, "edge_exists"):
            tx.run_cypher(
                f"""
                MATCH (n:{label} {{{key_prop}: $key_value}})
                MATCH (d:{distinct_label} {{{distinct_key_prop}: $distinct_key_value}})
                CREATE (n)-[:{edge_label}]->(d)
                RETURN 1 AS created
                """,
                {
                    "key_value": counter.key_value,
                    "distinct_key_value": distinct_key_value,
                },
            )
        count_rows = tx.run_cypher(
            f"""
            MATCH (n:{label} {{{key_prop}: $key_value}})-[:{edge_label}]->(d:{distinct_label})
            RETURN count(d) AS value
            """,
            {"key_value": counter.key_value},
        )
        value = _first_int(count_rows, "value")
        if value is None:
            raise ValueError("Distinct counter count query did not return an integer")
        now = _utc_now_iso()
        tx.run_cypher(
            f"""
            MATCH (n:{label} {{{key_prop}: $key_value}})
            SET n.{counter_prop} = $value,
                n.{counter_prop}_updated_at = $updated_at,
                n.{counter_prop}_source = $source
            RETURN n.{counter_prop} AS value
            """,
            {
                "key_value": counter.key_value,
                "value": value,
                "updated_at": now,
                "source": self._source,
            },
        )

    def read_counter_in_tx(self, tx: Any, counter: CounterDef) -> CounterRead:
        label = _identifier(counter.node_label, "node_label")
        key_prop = _identifier(counter.key_prop, "key_prop")
        counter_prop = _identifier(counter.counter_prop, "counter_prop")
        rows = tx.run_cypher(
            f"""
            MATCH (n:{label} {{{key_prop}: $key_value}})
            RETURN n.{counter_prop} AS value,
                   n.{counter_prop}_last_reconciled AS last_reconciled,
                   n.{counter_prop}_updated_at AS updated_at
            """,
            {"key_value": counter.key_value},
        )
        if not rows:
            return CounterRead(
                key=counter.lock_key,
                value=0,
                found=False,
                trusted=False,
                source="entity_property",
                status="missing_entity",
            )
        value = _first_int(rows, "value")
        if value is None:
            return CounterRead(
                key=counter.lock_key,
                value=0,
                found=True,
                trusted=False,
                source="entity_property",
                status="missing_property",
                metadata=dict(rows[0]),
            )
        return CounterRead(
            key=counter.lock_key,
            value=value,
            found=True,
            trusted=True,
            source="entity_property",
            status="materialized_property",
            metadata=dict(rows[0]),
        )

    async def reconcile_counter(
        self,
        counter: CounterDef,
        graph_truth_query: str,
        parameters: Optional[Mapping[str, Any]] = None,
    ) -> CounterReconciliation:
        truth_rows = await self._graph.run_query(
            graph_truth_query, dict(parameters or {})
        )
        graph_truth = _first_int(truth_rows, "cnt", "count", "value", "total")
        if graph_truth is None:
            raise ValueError("graph_truth_query did not return an integer count")

        before = await self.read_counter(counter)

        def operation(tx: Any) -> CounterRead:
            self._lock_entity_counters(tx, counter)
            self.set_counter_property_in_tx(
                tx,
                counter,
                graph_truth,
                reconciliation_status="reconciled_match"
                if before.found and before.value == graph_truth
                else "reconciled_corrected",
            )
            return self.read_counter_in_tx(tx, counter)

        result = self._graph.run_transaction(operation)
        read = await result if inspect.isawaitable(result) else result
        return CounterReconciliation(
            key=counter.lock_key,
            counter_value=before.value if before.found else None,
            graph_truth_value=graph_truth,
            status="reconciled_match"
            if before.found and before.value == graph_truth
            else "reconciled_corrected",
            updated=not (before.found and before.value == graph_truth),
            read=read,
        )

    def set_counter_property_in_tx(
        self,
        tx: Any,
        counter: CounterDef,
        value: int,
        *,
        reconciliation_status: str,
    ) -> None:
        label = _identifier(counter.node_label, "node_label")
        key_prop = _identifier(counter.key_prop, "key_prop")
        counter_prop = _identifier(counter.counter_prop, "counter_prop")
        now = _utc_now_iso()
        rows = tx.run_cypher(
            f"""
            MATCH (n:{label} {{{key_prop}: $key_value}})
            SET n.{counter_prop} = $value,
                n.{counter_prop}_last_reconciled = $last_reconciled,
                n.{counter_prop}_reconciliation_status = $reconciliation_status,
                n.{counter_prop}_source = $source
            RETURN n.{counter_prop} AS value
            """,
            {
                "key_value": counter.key_value,
                "value": int(value),
                "last_reconciled": now,
                "reconciliation_status": reconciliation_status,
                "source": f"{self._source}.reconcile",
            },
        )
        if not rows:
            raise ValueError(
                f"Counter entity not found: {counter.node_label}."
                f"{counter.key_prop}={counter.key_value}"
            )

    async def get_counter_or_graph_truth(
        self,
        counter: CounterDef,
        graph_truth_query: str,
        parameters: Optional[Mapping[str, Any]] = None,
    ) -> CounterRead:
        read = await self.read_counter(counter)
        if read.trusted:
            return read
        rows = await self._graph.run_query(graph_truth_query, dict(parameters or {}))
        truth = _first_int(rows, "cnt", "count", "value", "total")
        if truth is None:
            raise ValueError("graph_truth_query did not return an integer count")
        return CounterRead(
            key=counter.lock_key,
            value=truth,
            found=False,
            trusted=True,
            source="graph_truth_fallback",
            status="fallback_missing_entity_or_property",
            metadata={"counter_status": read.status},
        )


def soc_sequence_counter_def(
    entity_key: str,
    *,
    node_label: str = "User",
    key_prop: str = "id",
) -> CounterDef:
    return CounterDef(
        domain="soc",
        node_label=node_label,
        key_prop=key_prop,
        key_value=entity_key,
        counter_prop="sequence_count",
        trigger="decision",
        mode="cumulative",
        population="observed",
    )


def soc_cross_category_counter_def(
    entity_key: str,
    *,
    node_label: str = "User",
    key_prop: str = "id",
) -> CounterDef:
    return CounterDef(
        domain="soc",
        node_label=node_label,
        key_prop=key_prop,
        key_value=entity_key,
        counter_prop="cross_category_count",
        trigger="decision",
        mode="distinct",
        population="observed",
        distinct_label="Category",
        distinct_key_prop="id",
        edge_label="SEEN_CATEGORY",
    )


def soc_sequence_counter_key(source_id: str, window_minutes: int = 60) -> CounterKey:
    return CounterKey(
        domain="soc",
        name="referral_sequence_count",
        scope=f"source:{source_id}:window_minutes:{int(window_minutes)}",
    )


def soc_cross_category_counter_key(user_id: str, window_minutes: int = 60) -> CounterKey:
    return CounterKey(
        domain="soc",
        name="referral_cross_category_count",
        scope=f"user:{user_id}:window_minutes:{int(window_minutes)}",
    )
