"""Same-graph bounded projection migration, activation and transaction hooks.

Install the writer hooks before migration and quiesce older package versions.
Advisory locks coordinate participating writers, migration, and fenced reads;
they cannot make an old writer participate. Rollback removes only activation,
retaining canonical fields, generation anchors and immutable feed evidence.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
from typing import TYPE_CHECKING, Any

from ci_platform.graph import bounded_projection as bp
from ci_platform.graph.age_client import AGETransaction

if TYPE_CHECKING:
    from ci_platform.graph.age_graph_store import AGEGraphStore

VERSION = 1
_NAMESPACE_DOMAIN_RE = re.compile(
    r"^jmns__(?P<namespace>[0-9a-f]+)__(?P<domain>[a-zA-Z0-9_-]{1,200})$"
)


class ActivationAbsentError(ValueError):
    """The domain has no complete bounded-projection activation."""


class ActivationCorruptError(ValueError):
    """The domain's bounded-projection readiness evidence is contradictory."""


def _canonical_literal(store: AGEGraphStore, value: Any) -> str:
    """Use native AGE nonfinite floats, avoiding collidable string sentinels."""
    if isinstance(value, float) and not math.isfinite(value):
        token = "NaN" if math.isnan(value) else "Infinity" if value > 0 else "-Infinity"
        return f"toFloat({store._S(token)})"
    return str(store._S(value))


def lock(store: AGEGraphStore, tx: AGETransaction, domain: str, *, shared: bool = False) -> None:
    name = "pg_advisory_xact_lock_shared" if shared else "pg_advisory_xact_lock"
    key = json.dumps([store._client._graph, "bounded-projection-v1", domain])
    tx.execute_sql(f"SELECT {name}(hashtextextended(%s, 0))", (key,))


def state(store: AGEGraphStore, tx: AGETransaction, domain: str) -> dict[str, Any] | None:
    # Physical domains are validated by the store. This simple query also works
    # with the existing transaction facade before bounded labels are installed.
    rows = tx.run_cypher(f"MATCH (s:BoundedDomain) WHERE s.domain = {store._S(domain)} RETURN s LIMIT 2")
    if len(rows) > 1:
        raise ActivationCorruptError("duplicate bounded domain anchor")
    return store._node_to_dict(rows[0]["s"]) if rows else None


def _namespace_base_domain(domain: str) -> str | None:
    """Return the logical base domain encoded in an internal namespace key."""
    if not domain.startswith("jmns__"):
        return None
    match = _NAMESPACE_DOMAIN_RE.fullmatch(domain)
    if match is None:
        raise ActivationCorruptError("invalid namespaced physical domain")
    try:
        namespace = bytes.fromhex(match.group("namespace")).decode("utf-8")
    except (UnicodeDecodeError, ValueError) as exc:
        raise ActivationCorruptError("invalid namespace encoding") from exc
    if not namespace.strip():
        raise ActivationCorruptError("invalid empty namespace encoding")
    return match.group("domain")


def _require_activation(
    store: AGEGraphStore, tx: AGETransaction, domain: str,
) -> dict[str, Any]:
    """Validate the exact activation evidence stored for a base domain."""
    anchor = state(store, tx, domain)
    rows = tx.run_bounded_cypher(
        f"MATCH (a:BoundedActivation) WHERE a.domain = {store._S(domain)} "
        f"AND a.version = {store._S(VERSION)} RETURN a LIMIT 2"
    )
    if anchor is None and rows:
        raise ActivationCorruptError(
            f"bounded activation marker exists without domain anchor for {domain!r}"
        )
    if anchor is None or not rows:
        raise ActivationAbsentError(
            f"bounded projections are not activated for domain {domain!r}"
        )
    if len(rows) > 1:
        raise ActivationCorruptError(
            f"duplicate bounded activation markers for domain {domain!r}"
        )
    if anchor.get("version") != VERSION:
        raise ActivationCorruptError(
            f"bounded activation version contradicts domain anchor for {domain!r}"
        )
    return anchor


def _initialize_namespaced_domain(
    store: AGEGraphStore, tx: AGETransaction, domain: str,
) -> dict[str, Any]:
    """Create and backfill the per-physical-domain generation anchor once."""
    anchor = state(store, tx, domain)
    if anchor is not None:
        if anchor.get("version") != VERSION:
            raise ActivationCorruptError(
                f"bounded namespace anchor has unsupported version for {domain!r}"
            )
        return anchor

    rows = tx.run_bounded_cypher(
        f"MATCH (d:Decision) WHERE d.domain = {store._S(domain)} AND {bp.ACTIVE} "
        "OPTIONAL MATCH (d)-[:HAS_OUTCOME]->(o:Outcome) "
        "RETURN properties(d) AS d, properties(o) AS o ORDER BY d.decision_id"
    )
    ids: set[str] = set()
    for row in rows:
        decision = store._node_to_dict(row["d"])
        decision_id = decision.get("decision_id")
        if not isinstance(decision_id, str) or not decision_id or decision_id in ids:
            raise ValueError("duplicate/missing decision ID or ambiguous Outcome")
        ids.add(decision_id)
        routing(decision)
        bp.normalize(decision, store._node_to_dict(row["o"]))

    tx.run_bounded_cypher(
        f"CREATE (s:BoundedDomain {{domain: {store._S(domain)}, generation: 0, "
        f"version: {store._S(VERSION)}}}) RETURN s"
    )
    for decision_id in sorted(ids):
        emit(store, tx, domain, decision_id, initial=True)
    initialized = state(store, tx, domain)
    if initialized is None:
        raise RuntimeError("failed to initialize bounded namespace anchor")
    return initialized


def begin(store: AGEGraphStore, tx: AGETransaction, domain: str) -> bool:
    lock(store, tx, domain)
    if state(store, tx, domain) is not None:
        return True
    base_domain = _namespace_base_domain(domain)
    if base_domain is None:
        return False
    try:
        lock(store, tx, base_domain, shared=True)
        _require_activation(store, tx, base_domain)
    except ActivationAbsentError:
        return False
    _initialize_namespaced_domain(store, tx, domain)
    return True


def ready(store: AGEGraphStore, tx: AGETransaction, domain: str) -> dict[str, Any]:
    base_domain = _namespace_base_domain(domain)
    if base_domain is None:
        return _require_activation(store, tx, domain)
    lock(store, tx, base_domain, shared=True)
    _require_activation(store, tx, base_domain)
    return _initialize_namespaced_domain(store, tx, domain)


def routing(decision: dict[str, Any]) -> tuple[str, bool]:
    metadata = bp.decode(decision.get("metadata"))
    metadata = metadata if isinstance(metadata, dict) else {}
    top = decision.get("tenant_id")
    meta = metadata.get("tenant_id")
    if top is not None and meta is not None and str(top or "default") != str(meta or "default"):
        raise ValueError("conflicting tenant representations")
    return str((top if top is not None else meta) or "default"), {"signal_detail", "signal_timestamp"}.issubset(metadata)


def read_record(store: AGEGraphStore, tx: AGETransaction, domain: str, decision_id: str) -> tuple[dict[str, Any], dict[str, Any]]:
    rows = tx.run_bounded_cypher(
        f"MATCH (d:Decision) WHERE d.domain = {store._S(domain)} AND d.decision_id = {store._S(decision_id)} "
        "OPTIONAL MATCH (d)-[:HAS_OUTCOME]->(o:Outcome) RETURN properties(d) AS d, properties(o) AS o LIMIT 2"
    )
    if len(rows) != 1:
        raise ValueError(f"missing/duplicate decision or Outcome: {decision_id}")
    return store._node_to_dict(rows[0]["d"]), store._node_to_dict(rows[0]["o"])


def emit(store: AGEGraphStore, tx: AGETransaction, domain: str, decision_id: str, *, deleted: bool = False, initial: bool = False) -> None:
    anchor = state(store, tx, domain)
    if anchor is None:
        return
    decision, outcome = read_record(store, tx, domain, decision_id)
    tenant, legacy = routing(decision)
    if "_bp_tenant_id" in decision and decision["_bp_tenant_id"] != tenant:
        raise ValueError("decision routing identity is immutable")
    if "_bp_legacy" in decision and decision["_bp_legacy"] != legacy:
        raise ValueError("decision routing identity is immutable")
    if not deleted and decision.get("archived") is True:
        return
    S = store._S
    generation = int(anchor.get("generation", 0)) + 1
    event_id = hashlib.sha256(json.dumps([domain, "initial", decision_id] if initial else [domain, generation]).encode()).hexdigest()
    if initial:
        existing = tx.run_bounded_cypher(f"MATCH (e:BoundedDecisionEvent) WHERE e.domain = {S(domain)} AND e.decision_id = {S(decision_id)} RETURN e LIMIT 1")
        if existing:
            return
    if deleted:
        payload: dict[str, Any] = {"decision_id": decision_id, "domain": domain, "tenant_id": tenant, "exclude_legacy_signals": legacy, "_removed": True}
    else:
        payload = bp.normalize(decision, outcome)
        assignments = []
        for name in bp.FIELDS:
            value = payload.get(name)
            if name in bp.JSON_FIELDS and value is not None:
                value = json.dumps(value, sort_keys=True)
            # Native floats preserve projection types; confidence eligibility
            # still uses separate properties to avoid AGE's NaN ordering.
            assignments.append(f"d._bp_{name} = {_canonical_literal(store, value)}")
        assignments += [f"d._bp_legacy = {S(legacy)}", f"d._bp_confidence_nan = {S(math.isnan(float(decision.get('confidence') or 0.0)))}"]
        confidence = payload["confidence"]
        kind = "missing" if confidence is None else "finite" if math.isfinite(confidence) else "nan" if math.isnan(confidence) else "positive_infinity" if confidence > 0 else "negative_infinity"
        assignments += [f"d._bp_confidence_kind = {S(kind)}", f"d._bp_confidence_number = {S(confidence if kind == 'finite' else None)}"]
        tx.run_bounded_cypher(f"MATCH (d:Decision) WHERE d.domain = {S(domain)} AND d.decision_id = {S(decision_id)} SET {', '.join(assignments)} RETURN d.decision_id AS decision_id")
    tx.run_bounded_cypher(f"MATCH (s:BoundedDomain) WHERE s.domain = {S(domain)} SET s.generation = {S(generation)} RETURN s.generation AS generation")
    props = {
        "event_id": event_id, "generation": generation, "event_type": "delete" if deleted else "upsert",
        "decision_id": decision_id, "domain": domain, "tenant_id": tenant,
        "exclude_legacy_signals": legacy, "payload": json.dumps(payload, sort_keys=True),
    }
    literal = ", ".join(f"{name}: {S(value)}" for name, value in props.items())
    rows = tx.run_bounded_cypher(f"CREATE (e:BoundedDecisionEvent {{{literal}}}) RETURN e.event_id AS event_id")
    if not rows:
        raise RuntimeError("feed event creation failed")


def migrate(store: AGEGraphStore, domain: str) -> dict[str, int]:
    """Validate, backfill, and activate a quiesced physical domain atomically."""
    domain = store._validated_domain(domain)

    def operation(tx: AGETransaction) -> dict[str, int]:
        # Serialize graph-label installation across physical domains too.
        tx.execute_sql("SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))", (json.dumps([store._client._graph, "bounded-schema-v1"]),))
        lock(store, tx, domain)
        rows = tx.run_bounded_cypher(f"MATCH (d:Decision) WHERE d.domain = {store._S(domain)} AND {bp.ACTIVE} OPTIONAL MATCH (d)-[:HAS_OUTCOME]->(o:Outcome) RETURN properties(d) AS d, properties(o) AS o ORDER BY d.decision_id")
        ids: set[str] = set()
        for row in rows:
            decision = store._node_to_dict(row["d"])
            decision_id = decision.get("decision_id")
            if not isinstance(decision_id, str) or not decision_id or decision_id in ids:
                raise ValueError("duplicate/missing decision ID or ambiguous Outcome")
            ids.add(decision_id)
            routing(decision)
            bp.normalize(decision, store._node_to_dict(row["o"]))
        anchor = state(store, tx, domain)
        if anchor is None:
            tx.run_bounded_cypher(f"CREATE (s:BoundedDomain {{domain: {store._S(domain)}, generation: 0, version: {store._S(VERSION)}}}) RETURN s")
        before = int((anchor or {}).get("generation", 0))
        tx.run_bounded_cypher("CREATE (e:BoundedDecisionEvent {schema_install: true}) DELETE e")
        for decision_id in sorted(ids):
            emit(store, tx, domain, decision_id, initial=True)
        tx.run_bounded_cypher(f"MATCH (a:BoundedActivation) WHERE a.domain = {store._S(domain)} DELETE a")
        tx.run_bounded_cypher(f"CREATE (a:BoundedActivation {{domain: {store._S(domain)}, version: {store._S(VERSION)}}}) RETURN a")
        after = int((state(store, tx, domain) or {})["generation"])
        return {"scanned": len(ids), "events_created": after - before, "generation": after}

    result: dict[str, int] = store._run(store._client.run_transaction(operation))
    return result


def deactivate(store: AGEGraphStore, domain: str) -> None:
    domain = store._validated_domain(domain)

    def operation(tx: AGETransaction) -> None:
        lock(store, tx, domain)
        tx.run_bounded_cypher(f"MATCH (a:BoundedActivation) WHERE a.domain = {store._S(domain)} DELETE a")

    store._run(store._client.run_transaction(operation))


def read(store: AGEGraphStore, domain: str, kind: str, **options: Any) -> Any:
    """Execute a bounded read under the same domain lock as participating writes."""
    domain = store._validated_domain(domain)
    filters = options.get("filters") or {}
    bp.validate_filters(filters, routing_only=kind == "feed")
    projection = options.get("projection", "full")
    bp.project({}, projection)
    fence = options.get("as_of_generation")
    if fence is not None:
        bp.integer(fence, "as_of_generation")
    if kind == "feed":
        bp.integer(options["after_generation"], "after_generation")
        bp.integer(options["limit"], "limit", 1, 1000)
    compiled = ""
    if kind == "query":
        compiled = bp.query(domain, filters, store._S, **{k: options[k] for k in ("projection", "order_by", "descending", "limit", "offset", "after")})
    elif kind == "aggregate":
        compiled = bp.aggregate(domain, filters, store._S, options["group_by"], options["metrics"])

    def operation(tx: AGETransaction) -> Any:
        # Namespace initialization can create and backfill its physical anchor.
        lock(store, tx, domain, shared=_namespace_base_domain(domain) is None)
        anchor = ready(store, tx, domain)
        generation = int(anchor["generation"])
        if fence is not None and fence != generation:
            raise bp.GenerationChanged(fence, generation)
        if kind == "ready":
            return generation
        if kind == "count":
            rows = tx.run_bounded_cypher(f"MATCH (d:Decision) WHERE {bp.predicates(domain, filters, store._S)} RETURN count(d) AS cnt")
            return int(rows[0]["cnt"])
        if kind == "query":
            if options["order_by"] == "verified_at":
                invalid = tx.run_bounded_cypher(f"MATCH (d:Decision) WHERE {bp.predicates(domain, filters, store._S)} AND {bp.VERIFIED} AND d._bp_verified_at IS NULL RETURN d.decision_id AS decision_id LIMIT 1")
                if invalid:
                    raise ValueError("verified decision is missing verified_at")
            rows = tx.run_bounded_cypher(compiled)
            more = len(rows) > options["limit"]
            rows = rows[:options["limit"]]
            cursor = None
            if more:
                cursor_id = rows[-1]["_cursor_id"]
                if not isinstance(cursor_id, str) or not cursor_id:
                    raise ValueError("decision cursor ID must be a nonempty string")
                cursor = (float(rows[-1]["_cursor_value"]), cursor_id)
            items = []
            for row in rows:
                if projection == "full":
                    record = bp.normalize(store._node_to_dict(row["_decision"]), store._node_to_dict(row["_outcome"]))
                else:
                    record = {k: bp.decode(v) if k in bp.JSON_FIELDS else v for k, v in row.items() if not k.startswith("_cursor_")}
                    record["confidence"] = bp.number(record.get("confidence"))
                items.append(bp.project(record, projection))
            return items, cursor, more
        if kind == "aggregate":
            rows = tx.run_bounded_cypher(compiled)
            if len(rows) > 1000:
                raise bp.CardinalityExceeded(len(rows))
            aggregates = []
            for row in rows:
                if "correct_count" in options["metrics"] and row.get("correct_count") is None:
                    row["correct_count"] = 0
                if "avg_confidence" in options["metrics"]:
                    positive, negative = row.get("_positive_infinity"), row.get("_negative_infinity")
                    if row.get("_nan") or (positive and negative):
                        row["avg_confidence"] = float("nan")
                    elif positive or negative:
                        row["avg_confidence"] = float("inf") if positive else float("-inf")
                dimensions = {k: str(row[k]) for k in options["group_by"] if row.get(k) is not None}
                values = {m: float(row["_count" if m == "count" else m]) for m in options["metrics"] if row.get("_count" if m == "count" else m) is not None}
                aggregates.append((dimensions, values))
            return sorted(aggregates, key=lambda item: tuple((key in item[0], item[0].get(key, "")) for key in options["group_by"]))
        if kind == "feed":
            after = options["after_generation"]
            if after > generation:
                raise ValueError("after_generation exceeds current generation")
            S = store._S
            clauses = [f"e.domain = {S(domain)}", f"e.generation > {S(after)}", f"e.generation <= {S(generation)}"]
            if filters.get("tenant_id") is not None:
                clauses.append(f"e.tenant_id = {S(filters['tenant_id'])}")
            if filters.get("exclude_legacy_signals"):
                clauses.append("e.exclude_legacy_signals = false")
            rows = tx.run_bounded_cypher(f"MATCH (e:BoundedDecisionEvent) WHERE {' AND '.join(clauses)} RETURN properties(e) AS event ORDER BY e.generation ASC LIMIT {S(options['limit'] + 1)}")
            more = len(rows) > options["limit"]
            events = []
            for row in rows[:options["limit"]]:
                event = store._node_to_dict(row["event"])
                event.pop("event_id", None)
                payload = bp.decode(event["payload"])
                event["payload"] = bp.project(payload, projection) if event["event_type"] == "upsert" else payload
                events.append(event)
            next_generation = int(events[-1]["generation"]) if more else generation
            return events, next_generation, generation, more
        raise ValueError(f"unknown bounded read: {kind}")

    return store._run(store._client.run_transaction(operation))
