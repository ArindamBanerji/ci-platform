# AGE id() Probe Report

## Purpose

Read-only diagnostic for whether Apache AGE's `id()` can supply a deterministic `ORDER BY` tiebreaker for bounded traversal pagination. No test/probe query was executed. The pagination prerequisite was found in the sibling `copilot-sdk/docs/session_state.md` (`AGE-PAGINATION-DESIGN`, COMPLETE); that record gives the latest overall SDK test baseline as 4,179 passed, 0 failed. The latest local ci-platform session-state test count is 633 passed, 0 failed, 0 skipped (2026-09-26); it is not a current rerun.

## Findings

### Existing id() Usage in Codebase

Inspected `ci_platform/graph/age_client.py`, `ci_platform/graph/age_graph_store.py`, and the graph subdirectory. No Cypher `id(...)` call was found in ci-platform Python source. `age_graph_store.py` has ordering clauses on existing properties (for example `created_at`, `decision_id`, `status_id`, and `chain_index`), but the four affected traversals have no `ORDER BY`. `query_similar` is not evidence for ID ordering: its existing sibling wrapper orders by `created_at` and `decision_id` and uses bounded `SKIP`/`LIMIT`.

The client wraps queries with `SELECT * FROM cypher('<configured graph>', $$ ... $$) AS (...)`. It parses AGE agtype values; returned vertices/edges are unwrapped to property dictionaries and their encoded `id` is retained as `_age_id`. A scalar result from `id(n)` should be parsed as an integer by the existing scalar path, but that parsing expectation has not been live-probed.

Relevant source files found:

- `ci_platform/graph/age_client.py`
- `ci_platform/graph/age_graph_store.py`
- `ci_platform/graph/age_sdk_adapter.py`
- `ci_platform/graph/agtype.py`

Configured graph name is supplied to `AGEClient` as `graph_name`; local configuration documents `soc_graph`. Substitute the actual configured graph at probe time. Repository dependency documentation identifies PostgreSQL 17 and Apache AGE 1.7.0.

Actual traversal query shapes (abbreviated only to show the existing MATCH/WHERE/RETURN clauses):

`query_context` (`p` path, `e` root, `n` endpoint):

```cypher
MATCH p = (e {entity_id: <entity_id>})-[*1..<hop_count>]-(n)
WHERE e.domain = <domain> AND n.domain = <domain>
  AND size([v IN nodes(p) WHERE properties(v)['domain'] = <domain> | v]) = length(p) + 1
RETURN p
LIMIT 100
```

`contextual_judgment` (`p`, `e`, `j`):

```cypher
MATCH p=(e)-[*1..3]-(j:Decision)
WHERE j.domain = <domain> AND j.category = <category>
  AND (e.entity_group = <entity_group> OR e.entity_id = <entity_group>)
RETURN p LIMIT 100
```

`promotion_basis` (`p`, `r`, `j`):

```cypher
MATCH p=(r)-[*0..3]-(j)
WHERE r.domain = <domain>
  AND (r.rule_id = <rule_id> OR r.source_rule = <rule_id> OR r.target_rule = <rule_id>)
  AND (j.domain = <domain> OR j.domain IS NULL)
RETURN p LIMIT 100
```

`decision_movement` uses separate outbound and inbound direct-edge queries, each with `d`, `r`, and `e`, returning those three values with `LIMIT 50` and no ordering.

### id() Availability in Apache AGE

Apache AGE's scalar-functions manual documents `id(expression)` for vertex and edge expressions and describes an integer agtype result. Its `RETURN` clause accepts expressions, so returning `id(n)`/`id(r)` is documented syntax. The AGE client source itself does not call `id()` and thus does not establish runtime availability for the deployment. Sources: [AGE scalar functions](https://age.apache.org/age-manual/master/functions/scalar_functions.html), [AGE RETURN clause](https://age.apache.org/age-manual/master/clauses/return.html).

AGE's type documentation describes graph identity as a graphid composed from a label identifier and a sequence assigned within that label; IDs may overlap between separate graphs. This supports using IDs to distinguish entities within one graph, but does not establish that a sequence of IDs makes every path key unique under all query/path semantics. Source: [AGE types](https://age.apache.org/age-manual/master/intro/types.html).

### id() Stability Characteristics

- **Within repeated reads while an entity persists:** likely stable because the graphid is the entity's stored identity, rather than a result-row position. This is an inference from the documented graphid representation, not a guarantee established by this repository or a live probe.
- **Across transactions:** expected to remain the same for an unchanged, existing entity; AGE documentation inspected here does not state a formal cross-transaction durability guarantee.
- **Across VACUUM:** there is no evidence in the repository or cited AGE docs that logical graphids are PostgreSQL tuple `ctid` values. Do not assume VACUUM changes them; equally, this probe did not experimentally verify VACUUM behavior.
- **Monotonicity:** the per-label sequence component suggests allocation order within a label, but the sources inspected do not establish a globally monotonic ordering across labels, nor a permanent no-reuse guarantee after deletion.
- **Uniqueness:** graphid combines label identity and a label-local sequence, supporting entity distinction within a graph. AGE docs explicitly caution that IDs may overlap across different graphs. Do not use the value as a cross-graph key or durable business identifier.
- **Paths:** `id(p)` is not an appropriate probe: AGE documents `id()` for vertices/edges, not path values. A path tiebreaker must use IDs of its constituent nodes/relationships (or another demonstrated total key). Sorting only by endpoint IDs cannot distinguish parallel paths with the same endpoints.

### id() Performance Implications

The codebase does not run `EXPLAIN` for these queries and provides no evidence that `ORDER BY id(n)` can use an index. The deployment documentation says AGE 1.7.0; AGE 1.8 release material mentions vertex/edge ID indexes, which must not be projected backward onto this 1.7 deployment. Expect a possible sort and measure with the deployed version before enabling pagination. AGE query execution is wrapped in PostgreSQL `cypher(graph, query, parameters)` calls; graph name is runtime configuration, not universally fixed. Source: [AGE Cypher integration](https://age.apache.org/age-manual/master/intro/cypher.html).

### id() Deprecation Status

The current Apache AGE manual documents `id()` without a deprecation notice. Neo4j's deprecation of its `id()` in favor of `elementId()` is product-specific and is not evidence that Apache AGE deprecates the function. The reviewed AGE sources do not establish a general openCypher deprecation applicable to this AGE deployment. Do not replace this probe with Neo4j-only `elementId()`.

## Test Queries (ready to run manually)

These are proposed diagnostics only. Replace `soc_graph` if `AGEClient._graph` is configured differently. Run the stability query twice against a quiescent graph and compare ordered tuples. The SQL `AS` names and arity must correspond to the expressions in each `RETURN`.

### Four Traversal Query Probes

The following are probe variants based on actual AGE query shapes. Replace `<...>` with safely quoted Cypher literals from a disposable/test graph. They intentionally project IDs in addition to the original path so the returned result shape is diagnostic, not a drop-in application query.

**query_context** — endpoint ID is only a candidate tiebreaker; it cannot distinguish distinct paths ending at the same `n`:

```cypher
MATCH p = (e {entity_id: '<entity_id>'})-[*1..2]-(n)
WHERE e.domain = '<domain>' AND n.domain = '<domain>'
  AND size([v IN nodes(p) WHERE properties(v)['domain'] = '<domain>' | v]) = length(p) + 1
RETURN p, id(n) AS endpoint_id
ORDER BY id(n)
SKIP 0 LIMIT 100
```

**contextual_judgment** — IDs expose endpoint identities, but same endpoints can still have multiple paths:

```cypher
MATCH p=(e)-[*1..3]-(j:Decision)
WHERE j.domain = '<domain>' AND j.category = '<category>'
  AND (e.entity_group = '<entity_group>' OR e.entity_id = '<entity_group>')
RETURN p, id(e) AS entity_id, id(j) AS decision_node_id
ORDER BY id(e), id(j)
SKIP 0 LIMIT 100
```

**promotion_basis** — node IDs expose the endpoint pair, but do not alone distinguish multiple paths between that pair:

```cypher
MATCH p=(r)-[*0..3]-(j)
WHERE r.domain = '<domain>'
  AND (r.rule_id = '<rule_id>' OR r.source_rule = '<rule_id>' OR r.target_rule = '<rule_id>')
  AND (j.domain = '<domain>' OR j.domain IS NULL)
RETURN p, id(r) AS rule_node_id, id(j) AS endpoint_node_id
ORDER BY id(r), id(j)
SKIP 0 LIMIT 100
```

**decision_movement** — run separately for outbound and inbound; `id(r)` is the candidate unique edge tiebreaker:

```cypher
MATCH (d:Decision {decision_id: '<decision_id>'})-[r]->(e)
WHERE d.domain = '<domain>' AND (e.domain = '<domain>' OR e.domain IS NULL)
RETURN d, r, e, id(d) AS decision_node_id, id(r) AS relationship_id, id(e) AS endpoint_node_id
ORDER BY id(r)
SKIP 0 LIMIT 50
```

For inbound, use the actual opposite pattern: `MATCH (e)-[r]->(d:Decision {decision_id: '<decision_id>'})`; keep the same predicates and projection/order clause.

### Node id() Probe

```sql
SELECT * FROM cypher('soc_graph', $$
  MATCH (n:Decision)
  RETURN n.decision_id, id(n)
  ORDER BY id(n)
  LIMIT 5
$$) AS (decision_id agtype, node_id agtype);
```

### Relationship id() Probe

```sql
SELECT * FROM cypher('soc_graph', $$
  MATCH (a)-[r]->(b)
  RETURN type(r), id(r), id(a), id(b)
  ORDER BY id(r)
  LIMIT 5
$$) AS (rel_type agtype, rel_id agtype, src_id agtype, dst_id agtype);
```

### Stability Probe

Run this same query twice without graph mutations and compare the ordered `(decision_id, node_id)` rows:

```sql
SELECT * FROM cypher('soc_graph', $$
  MATCH (n:Decision)
  RETURN n.decision_id, id(n)
  ORDER BY id(n)
  LIMIT 10
$$) AS (decision_id agtype, node_id agtype);
```

### Path id() Probe

AGE `id()` is documented for vertices and edges, so this probe extracts IDs from the actual movement path components rather than calling `id(p)`:

```sql
SELECT * FROM cypher('soc_graph', $$
  MATCH p=(d:Decision {decision_id: '<decision_id>'})-[r]->(e)
  WHERE d.domain = '<domain>' AND (e.domain = '<domain>' OR e.domain IS NULL)
  RETURN [n IN nodes(p) | id(n)], [edge IN relationships(p) | id(edge)]
  ORDER BY id(r)
  LIMIT 5
$$) AS (node_ids agtype, relationship_ids agtype);
```

This checks path-component extraction and edge ordering for a one-edge movement path. For variable-length traversal paths, adapt the actual `MATCH` and inspect the returned sequences; do not infer uniqueness from endpoints alone.

### SKIP + ORDER BY id() Probe

```sql
SELECT * FROM cypher('soc_graph', $$
  MATCH (n:Decision)
  RETURN n.decision_id, id(n)
  ORDER BY id(n)
  SKIP 5 LIMIT 5
$$) AS (decision_id agtype, node_id agtype);
```

## Recommendation

### If id() is available and stable

The AGE manual says `id()` is available for vertex/edge expressions; a live runtime probe remains necessary. For `decision_movement`, order by `id(r)` as the final unique edge key after any desired business ordering. For path traversals, use a deterministic ordering over the ordered sequence of node and relationship IDs in each path, not merely the endpoint ID pair. AGE support for ordering by that constructed key and the resulting key's totality must be verified against the deployed server before implementation. IDs are graph-local identities, not cross-graph or business keys.

### If id() is not available

Fall back to the best existing-property order documented in `age_pagination_design.md`, with explicit edge cases: it is not a total ordering for arbitrary paths or parallel relationships. Do not ship offset pagination as deterministic under that fallback. A cursor-based predicate over existing properties would still require a unique cursor key; otherwise the design must be revisited rather than pretending a cursor solves ties.

## Risk Assessment

**Release gate: PARTIALLY RESOLVED; keep UNRESOLVED for production pagination.** Documentation establishes that AGE exposes `id()` for vertices and edges, which is promising for the movement query and for constructing path keys. It does not establish live availability in this PostgreSQL 17 / AGE 1.7.0 deployment, a total ordering of arbitrary variable-length paths, cross-transaction durability guarantees, or index-backed ordering. The written probes can settle the runtime questions, but were deliberately not run here. Concurrent graph writes between offset pages can still shift page boundaries even with deterministic ordering; ID tiebreaking does not provide snapshot isolation.
