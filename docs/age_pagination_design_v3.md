# AGE Pagination Design v3 — Reviewed Overscan and Offset Pages

Date: 2026-10-01  
Status: Design complete after source and internal-consistency review; no source implementation is included in this document.

## 1. Problem Statement

`LegacySignalFilteringGraphStore` hides legacy signal decisions from ordinary decision and traversal views. Its predicate identifies a legacy signal only when both `metadata.signal_detail` and `metadata.signal_timestamp` are present. A path containing one of those decisions is filtered as a whole.

The AGE traversal methods currently return at most 100 raw rows for `query_context`, `contextual_judgment`, and `promotion_basis`, and at most 50 raw rows for each direction of `decision_movement`. The wrapper filters the returned rows after the AGE query. If legacy rows occupy a large part or all of the first bounded result set, fewer than the intended visible result cap are returned even when ordinary rows exist beyond that set.

V1 proposed repeated path calls with increasing Python offsets. That cannot work: path methods returned the same Cypher-limited rows on every call, because the path queries had no `SKIP`. Sorting and slicing the same 100 rows does not expose row 101. This v2 replaces path paging with a single overscan query and one filtering pass. Movement remains pageable in Cypher because the live probe established a stable unique relationship ID ordering.

The target visible caps remain 100 rows for path traversals and 50 rows per direction for movement. The path overscan is bounded and best-effort: it can recover ordinary rows within its 1,000-row sample, but cannot promise to find ordinary rows after that cap.

## 2. Live Probe Findings

The live WSL2 PostgreSQL + AGE results supplied in the session reconciliation are treated as deployment evidence for this design:

| Probe | Result |
|---|---|
| P1: `id(n)` on nodes | PASS; integer IDs observed |
| P2: `id(r)` on edges | PASS |
| P3: `SKIP` + `ORDER BY id()` | PASS; adjacent pages had zero overlap |
| P4: repeated ordered reads | PASS; ordering was identical across two runs |
| P5: edge identity uniqueness | PASS; all sampled edge IDs unique |
| P6: ordering by a list comprehension of path component IDs | FAIL; AGE reports `unsupported SubLink` |
| P7: node identity uniqueness | PASS; 45,417 sampled node IDs unique |
| P8: edge identity uniqueness | PASS; 45,191 sampled edge IDs unique |

The implementation facts relevant to those results are:

- `AGEClient._parse_agtype()` attaches `_age_id` to a top-level vertex/edge dictionary when it unwraps that value's `properties`.
- It does not recursively normalize the vertex and edge objects inside a returned path. Path components therefore cannot be assumed to expose `_age_id` to Python.
- Calling `id(p)` is not the path identity solution. The live path-list ordering probe failed, so no design here relies on sorting a path by a component-ID list.
- AGE graph IDs combine label identity and a label-local sequence. They are useful as graph-local internal identities; they are not business IDs or cross-graph keys.

The v1 probe report was written before the live test and says the release gate was unresolved. The live results above supersede that conclusion for node/edge ID availability and movement ordering, while the path-ordering failure remains a hard constraint.

## 3. Design Decisions

There are two separate strategies because the methods return different kinds of values.

**Strategy A — `decision_movement`: ordered Cypher pages.** Each result row contains one relationship `r`; `ORDER BY id(r)` was live-tested as a total edge order, and `SKIP`/`LIMIT` produced disjoint pages. Multi-call pagination is valid for this method.

**Strategy B — path methods: single-call overscan and filter.** `query_context`, `contextual_judgment`, and `promotion_basis` return paths. AGE cannot order those paths by component-ID lists, and the Python path objects do not expose normalized `_age_id` values. Repeated calls therefore cannot provide a deterministic next page. Each method will instead fetch up to 1,000 raw paths in one Cypher call, without `ORDER BY` or `SKIP`; the wrapper filters that one batch and returns the first 100 visible rows.

The path `scan_cap` is exactly **1,000 raw paths**, ten times the existing 100-row visible cap. It is an upper bound, not a promise that every matching path is scanned. The 10x factor is a fixed design/resource tradeoff, not an empirically optimized ratio. If the batch reaches 1,000 and has fewer than 100 visible paths, the wrapper logs that the returned result may be partial and returns those visible paths. It does not issue another path call.

Deterministic ordering is not required for path overscan because there is no cross-call offset and no concatenation of pages. AGE may choose any 1,000 matching paths; one response filters that single returned set. This trades determinism/exhaustiveness for bounded single-query recovery. It does not guarantee the same selected 1,000 paths across calls or transactions.

For movement, the page cap is 50 and the scan cap is 500 raw rows per direction (10 pages). If fewer than 50 visible rows remain after the bounded scan, the wrapper returns the partial visible result and logs when the 500-row cap, rather than backend exhaustion, stopped the scan.

## 4. Strategy A — `decision_movement` (Cypher Pagination)

### 4A-1. Cypher change

Keep the existing outbound and inbound `MATCH` patterns and filters. The complete pair of queries is:

```python
for direction, pattern, safe_skip in (
    (
        "outbound",
        f"(d:Decision {{decision_id: {decision_literal}}})-[r]->(e)",
        safe_outbound_skip,
    ),
    (
        "inbound",
        f"(e)-[r]->(d:Decision {{decision_id: {decision_literal}}})",
        safe_inbound_skip,
    ),
):
    linked = self._run_query(f"""
        MATCH {pattern}
        WHERE d.domain = {domain_literal}
          AND (e.domain = {domain_literal} OR e.domain IS NULL)
        RETURN d, r, e
        ORDER BY id(r)
        SKIP {safe_skip} LIMIT {safe_limit}
    """)
```

Do not sort by properties or by `id(d)`/`id(e)`; the edge ID is the proven unique key for the row. Keep the query's existing projected variables and the wrapper's output dictionary shape.

### 4A-2. AGE method signature

```python
def decision_movement(
    self,
    domain: str,
    decision_id: str,
    *,
    outbound_skip: int = 0,
    inbound_skip: int = 0,
    limit: int = 50,
) -> list[dict[str, Any]]: ...
```

The `AGEGraphStoreAdapter` gets the same keyword-only parameters and forwards them. The GraphStore protocol and `LegacySignalFilteringGraphStore.decision_movement(domain, decision_id)` remain unchanged.

### 4A-3. Parameter clamping

- `safe_limit = max(1, min(int(limit), 50))`.
- `safe_outbound_skip = max(0, min(int(outbound_skip), 450))`.
- `safe_inbound_skip = max(0, min(int(inbound_skip), 450))`.
- Each integer is interpolated as a validated integer literal only. No caller string is placed in Cypher.
- Offset 450 plus a page of 50 is the last page within the 500-row scan cap.

Clamp the three movement integers directly using the expressions above; do not add a new generic pagination helper for this change.

### 4A-4/5. Wrapper paging and exhaustion

The wrapper pages both directions through the combined adapter method, tracks their offsets and visible results separately, and ignores later rows for a direction once that direction is exhausted. A direction is exhausted when a returned page is shorter than the requested page size, or its raw offset reaches 500. A short page is true backend exhaustion. Reaching 500 is a bounded partial scan and must be distinguishable with a `logging.warning` record.

The actual `AGEGraphStore.decision_movement()` makes two sequential `_run_query()` calls, one for outbound and one for inbound, then extends one combined list. Every emitted row is a dict with the established `direction` value (`"outbound"` or `"inbound"`) plus `decision`, `relationship`, and `evidence`. The adapter forwards that combined list unchanged. The wrapper partitions by `direction` before filtering and accumulating; outbound rows remain before inbound rows in the final result. If a row has no recognized direction, raise `ValueError` for the malformed adapter result instead of silently dropping it.

### 4A-6. Exact movement pseudocode

```text
PAGE = 50
RAW_CAP = 500
out_skip = 0; in_skip = 0
out_visible = []; in_visible = []
out_done = false; in_done = false

while (not out_done and len(out_visible) < PAGE) or
      (not in_done and len(in_visible) < PAGE):
    # Each AGE call returns at most one page for each direction.
    rows = reader.decision_movement(
        domain, decision_id,
        outbound_skip=min(out_skip, RAW_CAP - PAGE),
        inbound_skip=min(in_skip, RAW_CAP - PAGE),
        limit=PAGE,
    )
    if any(row.get("direction") not in {"outbound", "inbound"} for row in rows):
        raise ValueError("AGE decision_movement row has invalid direction")
    out_page = rows whose direction == "outbound"
    in_page = rows whose direction == "inbound"

    if not out_done:
        append non-legacy out_page rows until out_visible has PAGE
        out_skip += len(out_page)
        if len(out_page) < PAGE or out_skip >= RAW_CAP or len(out_visible) == PAGE:
            out_done = true
    if not in_done:
        append non-legacy in_page rows until in_visible has PAGE
        in_skip += len(in_page)
        if len(in_page) < PAGE or in_skip >= RAW_CAP or len(in_visible) == PAGE:
            in_done = true

return out_visible[:PAGE] + in_visible[:PAGE]
```

When one direction is done while the other continues, the combined AGE method will still execute both directional queries. The wrapper ignores the completed direction's rows. Its offset remains clamped at 450, so at most the final already-seen page may be fetched again; it is never accumulated twice. The loop is bounded to ten full-page calls because each live direction's offset advances by 50 per full page and stops at 500.

## 5. Strategy B-Revised — Path Traversals (Overscan + Single Pass)

### 5A. Methods

This strategy applies only to `query_context`, `contextual_judgment`, and `promotion_basis` when the wrapper is reading an `AGEGraphStoreAdapter` backed by `AGEGraphStore`.

### 5B. Cypher scan limit

Set the path query's `LIMIT` to a bounded `scan_cap`, whose wrapper-requested value is **1,000**. This is not the visible page size. The visible output cap stays **100** after filtering. One query can therefore return up to ten times the visible target for the wrapper to inspect. Preserve each existing Cypher predicate exactly; only the limit expression changes:

```python
# query_context
rows = self._run_query(f"""
    MATCH p = (e {{entity_id: {self._S(entity_id)}}})-[*1..{hop_count}]-(n)
    WHERE e.domain = {literal} AND n.domain = {literal}
      AND size([v IN nodes(p) WHERE properties(v)['domain'] = {literal} | v]) = length(p) + 1
    RETURN p
    LIMIT {safe_scan_cap}
""")

# contextual_judgment
rows = self._run_query(f"""
    MATCH p=(e)-[*1..3]-(j:Decision)
    WHERE j.domain = {self._S(domain_value)}
      AND j.category = {self._S(str(category))}
      AND (e.entity_group = {self._S(str(entity_group))}
           OR e.entity_id = {self._S(str(entity_group))})
    RETURN p LIMIT {safe_scan_cap}
""")

# promotion_basis
rows = self._run_query(f"""
    MATCH p=(r)-[*0..3]-(j)
    WHERE r.domain = {self._S(domain_value)}
      AND (r.rule_id = {self._S(str(rule_id))}
           OR r.source_rule = {self._S(str(rule_id))}
           OR r.target_rule = {self._S(str(rule_id))})
      AND (j.domain = {self._S(domain_value)} OR j.domain IS NULL)
    RETURN p LIMIT {safe_scan_cap}
""")
```

AGE store direct calls retain their existing behavior by default: `_scan_cap=100`. The wrapper uses the private AGE-specific path only to request `_scan_cap=1000`. Clamp `_scan_cap` to `[100, 1000]`; the lower bound preserves the historical default batch, and the upper bound is the fixed resource ceiling. The only interpolated value is the clamped integer.

For each method, compute `safe_scan_cap = max(100, min(int(_scan_cap), 1000))` before building Cypher. Do not accept a string query fragment or interpolate any other caller-controlled pagination value.

### 5C. Cypher clauses that do not change

Path queries keep their existing `MATCH`/`WHERE` predicates. They add neither `ORDER BY` nor `SKIP`. `ORDER BY` on a path component-ID list is unsupported in AGE; `SKIP` without a deterministic order would not create a safe multi-call cursor. There is exactly one query call per path method invocation by the filtering wrapper.

### 5D. AGE method signatures

Add one internal, keyword-only, underscored argument to each concrete `AGEGraphStore` path method:

```python
query_context(
    self, entity_id: str, hops: int = 2, *, domain: str,
    _scan_cap: int = 100,
) -> list[dict[str, Any]]

contextual_judgment(
    self, domain: str, entity_group: str, category: str, *,
    _scan_cap: int = 100,
) -> list[dict[str, Any]]

promotion_basis(
    self, domain: str, rule_id: str, *,
    _scan_cap: int = 100,
) -> list[dict[str, Any]]
```

`_scan_cap` is a private implementation hook, not part of `GraphStore` or `AGEGraphStoreAdapter`'s public path signatures. The adapter's ordinary path methods continue forwarding exactly as before, which preserves direct callers' 100-row default. The SDK wrapper detects the AGE adapter and invokes its concrete backing store with `_scan_cap=1000`. This is intentionally analogous to the existing AGE-only `query_similar` path that reaches the adapter's backing AGE store for AGE-specific query behavior.

The adapter does not expose or forward `_scan_cap`; only the wrapper's explicit AGE branch uses it. This is a deliberate layer crossing through `AGEGraphStoreAdapter._store`, matching the existing AGE-specific `query_similar` implementation. The alternative—adding `_scan_cap` to the adapter's public GraphStore-like path methods—was rejected because it would expose an internal raw-result control to all adapter callers and invite non-wrapper callers to receive a 1,000-row batch.

Before using this internal call, require both `isinstance(reader, AGEGraphStoreAdapter)` and `isinstance(reader._store, AGEGraphStore)`. Import both classes locally in the AGE-specific branch, following the wrapper's existing local AGE adapter import pattern. If the adapter's backing object is not an `AGEGraphStore`, do not pass `_scan_cap`; call the adapter path method once with its normal signature, filter that result, and emit `logger.warning` that AGE overscan could not be applied. This defensive fallback preserves compatibility with a future adapter substitute without assuming it accepts AGE-private arguments.

### 5E. Wrapper single-pass pseudocode

```text
reader = _reader()
if method has its existing local SQLite/InMemory read-view hook:
    return existing local traversal/filter behavior unchanged
if isinstance(reader, AGEGraphStoreAdapter) and isinstance(reader._store, AGEGraphStore):
    age = reader._store
    raw_rows = age.<path_method>(existing arguments, _scan_cap=1000)  # once
    visible = []
    for row in raw_rows:
        if not _contains_legacy_decision(row):
            visible.append(row)  # retain the existing native row shape
            if len(visible) == 100:
                break
    if len(raw_rows) == 1000 and len(visible) < 100:
        logger.warning(
            "AGE path overscan cap reached: %d visible of %d target after %d raw paths",
            len(visible), 100, len(raw_rows),
        )
    return visible
if isinstance(reader, AGEGraphStoreAdapter):
    logger.warning("AGE path overscan unavailable for non-AGE adapter backing store")
    raw_rows = reader.<path_method>(existing arguments)  # once, default signature
    return first 100 rows that are not legacy
otherwise:
    call reader.<path_method>(existing arguments) once, apply the existing
    legacy filter, and preserve the existing delegation/error behavior
```

Each AGE traversal query runs once; do not loop over `skip`, retry for another path batch, or sort paths in Python. Apply the existing recursive legacy predicate to each raw path as a whole and retain only the first 100 non-legacy rows from the single AGE result batch.

### 5F. Insufficient overscan

If all raw rows are legacy, return `[]`. If the query returns fewer than 1,000 raw rows and fewer than 100 visible rows, return the visible rows; the backend result was shorter than the scan bound. If exactly 1,000 raw rows are returned but fewer than 100 are visible, return that partial visible result and emit `logger.warning` with visible count, target count, and raw count. This is an operational coverage warning, not a query error. Do not silently claim the traversal was exhaustive.

This approach cannot guarantee that a non-legacy row exists in the arbitrary 1,000-row sample even if one exists beyond it. That is an explicit resource/coverage tradeoff. It also cannot promise repeatable membership/order across calls because there is no path ordering; deterministic ordering is not needed to combine pages because there are no pages.

### 5G. `_age_id` and `_path_sort_key` retirement

Do not add `_path_sort_key`, do not extract `_age_id` from paths, and do not sort path rows in Python. `_age_id` remains available on top-level returned vertex/edge objects only. Path overscan is a one-call set, so it has no cross-call ordering or offset requirement.

### 5H. Future options if overscan is insufficient

1. Clean legacy signal records from graph data using a separately reviewed migration, reducing how many rows the filter removes.
2. Raise the single-call scan ceiling above 1,000 only after measuring AGE query time, memory, response serialization, and connection timeout impact; keep a hard explicit maximum.
3. Change AGEClient path normalization to expose IDs recursively only if the AGE path representation is documented/tested; this alone does not solve AGE's unsupported path-ID `ORDER BY`.
4. Seek an AGE-supported total scalar path key or a cursor scheme that proves disjoint results for variable paths. Do not use unordered `SKIP` or assume endpoint IDs distinguish paths.
5. If exact/exhaustive filtered results are required, revisit the graph query/data model in a separate design; this v2 does not provide exhaustiveness beyond the scan cap.

## 6. Adapter Forwarding

`AGEGraphStoreAdapter.decision_movement()` adds and forwards `outbound_skip=0`, `inbound_skip=0`, and `limit=50` as keyword-only arguments. Its path traversal signatures and forwards remain unchanged. The wrapper's AGE-only path branch calls `reader._store` with `_scan_cap=1000`; the adapter does not add a public scan-cap parameter. No protocol change is made.

## 7. Wrapper Implementation Summary

### 7A. Movement

Use Strategy A's bounded per-direction Cypher pages. AGE performs two separate direction-specific queries and returns a combined, direction-tagged list. Validate tags, partition rows, filter each direction independently, preserve each `direction` field, stop at 50 visible rows, a short raw page, or 500 scanned raw rows, and concatenate outbound then inbound.

### 7B. Paths

Use one AGE backing-store call with `_scan_cap=1000`, filter once, and return up to 100 visible paths. Verify the backing object is an `AGEGraphStore` before using its private argument. If it is not, warn and use one normal adapter call. There is no path pagination loop.

### 7C. SQLite/InMemory

Keep all existing local private read-view hooks and native result behavior. Do not call AGE-specific pagination or change either store.

### 7D. Backend detection

Use the existing `_reader()` method, which unwraps `DualWriteStore` to its primary, for all four wrapper methods. Preserve local read-view hook checks first. `promotion_basis` currently delegates through `self._store` directly; change that delegation to the `_reader()` result so a dual-write wrapper reads its configured primary consistently with the other composite methods. For the AGE branch, require `isinstance(reader, AGEGraphStoreAdapter)` and `isinstance(reader._store, AGEGraphStore)`, then access `reader._store` for the private scan-cap call. Otherwise use the ordinary adapter signature with a warning. Do not infer backend identity from method names or arbitrary attributes.

### 7E. Public signatures

Do not add arguments to `LegacySignalFilteringGraphStore` methods. Keep the signatures `query_context(entity_id, max_depth, *, domain)`, `decision_movement(domain, decision_id)`, `contextual_judgment(domain, entity_group, category)`, and `promotion_basis(domain, rule_id)` unchanged.

### 7F. Logging

The current wrapper module has no logger. Add `import logging` and define `logger = logging.getLogger(__name__)` at module scope. Use `logger.warning` when path overscan returns exactly 1,000 raw paths with fewer than 100 visible paths, when a movement direction reaches 500 raw rows with fewer than 50 visible rows, or when an AGE adapter has a non-AGE backing store and overscan cannot be applied. Include visible count, target count, raw rows scanned, and direction where applicable. Empty/exhausted results below the cap do not produce a cap-reached message. Query exceptions continue to propagate.

## 8. Method Signature Summary

| Method/layer | Before | After |
|---|---|---|
| AGEGraphStore `query_context` | `(entity_id, hops=2, *, domain)` | `(entity_id, hops=2, *, domain, _scan_cap=100)`; private internal cap |
| AGEGraphStore `contextual_judgment` | `(domain, entity_group, category)` | `(domain, entity_group, category, *, _scan_cap=100)`; private internal cap |
| AGEGraphStore `promotion_basis` | `(domain, rule_id)` | `(domain, rule_id, *, _scan_cap=100)`; private internal cap |
| AGEGraphStore `decision_movement` | `(domain, decision_id)` | `(domain, decision_id, *, outbound_skip=0, inbound_skip=0, limit=50)` |
| AGEGraphStoreAdapter path methods | Existing signatures | Unchanged; normal 100-row behavior |
| AGEGraphStoreAdapter `decision_movement` | `(domain, decision_id)` | `(domain, decision_id, *, outbound_skip=0, inbound_skip=0, limit=50)` |
| LegacySignalFilteringGraphStore, all four methods | Existing public signatures | Unchanged |
| GraphStore protocol | Existing signatures | Unchanged |

All limits and offsets have the clamps specified in Sections 4 and 5. The 1,000 path cap is requested only by the wrapper's AGE-specific internal call.

## 9. Backward Compatibility

- Do not modify `GraphStore`, traversal protocols, or protocol typing files.
- Do not change public wrapper signatures, output list/dict shapes, or direction labels.
- AGE direct path calls and ordinary adapter calls retain default `LIMIT 100`; only the wrapper's internal AGE call requests 1,000 raw paths and then truncates after filtering.
- AGE movement direct calls retain the old maximum 50 rows per direction with default offsets zero; ordering becomes deterministic and the adapter/wrapper can request later pages.
- Do not modify SQLite or InMemory stores, their read-view hooks, or their behavior.
- Do not modify traversal routers, scorers, evidence providers, or other consumer code.
- Do not add graph labels, properties, relationship types, or indexes.
- The wrapper still returns at most 100 rows for each path method and at most 100 movement rows total (50 per direction).

## 10. Blast Radius Map

### Files expected to change

**ci-platform**

- `ci_platform/graph/age_graph_store.py`: add movement ordering and bounded directional `SKIP`/`LIMIT`; add private `_scan_cap` to three path methods and interpolate its clamped integer as the path `LIMIT`.
- `ci_platform/graph/age_sdk_adapter.py`: add/forward movement offsets and limit; leave path methods unchanged.
- `tests/test_age_graph_store.py`: query generation, clamping/defaults, one-call overscan limit, and no path `ORDER BY`/`SKIP` tests.
- `tests/test_age_sdk_adapter.py`: movement keyword forwarding and defaults; confirm path method behavior/signatures stay unchanged.

**copilot-sdk**

- `../copilot-sdk/copilot_sdk/graph/legacy_signal_filter.py`: add `logging` import and module logger; add AGE-only one-call overscan for paths with an `AGEGraphStore` backing-store type guard and warning fallback; add independent bounded movement paging with direction-tag validation; route `promotion_basis` through `_reader()`; preserve local backends and public signatures. This SDK source change is required even though this design document is stored in ci-platform.
- `tests/test_legacy_signal_filter.py`: overscan filtering, truncation/logging, movement paging, and local-backend compatibility tests.

### Files that must not change

- `../copilot-sdk/copilot_sdk/graph/protocol.py` and any public GraphStore protocol.
- SQLite and InMemory graph-store implementations.
- `AGEClient` (the design deliberately does not depend on recursive path-ID parsing).
- Consumer code, app routers, scorers, and query providers.
- Graph schema and stored data.

## 11. Test Strategy

### `ci-platform/tests/test_age_graph_store.py`

- `test_decision_movement_order_by_id_r`: both directional Cypher strings order by `id(r)` before `SKIP` and `LIMIT`.
- `test_decision_movement_skip_clamping`: negative and oversized offsets clamp to 0 and 450; limits clamp to 1 and 50.
- `test_decision_movement_defaults`: default offsets and limit produce the original page size plus the deterministic order clause.
- `test_path_methods_keep_unordered_cypher`: each path query contains its original predicates and no `ORDER BY` or `SKIP`.
- `test_path_scan_cap_default_and_overscan`: direct default uses `LIMIT 100`; `_scan_cap=1000` uses `LIMIT 1000`.
- `test_path_scan_cap_clamping`: values below 100 and above 1,000 are bounded to 100 and 1,000.
- `test_path_rows_are_not_python_paginated`: returned AGE query rows are not sorted or sliced by an offset; the store preserves row shape/order from the single raw result.

### `ci-platform/tests/test_age_sdk_adapter.py`

- `test_adapter_forwards_movement_pagination_kwargs`: movement offsets and limit reach AGEGraphStore unchanged.
- `test_adapter_movement_defaults_match_backend`: defaults are zero, zero, and 50.
- `test_adapter_path_signatures_unchanged`: normal path calls forward without private overscan arguments and retain default behavior.

### `copilot-sdk/tests/test_legacy_signal_filter.py`

- `test_wrapper_overscans_path_batch_once`: an AGE adapter over AGEGraphStore receives exactly one `_scan_cap=1000` call, and a fixture with 105 legacy then 100 ordinary rows returns those 100 ordinary rows.
- `test_wrapper_path_overscan_caps_visible_rows`: a raw batch with 1,000 ordinary rows returns exactly its first 100 in backend order.
- `test_wrapper_path_mixed_and_all_legacy_batches`: a mixed batch excludes only rows with both legacy markers, and an all-legacy batch returns `[]`.
- `test_wrapper_path_scan_cap_partial_result_warns`: a 1,000-row batch containing 999 legacy paths and one ordinary path returns one path and logs warning with counts 1/100/1000.
- `test_wrapper_path_short_result_is_not_capped`: a 20-row raw batch with 12 ordinary paths returns 12 without a scan-cap warning.
- `test_wrapper_path_empty_batch`: an empty AGE response returns `[]` after one call.
- `test_wrapper_movement_pages_directions_independently`: outbound returns a full 50-row legacy page then a 10-row page; inbound returns two full legacy pages then 5 visible rows; wrapper returns the 5 inbound rows without duplicating outbound rows.
- `test_wrapper_movement_scan_cap_warns`: ten full pages of legacy rows in one direction stop at 500 raw rows, return no rows for that direction, and produce one warning with the direction and counts.
- `test_wrapper_movement_short_page_exhaustion`: a 12-row outbound page and 0-row inbound page end both directions after the first query call.
- `test_wrapper_movement_exact_page_boundary`: exactly 50 visible rows in each direction return 100 total and make no second call.
- `test_wrapper_movement_rejects_invalid_direction`: one row missing the `direction` key raises `ValueError` rather than being silently omitted.
- `test_wrapper_local_backends_unchanged`: SQLite/InMemory read-view hooks return the existing result and receive no `_scan_cap` argument.
- `test_wrapper_non_age_adapter_backing_falls_back`: an AGEGraphStoreAdapter backed by a non-AGE test object receives one ordinary-signature call, emits a warning, and does not pass `_scan_cap`.
- `test_wrapper_promotion_basis_reads_dual_write_primary`: a DualWriteStore with AGE primary triggers one primary overscan call; a local primary uses one ordinary primary call; secondary is not read.
- `test_wrapper_public_signatures_unchanged`: signature inspection shows the four public wrapper methods have no new pagination parameters.

Tests exercise the real legacy predicate using nested path dictionaries with both marker keys, single-marker near-misses, and ordinary rows; they do not mock the predicate result.

## 12. Negative Constraints

1. Do not edit GraphStore protocol or public wrapper signatures.
2. Do not edit SQLite/InMemory implementations, AGEClient, or consumer code.
3. Do not use `_age_id` or `_path_sort_key` for path traversal results.
4. Do not issue a second AGE path query to obtain later rows.
5. Do not add path `ORDER BY` or `SKIP`; do not use list-comprehension ordering in Cypher.
6. Do not exceed a single 1,000-raw-path request per wrapped path method.
7. Do not exceed 10 movement pages per direction, 500 raw rows per direction, or 50 rows per movement page.
8. Do not exceed 100 visible path rows or 50 visible rows per movement direction.
9. Do not interpolate unvalidated strings into pagination clauses; only clamped integer literals may be interpolated.
10. Path `LIMIT 1000` is an intentional internal overscan change; ordinary direct AGE/adapter calls retain the 100 default.
11. Do not claim path overscan is deterministic, exhaustive, or guaranteed to find 100 visible results when more matching rows exist outside the sample.
12. Do not silently swallow query failures; preserve existing error propagation.
13. Validate the adapter backing object as `AGEGraphStore` before passing `_scan_cap`; use the specified warned default-call fallback for another backing type.
14. Reject movement rows with missing or unknown `direction` by raising `ValueError`; do not silently discard them.
15. Use `logger.warning`, not debug/info, for scan-cap insufficiency and overscan fallback conditions.

## 13. V1 Retrospective

V1 proposed multi-call path paging without verifying that a second call could retrieve a different raw batch. It kept `LIMIT 100`, added no Cypher `SKIP`, then applied Python slicing to repeated copies of those same 100 rows. That cannot recover row 101.

V1 also assumed `_age_id` was available inside decoded path components. The client only attaches it to top-level vertex/edge values; path contents are not recursively normalized. A sort key cannot rely on fields absent from the actual objects.

V1 was written before live AGE probes. It treated the missing total path key as an open design question instead of a hard implementation constraint. The live probe established that edge IDs support ordered movement pages but list-comprehension ordering over path component IDs fails.

Lessons retained in this design:

- Verify how each call obtains a new batch before designing a multi-call page loop.
- Verify data shape and normalization depth before using a nested attribute as a sort key.
- Update designs after live probes and distinguish proven capability from an untested assumption.
- Use bounded overscan only with an explicit statement of its partial-coverage behavior.

## 14. Review Record

Reviewed: `docs/age_pagination_design_v2.md`  
Reviewed by: Codex, GPT-6 Sol / high, 2026-10-01  
Review prompt: `REV-AGE-PAGINATION-DESIGN-V2`

### 14A. Code Verification Results

- CHECK-CODE-1: PASS — v2's before signature `(domain, decision_id)` matches `AGEGraphStore.decision_movement(self, domain: str, decision_id: str)`.
- CHECK-CODE-2: PASS — v2's before signature matches `query_context(self, entity_id, hops=2, *, domain)`.
- CHECK-CODE-3: PASS — v2's before signature matches `contextual_judgment(self, domain, entity_group, category)`.
- CHECK-CODE-4: PASS — v2's before signature matches `promotion_basis(self, domain, rule_id)`.
- CHECK-CODE-5: PASS — source uses `LIMIT 100` for all three path methods and `LIMIT 50` inside each movement-direction query; movement currently has no `ORDER BY`.
- CHECK-CODE-6: PASS — the adapter forwards all four methods. `query_context` maps `max_depth` to AGE's `hops`; the other three forward directly. V3 specifies movement keyword forwarding and keeps adapter path signatures unchanged.
- CHECK-CODE-7: PASS — `_reader()` unwraps `DualWriteStore` to `.primary`; query-context, movement, and contextual-judgment use it. Current `promotion_basis` uniquely calls `self._store` directly; v3 explicitly changes it to `_reader()` and tests this.
- CHECK-CODE-8: PASS — the sibling SDK `GraphStore` protocol defines all four methods with the existing public signatures. Those protocol signatures remain unchanged.

Source-location correction: the wrapper and protocol are not under `ci_platform/graph/`; their actual paths are `../copilot-sdk/copilot_sdk/graph/legacy_signal_filter.py` and `../copilot-sdk/copilot_sdk/graph/protocol.py`. The implementation blast radius therefore includes the SDK repository even though this design document is stored in ci-platform.

### 14B. Internal Consistency Results

- CHECK-IC-1: PASS — movement method and adapter keyword-only names, types, and defaults match in Sections 4 and 8.
- CHECK-IC-2: PASS — all three private `_scan_cap: int = 100` signatures and `[100, 1000]` clamp agree in Sections 5 and 8; adapter path signatures remain unchanged.
- CHECK-IC-3: PASS — Section 4 pseudocode matches the two directional AGE queries combined into direction-tagged rows and separate wrapper accumulators.
- CHECK-IC-4: PASS — Section 5 uses one `_reader()` result, a type-checked AGE backing-store access, one overscan query, and single-pass filtering; Section 7 specifies the same.
- CHECK-IC-5: PASS — Section 10 lists every file changed by Sections 4-7, including promotion-basis `_reader()` routing and its actual SDK location.
- CHECK-IC-6: PASS — Section 11 has a specific test for each change in Sections 4-7, including invalid directions, a non-AGE backing fallback, promotion primary routing, warnings, caps, and unchanged local stores.
- CHECK-IC-7: PASS — Section 12 prohibits repeated path calls, path `SKIP`/`ORDER BY`, `_age_id` path sorting, and overscan above 1,000.

### 14C. Design Gap Results

- GAP-1: CONFIRMED AND FIXED — AGE executes one query per direction and returns a combined list whose rows carry `direction`; v3 documents the shape and raises `ValueError` for missing/unknown tags.
- GAP-2: CONFIRMED AND FIXED — current `promotion_basis` uses `self._store`; v3 explicitly routes through `_reader()`, lists the change, and specifies a DualWrite primary-routing test.
- GAP-3: CONFIRMED AND FIXED — v3 documents the deliberate `reader._store` access, why `_scan_cap` is not exposed on adapter methods, validates the backing type, and specifies a warning plus default-call fallback.
- GAP-4: CONFIRMED AND FIXED — each test has a concrete setup and expected result, including exact scan-cap and direction cases; the vague catch-all instruction was removed.
- GAP-5: CONFIRMED AND FIXED — the current wrapper has no logger, so v3 explicitly adds the `logging` import and module logger, then requires `logger.warning` for path/movement cap exhaustion and the fallback condition.

### 14D. Issues Found and Resolved

1. Movement pseudocode did not explain where direction tags came from. V3 documents the two source queries, combined output dicts, tag values, partitioning, and invalid-tag behavior.
2. The promotion-basis `_reader()` correction was not explicit in the blast-radius section. V3 lists it and requires a DualWrite primary-routing test.
3. The wrapper's private adapter backing-store access lacked a type guard and fallback. V3 requires `isinstance(reader._store, AGEGraphStore)`, explains why `_scan_cap` is not added to adapter methods, and defines a warned normal-call fallback.
4. Some test requirements were broad or deferred to an “also cover” sentence. V3 supplies inputs and expected results for each test and removes that sentence.
5. The wrapper had no existing logger, and the path scan-cap log level was not fixed. V3 requires a module logger, specifies `logger.warning` and the counts, and fixes movement-cap and fallback warnings.
6. The prompt's wrapper/protocol paths did not match the repository layout. V3 records the real SDK paths and makes the cross-repo implementation boundary explicit.
7. V2 could imply the 1,000-row factor was empirically selected. V3 states it is a fixed design/resource tradeoff, not an observed optimum.

### 14E. Issues Found and Not Resolved

None — all review issues were resolved in the design. The overscan's possible partial coverage is an explicit property of the selected approach, not an unresolved implementation question.

### 14F. Changes from V2

- **Title/status:** identifies this as the reviewed v3 design.
- **Sections 1-2:** carried forward unchanged; they already state the best-effort scan limit and distinguish the pre-live probe report from supplied live results.
- **Section 3:** clarifies that the 10x overscan factor is a fixed resource tradeoff, not an empirical optimum.
- **Section 4:** verifies and documents the two directional AGE queries, combined direction-tagged result rows, invalid-tag failure, and concrete movement pseudocode.
- **Section 5:** adds an AGEGraphStore backing type check, exact non-AGE fallback, rationale for the private layer crossing, and warning-level/counted scan-cap logging.
- **Section 6:** carried forward unchanged; it already specifies movement-only adapter forwarding and unchanged adapter path signatures.
- **Section 7:** explicitly adds the logging import/module logger, changes `promotion_basis` to `_reader()`, aligns it with primary routing, and specifies exact backend and warning behavior.
- **Section 8:** carried forward unchanged; review confirmed signature and clamp agreement across the design sections.
- **Section 9:** carried forward unchanged; it retains protocol, wrapper, local backend, consumer, and graph schema boundaries.
- **Section 10:** corrects SDK file paths and lists the logger addition, direction validation, backing-type fallback, and promotion routing.
- **Section 11:** replaces broad test descriptions with concrete setups and expected results for all behavior changes.
- **Section 12:** retains all prior restrictions and adds adapter type validation, invalid direction handling, and fixed warning level.
- **Section 13:** retains the historical lessons without requiring prior design documents to implement.
- **Section 14:** records the source audit, consistency checks, gap resolutions, and complete v2-to-v3 change list.
