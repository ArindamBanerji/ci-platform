## AGE-ESCAPE-FIX (Sep 18, 2026)

Fixed `_S()`/`serialize_for_age()` backslash escaping in `age_client.py`.
Order: escape backslashes first, then quotes.
Applied the same quoted-string boundary to direct strings, list/tuple JSON,
NumPy JSON, and fallback JSON serialization.
Tests: +10 regression tests for injection payloads.
Sweep 4 F01 (P1): RESOLVED.
Mypy: `age_client.py` and `test_age_escaping.py` PASS.
ci-platform: 629 passed.
SOC consumer: 2475 passed, 16 skipped.

## AGE-JM-PHASE-02B (Sep 22, 2026)

G002: `AGEGraphStore.write_decision()` now executes through `AGEClient.run_transaction()`. The client uses a fresh `autocommit=False` connection and explicit `conn.commit()`; commit failures propagate before a decision ID is returned. Live AGE coverage verifies a committed decision can be read back.

G007: Decision node creation, optional entity edge, Domain anchor/IN_DOMAIN edge, Category node/IN_CATEGORY edge, and optional FactorVector/HAS_FACTOR_VECTOR edge now share the same transaction. Edge/node results are checked; any failure aborts the transaction. Live failure-injection coverage confirms FactorVector failure leaves no Decision node.

G008: Added `AGEGraphStore.write_outcome_and_update_centroid()` and transaction-facade support. Outcome and centroid writes run on the same AGE transaction; centroid failure rolls back the outcome. This establishes the atomic store API for callers that need both writes together.

Verification: ci-platform `tests/`: 649 passed; AGE graph-store/topology/domain-focused tests: 173 passed. Mypy clean for `ci_platform/graph/age_graph_store.py` and both changed test modules. Test count exceeds the 629 baseline because the live AGE tests ran and the new transaction tests were added. No git commands used.

Phase 2 transaction gaps G002 ✅, G007 ✅, G008 ✅ closed at the AGE store API. Together with the SDK Phase 02 record, all seven Phase 2 gaps are marked closed.

## MOCK-FIX-CI (Sep 23, 2026)
Files modified: tests/conftest.py, tests/test_age_archive.py, tests/test_age_graph_store_v.py, tests/test_counter_store.py, tests/test_graph_backend_switcher.py, tests/test_l5_upsert_current.py.
FakeAGEClient: removed from 4 REPLACE files; tests/test_age_graph_store.py still contains the legacy query-recorder fake and needs a dedicated migration.
FakeGraphStore: replaced with disposable AGE coverage in archive, D2 count, counter, and L5 current-version tests; memory_store fixture added for protocol-compliant unit replacements.
@pytest.mark.age tests: 53 deselected by -m "not age"; live AGE tests now require GRAPH_DSN through age_store/age_dsn fixtures.
Circular tests deleted: 0.
ci-platform tests: 578 passed, 53 deselected/skipped by age selection. mypy: clean.

## C1-SILENT-SUB (Sep 23, 2026)
Fixed: P1-001, P1-002, P1-005.
Tests: python -m pytest tests/ -q --timeout=120 -x -m "not age" stopped at pre-existing tests/test_age_sdk_adapter.py::test_adapter_delegates_counts_and_reads (FakeGraphStore.get_decision missing include_outcome); 222 passed before failure, 53 deselected. mypy: clean.

## CI-TEST-INFRA-FIX (2026-09-26)

- Fixed tests/test_age_graph_store_v.py: added an instance-level _S stub with monkeypatch to the object.__new__(AGEGraphStore) setup. The global-limit test no longer depends on the uninitialized _client; its assertion is unchanged.
- Fixed tests/test_counter_store.py: converted _run(), _seed_user_and_category(), and _user() to async. Both query-helper calls, all seven seed calls, and all three _user() assertions now await their results. Removed the unused asyncio import; no nested asyncio.run() remains in this file.
- Production code in ci_platform/ was not modified. SHA-256 comparison confirmed all 37 production Python files unchanged.
- Requested focused limit test: 1 passed. Complete counter-store module: 11 passed, including all seven live AGE tests, with no skips.
- Full validation: python -m pytest tests/ -q --timeout=120 — ci-platform: 631 passed, 0 failed, 0 skipped, in 37.24s.
- Requested mypy check: 7 pre-existing errors before and 7 after, with identical diagnostics after accounting for shifted line numbers. No new errors.
- Validation logs: ../.codex_tmp/ci_testfix_full_suite.log, ci_testfix_mypy_before.log, and ci_testfix_mypy_after.log.


## SS-01 (2026-09-26)

Finding: P2-001 (`_l5_upsert_current` edge swallowed).

Fix: The non-transactional L5 lineage edge path now logs the existing warning and re-raises the original edge-creation exception. The L5 node write still occurs before the edge operation, so partial completion remains observable to the caller without silently losing lineage. The transaction-backed path remains unchanged and continues to re-raise within its transaction boundary.

Files changed:
- `ci_platform/graph/age_graph_store.py`
- `tests/test_age_graph_store.py`

Tests added: 2.

Coverage:
- Forced non-transactional edge failure verifies the node CREATE query completed and the edge exception is surfaced.
- Forced transaction-scoped edge failure verifies the exception still re-raises.

Test counts after:
- ci-platform: 633 passed, 0 failed, 0 skipped.
- Focused regression: 2 passed.
- mypy: `python -m mypy ci_platform/graph/age_graph_store.py --ignore-missing-imports` clean.

Validation log: `../.codex_tmp/ss01_ci_full.log`.

## AGE-ID-PROBE — 2026-10-01
Status: COMPLETE
What: Read-only probe design for AGE `id()` availability and suitability as an ORDER BY tiebreaker.
Prerequisite: `AGE-PAGINATION-DESIGN` COMPLETE in sibling `copilot-sdk/docs/session_state.md`; latest overall baseline recorded there was 4,179 passed. Latest local ci-platform count recorded here: 633 passed, 0 failed, 0 skipped (2026-09-26).
Output: `docs/age_id_probe_report.md`
Files changed: `docs/age_id_probe_report.md`, `docs/session_state.md` (ONLY)
Source files changed: NONE (read-only diagnostic)
Finding: Live probe results supplied for this reconciliation confirm `id()` on nodes and edges; node and edge IDs were unique in the sampled graph, `ORDER BY id(r)` worked for edges, and repeated ordered reads / SKIP pages were stable. AGE rejected list-comprehension path-ID ordering with `unsupported SubLink`.
Live probe: P1-P5, P7, P8 PASS; P6 FAIL. Reported 45,417 unique node IDs and 45,191 unique edge IDs.
Release gate: PARTIALLY RESOLVED. Movement can use Cypher `ORDER BY id(r)`; path traversal ordering remains unresolved pending an implementable, bounded way to fetch disjoint raw path pages and a verified parsed path identity structure.

## AGE-PAGINATION-IMPL — HALTED AT DESIGN VERIFICATION — 2026-10-01
No production or test code changed. The live probe reconciliation was recorded above from the results supplied in the implementation prompt.
Blocking contradiction: path methods retain Cypher `LIMIT 100` and add no Cypher `SKIP` or `ORDER BY`, then Python sorts/slices those at-most-100 returned rows. Repeating the same AGE method with `skip=100` returns the same first bounded result and slices it to empty; it cannot fetch paths beyond the first batch or meet the wrapper's 1,000-raw-row scan cap. Python ordering cannot recover rows the query did not return.
Additional evidence gap: `AGEClient._parse_agtype()` adds `_age_id` only when the parsed top-level value is a vertex/edge dictionary with `properties`. It does not recursively normalize nested path components. The claimed `_age_id` path-component shape is therefore not established by the implementation read.
Required design update before implementation: define a bounded method for obtaining disjoint path pages with a total ordering supported by AGE, or explicitly change the requirement/scan cap and accept the resulting coverage limit. Verify how parsed path components expose IDs. No tests or type checks were run.

## AGE-PAGINATION-DESIGN-V2 — 2026-10-01
Status: COMPLETE
What: Revised AGE traversal pagination design after the v1 path-paging blockers.
Prerequisites: v1 design is COMPLETE in sibling `copilot-sdk/docs/session_state.md` and `../copilot-sdk/docs/age_pagination_design.md`. Live probe results are recorded in the AGE-ID-PROBE entry above; the v1 probe report remains the pre-live historical artifact.
Output: `docs/age_pagination_design_v2.md`
Key changes from v1:
  - Path strategy replaced: multi-call paging becomes one bounded 1,000-row overscan plus single-pass filtering.
  - `_path_sort_key` and path `_age_id` sorting retired.
  - Three path methods receive a private `_scan_cap=100` default; only the AGE wrapper branch requests 1,000. No path SKIP/ORDER BY or repeated path calls.
  - Movement keeps ordered `id(r)` Cypher pages with independent directional offsets, page cap 50, and scan cap 500 per direction.
  - V1 retained as historical record; v2 is self-contained and specifies signatures, limits, wrapper logic, tests, and constraints.
Strategy A (movement): `ORDER BY id(r)` with bounded Cypher `SKIP`/`LIMIT`.
Strategy B (paths): overscan and filter in one query; best-effort coverage through the first 1,000 raw results, with explicit partial-result logging.
Design completeness: Sections 1-13 present; cross-checked signature table, blast radius, test plan, and negative constraints.
Validation: `python -m pytest tests/ -q --timeout=120` — 649 passed, 0 failed, 0 skipped, 1,298 warnings (2026-10-01). This is the current ci-platform baseline; no source code was changed.
Files changed by this design task: `docs/age_pagination_design_v2.md`, `docs/session_state.md` only.


## AGE-CHECKPOINT-COUNT — 2026-10-01T16:14:19-07:00
Status: COMPLETE
Model: terra/high
What: Added optional decisions_count to AGE save_centroids() Cypher CREATE properties, serialized with the existing _S() helper and included only when the value is not None. Zero is persisted as an integer.

Prerequisites: FIX-CHAIN-1B-FIXER-2 COMPLETE and REV-CHAIN-1B-FIXER-2 present in copilot-sdk/docs/session_state.md. Task-start baselines: ci-platform 633 passed, 0 failures (SS-01); copilot-sdk 4179 passed, 0 failures.
Located/read:
  - C:/Users/baner/CopyFolder/IoT_thoughts/python-projects/kaggle_experiments/claude_projects/ci-platform/ci_platform/graph/age_graph_store.py
  - C:/Users/baner/CopyFolder/IoT_thoughts/python-projects/kaggle_experiments/claude_projects/ci-platform/ci_platform/graph/age_client.py
Files changed by this task:
  - ci_platform/graph/age_graph_store.py — save_centroids() only
  - tests/test_age_checkpoint_count.py — NEW
  - docs/session_state.md — this append

Design verification and adaptations:
  - save_centroids() already accepts **kwargs; decision_id was already consumed, while decisions_count was ignored.
  - Properties are assembled as a serialized string, not a dict. The existing properties are decision_id, domain, category, centroids, metadata, and created_at.
  - One shared property string serves three CREATE call sites: standalone, linked HAS_CENTROID_CHECKPOINT, and standalone fallback when the referenced decision does not exist. The conditional addition therefore covers all three.
  - _S() serializes integers as numeric literals. The existing checkpoint reader retains node properties and requires no change; historical missing counts remain absent and .get() returns None.
  - Omitted and explicitly None counts produce exactly the pre-change Cypher. No signature or imports changed.
  - Isolation gates were evaluated against task-start file hashes, because both worktrees already contained unrelated edits and decisions_count already legitimately exists in SDK local backends/protocols. A literal zero-hit scan would reject pre-existing valid code.
  - Concurrent AGE pagination design/probe documentation updates in both repositories were preserved. They are not changes made by this task.

Tests added: 16 (13 disposable live-AGE cases, 3 query-capture unit cases).
Coverage:
  - decisions_count=42 and decisions_count=0 round trips for all three CREATE paths.
  - Omitted and explicitly None count compatibility for all three paths.
  - Existing HAS_CENTROID_CHECKPOINT relationship remains intact.
  - Historical checkpoint unchanged after a new counted checkpoint; missing-count scorer fallback evaluates to 0.
  - Exact original Cypher comparison for omitted/None calls.
  - Before the production fix, the new live round-trip test failed with missing decisions_count, confirming the regression test detects the bug.

Validation:
  - ci-platform pre-change full suite: 633 passed, 0 failures.
  - ci-platform post-change full suite: 649 passed, 0 failures, 0 skipped (59.23s).
  - New checkpoint tests: 16 passed, 0 failures.
  - Random sampling: test_centroid_distance.py, test_dataops_schema.py, test_domain_enforcement.py — 20 passed, 0 failures.
  - copilot-sdk full suite: 4179 passed, 0 failures (2202.19s), with GRAPH_BACKEND unset and a temporary CROSS_SIGNAL_DB_PATH.
  - Two earlier sandboxed SDK attempts terminated on 120-second startup timeouts in test_evolution_telemetry.py (test_summary_cross_copilot_parity, then test_summary_event_types_valid). Stacks showed socket creation during a conservation read and FRED DNS resolution during Purchasing warmup. The isolated parity test passed in 111.78s. An approved unrestricted full run then passed with unchanged tests and timeout; its slowest startup test was 117.46s. These observations do not establish sandboxing as the sole cause.
  - mypy on age_graph_store.py and test_age_checkpoint_count.py: PASS.
  - V3 scan of the other already-dirty Python files: the same two pre-existing no-any-return errors remained at tests/test_age_graph_store_v.py:21 and tests/test_counter_store.py:46; 0 new errors.
  - Diff-driven caller/test audit: existing AGE writer, adapter, and outcome/checkpoint tests remain passing. No existing test assertions were changed.
Baseline: ci-platform 633 -> 649 (+16); copilot-sdk 4179 -> 4179.
Isolation: Confirmed for this task — no SQLite/InMemory/wrapper/protocol/reader or other copilot-sdk source changes; no historical backfill, imports, node labels, or relationship types added.
Logs: C:/Users/baner/AppData/Local/Temp/age-checkpoint-count-r60shr43/ci-full.log, sdk-full.log, sdk-full-retry.log, sdk-parity-repro.log, sdk-full-unrestricted.log.

## REV-AGE-PAGINATION-DESIGN-V2 — 2026-10-01 23:36 UTC
Status: COMPLETE
What: Reviewed v2 pagination design and produced corrected v3
Input: docs/age_pagination_design_v2.md (preserved, not modified)
Output: docs/age_pagination_design_v3.md (new)
Code verification: 8/8 PASS
Internal consistency: 7/7 PASS
Design gaps: 5 checked, 5 confirmed and fixed
VERIFY gate on v3: 7/7 PASS
Issues resolved in v3: 7 (movement direction split; promotion_basis delegation; adapter backing-store access; adapter type guard/fallback; test specificity; warning-level scan-cap logging; source-verified signatures and result shapes)
Issues unresolved: 0
Test baseline: 649 passed, 0 failed, 0 skipped (matches the v2 design session baseline)
Implementation prompt should be written from: docs/age_pagination_design_v3.md

## AGE-PAGINATION-IMPL-V5 — 2026-10-01 17:42 PDT
Status: COMPLETE
What: Implemented offset pagination for movement and bounded overscan for path traversal methods.
Design doc: docs/age_pagination_design_v3.md (reviewed v3)
Strategy A (movement): ORDER BY id(r) plus Cypher SKIP/LIMIT; wrapper pages directions independently.
Strategy B-revised (paths): Private _scan_cap (default 100, wrapper requests 1000); one AGE call and single-pass filter.
Additional fixes:
  - promotion_basis reads through _reader() (DualWrite primary)
  - Added module logger and warning-level cap/fallback messages
  - Added AGE backing-store type checks and invalid direction ValueError
  - Kept GraphStore protocol and public wrapper signatures unchanged
Files changed by this task:
  ci_platform/graph/age_graph_store.py
  ci_platform/graph/age_sdk_adapter.py
  tests/test_age_graph_store.py
  tests/test_age_sdk_adapter.py
  ../copilot-sdk/copilot_sdk/graph/legacy_signal_filter.py
  ../copilot-sdk/tests/test_legacy_signal_filter.py
Tests added: 33 collected cases (12 ci-platform, 21 copilot-sdk)
Design cross-check: 8/8 PASS
Validation:
  - Baseline: ci-platform 649; copilot-sdk 4179
  - Full ci-platform suite: 661 passed, 0 failed, 0 skipped
  - Full copilot-sdk suite: 4200 passed, 0 failed, 0 skipped
  - Focused ci-platform AGE store + adapter tests: 190 passed
  - Focused SDK wrapper tests: 101 passed
  - Mypy: age_graph_store.py, wrapper, and all three changed test files PASS. age_sdk_adapter.py reports 49 existing no-any-return diagnostics in unchanged direct-forwarding methods; the new decision_movement forwarder is clean (casted result). No protocol or unrelated typing changes made.
  - git diff --check: PASS in both repositories
Scope: No protocol, SQLite/InMemory backend, consumer, or graph-schema changes. Pre-existing dirty worktree files were left untouched.

## REV-AGE-PAGINATION-IMPL (review) — 2026-10-01
- Reviewer: sol/high
- Verdict: PASS
- Findings: 0 P1, 0 P2, 1 P3
- P3: `tests/test_age_graph_store.py` uses substring assertions such as `"LIMIT 100" in query`, which also matches `LIMIT 1000`; tighten to an exact clause or regex so a wrong 1000 cap cannot satisfy the default/clamp checks.
- Blast radius: clean; no incompatible consumers found in copilot-sdk apps or s2p-copilot. New AGE method parameters have defaults; protocol and wrapper public signatures remain unchanged.
- Validation: ci-platform 661 passed, copilot-sdk 4200 passed; `git diff --check` clean.
- Date: 2026-10-01

## DSTORE-MIGRATE-2-DESIGN-VERIFY (sol/high)

Date: 2026-10-02T23:41:14-07:00
Result: corrections needed. Design verification only; no runtime migration/deletion or commit performed. Both repos on main; pre-existing source edits preserved.
Files verified: 9 named files, all present; 1,924 source/config files scanned across copilot-sdk and ci-platform.
Actual deferred entries: 148 file-level scan/review entries containing 637 unique matching lines (design claimed 105). This inventory includes detection tests, historical reports and independent SQLite tools, not 148 required code edits; the previous 105-item SDK follow-up table had different scope. SDK contributes 146 files/634 lines; ci-platform contributes 2 files/3 lines. Indirect consumers and data-cutover work are additional semantic scope.
ci-platform findings: tests/test_age_graph_store_v.py retains a SQLiteGraphStore parity fixture; prompt0_ci_structural_map.py independently reads a code-review SQLite database and is not a scoring backend target. No targeted legacy-backend reference was found in ci_platform/ production Python.
Protocol gaps found: 0 missing memory methods for GraphStore (45), ProtocolV2GraphStore (66 effective) or L5LearningStore (7); 1 SDK memory signature defect (count_categories_with_n requires n instead of defaulting to 1). AGEGraphStoreAdapter has all methods and tested call shapes for those three protocols and GraphTraversalStore. Four native ScoringPersistenceStore methods remain absent; SDK consumers use GraphScoringPersistence over existing governance methods. This does not require changing AGE for backend elimination alone. Native transactional scoring upserts remain separate work; generic governance delete/create calls retain the previously noted durability/concurrency concern.
Sequencing: corrected to protocol verification/fix -> consumer migration -> infrastructure deletion -> enforcement. Resolve ProtocolV2OutcomeService's independent DurableOutbox dependency before deleting SDK graph/outbox.py; scoring PersistenceOutbox is an explicit resilience exception and rejects outcome deferral.
Corrections written to: canonical copilot-sdk docs/dstore_migrate2_design_corrections.md — [cross-repository report](../../copilot-sdk/docs/dstore_migrate2_design_corrections.md). Includes every scan hit and exact protocol signatures.
Validation: 52 focused SDK tests passed / 0 failed / 0 skipped; mypy passed for both local audit/report helpers. No product/test Python file changed; SHA-256 comparison confirms all 1,924 inventoried source/config files unchanged. No full-suite or live AGE rerun in this pass; earlier 661/4200 results remain historical.
Design document status: needs revision before implementation; apply the corrections and settle outcome durability, retained migration tools and durable-test policy. Recommended six implementation prompts plus review; 4–7 engineering days is a planning range, not measured effort. The 6–8-credit estimate is unverified.

## FIX-P4b-3a-CIPLATFORM (2026-10-04)

Added `production_ready: bool` to `AGEGraphStoreAdapter`, returning `True`. This structurally satisfies the copilot-sdk `ProductionReadyStore` runtime-checkable protocol; ci-platform does not import the SDK protocol.

Pre-check baseline: 661 passed, 0 failed. Post-check ci-platform suite: 662 passed, 0 failed. Adapter tests: 26 passed. Adapter property smoke check: PASS. `git diff --check`: PASS.

Added one dedicated adapter test using the existing `FakeGraphStore` construction pattern. It verifies the property exists, is true, and (when the SDK protocol is importable) that `isinstance(adapter, ProductionReadyStore)` succeeds.

Mypy: FAIL with 49 existing `no-any-return` diagnostics in unrelated adapter forwarding methods (same baseline diagnostics recorded by prior adapter work); the added property introduces no diagnostics. No unrelated annotation cleanup was made.

Cross-repository verification: copilot-sdk focused health/production tests passed (54 passed). Full copilot-sdk root suite passed after this adapter change: 4514 passed, 3 xfailed, 0 failed. The earlier combined direct live-app test invocation could not collect under this shell's test/offline backend environment; app suite runs before the marker addition had one live AGE classification failure each in Trading and Purchasing. The full SDK suite after adding the marker confirms the reported AGE-backed failures are cleared.

Files changed by this task: `ci_platform/graph/age_sdk_adapter.py` (new property) and `tests/test_age_sdk_adapter.py` (one new test). Other pre-existing worktree changes in these files were retained and not modified for this task.

Next: continue FIX-P4b-3b in copilot-sdk (`legacy_signal_filter.py`).

## CI-PLATFORM-SQLITE-CLEANUP (2026-10-06 17:42:29 -07:00)

- Result: PASS
- Blocker: ci-platform test imported the deleted `SQLiteGraphStore`.
- Action: migrated portable test `test_sqlite_d2_lifecycle_parity_in_memory` to `test_in_memory_d2_lifecycle_contract` using `InMemoryGraphStore`; retained its graph lifecycle assertions and removed the SQLite constructor path.
- Files changed: `tests/test_age_graph_store_v.py`, `docs/session_state.md`
- Before: ci-platform 662 passed
- After: ci-platform 662 passed / 0 failed / 0 errors
- Mypy: PASS (`tests/test_age_graph_store_v.py`)
- Architecture scan: CLEAN; no `SQLiteGraphStore`, `DualWriteStore`, `sqlite_store`, or `dual_write` references remain in Python tests after the specified exclusions.

## FIX-DRIFT-SDK-R2-CI — 2026-10-14

FIX-DRIFT-SDK-R2-CI: SHIPPED

Date: 2026-10-14

- Fixes: `get_graph_client()` now creates the shared production pool by default; governed Decision persistence performs advisory lock, identity validation, and conditional create in one database statement while retaining idempotency.
- Tests: 668 passed, 0 failed.
- Live governed-write conformance: 4 passed, including identical replay and conflict rejection.
- Mypy: clean for `age_client.py` and `age_graph_store.py`.

## FIX-DRIFT-SDK-R3-CI — 2026-10-14

FIX-DRIFT-SDK-R3-CI: SHIPPED

Date: 2026-10-14

- Fixes: AGE clients are keyed by normalized DSN and graph, pooled sessions reset on return, shared clients have explicit targeted/all shutdown, and checkpoint verified counts use the active graph transaction.
- Diagnostics: `get_pool_diagnostics()` reports pool size, checkout/return/reset counters, saturation, and registered DSN/graph keys.
- Tests: 670 passed, 0 failed.
- Mypy: clean for all R3-changed ci-platform files and tests.

## REV-DRIFT-SDK-R3-CI — 2026-10-14

REV-DRIFT-SDK-R3-CI: BLOCK
Date: 2026-10-14
Findings: 1 P1, 2 P2, 1 P3

- P1: closed AGE clients can reopen pooled connections through stale references.
- P2: reset-on-return uses two SQL executions and lacks a real checkout/return state-reset test.
- P2: the keyed client registry has no capacity or eviction bound.
- P3: pool borrow/return operations have no structured debug trace.

## FIX-DRIFT-SDK-R4-CI — 2026-10-14

FIX-DRIFT-SDK-R4-CI: SHIPPED

Date: 2026-10-14

- Fixes: permanent closed-client guard on every connection entry point, single-round-trip reset-on-return, bounded eight-client registry with close-all shutdown, native AGE decision pagination, and batched verified-decision paging.
- Diagnostics: structured pool borrow/return traces and complete pool lifecycle counters.
- Tests: 674 passed, 0 failed; focused AGE client/store/adapter coverage 233 passed.
- Mypy: clean on all R4-changed ci-platform files and tests.

## REV-DRIFT-SDK-R4-CI — 2026-10-14

REV-DRIFT-SDK-R4-CI: BLOCK

Date: 2026-10-14

Findings: 2 P1, 0 P2, 0 P3

- P1: `_ensure_pool()` does not recheck `_closed` after acquiring `_pool_lock`, allowing concurrent close/ensure to recreate a pool on a permanently closed client.
- P1: AGE verified paging exposes only creation-ordered numeric offsets; it provides no stable verification cursor for checkpoint replay, so late verification can move an unprocessed row into the skipped prefix.

Recorded R4 baseline: 674 passed; tests were not rerun during this read-only review.

## FIX-DRIFT-SDK-R5-CI — 2026-10-15

FIX-DRIFT-SDK-R5-CI: DONE

Date: 2026-10-15

Fixes: R5-1 closed-client TOCTOU race, plus the AGE-native pagination and composite verification cursor required by R5-3/R5-4.

Changes:
- `ci_platform/graph/age_client.py` — close and pool creation use the same lifecycle lock; explicit fresh-mode factory calls stay outside the pooled registry; psycopg server-side preparation is disabled for AGE connections.
- `ci_platform/graph/age_graph_store.py`, `age_sdk_adapter.py` — native offset/limit and `(verified_at, decision_id)` filtering with creation-time replay ordering.
- `tests/test_age_client.py`, `test_age_graph_store.py`, `test_age_sdk_adapter.py` — concurrent close, connection-mode, pagination, and cursor coverage.

Tests: 676 passed, 0 failed.

Mypy: clean on all changed ci-platform files.

## REV-DRIFT-SDK-R5-CI

Status: BLOCK
Verdict: BLOCK — P1-A PARTIALLY FIXED against this review's lifecycle requirements; P1-B NOT FIXED.
Date: 2026-10-15
Reviewer: Sol
Baseline: 676 passed, 0 failed, 0 skipped

### Scope and comprehension gate

Read session state first and confirmed FIX-DRIFT-SDK-R5-CI is DONE with 676 passed / 0 failed. Read all six requested files completely, in order, before issuing findings. Actual test paths are `tests/test_age_client.py`, `tests/test_age_graph_store.py`, and `tests/test_age_sdk_adapter.py`. Completed the architecture, change-inventory, and dependency-map gate before proceeding to validation.

File architecture:

1. `ci_platform/graph/age_client.py` owns AGE connection creation, the shared client registry, pooled checkout, transactions, and shutdown. R5-relevant changes coordinate open-state checks with pool creation, bypass the registry for fresh factory clients, and disable automatic preparation when creating AGE connections.
2. `ci_platform/graph/age_graph_store.py` implements synchronous graph persistence and generates Cypher through AGEClient. Its R5 verified-read implementation adds a composite verification boundary to native paging while preserving creation-time replay ordering.
3. `ci_platform/graph/age_sdk_adapter.py` exposes AGEGraphStore through the SDK interface. The actual class name is AGEGraphStoreAdapter. It forwards the verified-read pagination arguments unchanged and retains the list-of-dictionaries return shape.
4. `tests/test_age_client.py` covers connection modes, pooling, registry lifecycle, query execution, and live AGE access. Relevant checks cover fresh registry exclusion, preparation settings, closed-client rejection, and an ensure/close interleaving.
5. `tests/test_age_graph_store.py` covers generated Cypher, persistence operations, protocol signatures, and live AGE writes/reads. The pagination test checks SKIP/LIMIT and the composite predicate as strings, including an assertion requiring creation-time ordering.
6. `tests/test_age_sdk_adapter.py` covers structural protocol compatibility and delegation. Its fake store accepts and records verified pagination arguments, but does not apply the verification boundary to its data.

Dependency map: AGEGraphStoreAdapter -> AGEGraphStore -> AGEClient -> psycopg/psycopg_pool -> PostgreSQL/AGE. Each corresponding test file exercises its production counterpart. Store unit tests substitute FakeAGEClient; adapter unit tests substitute FakeGraphStore; the live tests exercise the real chain.

R5-relevant inventory (current-file line numbers):

| File:line | Behavior | Finding addressed |
|---|---|---|
| age_client.py:288 | Shared lifecycle-lock helper, including legacy test doubles | P1-A |
| age_client.py:296 | Open-state check under that lock | P1-A |
| age_client.py:301 | Fresh connection creation under lifecycle lock; prepare_threshold=None | Lifecycle / AGE compatibility |
| age_client.py:313 | Recheck closed state inside pool-creation/lookup lock | P1-A |
| age_client.py:334 | Disable automatic preparation for pooled connections at creation | AGE compatibility |
| age_client.py:371,744,762 | Connection/query/transaction entry points use the locked open-state check | P1-A |
| age_client.py:423 | Mark closed and detach pool under lock; close detached pool outside lock | P1-A |
| age_client.py:1397 | Return an unregistered fresh client before entering shared registry lock | Lifecycle isolation |
| age_graph_store.py:2927 | Verified pagination accepts verification boundary, offset, limit, chronological | P1-B |
| age_graph_store.py:2942 | Lexicographic timestamp/decision-ID predicate | P1-B |
| age_graph_store.py:2961 | Obtain outcome verification timestamp with creation-time fallback | P1-B |
| age_graph_store.py:2965 | Retain creation-time/decision-ID ordering, then SKIP/LIMIT | P1-B |
| age_sdk_adapter.py:353 | Forward all verified pagination arguments | P1-B |
| tests/test_age_client.py:62,188,272,290,613 | Registry exclusion, preparation settings, post-close rejection, ensure/close synchronization | P1-A / supporting coverage |
| tests/test_age_graph_store.py:815 | Query-text assertions for paging and verification predicate | P1-B |
| tests/test_age_sdk_adapter.py:51 | Fake-store signature and call-recording changes | P1-B |

Attribution limitation: there is no isolated R4/R5 commit or supplied before-R5 snapshot. HEAD is f08452c and the working tree combines multiple rounds. This inventory identifies the R5 areas from session state and current code; it is not a certified line-by-line isolated R5 patch. Native get_decisions offset/ordering support at age_graph_store.py:2897 and age_sdk_adapter.py:339 is also present in the combined diff and is already described in the R4 session entry.

### Blocking finding

**P1 — P1-B remains unfixed: verification boundary and page order disagree, and checkpoint replay still uses offsets.**

Locations: `ci_platform/graph/age_graph_store.py:2942`, `:2965`, `:2937`; corresponding incorrect-order assertion `tests/test_age_graph_store.py:842`. The SDK consumer at `../copilot-sdk/copilot_sdk/scoring/scorer.py:628` advances page_offset while retaining the same replay_cursor at `:634`.

The predicate compares `(coalesce(o.verified_at, d.created_at), d.decision_id)`, but ORDER BY compares `(d.created_at, d.decision_id)`. These are different total orders. A caller advancing the verification cursor from the last returned row can skip unseen rows or repeat already returned rows even with no concurrent writes.

Concrete counterexample: records A=(created 1, verified 30), B=(created 2, verified 10), C=(created 3, verified 20). With limit=1 and boundary=(0, ""), page 1 returns A. Advancing to (30, "A") produces an empty page, missing B and C. With limit=2, page 1 is [A,B]; advancing to (10,"B") produces [A,C], repeating A.

The actual SDK consumer instead keeps a fixed checkpoint boundary and increments numeric offsets. This also retains the original concurrency defect: after page 1 returns A, a newly verified older-created B can enter the prefix, so offset=1 returns A again and B is skipped. A fixed verification lower bound does not freeze membership or order of the remaining result set.

Required fix: establish one consistent continuation contract across AGE and SDK checkpoint replay. A keyset continuation must filter and order by the same immutable key and advance that key between pages. If replay must preserve historical creation order, explicitly design a stable replay snapshot/continuation that preserves it; simply changing ordering may alter replay behavior. Define cursor/offset interaction, preserve existing caller compatibility, and add behavioral traversal/concurrent-verification tests. Do not claim an unconditional concurrency guarantee from wall-clock verification timestamps: write_outcome accepts supplied verified_at at age_graph_store.py:1389, and transactions may commit out of timestamp order. Late rows behind a boundary require an explicit policy or stronger snapshot/progress semantics.

### P1-A lifecycle review

| Check | Result | Evidence |
|---|---|---|
| 1a Same lock; held through destruction | FAIL | Both methods use _lifecycle_lock, but _sync_close releases it before pool.close at age_client.py:430. Lookup at :386 and checkout at :389 are separate from shutdown. |
| 1b Waiting ensure detects closed | PASS | _ensure_pool rechecks _closed inside the shared lock before returning or creating a pool, age_client.py:314. The original R4 pool-recreation defect is fixed. |
| 1c Fresh isolation | CONCERN | Factory-created fresh clients bypass the pooled registry and registry-wide shutdown. However one-shot connection creation at :301 acquires the same lifecycle lock and individual close permanently closes the client, so the stronger no-pool-lock/no-close-interaction requirement is not met. |
| 1d Preparation disabled at creation | PASS | prepare_threshold=None is supplied to psycopg.connect at :308 and pooled connection kwargs at :334. This is local to AGEClient connection creation, not a global driver setting. |
| 1e Concurrent query/close and post-close tests | FAIL overall | Post-close ensure/query/transaction rejection exists at tests/test_age_client.py:272. The concurrency test at :290 races only _ensure_pool with close; its fake pool has no checkout/query operation. It does not exercise the lookup-to-checkout window required by this review. |

A focused probe used the real installed psycopg_pool with zero initial connections, pausing an actual AGEClient.run_query after pool lookup, closing the client, then allowing checkout. Result: PoolClosed propagated, lifecycle lock was not held during pool.close, no pool was recreated, and subsequent _ensure_pool raised RuntimeError. No database connection was made by this probe.

Important distinction: this is not evidence of a dangling database connection or unsafe memory access. Installed psycopg_pool.close explicitly rejects waiting/future borrowers and retains checked-out connections until return. Thus the original R4 resurrection bug is FIXED; the stronger lookup/checkout/destruction serialization requested here is only PARTIALLY FIXED. Do not classify the clean PoolClosed failure itself as silent corruption.

### P1-B cursor review

| Check | Result | Evidence |
|---|---|---|
| 2a Composite predicate | PASS for predicate | age_graph_store.py:2942 uses timestamp > boundary OR timestamp equality AND decision_id > boundary. Overall stability fails because ordering differs. |
| 2b Deterministic verification ordering | FAIL | :2965 orders by creation time, not verification time. The creation order is deterministic for unique IDs but is incompatible with the predicate. |
| 2c Separate offset mode / conflict rule | FAIL | :2937 and :2942 apply SKIP and the verification predicate together; no mutual-exclusion validation or documented precedence exists. Both actually affect results. |
| 2d Opaque returned cursor | FAIL | Both methods accept a caller-built tuple and return plain row lists. No page result returns a continuation cursor. The current SDK protocol also specifies that tuple/list interface, so satisfying this stronger requirement needs coordinated API design rather than silently replacing its return type. |
| 2e Concurrent verification stability | FAIL | Static keyset traversal already skips/repeats rows; fixed-watermark offset replay also shifts when an older-created decision becomes verified. |
| 2f Adapter translation | PASS | age_sdk_adapter.py:362 forwards both cursor fields and all paging arguments unchanged; returned rows are preserved. It cannot correct backend ordering or add absent cursor metadata. |
| 2g Behavioral test coverage | FAIL | tests/test_age_graph_store.py:815 provides empty fake responses and asserts query text. No exactly-once multi-page dataset or between-page verification test exists in the reviewed files. The adapter fake at :51 records but ignores verified_after. |

The static and concurrent examples were executed using a semantic evaluator of the actual emitted query's predicate, sort, SKIP, and LIMIT. They are controlled counterexamples, not live AGE pagination probes. Probe artifact: workspace `.codex_tmp/rev_drift_sdk_r5_ci_probe.py` (outside ci-platform source/tests).

### Blast radius and cross-cutting checks

| Check | Result | Evidence |
|---|---|---|
| 3a Exactly six R5 files | CONCERN / unverified | git status includes the six files, session state, and ci_platform/graph/__init__.py. The latter exports registry shutdown/reset helpers described by earlier R3 work. No isolated R5 baseline exists to certify exact attribution; do not label the earlier export change a proven R5 scope violation. |
| 3b Store/adapter public compatibility | PASS for existing call shapes and returns | AST comparison against HEAD found no removed public methods or changed return annotations. Pagination arguments are optional keyword-only additions. The API is extended, not literally identical. Current SDK signature tests pass. |
| 3c Client public compatibility | PASS for call signatures; lifecycle concern above | Existing connect/close/run_query/run_transaction call patterns remain. Post-close use explicitly raises as required. |
| 3d Dependencies | PASS | No dependency manifest changes. Added imports in the broader production diff are stdlib atexit/contextlib/typing; store/adapter add no imports. psycopg_pool was already used before this round. |
| 4a Shared mutable state | CONCERN | Normal construction creates one lifecycle lock; pool writes and closed checks are protected, metrics have their own lock, and the registry has its own lock. Diagnostic pool reads may be stale without affecting queries. Registry closed-state reads may race with direct close, but subsequent query checks fail closed. The lookup-to-checkout window remains as described in 1a. |
| 4b Query error propagation | PASS | _pooled_connection rethrows non-timeout errors; _sync_execute logs and rethrows after its bounded AGE conflict retry. AGEGraphStore._run_query maps PoolClosed to GraphUnavailableError with the original cause. No silent empty-result fallback for these exceptions. |
| 4c Pool survives query errors | PASS | A controlled borrower exception propagated, checkout/return counters remained balanced, and subsequent _ensure_pool returned the same pool. Query failure does not detach the pool. Installed ConnectionPool.wait closes itself on initialization timeout. |
| 4d Mypy | PASS | Required command returned Success: no issues found in 3 source files. |
| 4e Full tests | PASS | python -m pytest tests/ -q --timeout=120: 676 passed, 0 failed, 0 skipped, 1352 pytest_freezegun deprecation warnings, 81.16s. |

Additional finding classification:

- P1 (blocking): verification predicate/order mismatch plus offset-based continuation leaves P1-B open, detailed above.
- P2 (next round): complete or explicitly reconcile the stronger lifecycle acceptance contract at age_client.py:385/:423, including an actual query-versus-close regression test. Original closed-client recreation is fixed; safe pool rejection remains possible.
- P2 (next round): reconcile opaque cursor and cursor/offset rules with the existing SDK tuple/list contract at age_graph_store.py:2927 and age_sdk_adapter.py:353; add behavioral tests at tests/test_age_graph_store.py:815 and tests/test_age_sdk_adapter.py:51. These are also missing acceptance criteria for P1-B closure.
- P3 (tracked): age_client.py:193 documents fresh close as a no-op, but _sync_close marks fresh clients permanently closed. Update documentation to match the chosen lifecycle contract. This stale documentation is not established as newly introduced in R5.

### Verification and review-only boundary

- Read session state first: yes.
- Read all six files before findings: yes; comprehension gate delivered before review/test execution.
- Required mypy command on all three production files: passed.
- Full test suite: 676 passed / 0 failed / 0 skipped.
- Checked blast radius: yes; exact R5 attribution remains unverified for the reasons above.
- No production or test files edited. SHA-256 comparison across all 87 Python files under ci_platform/ and tests/ showed no changes during validation. The only repository edit by this review is this session-state append.
- Appended review results: yes.

R5 drift is NOT closed. Green tests and mypy do not establish cursor correctness, and this review does not claim live-stack closure.

## FIX-DRIFT-SDK-R6-CI

Date: 2026-10-15
Status: DONE — scoped ci-platform fixes and validation complete; SDK consumer follow-up remains outstanding.

Prerequisite: REV-DRIFT-SDK-R5-CI was BLOCK, with P1-A PARTIALLY FIXED and P1-B NOT FIXED. Recorded and previously executed baseline: 676 passed, 0 failed, 0 skipped.

Comprehension gate: reused the complete, ordered reads of all six files from the immediately preceding R5 review after verifying their SHA-256 hashes were unchanged. Rechecked edit sites and delivered architecture summaries, fix targets, and exact before/after production/test blocks before editing. Captured a task-start manifest of 186 repository files to distinguish R6 edits from earlier uncommitted changes.

Fixes applied:

- P1-B ORDER BY alignment: when verified_after is supplied, both the WHERE predicate and ORDER BY use the same `_verified_at = coalesce(o.verified_at, d.created_at)` timestamp and decision-ID tiebreaker, ascending. The verification alias is included in RETURN DISTINCT so AGE can order by that projected value. Public result shape remains the merged list of decision/outcome dictionaries.
- P1-B cursor precedence: a supplied verified_after suppresses SKIP entirely, ignoring offset. A code comment documents the rule. Without a cursor, existing creation-time ordering and SKIP/LIMIT behavior are preserved.
- P1-A PoolClosed conversion: ExitStack separates checkout context entry from query execution and context exit. Only PoolClosed raised during checkout entry becomes `RuntimeError("AGE client is closed")`, chained from the original exception. PoolClosed raised after successful checkout is not converted. Pool destruction remains outside the lifecycle lock; the existing permanent closed-state guard is retained.

Files changed by R6:

- `ci_platform/graph/age_client.py`
- `ci_platform/graph/age_graph_store.py`
- `tests/test_age_client.py`
- `tests/test_age_graph_store.py`
- `docs/session_state.md` (this append)

`ci_platform/graph/age_sdk_adapter.py` and `tests/test_age_sdk_adapter.py` required no changes. No SDK, wrapper, scorer, dependency, or other repository files were changed by this task. Earlier uncommitted edits, including graph/__init__.py, were preserved.

Tests added: five test functions / six collected cases.

- `test_verified_pagination_visits_all_exactly_once`: uses the existing disposable live-AGE graph fixture, writes the five requested decisions with differing creation/verification order, traverses limit=2 pages with an advancing cursor, checks ordered keys and disjoint pages, and verifies all five IDs exactly once in D4,D2,D5,D1,D3 order.
- `test_keyset_cursor_suppresses_skip`: supplies cursor plus offset=13 and verifies no SKIP; verifies offset-only reads retain SKIP and both modes retain LIMIT.
- `test_pool_closed_converts_to_runtime_error`: establishes a real psycopg pool with zero initial connections, closes it directly while leaving the client open, then verifies checkout raises exactly RuntimeError with the PoolClosed cause and does not replace the pool.
- `test_close_then_query_consistent_error`: closes the client through the async public API, verifies subsequent run_query raises RuntimeError, and verifies no pool recreation.
- `test_pool_closed_after_checkout_is_not_converted`, parameterized for query and return: verifies both post-checkout exceptions preserve their original type/object and keep checkout/return accounting balanced.

Existing tests updated: retained the native pagination test and corrected its cursor ORDER BY assertion; added the real PoolClosed exception export to the existing fake pooling module.

Before-fix regression evidence: live AGE traversal failed because the first page was not verification-ordered; the precedence test failed because SKIP was present; the checkout test failed with unconverted psycopg_pool.PoolClosed. The post-close and two post-checkout preservation cases already passed before the fix.

Validation:

- `python -m pytest tests/test_age_graph_store.py -k "visits_all_exactly_once or suppresses_skip" -v`: 2 passed, including the live AGE traversal; 0 skipped.
- `python -m pytest tests/test_age_client.py -k "pool_closed_converts or close_then_query_consistent" -v`: 2 passed.
- `python -m pytest tests/ -q --timeout=120`: 682 passed, 0 failed, 0 skipped, 1364 existing pytest_freezegun deprecation warnings, 56.83s.
- Required mypy command with `--config-file pyproject.toml` on age_client.py, age_graph_store.py, and age_sdk_adapter.py: clean, 3 source files.
- Additional mypy check on both changed test files with the same config: clean, 2 source files.
- `git diff --check`: passed.
- Baseline delta: 676 -> 682 (+6 collected regression cases).
- Task-start hash comparison confirms source/test changes are confined to the four listed files; session state is the only additional repository edit.

Self-check: session state read first; all six complete reads validated against unchanged file hashes before changes; changes confined to allowed scope; cursor ORDER BY matches predicate; cursor suppresses SKIP; checkout-only PoolClosed conversion verified; mypy and full suite passed; session state appended.

Outstanding SDK dependency (explicitly out of scope): `copilot_sdk/scoring/scorer.py:628` still advances page_offset with a fixed replay_cursor. This is a separate copilot-sdk fix and was not addressed here. Because the cursor now takes precedence over offset, that caller can repeat the same full batch until it is changed to advance its cursor. These ci-platform results do not establish end-to-end checkpoint replay closure or unrestricted concurrent-write snapshot guarantees.

## REV-DRIFT-SDK-R6-CI

Date: 2026-10-15
Reviewer: Sol
Status: PASS
VERDICT: PASS (scoped R6 fixes; not end-to-end SDK replay closure)
P1-A (checkout PoolClosed conversion): FIXED
P1-B (cursor/order mismatch and cursor/offset precedence): FIXED

### Prerequisites and comprehension gate

Read docs/session_state.md completely, followed by the six requested files completely in order. Confirmed REV-DRIFT-SDK-R5-CI is BLOCK with P1-A PARTIALLY FIXED and P1-B NOT FIXED; FIX-DRIFT-SDK-R6-CI reports 682 passed, zero failed/skipped, and clean mypy. Architecture summaries and change inventory were delivered before proceeding to fix verification.

- ci_platform/graph/age_client.py owns AGE connections, pool checkout, transaction execution, and lifecycle management. R6 isolates context entry so only checkout PoolClosed becomes the client's RuntimeError; shutdown and return handling remain intact.
- ci_platform/graph/age_graph_store.py implements graph persistence and reads through AGEClient. R6 aligns verified keyset ordering with its predicate and suppresses offset in cursor mode.
- ci_platform/graph/age_sdk_adapter.py exposes the SDK interface through delegation to AGEGraphStore. R6 makes no changes; pagination forwarding remains transparent.
- tests/test_age_client.py covers client configuration, pooling, lifecycle, serialization, and live queries. R6 adds direct-pool-close and post-client-close checks plus two exception-boundary cases.
- tests/test_age_graph_store.py covers generated queries, persistence semantics, and live AGE operations. R6 corrects the cursor-order assertion and adds real graph traversal and SKIP precedence coverage.
- tests/test_age_sdk_adapter.py covers protocol compatibility, delegation, and live adapter behavior. R6 makes no changes.

### R6 change inventory and scope

Current-file line ranges:

| File:lines | R6 change | Requirement match |
|---|---|---|
| ci_platform/graph/age_client.py:38 | Add stdlib ExitStack import | Supports checkout-only conversion |
| ci_platform/graph/age_client.py:385-398 | Local PoolClosed import; enter pool context through ExitStack; catch at entry and chain RuntimeError | P1-A, matches |
| ci_platform/graph/age_graph_store.py:2937-2940 | Document cursor precedence and suppress SKIP when verified_after is supplied | P1-B, matches |
| ci_platform/graph/age_graph_store.py:2952-2954 | Select verification alias for cursor sorting; preserve creation sorting for legacy offset reads | P1-B, matches |
| ci_platform/graph/age_graph_store.py:2965-2967 | Project verification alias in RETURN DISTINCT and order by selected alias plus decision ID | P1-B, matches |
| tests/test_age_client.py:134,163 | Supply real PoolClosed in existing fake pool module | Necessary test-double compatibility |
| tests/test_age_client.py:292-314 | Direct pool-close regression with exact exception type, message, cause, and unchanged pool reference | Required test 3c |
| tests/test_age_client.py:317-327 | Close client, then reject run_query without pool recreation | Required test 3d |
| tests/test_age_client.py:330-360 | Parameterized query/return cases preserving post-checkout PoolClosed and accounting | Two additional regression cases |
| tests/test_age_graph_store.py:842 | Correct existing cursor ORDER BY assertion | Explicitly required |
| tests/test_age_graph_store.py:845-899 | Live AGE traversal over differing creation/verification orders | Required test 3a |
| tests/test_age_graph_store.py:902-915 | Cursor plus offset emits no SKIP; offset-only retains SKIP; both retain LIMIT | Required test 3b |
| ci_platform/graph/age_sdk_adapter.py; tests/test_age_sdk_adapter.py | No R6 changes | Matches scope |
| docs/session_state.md:440-490 | R6 results, validation, and outstanding SDK dependency | Required documentation |

Scope PASS: compared the pre-R6 SHA-256 snapshot with the current manifest of 186 tracked/untracked, nonignored repository files. Exactly four source/test files above and session state differ. Earlier uncommitted changes, including graph/__init__.py, are not R6 changes. No new dependency manifest, scorer, wrapper, or other repository file changed in R6. The adapter and its tests are byte-for-byte unchanged from the pre-R6 snapshot.

### P1-B verification

| Check | Result | Evidence |
|---|---|---|
| 1a Predicate timestamp | PASS | age_graph_store.py:2947-2950 uses _verified_at > boundary OR (_verified_at = boundary AND d.decision_id > boundary_id). |
| 1b Sort timestamp | PASS | :2954 selects _verified_at when a cursor exists; :2967 emits ORDER BY _verified_at ASC, _decision_id ASC. |
| 1c Identical expression | PASS | WHERE and ORDER BY both use the exact alias _verified_at. Its single definition at :2962 is coalesce(o.verified_at, d.created_at). _decision_id at :2965 aliases the same d.decision_id used by the predicate. |
| 1d Counterexample | PASS | Trace below visits all three records exactly once. |
| 1e Cursor excludes offset | PASS | :2939 produces an empty pagination prefix when verified_after is not None. LIMIT is added separately. SKIP exists only in offset mode. Precedence is documented at :2937. |
| 1f Existing assertion | PASS | tests/test_age_graph_store.py:842 now asserts verification-alias ordering for cursor mode. The creation-order assertion at :836 correctly remains for offset-only mode. |

Counterexample replay with limit=1:

| Incoming cursor | Eligible records in query order | Page | Next cursor |
|---|---|---|---|
| (0, "") | B(10), C(20), A(30) | B | (10, "B") |
| (10, "B") | C(20), A(30) | C | (20, "C") |
| (20, "C") | A(30) | A | (30, "A") |
| (30, "A") | none | empty | finished |

This is a trace of the emitted predicate and order. The five-record regression independently executes the ordering and continuation against live AGE.

### P1-A verification

| Check | Result | Evidence |
|---|---|---|
| 2a Checkout catch | PASS | age_client.py:392-397 catches PoolClosed around stack.enter_context(pool.connection(...)). Both context construction and entry are inside that catch. |
| 2b Public error and cause | PASS | :397 raises RuntimeError("AGE client is closed") from exc. |
| 2c Import | PASS | PoolClosed is imported locally from psycopg_pool at :387, before use; optional pooling remains lazily imported. |
| 2d Close outside lock | PASS | :432-437 marks closed and detaches the pool under the lifecycle lock; :438-439 destroys it after leaving that block. |
| 2e Checkout-only boundary | PASS | Yield/query execution at :406 and ExitStack cleanup lie outside the inner catch. Existing timeout handling is unchanged. The two extra regression cases assert post-checkout PoolClosed remains unconverted. |

### Test review

All four requested behavioral tests exist with real bodies and assertions.

- 3a PASS: live AGE data uses the requested five creation days and verification days [15,10,20,8,12]. limit=2 pages advance the last composite key; each page is ordered, every key is beyond the prior boundary, pages are disjoint, and the final sequence is exactly D4,D2,D5,D1,D3 with five unique IDs.
- 3b PASS: verified_after plus offset=13 excludes SKIP; offset-only includes SKIP 13; LIMIT 2 remains in both modes.
- 3c PASS: establishes an actual psycopg pool with zero initial connections, calls pool.close directly while client._closed is False, attempts checkout, and asserts exact RuntimeError, closed message, and PoolClosed cause. This exercises the relevant closed-pool/open-client window without requiring a database connection.
- 3d PASS: calls the public asynchronous client.close, then run_query, asserting RuntimeError and no recreated pool.
- 3e PASS: four required tests plus a fifth function parameterized over query and return give six additional collected cases, matching 676 -> 682.
- 3f PASS: fresh full-suite result recorded below confirms the session-state count.

### Architectural invariants

- 4a PASS: no scorer formulas, tensor values, penalty ratios, learning rates, or conservation thresholds changed in R6.
- 4b PASS: no new module-global mutable state; new test pools, errors, and collections are local.
- 4c PASS: no new DecisionStore imports in store or adapter; production additions are stdlib ExitStack and the already-used psycopg_pool package's exception type.
- 4d PASS: unchanged age_sdk_adapter.py:353-368 forwards domain, offset, limit, chronological, and verified_after without transformation.
- 4e PASS: R6 did not change the SDK consumer. Read-only inspection confirms scorer.py:628-640 still advances page_offset with the fixed replay_cursor at :634.

### Findings and outstanding items

No new P1 or P2 findings in the scoped R6 changes. Both requested fixes are correctly implemented.

P3-OBS-1 (inherited, not introduced by R6): age_client.py:193-198 still describes fresh-mode close as a no-op, although _sync_close permanently marks the client closed. Update that documentation in a later round; no production edits made in this review.

Outstanding items, not attributed to R6:
- SDK consumer copilot_sdk/scoring/scorer.py:628-640 must advance its verification cursor rather than increment an offset against a fixed cursor. With cursor precedence, a full batch can repeat indefinitely. This remains an explicit separate SDK fix.
- The existing tuple-input/list-output API is not an opaque returned-cursor API. Any change requires coordinated SDK/backend design.
- Arbitrary backdated verification writes, commits arriving behind an advanced timestamp boundary, and unrestricted concurrent-write snapshot guarantees remain outside the evidence established here.
- The inherited fresh-close documentation observation above remains tracked.

R6 passes its requested ci-platform scope. This verdict does not close end-to-end checkpoint replay or all historical drift findings.

### Fresh review validation and read-only boundary

- python -m mypy ci_platform/graph/age_client.py ci_platform/graph/age_graph_store.py ci_platform/graph/age_sdk_adapter.py --config-file pyproject.toml: Success, no issues found in 3 source files.
- python -m pytest tests/ -q --timeout=120: 682 passed, 0 failed, 0 skipped, 1364 existing pytest_freezegun deprecation warnings, 71.59 seconds. Live AGE traversal executed without skipping.
- git diff --check: passed (only existing line-ending notices).
- Reviewed all six files completely and in the requested order before findings.
- This review changes only docs/session_state.md; no production or test files edited.

## IMPL-BOUNDED-AGE / P2b (2026-10-15)

Status: implementation complete; P2c unblocked.

### Scope and contract decisions

- Production modified: ci_platform/graph/age_client.py, ci_platform/graph/age_graph_store.py, ci_platform/graph/age_sdk_adapter.py.
- Production created: ci_platform/graph/bounded_projection.py, ci_platform/graph/bounded_projection_migration.py.
- Tests created: tests/test_bounded_projection.py, tests/test_bounded_projection_age.py, tests/test_bounded_projection_migration.py.
- Existing test modified: tests/test_age_graph_store.py. Its transaction fake now consumes queued outcome responses inside transactions; query-capture assertions select the mutation statement rather than assuming it is the first statement. The governed-write test checks one transaction, a domain lock, and one mutation statement. Existing behavioral assertions remain.
- Documentation: this required session-state append.
- No copilot-sdk, wrapper, factory, protocol, scorer, formula, dependency-manifest or application files edited. Existing unrelated working-tree changes were preserved; HEAD~1 was not used as the scope baseline.
- User explicitly authorized transaction hooks inside existing AGEGraphStore mutations, with public signatures and the legacy adapter preserved.
- User corrections override the old design/prompt: generation fencing IS allowed with a cursor; verified ordering excludes pending and raises for matching verified rows missing verified_at. Generic missing creation keys use (0.0, actual decision_id). Supplemental H/LegacyOrder semantics are not changed.
- Implemented actual shipped names/signatures: query_decisions(domain, *, filters=None, projection="summary", page=None, as_of_generation=None); count_decisions(domain, *, filters=None); aggregate_decisions(domain, *, filters=None, group_by=(), metrics=("count",)); get_decision_changes(domain, *, after_generation, limit=1000, projection="full", filters=None). SDK dataclasses/results/Literal aliases remain unchanged. Abandoned get_decision_projections/count_decision_projections names were not introduced.

### Implementation and comprehension result

Before: the legacy AGEGraphStoreAdapter exposed V2 only; no bounded canonical fields, domain generation anchor, feed or activation marker.
After: BoundedAGEGraphStoreAdapter is a separate subclass in the same module; its constructor and every bounded read require same-graph activation for the physical domain.

The compiler has no SDK imports: primitive predicates, closed projection/group/metric manifests, canonical normalization, matching timestamp/ID cursor predicates and ordering, native scalar count and aggregate queries. Query/count/aggregate share predicates. Narrow projections select explicit properties; learning_metadata retains only its five allowed fields. Full projections hide internal bookkeeping. Query output uses limit+1; aggregates fetch at most 1001 groups and raise the SDK cardinality exception above 1000.

AGEClient._S is the existing inner-Cypher literal serializer, not a PostgreSQL positional parameter. New AGETransaction.run_bounded_cypher uses it through compiled queries, quotes the graph identifier argument, and chooses an outer dollar delimiter absent from the serialized query. Live tests exercise quotes, backslashes and dollar delimiters. Existing client methods/public signatures are unchanged.

Mutations acquire a transaction-scoped exclusive advisory lock per graph/physical domain. Domain generation, canonical fields and event-time payload are persisted on the same AGE connection/transaction as the Decision mutation. Hooks cover plain create, governed create, successful verification (including the existing combined centroid transaction), both archive methods, and domain-scoped reset. Identical governed/outcome replay emits no event. Domain reset retains generation/feed anchors and emits routing-preserving tombstones before removal. Reads use the matching shared lock through generation checking and result fetch; feed terminal next_generation advances to committed H even for a routing-filtered empty page.

Migration migrate(store, domain) validates active decision identities, tenant conflicts and timestamp ambiguity before backfill; initial events are idempotent, including reruns after later hooked writes. Canonical fields, BoundedDomain, BoundedDecisionEvent and BoundedActivation all live in the same graph. Graph-level migration locking coordinates label installation. deactivate(store, domain) removes activation only: evidence, canonical fields and writer tracking remain, and existing bounded instances reject reads until reactivation.

Nonfinite confidence values are explicitly represented/normalized because AGE numeric ordering differs from Python. Positive inclusive native predicates use finite canonical numbers plus signed-infinity cases; NaN cannot pass a bound. Aggregate reductions preserve nonfinite results when no filter excludes them. Live tests cover plain and governed writes with NaN/+inf/-inf, query/count/average parity, empty aggregates, all four group aliases and missing dimensions.

### Validation

- Actual before baseline: 682 passed, 0 failed, 0 skipped; 1364 existing pytest_freezegun deprecation warnings, 102.42 seconds. The prompt's 224/8 baseline was stale for this checkout.
- Final: python -m pytest tests/ -q --timeout=120: **742 passed, 0 failed, 0 skipped**, 1484 instances of the same existing warning, 143.72 seconds.
- New tests: **60 collected/passed cases** across the three new files; total delta is exactly +60.
- Live AGE tests ran against uniquely named disposable protocol_v2_test_bounded_* graphs with cleanup; GRAPH_DSN was present. No shared production graph was migrated or activated.
- Covered: activation/revocation, idempotent backfill, conflict rollback, native filters/counts/aggregates, all projections and independent event payloads, fenced cursor paging in both directions with reversed creation/verification order, null creation keys and missing verification errors, routing filters/watermark, create/verify/archive/reset events, concurrent generation allocation, injected event failure rolling back the Decision and generation, cardinality ceiling and literal-boundary injection cases.
- Mypy command with --config-file pyproject.toml on all five production files and all three new test files: **Success: no issues found in 8 source files**. No new type-ignore/cast suppression.
- Fresh-process imports of compiler, migration and adapter modules loaded **no copilot_sdk modules**. SDK result types are imported only when bounded capability is used.
- Pre-P2b source snapshot comparison: AGEGraphStoreAdapter class byte-for-byte unchanged; existing age_client code unchanged after removing the new transaction method. Existing graph-store changes are confined to the seven decision mutation/serialization methods identified above plus the hook import.

AGEGraphStoreAdapter unchanged: YES.
Import cycle check: YES.
Activation marker guard: YES.
P2c unblocked: YES (implementation prerequisite; independent review/rollout gates remain).

### Rollout and remaining scope

Install this writer-hook version on every writer and quiesce older binaries before running migrate(store, physical_domain); reconcile backfill and commit activation before selecting the bounded variant. Advisory locks cannot coordinate older writers that do not acquire them. Removing activation reverts capability selection, not the stored evidence. No automatic production cutover was performed.

P2c owns wrapper/policy composition and factory selection in copilot-sdk. Supplemental consumer capabilities and H ordering remain later work. The previously tracked SDK replay consumer's fixed-cursor/offset issue is untouched. Passing disposable-AGE contracts does not claim end-to-end live-stack gap closure under Rule 85.


## REV-P2b (2026-10-15)

Verdict: FAIL.
Findings: 1 P1, 2 P2, 0 P3.
Fixer needed: YES.
P2c unblocked: NO, pending the fixes and re-review below.

### Review provenance and scope

This is a critical self-review, not an independent-author review: the reviewer authored the preceding P2b implementation in this thread. No production, test, or design files were changed during review. Only this required session-state entry was appended. Disposable live AGE graphs were created and removed for probes; no production graph was activated.

Scope: P2b working-tree changes, not a P2b commit (none exists). HEAD is f08452c. The completion entry and retained pre-P2b source snapshots define the change boundary; HEAD~1 was not used. Existing unrelated changes remain outside scope.

Files reviewed:
- ci_platform/graph/bounded_projection.py (new)
- ci_platform/graph/bounded_projection_migration.py (new)
- ci_platform/graph/age_sdk_adapter.py (bounded subclass/import additions)
- ci_platform/graph/age_graph_store.py (mutation transaction hooks and serialization)
- ci_platform/graph/age_client.py (new transaction query executor)
- tests/test_bounded_projection.py (new)
- tests/test_bounded_projection_age.py (new)
- tests/test_bounded_projection_migration.py (new)
- tests/test_age_graph_store.py (transaction fake/query assertion adaptations)
- docs/session_state.md (implementation report)

No SDK, scorer, wrapper, factory, protocol, application, or dependency-manifest changes belong to P2b. The legacy AGEGraphStoreAdapter class compares exactly with its pre-P2b snapshot. Existing age_client.py content compares exactly after removing the new run_bounded_cypher method. Existing AGEGraphStore changes are confined to _write_decision_impl, write_governed_decision, _decision_props, _write_outcome_impl, archive_old_decisions, archive_decisions, domain_scoped_reset, and the hook import; public signatures are preserved.

### Count investigation: explained, not a regression

The 224 baseline is not the full root-suite count at its tagged revision. v0.7.17-ci points to 2933ba8 (message: 224P). Collection from an isolated git archive of that revision gives 619 cases. Do not describe the entire 458 gap as newly added tests.

Every subsequent committed revision:
- bdf2aeb: root collection 631; 36 added node IDs and 24 removed/renamed, net +12. Additions occur in test_g040_domain_isolation (16), test_age_escaping (10), test_age_graph_store (6), test_age_graph_store_topology (1), test_age_archive (3).
- f08452c: root collection 665; 35 added node IDs and 1 removed/renamed, net +34. Additions occur in test_age_graph_store (11), test_checkpoint_count (16), test_age_sdk_adapter (4), test_platform_state_transactions (3), test_age_graph_store_v (1).
- Remaining pre-P2b working-tree rounds bring 665 to the independently measured 682 baseline (+17). Session entries record 668, 670, 674, 676, then R6's 682.

Reconciliation: 224 + 395 (already present in tagged root collection) + 12 + 34 + 17 = 682; P2b adds 60 = 742. The old 224 message does not identify the exact subset it measured, so that subset is not inferred.

The three new files contain 23 test functions, expanded by parameterization into exactly 60 collected cases: compiler 19, live AGE 35, migration 6. A grep of function definitions is not a collected-test count.

### Contract and architecture checks

- All four inspect.signature comparisons with InMemoryGraphStore match: query_decisions, count_decisions, aggregate_decisions, get_decision_changes. The review prompt's get_decision_projections/count_decision_projections/aggregate_decision_projections names are obsolete and are not the shipped protocol.
- User-approved corrections apply over stale design wording: generation fences are allowed with cursors; verified sort excludes pending and raises for matching verified rows without verified_at; missing creation timestamps retain the actual ID. Timestamp sort/predicate direction agrees. V-order has no creation-time fallback, though the compiler's null-to-zero expression is preceded by an integrity check in the same locked read.
- Compiler imports no copilot_sdk modules. Closed property/dimension/order manifests prevent caller identifiers entering Cypher. Values use the existing _S literal serializer (not PostgreSQL positional parameters). Outer graph quoting/dollar delimiters are protected. Finding R-03 concerns quoted-data rejection, not injection.
- Narrow manifests match SDK constants; learning_metadata is allowlisted. Full evidence excludes implementation bookkeeping. Native count/aggregate use shared predicates, inclusive NaN-safe confidence bounds and half-open timestamp bounds. Aggregates fetch at most 1001 groups and raise above 1000.
- Construction and subsequent bounded reads require activation. Backfill validates identities, tenant conflicts and timestamps before atomically committing activation. Idempotency, marker removal/re-activation, and per-domain generation are covered by live tests. Older writers must remain quiesced as documented.
- Generation allocation, event payload persistence and create/verification/archive/reset mutations share one transaction and exclusive graph/domain advisory lock. Reads hold the corresponding shared lock through generation checking and fetch. Live concurrent writers and injected event-failure rollback pass. Atomicity is VERIFIED for participating writer paths; this does not claim end-to-end live-stack closure.
- The existing 60 tests pass but do not cover string IDs/text that resemble JSON/null, nonfinite journal P&L parity, or forbidden-syntax words inside quoted journal data. The probes below use real store operations and disposable AGE graphs.

### FINDING P2b-R-01: Generic result decoding corrupts IDs and cursor progress

Severity: P1.
File: ci_platform/graph/age_client.py:1386; related cursor construction ci_platform/graph/bounded_projection_migration.py:204.
Issue: The new bounded executor applies _normalize_value after agtype parsing to every returned field. That helper converts the legitimate string "null" to None and JSON-looking strings to lists/dicts. It cannot distinguish serialized container fields from string identity/text fields.
Evidence: Write governed IDs "null" and "z" at created_at=1; query ascending with limit=1. Both page 1 and page 2 return decision_id=None, cursor DecisionCursor(created_at, 1.0, "None"), has_more=True. The cursor compares "None" against the actual stored "null", repeatedly returning the same row. Also notes='{"hello":1}' becomes a dict and reflection='null' becomes None in direct journal reads, while the feed retains both strings. InMemory retains the ID and text strings.
Fix: In the new bounded executor preserve the types produced by _parse_agtype; decode serialized containers only for explicitly declared JSON fields/payloads in the bounded layer. Add ascending/descending cursor and query/feed/aggregate regressions for literal "null" and JSON-looking string identifiers/text without changing the legacy executor's behavior.
FAILURE MODE TO PREVENT: Repeated cursor pages/infinite traversal, corrupted governed identities, and inconsistent direct/feed text.

### FINDING P2b-R-02: Nonfinite journal numbers lose their type in direct projections

Severity: P2.
File: ci_platform/graph/bounded_projection_migration.py:102 and :211.
Issue: Canonicalization stringifies every nonfinite float, but narrow query decoding restores only confidence. Journal P&L therefore differs from normalized full/feed evidence and P2a.
Evidence: A governed decision with metadata pnl=float("inf") returns pnl='inf' (str) from a journal query, but pnl=inf (float) from its journal feed payload and InMemory. The discrepancy was reproduced on live AGE.
Fix: Define reversible field-aware encoding/decoding for nonfinite numeric projection values, preserving P2a's normalization and the original types; test positive/negative infinity and NaN across direct journal/full/feed results. Do not stringify all nonfinite floats without restoring their declared types.
FAILURE MODE TO PREVENT: Direct/feed disagreement and numeric journal consumers receiving strings.

### FINDING P2b-R-03: Safety scan treats quoted journal data as executable Cypher

Severity: P2.
File: ci_platform/graph/age_client.py:1373 (calls the whole-query regex guard at :100).
Issue: run_bounded_cypher calls _check_safe_cypher on the serialized query including quoted literal values. The guard rejects a MERGE pattern even when it occurs only inside journal text or the JSON event payload.
Evidence: An unactivated legacy governed write with notes='Explain MERGE (n) in the journal' succeeds. migrate(store, domain) then fails while canonicalizing that valid record: ValueError("Forbidden: MERGE is not supported by Apache AGE..."). Activation is rolled back, but valid historical evidence prevents migration.
Fix: Apply the unsupported-syntax guard only to lexically executable Cypher, ignoring correctly escaped quoted literals/comments, or validate the bounded compiler's syntax before binding values. Preserve rejection of actual unsupported statements and add historical-backfill and activated-write regressions for MERGE/SET-looking text.
FAILURE MODE TO PREVENT: Valid evidence blocking activation or causing otherwise valid hooked writes to roll back.

### Validation and verdict

- python -m mypy [all five P2b production files] --config-file pyproject.toml: Success, no issues found in 5 source files.
- New tests: 60 passed, zero failed/skipped, 27.52 seconds; 120 existing pytest_freezegun warnings.
- Full suite: 742 passed, zero failed/skipped, 99.39 seconds; 1484 existing pytest_freezegun deprecation warnings (same two per case, not a new P2b warning category).
- Live probes reproduce all three findings; disposable graphs cleaned up. No regression tests were committed because this task is review-only.

P2b REVIEW VERDICT: FAIL.
P1 findings: 1. P2 findings: 2. P3 findings: 0.
Count investigation: explained.
Legacy adapter unchanged: YES.
Import cycle: NONE.
V-order contract parity: MATCHES P2a for timestamp eligibility, missing-time integrity, ordering and fencing; arbitrary string cursor identity is blocked by R-01.
Transaction atomicity: VERIFIED for participating mutation paths.
Fixer prompt needed: YES.
Required before clearance: repair bounded decoding/cursors (R-01), numeric journal parity (R-02), and literal-aware syntax validation (R-03); add reproducing regression cases and rerun mypy/full tests. Passing the existing suite alone does not resolve these demonstrated defects.


## FIX-P2b-R01-R02-R03 (2026-10-16)

Status: implementation and validation complete; ready for re-review.
Files changed: ci_platform/graph/age_client.py, ci_platform/graph/bounded_projection_migration.py.
Files created: tests/test_bounded_projection_fixer.py.
Documentation: this required session-state append.
R-01 fixed: YES. R-02 fixed: YES. R-03 fixed: YES.

### Comprehension and before/after

Read REV-P2b evidence and the affected code before editing. R-01's new bounded executor called the legacy _normalize_value on each scalar, turning string "null" into None and JSON-looking text into containers. Cursor construction then str(None) produced "None", repeating the same first page for IDs "null" and "z" at created_at=1. R-02's canonicalization stringified all nonfinite floats; only confidence was restored in direct reads, so pnl='inf' differed from feed/InMemory float infinity. R-03's regex scanned quoted canonical values and event JSON as executable syntax; notes='Explain MERGE (n) in the journal' blocked backfill.

R-01 fix: _decode_bounded_value uses an explicit immutable JSON-field allowlist. Plain string IDs, cursor IDs, notes and other text are preserved after agtype parsing. Nested strings inside decoded containers are not recursively coerced. Cursor construction validates a nonempty string and uses it directly instead of str() coercion. Legacy _normalize_value and its existing executor usages remain unchanged.

R-02 fix: Option C, native AGE numeric storage. A live pre-edit probe confirmed toFloat('Infinity'), toFloat('-Infinity') and toFloat('NaN') return Python floats. _canonical_literal emits these expressions for nonfinite floats, using _S for the token. Other values retain _S serialization. Native agtype parsing preserves numeric types without a sentinel/collision problem. Explicit numeric-field compatibility decoding retains support for P2b's existing 'inf'/'-inf'/'nan' canonical strings in confidence, pnl, entry_price and exit_price, all fields normalized to numeric values before storage. Notes containing these strings remain strings. Feed and full evidence encoding is unchanged.

R-03 fix: Option B, literal-aware syntax validation. _cypher_syntax masks escaped single/double-quoted literals, quoted identifiers and comments before the existing unsupported-MERGE/whole-node-SET checks. The guard remains on all three existing executor call sites, including reads. Ordinary CREATE/DELETE are legitimate operations and were never globally prohibited. The guard checks AGE dialect restrictions; _S and SQL quoting prevent values from becoming executable code. Moving the guard only to writes would not fix backfill's canonical-field/event writes, where the false positive occurred.

### Scoped line-by-line diff audit

The requested git diff commands were run, but this dirty checkout includes previous uncommitted rounds and migration.py is untracked. A pre-fixer source snapshot and SHA-256 manifest of production/test/doc files establish the actual scope. Snapshot directory: C:/Users/baner/AppData/Local/Temp/p2b-fixer-before-up0j12l4.

- age_client.py: 37 added / 4 removed lines (41 changed, below 80).
  - Two frozenset allowlists and _decode_bounded_value added: bounded-only field decoding, no module-global mutable state.
  - _cypher_syntax added: masks literals/comments for syntax inspection.
  - Three old guard references to raw query text replaced with masked syntax plus one local assignment: applies to all guard callers, deliberately accepting quoted data while still rejecting executable unsupported patterns.
  - One bounded result-comprehension line now calls the field-aware decoder; existing non-bounded scalar normalization is unchanged.
- bounded_projection_migration.py: 17 added / 6 removed lines (23 changed).
  - Private _canonical_literal added: native nonfinite expressions; other serialization unchanged. The explicit str return preserves _S's string contract for mypy without a cast/ignore.
  - Blanket float-to-string canonicalization replaced by the helper call. Confidence eligibility properties and event/generation logic unchanged.
  - Cursor str() coercion replaced by validation and direct string use; invalid persisted IDs fail explicitly instead of inventing an identity.
- Imports added/removed: NONE in either production file (verified through AST comparison).
- Public signatures added/removed/changed: NONE (AST comparison).
- New private helpers: _decode_bounded_value, _cypher_syntax, _canonical_literal.
- Hash comparison confirms no other production/test/design file changed. Existing unrelated working-tree modifications preserved. No SDK, scorer, adapter, compiler, wrapper or factory changes.

### Step 5 verification (completed before suite execution)

| Check | Result and evidence |
|---|---|
| CHECK-01 JSON allowlist | PASS: _BOUNDED_JSON_FIELDS is explicit. |
| CHECK-02 decision_id excluded | PASS: neither decision_id nor _cursor_id is in JSON decoding fields. |
| CHECK-03 raw cursor string | PASS: agtype string -> identity-preserving decoder -> validated string cursor; live multi-page traversal with adversarial IDs progresses. |
| CHECK-04 adversarial decoding | PASS: all seven requested actual-helper cases retain the specified types. |
| CHECK-05 nonfinite encoding | PASS: _canonical_literal handles positive infinity, negative infinity, NaN natively. |
| CHECK-06 numeric decoding | PASS: native agtype parsing plus old-format numeric-field compatibility decoding. |
| CHECK-07 numeric round trips | PASS: live AGE round trips for inf, -inf, NaN, 0.0, 1.5, -99.9; all return float with matching value/NaN. |
| CHECK-08 write guard retained | PASS: executable MERGE and whole-node SET still raise ValueError, including after comments. |
| CHECK-09 read/legacy text safety | PASS under allowed Option B: quoted data is masked on reads and writes; the guard remains installed. |
| CHECK-10 legacy text | PASS: all seven English keyword examples survive historical writes, migration, activated writes and reads. |
| CHECK-11 injection prevention | PASS at the public value boundary: the requested SQL/MERGE/CREATE strings are stored verbatim as text and create no Malicious nodes; unsupported executable MERGE/SET still rejected. |
| CHECK-12 imports | PASS: no production import changes or dependencies. |
| CHECK-13 signatures | PASS: all existing public signatures identical. |
| CHECK-14 scope | PASS: exactly two production files and the new regression test file, plus this authorized session append. |

Verification checks: 14/14 semantic checks PASS, with explicit CHECK-09/CHECK-11 qualifications. The literal alternative assertions in the prompt are NOT claimed: Option B retains the guard on reads, and deliberately executing raw CREATE is valid for this internal executor. Rejecting all CREATE statements would break legitimate writes; keywords in user data are safely bound, not blacklisted. The regression tests prove non-execution of injected statements rather than pretending the raw low-level executor is an untrusted-query API.

### Regression tests and gates

New regression tests: 62 collected cases in tests/test_bounded_projection_fixer.py (10 parameterized/nonparameterized functions). Coverage includes C/V cursor paging in both directions with summary/full projections and null/true/123/JSON-looking IDs; plain-text vs structured JSON parity; native numeric/direct/feed/InMemory parity; existing encoded journal values; historical backfill and activated keyword writes; syntax checks after comments; and SQL/Cypher/dollar-delimiter injection strings remaining data.

- Before baseline: 742 passed, zero failed/skipped (REV-P2b).
- New isolated file: 62 passed, zero failed/skipped, 15.05 seconds.
- Mypy: python -m mypy ci_platform/graph/age_client.py ci_platform/graph/bounded_projection_migration.py tests/test_bounded_projection_fixer.py --config-file pyproject.toml -> Success: no issues found in 3 source files. An initial Any-return error in the new helper was corrected before the final gate; no suppression added.
- Full suite: python -m pytest tests/ -q --timeout=120 -> 804 passed, zero failed/skipped, 142.92 seconds. Delta: exactly +62.
- Warnings: 1608 instances of the pre-existing pytest_freezegun distutils deprecation (two per case); no new warning category.
- Live tests used disposable protocol_v2_test_bounded_* graphs, cleaned up afterward. No production activation or migration performed; no live-stack gap closure claimed.

### Step 8 self-check

SC-1 YES: CHECK-04 actual decoder cases and live C/V ASC/DESC cursor tests show decision_id='null' progresses, including past 'z' in descending order; bounded loops detect repeats.
SC-2 YES: CHECK-01/02 and actual decoder tests preserve plain IDs/text and decode only designated JSON fields (numeric compatibility handled separately in numeric-only fields).
SC-3 YES: CHECK-07's six live values and direct/full/feed/InMemory parity tests preserve float type, including NaN and both infinities.
SC-4 YES: CHECK-10 covers the seven legacy texts in backfill and activated writes; CHECK-08 retains unsupported executable-statement rejection.
SC-5 YES: existing string-encoded nonfinite journal fields, literal null/JSON-looking strings, structured JSON fields, native finite numbers and keyword-containing historical notes remain supported. No graph rewrite needed for those old journal values.
SC-6 YES: final configured mypy gate clean on both production files and new tests.
SC-7 YES for the documented 14 semantic checks; CHECK-09/11 follow the explicitly allowed Option B and the actual query/data security boundary as qualified above.


## REV-FIX-P2b (2026-10-16)

Verdict: PASS WITH OBSERVATIONS.
R-01: CLOSED. R-02: CLOSED. R-03: CLOSED.
New findings: 0 P1, 0 P2, 1 P3.
Test count: 804 passed, 0 failed, 0 skipped.
Fixer needed: NO (nonblocking test-coverage observation tracked below).
P2c unblocked: YES for this code-review prerequisite; rollout/live-stack gates remain separate.

### Provenance, exact scope and diff

Critical self-review: the reviewer authored the fixer in this thread; this is not an independent-author review. Read both REV-P2b and FIX-P2b-R01-R02-R03 before examining code. The fixer's claim was 804 tests (742 + 62), native AGE nonfinite storage, field-aware string decoding, literal-aware Option B guard, and 14 semantic checks with explicit qualifications for checks 09/11.

No fixer commit exists: git log -5 still starts at f08452c. Used the retained pre-fixer snapshots and hashes in C:/Users/baner/AppData/Local/Temp/p2b-fixer-before-up0j12l4 rather than an unrelated HEAD~1 diff.

Files reviewed and fixer line counts:
- ci_platform/graph/age_client.py: +37 / -4.
- ci_platform/graph/bounded_projection_migration.py: +17 / -6.
- tests/test_bounded_projection_fixer.py: +173 / -0, 10 functions expanding to 62 regression cases.
- docs/session_state.md: authorized fixer report; reviewed as evidence, excluded from production scope.

Recomputed pre-fixer hashes confirm those are the only changed production/test files. AST comparisons confirm no changed public signatures and no production import/dependency changes. Unrelated prior dirty files were not attributed to the fixer. Read every fixer diff hunk and the complete regression file. Review-start hashes confirm no source/test/design/session edits during verification; only this final entry is appended.

### R-01: CLOSED

Explicit _BOUNDED_JSON_FIELDS at age_client.py:76 enumerates structured fields. decision_id, _cursor_id, notes, action/category/status, tenant, source, ticker and regime are excluded. _decode_bounded_value at :84 returns the same string value for those fields, not a JSON interpretation. It does not recursively decode plain text inside containers. Existing legacy _normalize_value remains unchanged.

Path: compiler returns d.decision_id AS _cursor_id -> _parse_agtype unwraps the AGE string -> field-aware decoder is identity for _cursor_id -> migration.py:212 validates the raw string and uses it without str() coercion. Although the common decoder function is called, its JSON branch is never taken for identity fields. There is no transformed/post-JSON cursor value.

Fresh actual-helper checks preserved strings 'null', 'true', 'false', '123', '', and notes='{not json but has braces}'. A fresh live graph with IDs 'null' and 'z' at the same timestamp returned page 1='null', cursor ID='null', page 2='z', has_more=False. The full suite also exercises both timestamp orders, both directions and summary/full paging with adversarial string IDs.

### R-02: CLOSED

_canonical_literal at migration.py:24 is applied to canonical property assignments at :110. Nonfinite Python floats become toFloat('Infinity'), toFloat('-Infinity'), or toFloat('NaN'), with tokens quoted by _S. AGE stores native floats; _parse_agtype returns Python floats. Finite values retain the ordinary serializer. No ambiguous sentinel is introduced.

Fresh live probes round-tripped inf, -inf, NaN, 0.0, 1.5 and -99.9 through the actual write-expression/read path. For each, direct journal reads, event feed payloads, and InMemory reads returned float with the expected value (math.isnan for NaN). Regression tests additionally cover entry_price/exit_price, full projection and old canonical strings.

Backward compatibility: _BOUNDED_FLOAT_FIELDS limits restoration of old 'inf'/'-inf'/'nan' strings to confidence, pnl, entry_price and exit_price. Those fields already normalize to numbers before canonical storage, so valid textual notes are not mistaken for numeric encodings. Existing native floats pass through unchanged. The full suite passes the tests that seed old canonical strings explicitly.

### R-03: CLOSED

Option B variant: the guard remains on reads and writes but inspects only literal/comment-masked syntax. _cypher_syntax is at age_client.py:99; _check_safe_cypher at :132 is called by _sync_execute (:683), _execute_cypher_on_connection (:746), and run_bounded_cypher (:1406). All three now use the literal-aware guard, not the former whole-text scan.

Fresh live legacy write notes='Explain MERGE (n) in the journal' -> migration -> activated journal query succeeds with unchanged text. Backfill still executes canonical-field/event writes, so merely removing guard calls from reads would not address the original failure. The regression file covers the seven English keyword examples in both backfill and active writes.

Executable MERGE (n:Decision {id: "evil"}) RETURN n and whole-node SET still raise ValueError in the guard. The raw attempt "'; DROP TABLE decisions; --" was rejected by the bounded executor/AGE parser with SyntaxError. Bound injection-like strings remain data and do not create Malicious nodes (regression cases pass). Qualification: the syntax guard is not a general SQL-injection validator and does not itself reject every arbitrary string; _S and outer SQL quoting prevent data becoming syntax, and AGE parses submitted raw queries. This is consistent with permitted Option B and does not require blacklisting legitimate CREATE operations.

### New-defect scan and test quality

The new decoder catches only JSONDecodeError for explicitly structured fields and retains the original value on invalid JSON, consistent with existing compatibility behavior. It does not suppress database, transaction or cursor integrity errors. Private helpers only; no dependencies or public API changes. Shared guard behavior intentionally changes for literal/comment false positives; unsupported executable patterns remain checked.

All 62 new cases use actual production helpers; live cases operate on real disposable AGE graphs, including query/feed/InMemory comparisons, not mocks of the store. Tests isolate graphs and use bounded loops to detect repeated cursor pages without hanging. NaN assertions use math.isnan rather than equality. Existing empty-string and nested JSON cases are covered. Additional fresh review probes preserved Unicode (including non-BMP characters) and 100,010-character journal text with nested JSON. A NUL-containing write raised SyntaxError and rolled back the Decision and generation, with no partial feed event. All disposable graphs were cleaned up.

FINDING FIX-P2b-NF-01: Extended string-boundary checks are not retained as regression tests.
Severity: P3.
File: tests/test_bounded_projection_fixer.py:96.
Issue: The committed tests cover empty strings, braces, nesting, quotes and keyword text, but omit Unicode/non-BMP text, long text and NUL rejection/rollback.
Evidence: These cases passed fresh live review probes, yet no equivalent cases appear in the 62-case regression file.
Fix: Add durable parameterized Unicode/long-text cases and an explicit NUL-write failure test asserting unchanged decision count, generation and feed.
FAILURE MODE TO PREVENT: A future parser/serializer edit could regress those boundaries without the existing regression file detecting it. This is a nonblocking coverage observation, not a reproduced implementation defect.

### Fresh validation

- python -m mypy ci_platform/graph/age_client.py --config-file pyproject.toml: Success, no issues found in 1 source file; no warnings.
- python -m mypy ci_platform/graph/bounded_projection_migration.py --config-file pyproject.toml: Success, no issues found in 1 source file; no warnings.
- python -m pytest tests/ -q --timeout=120: 804 passed, 0 failed, 0 skipped, 184.59 seconds.
- 1608 instances of the existing pytest_freezegun distutils deprecation, unchanged category/two per case.
- Initial one-off probe hit a tests-package import-order collision; rerunning with the ci-platform fixture imported first succeeded. This was probe setup, not a production/test-suite failure.

RE-REVIEW VERDICT: PASS WITH OBSERVATIONS.
R-01 (cursor string decode): CLOSED.
R-02 (nonfinite journal numbers): CLOSED.
R-03 (syntax guard false positives): CLOSED.
New findings: 0 P1 / 0 P2 / 1 P3.
Scope check: only age_client.py + bounded_projection_migration.py + the new test file, plus authorized documentation: YES.
Public signatures unchanged: YES.
Backward compatible with existing AGE data for the reviewed contracts: YES.
Test count 804 confirmed: YES.
Fixer needed: NO.
P2c unblocked: YES for this review gate. No production activation or live-stack gap closure claimed.

=== FIX-REV-P2-AGE-DATA-INTEGRITY (R3+R4+R6) ===
date: 2026-10-16
model: terra+high
scope: R3 (retention decoder), R4 (activation classification), R6 (ImportError test)
repos: ci-platform + copilot-sdk (factory + test file)
findings fixed: R3 P1, R4 P2, R6 P2
files changed: ci-platform: ci_platform/graph/age_client.py, ci_platform/graph/age_graph_store.py, ci_platform/graph/bounded_projection_migration.py, tests/test_age_data_integrity.py, tests/test_bounded_projection_age.py; copilot-sdk: copilot_sdk/graph/factory.py, tests/test_bounded_projection_wrappers.py
tests added: 13 pytest cases (12 ci-platform, 1 copilot-sdk)
self-verify: CHECK-01 through CHECK-07: PASS
layer-1: L1-1 PASS; L1-2 PASS; L1-3 PASS; L1-4 QUALIFIED (ci-platform green; SDK exact full run had one unrelated transient that passed isolated); L1-5 PASS; L1-6 PASS
suite ci-platform: 816 passed, 0 skipped, 0 failed
suite copilot-sdk: exact full run 4,725 passed, 1 xfailed, 1 transient external FRED failure; failed case passed isolated. A second diagnostic -x run exposed an unrelated decision-ordering flake, also passed isolated. Persistent/task-related failures: 0.
mypy: PASS: age_client.py, age_graph_store.py, bounded_projection_migration.py, test_age_data_integrity.py, test_bounded_projection_age.py, factory.py, test_bounded_projection_wrappers.py
retention decoder approach: a (rationale: an opt-in preserve_strings flag keeps every legacy decoder caller unchanged while retention explicitly preserves identity fields)
activation exception: ActivationAbsentError and ActivationCorruptError in ci_platform/graph/bounded_projection_migration.py
next: FIX-REV-P2-AGE-MECHANICAL (R5+R8), then re-review (Sol+high)

=== FIX-REV-P2-AGE-MECHANICAL (R5+R8) ===
date: 2026-10-16
model: spark+medium
scope: R5 (pool close on wait failure), R8 (manifest freeze)
repo: ci-platform only
files changed: ci_platform/graph/age_client.py; ci_platform/graph/bounded_projection.py; tests/test_age_client.py; tests/test_bounded_projection.py; docs/session_state.md
implementation: `_ensure_pool()` closes a newly created pool when its readiness `wait()` raises, clears the reference, and re-raises the initialization failure. `COLLECTIONS` and `GROUPS` are immutable `MappingProxyType` views; no post-definition registrations exist.
tests added: 2 (pool wait failure cleanup; compiler manifest immutability)
self-verify: CHECK-01 PASS (both manifests reject item assignment with TypeError); CHECK-02 PASS (wait failure branch closes the captured pool before clearing and re-raising); CHECK-03 PASS (both manifests use MappingProxyType); CHECK-04 PASS (scope limited to age_client.py, bounded_projection.py, their two test files, and this log)
layer-1: L1-1 PASS (no public signatures changed); L1-2 PASS (module-global mutability reduced); L1-3 PASS (mypy clean on both production files); L1-4 PASS (full suite green); L1-5 PASS (no _StoreProxy references added); L1-6 PASS (no DecisionStore imports added)
suite: 818 passed, 0 failed, 0 skipped; 1636 warnings; 99.92 seconds
mypy: Success, no issues found in 2 source files
next: re-review (Sol+high) covering all REV-P2 fixes

=== RE-REVIEW-REV-P2 (Sol+high) ===
date: 2026-10-16
model: sol+high
scope: independent verification of R1-R6, R8 fixes
verdict: FAIL
per-finding: R1 PASS; R2 FAIL; R3 PASS; R4 PASS; R5 PASS; R6 PASS; R8 PASS
cross-fix: FAIL — the namespace encoding is syntactically AGE-safe, but it is neither reserved against ordinary-domain collision nor integrated with per-physical-domain bounded activation/migration. A public-operation probe stored a raw decision under `jmns__61726d__scoring` and namespace `arm/scoring` returned it. A readiness probe accepted activated `s2p` and rejected encoded `jmns__61726d__s2p` as unactivated.
deferred: R7, R9, R10 confirmed P3 and non-blocking; none is a prerequisite for the shipped fixes
suite ci-platform: 818 passed, 0 failed, 0 skipped
suite copilot-sdk: 4726 passed, 0 failed, 1 xfailed
new findings: none; original R2 remains partially fixed/open
review note: focused fixer selections also passed (SDK 45; platform 113). This review was performed fresh, but the current thread also authored 35a/35c, so it is not independent-author verification.
next: fix R2 by defining and enforcing a globally reserved collision-free physical namespace representation and activating/migrating the exact encoded physical domains used by namespace reads, writes, generations and feeds; add real AGE composition coverage, then re-review. Bounded projection core remains blocked.

=== FIX-REV-P2-R2-COMPLETION (GAP-2 activation) ===
date: 2026-10-16
scope: GAP-2 activation integration for namespace-encoded domains, plus AGE raw-prefix reservation at the public decision-write boundary
files: ci_platform/graph/bounded_projection_migration.py, ci_platform/graph/age_graph_store.py, tests/test_namespace_activation_completion.py, tests/test_bounded_projection_migration.py, docs/session_state.md
implementation: jmns__<hex>__<base> parses to an activation base; the base anchor/marker and shared advisory lock authorize use. Each encoded domain is initialized/backfilled under its own lock and retains an independent generation anchor and feed. Raw untagged jmns__ decision writes are rejected before connection use; tagged namespace writes remain valid.
tests: 5 ci-platform test functions added for activation positive/negative cases, AGE reservation, multiple namespace anchors, and live AGE write/query/feed composition
suite: 823 passed, 0 failed, 0 skipped
mypy: Success, no issues found in age_graph_store.py, bounded_projection_migration.py, and both changed test files
=== RE-REVIEW-R2-ONLY (35f) ===
date: 2026-10-16
verdict: FAIL
suite: 823 passed

--- FIX-R2-GAP1-RESERVATION (35g) ---
Date: 2026-10-16
Prompt: codex_fix_r2_gap1_reservation_v2.md
Model: Terra+high

Changes:
namespace.py: Added is_internal_namespace() with type-identity check (type(x) is _InternalNamespace).
memory_store.py: Extended the jmns__ guard to save_k_utility, save_holdout_decision, enqueue_to_outbox, write_decision, write_governed_decision, write_outcome, write_observation, append_evidence_receipt, write_conservation_status, write_fingerprint, write_centroid_checkpoint, write_evolution_event, prune_evolution_events, write_transfer_pattern, link_entity, update_centroid, update_dk_weights, update_conservation_state, save_centroids, save_evolution, delete_evolution, save_evolution_state, save_posterior, delete_posterior, save_promotion, delete_promotion, save_ledger, delete_ledger, save_governance, delete_governance, save_evolution_event, write_entity_enrichment, archive_old_decisions, archive_decisions, domain_scoped_reset, and link_decision_to_entity; replaced attribute-tag bypasses with is_internal_namespace().
age_graph_store.py: Extended the jmns__ guard to save_evolution, delete_evolution, save_evolution_state, save_posterior, delete_posterior, save_promotion, delete_promotion, save_ledger, delete_ledger, save_governance, delete_governance, write_decision, write_governed_decision, write_outcome, write_outcome_and_update_centroid, write_observation, write_conservation_status, write_fingerprint, write_centroid_checkpoint, append_evidence_receipt, write_evolution_event, write_transfer_pattern, link_entity, update_centroid, update_dk_weights, update_conservation_state, save_centroids, save_evolution_event, link_decision_to_entity, prune_evolution_events, archive_old_decisions, archive_decisions, domain_scoped_reset, and write_entity_enrichment; replaced attribute-tag bypasses with is_internal_namespace().

Tests added: 77 method-specific/type-identity/forgery/positive tests (41 SDK, 36 CI).
SDK baseline: 4773 passed, 1 xfailed, 0 failed.
CI baseline: 859 passed, 0 failed.
Mypy: clean on copilot_sdk/graph/namespace.py, copilot_sdk/graph/memory_store.py, ci_platform/graph/age_graph_store.py, and both changed reservation test files.

Self-verification: 10/10 CHECKs PASS.
Layer 1: PASS.

CONCRETE WRITE METHOD LIST (for re-review reference):
memory_store.py: save_k_utility, save_holdout_decision, enqueue_to_outbox, write_decision, write_governed_decision, write_outcome, write_observation, append_evidence_receipt, write_conservation_status, write_fingerprint, write_centroid_checkpoint, write_evolution_event, prune_evolution_events, write_transfer_pattern, link_entity, update_centroid, update_dk_weights, update_conservation_state, save_centroids, save_evolution, delete_evolution, save_evolution_state, save_posterior, delete_posterior, save_promotion, delete_promotion, save_ledger, delete_ledger, save_governance, delete_governance, save_evolution_event, write_entity_enrichment, archive_old_decisions, archive_decisions, domain_scoped_reset, link_decision_to_entity.
age_graph_store.py: save_evolution, delete_evolution, save_evolution_state, save_posterior, delete_posterior, save_promotion, delete_promotion, save_ledger, delete_ledger, save_governance, delete_governance, write_decision, write_governed_decision, write_outcome, write_outcome_and_update_centroid, write_observation, write_conservation_status, write_fingerprint, write_centroid_checkpoint, append_evidence_receipt, write_evolution_event, write_transfer_pattern, link_entity, update_centroid, update_dk_weights, update_conservation_state, save_centroids, save_evolution_event, link_decision_to_entity, prune_evolution_events, archive_old_decisions, archive_decisions, domain_scoped_reset, write_entity_enrichment.

FAILURE MODE PREVENTED:
R2-01: Raw reserved domains in non-decision writes are now rejected by all public domain-bearing write methods.
R2-02: Forged str subclass bypass is now impossible because trust uses exact type identity rather than an attribute check.
R2-03: Previously untested write families now have dedicated raw-prefix rejection coverage, plus forgery and genuine-internal positive coverage.

--- RE-REVIEW-R2-GAP1 (35h) ---
Date: 2026-10-16
Prompt: codex_re_review_r2_gap1_v1.md
Model: Sol+high

R2-01: FAIL — the 36 InMemoryGraphStore and 34 AGEGraphStore methods claimed by 35g are guarded, but the public AGEGraphStore.run_transaction() facade exposes four additional domain-bearing writes without reservation checks: AGEGraphStoreTransaction.write_outcome(), update_centroid(), write_outcome_and_update_centroid(), and write_centroid_checkpoint(). An adversarial probe confirmed update_centroid persisted `jmns__forged__domain` into its write identity, and the other three facade methods forward that raw domain unchanged to unguarded private implementations. AGEGraphStoreTransaction.write_decision() is safe because _write_decision_impl() calls _validated_write_domain().
R2-02: PASS — is_internal_namespace() is exactly `type(domain) is _InternalNamespace`; plain strings, forged str subclasses, and _InternalNamespace subclasses are rejected while the exact internal type passes. Production code has zero _copilot_namespace_internal attribute checks.
R2-03: FAIL — the named test files contain 36 SDK and 35 CI raw-prefix reject tests, forgery coverage in both repos, and an SDK positive internal-type test; focused runs pass 47 SDK and 40 CI tests. However, there is zero AGEGraphStoreTransaction/run_transaction reservation coverage, leaving all four unsafe facade write paths untested.
Regressions: PASS (qualified) — ci-platform: 859 passed, 0 failed. copilot-sdk: 4772 passed, 1 xfailed, 1 documented order-dependent failure in tests/backend/test_self_computation_router.py::test_audit_trail_returns_verified_trails. The two documented ordering nodes also remain nondeterministic in isolation; no namespace-reservation test failed.
Blast radius: FAIL — the requested `git diff --name-only HEAD~1` comparison contains 470 SDK paths (467 outside the allowed list) and 15 CI paths (13 outside the allowed list). The repositories contain a cumulative uncommitted worktree relative to old HEAD commits, so 35g is not isolated by this comparison.

SDK baseline: 4772 passed, 1 xfailed, 1 known order-dependent failure.
CI baseline: 859 passed, 0 failed.

Overall verdict: FAIL.
New findings: 1 P2 blast-radius/scope-attribution finding. The transaction-facade bypass is a remaining R2-01 P1, and its missing tests keep R2-03 P2 open.
P1 findings: 1. P2 findings: 2. P3 findings: 0.
P2 bounded core remains blocked. P4 is not unblocked. Another fixer round is required.

--- FIX-R2-TRANSACTION-GUARD (35i) ---
Date: 2026-10-17
Prompt: codex_fix_r2_transaction_guard_v1.md
Model: Terra+high

Methods guarded:
  AGEGraphStoreTransaction.write_outcome
  AGEGraphStoreTransaction.update_centroid
  AGEGraphStoreTransaction.write_outcome_and_update_centroid
  AGEGraphStoreTransaction.write_centroid_checkpoint

Implementation: each public transaction-facade method now inspects the domain supplied through `**kwargs` and applies the same exact-type `is_internal_namespace()` reservation condition as the top-level AGEGraphStore write methods before delegating to its private implementation. AGEGraphStoreTransaction.write_decision remains protected by _write_decision_impl() calling _validated_write_domain().

Tests added: 10 (four raw-prefix rejects, four forged-str-subclass rejects, one normal-domain write_decision positive, and one exact _InternalNamespace positive).
Focused namespace activation suite: 50 passed.
CI baseline: 869 passed, 0 failed (was 859).
Self-verification: 8/8 PASS, including adversarial execution of all four methods and an explicit audit of public `**kwargs` transaction writes.
mypy: clean on ci_platform/graph/age_graph_store.py and tests/test_namespace_activation_completion.py.
Blast radius: PASS — this session touched only ci_platform/graph/age_graph_store.py, tests/test_namespace_activation_completion.py, and docs/session_state.md.
Layer 1: PASS — production behavior changed only by adding the four reservation guards.

--- RE-REVIEW-R2-FINAL (35j) ---
Date: 2026-10-17
Prompt: codex_re_review_r2_final_v1.md
Model: Sol+high

R2-01: PASS — full-file AST audits found zero unguarded public domain/domain_name write methods in any class. The `**kwargs` audit found only AGEGraphStoreTransaction.write_decision without an inline guard; it delegates to _write_decision_impl(), which calls _validated_write_domain(). Adversarial execution confirmed all four 35i transaction methods reject a raw `jmns__` domain before persistence. SDK `save_rl_state()` uses constructor-normalized `self.domain`; transfer-pattern writes guard both source and target domains.
R2-02: PASS — is_internal_namespace() is exactly `type(domain) is _InternalNamespace`; plain strings, forged str subclasses, and _InternalNamespace subclasses are rejected while the exact internal type passes. Production code has zero residual `_copilot_namespace_internal` checks outside namespace.py.
R2-03: PASS — the focused suites passed 47 SDK tests and 50 CI tests. CI contains 14 transaction-related tests, including the required four raw-prefix rejects and four forgery rejects.
Regressions: FAIL — ci-platform passed 869/869. The copilot-sdk full suite produced 4772 passed, 1 xfailed, and 1 failed: tests/backend/test_self_computation_router.py::test_audit_trail_returns_verified_trails returned `[d2, d1]` instead of `[d1, d2]`. The same test failed alone, and it plus test_decisions_returns_all both failed when run together. No namespace-reservation test failed, but this gate requires zero failures.
Guard consistency: PASS — all 78 reserved-prefix checks retain startswith(`jmns__`) followed by `not is_internal_namespace(...)`, and all raise ValueError with the identical `domain prefix 'jmns__' is reserved for namespace routing` message. Source/target-domain checks use their corresponding variables; the four `**kwargs` transaction guards add a `domain is not None` precondition before the common predicate.

SDK baseline: 4772 passed, 1 xfailed, 1 failed (focused namespace suite: 47 passed).
CI baseline: 869 passed, 0 failed (focused namespace suite: 50 passed).

Overall verdict: FAIL — namespace reservation gates R2-01/R2-02/R2-03 and guard consistency pass, but the strict no-regressions gate does not.
New findings: 0 new namespace-reservation findings. One pre-existing P2 SDK ordering defect remains an acceptance blocker because it currently fails both in the full suite and in isolation.
P1 findings: 0. P2 findings: 1. P3 findings: 0.
P2 bounded core is not accepted by this final gate. P4 remains blocked pending a zero-failure SDK baseline.
