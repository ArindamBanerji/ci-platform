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
