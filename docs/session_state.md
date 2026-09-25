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
