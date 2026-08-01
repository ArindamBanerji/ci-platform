# Graph Report - ci-platform  (2026-08-01)

## Corpus Check
- 90 files · ~74,981 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 1717 nodes · 3223 edges · 41 communities detected
- Extraction: 83% EXTRACTED · 17% INFERRED · 0% AMBIGUOUS · INFERRED: 541 edges (avg confidence: 0.74)
- Token cost: 0 input · 0 output

## Community Hubs (Navigation)
- [[_COMMUNITY_Community 0|Community 0]]
- [[_COMMUNITY_Community 1|Community 1]]
- [[_COMMUNITY_Community 2|Community 2]]
- [[_COMMUNITY_Community 3|Community 3]]
- [[_COMMUNITY_Community 4|Community 4]]
- [[_COMMUNITY_Community 5|Community 5]]
- [[_COMMUNITY_Community 6|Community 6]]
- [[_COMMUNITY_Community 7|Community 7]]
- [[_COMMUNITY_Community 8|Community 8]]
- [[_COMMUNITY_Community 9|Community 9]]
- [[_COMMUNITY_Community 10|Community 10]]
- [[_COMMUNITY_Community 11|Community 11]]
- [[_COMMUNITY_Community 12|Community 12]]
- [[_COMMUNITY_Community 13|Community 13]]
- [[_COMMUNITY_Community 14|Community 14]]
- [[_COMMUNITY_Community 15|Community 15]]
- [[_COMMUNITY_Community 16|Community 16]]
- [[_COMMUNITY_Community 17|Community 17]]
- [[_COMMUNITY_Community 18|Community 18]]
- [[_COMMUNITY_Community 19|Community 19]]
- [[_COMMUNITY_Community 20|Community 20]]
- [[_COMMUNITY_Community 21|Community 21]]
- [[_COMMUNITY_Community 22|Community 22]]
- [[_COMMUNITY_Community 23|Community 23]]
- [[_COMMUNITY_Community 24|Community 24]]
- [[_COMMUNITY_Community 25|Community 25]]
- [[_COMMUNITY_Community 26|Community 26]]
- [[_COMMUNITY_Community 28|Community 28]]
- [[_COMMUNITY_Community 29|Community 29]]
- [[_COMMUNITY_Community 30|Community 30]]
- [[_COMMUNITY_Community 32|Community 32]]
- [[_COMMUNITY_Community 33|Community 33]]
- [[_COMMUNITY_Community 34|Community 34]]
- [[_COMMUNITY_Community 35|Community 35]]
- [[_COMMUNITY_Community 36|Community 36]]
- [[_COMMUNITY_Community 43|Community 43]]
- [[_COMMUNITY_Community 44|Community 44]]
- [[_COMMUNITY_Community 45|Community 45]]
- [[_COMMUNITY_Community 54|Community 54]]
- [[_COMMUNITY_Community 55|Community 55]]
- [[_COMMUNITY_Community 56|Community 56]]

## God Nodes (most connected - your core abstractions)
1. `_new_store()` - 95 edges
2. `AGEGraphStore` - 92 edges
3. `AGEClient` - 78 edges
4. `AGEGraphStoreAdapter` - 68 edges
5. `SAPODataConnector` - 40 edges
6. `FakeGraphStore` - 40 edges
7. `BackgroundTaskManager` - 37 edges
8. `DeploymentQualifier` - 36 edges
9. `EvidenceLedger` - 34 edges
10. `EntityCache` - 34 edges

## Surprising Connections (you probably didn't know these)
- `EnrichmentPayload` --uses--> `SentinelConnector`  [INFERRED]
  ci_platform\connectors\sentinel_writeback.py → ci_platform\connectors\sentinel.py
- `test_outcome_entry_appended_to_chain()` --calls--> `EvidenceLedger`  [INFERRED]
  tests\test_evidence_ledger.py → ci_platform\audit\evidence_ledger.py
- `test_outcome_entry_tamper_detected()` --calls--> `EvidenceLedger`  [INFERRED]
  tests\test_evidence_ledger.py → ci_platform\audit\evidence_ledger.py
- `test_chain_index_monotonic()` --calls--> `EvidenceLedger`  [INFERRED]
  tests\test_evidence_ledger.py → ci_platform\audit\evidence_ledger.py
- `SentinelConfig` --uses--> `SourceConnectorProtocol`  [INFERRED]
  ci_platform\connectors\sentinel.py → ci_platform\connectors\base.py

## Communities

### Community 0 - "Community 0"
Cohesion: 0.01
Nodes (179): AGEClient, AGETransaction, _check_safe_cypher(), _env_int(), _env_truthy(), get_graph_client(), ci_platform/graph/age_client.py — Shared AGE/PostgreSQL graph client.  Apache AG, Sync-core graph client for Apache AGE / PostgreSQL.     Drop-in interface replac (+171 more)

### Community 1 - "Community 1"
Cohesion: 0.05
Nodes (45): AGEGraphStore, _as_float(), _as_int(), _decode_conservation_float(), _decode_dk_welford_state(), _decode_json_array_field(), _factor_vector_from_factors(), _int_from_rows() (+37 more)

### Community 2 - "Community 2"
Cohesion: 0.03
Nodes (102): _conservation_payload(), _conservation_row(), FakeAGEClient, FakeTransaction, _new_store(), test_age_centroid_duplicate_returns_latest(), test_age_client_s_matches_serialize_for_age_for_strings(), test_age_conservation_duplicate_returns_latest() (+94 more)

### Community 3 - "Community 3"
Cohesion: 0.03
Nodes (78): ABC, LedgerEntry, SourceConnectorProtocol, EnrichmentPayload, EnrichmentType, EnrichmentAdvisor, EnrichmentReport, FactorOpportunity (+70 more)

### Community 4 - "Community 4"
Cohesion: 0.03
Nodes (18): AGEGraphStoreAdapter, SDK GraphStore adapter for AGEGraphStore., Transitional SDK GraphStore-compatible wrapper around AGEGraphStore., Generate a bare AGE decision ID; the primary owns prefix policy., FakeGraphStore, test_adapter_close_delegates_to_store(), test_adapter_delegates_centroids_and_evolution_events(), test_adapter_delegates_counts_and_reads() (+10 more)

### Community 5 - "Community 5"
Cohesion: 0.04
Nodes (45): ConnectionError, _activity_ids_for_variants(), CelonisConfig, CelonisProcessConnector, _copy_records(), _extend_unique(), _extract_record_list(), from_env() (+37 more)

### Community 6 - "Community 6"
Cohesion: 0.04
Nodes (63): _await_any(), BackgroundTaskError, BackgroundTaskManager, BackgroundTaskStatus, Shared background task management for non-decision-critical work.  BackgroundTas, Drain or cancel in-flight tasks during application shutdown/tests., Return structured diagnostics without task payloads or stack traces., Return JSON-friendly diagnostics. (+55 more)

### Community 7 - "Community 7"
Cohesion: 0.05
Nodes (47): _copy_records(), from_dir(), from_env(), _load_json_file(), _parse_env_bool(), _patch_path(), SAP S/4HANA fixture parsing, manifest building, and read connector.  This module, Read-only SAP OData connector with REST and fixture source selection. (+39 more)

### Community 8 - "Community 8"
Cohesion: 0.06
Nodes (47): AGECounterStore, CounterDef, CounterKey, CounterRead, CounterReconciliation, CounterStatus, _first_bool(), _first_int() (+39 more)

### Community 9 - "Community 9"
Cohesion: 0.06
Nodes (48): EvidenceLedger, OutcomeEntry, Evidence Ledger — hash-chained audit trail for per-decision accountability.  EU, Append-only hash-chained audit ledger.      Usage:         ledger = EvidenceLedg, Append a new decision entry. Returns the sealed LedgerEntry., Append an outcome verification event to the chain.          Multiple outcomes fo, Verify chain integrity: every entry is internally valid and prev_hash links are, Compute and store entry_hash. Returns self for chaining. (+40 more)

### Community 10 - "Community 10"
Cohesion: 0.06
Nodes (50): _make_alerts(), Integration Test 1 — P28 pipeline end-to-end.  Tests DeploymentQualifier.qualify, Case 3 — Threshold isolation: L2 AMBER must not be classified as GREEN.      sig, Synthetic alerts with per-factor standard deviations matching sigma_profile., Case 1 — High-noise deployment: DiagonalKernel, AMBER, τ sweep triggered.      s, Case 2 — Low-noise centroidal deployment: L2 kernel, GREEN, τ sweep not triggere, test_case1_high_noise_diagonal_amber(), test_case2_low_noise_l2_green() (+42 more)

### Community 11 - "Community 11"
Cohesion: 0.06
Nodes (38): SentinelConfig, SentinelConnector, SplunkConfig, SplunkConnector, SourceConnectorProtocol, Connection mode does not change run_query's list-of-dicts result shape., Connection mode does not change run_query's list-of-dicts result shape., test_run_query_same_result_shape_in_fresh_and_warm_fallback() (+30 more)

### Community 12 - "Community 12"
Cohesion: 0.08
Nodes (30): EntityCache, EntityCacheEntry, EntityCacheKey, EntityCacheStats, EntityCacheStatus, Entity context cache for copilot analyze hot paths.  The cache is intentionally, Typed key for recurring entity context.      `kind` should name a cacheable enti, Bounded read-through LRU cache for stable entity context. (+22 more)

### Community 13 - "Community 13"
Cohesion: 0.08
Nodes (40): _connection_from_mapping(), ConnectionConfig, EnterpriseConnectorProfile, EntityMapping, from_yaml(), _is_absent(), _mappings_from_sequence(), _optional_str() (+32 more)

### Community 14 - "Community 14"
Cohesion: 0.07
Nodes (17): age_available(), age_test_graph(), Shared live AGE test availability and disposable graph fixtures., _Decision, _FakeAGEClient, fixture_graph(), _InMemoryAGE, Behavioral D2 verified-decision tests for SOC AGE count readers. (+9 more)

### Community 15 - "Community 15"
Cohesion: 0.05
Nodes (11): AGE type roundtrip tests — verify AGEClient normalizes types at the boundary.  T, Verify serialize → normalize returns the original value., numpy array → serialize → normalize → list (tolist conversion)., Test _normalize_value — the read-path boundary., Strings that aren't valid JSON stay as strings., Numeric strings pass through unchanged — no scalar coercion.         _parse_agty, Boolean strings pass through unchanged — no scalar coercion.         _parse_agty, Test serialize_for_age — the write-path boundary. (+3 more)

### Community 16 - "Community 16"
Cohesion: 0.09
Nodes (15): CounterStore, Protocol, GraphStoreCounts, Two-phase rollout strategy backed by GraphStore counts., Derive phase A/B status from verified GraphStore decisions., TwoPhaseStrategy, FailingGraphStore, FakeGraphStore (+7 more)

### Community 17 - "Community 17"
Cohesion: 0.11
Nodes (24): _find_attr(), _find_text(), Validate a base64-encoded SAMLResponse.          When IdP x509 cert is configure, True when all required IdP details are present., Parse base64 SAMLResponse XML without signature verification. Test use only., Full signature + assertion verification via python3-saml., Return SAML 2.0 SP metadata XML string., Create a base64-encoded AuthnRequest and return redirect URL. (+16 more)

### Community 18 - "Community 18"
Cohesion: 0.22
Nodes (15): MemoryL5Store, _target_id(), test_l5_upsert_cleanup_duplicates(), test_l5_upsert_create_fresh(), test_l5_upsert_edge_condition_false(), test_l5_upsert_edge_wanted_no_target_id(), test_l5_upsert_garbled_with_incoming_edges(), test_l5_upsert_missing_edge_target() (+7 more)

### Community 19 - "Community 19"
Cohesion: 0.11
Nodes (13): AGE Cypher compatibility tests — document known AGE vs Neo4j incompatibilities., Verify AGEClient source avoids known AGE anti-patterns., AGE reserves 'count' as keyword. Use 'cnt' instead., AGE does not support ON CREATE SET / ON MATCH SET., AGE nodes use alert_id/decision_id, not bare 'id'., AGE does not support datetime(). Use epoch integers., AGE does not support labels(n)[0]. Use head(labels(n))., AGE does not support NOT (a)<-[:REL]-(). Use NOT exists(). (+5 more)

### Community 20 - "Community 20"
Cohesion: 0.15
Nodes (21): _coerce_number(), normalize_agtype_row(), normalize_agtype_value(), AGE agtype read-side normalization.  AGE returns property values as agtype-encod, Normalize a single AGE agtype value to a Python value., Convert a psycopg row plus column names to a normalized dict., test_boolean_false(), test_boolean_true() (+13 more)

### Community 21 - "Community 21"
Cohesion: 0.13
Nodes (20): cmdb_criticality_to_float(), dn_list_to_names(), dn_to_username(), get_transformer(), Deterministic field transformers for enterprise connector profiles., Map common CMDB criticality labels or 1-5 levels to bounded floats., Return a registered transformer by name., Convert common yes/no style values to bool. (+12 more)

### Community 22 - "Community 22"
Cohesion: 0.21
Nodes (16): AGEGraphStore, _decisions(), _domain(), FakeArchiveStore, _ids(), In-memory AGE query double for the retention query shapes only., test_active_reads_and_d2_counts_exclude_archived_decisions(), test_archive_801_retains_newest_800_and_archives_oldest() (+8 more)

### Community 23 - "Community 23"
Cohesion: 0.13
Nodes (17): compute_centroid_distance(), interpret_distance_trend(), Centroid convergence health — EXP-G1 primary γ metric.  compute_centroid_distanc, L2 distance between current centroid tensor and canonical baseline.      Formula, Interpret a chronological sequence of centroid distances.      Args:         dis, Add centroid distance health to the qualification report.         Call alongside, Tests for centroid_convergence.py and DeploymentQualifier.qualify_with_distance(, Distance from a tensor to itself is exactly 0. (+9 more)

### Community 24 - "Community 24"
Cohesion: 0.19
Nodes (9): SentinelWriteBack, test_build_comment_tagged(), test_bulk_enrich(), test_enrich_incident_all_three(), test_enrich_incident_decision_only(), test_enrich_incident_write_failure(), test_format_campaign_comment(), test_format_decision_comment() (+1 more)

### Community 25 - "Community 25"
Cohesion: 0.25
Nodes (14): create_affects_query(), create_alert_query(), create_feeds_query(), create_system_query(), delete_dataops_graph(), derive_recurrence_count(), derive_severity(), is_resolved() (+6 more)

### Community 26 - "Community 26"
Cohesion: 0.38
Nodes (4): Conformance tests for canonical JM topology edges., _store(), test_write_decision_creates_factor_vector_node(), test_write_decision_creates_in_domain_edge()

### Community 28 - "Community 28"
Cohesion: 0.4
Nodes (3): Shared domain configuration contracts., Canonical Source-to-Pay invoice exception domain configuration., S2PDomainConfigV2

### Community 29 - "Community 29"
Cohesion: 0.6
Nodes (4): _method_source(), Contract tests for domain-scoped AGE artifact idempotency reads., test_artifact_idempotency_domain_scoped(), test_artifact_read_uses_domain_predicate()

### Community 30 - "Community 30"
Cohesion: 0.5
Nodes (3): Contract checks for domain-scoped CI graph reads., A graph read cannot be invoked without an explicit domain., test_age_store_get_decision_requires_domain()

### Community 32 - "Community 32"
Cohesion: 1.0
Nodes (1): Prompt 0 ci-platform: Structural map of the Bridge library. Run from ci-platform

### Community 33 - "Community 33"
Cohesion: 1.0
Nodes (1): ci_platform.graph — Shared graph client for all copilots.  Usage (SOC, S2P, any

### Community 34 - "Community 34"
Cohesion: 1.0
Nodes (1): Strategy helpers for GraphStore-backed platform decisions.

### Community 35 - "Community 35"
Cohesion: 1.0
Nodes (1): Schema constants for the DataOps AGE graph namespace.

### Community 36 - "Community 36"
Cohesion: 1.0
Nodes (1): DataOps graph schema constants for ci-platform.

### Community 43 - "Community 43"
Cohesion: 1.0
Nodes (1): Connection behavior used by run_query: fresh, pooled, or warm_fallback.

### Community 44 - "Community 44"
Cohesion: 1.0
Nodes (1): Serialize Python types for AGE Cypher parameter interpolation.         Used in _

### Community 45 - "Community 45"
Cohesion: 1.0
Nodes (1): Convert the legacy factors mapping into the canonical vector shape.

### Community 54 - "Community 54"
Cohesion: 1.0
Nodes (1): Connection behavior used by run_query: fresh, pooled, or warm_fallback.

### Community 55 - "Community 55"
Cohesion: 1.0
Nodes (1): Serialize Python types for AGE Cypher parameter interpolation.         Used in _

### Community 56 - "Community 56"
Cohesion: 1.0
Nodes (1): Serialize Python types for AGE Cypher parameter interpolation.         Used in _

## Knowledge Gaps
- **320 isolated node(s):** `Shared domain configuration contracts.`, `Canonical Source-to-Pay invoice exception domain configuration.`, `Prompt 0 ci-platform: Structural map of the Bridge library. Run from ci-platform`, `Evidence Ledger — hash-chained audit trail for per-decision accountability.  EU`, `Compute and store entry_hash. Returns self for chaining.` (+315 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **Thin community `Community 32`** (2 nodes): `Prompt 0 ci-platform: Structural map of the Bridge library. Run from ci-platform`, `prompt0_ci_structural_map.py`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 33`** (2 nodes): `__init__.py`, `ci_platform.graph — Shared graph client for all copilots.  Usage (SOC, S2P, any`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 34`** (2 nodes): `__init__.py`, `Strategy helpers for GraphStore-backed platform decisions.`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 35`** (2 nodes): `schema.py`, `Schema constants for the DataOps AGE graph namespace.`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 36`** (2 nodes): `__init__.py`, `DataOps graph schema constants for ci-platform.`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 43`** (1 nodes): `Connection behavior used by run_query: fresh, pooled, or warm_fallback.`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 44`** (1 nodes): `Serialize Python types for AGE Cypher parameter interpolation.         Used in _`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 45`** (1 nodes): `Convert the legacy factors mapping into the canonical vector shape.`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 54`** (1 nodes): `Connection behavior used by run_query: fresh, pooled, or warm_fallback.`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 55`** (1 nodes): `Serialize Python types for AGE Cypher parameter interpolation.         Used in _`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 56`** (1 nodes): `Serialize Python types for AGE Cypher parameter interpolation.         Used in _`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `AGEClient` connect `Community 0` to `Community 1`, `Community 2`, `Community 8`, `Community 14`, `Community 15`, `Community 25`?**
  _High betweenness centrality (0.321) - this node is a cross-community bridge._
- **Why does `AGEGraphStore` connect `Community 1` to `Community 0`, `Community 2`, `Community 4`, `Community 14`, `Community 18`, `Community 22`?**
  _High betweenness centrality (0.278) - this node is a cross-community bridge._
- **Why does `AGEGraphStoreAdapter` connect `Community 4` to `Community 1`?**
  _High betweenness centrality (0.080) - this node is a cross-community bridge._
- **Are the 10 inferred relationships involving `AGEGraphStore` (e.g. with `AGEClient` and `AGEGraphStoreAdapter`) actually correct?**
  _`AGEGraphStore` has 10 INFERRED edges - model-reasoned connections that need verification._
- **Are the 34 inferred relationships involving `AGEClient` (e.g. with `AGEGraphStore` and `FakeTransaction`) actually correct?**
  _`AGEClient` has 34 INFERRED edges - model-reasoned connections that need verification._
- **Are the 17 inferred relationships involving `AGEGraphStoreAdapter` (e.g. with `AGEGraphStore` and `FakeGraphStore`) actually correct?**
  _`AGEGraphStoreAdapter` has 17 INFERRED edges - model-reasoned connections that need verification._
- **Are the 21 inferred relationships involving `SAPODataConnector` (e.g. with `_FakeResponse` and `_FakeAsyncClient`) actually correct?**
  _`SAPODataConnector` has 21 INFERRED edges - model-reasoned connections that need verification._