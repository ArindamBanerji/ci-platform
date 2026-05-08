# Graph Report - ci-platform  (2026-05-03)

## Corpus Check
- 46 files · ~23,928 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 549 nodes · 886 edges · 20 communities detected
- Extraction: 76% EXTRACTED · 24% INFERRED · 0% AMBIGUOUS · INFERRED: 214 edges (avg confidence: 0.74)
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
- [[_COMMUNITY_Community 25|Community 25]]

## God Nodes (most connected - your core abstractions)
1. `AGEClient` - 39 edges
2. `DeploymentQualifier` - 36 edges
3. `EvidenceLedger` - 34 edges
4. `OnboardingPipeline` - 30 edges
5. `EntityResolver` - 27 edges
6. `SentinelConnector` - 23 edges
7. `PIIRedactor` - 22 edges
8. `SAMLService` - 19 edges
9. `TestNormalizeValue` - 18 edges
10. `SentinelWriteBack` - 17 edges

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
Cohesion: 0.03
Nodes (70): AGEClient, _check_safe_cypher(), get_graph_client(), ci_platform/graph/age_client.py — Shared AGE/PostgreSQL graph client.  Apache AG, No-op. AGEClient uses per-query connections.         Exists for interface parity, Create AGE graph if it doesn't exist. Idempotent., Parse an agtype value returned from AGE.         Nodes/edges: {id, label, proper, Normalize AGE agtype values to clean Python types.         Called once per field (+62 more)

### Community 1 - "Community 1"
Cohesion: 0.08
Nodes (41): _compute_ece(), DeploymentQualifier, NoiseProfile, QualificationResult, Deployment Qualification — decides whether learning is safe to enable.  Three me, Compute Expected Calibration Error for a given tau.     Rescales confidence scor, Per-deployment τ calibration from first 50 shadow decisions.      Called when: s, Measures factor noise, sweeps τ, generates remediation report.      Usage: (+33 more)

### Community 2 - "Community 2"
Cohesion: 0.08
Nodes (40): EvidenceLedger, Append-only hash-chained audit ledger.      Usage:         ledger = EvidenceLedg, _base_kwargs(), _append_decision(), test_concurrent_append_and_outcome_no_corruption(), test_concurrent_appends_unique_chain_indices(), test_interleaved_append_and_outcome_concurrent(), test_sequential_append_chain_integrity() (+32 more)

### Community 3 - "Community 3"
Cohesion: 0.1
Nodes (25): ABC, LedgerEntry, SourceConnectorProtocol, IdentifierType, ResolvedEntity, _failed_result(), _infer_user_id_type(), LoadManifest (+17 more)

### Community 4 - "Community 4"
Cohesion: 0.05
Nodes (11): AGE type roundtrip tests — verify AGEClient normalizes types at the boundary.  T, Verify serialize → normalize returns the original value., numpy array → serialize → normalize → list (tolist conversion)., Test _normalize_value — the read-path boundary., Strings that aren't valid JSON stay as strings., Numeric strings pass through unchanged — no scalar coercion.         _parse_agty, Boolean strings pass through unchanged — no scalar coercion.         _parse_agty, Test serialize_for_age — the write-path boundary. (+3 more)

### Community 5 - "Community 5"
Cohesion: 0.11
Nodes (24): _find_attr(), _find_text(), Validate a base64-encoded SAMLResponse.          When IdP x509 cert is configure, True when all required IdP details are present., Parse base64 SAMLResponse XML without signature verification. Test use only., Full signature + assertion verification via python3-saml., Return SAML 2.0 SP metadata XML string., Create a base64-encoded AuthnRequest and return redirect URL. (+16 more)

### Community 6 - "Community 6"
Cohesion: 0.11
Nodes (22): EnrichmentPayload, EnrichmentType, Enum, _deduplicate(), _get_spacy_model(), _merge_reports(), PIIRedactor, Remove overlapping spans, keeping the longest match. (+14 more)

### Community 7 - "Community 7"
Cohesion: 0.16
Nodes (14): EntityResolver, Identifier, Fraction of entities with >= 2 distinct identifier types., P26 hashed values with same hash resolve to same entity., test_canonical_id_deterministic(), test_completeness_score(), test_cross_type_email_upn(), test_display_name_priority() (+6 more)

### Community 8 - "Community 8"
Cohesion: 0.11
Nodes (13): AGE Cypher compatibility tests — document known AGE vs Neo4j incompatibilities., Verify AGEClient source avoids known AGE anti-patterns., AGE reserves 'count' as keyword. Use 'cnt' instead., AGE does not support ON CREATE SET / ON MATCH SET., AGE nodes use alert_id/decision_id, not bare 'id'., AGE does not support datetime(). Use epoch integers., AGE does not support labels(n)[0]. Use head(labels(n))., AGE does not support NOT (a)<-[:REL]-(). Use NOT exists(). (+5 more)

### Community 9 - "Community 9"
Cohesion: 0.15
Nodes (12): SentinelConfig, SentinelConnector, SourceConnectorProtocol, config(), test_fetch_alerts_mocked(), test_health_check_mocked(), test_is_configured_false(), test_is_configured_true() (+4 more)

### Community 10 - "Community 10"
Cohesion: 0.12
Nodes (17): EnrichmentAdvisor, EnrichmentReport, FactorOpportunity, EnrichmentAdvisor — P28 Phase 2 enrichment opportunity scoring.  Ranks alert fac, Output of EnrichmentAdvisor.recommend()., Scores per-factor enrichment opportunity from a σ profile.      Args:         si, Score all factors and return a ranked EnrichmentReport., _score() (+9 more)

### Community 11 - "Community 11"
Cohesion: 0.13
Nodes (17): compute_centroid_distance(), interpret_distance_trend(), Centroid convergence health — EXP-G1 primary γ metric.  compute_centroid_distanc, L2 distance between current centroid tensor and canonical baseline.      Formula, Interpret a chronological sequence of centroid distances.      Args:         dis, Add centroid distance health to the qualification report.         Call alongside, Tests for centroid_convergence.py and DeploymentQualifier.qualify_with_distance(, Distance from a tensor to itself is exactly 0. (+9 more)

### Community 12 - "Community 12"
Cohesion: 0.16
Nodes (10): SplunkConfig, SplunkConnector, config(), test_build_spl_query(), test_fetch_alerts_mocked(), test_health_check_mocked(), test_is_configured_false(), test_is_configured_true() (+2 more)

### Community 13 - "Community 13"
Cohesion: 0.19
Nodes (9): SentinelWriteBack, test_build_comment_tagged(), test_bulk_enrich(), test_enrich_incident_all_three(), test_enrich_incident_decision_only(), test_enrich_incident_write_failure(), test_format_campaign_comment(), test_format_decision_comment() (+1 more)

### Community 14 - "Community 14"
Cohesion: 0.15
Nodes (8): OutcomeEntry, Evidence Ledger — hash-chained audit trail for per-decision accountability.  EU, Append a new decision entry. Returns the sealed LedgerEntry., Append an outcome verification event to the chain.          Multiple outcomes fo, Verify chain integrity: every entry is internally valid and prev_hash links are, Compute and store entry_hash. Returns self for chaining., True if the stored entry_hash matches a fresh computation., Outcome verification event — appended when a decision's outcome is verified.

### Community 15 - "Community 15"
Cohesion: 0.23
Nodes (13): _age_client(), _mock_conn(), tests/test_graph_backend_switcher.py  Signature-parity tests: verify AGEClient m, Internal callers using alert_id/entity_id/action/verified_correct     must conti, Return a mock psycopg connection context manager returning empty rows., Return an AGEClient with no real DSN (mocked connection)., Exact kwargs from gen-ai-roi-demo-v4-v50/backend/app/routers/evolution.py:417-43, Reasoning is written into the Decision node, not silently dropped. (+5 more)

### Community 16 - "Community 16"
Cohesion: 0.27
Nodes (9): _make_alerts(), Integration Test 1 — P28 pipeline end-to-end.  Tests DeploymentQualifier.qualify, Case 3 — Threshold isolation: L2 AMBER must not be classified as GREEN.      sig, Synthetic alerts with per-factor standard deviations matching sigma_profile., Case 1 — High-noise deployment: DiagonalKernel, AMBER, τ sweep triggered.      s, Case 2 — Low-noise centroidal deployment: L2 kernel, GREEN, τ sweep not triggere, test_case1_high_noise_diagonal_amber(), test_case2_low_noise_l2_green() (+1 more)

### Community 17 - "Community 17"
Cohesion: 1.0
Nodes (1): Prompt 0 ci-platform: Structural map of the Bridge library. Run from ci-platform

### Community 18 - "Community 18"
Cohesion: 1.0
Nodes (1): ci_platform.graph — Shared graph client for all copilots.  Usage (SOC, S2P, any

### Community 25 - "Community 25"
Cohesion: 1.0
Nodes (1): Serialize Python types for AGE Cypher parameter interpolation.         Used in _

## Knowledge Gaps
- **142 isolated node(s):** `Prompt 0 ci-platform: Structural map of the Bridge library. Run from ci-platform`, `Evidence Ledger — hash-chained audit trail for per-decision accountability.  EU`, `Compute and store entry_hash. Returns self for chaining.`, `True if the stored entry_hash matches a fresh computation.`, `Outcome verification event — appended when a decision's outcome is verified.` (+137 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **Thin community `Community 17`** (2 nodes): `Prompt 0 ci-platform: Structural map of the Bridge library. Run from ci-platform`, `prompt0_ci_structural_map.py`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 18`** (2 nodes): `__init__.py`, `ci_platform.graph — Shared graph client for all copilots.  Usage (SOC, S2P, any`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 25`** (1 nodes): `Serialize Python types for AGE Cypher parameter interpolation.         Used in _`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `DeploymentQualifier` connect `Community 1` to `Community 3`, `Community 16`, `Community 11`?**
  _High betweenness centrality (0.145) - this node is a cross-community bridge._
- **Why does `SourceConnectorProtocol` connect `Community 3` to `Community 9`, `Community 12`?**
  _High betweenness centrality (0.114) - this node is a cross-community bridge._
- **Why does `LedgerEntry` connect `Community 3` to `Community 14`?**
  _High betweenness centrality (0.112) - this node is a cross-community bridge._
- **Are the 11 inferred relationships involving `AGEClient` (e.g. with `TestNormalizeValue` and `TestSerializeForAge`) actually correct?**
  _`AGEClient` has 11 INFERRED edges - model-reasoned connections that need verification._
- **Are the 25 inferred relationships involving `DeploymentQualifier` (e.g. with `StageResult` and `LoadManifest`) actually correct?**
  _`DeploymentQualifier` has 25 INFERRED edges - model-reasoned connections that need verification._
- **Are the 25 inferred relationships involving `EvidenceLedger` (e.g. with `test_genesis_entry_prev_hash_is_zeros()` and `test_second_entry_links_to_first()`) actually correct?**
  _`EvidenceLedger` has 25 INFERRED edges - model-reasoned connections that need verification._
- **Are the 21 inferred relationships involving `OnboardingPipeline` (e.g. with `SourceConnectorProtocol` and `EntityResolver`) actually correct?**
  _`OnboardingPipeline` has 21 INFERRED edges - model-reasoned connections that need verification._