# G15 Celonis Process Mining Connector Plan

## 1. Executive Summary

Current state: ci-platform has an alert-oriented `SourceConnectorProtocol`, not a generic process/source-node connector abstraction. The protocol requires `fetch_alerts()`, `write_disposition()`, and `health_check()` [ci_platform/connectors/base.py:5](../../ci_platform/connectors/base.py#L5)-[11](../../ci_platform/connectors/base.py#L11). Existing connectors implement that alert contract, including Sentinel [ci_platform/connectors/sentinel.py:48](../../ci_platform/connectors/sentinel.py#L48)-[56](../../ci_platform/connectors/sentinel.py#L56) and Splunk [ci_platform/connectors/splunk.py:34](../../ci_platform/connectors/splunk.py#L34)-[40](../../ci_platform/connectors/splunk.py#L40). The onboarding path produces a `LoadManifest` with `nodes`, `relationships`, `entity_map`, and `stats` [ci_platform/onboarding/pipeline.py:61](../../ci_platform/onboarding/pipeline.py#L61)-[66](../../ci_platform/onboarding/pipeline.py#L66), and its load stage creates dictionary-shaped nodes and relationships [ci_platform/onboarding/pipeline.py:310](../../ci_platform/onboarding/pipeline.py#L310)-[390](../../ci_platform/onboarding/pipeline.py#L390).

Target state: add a future Celonis process-mining integration that produces a process subgraph in the repo's actual manifest/dictionary shape first, then optionally connects to Celonis through `pycelonis>=2.0` or a REST fallback behind mocks. Unit tests must be offline and deterministic.

Classification: `SCOPE_REPAIR_NEEDED`. The uploaded request assumes `SourceNode`, `SourceEdge`, and `GraphIngester` may exist, but repository discovery found no Python matches for those symbols, while the real ingestion abstraction is `LoadManifest` plus AGE query helpers.

This prompt is plan-only. No source, test, dependency, fixture, or config files were changed. No live Celonis calls were made. Cross-domain edges are not CelonisConnector responsibility; `BOTTLENECK_AT`, `TRIGGERED_BY`, and `INVOICE_PATTERN` must be created later by enrichment, context routing, or cross-graph attention sweeps.

## 2. Current Architecture

Connector interface: `SourceConnectorProtocol` is alert-oriented and requires `fetch_alerts(self, since, limit)`, `write_disposition(self, alert_id, disposition)`, and `health_check()` [ci_platform/connectors/base.py:5](../../ci_platform/connectors/base.py#L5)-[11](../../ci_platform/connectors/base.py#L11). This should not be forced to represent process mining records without an adapter decision.

Existing connectors: Sentinel defines `SentinelConfig` and `SentinelConnector(SourceConnectorProtocol)` [ci_platform/connectors/sentinel.py:36](../../ci_platform/connectors/sentinel.py#L36)-[56](../../ci_platform/connectors/sentinel.py#L56), uses `httpx.AsyncClient` for token/query/write APIs [ci_platform/connectors/sentinel.py:62](../../ci_platform/connectors/sentinel.py#L62)-[90](../../ci_platform/connectors/sentinel.py#L90), and maps external rows to canonical alert dictionaries [ci_platform/connectors/sentinel.py:159](../../ci_platform/connectors/sentinel.py#L159)-[170](../../ci_platform/connectors/sentinel.py#L170). Splunk follows the same pattern with `SplunkConnector(SourceConnectorProtocol)` [ci_platform/connectors/splunk.py:21](../../ci_platform/connectors/splunk.py#L21)-[40](../../ci_platform/connectors/splunk.py#L40), `httpx.AsyncClient` fetch/write behavior [ci_platform/connectors/splunk.py:46](../../ci_platform/connectors/splunk.py#L46)-[99](../../ci_platform/connectors/splunk.py#L99), and alert mapping [ci_platform/connectors/splunk.py:138](../../ci_platform/connectors/splunk.py#L138)-[148](../../ci_platform/connectors/splunk.py#L148).

Ingestion path: `OnboardingPipeline` accepts a `SourceConnectorProtocol` [ci_platform/onboarding/pipeline.py:83](../../ci_platform/onboarding/pipeline.py#L83)-[92](../../ci_platform/onboarding/pipeline.py#L92), extracts alerts through `fetch_alerts` [ci_platform/onboarding/pipeline.py:176](../../ci_platform/onboarding/pipeline.py#L176)-[189](../../ci_platform/onboarding/pipeline.py#L189), normalizes alert fields [ci_platform/onboarding/pipeline.py:191](../../ci_platform/onboarding/pipeline.py#L191)-[233](../../ci_platform/onboarding/pipeline.py#L233), resolves user/asset identifiers [ci_platform/onboarding/pipeline.py:254](../../ci_platform/onboarding/pipeline.py#L254)-[308](../../ci_platform/onboarding/pipeline.py#L308), and builds `LoadManifest` nodes/relationships [ci_platform/onboarding/pipeline.py:310](../../ci_platform/onboarding/pipeline.py#L310)-[399](../../ci_platform/onboarding/pipeline.py#L399). Its current load stage is security-alert-specific: it emits `User` or `Asset` nodes from resolved entities [ci_platform/onboarding/pipeline.py:327](../../ci_platform/onboarding/pipeline.py#L327)-[335](../../ci_platform/onboarding/pipeline.py#L335), `Alert` nodes [ci_platform/onboarding/pipeline.py:337](../../ci_platform/onboarding/pipeline.py#L337)-[351](../../ci_platform/onboarding/pipeline.py#L351), `AlertType` nodes [ci_platform/onboarding/pipeline.py:353](../../ci_platform/onboarding/pipeline.py#L353)-[357](../../ci_platform/onboarding/pipeline.py#L357), and `CLASSIFIED_AS`, `INVOLVES`, or `DETECTED_ON` relationships [ci_platform/onboarding/pipeline.py:358](../../ci_platform/onboarding/pipeline.py#L358)-[374](../../ci_platform/onboarding/pipeline.py#L374).

SourceNode/SourceEdge/GraphIngester status: no Python definitions or usages of `SourceNode`, `SourceEdge`, or `GraphIngester` were found by repository search. The implemented equivalent to target for a first process connector is therefore a process-specific manifest adapter, not a non-existent ingester class.

AGE graph access: `AGEClient` is the shared graph client [ci_platform/graph/age_client.py:72](../../ci_platform/graph/age_client.py#L72)-[84](../../ci_platform/graph/age_client.py#L84), exposes `run_query()` as the central Cypher execution path [ci_platform/graph/age_client.py:884](../../ci_platform/graph/age_client.py#L884)-[903](../../ci_platform/graph/age_client.py#L903), and rejects unsupported AGE Cypher patterns such as `MERGE` [ci_platform/graph/age_client.py:53](../../ci_platform/graph/age_client.py#L53)-[69](../../ci_platform/graph/age_client.py#L69). Any future graph-write integration must respect the existing MATCH-then-CREATE guidance [ci_platform/graph/age_client.py:13](../../ci_platform/graph/age_client.py#L13), and tests already protect `MERGE` rejection [tests/test_age_client.py:120](../../tests/test_age_client.py#L120)-[132](../../tests/test_age_client.py#L132).

Graph label convention: current AGE queries use PascalCase node labels such as `Alert`, `Asset`, `User`, `Location`, `AttackPattern`, `Campaign`, `ThreatIndicator`, and `BehaviorHistory` [ci_platform/graph/age_client.py:374](../../ci_platform/graph/age_client.py#L374)-[381](../../ci_platform/graph/age_client.py#L381). The onboarding manifest also uses PascalCase `User`, `Asset`, `Alert`, and `AlertType` types [ci_platform/onboarding/pipeline.py:327](../../ci_platform/onboarding/pipeline.py#L327)-[357](../../ci_platform/onboarding/pipeline.py#L357). The embedded process labels `ProcessModel`, `ProcessVariant`, `Activity`, `Transition`, and `ProcessKPI` are consistent with this convention.

Celonis/process-mining/D-CEL data: repository search found no in-code `celonis`, `process_mining`, `ProcessModel`, `ProcessVariant`, `D-CEL`, or `DCEL` references. Therefore the future implementation should add small synthetic fixtures rather than depend on existing cached D-CEL data.

Dependency state: `pyproject.toml` declares `httpx`, `numpy`, and `python3-saml` as runtime dependencies [pyproject.toml:5](../../pyproject.toml#L5)-[10](../../pyproject.toml#L10), and `psycopg[async]` only under the `graph` extra [pyproject.toml:12](../../pyproject.toml#L12)-[13](../../pyproject.toml#L13). `pycelonis` is not currently declared. `requirements.txt` and `poetry.lock` are absent in this repo, based on local path checks.

Existing tests: connector tests use mocks, not live services. Sentinel tests patch `httpx.AsyncClient` for fetch, write, and health behavior [tests/test_sentinel.py:70](../../tests/test_sentinel.py#L70)-[166](../../tests/test_sentinel.py#L166). Splunk tests also patch `httpx.AsyncClient` [tests/test_splunk.py:54](../../tests/test_splunk.py#L54)-[126](../../tests/test_splunk.py#L126). Onboarding tests use an `AsyncMock` connector and inspect resulting manifest behavior [tests/test_onboarding_pipeline.py:38](../../tests/test_onboarding_pipeline.py#L38)-[52](../../tests/test_onboarding_pipeline.py#L52), [tests/test_onboarding_pipeline.py:109](../../tests/test_onboarding_pipeline.py#L109)-[128](../../tests/test_onboarding_pipeline.py#L128).

## 3. Target Process Graph Schema

Use the embedded schema as the normative target, represented in the current manifest dictionary style unless a later prompt explicitly approves an AGE writer.

Node types:

- `ProcessModel`: `id`, `name`, `case_count`, `variant_count`, `source`, `extracted_at`.
- `ProcessVariant`: `id`, `process_model_id`, `frequency`, `avg_duration`, `conformance_rate`.
- `Activity`: `id`, `name`, `avg_duration`, `automation_rate`, `rework_rate`.
- `Transition`: `id`, `from_activity`, `to_activity`, `frequency`, `wait_time`, `conformance`.
- `ProcessKPI`: optional node only if the manifest/writer path can represent KPI nodes cleanly; properties may include `cycle_time`, `on_time_rate`, and `conformance_rate`.

Intra-process edges:

- `ProcessModel -[HAS_VARIANT]-> ProcessVariant`.
- `ProcessVariant -[CONTAINS]-> Activity`.
- `Activity -[TRANSITIONS_TO]-> Activity`, with transition metrics as relationship properties when the future manifest/writer supports relationship properties. If the chosen writer cannot preserve relationship properties, use `Transition` nodes connected by explicit relationships and document that decision in the implementation prompt.

Out-of-scope cross-domain edges:

- `Activity -[BOTTLENECK_AT]-> PipelineSystem`.
- `Activity -[TRIGGERED_BY]-> SchemaChange`.
- `Supplier -[INVOICE_PATTERN]-> Activity`.

Those cross-domain edges are future enrichment/context-router/cross-graph work, not CelonisConnector output.

## 4. Celonis API / Access Design

Preferred future integration is `pycelonis>=2.0` if a dependency change is separately approved. Because `pycelonis` is not in current dependencies [pyproject.toml:5](../../pyproject.toml#L5)-[13](../../pyproject.toml#L13), Prompt 1 should not require it. Use a lazy import inside a client wrapper, and provide a REST fallback using the existing `httpx` dependency already used by Sentinel and Splunk [ci_platform/connectors/sentinel.py:6](../../ci_platform/connectors/sentinel.py#L6), [ci_platform/connectors/splunk.py:6](../../ci_platform/connectors/splunk.py#L6).

Environment variables for future manual/live validation may include `CELONIS_BASE_URL`, `CELONIS_API_TOKEN`, and optionally `CELONIS_DATA_POOL_ID` / `CELONIS_PROCESS_MODEL_ID`. Do not store secrets in code or fixtures. Unit tests must use fixtures/mocks and must not contact Celonis.

API details for `pycelonis>=2.0` must be verified during implementation from the installed package or official docs available then. This plan intentionally does not bake in pycelonis method names from memory.

## 5. CelonisConnector / Adapter Design

Do not force process mining into the current alert-oriented `fetch_alerts()` contract unless a later implementation prompt explicitly approves an adapter. The safer architecture is:

- `CelonisProcessConnector` or `CelonisConnector` exposes process-specific methods:
  - `connect()`
  - `health_check()`
  - `fetch_process_models()`
  - `fetch_variants(process_model_id)`
  - `fetch_activities(process_model_id, variant_id=None)`
  - `fetch_transitions(process_model_id, variant_id=None)`
  - `to_load_manifest()` or `to_process_manifest()`
- `ProcessManifestBuilder` converts normalized Celonis records to the existing `LoadManifest` shape: `nodes`, `relationships`, `entity_map`, and `stats` [ci_platform/onboarding/pipeline.py:61](../../ci_platform/onboarding/pipeline.py#L61)-[66](../../ci_platform/onboarding/pipeline.py#L66).
- A later AGE writer may consume that manifest and use `AGEClient.run_query()` [ci_platform/graph/age_client.py:884](../../ci_platform/graph/age_client.py#L884)-[903](../../ci_platform/graph/age_client.py#L903), respecting `MERGE` rejection [ci_platform/graph/age_client.py:53](../../ci_platform/graph/age_client.py#L53)-[69](../../ci_platform/graph/age_client.py#L69).

Error handling:

- Celonis unavailable: use cached fixture fallback only when explicitly enabled.
- Malformed response: raise a clear connector/normalization error.
- Missing optional metrics: omit the property or set `None`, matching the final manifest convention chosen in implementation.
- Missing required process fields: reject the record with an explicit error.
- No cross-domain enrichment: connector emits only process nodes and intra-process edges.

Cadence should be configurable as hourly or daily, but scheduling is out of scope unless a current scheduler is found in a later prompt.

## 6. Fixture / Cached Data Strategy

No existing Celonis or D-CEL cached data was found. Add synthetic fixture files in a future implementation, likely under `tests/fixtures/celonis/`, unless test conventions point elsewhere at that time.

The minimal fixture should include:

- one process model;
- two variants;
- at least three activities;
- transitions with frequency, wait time, and conformance;
- optional KPI sample.

Fixtures must be small, deterministic, and sufficient to prove manifest shape and intra-process relationships. Tests must not require `pycelonis` or a live Celonis tenant.

## 7. Integration Points

Future production files:

- `ci_platform/connectors/celonis.py`: new process connector/client/fixture fallback module. Existing connector modules live under `ci_platform/connectors/` [ci_platform/connectors/sentinel.py:48](../../ci_platform/connectors/sentinel.py#L48), [ci_platform/connectors/splunk.py:34](../../ci_platform/connectors/splunk.py#L34).
- `ci_platform/connectors/process_manifest.py` or a private helper inside `celonis.py`: converts process records into the `LoadManifest` dictionary shape, because `LoadManifest` is the real manifest abstraction [ci_platform/onboarding/pipeline.py:61](../../ci_platform/onboarding/pipeline.py#L61)-[66](../../ci_platform/onboarding/pipeline.py#L66).
- Optional AGE ingestion module only in a later prompt: use `AGEClient.run_query()` if direct graph writes are approved [ci_platform/graph/age_client.py:884](../../ci_platform/graph/age_client.py#L884)-[903](../../ci_platform/graph/age_client.py#L903).

Future tests/fixtures:

- `tests/test_celonis_connector.py`: fixture parsing, offline client behavior, manifest conversion, no cross-domain edges.
- `tests/fixtures/celonis/process_fixture.json`: proposed synthetic process data.
- Existing onboarding or AGE tests only if integration with `LoadManifest`/AGE writer is approved later.

Dependency/config files:

- No dependency file changes in Prompt 1.
- `pyproject.toml` only if a later implementation prompt explicitly approves optional `pycelonis` dependency support. Current dependencies do not include it [pyproject.toml:5](../../pyproject.toml#L5)-[13](../../pyproject.toml#L13).

Forbidden:

- No SOC, SDK, S2P, GAE, or external repo changes.
- No live Celonis calls.
- No dependency installation.

## 8. What Does NOT Change

- Existing Sentinel/Splunk alert connectors remain unchanged.
- `SourceConnectorProtocol` remains unchanged unless a later implementation prompt proves a separate process connector protocol is necessary.
- Existing onboarding pipeline remains unchanged in Prompt 1.
- Existing AGE client behavior remains unchanged; it rejects unsupported Cypher such as `MERGE` [ci_platform/graph/age_client.py:53](../../ci_platform/graph/age_client.py#L53)-[69](../../ci_platform/graph/age_client.py#L69).
- No cross-domain `BOTTLENECK_AT`, `TRIGGERED_BY`, or `INVOICE_PATTERN` edges in CelonisConnector.
- No live Celonis in unit tests.
- `pycelonis` remains optional until a dependency prompt approves it.
- No SOC/SDK/S2P/GAE changes.
- No dependency changes in this planning prompt.

## 9. Risks and Mitigations

- Alert-oriented protocol risk: current `SourceConnectorProtocol` is alert-specific [ci_platform/connectors/base.py:5](../../ci_platform/connectors/base.py#L5)-[11](../../ci_platform/connectors/base.py#L11). Mitigation: add a process-specific adapter/manifest builder instead of pretending Celonis emits alerts.
- No SourceNode/SourceEdge/GraphIngester: repository search found no such symbols. Mitigation: target `LoadManifest` dictionaries first.
- pycelonis API drift: `pycelonis` is not a dependency today [pyproject.toml:5](../../pyproject.toml#L5)-[13](../../pyproject.toml#L13). Mitigation: lazy import and verify API details during implementation.
- No live tenant in CI: tests must use fixtures/mocks like existing connector tests [tests/test_sentinel.py:70](../../tests/test_sentinel.py#L70)-[166](../../tests/test_sentinel.py#L166).
- Cached D-CEL data missing: add synthetic fixtures.
- AGE label mismatch: PascalCase labels are consistent with existing graph queries [ci_platform/graph/age_client.py:374](../../ci_platform/graph/age_client.py#L374)-[381](../../ci_platform/graph/age_client.py#L381), but tests should still assert the chosen convention.
- Transition node vs relationship ambiguity: decide based on whether the future writer preserves relationship properties.
- Cross-domain edge scope creep: test that connector output does not emit `BOTTLENECK_AT`, `TRIGGERED_BY`, or `INVOICE_PATTERN`.
- Large Celonis payloads: page/limit API access in future client wrapper and keep unit fixtures small.
- Secrets/env vars missing: health check should return a clear not-configured status.
- Malformed Celonis response: normalize with explicit validation errors.
- Accidental hard dependency: tests must prove unit path works without importing `pycelonis`.

## 10. Test Plan

- `test_celonis_connector_loads_fixture_process_model`: loads the synthetic fixture and exposes one process model offline.
- `test_process_node_types_have_required_properties`: validates `ProcessModel`, `ProcessVariant`, `Activity`, and `Transition` required properties.
- `test_intra_process_edges_connect_expected_node_types`: verifies `HAS_VARIANT`, `CONTAINS`, and `TRANSITIONS_TO`.
- `test_connector_does_not_emit_cross_domain_edges`: rejects `BOTTLENECK_AT`, `TRIGGERED_BY`, and `INVOICE_PATTERN` from connector output.
- `test_cached_fallback_used_when_celonis_unavailable`: proves fallback is opt-in and fixture-backed.
- `test_malformed_celonis_response_returns_clear_error`: proves bad payloads do not silently create partial graph data.
- `test_round_trip_fixture_to_manifest_or_ingestion_format`: proves fixture records convert to `LoadManifest`-style dictionaries.
- `test_pycelonis_not_required_for_unit_tests`: proves tests pass without `pycelonis` import availability.
- `test_node_labels_follow_pascal_case_or_current_schema_convention`: protects the label convention.
- `test_transition_relationship_or_node_shape_matches_plan`: locks the chosen transition representation.

All tests must be offline and deterministic.

## 11. Files to Modify in Future Implementation

Production files:

- `ci_platform/connectors/celonis.py` (new): connector modules already live under `ci_platform/connectors/` [ci_platform/connectors/sentinel.py:48](../../ci_platform/connectors/sentinel.py#L48), [ci_platform/connectors/splunk.py:34](../../ci_platform/connectors/splunk.py#L34).
- `ci_platform/connectors/process_manifest.py` (new, optional) or private helpers in `celonis.py`: needed because `LoadManifest` is the current manifest shape [ci_platform/onboarding/pipeline.py:61](../../ci_platform/onboarding/pipeline.py#L61)-[66](../../ci_platform/onboarding/pipeline.py#L66).
- Optional future AGE writer/adapter only after a separate prompt: must use `AGEClient.run_query()` [ci_platform/graph/age_client.py:884](../../ci_platform/graph/age_client.py#L884)-[903](../../ci_platform/graph/age_client.py#L903).

Fixture files:

- `tests/fixtures/celonis/process_fixture.json` or equivalent test fixture path.

Test files:

- `tests/test_celonis_connector.py`.
- Optional manifest/AGE tests if the implementation prompt includes a writer.

Dependency/config files:

- None for Prompt 1.
- `pyproject.toml` only in a later dependency-approved prompt.

Forbidden files/repos:

- No source changes outside ci-platform.
- No SOC/SDK/S2P/GAE repositories.
- No live tenant secrets or fixture secrets.

## 12. Future Implementation Sequence

Prompt 1: implement offline fixture parser plus process manifest/node/edge adapter and tests. No pycelonis dependency and no live calls.

Prompt 2: implement Celonis client wrapper with optional lazy `pycelonis` and REST fallback behind mocks.

Prompt 3: integrate with existing onboarding/manifest or AGE writer path if required and explicitly approved.

Prompt 4: GPT-5.5 line-by-line and architecture review.

## 13. Validation Commands for Future Implementation

Targeted connector tests:

```powershell
cd "C:\Users\baner\CopyFolder\IoT_thoughts\python-projects\kaggle_experiments\claude_projects\ci-platform"
python -m pytest tests\test_celonis_connector.py -v --timeout=120
```

Targeted onboarding/manifest tests if touched:

```powershell
cd "C:\Users\baner\CopyFolder\IoT_thoughts\python-projects\kaggle_experiments\claude_projects\ci-platform"
python -m pytest tests\test_onboarding_pipeline.py -v --timeout=120
```

Connector subset:

```powershell
cd "C:\Users\baner\CopyFolder\IoT_thoughts\python-projects\kaggle_experiments\claude_projects\ci-platform"
python -m pytest tests -q --timeout=120 -k "connector or sentinel or splunk or celonis"
```

Full ci-platform suite:

```powershell
cd "C:\Users\baner\CopyFolder\IoT_thoughts\python-projects\kaggle_experiments\claude_projects\ci-platform"
python -m pytest tests/ -q --timeout=120
```

## 14. Manual Live Validation Appendix

Manual validation is optional and not part of CI or unit tests.

Potential environment variables:

- `CELONIS_BASE_URL`
- `CELONIS_API_TOKEN`
- `CELONIS_DATA_POOL_ID`
- `CELONIS_PROCESS_MODEL_ID`
- `CELONIS_USE_FIXTURE_FALLBACK=0`

Manual pycelonis dependency decision:

- Install `pycelonis>=2.0` only after a dependency-approved prompt.
- If no dependency approval exists, use the REST fallback smoke path.

Example future smoke command, after implementation and explicit live-stack approval:

```powershell
cd "C:\Users\baner\CopyFolder\IoT_thoughts\python-projects\kaggle_experiments\claude_projects\ci-platform"
python -m pytest tests\test_celonis_connector.py -v -m manual_celonis
```

## 15. Reading Log

- `CLAUDE.md`: repository grounding and AGEClient boundary rules [CLAUDE.md:1](../../CLAUDE.md#L1)-[24](../../CLAUDE.md#L24), no-git and dependency-flow rules [CLAUDE.md:68](../../CLAUDE.md#L68)-[73](../../CLAUDE.md#L73).
- `ci_platform/connectors/base.py`: full connector protocol [ci_platform/connectors/base.py:1](../../ci_platform/connectors/base.py#L1)-[11](../../ci_platform/connectors/base.py#L11).
- `ci_platform/connectors/sentinel.py`: full Sentinel connector shape [ci_platform/connectors/sentinel.py:36](../../ci_platform/connectors/sentinel.py#L36)-[192](../../ci_platform/connectors/sentinel.py#L192).
- `ci_platform/connectors/splunk.py`: full Splunk connector shape [ci_platform/connectors/splunk.py:21](../../ci_platform/connectors/splunk.py#L21)-[157](../../ci_platform/connectors/splunk.py#L157).
- `ci_platform/connectors/sentinel_writeback.py`: writeback wrapper pattern [ci_platform/connectors/sentinel_writeback.py:23](../../ci_platform/connectors/sentinel_writeback.py#L23)-[168](../../ci_platform/connectors/sentinel_writeback.py#L168).
- `ci_platform/onboarding/pipeline.py`: connector ingestion and `LoadManifest` generation [ci_platform/onboarding/pipeline.py:49](../../ci_platform/onboarding/pipeline.py#L49)-[430](../../ci_platform/onboarding/pipeline.py#L430).
- `ci_platform/graph/age_client.py`: AGE client, label examples, and Cypher constraints [ci_platform/graph/age_client.py:1](../../ci_platform/graph/age_client.py#L1)-[170](../../ci_platform/graph/age_client.py#L170), [ci_platform/graph/age_client.py:367](../../ci_platform/graph/age_client.py#L367)-[420](../../ci_platform/graph/age_client.py#L420), [ci_platform/graph/age_client.py:621](../../ci_platform/graph/age_client.py#L621)-[690](../../ci_platform/graph/age_client.py#L690), [ci_platform/graph/age_client.py:884](../../ci_platform/graph/age_client.py#L884)-[903](../../ci_platform/graph/age_client.py#L903).
- `ci_platform/graph/age_graph_store.py`: GraphStore adapter node/edge write examples [ci_platform/graph/age_graph_store.py:16](../../ci_platform/graph/age_graph_store.py#L16)-[330](../../ci_platform/graph/age_graph_store.py#L330).
- `ci_platform/graph/__init__.py`: exported graph client/store APIs [ci_platform/graph/__init__.py:1](../../ci_platform/graph/__init__.py#L1)-[13](../../ci_platform/graph/__init__.py#L13).
- `pyproject.toml`: dependency and test config [pyproject.toml:1](../../pyproject.toml#L1)-[49](../../pyproject.toml#L49).
- `tests/test_onboarding_pipeline.py`: mocked connector and manifest tests [tests/test_onboarding_pipeline.py:1](../../tests/test_onboarding_pipeline.py#L1)-[212](../../tests/test_onboarding_pipeline.py#L212).
- `tests/test_sentinel.py`: mocked Sentinel connector tests [tests/test_sentinel.py:1](../../tests/test_sentinel.py#L1)-[166](../../tests/test_sentinel.py#L166).
- `tests/test_splunk.py`: mocked Splunk connector tests [tests/test_splunk.py:1](../../tests/test_splunk.py#L1)-[126](../../tests/test_splunk.py#L126).
- `tests/test_age_client.py`: AGE Cypher safety and integration patterns [tests/test_age_client.py:105](../../tests/test_age_client.py#L105)-[190](../../tests/test_age_client.py#L190), [tests/test_age_client.py:216](../../tests/test_age_client.py#L216)-[300](../../tests/test_age_client.py#L300).

## Prompt Verification Pass

1. Referenced paths exist or are marked proposed new files.
2. Actual connector protocol is cited.
3. Actual ingestion path is cited.
4. `SourceNode` / `SourceEdge` / `GraphIngester` absence is documented from repository search, with `LoadManifest` as the real target abstraction.
5. D-CEL cached data absence is documented from repository search.
6. `pycelonis` dependency state is documented without installing it.
7. Cross-domain edges are explicitly out of scope.
8. Tests are fully offline and deterministic.
9. No source, test, dependency, fixture, or config files were changed.
10. No external repos were read.
11. Plan has enough detail for later implementation prompts.

## Implementation Addendum — G15-IMPL-1

- Date: 2026-05-19
- Ambiguity or drift: The target process schema includes direct `Activity -[TRANSITIONS_TO]-> Activity` edges, while the implementation prompt requires `Transition` nodes connected by `TRANSITION_FROM` and `TRANSITION_TO`.
- Safe interpretation: IMPL-1 models transitions as `Transition` nodes with `TRANSITION_FROM` / `TRANSITION_TO` relationships and does not emit direct `TRANSITIONS_TO` edges.
- Files affected: `ci_platform/connectors/celonis.py`, `tests/fixtures/celonis/process_fixture.json`, `tests/test_celonis_connector.py`.
- Why this preserves the approved architecture: transition metrics remain first-class node properties without requiring relationship-property support; the output stays `LoadManifest`-compatible, offline-only, and excludes cross-domain edges.

## Implementation Addendum — G15-IMPL-2

- Date: 2026-05-19
- Ambiguity or drift: The real `pycelonis` API surface is not a project dependency and was intentionally not installed or called during IMPL-2.
- Safe interpretation: IMPL-2 keeps the pycelonis path as lazy availability detection only and uses mocked fixture-shaped REST responses plus fixture fallback for testable behavior.
- Files affected: `ci_platform/connectors/celonis.py`, `tests/test_celonis_connector.py`.
- Why this preserves the approved architecture: no hard pycelonis dependency is introduced, REST tests remain offline and mocked, fixture fallback is explicit, and real Celonis OLAP response adaptation remains deferred to a future implementation prompt.
