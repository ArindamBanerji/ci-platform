# Enterprise Connector Profiles: CMDB and Identity

## 1. Executive Summary

Classification: SCOPE_REPAIR_NEEDED.

Current state: ci-platform has an alert-oriented `SourceConnectorProtocol` with `fetch_alerts`, `write_disposition`, and `health_check` (`ci_platform/connectors/base.py:5-11`). Existing concrete connectors are Sentinel and Splunk, both implementing that alert connector protocol (`ci_platform/connectors/sentinel.py:48-56`; `ci_platform/connectors/splunk.py:34-40`). The onboarding pipeline consumes a `SourceConnectorProtocol`, normalizes alert records, resolves User/Asset entities, and builds a `LoadManifest` containing node and relationship dictionaries (`ci_platform/onboarding/pipeline.py:83-100`; `ci_platform/onboarding/pipeline.py:126-149`; `ci_platform/onboarding/pipeline.py:310-399`).

The original request assumes `SourceNode`, `SourceEdge`, and `GraphIngester` abstractions. Those names do not exist in the current repo search; the actual ingestion-shaped output is `LoadManifest.nodes` and `LoadManifest.relationships` (`ci_platform/onboarding/pipeline.py:61-66`; `ci_platform/onboarding/pipeline.py:381-389`). Therefore the safe design is not to force a nonexistent GraphIngester contract. The future implementation should add an enterprise profile loader plus adapter layer that can map YAML records into source-node-like dictionaries and, where needed, integrate through existing `LoadManifest`/AGEClient patterns.

Target state: add an `EnterpriseConnectorProfile` YAML profile layer for CMDB and Identity that lets enterprise users configure field mappings and named transformers without writing Python connectors. The profile loader should validate YAML, build an offline-testable adapter, and map records into Asset/User node dictionaries compatible with the current manifest style. Plan-only; no source, test, dependency, or config files were changed by this prompt.

CA-P2-01 / SAML is out of scope. Existing SAML code lives under `ci_platform/auth/saml.py` and defines `SAMLConfig`/`SAMLService` (`ci_platform/auth/saml.py:12-39`), but this plan does not modify or extend authentication.

## 2. Current Architecture

### Connector Interface

`SourceConnectorProtocol` is an abstract class with exactly three async methods: `fetch_alerts(self, since: datetime, limit: int = 500) -> List[Dict]`, `write_disposition(self, alert_id: str, disposition: Dict) -> bool`, and `health_check(self) -> Dict` (`ci_platform/connectors/base.py:5-11`). It is alert-oriented, not entity-oriented.

Sentinel implements `SourceConnectorProtocol` (`ci_platform/connectors/sentinel.py:48-56`), fetches alerts from Log Analytics with `httpx.AsyncClient` (`ci_platform/connectors/sentinel.py:56-72`), maps KQL rows into alert dictionaries (`ci_platform/connectors/sentinel.py:159-170`), writes dispositions through Microsoft Graph (`ci_platform/connectors/sentinel.py:74-90`), and exposes `health_check` (`ci_platform/connectors/sentinel.py:92-122`).

Splunk implements `SourceConnectorProtocol` (`ci_platform/connectors/splunk.py:34-40`), creates/polls Splunk searches (`ci_platform/connectors/splunk.py:40-76`), maps Splunk rows into alert dictionaries (`ci_platform/connectors/splunk.py:138-148`), writes dispositions through HEC (`ci_platform/connectors/splunk.py:78-99`), and exposes `health_check` (`ci_platform/connectors/splunk.py:101-130`).

There is no connector registry in `ci_platform/connectors/__init__.py`; the file is empty (`ci_platform/connectors/__init__.py:1`). Existing tests instantiate concrete connectors directly (`tests/test_sentinel.py:22-33`; `tests/test_splunk.py:20-31`).

### SourceNode / SourceEdge / Ingestion Path

No `SourceNode`, `SourceEdge`, or `GraphIngester` symbol exists in the current repo search. The closest current structures are `LoadManifest` and `OnboardingPipeline`.

`LoadManifest` has `nodes: List[Dict]`, `relationships: List[Dict]`, `entity_map: Dict[str, str]`, and `stats: Dict` (`ci_platform/onboarding/pipeline.py:61-66`). `PipelineResult` carries an optional `load_manifest` (`ci_platform/onboarding/pipeline.py:69-78`).

`OnboardingPipeline` accepts a `SourceConnectorProtocol` in its constructor (`ci_platform/onboarding/pipeline.py:83-92`). Its `run()` path executes extract, normalize, redact, resolve, load, and compute stages (`ci_platform/onboarding/pipeline.py:108-160`). `_extract()` calls `self._connector.fetch_alerts(since=since, limit=limit)` (`ci_platform/onboarding/pipeline.py:176-189`). `_normalize()` maps aliases into canonical alert fields and drops records missing required alert fields (`ci_platform/onboarding/pipeline.py:191-233`). `_resolve()` creates entity identifiers from `user_name` and `asset_hostname` (`ci_platform/onboarding/pipeline.py:254-308`). `_load()` builds entity nodes of type `User` or `Asset`, alert nodes, alert type nodes, and relationships into `LoadManifest` (`ci_platform/onboarding/pipeline.py:310-399`).

AGEClient is the graph execution boundary. It exposes no-op async `connect()` and `close()` for interface parity (`ci_platform/graph/age_client.py:98-110`) and async `run_query(query, parameters)` returning `List[Dict[str, Any]]` (`ci_platform/graph/age_client.py:350-363`). This gives future validation-query support a graph execution surface, but there is no current generic ingester that consumes arbitrary `LoadManifest` nodes.

### Existing Connector Examples

Sentinel and Splunk are the active connector examples. Both rely on `httpx.AsyncClient` for live network calls (`ci_platform/connectors/sentinel.py:62-68`; `ci_platform/connectors/splunk.py:46-53`) and have mocked network tests (`tests/test_sentinel.py:70-115`; `tests/test_splunk.py:54-88`).

Sentinel tests cover configuration, row mapping, mocked fetch, mocked write disposition, and mocked health check (`tests/test_sentinel.py:22-166`). Splunk tests cover configuration, row mapping, SPL building, mocked fetch, mocked write disposition, and mocked health check (`tests/test_splunk.py:20-126`).

### YAML Support

No production/test/config `yaml`, `safe_load`, `PyYAML`, or `ruamel` usage was found by repo search; the only current YAML matches are in this implementation plan. The current project dependencies are `httpx>=0.25.0`, `numpy>=1.24.0`, and `python3-saml>=1.16.0`; optional graph dependency is `psycopg[async]>=3.1.0` (`pyproject.toml:10-13`). PyYAML is absent. A future implementation must either add a YAML dependency after explicit approval or use a standard-library-supported format only if the user changes the spec. Because this task’s embedded schemas are YAML, the plan assumes adding `PyYAML` is a future dependency/config change.

### Existing Transformer / Normalizer Utilities

There is no generic transformer registry today. Existing normalization is alert-specific in `_FIELD_ALIASES` (`ci_platform/onboarding/pipeline.py:13-28`) and `_normalize()` (`ci_platform/onboarding/pipeline.py:191-233`). Entity normalization exists inside `EntityResolver._normalize`, with rules for email/UPN, SAM account names, SID, hostname, IP, and hashes (`ci_platform/entity_resolution/resolver.py:88-100`). PII redaction has pattern-based transforms, but it is not a field-mapping transformer registry (`ci_platform/redaction/pii_redactor.py:29-41`).

### Existing Test Patterns

Connector tests use mocked `httpx.AsyncClient` and direct helper assertions (`tests/test_sentinel.py:70-166`; `tests/test_splunk.py:54-126`). Onboarding tests use `AsyncMock` connectors and exercise each pipeline stage offline (`tests/test_onboarding_pipeline.py:38-45`; `tests/test_onboarding_pipeline.py:48-78`; `tests/test_onboarding_pipeline.py:109-129`; `tests/test_onboarding_pipeline.py:159-165`). This is the test style future CMDB/Identity profile tests should follow.

### SAML / LDAP / Identity Boundary

SAML exists as auth infrastructure in `ci_platform/auth/saml.py`, with `SAMLConfig` and `SAMLService` (`ci_platform/auth/saml.py:12-39`). This is CA-P2-01/auth territory and is out of scope. No LDAP connector or identity connector currently exists in repo search; Identity profiles should be connector-profile configuration and mocked offline adapter tests only.

## 3. Target Architecture — EnterpriseConnectorProfile / ProfileLoader

Because current connectors are alert-oriented and there is no `SourceNode`/`SourceEdge` class, introduce a profile layer without changing `SourceConnectorProtocol` initially.

Future components:

- `ci_platform/connectors/profiles.py`: dataclasses for `EnterpriseConnectorProfile`, `EntityMapping`, `ConnectionConfig`, and an adapter such as `ProfileBackedEntityConnector`.
- `ci_platform/connectors/transformers.py`: named transformer registry.
- Optional future `ci_platform/connectors/profile_loader.py` if splitting YAML parsing from profile dataclasses improves maintainability.

`ProfileLoader.from_yaml(path)` should return a validated `EnterpriseConnectorProfile` or a profile-backed entity adapter, not a current `SourceConnectorProtocol` by default. The current protocol is alert-oriented (`ci_platform/connectors/base.py:5-11`), so a compatibility bridge should be added only if a later integration prompt needs the profile adapter to pass through `OnboardingPipeline`.

`ProfileLoader.from_yaml(path)` should:

1. Load YAML using `yaml.safe_load` once PyYAML is explicitly approved and added.
2. Validate the top-level object is a mapping.
3. Validate required top-level fields:
   - `profile_type`
   - `tier`
   - `cadence`
   - `entity_type_produced`
   - `connection`
   - `entity_mappings`
   - `semantic_registry_concept`
4. Validate `profile_type` allowlist:
   - `CMDBConnectorProfile`
   - `IdentityConnectorProfile`
5. Validate `tier` is an integer and initially must be `1`.
6. Validate `cadence` allowlist:
   - `hourly`
   - `daily`
7. Validate `entity_type_produced` allowlist:
   - `Asset`
   - `User`
8. Validate `entity_mappings` is a non-empty list.
9. Validate each mapping has:
   - `source_field`
   - `target_property`
   - `required`
   - optional `transformer`
10. Validate every named transformer exists in the transformer registry.

Field mapping behavior:

- Each source record is read as a dict.
- For each mapping, read `source_field`.
- If missing/blank and `required: true`, raise a clear record-level mapping error.
- If missing/blank and `required: false`, omit `target_property`.
- If `transformer` is present, apply the named transformer before assigning `target_property`.
- The adapter should output node dictionaries shaped like current `LoadManifest.nodes`: at minimum `{"id": ..., "type": "Asset" | "User", ...properties}` because current `_load()` already uses dict nodes with `id` and `type` (`ci_platform/onboarding/pipeline.py:327-335`; `ci_platform/onboarding/pipeline.py:343-357`).

Transformer registry:

- `cmdb_criticality_to_float`: map CMDB criticality labels/numbers to a float, e.g. critical/high/medium/low or 1-5 scale.
- `yes_no_to_bool`: accept yes/no, y/n, true/false, 1/0.
- `dn_to_username`: parse LDAP distinguished names and return the first CN or uid-like username, e.g. `CN=Jane Doe,OU=Users,...` -> `Jane Doe`.
- `dn_list_to_names`: apply DN parsing to a list or semicolon/comma separated values.
- Unknown transformer names must raise a clear validation error before runtime mapping.

Adapter behavior:

- Do not change `SourceConnectorProtocol` unless later implementation proves an adapter cannot work.
- For unit tests, provide a fake fetch provider that returns fixture records. No live CMDB or LDAP network calls.
- For production, the adapter can expose `fetch_records()` / `map_records_to_nodes()` for entity profiles. If integration with existing alert-oriented `OnboardingPipeline` is required later, add a small bridge that converts mapped nodes into `LoadManifest`, not fake alert records.
- `write_disposition()` is not semantically meaningful for CMDB/Identity. Do not force enterprise entity profiles to implement the existing alert connector protocol unless a compatibility adapter returns a clear unsupported result.

Validation query handling:

- CMDB profiles may include `validation_query`.
- Run it only after ingestion if the chosen ingestion path has an `AGEClient.run_query` or equivalent graph execution object (`ci_platform/graph/age_client.py:350-363`).
- Since there is no current generic GraphIngester, validation-query execution is a future integration point, not a requirement for the first profile-loader implementation.

## 4. CMDB Profile Spec

Normative embedded YAML:

```yaml
profile_type: CMDBConnectorProfile
tier: 1
cadence: daily
entity_type_produced: Asset
connection:
  base_url: <CMDB_API_URL>
  auth_type: api_key
  api_key_env_var: CMDB_API_KEY
entity_mappings:
  - source_field: ci_id
    target_property: id
    required: true
  - source_field: ci_name
    target_property: name
    required: true
  - source_field: criticality_level
    target_property: criticality_score
    transformer: cmdb_criticality_to_float
    required: true
  - source_field: monitoring_status
    target_property: monitoring_active
    transformer: yes_no_to_bool
    required: false
  - source_field: owner_team
    target_property: owner
    required: false
  - source_field: data_classification
    target_property: data_class
    required: false
semantic_registry_concept: critical_assets
validation_query: |
  MATCH (a:Asset) WHERE a.criticality_score IS NOT NULL
  RETURN count(a) AS count
```

Required mappings:

- `ci_id -> id`.
- `ci_name -> name`.
- `criticality_level -> criticality_score` via `cmdb_criticality_to_float`.

Optional mappings:

- `monitoring_status -> monitoring_active` via `yes_no_to_bool`.
- `owner_team -> owner`.
- `data_classification -> data_class`.

Connection:

- REST API style connection.
- `base_url` required.
- `auth_type` allowlist should include `api_key`, `oauth2`, and `basic`; embedded spec uses `api_key`.
- `api_key_env_var` required when `auth_type: api_key`.
- Missing secret env vars should fail health check or connector construction with a clear error, but unit tests should mock env access.

Semantic registry:

- `semantic_registry_concept: critical_assets`.

Validation query:

- Optional.
- Should run only after node ingestion and only if graph execution is available.
- Query text must not be interpolated with secrets or user-controlled values.

## 5. Identity Profile Spec

Normative embedded YAML:

```yaml
profile_type: IdentityConnectorProfile
tier: 1
cadence: hourly
entity_type_produced: User
connection:
  source_type: ldap
  host: <LDAP_HOST>
  port: 636
  bind_dn_env_var: LDAP_BIND_DN
  bind_pw_env_var: LDAP_BIND_PW
  base_dn: <BASE_DN>
entity_mappings:
  - source_field: sAMAccountName
    target_property: id
    required: true
  - source_field: displayName
    target_property: name
    required: true
  - source_field: department
    target_property: department
    required: true
  - source_field: title
    target_property: title
    required: false
  - source_field: manager
    target_property: manager
    transformer: dn_to_username
    required: false
  - source_field: memberOf
    target_property: groups
    transformer: dn_list_to_names
    required: false
semantic_registry_concept: identity_context
```

Required mappings:

- `sAMAccountName -> id`.
- `displayName -> name`.
- `department -> department`.

Optional mappings:

- `title -> title`.
- `manager -> manager` via `dn_to_username`.
- `memberOf -> groups` via `dn_list_to_names`.

Connection:

- `source_type` allowlist should include `ldap`, `ad`, `okta`, and `hr_api`.
- Embedded LDAP schema requires `host`, `port`, `bind_dn_env_var`, `bind_pw_env_var`, and `base_dn`.
- Hourly cadence.
- No live LDAP calls in tests.

Semantic registry:

- `semantic_registry_concept: identity_context`.

## 6. What Does NOT Change

- Existing Sentinel and Splunk connectors remain unchanged (`ci_platform/connectors/sentinel.py:48-56`; `ci_platform/connectors/splunk.py:34-40`).
- `SourceConnectorProtocol` should remain unchanged for the first implementation unless adapter tests prove entity profile adapters cannot work (`ci_platform/connectors/base.py:5-11`).
- `OnboardingPipeline` and `LoadManifest` should remain unchanged for the first implementation unless a later adapter integration prompt explicitly needs it (`ci_platform/onboarding/pipeline.py:61-66`; `ci_platform/onboarding/pipeline.py:83-100`).
- `AGEClient` public API remains unchanged (`ci_platform/graph/age_client.py:98-110`; `ci_platform/graph/age_client.py:350-363`).
- No external repo changes.
- No SAML / CA-P2-01 implementation (`ci_platform/auth/saml.py:12-39`).
- No live LDAP or CMDB calls in tests.

## 7. Integration Points

Production files for future implementation:

- `ci_platform/connectors/profiles.py` (new): profile dataclasses, validation, and profile-backed adapter. In scope because existing connector abstractions live under `ci_platform/connectors` and `SourceConnectorProtocol` is there (`ci_platform/connectors/base.py:5-11`).
- `ci_platform/connectors/transformers.py` (new): named transformer registry. In scope because current transformation is ad hoc in connectors/pipeline mappings, not centralized (`ci_platform/connectors/sentinel.py:159-170`; `ci_platform/connectors/splunk.py:138-148`; `ci_platform/onboarding/pipeline.py:13-28`).
- Optional `ci_platform/connectors/profile_loader.py` (new): separate YAML loading from profile dataclasses if needed for readability. YAML support is absent today (`pyproject.toml:10-13` and no repo `yaml` usage).
- Optional future `ci_platform/onboarding/entity_profile_pipeline.py` (new, later prompt only): bridge profile-mapped Asset/User nodes into `LoadManifest` if a standalone entity ingestion path is needed. In scope only because current `LoadManifest` is the closest existing ingestion-shaped structure (`ci_platform/onboarding/pipeline.py:61-66`; `ci_platform/onboarding/pipeline.py:310-399`).

Test and fixture files for future implementation:

- `tests/test_enterprise_connector_profiles.py` or `tests/test_profile_loader.py`: validation and loader tests.
- `tests/test_connector_transformers.py`: transformer registry tests.
- `tests/fixtures/cmdb_profile.yaml`: embedded CMDB schema fixture.
- `tests/fixtures/identity_profile.yaml`: embedded Identity schema fixture.
- `tests/fixtures/cmdb_records.json`: offline CMDB records.
- `tests/fixtures/identity_records.json`: offline LDAP/identity records.

Dependency/config files:

- `pyproject.toml` only if implementation approval explicitly allows adding PyYAML. Current dependencies do not include YAML support (`pyproject.toml:10-13`).

## 8. Risks and Mitigations

- Malformed YAML: use `yaml.safe_load`, catch parser exceptions, and return a clear profile-load error.
- Empty YAML: reject `None` or non-mapping top-level values.
- Unknown `profile_type`: validate against `CMDBConnectorProfile` and `IdentityConnectorProfile`.
- Unknown transformer name: validate during profile load, before mapping records.
- Required source field missing: fail record mapping with a clear message naming `source_field` and `target_property`.
- Secret/env var missing: profile validation should check schema shape; runtime connector health should report missing env var without attempting network.
- Live network dependency in tests: inject fetch providers and mock `httpx`/LDAP clients; do not contact CMDB/LDAP.
- Validation query unsupported by current ingester: treat as future integration because no `GraphIngester` exists today.
- Schema drift between YAML and node properties: tests must assert exact mapped Asset/User node dictionaries.
- Over-broad dependency addition: add only PyYAML if approved; no LDAP client dependency is needed for offline tests.
- LDAP/SAML scope creep: Identity profile connection config is not SAML auth; `ci_platform/auth/saml.py` remains out of scope (`ci_platform/auth/saml.py:12-39`).

## 9. Test Plan

Future tests:

- `test_profile_loader_validates_required_top_level_fields`: missing each required top-level key returns a clear validation error.
- `test_profile_loader_rejects_missing_entity_mappings`: empty/missing `entity_mappings` is rejected.
- `test_profile_loader_rejects_unknown_profile_type`: unknown `profile_type` is rejected.
- `test_transformer_registry_resolves_known_transformers`: all four embedded-spec transformer names resolve.
- `test_transformer_registry_rejects_unknown_transformer`: unknown transformer fails at load/validation time.
- `test_cmdb_profile_maps_asset_node_properties`: offline CMDB record maps to an Asset node dict with `id`, `name`, `criticality_score`, and optional properties.
- `test_identity_profile_maps_user_node_properties`: offline identity record maps to a User node dict with transformed `manager` and `groups`.
- `test_validation_query_runs_after_ingestion_when_supported`: with a fake graph executor, validation query runs after fake ingestion.
- `test_empty_yaml_returns_clear_error`: empty file or YAML null returns a helpful error.
- `test_yaml_to_profile_adapter_to_node_dicts_round_trip`: YAML profile plus fixture records produce expected manifest-compatible node dictionaries. This intentionally avoids implying nonexistent `SourceNode` classes because the repo currently exposes `LoadManifest.nodes: List[Dict]` (`ci_platform/onboarding/pipeline.py:61-66`).
- `test_connection_failure_handled_gracefully_with_mock`: mocked fetch failure returns a connector health/error result without live network.

All tests must be offline and mock CMDB/LDAP connections.

## 10. Files to Modify in Future Implementation

Production files:

- `ci_platform/connectors/profiles.py` (new): profile schema, validation, mapping, adapter. In scope from connector package evidence (`ci_platform/connectors/base.py:5-11`).
- `ci_platform/connectors/transformers.py` (new): transformer registry. In scope from missing generic transformer registry and existing ad hoc mapping evidence (`ci_platform/onboarding/pipeline.py:13-28`; `ci_platform/connectors/sentinel.py:159-170`; `ci_platform/connectors/splunk.py:138-148`).
- `ci_platform/connectors/profile_loader.py` (new, optional): YAML loader if separated from profiles.
- `ci_platform/onboarding/entity_profile_pipeline.py` (new, optional later prompt): only if adapter-to-manifest ingestion is implemented; current `LoadManifest` lines prove the closest architecture (`ci_platform/onboarding/pipeline.py:61-66`).

Test files:

- `tests/test_enterprise_connector_profiles.py` or `tests/test_profile_loader.py`.
- `tests/test_connector_transformers.py`.

Fixture files:

- `tests/fixtures/cmdb_profile.yaml`.
- `tests/fixtures/identity_profile.yaml`.
- `tests/fixtures/cmdb_records.json`.
- `tests/fixtures/identity_records.json`.

Dependency/config files:

- `pyproject.toml` only if PyYAML is approved for implementation. Current dependencies omit YAML (`pyproject.toml:10-13`).

Forbidden files/repos:

- Existing connector source unless extending exports is explicitly approved.
- `ci_platform/auth/**` and SAML code.
- External repos.
- Live secrets or environment-specific config.
- Tests that call live LDAP/CMDB.

## 11. Future Implementation Sequence

1. Prompt 1: implement schema dataclasses, transformer registry, ProfileLoader, and offline unit tests. Include PyYAML dependency only if explicitly approved.
2. Prompt 2: implement CMDB profile adapter behavior and fixtures/tests using mocked records.
3. Prompt 3: implement Identity profile adapter behavior and fixtures/tests using mocked records.
4. Prompt 4: GPT-5.5 line-by-line plus architecture review.
5. Prompt 5: targeted fixer only if P1/P2 findings remain.

No SAML implementation.

## 12. Validation Commands for Future Implementation

Targeted loader/transformer tests:

```powershell
cd "C:\Users\baner\CopyFolder\IoT_thoughts\python-projects\kaggle_experiments\claude_projects\ci-platform"
python -m pytest tests\test_enterprise_connector_profiles.py tests\test_connector_transformers.py -v --timeout=120
```

Targeted connector adapter tests:

```powershell
cd "C:\Users\baner\CopyFolder\IoT_thoughts\python-projects\kaggle_experiments\claude_projects\ci-platform"
python -m pytest tests -q --timeout=120 -k "profile_loader or connector_profile or transformer or cmdb or identity"
```

Full ci-platform regression:

```powershell
cd "C:\Users\baner\CopyFolder\IoT_thoughts\python-projects\kaggle_experiments\claude_projects\ci-platform"
python -m pytest tests/ -q --timeout=120
```

Do not hardcode expected pass counts.

## 13. Reading Log

- `CLAUDE.md:1-80`: grounding contract, public API cautions, no git rule.
- `ci_platform/connectors/base.py:1-11`: current connector protocol.
- `ci_platform/connectors/sentinel.py:1-192`: Sentinel config, fetch/write/health, mapping.
- `ci_platform/connectors/splunk.py:1-157`: Splunk config, fetch/write/health, mapping.
- `ci_platform/connectors/__init__.py:1`: empty connector package initializer; no registry.
- `ci_platform/onboarding/pipeline.py:1-542`: pipeline dataclasses, extract/normalize/redact/resolve/load/compute stages.
- `ci_platform/graph/age_client.py:90-110,350-365,580-720`: graph client lifecycle/query APIs and graph write examples.
- `ci_platform/graph/age_graph_store.py:1-180`: graph-store adapter, not a generic ingester.
- `ci_platform/entity_resolution/resolver.py:1-75,88-100`: identifier/entity structures and normalization.
- `ci_platform/redaction/pii_redactor.py:1-80`: redaction structures and pattern transforms; not mapping transformer registry.
- `ci_platform/auth/saml.py:1-40`: SAML/auth boundary.
- `pyproject.toml:1-49`: dependencies, optional graph dependency, mypy config.
- `tests/test_onboarding_pipeline.py:1-212`: offline pipeline test style.
- `tests/test_sentinel.py:1-166`: mocked Sentinel connector tests.
- `tests/test_splunk.py:1-126`: mocked Splunk connector tests.

## Prompt Verification Pass

- All referenced paths exist or are marked proposed new files.
- `SourceConnectorProtocol`, `LoadManifest`, and `OnboardingPipeline` evidence is cited.
- `SourceNode`, `SourceEdge`, and `GraphIngester` were searched for and are marked absent; the plan is classified SCOPE_REPAIR_NEEDED.
- YAML dependency state is verified from repo search and `pyproject.toml`.
- Embedded CMDB and Identity schemas are used as normative specs.
- No external repo work is included.
- CA-P2-01 / SAML is explicitly out of scope.
- Tests are fully offline and mock LDAP/CMDB.
- Dependency changes are proposed only because current YAML support is absent.
- The plan has enough detail for later implementation prompts.
