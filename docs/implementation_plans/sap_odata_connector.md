# SAP S/4HANA OData Connector Plan

## 1. Executive Summary

Current state: ci-platform has an alert-oriented `SourceConnectorProtocol` with `fetch_alerts`, `write_disposition`, and `health_check`, so SAP process/procurement reads should not be forced into that protocol (`ci_platform/connectors/base.py:5-11`). The closest non-alert precedent is the Celonis connector: it keeps a connector-local config/source-selection layer, fixture fallback, REST via `httpx`, and a manifest builder that returns `nodes`, `relationships`, `entity_map`, and `stats` without directly writing to AGE (`ci_platform/connectors/celonis.py:64-83`, `ci_platform/connectors/celonis.py:299-338`, `ci_platform/connectors/celonis.py:479-499`). No SAP connector file exists in `ci_platform/connectors/`; `ci_platform/connectors/` currently contains `base.py`, `celonis.py`, `profiles.py`, `sentinel.py`, `sentinel_writeback.py`, `splunk.py`, and transformer/profile support discovered during this plan.

Target state: add a future `SAPODataConnector` in `ci_platform/connectors/sap.py` that reads SAP S/4HANA OData V2 purchase orders, supplier invoices, and suppliers/business partners, converts fixture or REST data into a LoadManifest-compatible dict, and supports a transport-only OData PATCH write-back flow. The manifest target follows the current `LoadManifest` fields (`nodes`, `relationships`, `entity_map`, `stats`) from `ci_platform/onboarding/pipeline.py:61-67` and the Celonis manifest dict shape from `ci_platform/connectors/celonis.py:165-175`.

Classification: `PLAN_READY`.

This is plan-only: no source, test, dependency, or config files were changed. Tests for future implementation must be offline and must not make live SAP calls. SAP write-back safety, conservation checks, approval policy, and risk gating are caller responsibilities; the connector only validates transport payload shape and allowed demo fields, mirroring the repository split where write-back helpers call connector transports and audit/decision ledgers are separate concerns (`ci_platform/connectors/sentinel_writeback.py:23-71`, `ci_platform/audit/evidence_ledger.py:116-185`).

## 2. Current Architecture

G15 Celonis pattern:

- Configuration is a dataclass with explicit env parsing and boolean fallback parsing (`CelonisConfig.from_env`) (`ci_platform/connectors/celonis.py:64-83`, `ci_platform/connectors/celonis.py:564-572`).
- Source selection is instance-local: configured live path first, fixture fallback when enabled and path exists, otherwise `not_configured` (`ci_platform/connectors/celonis.py:286-312`, `ci_platform/connectors/celonis.py:501-515`).
- `health_check()` reports `degraded` for fixture, `ok` for REST or pycelonis availability, and `not_configured` when no source is available (`ci_platform/connectors/celonis.py:313-338`).
- REST uses `httpx.AsyncClient`, bearer auth, non-2xx handling, and JSON parse validation (`ci_platform/connectors/celonis.py:534-556`).
- Fixture fallback loads deterministic JSON through `ProcessFixture.from_json`, validates required keys, IDs, and references, and never imports pycelonis (`ci_platform/connectors/celonis.py:86-163`, `ci_platform/connectors/celonis.py:558-561`).
- Manifest conversion reuses `ProcessManifestBuilder` and returns a dict containing `nodes`, `relationships`, `entity_map`, and `stats` (`ci_platform/connectors/celonis.py:165-175`, `ci_platform/connectors/celonis.py:479-499`).

Connector protocol boundary:

- `SourceConnectorProtocol` is alert-oriented because it requires `fetch_alerts`, `write_disposition`, and `health_check` (`ci_platform/connectors/base.py:5-11`).
- `OnboardingPipeline` is also alert-ingestion oriented: it accepts a `SourceConnectorProtocol`, calls `connector.fetch_alerts`, and builds `Alert`, `AlertType`, `User`, and `Asset` nodes (`ci_platform/onboarding/pipeline.py:83-92`, `ci_platform/onboarding/pipeline.py:176-189`, `ci_platform/onboarding/pipeline.py:327-375`).
- Therefore SAP should be a standalone adapter/client with `to_load_manifest()` rather than inheriting `SourceConnectorProtocol`.

Existing connector examples:

- Sentinel inherits `SourceConnectorProtocol`, fetches alerts with `httpx.AsyncClient`, and patches alert comments through `write_disposition` (`ci_platform/connectors/sentinel.py:36-48`, `ci_platform/connectors/sentinel.py:56-90`).
- Splunk inherits `SourceConnectorProtocol`, fetches alerts through job/result REST calls, and writes dispositions to HEC (`ci_platform/connectors/splunk.py:21-34`, `ci_platform/connectors/splunk.py:40-99`).
- Sentinel write-back is a wrapper around `write_disposition`; it formats decision/provenance/campaign comments but does not own graph/audit policy (`ci_platform/connectors/sentinel_writeback.py:23-71`, `ci_platform/connectors/sentinel_writeback.py:100-168`).

Manifest and graph boundaries:

- `LoadManifest` is a dataclass with `nodes`, `relationships`, `entity_map`, and `stats` (`ci_platform/onboarding/pipeline.py:61-67`).
- The onboarding loader internally uses dict nodes with `id` and `type`, and relationships with `type` plus endpoint keys (`from`/`to` in alert onboarding) (`ci_platform/onboarding/pipeline.py:321-362`, `ci_platform/onboarding/pipeline.py:381-389`).
- Celonis emits manifest-compatible dicts with `source`, `target`, and `type` relationship keys, so SAP can follow the Celonis standalone-manifest convention instead of the alert pipeline internals (`ci_platform/connectors/celonis.py:189-227`).
- AGE writes should not be performed by the SAP connector: AGE has a central `run_query` choke point and graph write methods live in graph store/client modules, not connector modules (`ci_platform/graph/age_client.py:72-84`, `ci_platform/graph/age_graph_store.py:65-98`).

Dependency and test patterns:

- `httpx>=0.25.0` is already a runtime dependency (`pyproject.toml:10`).
- Celonis connector tests are offline and fixture/mocked: they use fixture paths, monkeypatch env vars, fake pycelonis via `sys.modules`, and monkeypatch `httpx.AsyncClient` (`tests/test_celonis_connector.py:20-28`, `tests/test_celonis_connector.py:245-306`, `tests/test_celonis_connector.py:309-345`).
- Sentinel and Splunk tests mock `httpx.AsyncClient` rather than making live calls (`tests/test_sentinel.py:70-115`, `tests/test_splunk.py:54-88`, `tests/test_splunk.py:90-126`).
- Evidence/audit support exists as a separate append-only ledger with `append()` and `append_outcome()` APIs (`ci_platform/audit/evidence_ledger.py:116-225`), and decision graph linking exists in `AGEGraphStore` (`ci_platform/graph/age_graph_store.py:260-305`); SAP write-back should not bypass these abstractions.

SAP connector status: no existing SAP connector implementation was found in `ci_platform/connectors/` or `tests/` during local search for SAP/OData names. Future file paths below are proposed new files unless otherwise marked.

## 3. SAP OData V2 API Design

Planned read endpoints, without live calls in unit tests:

- Purchase Orders: `GET /sap/opu/odata/sap/API_PURCHASEORDER_PROCESS_SRV/A_PurchaseOrder`.
- Supplier Invoices: `GET /sap/opu/odata/sap/API_SUPPLIERINVOICE_PROCESS_SRV/A_SupplierInvoice`.
- Business Partners / Suppliers: `GET /sap/opu/odata/sap/API_BUSINESS_PARTNER/A_BusinessPartner`.

Planned write endpoint:

- Purchase Order updates: `PATCH /sap/opu/odata/sap/API_PURCHASEORDER_PROCESS_SRV/A_PurchaseOrder('{po_id}')`.
- Supplier Invoice write-back is future/optional and should stay disabled unless an implementation prompt explicitly approves invoice fields.
- Business Partner is read-only in this connector.

Auth design:

- Sandbox/demo API key: send configured API key header.
- Production bearer/OAuth token: send `Authorization: Bearer <token>`.
- Basic auth is not included in the first SAP implementation scope because the requested SAP modes are API key and OAuth/bearer token. Existing connectors show mixed auth styles: Sentinel obtains bearer tokens (`ci_platform/connectors/sentinel.py:126-150`), Splunk search uses username/password auth while HEC uses a token (`ci_platform/connectors/splunk.py:40-52`, `ci_platform/connectors/splunk.py:92-99`), and Celonis REST uses a bearer token (`ci_platform/connectors/celonis.py:534-556`). If SAP Basic auth is later approved, add explicit config fields and mocked tests rather than inferring it from existing connectors.
- No secrets in code or fixtures.

Sandbox/manual validation:

- SAP Business Accelerator Hub or an SAP sandbox may be used only in a future manual validation appendix.
- CI/unit tests must stay fixture-backed or mocked, matching existing connector tests (`tests/test_celonis_connector.py:309-345`, `tests/test_sentinel.py:70-115`).

## 4. SAPConfig Design

Future dataclass:

```python
@dataclass
class SAPConfig:
    base_url: str | None = None
    api_key: str | None = None
    bearer_token: str | None = None
    sap_client: str | None = None
    use_fixture_fallback: bool = True
    write_demo_mode: bool = True
    fixture_dir: str | None = None
```

`from_env()` should read:

- `SAP_BASE_URL`
- `SAP_API_KEY`
- `SAP_BEARER_TOKEN` or `SAP_OAUTH_TOKEN`
- `SAP_CLIENT`
- `SAP_USE_FIXTURE_FALLBACK`
- `SAP_WRITE_DEMO_MODE`
- `SAP_FIXTURE_DIR`

Missing env vars should produce `None` values rather than crashing, following Celonis missing-env behavior (`ci_platform/connectors/celonis.py:64-83`). Boolean parsing should accept explicit truthy/falsy values and reject ambiguous values, following the Celonis `_parse_bool_env` pattern (`ci_platform/connectors/celonis.py:564-572`).

## 5. SAPODataConnector Design

Do not inherit `SourceConnectorProtocol`; the protocol is alert-oriented (`ci_platform/connectors/base.py:5-11`). Proposed methods:

- `connect() -> None`
- `health_check() -> dict`
- `fetch_purchase_orders() -> list[dict]`
- `fetch_invoices() -> list[dict]`
- `fetch_suppliers() -> list[dict]`
- `to_load_manifest() -> dict`
- `write_update(entity_type, entity_id, payload, decision_id=None) -> dict`

Source selection:

- Prefer configured REST OData when `base_url` and either `api_key` or `bearer_token` are configured.
- Use fixture fallback only when `use_fixture_fallback=True` and fixture files exist, mirroring Celonis `_can_use_fixture()` semantics (`ci_platform/connectors/celonis.py:501-515`).
- Return `not_configured` when neither REST nor fixture is available, matching Celonis health state behavior (`ci_platform/connectors/celonis.py:313-338`).

REST/httpx:

- Use `httpx.AsyncClient`; do not add `requests` or `urllib`.
- Reuse the repository's mocked async client test style (`tests/test_celonis_connector.py:309-345`, `tests/test_sentinel.py:70-115`).
- Parse fixture-shaped or normalized SAP response dicts in tests; live SAP response adaptation belongs to manual/sandbox validation.

## 6. SAP Read Manifest Design

Node types:

- `PurchaseOrder`: `id`, `po_number`, `supplier`, `amount`, `status`, `plant`, optional material/schema/process fields when fixtures include them.
- `SupplierInvoice`: `id`, `invoice_number`, `supplier`, `amount`, `match_status`.
- `BusinessPartner`: `id`, `name`, `supplier_type`, `plant_codes`.

Edges:

- `PurchaseOrder -[INVOICED_BY]-> SupplierInvoice`.
- `PurchaseOrder -[ORDERED_FROM]-> BusinessPartner`.

Manifest shape:

- Return a dict with `nodes`, `relationships`, `entity_map`, and `stats`, matching `LoadManifest` field names (`ci_platform/onboarding/pipeline.py:61-67`) and Celonis standalone manifest output (`ci_platform/connectors/celonis.py:165-175`).
- Nodes should include `id` and PascalCase `type`; Celonis uses PascalCase process node types in its constants and node builder (`ci_platform/connectors/celonis.py:20-27`, `ci_platform/connectors/celonis.py:177-187`).
- Relationships should include `source`, `target`, and `type` to match the Celonis standalone manifest convention (`ci_platform/connectors/celonis.py:189-227`).
- `stats` should include deterministic node/relationship counts and type counts, following Celonis stats construction (`ci_platform/connectors/celonis.py:229-251`).

## 7. Write-Back Design: Autonomous Loop Transport

`write_update(entity_type, entity_id, payload, decision_id=None)` should be a transport method only.

Allowed writes:

- `PurchaseOrder` in the first implementation.
- `SupplierInvoice` only if a later implementation prompt explicitly approves invoice write fields.

Read-only:

- `BusinessPartner` writes must be rejected.

Payload validation:

- `payload` must be a non-empty mapping.
- Allowed demo fields should be allowlisted, such as `matching_parameter`, `approval_threshold`, `routing_rule`, and `hold_status`.
- Reject unknown entity types, BusinessPartner writes, empty payloads, and unknown payload keys before any transport call.

OData V2 CSRF flow:

1. `GET` the service root with `X-CSRF-Token: Fetch`.
2. Capture the `X-CSRF-Token` response header.
3. Capture session cookies.
4. `PATCH` the entity endpoint with the token, cookies, `Content-Type: application/json`, and payload.
5. On first `403`, refresh token once and retry the PATCH once.
6. A second `403` raises `ConnectionError`.

Token state:

- Token and cookies must be connector-instance-local, not module global.
- Avoid time-dependent token TTL behavior unless a future implementation injects a clock for deterministic tests.

Demo mode:

- If `SAP_WRITE_DEMO_MODE` or `config.write_demo_mode` is true, do not perform live write-back.
- Return a cached response from `tests/fixtures/sap/write_response_cache.json`.
- Still validate entity type and payload before returning cached success/failure.

Audit/manifest relationship:

- If future callers want `UPDATED_BY` or `DECIDED_ON` relationships, route that through existing graph/audit abstractions rather than the SAP connector. The repo already separates connector writeback (`SentinelWriteBack`) from evidence ledger and graph decision-link APIs (`ci_platform/connectors/sentinel_writeback.py:23-71`, `ci_platform/audit/evidence_ledger.py:116-225`, `ci_platform/graph/age_graph_store.py:260-305`).
- Conservation and safety gates remain caller-owned.

## 8. Fixture Strategy

Future fixture files:

- `tests/fixtures/sap/purchase_orders.json`
- `tests/fixtures/sap/invoices.json`
- `tests/fixtures/sap/suppliers.json`
- `tests/fixtures/sap/write_response_cache.json`

Fixtures must be deterministic, contain no secrets or live SAP data, and include at least:

- one purchase order;
- one supplier invoice;
- one business partner/supplier;
- one PO-to-invoice relationship key;
- one PO-to-supplier relationship key;
- one cached write success response;
- one cached write rejection/error response if useful.

The fixture parser should mirror `ProcessFixture.from_json`: validate top-level mappings/lists, required fields, duplicate IDs, and references with clear errors (`ci_platform/connectors/celonis.py:86-163`).

## 9. What Does NOT Change

- Existing Sentinel, Splunk, and Celonis connectors remain unchanged (`ci_platform/connectors/sentinel.py:36-48`, `ci_platform/connectors/splunk.py:21-34`, `ci_platform/connectors/celonis.py:286-338`).
- `SourceConnectorProtocol` remains unchanged (`ci_platform/connectors/base.py:5-11`).
- `OnboardingPipeline` remains unchanged (`ci_platform/onboarding/pipeline.py:83-92`, `ci_platform/onboarding/pipeline.py:176-189`).
- `AGEClient` and graph store remain unchanged; SAP connector does not write AGE (`ci_platform/graph/age_client.py:72-84`, `ci_platform/graph/age_graph_store.py:65-98`).
- No SOC/SDK/S2P/GAE changes.
- No live SAP calls in tests.
- No dependency changes in this planning prompt; `httpx` already exists (`pyproject.toml:10`).
- No conservation/safety gate inside the connector.

## 10. Risks and Mitigations

- OData V2 CSRF token handling: test token fetch, cookie capture, PATCH headers, first-403 refresh, and second-403 failure with mocked `httpx`.
- Cookie/session handling: store token/cookies per connector instance and avoid global state.
- Accidental live writes: default `write_demo_mode=True`, require explicit config for live writes, and keep all unit tests mocked/fixture-backed.
- Secrets in code/fixtures: fixture scan tests should reject token/password/bearer-like content.
- SAP sandbox/API shape drift: implementation should normalize SAP responses behind small parser functions and keep live shape validation in manual sandbox tests.
- SAP service/entity-set naming drift: endpoint strings are planned constants; real shape must be manually validated before production use.
- Fixture/demo response overfitting: include malformed-response tests and at least one relation across PO/invoice/supplier.
- Connector protocol mismatch: do not inherit `SourceConnectorProtocol` because it is alert-oriented (`ci_platform/connectors/base.py:5-11`).
- Write-back safety boundary: caller must run conservation/safety gates; connector validates transport payload only.
- Idempotency / duplicate PATCH risk: future live mode should include caller-provided `decision_id` in response/audit metadata but should not retry beyond one CSRF-refresh retry.
- No audit/evidence integration yet: current evidence ledger and graph decision links are separate modules (`ci_platform/audit/evidence_ledger.py:116-225`, `ci_platform/graph/age_graph_store.py:260-305`).
- Malformed SAP responses: raise `ValueError` with endpoint/entity context.
- Numeric/currency parsing: normalize amounts deterministically and test string/number cases.
- Timezone/date fields: keep raw SAP date strings unless a future parser owns deterministic conversion.

## 11. Test Plan

Future tests, all offline and deterministic:

- `test_sap_config_from_env_reads_vars`
- `test_health_check_not_configured`
- `test_health_check_fixture_fallback`
- `test_fetch_purchase_orders_from_fixture`
- `test_fetch_invoices_from_fixture`
- `test_fetch_suppliers_from_fixture`
- `test_to_load_manifest_shape`
- `test_manifest_edges_purchase_order_to_invoice_and_supplier`
- `test_write_update_demo_mode_returns_cached_success`
- `test_write_update_rejects_business_partner`
- `test_write_update_rejects_empty_payload`
- `test_write_update_fetches_csrf_token_and_patches_mocked`
- `test_write_update_refreshes_token_once_on_403`
- `test_write_update_second_403_raises`
- `test_no_live_sap_calls_in_tests`
- `test_no_secrets_in_fixtures`

Mocking should follow existing `httpx.AsyncClient` patterns from connector tests (`tests/test_celonis_connector.py:309-345`, `tests/test_sentinel.py:70-115`, `tests/test_splunk.py:54-126`).

## 12. Files to Modify in Future Implementation

Production files:

- `ci_platform/connectors/sap.py` (proposed new): in scope because connector implementations live under `ci_platform/connectors/`, and the closest standalone manifest-producing connector is `ci_platform/connectors/celonis.py` (`ci_platform/connectors/celonis.py:1-6`, `ci_platform/connectors/celonis.py:286-338`).

Fixture files:

- `tests/fixtures/sap/purchase_orders.json`
- `tests/fixtures/sap/invoices.json`
- `tests/fixtures/sap/suppliers.json`
- `tests/fixtures/sap/write_response_cache.json`

Test files:

- `tests/test_sap_connector.py`, following existing connector test locations and mocked async style (`tests/test_celonis_connector.py:1-17`, `tests/test_sentinel.py:70-115`).

Dependency/config files:

- None expected because `httpx` is already in runtime dependencies (`pyproject.toml:10`).

Forbidden files/repos:

- `ci_platform/connectors/base.py`
- `ci_platform/connectors/sentinel.py`
- `ci_platform/connectors/splunk.py`
- `ci_platform/connectors/celonis.py` unless a future prompt explicitly requests shared refactoring
- `ci_platform/onboarding/**`
- `ci_platform/graph/**`
- `tests` outside `tests/test_sap_connector.py` and `tests/fixtures/sap/**`
- `requirements.txt`, `pyproject.toml`
- any SOC/SDK/S2P/GAE repo or file

## 13. Future Implementation Sequence

Prompt 1: implement SAP fixture parser + read manifest builder + offline read tests. No REST, no write-back.

Prompt 2: implement `SAPConfig`, connector source selection, fixture fallback, and mocked REST read tests using `httpx`.

Prompt 3: implement `write_update` demo mode, CSRF mocked flow, one-refresh retry, and write-back tests. Keep live write disabled in tests.

Prompt 4: GPT-5.5 line-by-line and architecture review.

This split mirrors the Celonis layering where fixture/manifest behavior and connector source selection are separable (`ci_platform/connectors/celonis.py:86-251`, `ci_platform/connectors/celonis.py:286-561`).

## 14. Validation Commands for Future Implementation

Targeted SAP tests:

```powershell
cd "C:\Users\baner\CopyFolder\IoT_thoughts\python-projects\kaggle_experiments\claude_projects\ci-platform"; python -m pytest tests/test_sap_connector.py -v --timeout=120
```

Connector subset:

```powershell
cd "C:\Users\baner\CopyFolder\IoT_thoughts\python-projects\kaggle_experiments\claude_projects\ci-platform"; python -m pytest tests/ -q --timeout=120 -k "sap or connector"
```

Full ci-platform tests:

```powershell
cd "C:\Users\baner\CopyFolder\IoT_thoughts\python-projects\kaggle_experiments\claude_projects\ci-platform"; python -m pytest tests/ -q --timeout=120
```

No expected pass counts should be hardcoded.

## 15. Manual Live Validation Appendix

Future-only manual validation, not CI:

- Required env vars: `SAP_BASE_URL`, one of `SAP_API_KEY` or `SAP_BEARER_TOKEN`/`SAP_OAUTH_TOKEN`, optional `SAP_CLIENT`, explicit `SAP_WRITE_DEMO_MODE=false` for a sandbox write smoke only.
- Manual read smoke should call configured sandbox endpoints and print counts only.
- Manual write smoke must target a demo/sandbox tenant, require caller-side safety/conservation approval, and log the `decision_id` and SAP response without secrets.
- Live SAP write-back must never be part of unit tests.

## 16. Reading Log

- `CLAUDE.md:5-10`, `CLAUDE.md:26-30`, `CLAUDE.md:40-46`, `CLAUDE.md:54-101`
- `ci_platform/connectors/base.py:5-11`
- `ci_platform/connectors/celonis.py:1-6`, `ci_platform/connectors/celonis.py:17-27`, `ci_platform/connectors/celonis.py:64-83`, `ci_platform/connectors/celonis.py:86-251`, `ci_platform/connectors/celonis.py:286-586`
- `ci_platform/connectors/profiles.py:1-10`, `ci_platform/connectors/profiles.py:23-60`, `ci_platform/connectors/profiles.py:63-128`, `ci_platform/connectors/profiles.py:131-294`
- `ci_platform/connectors/sentinel.py:6-8`, `ci_platform/connectors/sentinel.py:36-48`, `ci_platform/connectors/sentinel.py:56-122`, `ci_platform/connectors/sentinel.py:126-192`
- `ci_platform/connectors/splunk.py:6-8`, `ci_platform/connectors/splunk.py:21-34`, `ci_platform/connectors/splunk.py:40-130`, `ci_platform/connectors/splunk.py:134-157`
- `ci_platform/connectors/sentinel_writeback.py:1-168`
- `ci_platform/onboarding/pipeline.py:61-67`, `ci_platform/onboarding/pipeline.py:83-92`, `ci_platform/onboarding/pipeline.py:176-189`, `ci_platform/onboarding/pipeline.py:310-390`
- `ci_platform/graph/age_client.py:1-18`, `ci_platform/graph/age_client.py:49-84`, `ci_platform/graph/age_client.py:193-213`, `ci_platform/graph/age_client.py:350-359`
- `ci_platform/graph/age_graph_store.py:65-140`, `ci_platform/graph/age_graph_store.py:260-305`
- `ci_platform/audit/evidence_ledger.py:116-225`
- `pyproject.toml:10-12`
- `tests/test_celonis_connector.py:1-345`
- `tests/test_sentinel.py:1-166`
- `tests/test_splunk.py:1-126`
- `tests/test_sentinel_writeback.py:1-153`

Prompt verification:

- Referenced existing paths were read; proposed SAP paths are marked proposed new.
- G15 connector evidence is cited.
- `SourceConnectorProtocol` boundary is cited.
- `LoadManifest` target shape is cited.
- `httpx` availability is cited.
- CSRF write-back flow is documented.
- Demo mode prevents live writes in tests.
- Conservation/safety gate boundary is explicit.
- Tests are offline and deterministic.
- No source/test/dependency files were changed.
- No external repos were read.
