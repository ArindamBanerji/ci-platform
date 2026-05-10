# DataOps Graph Schema and Seed Plan

## 1. Executive Summary

Add a DataOps graph namespace to the same PostgreSQL + Apache AGE database used by SOC. DataOps must use the same `AGEClient` and graph database, but distinct labels and edge types:

- Node labels: `PipelineSystem`, `DataQualityAlert`
- Edge labels: `FEEDS`, `AFFECTS`, `CASCADES`

This work seeds graph data for a future DataOps Copilot. It must not modify SOC labels, SOC nodes, AGEClient, or any SOC seed script. Unit tests should verify schema and script safety without requiring live AGE/PostgreSQL. Live seeding remains manual.

## 2. Source Contracts from Prompt 0

### Repository Rules

`CLAUDE.md` requires source-grounded changes and verification after changes. It also identifies `AGEClient` as the stable graph infrastructure API and warns that changing it affects downstream consumers.

AGE/Cypher safety rules from `CLAUDE.md`:

- No `MERGE`; use `CREATE` or `MATCH + SET`.
- No raw AGE `$params` at the Cypher parser layer.
- No `SET n = {}`.
- No Cypher date/date-time helpers; use epoch integers.
- No array/map properties; serialize complex values as JSON strings.
- Do not use `count` as a return alias; use `cnt`.
- Do not import from `gen-ai-roi-demo-v4-v50`.

### AGEClient Contract

Prompt 0 proved the requested `graph/age_client.py` path does not exist. The actual file is:

```text
ci_platform/graph/age_client.py
```

Actual stable imports:

```python
from ci_platform.graph import AGEClient, get_graph_client
```

Constructor:

```python
AGEClient(dsn: Optional[str] = None, graph_name: Optional[str] = None)
```

Public query API:

```python
await client.run_query(query: str, parameters: Optional[dict] = None) -> list[dict]
```

The serializer requested as `_S()` does not exist as a module-level symbol in `ci-platform`. The actual serializer is:

```python
AGEClient.serialize_for_age(value)
```

Implementation should either use `run_query(..., parameters=...)` and let `AGEClient` serialize, or define a local alias in the seed script:

```python
_S = AGEClient.serialize_for_age
```

Tests should accept this local alias as the implementation of the `_S` requirement.

### Existing Seed Graph Pattern

Prompt 0 proved `scripts/seed_graph.py` does not exist in this repo. There is no SOC seed script to copy or modify.

Use the existing AGEClient write pattern instead:

- Guard/lookup with `MATCH`.
- Use `CREATE` after guard checks.
- For idempotent updates, use `MATCH + SET`, not `MERGE`.
- Keep all DataOps seed statements label-scoped.

### DataOps Seed JSON

Primary seed path exists:

```text
..\copilot-sdk\copilot_sdk\scoring\presets\dataops_seed.json
```

Fallback seed path exists:

```text
..\compounding-scorer\compounding_scorer\presets\dataops_seed.json
```

Seed shape:

- JSON top-level is a list.
- Exactly 20 events.
- Each row has `event_id`, `dataset`, `category`, `action_taken`, `is_correct`, `factors`.
- There is no `system` field.

Implementation must map seed `dataset` values deterministically to one of the 9 `PipelineSystem` rows.

## 3. Files to Create

```text
dataops/__init__.py
dataops/schema.py
scripts/seed_dataops_graph.py
tests/test_dataops_schema.py
```

Note: `pyproject.toml` currently packages `ci_platform*`, not root-level `dataops`. This plan follows the design request literally, but the implementation review should verify whether root-level `dataops` import is acceptable for tests and future packaging. Do not modify package config in this slice.

## 4. Forbidden Files

Do not modify:

```text
scripts/seed_graph.py
graph/age_client.py
graph/**
ci_platform/graph/age_client.py
graph-attention-engine-v50/**
gen-ai-roi-demo-v4-v50/**
s2p-copilot/**
copilot-sdk/**
package/config files
```

`scripts/seed_graph.py` and `graph/age_client.py` are absent, but they remain forbidden concepts: do not create SOC seed code and do not create a second graph client path.

## 5. Schema Contract

`dataops/schema.py` must define these constants:

```python
PIPELINE_SYSTEM = "PipelineSystem"
DATA_QUALITY_ALERT = "DataQualityAlert"
FEEDS = "FEEDS"
AFFECTS = "AFFECTS"
CASCADES = "CASCADES"
```

`CATEGORIES` must be exactly:

```python
(
    "pipeline_failure",
    "schema_change",
    "volume_anomaly",
    "quality_anomaly",
    "freshness_violation",
    "transform_drift",
)
```

`ACTIONS` must be exactly:

```python
(
    "auto_approve",
    "investigate",
    "escalate_to_owner",
    "pause_downstream",
    "refer_to_specialist",
)
```

`SYSTEMS` must contain exactly 9 systems:

```text
warehouse_etl
payment_gateway
crm_sync
hr_feed
billing_api
iot_sensors
marketing_db
erp_export
inventory_feed
```

Each system row must include:

- `name`
- `display_name`
- `sla_minutes`
- `business_criticality`
- `source_reliability`
- `owner`

The seed script may add default runtime properties when creating nodes:

- `status`
- `last_run`
- `description`

`SYSTEM_NAMES` should be derived from `SYSTEMS`, not duplicated manually.

`FEEDS_EDGES` must contain exactly 9 directed edges:

```text
billing_api -> warehouse_etl
billing_api -> payment_gateway
crm_sync -> warehouse_etl
crm_sync -> marketing_db
erp_export -> warehouse_etl
erp_export -> billing_api
inventory_feed -> warehouse_etl
iot_sensors -> inventory_feed
warehouse_etl -> marketing_db
```

No `FEEDS` edge may be self-referential. Every edge endpoint must exist in `SYSTEM_NAMES`.

Dataset-to-system mapping must cover all 20 seed datasets. Recommended deterministic mapping:

```python
DATASET_SYSTEM_MAP = {
    "orders_daily": "warehouse_etl",
    "payments_hourly": "payment_gateway",
    "customer_events": "crm_sync",
    "risk_features": "warehouse_etl",
    "product_catalog": "erp_export",
    "revenue_mart": "billing_api",
    "identity_dim": "hr_feed",
    "traffic_counts": "iot_sensors",
    "partner_uploads": "crm_sync",
    "settlement_batches": "payment_gateway",
    "inventory_snapshots": "inventory_feed",
    "lead_scoring": "marketing_db",
    "policy_scores": "hr_feed",
    "supplier_risk": "erp_export",
    "user_activity": "crm_sync",
    "search_index": "marketing_db",
    "billing_exports": "billing_api",
    "feature_store": "warehouse_etl",
    "campaign_attribution": "marketing_db",
    "customer_360": "crm_sync",
}
```

## 6. Seed Script Contract

Create `scripts/seed_dataops_graph.py`.

The script must:

- Import `AGEClient` from `ci_platform.graph`.
- Define `_S = AGEClient.serialize_for_age` or otherwise use `AGEClient.serialize_for_age` for direct string literal interpolation.
- Support `--dry-run`.
- Support `--force`.
- Check whether any `PipelineSystem` nodes already exist; skip unless `--force`.
- If `--force`, delete only DataOps labels and edges:
  - Labels: `PipelineSystem`, `DataQualityAlert`
  - Edges: `FEEDS`, `AFFECTS`, `CASCADES`
- Never delete or match-destructively against SOC labels such as `Alert`, `User`, `Asset`, `Entity`, `Decision`, `ThreatIndicator`, `AttackPattern`, `Campaign`, or `Location`.
- Create 9 `PipelineSystem` nodes.
- Create 9 `FEEDS` edges.
- Read `dataops_seed.json` from the adjacent `copilot-sdk` path.
- Use `compounding-scorer` fallback only when the primary path is missing.
- Create 20 `DataQualityAlert` nodes.
- Create 20 `AFFECTS` edges from alert to mapped system.
- Print:

```text
Seeded: 9 systems, 9 FEEDS, 20 alerts, 20 AFFECTS
```

### Derived Alert Fields

Severity from `impact_scope`:

```python
if impact_scope > 0.7:
    severity = "high"
elif impact_scope > 0.4:
    severity = "medium"
else:
    severity = "low"
```

Recurrence count from `recurrence_frequency`:

```python
if recurrence_frequency >= 0.8:
    recurrence_count = 12
elif recurrence_frequency >= 0.5:
    recurrence_count = 3
else:
    recurrence_count = 0
```

Required `DataQualityAlert` scalar properties:

- `alert_id`
- `system_name`
- `dataset`
- `category`
- `severity`
- `detected_at`
- `detected_at_epoch`
- `recurrence_count`
- `resolved`
- `action_taken`
- `is_correct`
- `impact_scope`
- `source_reliability`
- `recurrence_frequency`
- `downstream_urgency`
- `data_freshness`
- `business_criticality`

Complex factor data may additionally be stored as `factors_json`, serialized with `json.dumps(..., sort_keys=True)`.

### CASCADES

Do not seed `CASCADES` edges in this first implementation unless a deterministic cascade rule is explicitly added and covered by tests. Keep `CASCADES` as a schema constant for future DataOps backend prompts.

## 7. AGE/Cypher Safety Contract

Seed script Cypher must obey:

- Use `_S()` or `AGEClient.serialize_for_age()` for direct string literals.
- Prefer `run_query(..., parameters=...)` for values.
- No `MERGE`.
- No `ON CREATE SET`.
- No `ON MATCH SET`.
- No `SET n = {}`.
- No `AS count`; use `AS cnt`.
- No `date()`, `datetime()`, or `duration()`.
- No array/map properties; JSON-serialize maps/lists.
- Delete queries must be scoped to DataOps labels/relationships only.

Recommended deletion sequence for `--force`:

```cypher
MATCH (:DataQualityAlert)-[r:AFFECTS]->(:PipelineSystem) DELETE r
MATCH (:PipelineSystem)-[r:FEEDS]->(:PipelineSystem) DELETE r
MATCH (:PipelineSystem)-[r:CASCADES]->(:PipelineSystem) DELETE r
MATCH (a:DataQualityAlert) DELETE a
MATCH (s:PipelineSystem) DELETE s
```

Recommended existing-data guard:

```cypher
MATCH (s:PipelineSystem) RETURN count(s) AS cnt
```

## 8. Test Plan

Create `tests/test_dataops_schema.py`. These are unit/source-inspection tests only and must not require live AGE/PostgreSQL.

Required tests:

- Schema constants exist and match exact labels.
- Categories match the DataOps preset categories.
- Actions match the DataOps preset actions.
- DataOps constants do not include SOC node labels.
- `SYSTEMS` has exactly 9 rows.
- Each system has required fields.
- `SYSTEM_NAMES` is derived from `SYSTEMS`.
- `FEEDS_EDGES` has exactly 9 rows.
- Every `FEEDS` endpoint is a known system.
- No `FEEDS` self-edge.
- `DATASET_SYSTEM_MAP` covers every dataset in the adjacent seed JSON.
- `scripts/seed_dataops_graph.py` exists.
- Primary adjacent seed path is readable if the adjacent repo exists.
- Seed data has 20 rows and valid categories/actions.
- Seed script source imports/uses `AGEClient`.
- Seed script source uses `_S` or `serialize_for_age`.
- Seed script source has no forbidden patterns:
  - `MERGE`
  - `ON CREATE`
  - `ON MATCH`
  - `SET n =`
  - `AS count`
  - `date(`
  - `datetime(`
  - `duration(`
- Source inspection verifies delete/destructive queries mention only DataOps labels and edges, not SOC labels.

## 9. Validation Commands

Run from `ci-platform`:

```powershell
python -m pytest tests/test_dataops_schema.py -v --timeout=60
python -m pytest tests/ -q --timeout=120
python -c "from dataops.schema import PIPELINE_SYSTEM, DATA_QUALITY_ALERT, FEEDS, AFFECTS; print('DataOps schema OK')"
```

Optional manual dry-run:

```powershell
python scripts/seed_dataops_graph.py --dry-run
```

Do not run live seeding unless AGE/PostgreSQL is confirmed running by the user.

## 10. Open Risks / Decisions

- The design asks for root-level `dataops`, but `pyproject.toml` packages only `ci_platform*`. Implementation should follow the prompt unless a later packaging prompt changes this.
- The requested `graph/age_client.py` and `scripts/seed_graph.py` paths are absent. Use `ci_platform/graph/age_client.py`; do not create a root `graph` package.
- `_S()` is not present in `AGEClient`; create a local `_S` alias in the seed script if required by tests.
- The DataOps seed has `dataset`, not `system`; the deterministic mapping in this plan is part of the implementation contract.
- Live seeding depends on AGE/PostgreSQL availability and is manual.
- `CASCADES` should remain a schema constant only unless a deterministic cascade rule is approved later.
