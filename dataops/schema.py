"""Schema constants for the DataOps AGE graph namespace."""

PIPELINE_SYSTEM = "PipelineSystem"
DATA_QUALITY_ALERT = "DataQualityAlert"
FEEDS = "FEEDS"
AFFECTS = "AFFECTS"
CASCADES = "CASCADES"

CATEGORIES = [
    "pipeline_failure",
    "schema_change",
    "volume_anomaly",
    "quality_anomaly",
    "freshness_violation",
    "transform_drift",
]

ACTIONS = [
    "auto_approve",
    "investigate",
    "escalate_to_owner",
    "pause_downstream",
    "refer_to_specialist",
]

SYSTEMS = [
    {
        "name": "warehouse_etl",
        "display_name": "Warehouse ETL",
        "sla_minutes": 30,
        "business_criticality": 0.92,
        "source_reliability": 0.82,
        "owner": "data-platform",
        "status": "active",
        "last_run": "2026-05-08T00:00:00Z",
        "description": "Central batch transformation layer for curated analytics tables.",
    },
    {
        "name": "payment_gateway",
        "display_name": "Payment Gateway",
        "sla_minutes": 15,
        "business_criticality": 0.95,
        "source_reliability": 0.88,
        "owner": "payments",
        "status": "active",
        "last_run": "2026-05-08T00:05:00Z",
        "description": "Payment authorization and settlement feed integration.",
    },
    {
        "name": "crm_sync",
        "display_name": "CRM Sync",
        "sla_minutes": 60,
        "business_criticality": 0.74,
        "source_reliability": 0.76,
        "owner": "revenue-ops",
        "status": "active",
        "last_run": "2026-05-08T00:10:00Z",
        "description": "Customer and account synchronization pipelines.",
    },
    {
        "name": "hr_feed",
        "display_name": "HR Feed",
        "sla_minutes": 120,
        "business_criticality": 0.58,
        "source_reliability": 0.84,
        "owner": "people-analytics",
        "status": "active",
        "last_run": "2026-05-08T00:15:00Z",
        "description": "Workforce identity and policy score reference feeds.",
    },
    {
        "name": "billing_api",
        "display_name": "Billing API",
        "sla_minutes": 20,
        "business_criticality": 0.9,
        "source_reliability": 0.79,
        "owner": "billing",
        "status": "active",
        "last_run": "2026-05-08T00:20:00Z",
        "description": "Billing export and revenue service API pipelines.",
    },
    {
        "name": "iot_sensors",
        "display_name": "IoT Sensors",
        "sla_minutes": 10,
        "business_criticality": 0.62,
        "source_reliability": 0.7,
        "owner": "operations",
        "status": "active",
        "last_run": "2026-05-08T00:25:00Z",
        "description": "Traffic and telemetry collection pipelines.",
    },
    {
        "name": "marketing_db",
        "display_name": "Marketing DB",
        "sla_minutes": 45,
        "business_criticality": 0.68,
        "source_reliability": 0.73,
        "owner": "marketing-analytics",
        "status": "active",
        "last_run": "2026-05-08T00:30:00Z",
        "description": "Campaign, attribution, search, and scoring marts.",
    },
    {
        "name": "erp_export",
        "display_name": "ERP Export",
        "sla_minutes": 90,
        "business_criticality": 0.8,
        "source_reliability": 0.81,
        "owner": "enterprise-systems",
        "status": "active",
        "last_run": "2026-05-08T00:35:00Z",
        "description": "ERP product, supplier, and operational reference exports.",
    },
    {
        "name": "inventory_feed",
        "display_name": "Inventory Feed",
        "sla_minutes": 25,
        "business_criticality": 0.83,
        "source_reliability": 0.77,
        "owner": "supply-chain",
        "status": "active",
        "last_run": "2026-05-08T00:40:00Z",
        "description": "Inventory snapshots and downstream fulfillment availability.",
    },
]

SYSTEM_NAMES = [system["name"] for system in SYSTEMS]

FEEDS_EDGES = [
    ("billing_api", "warehouse_etl"),
    ("billing_api", "payment_gateway"),
    ("crm_sync", "warehouse_etl"),
    ("crm_sync", "marketing_db"),
    ("erp_export", "warehouse_etl"),
    ("erp_export", "billing_api"),
    ("inventory_feed", "warehouse_etl"),
    ("iot_sensors", "inventory_feed"),
    ("warehouse_etl", "marketing_db"),
]

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
