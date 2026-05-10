import json
import importlib.util
import sys
from pathlib import Path

from dataops import schema


REPO_ROOT = Path(__file__).resolve().parents[1]
SEED_SCRIPT = REPO_ROOT / "scripts" / "seed_dataops_graph.py"
PRIMARY_SEED = (
    REPO_ROOT.parent
    / "copilot-sdk"
    / "copilot_sdk"
    / "scoring"
    / "presets"
    / "dataops_seed.json"
)


def test_schema_constants_exist():
    assert schema.PIPELINE_SYSTEM == "PipelineSystem"
    assert schema.DATA_QUALITY_ALERT == "DataQualityAlert"
    assert schema.FEEDS == "FEEDS"
    assert schema.AFFECTS == "AFFECTS"
    assert schema.CASCADES == "CASCADES"


def test_categories_match_preset():
    assert schema.CATEGORIES == [
        "pipeline_failure",
        "schema_change",
        "volume_anomaly",
        "quality_anomaly",
        "freshness_violation",
        "transform_drift",
    ]


def test_actions_match_preset():
    assert schema.ACTIONS == [
        "auto_approve",
        "investigate",
        "escalate_to_owner",
        "pause_downstream",
        "refer_to_specialist",
    ]


def test_no_soc_node_labels_in_dataops():
    labels = {
        schema.PIPELINE_SYSTEM,
        schema.DATA_QUALITY_ALERT,
        schema.FEEDS,
        schema.AFFECTS,
        schema.CASCADES,
    }
    assert labels.isdisjoint(
        {
            "User",
            "Asset",
            "Entity",
            "Decision",
            "ThreatIndicator",
            "AttackPattern",
            "Campaign",
            "Location",
        }
    )


def test_nine_pipeline_systems():
    assert len(schema.SYSTEMS) == 9
    required = {
        "name",
        "display_name",
        "sla_minutes",
        "business_criticality",
        "source_reliability",
        "owner",
    }
    for system in schema.SYSTEMS:
        assert required.issubset(system)
    assert schema.SYSTEM_NAMES == [system["name"] for system in schema.SYSTEMS]
    assert set(schema.SYSTEM_NAMES) == {
        "warehouse_etl",
        "payment_gateway",
        "crm_sync",
        "hr_feed",
        "billing_api",
        "iot_sensors",
        "marketing_db",
        "erp_export",
        "inventory_feed",
    }


def test_feeds_edges():
    assert schema.FEEDS_EDGES == [
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
    system_names = set(schema.SYSTEM_NAMES)
    for source, target in schema.FEEDS_EDGES:
        assert source in system_names
        assert target in system_names


def test_no_self_feeds():
    assert all(source != target for source, target in schema.FEEDS_EDGES)


def test_seed_script_exists():
    assert SEED_SCRIPT.exists()


def _load_seed_data():
    if not PRIMARY_SEED.exists():
        return []
    return json.loads(PRIMARY_SEED.read_text(encoding="utf-8"))


def test_seed_data_readable_if_adjacent_repo_present():
    rows = _load_seed_data()
    if PRIMARY_SEED.exists():
        assert isinstance(rows, list)
        assert len(rows) == 20
        assert {"event_id", "dataset", "category", "action_taken", "factors"}.issubset(rows[0])


def test_seed_data_categories_and_actions_match_schema_if_readable():
    rows = _load_seed_data()
    if not rows:
        return
    assert {row["category"] for row in rows}.issubset(set(schema.CATEGORIES))
    assert {row["action_taken"] for row in rows}.issubset(set(schema.ACTIONS))
    assert {row["dataset"] for row in rows}.issubset(set(schema.DATASET_SYSTEM_MAP))
    assert set(schema.DATASET_SYSTEM_MAP.values()).issubset(set(schema.SYSTEM_NAMES))


def test_seed_script_uses_ageclient_and_serializer():
    source = SEED_SCRIPT.read_text(encoding="utf-8")
    assert "AGEClient" in source
    assert "_S(" in source
    assert "serialize_for_age" in source


def test_seed_script_avoids_forbidden_age_patterns():
    source = SEED_SCRIPT.read_text(encoding="utf-8")
    forbidden = [
        "$",
        "MERGE",
        "ON CREATE",
        "ON MATCH",
        "SET n =",
        "SET node =",
        "AS count",
        "date(",
        "datetime(",
        "duration(",
    ]
    for pattern in forbidden:
        assert pattern not in source


def test_seed_script_destructive_queries_are_dataops_scoped():
    source = SEED_SCRIPT.read_text(encoding="utf-8")
    delete_lines = [line for line in source.splitlines() if "DELETE" in line]
    assert delete_lines
    for line in delete_lines:
        assert (
            "PIPELINE_SYSTEM" in line
            or "DATA_QUALITY_ALERT" in line
            or "PipelineSystem" in line
            or "DataQualityAlert" in line
        )
        assert "FEEDS" in line or "AFFECTS" in line or "CASCADES" in line or "DELETE a" in line or "DELETE s" in line
        assert "User" not in line
        assert "Asset" not in line
        assert "Entity" not in line
        assert "Decision" not in line


def test_seed_script_skip_path_does_not_print_seeded_summary(monkeypatch, capsys):
    spec = importlib.util.spec_from_file_location("seed_dataops_graph", SEED_SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)

    monkeypatch.setattr(sys, "argv", ["seed_dataops_graph.py"])
    monkeypatch.setattr(module, "load_seed_events", lambda: [{"event_id": "DOP-001"}])
    monkeypatch.setattr(module, "normalize_event", lambda event, index: {"alert_id": f"DQ-{index:03d}"})

    async def fake_seed_graph(alerts, force=False):
        print("DataOps graph already has 9 PipelineSystem nodes; use --force to reseed")
        return "skipped"

    monkeypatch.setattr(module, "seed_graph", fake_seed_graph)

    module.main()
    output = capsys.readouterr().out

    assert "already has 9 PipelineSystem nodes" in output
    assert "Seeded:" not in output
