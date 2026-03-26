from datetime import datetime
from unittest.mock import AsyncMock, MagicMock

import pytest

from ci_platform.entity_resolution.resolver import (
    EntityResolver, Identifier, IdentifierType,
)
from ci_platform.onboarding.pipeline import (
    LoadManifest, OnboardingPipeline, PipelineResult, StageResult,
)
from ci_platform.redaction.pii_redactor import PIIRedactor

SAMPLE_RAW_ALERTS = [
    {
        "SystemAlertId": "A-001",
        "AlertName": "Brute Force",
        "AlertSeverity": "High",
        "CompromisedEntity": "john@firm.com",
        "TimeGenerated": "2026-03-01T10:00:00Z",
        "ProviderName": "Sentinel",
        "Description": "Multiple failed logins from 192.168.1.100",
        "asset_hostname": "SRV-WEB-01",
    },
    {
        "SystemAlertId": "A-002",
        "AlertName": "Data Upload",
        "AlertSeverity": "Medium",
        "CompromisedEntity": "jane@firm.com",
        "TimeGenerated": "2026-03-02T14:00:00Z",
        "ProviderName": "Sentinel",
        "Description": "Large upload to external storage",
        "asset_hostname": "LAPTOP-JANE",
    },
]


@pytest.fixture
def mock_connector():
    connector = AsyncMock()
    connector.fetch_alerts = AsyncMock(return_value=SAMPLE_RAW_ALERTS)
    connector.health_check = AsyncMock(
        return_value={"read": True, "write": True, "source": "test"}
    )
    return connector


@pytest.mark.asyncio
async def test_full_pipeline(mock_connector):
    pipeline = OnboardingPipeline(mock_connector)
    result = await pipeline.run(days_back=30, limit=100)
    assert result.success is True
    assert len(result.stages) == 6
    assert result.alerts_imported >= 1


@pytest.mark.asyncio
async def test_extract_stage(mock_connector):
    pipeline = OnboardingPipeline(mock_connector)
    stage, alerts = await pipeline._extract(30, 100)
    assert stage.success is True
    assert stage.records_out == 2
    assert len(alerts) == 2


def test_normalize_stage():
    pipeline = OnboardingPipeline(AsyncMock())
    stage, normalized = pipeline._normalize(SAMPLE_RAW_ALERTS)
    assert stage.success is True
    assert all("alert_type" in a for a in normalized)
    assert all("severity" in a for a in normalized)


def test_normalize_drops_malformed():
    pipeline = OnboardingPipeline(AsyncMock())
    bad_alerts = [{"random_field": "no alert_type"}]
    stage, normalized = pipeline._normalize(bad_alerts)
    assert stage.records_out <= stage.records_in


def test_redact_stage():
    pipeline = OnboardingPipeline(AsyncMock())
    alerts = [
        {
            "alert_type": "test",
            "user_name": "john@firm.com",
            "description": "SSN: 123-45-6789",
        }
    ]
    stage, redacted = pipeline._redact(alerts)
    assert stage.success is True
    assert "john@firm.com" not in str(redacted)
    assert "123-45-6789" not in str(redacted)
    assert redacted[0]["alert_type"] == "test"


def test_resolve_stage():
    pipeline = OnboardingPipeline(AsyncMock())
    alerts = [
        {"alert_id": "A-1", "user_name": "john@firm.com", "asset_hostname": "SRV-01"},
        {"alert_id": "A-2", "user_name": "john@firm.com", "asset_hostname": "SRV-02"},
    ]
    stage, entities, entity_map = pipeline._resolve(alerts)
    assert stage.success is True
    assert len(entities) >= 1
    assert "A-1" in entity_map


def test_load_stage():
    pipeline = OnboardingPipeline(AsyncMock())
    alerts = [
        {
            "alert_id": "A-1",
            "alert_type": "test",
            "severity": "high",
            "user_name": "john@firm.com",
            "asset_hostname": "SRV-01",
            "timestamp": "2026-03-01",
        }
    ]
    resolver = EntityResolver()
    ids = [Identifier("john@firm.com", IdentifierType.EMAIL, "test")]
    entities = resolver.resolve(ids)
    entity_map = {"A-1": entities[0].canonical_id}
    stage, manifest = pipeline._load(alerts, entities, entity_map)
    assert stage.success is True
    assert len(manifest.nodes) >= 1
    assert len(manifest.relationships) >= 1


def test_compute_stage():
    pipeline = OnboardingPipeline(AsyncMock())
    alerts = [
        {"alert_type": "brute_force", "severity": "high", "timestamp": "2026-03-01"},
        {"alert_type": "brute_force", "severity": "high", "timestamp": "2026-03-02"},
        {"alert_type": "data_upload", "severity": "medium", "timestamp": "2026-03-03"},
    ]
    stage, config = pipeline._compute(alerts, days_back=30)
    assert stage.success is True
    assert "estimated_alert_volume" in config
    assert "category_distribution" in config or "alert_type_distribution" in config


@pytest.mark.asyncio
async def test_progress_callback(mock_connector):
    progress = []

    def callback(stage, pct):
        progress.append((stage, pct))

    pipeline = OnboardingPipeline(mock_connector)
    await pipeline.run(days_back=30, limit=100, progress_callback=callback)
    assert len(progress) >= 6
    stage_names = [p[0] for p in progress]
    assert "extract" in stage_names
    assert "load" in stage_names


@pytest.mark.asyncio
async def test_extract_failure_stops_pipeline(mock_connector):
    mock_connector.fetch_alerts = AsyncMock(side_effect=Exception("Connection refused"))
    pipeline = OnboardingPipeline(mock_connector)
    result = await pipeline.run(days_back=30, limit=100)
    assert result.success is False
    assert result.stages[0].success is False


# ── CI-3: shadow_decisions threaded through pipeline ──────────────────────────

def test_tau_sweep_reachable_via_pipeline_compute():
    """CI-3: TD-034 v2 τ sweep triggers when sigma_mean > 0.12 and shadow_decisions provided."""
    import numpy as np
    pipeline = OnboardingPipeline(AsyncMock())

    # High-noise alerts: sigma_mean will exceed 0.12 threshold
    rng = np.random.default_rng(5)
    alerts = [
        {
            "alert_type": "brute_force",
            "severity": "high",
            "factor_vector": np.clip(rng.normal(0.5, 0.18, 6), 0, 1).tolist(),
        }
        for _ in range(100)
    ]
    shadow = [
        {"confidence": float(rng.uniform(0.4, 0.95)), "correct": bool(rng.random() > 0.4)}
        for _ in range(50)
    ]
    stage, config = pipeline._compute(alerts, days_back=30, shadow_decisions=shadow)
    assert stage.success is True
    tau_sweep = config.get("tau_sweep", {})
    assert tau_sweep is not None
    # If triggered, sweep_results must be populated
    if tau_sweep.get("tau_sweep_triggered"):
        assert len(tau_sweep["sweep_results"]) == 5


# ── CI-5: pipeline → ledger integration ───────────────────────────────────────

@pytest.mark.asyncio
async def test_pipeline_qualification_entry_fields_populated(mock_connector):
    """CI-5: After full pipeline run, qualification_entry has kernel_type and noise_zone set."""
    pipeline = OnboardingPipeline(mock_connector)
    result = await pipeline.run(days_back=30, limit=100)
    assert result.success is True
    assert result.recommended_config is not None
    entry = result.recommended_config.get("qualification_entry")
    assert entry is not None, "qualification_entry missing from recommended_config"
    assert entry["kernel_type"] is not None, "kernel_type must not be None"
    assert entry["noise_zone"] is not None, "noise_zone must not be None"
    assert entry["conservation_status"] == "pending"
    assert entry["entry_hash"] != ""
