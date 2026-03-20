from unittest.mock import AsyncMock, MagicMock

import pytest

from ci_platform.connectors.sentinel_writeback import EnrichmentType, SentinelWriteBack


@pytest.fixture
def mock_connector():
    connector = MagicMock()
    connector.write_disposition = AsyncMock(return_value=True)
    connector.is_configured.return_value = True
    return connector


def test_format_decision_comment(mock_connector):
    wb = SentinelWriteBack(mock_connector)
    decision = {
        "action": "escalate",
        "confidence": 0.89,
        "explanation": "Anomalous login from Singapore",
        "factors": [
            {"name": "threat_intel", "value": 0.85},
            {"name": "time_anomaly", "value": 0.92},
        ],
        "similar_cases_count": 47,
        "verified_outcomes": 12,
    }
    comment = wb.format_decision_comment(decision)
    assert "ESCALATE" in comment or "escalate" in comment
    assert "0.89" in comment or "89%" in comment
    assert "Singapore" in comment


def test_format_provenance_comment(mock_connector):
    wb = SentinelWriteBack(mock_connector)
    provenance = {
        "factors": [
            {
                "factor_name": "travel_match",
                "factor_value": 0.25,
                "computation_method": "Graph traversal",
                "graph_nodes_consulted": ["User-001", "Travel-001"],
                "explanation": "No travel match",
            }
        ]
    }
    comment = wb.format_provenance_comment(provenance)
    assert "travel_match" in comment
    assert "0.25" in comment


def test_format_campaign_comment(mock_connector):
    wb = SentinelWriteBack(mock_connector)
    campaign = {
        "campaign_id": "CAMP-2026-003",
        "alert_count": 12,
        "tactics": ["InitialAccess", "CredentialAccess"],
        "first_seen": "2026-03-15",
        "description": "Credential harvesting campaign",
    }
    comment = wb.format_campaign_comment(campaign)
    assert "CAMP-2026-003" in comment
    assert "12" in comment


@pytest.mark.asyncio
async def test_enrich_incident_decision_only(mock_connector):
    wb = SentinelWriteBack(mock_connector)
    decision = {
        "action": "investigate",
        "confidence": 0.75,
        "explanation": "Suspicious activity",
        "factors": [],
        "similar_cases_count": 0,
        "verified_outcomes": 0,
    }
    result = await wb.enrich_incident("ALERT-001", decision)
    assert result["success"] is True
    assert result["enrichments_written"] >= 1


@pytest.mark.asyncio
async def test_enrich_incident_all_three(mock_connector):
    wb = SentinelWriteBack(mock_connector)
    decision = {
        "action": "escalate", "confidence": 0.9,
        "explanation": "test", "factors": [],
        "similar_cases_count": 5, "verified_outcomes": 3,
    }
    provenance = {
        "factors": [{
            "factor_name": "f1", "factor_value": 0.5,
            "computation_method": "test",
            "graph_nodes_consulted": [],
            "explanation": "test",
        }]
    }
    campaign = {
        "campaign_id": "C-001", "alert_count": 3,
        "tactics": ["Recon"], "first_seen": "2026-03-01",
        "description": "test",
    }
    result = await wb.enrich_incident(
        "ALERT-002", decision, provenance=provenance, campaign=campaign
    )
    assert result["enrichments_written"] == 3


@pytest.mark.asyncio
async def test_enrich_incident_write_failure(mock_connector):
    mock_connector.write_disposition = AsyncMock(return_value=False)
    wb = SentinelWriteBack(mock_connector)
    decision = {
        "action": "monitor", "confidence": 0.6,
        "explanation": "low risk", "factors": [],
        "similar_cases_count": 0, "verified_outcomes": 0,
    }
    result = await wb.enrich_incident("ALERT-003", decision)
    assert result["success"] is False
    assert len(result["errors"]) > 0


@pytest.mark.asyncio
async def test_bulk_enrich(mock_connector):
    wb = SentinelWriteBack(mock_connector)
    enrichments = [
        {
            "alert_id": "A-1",
            "decision": {
                "action": "escalate", "confidence": 0.9,
                "explanation": "t", "factors": [],
                "similar_cases_count": 0, "verified_outcomes": 0,
            },
        },
        {
            "alert_id": "A-2",
            "decision": {
                "action": "monitor", "confidence": 0.5,
                "explanation": "t", "factors": [],
                "similar_cases_count": 0, "verified_outcomes": 0,
            },
        },
    ]
    result = await wb.bulk_enrich(enrichments)
    assert result["total"] == 2
    assert result["succeeded"] == 2


def test_build_comment_tagged(mock_connector):
    wb = SentinelWriteBack(mock_connector)
    comment = wb._build_comment(EnrichmentType.DECISION, "test message")
    assert "[SOC Copilot" in str(comment)
