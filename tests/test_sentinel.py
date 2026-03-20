from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from ci_platform.connectors.sentinel import SentinelConfig, SentinelConnector


@pytest.fixture
def config():
    return SentinelConfig(
        tenant_id="test-tenant",
        client_id="test-client",
        client_secret="test-secret",
        workspace_id="test-workspace",
        subscription_id="test-sub",
        resource_group="test-rg",
        workspace_name="test-ws",
    )


def test_is_configured_true(config):
    connector = SentinelConnector(config)
    assert connector.is_configured() is True


def test_is_configured_false():
    connector = SentinelConnector(SentinelConfig())
    assert connector.is_configured() is False


def test_map_alert(config):
    connector = SentinelConnector(config)
    row = {
        "SystemAlertId": "ALERT-001",
        "AlertName": "Suspicious Login",
        "AlertSeverity": "High",
        "CompromisedEntity": "jsmith",
        "TimeGenerated": "2026-03-19T10:00:00Z",
        "ProviderName": "Azure Sentinel",
        "Description": "Unusual login activity",
        "Tactics": "InitialAccess",
        "Techniques": "T1078",
    }
    mapped = connector._map_alert(row)
    assert mapped["alert_id"] == "ALERT-001"
    assert mapped["alert_type"] == "Suspicious Login"
    assert mapped["severity"] == "high"
    assert mapped["user_name"] == "jsmith"


def test_map_disposition_escalate(config):
    connector = SentinelConnector(config)
    result = connector._map_disposition(
        {"action": "escalate", "confidence": 0.9, "explanation": "High risk", "analyst": "auto"}
    )
    assert result["status"] == "inProgress"
    assert result["classification"] == "truePositive"


def test_map_disposition_suppress(config):
    connector = SentinelConnector(config)
    result = connector._map_disposition(
        {"action": "suppress", "confidence": 0.85, "explanation": "False positive"}
    )
    assert result["status"] == "resolved"
    assert result["classification"] == "falsePositive"


@pytest.mark.asyncio
async def test_fetch_alerts_mocked(config):
    connector = SentinelConnector(config)
    mock_token_response = MagicMock()
    mock_token_response.status_code = 200
    mock_token_response.json.return_value = {
        "access_token": "fake-token",
        "expires_in": 3600,
    }
    mock_query_response = MagicMock()
    mock_query_response.status_code = 200
    mock_query_response.json.return_value = {
        "tables": [
            {
                "columns": [
                    {"name": "AlertName"},
                    {"name": "AlertSeverity"},
                    {"name": "TimeGenerated"},
                    {"name": "CompromisedEntity"},
                    {"name": "Description"},
                    {"name": "ProviderName"},
                    {"name": "SystemAlertId"},
                    {"name": "Tactics"},
                    {"name": "Techniques"},
                ],
                "rows": [
                    [
                        "Brute Force", "High", "2026-03-19T10:00:00Z",
                        "jsmith", "desc", "Sentinel", "A-001",
                        "CredAccess", "T1110",
                    ]
                ],
            }
        ]
    }
    with patch("httpx.AsyncClient") as MockClient:
        mock_client = AsyncMock()
        mock_client.post.side_effect = [mock_token_response, mock_query_response]
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        MockClient.return_value = mock_client

        alerts = await connector.fetch_alerts(datetime(2026, 3, 1))
        assert len(alerts) == 1
        assert alerts[0]["alert_id"] == "A-001"


@pytest.mark.asyncio
async def test_write_disposition_mocked(config):
    connector = SentinelConnector(config)
    mock_token_response = MagicMock()
    mock_token_response.status_code = 200
    mock_token_response.json.return_value = {
        "access_token": "fake-token",
        "expires_in": 3600,
    }
    mock_patch_response = MagicMock()
    mock_patch_response.status_code = 200

    with patch("httpx.AsyncClient") as MockClient:
        mock_client = AsyncMock()
        mock_client.post.return_value = mock_token_response
        mock_client.patch.return_value = mock_patch_response
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        MockClient.return_value = mock_client

        result = await connector.write_disposition(
            "A-001",
            {"action": "escalate", "confidence": 0.9, "explanation": "test"},
        )
        assert result is True


@pytest.mark.asyncio
async def test_health_check_mocked(config):
    connector = SentinelConnector(config)
    mock_token_response = MagicMock()
    mock_token_response.status_code = 200
    mock_token_response.json.return_value = {
        "access_token": "fake-token",
        "expires_in": 3600,
    }
    mock_ok = MagicMock()
    mock_ok.status_code = 200
    mock_ok.json.return_value = {"tables": [{"rows": []}]}

    with patch("httpx.AsyncClient") as MockClient:
        mock_client = AsyncMock()
        mock_client.post.return_value = mock_token_response
        mock_client.get.return_value = mock_ok
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        MockClient.return_value = mock_client

        health = await connector.health_check()
        assert health["source"] == "sentinel"
