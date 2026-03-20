from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from ci_platform.connectors.splunk import SplunkConfig, SplunkConnector


@pytest.fixture
def config():
    return SplunkConfig(
        base_url="https://splunk.test:8089",
        hec_url="https://splunk.test:8088",
        username="admin",
        password="secret",
        hec_token="hec-token-123",
    )


def test_is_configured_true(config):
    connector = SplunkConnector(config)
    assert connector.is_configured() is True


def test_is_configured_false():
    connector = SplunkConnector(SplunkConfig())
    assert connector.is_configured() is False


def test_map_alert(config):
    connector = SplunkConnector(config)
    row = {
        "_time": "2026-03-19T10:00:00Z",
        "alert_name": "Brute Force Detected",
        "severity": "High",
        "src_user": "jsmith",
        "source": "Splunk ES",
        "description": "Multiple failed logins",
        "sid": "SPLUNK-001",
    }
    mapped = connector._map_alert(row)
    assert mapped["alert_type"] == "Brute Force Detected"
    assert mapped["severity"] == "high"
    assert mapped["user_name"] == "jsmith"


def test_build_spl_query(config):
    connector = SplunkConnector(config)
    query = connector._build_spl_query(datetime(2026, 3, 1), 100)
    assert "index=main" in query
    assert "head 100" in query


@pytest.mark.asyncio
async def test_fetch_alerts_mocked(config):
    connector = SplunkConnector(config)
    mock_create = MagicMock()
    mock_create.status_code = 201
    mock_create.json.return_value = {"sid": "job-123"}

    mock_results = MagicMock()
    mock_results.status_code = 200
    mock_results.json.return_value = {
        "results": [
            {
                "_time": "2026-03-19T10:00:00Z",
                "alert_name": "Suspicious Login",
                "severity": "Medium",
                "src_user": "jdoe",
                "source": "Splunk ES",
                "description": "Unusual activity",
                "sid": "S-001",
            }
        ]
    }

    with patch("httpx.AsyncClient") as MockClient:
        mock_client = AsyncMock()
        mock_client.post.return_value = mock_create
        mock_client.get.return_value = mock_results
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        MockClient.return_value = mock_client

        alerts = await connector.fetch_alerts(datetime(2026, 3, 1))
        assert len(alerts) == 1
        assert alerts[0]["alert_type"] == "Suspicious Login"


@pytest.mark.asyncio
async def test_write_disposition_mocked(config):
    connector = SplunkConnector(config)
    mock_response = MagicMock()
    mock_response.status_code = 200

    with patch("httpx.AsyncClient") as MockClient:
        mock_client = AsyncMock()
        mock_client.post.return_value = mock_response
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        MockClient.return_value = mock_client

        result = await connector.write_disposition(
            "S-001",
            {"action": "escalate", "confidence": 0.9, "explanation": "High risk alert"},
        )
        assert result is True


@pytest.mark.asyncio
async def test_health_check_mocked(config):
    connector = SplunkConnector(config)
    mock_ok = MagicMock()
    mock_ok.status_code = 200
    mock_ok.json.return_value = {"generator": {"version": "9.1"}}

    with patch("httpx.AsyncClient") as MockClient:
        mock_client = AsyncMock()
        mock_client.get.return_value = mock_ok
        mock_client.post.return_value = mock_ok
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        MockClient.return_value = mock_client

        health = await connector.health_check()
        assert health["source"] == "splunk"
