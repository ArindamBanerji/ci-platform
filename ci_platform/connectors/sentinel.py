import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional

import httpx

from ci_platform.connectors.base import SourceConnectorProtocol

_LOG_ANALYTICS_SCOPE = "https://api.loganalytics.io/.default"
_GRAPH_SCOPE = "https://graph.microsoft.com/.default"
_TOKEN_URL = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
_QUERY_URL = "https://api.loganalytics.io/v1/workspaces/{workspace_id}/query"
_GRAPH_ALERTS_URL = "https://graph.microsoft.com/v1.0/security/alerts"

_KQL_TEMPLATE = """SecurityAlert
| where TimeGenerated > datetime('{since}')
| take {limit}
| project AlertName, AlertSeverity, TimeGenerated, CompromisedEntity,
          Description, ProviderName, SystemAlertId, Tactics, Techniques"""

_ACTION_MAP: Dict[str, Dict[str, str]] = {
    "escalate":    {"status": "inProgress",  "classification": "truePositive"},
    "investigate": {"status": "inProgress",  "classification": "unknown"},
    "suppress":    {"status": "resolved",    "classification": "falsePositive"},
    "monitor":     {"status": "inProgress",  "classification": "informational"},
}

# KQL columns returned in project order
_KQL_COLUMNS = [
    "AlertName", "AlertSeverity", "TimeGenerated", "CompromisedEntity",
    "Description", "ProviderName", "SystemAlertId", "Tactics", "Techniques",
]


@dataclass
class SentinelConfig:
    tenant_id: str = ""
    client_id: str = ""
    client_secret: str = ""
    workspace_id: str = ""
    subscription_id: str = ""
    resource_group: str = ""
    workspace_name: str = ""
    api_version: str = "2023-11-01"


class SentinelConnector(SourceConnectorProtocol):
    def __init__(self, config: SentinelConfig):
        self._config = config
        # token cache keyed by scope → {access_token, expires_at}
        self._token_cache: Dict[str, Dict] = {}

    # ── SourceConnectorProtocol ───────────────────────────────────────────────

    async def fetch_alerts(self, since: datetime, limit: int = 500) -> List[Dict]:
        since_iso = since.strftime("%Y-%m-%dT%H:%M:%SZ")
        kql = _KQL_TEMPLATE.format(since=since_iso, limit=limit)
        token = await self._get_token(_LOG_ANALYTICS_SCOPE)
        url = _QUERY_URL.format(workspace_id=self._config.workspace_id)

        async with httpx.AsyncClient() as client:
            resp = await client.post(
                url,
                headers={"Authorization": f"Bearer {token}"},
                json={"query": kql},
                timeout=30,
            )
            resp.raise_for_status()
            data = resp.json()

        return self._parse_kql_response(data)

    async def write_disposition(self, alert_id: str, disposition: Dict) -> bool:
        token = await self._get_token(_GRAPH_SCOPE)
        body = self._map_disposition(disposition)
        url = f"{_GRAPH_ALERTS_URL}/{alert_id}"

        async with httpx.AsyncClient() as client:
            resp = await client.patch(
                url,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json",
                },
                json=body,
                timeout=30,
            )

        return resp.status_code == 200

    async def health_check(self) -> Dict:
        read_ok = False
        write_ok = False

        try:
            token = await self._get_token(_LOG_ANALYTICS_SCOPE)
            url = _QUERY_URL.format(workspace_id=self._config.workspace_id)
            async with httpx.AsyncClient() as client:
                resp = await client.post(
                    url,
                    headers={"Authorization": f"Bearer {token}"},
                    json={"query": "SecurityAlert | take 1"},
                    timeout=15,
                )
            read_ok = resp.status_code == 200
        except Exception:
            pass

        try:
            token = await self._get_token(_GRAPH_SCOPE)
            async with httpx.AsyncClient() as client:
                resp = await client.get(
                    f"{_GRAPH_ALERTS_URL}?$top=1",
                    headers={"Authorization": f"Bearer {token}"},
                    timeout=15,
                )
            write_ok = resp.status_code == 200
        except Exception:
            pass

        return {"read": read_ok, "write": write_ok, "source": "sentinel"}

    # ── auth ─────────────────────────────────────────────────────────────────

    async def _get_token(self, scope: str) -> str:
        cached = self._token_cache.get(scope)
        if cached and cached["expires_at"] > time.time() + 60:
            return cached["access_token"]

        url = _TOKEN_URL.format(tenant_id=self._config.tenant_id)
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                url,
                data={
                    "grant_type": "client_credentials",
                    "client_id": self._config.client_id,
                    "client_secret": self._config.client_secret,
                    "scope": scope,
                },
                timeout=15,
            )
            resp.raise_for_status()
            payload = resp.json()

        self._token_cache[scope] = {
            "access_token": payload["access_token"],
            "expires_at": time.time() + payload.get("expires_in", 3600),
        }
        return payload["access_token"]

    # ── helpers ───────────────────────────────────────────────────────────────

    def is_configured(self) -> bool:
        cfg = self._config
        return bool(cfg.tenant_id and cfg.client_id
                    and cfg.client_secret and cfg.workspace_id)

    def _map_alert(self, row: Dict) -> Dict:
        return {
            "alert_id":   row.get("SystemAlertId", ""),
            "alert_type": row.get("AlertName", ""),
            "severity":   row.get("AlertSeverity", "").lower(),
            "timestamp":  row.get("TimeGenerated", ""),
            "user_name":  row.get("CompromisedEntity", ""),
            "description": row.get("Description", ""),
            "source":     row.get("ProviderName", "sentinel"),
            "tactics":    row.get("Tactics", ""),
            "techniques": row.get("Techniques", ""),
        }

    def _map_disposition(self, disposition: Dict) -> Dict:
        action = disposition.get("action", "investigate")
        mapping = _ACTION_MAP.get(action, _ACTION_MAP["investigate"])
        body: Dict = {
            "status": mapping["status"],
            "classification": mapping["classification"],
        }
        if disposition.get("explanation"):
            body["comments"] = disposition["explanation"]
        if disposition.get("analyst"):
            body["assignedTo"] = disposition["analyst"]
        return body

    def _parse_kql_response(self, data: Dict) -> List[Dict]:
        alerts = []
        for table in data.get("tables", []):
            columns = [c["name"] for c in table.get("columns", [])]
            for row_values in table.get("rows", []):
                row = dict(zip(columns, row_values))
                alerts.append(self._map_alert(row))
        return alerts
