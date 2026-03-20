import asyncio
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, List

import httpx

from ci_platform.connectors.base import SourceConnectorProtocol

_POLL_INTERVAL = 1.0   # seconds between result polls
_POLL_TIMEOUT = 30.0   # seconds before giving up on a search job

_SPL_TEMPLATE = (
    "search index={index} sourcetype=*alert* earliest_time={epoch}"
    " | head {limit}"
    " | table _time, alert_name, severity, src_user,"
    " description, source, mitre_attack_technique"
)


@dataclass
class SplunkConfig:
    base_url: str = ""        # https://splunk.firm.com:8089
    hec_url: str = ""         # https://splunk.firm.com:8088
    username: str = ""
    password: str = ""
    hec_token: str = ""
    verify_ssl: bool = True
    search_index: str = "main"
    hec_index: str = "soc_copilot"
    app: str = "search"


class SplunkConnector(SourceConnectorProtocol):
    def __init__(self, config: SplunkConfig):
        self._config = config

    # ── SourceConnectorProtocol ───────────────────────────────────────────────

    async def fetch_alerts(self, since: datetime, limit: int = 500) -> List[Dict]:
        spl = self._build_spl_query(since, limit)
        cfg = self._config
        auth = (cfg.username, cfg.password)
        jobs_url = f"{cfg.base_url}/services/search/jobs"

        async with httpx.AsyncClient(verify=cfg.verify_ssl) as client:
            # Phase 1: create search job
            resp = await client.post(
                jobs_url,
                data={"search": spl, "output_mode": "json"},
                auth=auth,
                timeout=15,
            )
            resp.raise_for_status()
            sid = resp.json()["sid"]

            # Phase 2: poll until done
            results_url = f"{cfg.base_url}/services/search/jobs/{sid}/results"
            elapsed = 0.0
            while elapsed < _POLL_TIMEOUT:
                r = await client.get(
                    results_url,
                    params={"output_mode": "json", "count": limit},
                    auth=auth,
                    timeout=15,
                )
                if r.status_code == 200:
                    rows = r.json().get("results", [])
                    return [self._map_alert(row) for row in rows]
                # 204 / 202 → still running; anything else → bail
                if r.status_code not in (202, 204):
                    r.raise_for_status()
                await asyncio.sleep(_POLL_INTERVAL)
                elapsed += _POLL_INTERVAL

        return []

    async def write_disposition(self, alert_id: str, disposition: Dict) -> bool:
        cfg = self._config
        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        payload = {
            "index": cfg.hec_index,
            "sourcetype": "soc_copilot:disposition",
            "event": {
                "alert_id": alert_id,
                "action": disposition.get("action", ""),
                "confidence": disposition.get("confidence", 0.0),
                "explanation": disposition.get("explanation", ""),
                "timestamp": now_iso,
            },
        }
        async with httpx.AsyncClient(verify=cfg.verify_ssl) as client:
            resp = await client.post(
                f"{cfg.hec_url}/services/collector/event",
                headers={"Authorization": f"Splunk {cfg.hec_token}"},
                json=payload,
                timeout=15,
            )
        return resp.status_code == 200

    async def health_check(self) -> Dict:
        cfg = self._config
        auth = (cfg.username, cfg.password)
        read_ok = False
        write_ok = False

        try:
            async with httpx.AsyncClient(verify=cfg.verify_ssl) as client:
                resp = await client.get(
                    f"{cfg.base_url}/services/server/info",
                    params={"output_mode": "json"},
                    auth=auth,
                    timeout=10,
                )
            read_ok = resp.status_code == 200
        except Exception:
            pass

        try:
            async with httpx.AsyncClient(verify=cfg.verify_ssl) as client:
                resp = await client.post(
                    f"{cfg.hec_url}/services/collector/health",
                    headers={"Authorization": f"Splunk {cfg.hec_token}"},
                    timeout=10,
                )
            write_ok = resp.status_code == 200
        except Exception:
            pass

        return {"read": read_ok, "write": write_ok, "source": "splunk"}

    # ── helpers ───────────────────────────────────────────────────────────────

    def is_configured(self) -> bool:
        cfg = self._config
        return bool(cfg.base_url and cfg.username and cfg.password)

    def _map_alert(self, row: Dict) -> Dict:
        return {
            "alert_id":   row.get("sid", row.get("_cd", "")),
            "alert_type": row.get("alert_name", ""),
            "severity":   row.get("severity", "").lower(),
            "timestamp":  row.get("_time", ""),
            "user_name":  row.get("src_user", ""),
            "description": row.get("description", ""),
            "source":     row.get("source", "splunk"),
            "techniques": row.get("mitre_attack_technique", ""),
        }

    def _build_spl_query(self, since: datetime, limit: int) -> str:
        epoch = int(since.replace(tzinfo=timezone.utc).timestamp()
                    if since.tzinfo is None else since.timestamp())
        return _SPL_TEMPLATE.format(
            index=self._config.search_index,
            epoch=epoch,
            limit=limit,
        )
