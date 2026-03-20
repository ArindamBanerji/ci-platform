from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional

from ci_platform.connectors.sentinel import SentinelConnector


class EnrichmentType(Enum):
    DECISION = "decision"
    PROVENANCE = "provenance"
    CAMPAIGN = "campaign"


@dataclass
class EnrichmentPayload:
    alert_id: str
    enrichment_type: EnrichmentType
    content: Dict
    timestamp: str  # ISO format


class SentinelWriteBack:
    def __init__(self, connector: SentinelConnector):
        self._connector = connector

    # ── public API ────────────────────────────────────────────────────────────

    async def enrich_incident(
        self,
        alert_id: str,
        decision: Dict,
        provenance: Optional[Dict] = None,
        campaign: Optional[Dict] = None,
    ) -> Dict:
        errors: List[str] = []
        written = 0

        # Always write decision enrichment
        decision_comment = self.format_decision_comment(decision)
        body = self._build_comment(EnrichmentType.DECISION, decision_comment)
        ok = await self._connector.write_disposition(alert_id, body)
        if ok:
            written += 1
        else:
            errors.append(f"Failed to write DECISION enrichment for {alert_id}")

        if provenance is not None:
            prov_comment = self.format_provenance_comment(provenance)
            body = self._build_comment(EnrichmentType.PROVENANCE, prov_comment)
            ok = await self._connector.write_disposition(alert_id, body)
            if ok:
                written += 1
            else:
                errors.append(f"Failed to write PROVENANCE enrichment for {alert_id}")

        if campaign is not None:
            camp_comment = self.format_campaign_comment(campaign)
            body = self._build_comment(EnrichmentType.CAMPAIGN, camp_comment)
            ok = await self._connector.write_disposition(alert_id, body)
            if ok:
                written += 1
            else:
                errors.append(f"Failed to write CAMPAIGN enrichment for {alert_id}")

        return {
            "success": len(errors) == 0,
            "enrichments_written": written,
            "alert_id": alert_id,
            "errors": errors,
        }

    async def bulk_enrich(self, enrichments: List[Dict]) -> Dict:
        succeeded = 0
        failed = 0
        all_errors: List[str] = []

        for item in enrichments:
            result = await self.enrich_incident(
                alert_id=item["alert_id"],
                decision=item["decision"],
                provenance=item.get("provenance"),
                campaign=item.get("campaign"),
            )
            if result["success"]:
                succeeded += 1
            else:
                failed += 1
            all_errors.extend(result["errors"])

        return {
            "total": len(enrichments),
            "succeeded": succeeded,
            "failed": failed,
            "errors": all_errors,
        }

    # ── formatters ────────────────────────────────────────────────────────────

    def format_decision_comment(self, decision: Dict) -> str:
        action = decision.get("action", "unknown").upper()
        confidence = decision.get("confidence", 0.0)
        explanation = decision.get("explanation", "")
        factors = decision.get("factors", [])
        similar = decision.get("similar_cases_count", 0)
        verified = decision.get("verified_outcomes", 0)

        factor_str = ""
        if factors:
            parts = [f"{f['name']}={f['value']:.2f}" for f in factors]
            factor_str = " " + ", ".join(parts) + "."

        similar_str = ""
        if similar:
            similar_str = f" Based on {similar} similar past decisions"
            if verified:
                similar_str += f" ({verified} verified outcomes)"
            similar_str += "."

        return (
            f"SOC Copilot: {action} (confidence {confidence:.2f}). "
            f"{explanation}.{factor_str}{similar_str}"
        )

    def format_provenance_comment(self, provenance: Dict) -> str:
        factors = provenance.get("factors", [])
        if not factors:
            return "Factor provenance: no factors recorded."

        parts = []
        for f in factors:
            name = f.get("factor_name", "unknown")
            value = f.get("factor_value", 0.0)
            method = f.get("computation_method", "")
            nodes = f.get("graph_nodes_consulted", [])
            explanation = f.get("explanation", "")
            nodes_str = ", ".join(nodes) if nodes else "none"
            parts.append(
                f"{name}={value:.2f} [{method}; nodes: {nodes_str}; {explanation}]"
            )

        return "Factor provenance: " + " | ".join(parts) + "."

    def format_campaign_comment(self, campaign: Dict) -> str:
        cid = campaign.get("campaign_id", "unknown")
        count = campaign.get("alert_count", 0)
        tactics = campaign.get("tactics", [])
        first_seen = campaign.get("first_seen", "unknown")
        description = campaign.get("description", "")

        tactics_str = "→".join(tactics) if tactics else "unknown"

        return (
            f"Campaign: {cid} ({description}). "
            f"{count} related alerts. "
            f"Tactics: {tactics_str}. "
            f"First seen: {first_seen}."
        )

    # ── internal ──────────────────────────────────────────────────────────────

    def _build_comment(self, enrichment_type: EnrichmentType, formatted_text: str) -> Dict:
        tag = enrichment_type.value.capitalize()
        return {
            "properties": {
                "message": f"[SOC Copilot - {tag}] {formatted_text}"
            }
        }
