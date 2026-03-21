import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Callable, Dict, List, Optional, Tuple

from ci_platform.connectors.base import SourceConnectorProtocol
from ci_platform.entity_resolution.resolver import (
    EntityResolver, Identifier, IdentifierType, ResolvedEntity,
)
from ci_platform.redaction.pii_redactor import PIIRedactor

# Canonical field aliases — maps common raw field names to our schema
_FIELD_ALIASES: Dict[str, str] = {
    "SystemAlertId":    "alert_id",
    "AlertName":        "alert_type",
    "AlertSeverity":    "severity",
    "CompromisedEntity": "user_name",
    "TimeGenerated":    "timestamp",
    "ProviderName":     "source",
    "Description":      "description",
    "Tactics":          "tactics",
    "Techniques":       "techniques",
    # Splunk-style
    "alert_name":       "alert_type",
    "src_user":         "user_name",
    "_time":            "timestamp",
}

_REQUIRED_FIELDS = {"alert_type", "severity"}

# Rough alert-type → TD-034 category mapping
_CATEGORY_MAP: Dict[str, str] = {
    "brute": "credential_attack",
    "login": "credential_attack",
    "password": "credential_attack",
    "upload": "data_exfiltration",
    "download": "data_exfiltration",
    "exfil": "data_exfiltration",
    "ransomware": "malware",
    "malware": "malware",
    "phish": "phishing",
    "recon": "reconnaissance",
    "scan": "reconnaissance",
    "lateral": "lateral_movement",
}


# ── dataclasses ───────────────────────────────────────────────────────────────

@dataclass
class StageResult:
    stage: str
    success: bool
    duration_seconds: float
    records_in: int
    records_out: int
    details: Dict = field(default_factory=dict)


@dataclass
class LoadManifest:
    nodes: List[Dict] = field(default_factory=list)
    relationships: List[Dict] = field(default_factory=list)
    entity_map: Dict[str, str] = field(default_factory=dict)
    stats: Dict = field(default_factory=dict)


@dataclass
class PipelineResult:
    success: bool
    stages: List[StageResult]
    total_duration_seconds: float
    alerts_imported: int
    entities_resolved: int
    redactions_applied: int
    load_manifest: Optional[LoadManifest]
    recommended_config: Optional[Dict]


# ── pipeline ──────────────────────────────────────────────────────────────────

class OnboardingPipeline:
    def __init__(
        self,
        connector: SourceConnectorProtocol,
        redactor: Optional[PIIRedactor] = None,
        resolver: Optional[EntityResolver] = None,
    ):
        self._connector = connector
        self._redactor = redactor or PIIRedactor()
        self._resolver = resolver or EntityResolver()

    async def run(
        self,
        days_back: int = 30,
        limit: int = 10000,
        progress_callback: Optional[Callable] = None,
    ) -> PipelineResult:
        stages: List[StageResult] = []
        pipeline_start = time.monotonic()

        def _progress(name: str, pct: float) -> None:
            if progress_callback:
                progress_callback(name, pct)

        # ── Stage 1: Extract ──────────────────────────────────────────────────
        try:
            stage, raw_alerts = await self._extract(days_back, limit)
        except Exception as exc:
            stage = StageResult(
                stage="extract", success=False,
                duration_seconds=0.0, records_in=0, records_out=0,
                details={"error": str(exc)},
            )
            stages.append(stage)
            _progress("extract", 0.0)
            return _failed_result(stages, pipeline_start)

        stages.append(stage)
        _progress("extract", 1 / 6)
        if not stage.success:
            return _failed_result(stages, pipeline_start)

        # ── Stage 2: Normalize ────────────────────────────────────────────────
        stage, norm_alerts = self._normalize(raw_alerts)
        stages.append(stage)
        _progress("normalize", 2 / 6)
        if not stage.success:
            return _failed_result(stages, pipeline_start)

        # ── Stage 3: Redact ───────────────────────────────────────────────────
        stage, redacted_alerts = self._redact(norm_alerts)
        stages.append(stage)
        _progress("redact", 3 / 6)
        total_redactions = stage.details.get("total_redactions", 0)
        if not stage.success:
            return _failed_result(stages, pipeline_start)

        # ── Stage 4: Resolve ──────────────────────────────────────────────────
        stage, entities, entity_map = self._resolve(redacted_alerts)
        stages.append(stage)
        _progress("resolve", 4 / 6)
        if not stage.success:
            return _failed_result(stages, pipeline_start)

        # ── Stage 5: Load ─────────────────────────────────────────────────────
        stage, manifest = self._load(redacted_alerts, entities, entity_map)
        stages.append(stage)
        _progress("load", 5 / 6)
        if not stage.success:
            return _failed_result(stages, pipeline_start)

        # ── Stage 6: Compute ──────────────────────────────────────────────────
        stage, recommended = self._compute(redacted_alerts, days_back=days_back)
        stages.append(stage)
        _progress("compute", 6 / 6)

        total_dur = time.monotonic() - pipeline_start
        return PipelineResult(
            success=stage.success,
            stages=stages,
            total_duration_seconds=total_dur,
            alerts_imported=len(redacted_alerts),
            entities_resolved=len(entities),
            redactions_applied=total_redactions,
            load_manifest=manifest,
            recommended_config=recommended if stage.success else None,
        )

    # ── stages ────────────────────────────────────────────────────────────────

    async def _extract(
        self, days_back: int, limit: int
    ) -> Tuple[StageResult, List[Dict]]:
        t0 = time.monotonic()
        since = datetime.now(timezone.utc) - timedelta(days=days_back)
        alerts = await self._connector.fetch_alerts(since=since, limit=limit)
        dur = time.monotonic() - t0
        stage = StageResult(
            stage="extract", success=True,
            duration_seconds=dur,
            records_in=0, records_out=len(alerts),
            details={"since": since.isoformat(), "limit": limit},
        )
        return stage, alerts

    def _normalize(self, raw_alerts: List[Dict]) -> Tuple[StageResult, List[Dict]]:
        t0 = time.monotonic()
        normalized: List[Dict] = []
        dropped = 0

        for raw in raw_alerts:
            rec: Dict = {}
            # Apply aliases first
            for raw_key, value in raw.items():
                canonical = _FIELD_ALIASES.get(raw_key, raw_key)
                rec[canonical] = value

            # Generate alert_id if absent
            if "alert_id" not in rec or not rec["alert_id"]:
                rec["alert_id"] = f"gen-{uuid.uuid4().hex[:8]}"

            # Ensure canonical fields exist with defaults
            rec.setdefault("alert_type", "")
            rec.setdefault("severity", "")
            rec.setdefault("timestamp", "")
            rec.setdefault("user_name", "")
            rec.setdefault("asset_hostname", "")
            rec.setdefault("description", "")
            rec.setdefault("source", "unknown")
            rec.setdefault("tactics", "")
            rec.setdefault("techniques", "")

            # Validate required fields
            if not all(rec.get(f) for f in _REQUIRED_FIELDS):
                dropped += 1
                continue

            rec["severity"] = rec["severity"].lower()
            normalized.append(rec)

        dur = time.monotonic() - t0
        stage = StageResult(
            stage="normalize", success=True,
            duration_seconds=dur,
            records_in=len(raw_alerts), records_out=len(normalized),
            details={"dropped": dropped},
        )
        return stage, normalized

    def _redact(self, alerts: List[Dict]) -> Tuple[StageResult, List[Dict]]:
        t0 = time.monotonic()
        redacted_alerts: List[Dict] = []
        total_redactions = 0

        for alert in alerts:
            clean, report = self._redactor.redact_dict(alert)
            redacted_alerts.append(clean)
            total_redactions += report.total_redactions

        dur = time.monotonic() - t0
        stage = StageResult(
            stage="redact", success=True,
            duration_seconds=dur,
            records_in=len(alerts), records_out=len(redacted_alerts),
            details={"total_redactions": total_redactions},
        )
        return stage, redacted_alerts

    def _resolve(
        self, alerts: List[Dict]
    ) -> Tuple[StageResult, List[ResolvedEntity], Dict[str, str]]:
        t0 = time.monotonic()
        all_identifiers: List[Identifier] = []
        alert_id_to_idents: Dict[str, List[int]] = {}

        for alert in alerts:
            aid = alert.get("alert_id", "")
            start_idx = len(all_identifiers)

            user = alert.get("user_name", "")
            if user:
                id_type = _infer_user_id_type(user)
                all_identifiers.append(Identifier(user, id_type, alert.get("source", "unknown")))

            hostname = alert.get("asset_hostname", "")
            if hostname:
                all_identifiers.append(Identifier(hostname, IdentifierType.HOSTNAME, alert.get("source", "unknown")))

            end_idx = len(all_identifiers)
            if end_idx > start_idx:
                alert_id_to_idents[aid] = list(range(start_idx, end_idx))

        entities = self._resolver.resolve(all_identifiers)

        # Build a lookup: normalized identifier value → canonical_id
        value_to_canonical: Dict[str, str] = {}
        for entity in entities:
            for ident in entity.identifiers:
                value_to_canonical[ident.value.lower()] = entity.canonical_id

        # Map each alert to its canonical entity via its first matching identifier
        entity_map: Dict[str, str] = {}
        for alert in alerts:
            aid = alert.get("alert_id", "")
            idxs = alert_id_to_idents.get(aid, [])
            for idx in idxs:
                val = all_identifiers[idx].value.lower()
                if val in value_to_canonical:
                    entity_map[aid] = value_to_canonical[val]
                    break

        dur = time.monotonic() - t0
        stage = StageResult(
            stage="resolve", success=True,
            duration_seconds=dur,
            records_in=len(alerts), records_out=len(entities),
            details={
                "identifiers_extracted": len(all_identifiers),
                "entities_resolved": len(entities),
                "alerts_mapped": len(entity_map),
            },
        )
        return stage, entities, entity_map

    def _load(
        self,
        alerts: List[Dict],
        entities: List[ResolvedEntity],
        entity_map: Dict[str, str],
    ) -> Tuple[StageResult, LoadManifest]:
        t0 = time.monotonic()
        nodes: List[Dict] = []
        relationships: List[Dict] = []
        node_ids: set = set()

        def _add_node(node: Dict) -> None:
            nid = node["id"]
            if nid not in node_ids:
                node_ids.add(nid)
                nodes.append(node)

        # Entity nodes (User / Asset)
        for entity in entities:
            node_type = "User" if entity.entity_type == "user" else "Asset"
            _add_node({
                "id": entity.canonical_id,
                "type": node_type,
                "display_name": entity.display_name,
                "identifiers": [i.value for i in entity.identifiers],
            })

        # Alert nodes + relationships
        alert_type_ids: Dict[str, str] = {}
        for alert in alerts:
            aid = alert.get("alert_id", "")
            atype = alert.get("alert_type", "unknown")

            _add_node({
                "id": f"alert:{aid}",
                "type": "Alert",
                "alert_id": aid,
                "alert_type": atype,
                "severity": alert.get("severity", ""),
                "timestamp": alert.get("timestamp", ""),
                "source": alert.get("source", ""),
            })

            # AlertType node (de-duplicated)
            at_id = f"alerttype:{atype.lower().replace(' ', '_')}"
            if at_id not in alert_type_ids:
                alert_type_ids[at_id] = atype
                _add_node({"id": at_id, "type": "AlertType", "name": atype})
            relationships.append({
                "type": "CLASSIFIED_AS",
                "from": f"alert:{aid}",
                "to": at_id,
            })

            # INVOLVES (Alert → User/Asset entity)
            canonical = entity_map.get(aid)
            if canonical:
                # Determine if entity is user or asset
                entity_obj = next((e for e in entities if e.canonical_id == canonical), None)
                rel_type = "INVOLVES" if (entity_obj and entity_obj.entity_type == "user") else "DETECTED_ON"
                relationships.append({
                    "type": rel_type,
                    "from": f"alert:{aid}",
                    "to": canonical,
                })

        # Count by type
        by_type: Dict[str, int] = {}
        for n in nodes:
            by_type[n["type"]] = by_type.get(n["type"], 0) + 1

        manifest = LoadManifest(
            nodes=nodes,
            relationships=relationships,
            entity_map=entity_map,
            stats={
                "node_count": len(nodes),
                "relationship_count": len(relationships),
                "by_type": by_type,
            },
        )

        dur = time.monotonic() - t0
        stage = StageResult(
            stage="load", success=True,
            duration_seconds=dur,
            records_in=len(alerts), records_out=len(nodes),
            details=manifest.stats,
        )
        return stage, manifest

    def _compute(
        self, alerts: List[Dict], days_back: int = 30
    ) -> Tuple[StageResult, Dict]:
        t0 = time.monotonic()

        from ci_platform.onboarding.deployment_qualification import DeploymentQualifier

        qualifier = DeploymentQualifier()
        qualification = qualifier.qualify(alerts, days_in_sample=days_back)

        config = {
            "tau_initial": qualification.tau.tau_optimal,
            "sigma_mean": qualification.noise.sigma_mean,
            "sigma_per_factor": qualification.noise.sigma_per_factor,
            "noise_classification": qualification.noise.classification,
            "learning_recommended": qualification.noise.learning_recommended,
            "recalibrate_tau": qualification.tau.recalibrate,
            "category_distribution": qualification.category_distribution,
            "alert_type_distribution": qualification.category_distribution,
            "estimated_category_distribution": qualification.category_distribution,
            "estimated_alert_volume": round(qualification.estimated_daily_volume, 2),
            "estimated_daily_volume": qualification.estimated_daily_volume,
            "remediations": [
                {
                    "factor": r.factor,
                    "current": r.current_noise,
                    "integration": r.integration,
                    "after": r.expected_noise_after,
                    "priority": r.priority,
                }
                for r in qualification.remediations
            ],
            "summary": qualification.summary,
        }

        dur = time.monotonic() - t0
        stage = StageResult(
            stage="compute", success=True,
            duration_seconds=dur,
            records_in=len(alerts), records_out=1,
            details={"qualification": config},
        )
        return stage, config


# ── helpers ───────────────────────────────────────────────────────────────────

def _infer_user_id_type(value: str) -> IdentifierType:
    if "@" in value:
        return IdentifierType.EMAIL
    if "\\" in value:
        return IdentifierType.SAM
    if value.startswith("S-1-"):
        return IdentifierType.SID
    return IdentifierType.DISPLAY_NAME


def _failed_result(stages: List[StageResult], t0: float) -> PipelineResult:
    return PipelineResult(
        success=False,
        stages=stages,
        total_duration_seconds=time.monotonic() - t0,
        alerts_imported=0,
        entities_resolved=0,
        redactions_applied=0,
        load_manifest=None,
        recommended_config=None,
    )
