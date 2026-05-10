"""Seed DataOps pipeline graph nodes into the shared AGE graph."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Literal

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from ci_platform.graph import AGEClient
from dataops.schema import (
    AFFECTS,
    CASCADES,
    CATEGORIES,
    DATASET_SYSTEM_MAP,
    DATA_QUALITY_ALERT,
    FEEDS,
    FEEDS_EDGES,
    PIPELINE_SYSTEM,
    SYSTEMS,
    SYSTEM_NAMES,
)

_S = AGEClient.serialize_for_age
SeedStatus = Literal["seeded", "skipped"]

PRIMARY_SEED_PATH = (
    REPO_ROOT.parent
    / "copilot-sdk"
    / "copilot_sdk"
    / "scoring"
    / "presets"
    / "dataops_seed.json"
)
FALLBACK_SEED_PATH = (
    REPO_ROOT.parent
    / "compounding-scorer"
    / "compounding_scorer"
    / "presets"
    / "dataops_seed.json"
)


def main() -> None:
    parser = argparse.ArgumentParser(description="Seed DataOps AGE graph namespace")
    parser.add_argument("--dry-run", action="store_true", help="validate inputs only")
    parser.add_argument("--force", action="store_true", help="replace existing DataOps graph")
    args = parser.parse_args()

    events = load_seed_events()
    alerts = [normalize_event(event, index) for index, event in enumerate(events, start=1)]
    summary = (
        f"Seeded: {len(SYSTEMS)} systems, {len(FEEDS_EDGES)} {FEEDS}, "
        f"{len(alerts)} alerts, {len(alerts)} {AFFECTS}"
    )

    if args.dry_run:
        print(f"Dry run OK: {summary}")
        return

    status = asyncio.run(seed_graph(alerts, force=args.force))
    if status == "seeded":
        print(summary)


def load_seed_events() -> list[dict[str, Any]]:
    seed_path = resolve_seed_path()
    events = json.loads(seed_path.read_text(encoding="utf-8"))
    if not isinstance(events, list) or len(events) != 20:
        raise ValueError(f"Expected 20 DataOps seed events in {seed_path}, got {len(events)}")
    return events


def resolve_seed_path() -> Path:
    if PRIMARY_SEED_PATH.exists():
        return PRIMARY_SEED_PATH
    if FALLBACK_SEED_PATH.exists():
        return FALLBACK_SEED_PATH
    raise FileNotFoundError(
        "DataOps seed JSON not found. Tried: "
        f"{PRIMARY_SEED_PATH} and {FALLBACK_SEED_PATH}"
    )


def normalize_event(event: dict[str, Any], index: int) -> dict[str, Any]:
    dataset = str(event.get("dataset") or "").strip()
    system_name = DATASET_SYSTEM_MAP.get(dataset)
    if system_name not in SYSTEM_NAMES:
        raise ValueError(f"No PipelineSystem mapping for dataset {dataset!r}")

    category = str(event.get("category") or "")
    if category not in CATEGORIES:
        raise ValueError(f"Unsupported DataOps category {category!r}")

    factors = event.get("factors")
    if not isinstance(factors, dict):
        raise ValueError(f"Seed event {event.get('event_id')} has invalid factors")

    return {
        "alert_id": f"DQ-{index:03d}",
        "source_event_id": str(event.get("event_id") or ""),
        "system_name": system_name,
        "dataset": dataset,
        "category": category,
        "severity": derive_severity(factors),
        "detected_at": "2026-05-08T00:00:00Z",
        "detected_at_epoch": 1778227200 + index,
        "recurrence_count": derive_recurrence_count(factors),
        "resolved": is_resolved(event),
        "action_taken": str(event.get("action_taken") or ""),
        "is_correct": bool(event.get("is_correct", False)),
        "impact_scope": float(factors.get("impact_scope", 0.0)),
        "source_reliability": float(factors.get("source_reliability", 0.0)),
        "recurrence_frequency": float(factors.get("recurrence_frequency", 0.0)),
        "downstream_urgency": float(factors.get("downstream_urgency", 0.0)),
        "data_freshness": float(factors.get("data_freshness", 0.0)),
        "business_criticality": float(factors.get("business_criticality", 0.0)),
        "factors_json": json.dumps(factors, sort_keys=True),
    }


def derive_severity(factors: dict[str, Any]) -> str:
    impact_scope = float(factors.get("impact_scope", 0.0))
    if impact_scope > 0.7:
        return "high"
    if impact_scope > 0.4:
        return "medium"
    return "low"


def derive_recurrence_count(factors: dict[str, Any]) -> int:
    recurrence_frequency = float(factors.get("recurrence_frequency", 0.0))
    if recurrence_frequency >= 0.8:
        return 12
    if recurrence_frequency >= 0.5:
        return 3
    return 0


def is_resolved(event: dict[str, Any]) -> bool:
    outcome = event.get("outcome")
    if outcome is not None:
        return str(outcome).lower() == "correct"
    return bool(event.get("is_correct", False))


async def seed_graph(alerts: list[dict[str, Any]], force: bool = False) -> SeedStatus:
    # GRAPH_DSN/DATABASE_URL select the PostgreSQL database; AGE_GRAPH_NAME selects the AGE graph used by cypher().
    dsn = os.environ.get("GRAPH_DSN") or os.environ.get("DATABASE_URL")
    graph_name = os.environ.get("AGE_GRAPH_NAME", "soc_graph")
    client = AGEClient(dsn=dsn, graph_name=graph_name)
    await client.ensure_graph()
    existing = await client.run_query(
        f"MATCH (s:{PIPELINE_SYSTEM}) RETURN count(s) AS cnt"
    )
    existing_count = int(existing[0].get("cnt") or 0) if existing else 0
    if existing_count and not force:
        print(f"DataOps graph already has {existing_count} PipelineSystem nodes; use --force to reseed")
        return "skipped"

    if force:
        await delete_dataops_graph(client)

    for system in SYSTEMS:
        await client.run_query(create_system_query(system))

    for source, target in FEEDS_EDGES:
        await client.run_query(create_feeds_query(source, target))

    for alert in alerts:
        await client.run_query(create_alert_query(alert))
        await client.run_query(create_affects_query(alert["alert_id"], alert["system_name"]))

    return "seeded"


async def delete_dataops_graph(client: AGEClient) -> None:
    delete_queries = [
        f"MATCH (a:{DATA_QUALITY_ALERT})-[r:{AFFECTS}]->(s:{PIPELINE_SYSTEM}) DELETE r",
        f"MATCH (s1:{PIPELINE_SYSTEM})-[r:{FEEDS}]->(s2:{PIPELINE_SYSTEM}) DELETE r",
        f"MATCH (s1:{PIPELINE_SYSTEM})-[r:{CASCADES}]->(s2:{PIPELINE_SYSTEM}) DELETE r",
        f"MATCH (a:{DATA_QUALITY_ALERT}) DELETE a",
        f"MATCH (s:{PIPELINE_SYSTEM}) DELETE s",
    ]
    for query in delete_queries:
        await client.run_query(query)


def create_system_query(system: dict[str, Any]) -> str:
    return f"""
CREATE (s:{PIPELINE_SYSTEM} {{
    name: {_S(system["name"])},
    display_name: {_S(system["display_name"])},
    sla_minutes: {int(system["sla_minutes"])},
    business_criticality: {float(system["business_criticality"])},
    source_reliability: {float(system["source_reliability"])},
    owner: {_S(system["owner"])},
    status: {_S(system.get("status", "active"))},
    last_run: {_S(system.get("last_run", ""))},
    description: {_S(system.get("description", ""))}
}})
RETURN s
"""


def create_feeds_query(source: str, target: str) -> str:
    return f"""
MATCH (source:{PIPELINE_SYSTEM} {{name: {_S(source)}}})
MATCH (target:{PIPELINE_SYSTEM} {{name: {_S(target)}}})
CREATE (source)-[r:{FEEDS} {{
    created_at_epoch: {int(time.time())},
    source_name: {_S(source)},
    target_name: {_S(target)}
}}]->(target)
RETURN r
"""


def create_alert_query(alert: dict[str, Any]) -> str:
    return f"""
CREATE (a:{DATA_QUALITY_ALERT} {{
    alert_id: {_S(alert["alert_id"])},
    source_event_id: {_S(alert["source_event_id"])},
    system_name: {_S(alert["system_name"])},
    dataset: {_S(alert["dataset"])},
    category: {_S(alert["category"])},
    severity: {_S(alert["severity"])},
    detected_at: {_S(alert["detected_at"])},
    detected_at_epoch: {int(alert["detected_at_epoch"])},
    recurrence_count: {int(alert["recurrence_count"])},
    resolved: {_S(bool(alert["resolved"]))},
    action_taken: {_S(alert["action_taken"])},
    is_correct: {_S(bool(alert["is_correct"]))},
    impact_scope: {float(alert["impact_scope"])},
    source_reliability: {float(alert["source_reliability"])},
    recurrence_frequency: {float(alert["recurrence_frequency"])},
    downstream_urgency: {float(alert["downstream_urgency"])},
    data_freshness: {float(alert["data_freshness"])},
    business_criticality: {float(alert["business_criticality"])},
    factors_json: {_S(alert["factors_json"])}
}})
RETURN a
"""


def create_affects_query(alert_id: str, system_name: str) -> str:
    return f"""
MATCH (a:{DATA_QUALITY_ALERT} {{alert_id: {_S(alert_id)}}})
MATCH (s:{PIPELINE_SYSTEM} {{name: {_S(system_name)}}})
CREATE (a)-[r:{AFFECTS} {{
    created_at_epoch: {int(time.time())},
    system_name: {_S(system_name)}
}}]->(s)
RETURN r
"""


if __name__ == "__main__":
    main()
