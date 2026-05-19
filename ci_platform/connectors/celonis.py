"""Offline Celonis process fixture parsing and manifest building.

This module intentionally avoids live Celonis access. It maps deterministic
process fixture data into LoadManifest-shaped dicts for later
connector/onboarding integration.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from json import JSONDecodeError
from pathlib import Path
from typing import Any, Callable

import httpx


PROCESS_NODE_TYPES = {"ProcessModel", "ProcessVariant", "Activity", "Transition"}
INTRA_PROCESS_EDGES = {
    "HAS_VARIANT",
    "CONTAINS",
    "TRANSITION_FROM",
    "TRANSITION_TO",
}
CROSS_DOMAIN_EDGES = {"BOTTLENECK_AT", "TRIGGERED_BY", "INVOICE_PATTERN"}
_FALSE_VALUES = {"0", "false", "no", "off"}
_TRUE_VALUES = {"1", "true", "yes", "on"}

_PROCESS_MODEL_FIELDS = {
    "id",
    "name",
    "case_count",
    "variant_count",
    "source",
    "extracted_at",
}
_PROCESS_VARIANT_FIELDS = {
    "id",
    "process_model_id",
    "frequency",
    "avg_duration",
    "conformance_rate",
    "activity_ids",
}
_ACTIVITY_FIELDS = {
    "id",
    "name",
    "avg_duration",
    "automation_rate",
    "rework_rate",
}
_TRANSITION_FIELDS = {
    "id",
    "from_activity",
    "to_activity",
    "frequency",
    "wait_time",
    "conformance",
}


@dataclass
class CelonisConfig:
    base_url: str | None = None
    api_token: str | None = None
    data_pool_id: str | None = None
    process_model_id: str | None = None
    use_fixture_fallback: bool = True

    @classmethod
    def from_env(cls) -> "CelonisConfig":
        return cls(
            base_url=os.getenv("CELONIS_BASE_URL"),
            api_token=os.getenv("CELONIS_API_TOKEN"),
            data_pool_id=os.getenv("CELONIS_DATA_POOL_ID"),
            process_model_id=os.getenv("CELONIS_PROCESS_MODEL_ID"),
            use_fixture_fallback=_parse_env_bool(
                os.getenv("CELONIS_USE_FIXTURE_FALLBACK"),
                default=True,
            ),
        )


@dataclass(frozen=True)
class ProcessFixture:
    process_models: list[dict[str, Any]]
    variants: list[dict[str, Any]]
    activities: list[dict[str, Any]]
    transitions: list[dict[str, Any]]

    @classmethod
    def from_json(cls, path: str | Path) -> "ProcessFixture":
        fixture_path = Path(path)
        try:
            raw = json.loads(fixture_path.read_text(encoding="utf-8"))
        except JSONDecodeError as exc:
            raise ValueError(f"Invalid process fixture JSON in {fixture_path}: {exc}") from exc

        if not isinstance(raw, dict):
            raise ValueError("Process fixture JSON must be a top-level mapping")

        required_keys = ("process_models", "variants", "activities", "transitions")
        for key in required_keys:
            if key not in raw:
                raise ValueError(f"Process fixture missing required top-level key: {key}")
            if not isinstance(raw[key], list):
                raise ValueError(f"Process fixture top-level key {key} must be a list")

        fixture = cls(
            process_models=_copy_records(raw["process_models"], "ProcessModel"),
            variants=_copy_records(raw["variants"], "ProcessVariant"),
            activities=_copy_records(raw["activities"], "Activity"),
            transitions=_copy_records(raw["transitions"], "Transition"),
        )
        fixture._validate()
        return fixture

    def _validate(self) -> None:
        _validate_required_fields("ProcessModel", self.process_models, _PROCESS_MODEL_FIELDS)
        _validate_required_fields("ProcessVariant", self.variants, _PROCESS_VARIANT_FIELDS)
        _validate_required_fields("Activity", self.activities, _ACTIVITY_FIELDS)
        _validate_required_fields("Transition", self.transitions, _TRANSITION_FIELDS)

        model_ids = _validate_unique_ids("ProcessModel", self.process_models)
        _validate_unique_ids("ProcessVariant", self.variants)
        activity_ids = _validate_unique_ids("Activity", self.activities)
        _validate_unique_ids("Transition", self.transitions)

        for index, variant in enumerate(self.variants):
            model_id = variant["process_model_id"]
            if model_id not in model_ids:
                raise ValueError(
                    "ProcessVariant record "
                    f"{index} has invalid process_model_id reference: {model_id}"
                )
            activity_id_list = variant["activity_ids"]
            if not isinstance(activity_id_list, list):
                raise ValueError(
                    f"ProcessVariant record {index} field activity_ids must be a list"
                )
            for activity_id in activity_id_list:
                if activity_id not in activity_ids:
                    raise ValueError(
                        "ProcessVariant record "
                        f"{index} has invalid activity_ids reference: {activity_id}"
                    )

        for index, transition in enumerate(self.transitions):
            from_activity = transition["from_activity"]
            to_activity = transition["to_activity"]
            if from_activity not in activity_ids:
                raise ValueError(
                    "Transition record "
                    f"{index} has invalid from_activity reference: {from_activity}"
                )
            if to_activity not in activity_ids:
                raise ValueError(
                    "Transition record "
                    f"{index} has invalid to_activity reference: {to_activity}"
                )


class ProcessManifestBuilder:
    def __init__(self, fixture: ProcessFixture):
        self._fixture = fixture

    def build(self) -> dict[str, Any]:
        return {
            "nodes": self._build_nodes(),
            "relationships": self._build_relationships(),
            "entity_map": {},
            "stats": self._build_stats(),
        }

    def _build_nodes(self) -> list[dict[str, Any]]:
        nodes: list[dict[str, Any]] = []
        for record in self._fixture.process_models:
            nodes.append({**record, "type": "ProcessModel"})
        for record in self._fixture.variants:
            nodes.append({**record, "type": "ProcessVariant"})
        for record in self._fixture.activities:
            nodes.append({**record, "type": "Activity"})
        for record in self._fixture.transitions:
            nodes.append({**record, "type": "Transition"})
        return nodes

    def _build_relationships(self) -> list[dict[str, Any]]:
        relationships: list[dict[str, Any]] = []

        for variant in self._fixture.variants:
            relationships.append(
                {
                    "source": variant["process_model_id"],
                    "target": variant["id"],
                    "type": "HAS_VARIANT",
                }
            )

        for variant in self._fixture.variants:
            for activity_id in variant["activity_ids"]:
                relationships.append(
                    {
                        "source": variant["id"],
                        "target": activity_id,
                        "type": "CONTAINS",
                    }
                )

        for transition in self._fixture.transitions:
            relationships.append(
                {
                    "source": transition["from_activity"],
                    "target": transition["id"],
                    "type": "TRANSITION_FROM",
                }
            )
            relationships.append(
                {
                    "source": transition["id"],
                    "target": transition["to_activity"],
                    "type": "TRANSITION_TO",
                }
            )

        return relationships

    def _build_stats(self) -> dict[str, Any]:
        node_types = {
            "Activity": len(self._fixture.activities),
            "ProcessModel": len(self._fixture.process_models),
            "ProcessVariant": len(self._fixture.variants),
            "Transition": len(self._fixture.transitions),
        }
        edge_types = {
            "CONTAINS": sum(len(variant["activity_ids"]) for variant in self._fixture.variants),
            "HAS_VARIANT": len(self._fixture.variants),
            "TRANSITION_FROM": len(self._fixture.transitions),
            "TRANSITION_TO": len(self._fixture.transitions),
        }
        return {
            "node_count": sum(node_types.values()),
            "relationship_count": sum(edge_types.values()),
            "node_types": node_types,
            "edge_types": edge_types,
            "process_model_count": len(self._fixture.process_models),
            "variant_count": len(self._fixture.variants),
            "activity_count": len(self._fixture.activities),
            "transition_count": len(self._fixture.transitions),
        }


def _copy_records(records: Any, record_type: str) -> list[dict[str, Any]]:
    copied: list[dict[str, Any]] = []
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            raise ValueError(f"{record_type} record {index} must be a mapping")
        copied.append(dict(record))
    return copied


def _validate_required_fields(
    record_type: str,
    records: list[dict[str, Any]],
    required_fields: set[str],
) -> None:
    for index, record in enumerate(records):
        for field in sorted(required_fields):
            if field not in record:
                raise ValueError(
                    f"{record_type} record {index} missing required field: {field}"
                )


def _validate_unique_ids(record_type: str, records: list[dict[str, Any]]) -> set[Any]:
    ids: set[Any] = set()
    for index, record in enumerate(records):
        record_id = record["id"]
        if record_id in ids:
            raise ValueError(f"{record_type} record {index} has duplicate id: {record_id}")
        ids.add(record_id)
    return ids


class CelonisProcessConnector:
    """Process mining connector with lazy live-client paths and fixture fallback."""

    def __init__(
        self,
        config: CelonisConfig | None = None,
        fixture_path: str | Path | None = None,
    ):
        self._config = config or CelonisConfig()
        self._fixture_path = Path(fixture_path) if fixture_path else None
        self._source: str | None = None
        self._last_reason: str | None = None

    async def connect(self) -> None:
        if self._source:
            return

        if self._is_configured():
            if self._try_pycelonis():
                self._source = "pycelonis"
                return
            self._source = "rest"
            return

        if self._can_use_fixture():
            self._source = "fixture"

    async def health_check(self) -> dict[str, Any]:
        await self.connect()
        if self._source == "fixture":
            result: dict[str, Any] = {"status": "degraded", "source": "fixture"}
            if self._last_reason:
                result["reason"] = self._last_reason
            return result
        if self._source == "rest":
            try:
                await self._fetch_via_rest("health")
            except ConnectionError as exc:
                if self._can_use_fixture():
                    self._source = "fixture"
                    self._last_reason = str(exc)
                    return {
                        "status": "degraded",
                        "source": "fixture",
                        "reason": str(exc),
                    }
                return {"status": "error", "source": "rest", "reason": str(exc)}
            except ValueError as exc:
                return {"status": "error", "source": "rest", "reason": str(exc)}
            return {"status": "ok", "source": "rest"}
        if self._source == "pycelonis":
            return {"status": "ok", "source": "pycelonis"}
        return {"status": "not_configured", "source": None}

    async def fetch_process_models(self) -> list[dict[str, Any]]:
        await self.connect()
        if self._source == "fixture":
            return list(self._fetch_from_fixture().process_models)
        if self._source == "rest":
            return await self._fetch_list_with_fallback(
                "process_models",
                "process_models",
                "ProcessModel",
                _PROCESS_MODEL_FIELDS,
                lambda: list(self._fetch_from_fixture().process_models),
            )
        if self._source == "pycelonis":
            raise NotImplementedError(
                "pycelonis process fetch is deferred; use REST or fixture fallback"
            )
        raise ConnectionError("CelonisProcessConnector is not configured")

    async def fetch_variants(self, process_model_id: str) -> list[dict[str, Any]]:
        await self.connect()
        if self._source == "fixture":
            return [
                variant
                for variant in self._fetch_from_fixture().variants
                if variant["process_model_id"] == process_model_id
            ]
        if self._source == "rest":
            return await self._fetch_list_with_fallback(
                "variants",
                f"process_models/{process_model_id}/variants",
                "ProcessVariant",
                _PROCESS_VARIANT_FIELDS,
                lambda: [
                    variant
                    for variant in self._fetch_from_fixture().variants
                    if variant["process_model_id"] == process_model_id
                ],
            )
        if self._source == "pycelonis":
            raise NotImplementedError(
                "pycelonis variant fetch is deferred; use REST or fixture fallback"
            )
        raise ConnectionError("CelonisProcessConnector is not configured")

    async def fetch_activities(
        self,
        process_model_id: str,
        variant_id: str | None = None,
    ) -> list[dict[str, Any]]:
        await self.connect()
        if self._source == "fixture":
            fixture = self._fetch_from_fixture()
            activity_ids = _activity_ids_for_variants(
                fixture.variants,
                process_model_id,
                variant_id,
            )
            return [
                activity
                for activity in fixture.activities
                if activity["id"] in activity_ids
            ]
        if self._source == "rest":
            endpoint = f"process_models/{process_model_id}/activities"
            if variant_id:
                endpoint = f"{endpoint}?variant_id={variant_id}"
            return await self._fetch_list_with_fallback(
                "activities",
                endpoint,
                "Activity",
                _ACTIVITY_FIELDS,
                lambda: [
                    activity
                    for activity in self._fetch_from_fixture().activities
                    if activity["id"]
                    in _activity_ids_for_variants(
                        self._fetch_from_fixture().variants,
                        process_model_id,
                        variant_id,
                    )
                ],
            )
        if self._source == "pycelonis":
            raise NotImplementedError(
                "pycelonis activity fetch is deferred; use REST or fixture fallback"
            )
        raise ConnectionError("CelonisProcessConnector is not configured")

    async def fetch_transitions(
        self,
        process_model_id: str,
        variant_id: str | None = None,
    ) -> list[dict[str, Any]]:
        await self.connect()
        if self._source == "fixture":
            fixture = self._fetch_from_fixture()
            activity_ids = _activity_ids_for_variants(
                fixture.variants,
                process_model_id,
                variant_id,
            )
            return [
                transition
                for transition in fixture.transitions
                if transition["from_activity"] in activity_ids
                and transition["to_activity"] in activity_ids
            ]
        if self._source == "rest":
            endpoint = f"process_models/{process_model_id}/transitions"
            if variant_id:
                endpoint = f"{endpoint}?variant_id={variant_id}"
            return await self._fetch_list_with_fallback(
                "transitions",
                endpoint,
                "Transition",
                _TRANSITION_FIELDS,
                lambda: [
                    transition
                    for transition in self._fetch_from_fixture().transitions
                    if transition["from_activity"]
                    in _activity_ids_for_variants(
                        self._fetch_from_fixture().variants,
                        process_model_id,
                        variant_id,
                    )
                    and transition["to_activity"]
                    in _activity_ids_for_variants(
                        self._fetch_from_fixture().variants,
                        process_model_id,
                        variant_id,
                    )
                ],
            )
        if self._source == "pycelonis":
            raise NotImplementedError(
                "pycelonis transition fetch is deferred; use REST or fixture fallback"
            )
        raise ConnectionError("CelonisProcessConnector is not configured")

    async def to_process_manifest(self) -> dict[str, Any]:
        await self.connect()
        process_models = await self.fetch_process_models()
        variants: list[dict[str, Any]] = []
        activities: list[dict[str, Any]] = []
        transitions: list[dict[str, Any]] = []

        for process_model in process_models:
            process_model_id = process_model["id"]
            _extend_unique(variants, await self.fetch_variants(process_model_id))
            _extend_unique(activities, await self.fetch_activities(process_model_id))
            _extend_unique(transitions, await self.fetch_transitions(process_model_id))

        fixture = ProcessFixture(
            process_models=list(process_models),
            variants=variants,
            activities=activities,
            transitions=transitions,
        )
        fixture._validate()
        return ProcessManifestBuilder(fixture).build()

    def _is_configured(self) -> bool:
        return bool(self._config.base_url and self._config.api_token)

    def _can_use_fixture(self) -> bool:
        return bool(self._config.use_fixture_fallback and self._fixture_path)

    def _try_pycelonis(self) -> bool:
        if not self._is_configured():
            return False
        try:
            import pycelonis  # type: ignore  # noqa: F401
        except ImportError:
            return False
        return True

    async def _fetch_list_with_fallback(
        self,
        key: str,
        endpoint: str,
        record_type: str,
        required_fields: set[str],
        fallback: Callable[[], list[dict[str, Any]]],
    ) -> list[dict[str, Any]]:
        try:
            payload = await self._fetch_via_rest(endpoint)
        except ConnectionError as exc:
            if self._can_use_fixture():
                self._source = "fixture"
                self._last_reason = str(exc)
                return fallback()
            raise
        return _extract_record_list(payload, key, record_type, required_fields)

    async def _fetch_via_rest(self, endpoint: str) -> dict[str, Any]:
        if not self._config.base_url or not self._config.api_token:
            raise ConnectionError("Celonis REST source is not configured")

        url = f"{self._config.base_url.rstrip('/')}/{endpoint.lstrip('/')}"
        headers = {"Authorization": f"Bearer {self._config.api_token}"}
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(url, headers=headers, timeout=30.0)
        except httpx.HTTPError as exc:
            raise ConnectionError(f"Celonis REST request failed: {exc}") from exc

        status_code = getattr(response, "status_code", None)
        if not isinstance(status_code, int) or not 200 <= status_code < 300:
            raise ConnectionError(f"Celonis REST request returned status {status_code}")

        try:
            payload = response.json()
        except ValueError as exc:
            raise ValueError("Celonis REST response did not contain valid JSON") from exc
        if not isinstance(payload, dict):
            raise ValueError("Celonis REST response must be a JSON object")
        return payload

    def _fetch_from_fixture(self) -> ProcessFixture:
        if not self._fixture_path:
            raise ConnectionError("Celonis fixture fallback is enabled but no fixture path was provided")
        return ProcessFixture.from_json(self._fixture_path)


def _parse_env_bool(value: str | None, default: bool) -> bool:
    if value is None:
        return default
    normalized = value.strip().lower()
    if normalized in _TRUE_VALUES:
        return True
    if normalized in _FALSE_VALUES:
        return False
    raise ValueError(f"Invalid boolean value for CELONIS_USE_FIXTURE_FALLBACK: {value}")


def _extract_record_list(
    payload: dict[str, Any],
    key: str,
    record_type: str,
    required_fields: set[str],
) -> list[dict[str, Any]]:
    records = payload.get(key)
    if not isinstance(records, list):
        raise ValueError(f"Celonis REST response missing list field: {key}")
    copied = _copy_records(records, record_type)
    _validate_required_fields(record_type, copied, required_fields)
    return copied


def _activity_ids_for_variants(
    variants: list[dict[str, Any]],
    process_model_id: str,
    variant_id: str | None,
) -> set[Any]:
    selected = [
        variant
        for variant in variants
        if variant["process_model_id"] == process_model_id
        and (variant_id is None or variant["id"] == variant_id)
    ]
    activity_ids: set[Any] = set()
    for variant in selected:
        activity_ids.update(variant["activity_ids"])
    return activity_ids


def _extend_unique(target: list[dict[str, Any]], records: list[dict[str, Any]]) -> None:
    seen = {record["id"] for record in target}
    for record in records:
        if record["id"] not in seen:
            target.append(record)
            seen.add(record["id"])
