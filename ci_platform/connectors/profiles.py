"""YAML-backed enterprise connector profile schemas."""

from __future__ import annotations

from dataclasses import dataclass
from importlib import import_module
from pathlib import Path
from typing import Any, cast

from ci_platform.connectors.transformers import TRANSFORMER_REGISTRY, get_transformer


def _load_yaml_module() -> Any:
    try:
        return import_module("yaml")
    except ImportError:  # pragma: no cover - exercised only without PyYAML installed
        return None


yaml = cast(Any, _load_yaml_module())


PROFILE_TYPES = {"CMDBConnectorProfile", "IdentityConnectorProfile"}
CADENCES = {"hourly", "daily"}
ENTITY_TYPES = {"Asset", "User"}
CMDB_AUTH_TYPES = {"api_key", "oauth2", "basic"}
IDENTITY_SOURCE_TYPES = {"ldap", "ad", "okta", "hr_api"}


@dataclass(frozen=True)
class EntityMapping:
    source_field: str
    target_property: str
    required: bool = True
    transformer: str | None = None


@dataclass(frozen=True)
class ConnectionConfig:
    base_url: str | None = None
    auth_type: str | None = None
    api_key_env_var: str | None = None
    source_type: str | None = None
    host: str | None = None
    port: int | None = None
    bind_dn_env_var: str | None = None
    bind_pw_env_var: str | None = None
    base_dn: str | None = None


@dataclass(frozen=True)
class EnterpriseConnectorProfile:
    profile_type: str
    tier: int
    cadence: str
    entity_type_produced: str
    connection: ConnectionConfig
    entity_mappings: list[EntityMapping]
    semantic_registry_concept: str
    validation_query: str | None = None


class ProfileLoader:
    """Load and validate enterprise connector YAML profiles."""

    @staticmethod
    def from_yaml(path: str | Path) -> EnterpriseConnectorProfile:
        if yaml is None:
            raise RuntimeError("PyYAML is required to load enterprise connector profiles")

        profile_path = Path(path)
        try:
            data = yaml.safe_load(profile_path.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            raise ValueError(f"Invalid YAML in {profile_path}: {exc}") from exc

        if data is None:
            raise ValueError("Enterprise connector profile YAML is empty")
        if not isinstance(data, dict):
            raise ValueError("Enterprise connector profile YAML must be a mapping")

        return _profile_from_mapping(data)


class ProfileBackedEntityAdapter:
    """Maps source records to LoadManifest-compatible node dicts."""

    def __init__(self, profile: EnterpriseConnectorProfile):
        self._profile = profile

    def map_record(self, record: dict[str, Any]) -> dict[str, Any]:
        """Map one source record to a LoadManifest.nodes-style node dict."""
        node: dict[str, Any] = {"type": self._profile.entity_type_produced}

        for mapping in self._profile.entity_mappings:
            value = record.get(mapping.source_field)
            if _is_absent(value):
                if mapping.required:
                    raise ValueError(f"Missing required source field: {mapping.source_field}")
                continue

            if mapping.transformer:
                transformer = get_transformer(mapping.transformer)
                try:
                    value = transformer(value)
                except ValueError as exc:
                    raise ValueError(
                        "Transformer "
                        f"{mapping.transformer!r} failed for source field "
                        f"{mapping.source_field!r}: {exc}"
                    ) from exc

            node[mapping.target_property] = value

        node_id = node.get("id")
        if _is_absent(node_id):
            raise ValueError("Mapped node must include a non-empty id")
        return node

    def map_records(self, records: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Map all records, failing with record index context on errors."""
        nodes = []
        for index, record in enumerate(records):
            try:
                nodes.append(self.map_record(record))
            except ValueError as exc:
                raise ValueError(f"Record {index} failed to map: {exc}") from exc
        return nodes


def _profile_from_mapping(data: dict[str, Any]) -> EnterpriseConnectorProfile:
    required_fields = {
        "profile_type",
        "tier",
        "cadence",
        "entity_type_produced",
        "connection",
        "entity_mappings",
        "semantic_registry_concept",
    }
    missing = sorted(field for field in required_fields if field not in data)
    if missing:
        raise ValueError(f"Missing required profile field(s): {', '.join(missing)}")

    profile_type = _require_str(data["profile_type"], "profile_type")
    if profile_type not in PROFILE_TYPES:
        raise ValueError(f"Unsupported profile_type: {profile_type}")

    tier = data["tier"]
    if isinstance(tier, bool) or not isinstance(tier, int):
        raise ValueError("tier must be an integer")
    if tier != 1:
        raise ValueError("Only tier 1 enterprise connector profiles are currently supported")

    cadence = _require_str(data["cadence"], "cadence")
    if cadence not in CADENCES:
        raise ValueError(f"Unsupported cadence: {cadence}")

    entity_type = _require_str(data["entity_type_produced"], "entity_type_produced")
    if entity_type not in ENTITY_TYPES:
        raise ValueError(f"Unsupported entity_type_produced: {entity_type}")
    _validate_profile_entity_consistency(profile_type, entity_type)

    semantic_concept = _require_str(
        data["semantic_registry_concept"],
        "semantic_registry_concept",
    )
    validation_query = data.get("validation_query")
    if validation_query is not None and not isinstance(validation_query, str):
        raise ValueError("validation_query must be a string when provided")

    connection_data = data["connection"]
    if not isinstance(connection_data, dict):
        raise ValueError("connection must be a mapping")
    connection = _connection_from_mapping(profile_type, connection_data)

    mappings = _mappings_from_sequence(data["entity_mappings"])

    return EnterpriseConnectorProfile(
        profile_type=profile_type,
        tier=tier,
        cadence=cadence,
        entity_type_produced=entity_type,
        connection=connection,
        entity_mappings=mappings,
        semantic_registry_concept=semantic_concept,
        validation_query=validation_query,
    )


def _is_absent(value: Any) -> bool:
    return value is None or (isinstance(value, str) and not value.strip())


def _connection_from_mapping(profile_type: str, data: dict[str, Any]) -> ConnectionConfig:
    port = data.get("port")
    if port is not None and (isinstance(port, bool) or not isinstance(port, int)):
        raise ValueError("connection.port must be an integer when provided")

    config = ConnectionConfig(
        base_url=_optional_str(data.get("base_url"), "connection.base_url"),
        auth_type=_optional_str(data.get("auth_type"), "connection.auth_type"),
        api_key_env_var=_optional_str(data.get("api_key_env_var"), "connection.api_key_env_var"),
        source_type=_optional_str(data.get("source_type"), "connection.source_type"),
        host=_optional_str(data.get("host"), "connection.host"),
        port=port,
        bind_dn_env_var=_optional_str(data.get("bind_dn_env_var"), "connection.bind_dn_env_var"),
        bind_pw_env_var=_optional_str(data.get("bind_pw_env_var"), "connection.bind_pw_env_var"),
        base_dn=_optional_str(data.get("base_dn"), "connection.base_dn"),
    )

    if profile_type == "CMDBConnectorProfile":
        _validate_cmdb_connection(config)
    else:
        _validate_identity_connection(config)
    return config


def _validate_cmdb_connection(config: ConnectionConfig) -> None:
    if not config.base_url:
        raise ValueError("CMDBConnectorProfile connection.base_url is required")
    if config.auth_type not in CMDB_AUTH_TYPES:
        raise ValueError(
            "CMDBConnectorProfile connection.auth_type must be one of: "
            f"{', '.join(sorted(CMDB_AUTH_TYPES))}"
        )
    if config.auth_type == "api_key" and not config.api_key_env_var:
        raise ValueError("CMDBConnectorProfile connection.api_key_env_var is required for api_key auth")


def _validate_identity_connection(config: ConnectionConfig) -> None:
    if config.source_type not in IDENTITY_SOURCE_TYPES:
        raise ValueError(
            "IdentityConnectorProfile connection.source_type must be one of: "
            f"{', '.join(sorted(IDENTITY_SOURCE_TYPES))}"
        )
    if config.source_type in {"okta", "hr_api"}:
        raise ValueError(
            f"IdentityConnectorProfile source_type {config.source_type!r} is reserved for a future adapter"
        )
    missing = [
        name
        for name, value in {
            "host": config.host,
            "port": config.port,
            "bind_dn_env_var": config.bind_dn_env_var,
            "bind_pw_env_var": config.bind_pw_env_var,
            "base_dn": config.base_dn,
        }.items()
        if value in (None, "")
    ]
    if missing:
        raise ValueError(
            "IdentityConnectorProfile LDAP/AD connection missing required field(s): "
            f"{', '.join(missing)}"
        )


def _mappings_from_sequence(value: Any) -> list[EntityMapping]:
    if not isinstance(value, list) or not value:
        raise ValueError("entity_mappings must be a non-empty list")

    mappings = []
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            raise ValueError(f"entity_mappings[{index}] must be a mapping")
        for field in ("source_field", "target_property", "required"):
            if field not in item:
                raise ValueError(f"entity_mappings[{index}] missing required field: {field}")

        source_field = _require_str(item["source_field"], f"entity_mappings[{index}].source_field")
        target_property = _require_str(
            item["target_property"],
            f"entity_mappings[{index}].target_property",
        )
        required = item["required"]
        if not isinstance(required, bool):
            raise ValueError(f"entity_mappings[{index}].required must be a boolean")

        transformer = item.get("transformer")
        if transformer is not None:
            transformer = _require_str(transformer, f"entity_mappings[{index}].transformer")
            if transformer not in TRANSFORMER_REGISTRY:
                raise ValueError(f"Unknown transformer in entity_mappings[{index}]: {transformer}")

        mappings.append(
            EntityMapping(
                source_field=source_field,
                target_property=target_property,
                required=required,
                transformer=transformer,
            )
        )
    return mappings


def _validate_profile_entity_consistency(profile_type: str, entity_type: str) -> None:
    expected = {
        "CMDBConnectorProfile": "Asset",
        "IdentityConnectorProfile": "User",
    }[profile_type]
    if entity_type != expected:
        raise ValueError(f"{profile_type} must produce entity_type_produced={expected}")


def _require_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string")
    return value.strip()


def _optional_str(value: Any, field_name: str) -> str | None:
    if value is None:
        return None
    return _require_str(value, field_name)
