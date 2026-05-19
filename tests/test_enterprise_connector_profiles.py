import json
from pathlib import Path

import pytest

from ci_platform.connectors.profiles import (
    EnterpriseConnectorProfile,
    ProfileBackedEntityAdapter,
    ProfileLoader,
)


FIXTURES = Path(__file__).parent / "fixtures"


VALID_CMDB_YAML = """
profile_type: CMDBConnectorProfile
tier: 1
cadence: daily
entity_type_produced: Asset
connection:
  base_url: https://cmdb.example/api
  auth_type: api_key
  api_key_env_var: CMDB_API_KEY
entity_mappings:
  - source_field: ci_id
    target_property: id
    required: true
  - source_field: ci_name
    target_property: name
    required: true
  - source_field: criticality_level
    target_property: criticality_score
    transformer: cmdb_criticality_to_float
    required: true
  - source_field: monitoring_status
    target_property: monitoring_active
    transformer: yes_no_to_bool
    required: false
semantic_registry_concept: critical_assets
validation_query: |
  MATCH (a:Asset) WHERE a.criticality_score IS NOT NULL
  RETURN count(a) AS count
"""


VALID_IDENTITY_YAML = """
profile_type: IdentityConnectorProfile
tier: 1
cadence: hourly
entity_type_produced: User
connection:
  source_type: ldap
  host: ldap.example.com
  port: 636
  bind_dn_env_var: LDAP_BIND_DN
  bind_pw_env_var: LDAP_BIND_PW
  base_dn: DC=example,DC=com
entity_mappings:
  - source_field: sAMAccountName
    target_property: id
    required: true
  - source_field: displayName
    target_property: name
    required: true
  - source_field: department
    target_property: department
    required: true
  - source_field: manager
    target_property: manager
    transformer: dn_to_username
    required: false
  - source_field: memberOf
    target_property: groups
    transformer: dn_list_to_names
    required: false
semantic_registry_concept: identity_context
"""


def _write_profile(tmp_path, content):
    path = tmp_path / "profile.yaml"
    path.write_text(content, encoding="utf-8")
    return path


def test_profile_loader_rejects_empty_yaml(tmp_path):
    path = _write_profile(tmp_path, "")

    with pytest.raises(ValueError, match="empty"):
        ProfileLoader.from_yaml(path)


def test_profile_loader_validates_required_fields(tmp_path):
    path = _write_profile(
        tmp_path,
        """
profile_type: CMDBConnectorProfile
tier: 1
cadence: daily
entity_type_produced: Asset
connection: {}
entity_mappings: []
""",
    )

    with pytest.raises(ValueError, match="semantic_registry_concept"):
        ProfileLoader.from_yaml(path)


def test_profile_loader_rejects_unknown_profile_type(tmp_path):
    path = _write_profile(
        tmp_path,
        VALID_CMDB_YAML.replace("CMDBConnectorProfile", "UnknownProfile", 1),
    )

    with pytest.raises(ValueError, match="UnknownProfile"):
        ProfileLoader.from_yaml(path)


def test_profile_loader_rejects_missing_entity_mappings(tmp_path):
    path = _write_profile(
        tmp_path,
        VALID_CMDB_YAML.replace("entity_mappings:", "entity_mappings: []\nunused:", 1),
    )

    with pytest.raises(ValueError, match="entity_mappings"):
        ProfileLoader.from_yaml(path)


def test_profile_loader_rejects_unknown_transformer(tmp_path):
    path = _write_profile(
        tmp_path,
        VALID_CMDB_YAML.replace("cmdb_criticality_to_float", "unknown_transformer"),
    )

    with pytest.raises(ValueError, match="unknown_transformer"):
        ProfileLoader.from_yaml(path)


def test_profile_loader_accepts_valid_cmdb_yaml(tmp_path):
    profile = ProfileLoader.from_yaml(_write_profile(tmp_path, VALID_CMDB_YAML))

    assert isinstance(profile, EnterpriseConnectorProfile)
    assert profile.profile_type == "CMDBConnectorProfile"
    assert profile.entity_type_produced == "Asset"
    assert profile.connection.base_url == "https://cmdb.example/api"
    assert profile.connection.auth_type == "api_key"
    assert profile.connection.api_key_env_var == "CMDB_API_KEY"
    assert profile.entity_mappings[2].transformer == "cmdb_criticality_to_float"
    assert profile.validation_query is not None


def test_profile_loader_accepts_valid_identity_yaml(tmp_path):
    profile = ProfileLoader.from_yaml(_write_profile(tmp_path, VALID_IDENTITY_YAML))

    assert profile.profile_type == "IdentityConnectorProfile"
    assert profile.entity_type_produced == "User"
    assert profile.connection.source_type == "ldap"
    assert profile.connection.host == "ldap.example.com"
    assert profile.connection.port == 636
    assert profile.entity_mappings[-1].transformer == "dn_list_to_names"


def test_profile_loader_rejects_cmdb_missing_required_connection_field(tmp_path):
    path = _write_profile(
        tmp_path,
        VALID_CMDB_YAML.replace("  api_key_env_var: CMDB_API_KEY\n", ""),
    )

    with pytest.raises(ValueError, match="api_key_env_var"):
        ProfileLoader.from_yaml(path)


def test_profile_loader_rejects_identity_missing_required_connection_field(tmp_path):
    path = _write_profile(
        tmp_path,
        VALID_IDENTITY_YAML.replace("  bind_pw_env_var: LDAP_BIND_PW\n", ""),
    )

    with pytest.raises(ValueError, match="bind_pw_env_var"):
        ProfileLoader.from_yaml(path)


def test_profile_loader_rejects_profile_entity_mismatch(tmp_path):
    path = _write_profile(
        tmp_path,
        VALID_CMDB_YAML.replace("entity_type_produced: Asset", "entity_type_produced: User"),
    )

    with pytest.raises(ValueError, match="CMDBConnectorProfile"):
        ProfileLoader.from_yaml(path)


def _load_fixture_records(name):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def test_cmdb_profile_maps_asset_node_properties():
    profile = ProfileLoader.from_yaml(FIXTURES / "cmdb_profile.yaml")
    records = _load_fixture_records("cmdb_records.json")

    nodes = ProfileBackedEntityAdapter(profile).map_records(records)

    assert {node["type"] for node in nodes} == {"Asset"}
    db_node = nodes[0]
    assert db_node["id"] == "CI-001"
    assert db_node["name"] == "db-prod-01"
    assert db_node["criticality_score"] == 1.0
    assert db_node["monitoring_active"] is True
    assert db_node["owner"] == "DBA"
    assert db_node["data_class"] == "confidential"
    staging_node = nodes[1]
    assert "monitoring_active" not in staging_node
    assert "owner" not in staging_node
    assert "data_class" not in staging_node


def test_identity_profile_maps_user_node_properties():
    profile = ProfileLoader.from_yaml(FIXTURES / "identity_profile.yaml")
    records = _load_fixture_records("identity_records.json")

    nodes = ProfileBackedEntityAdapter(profile).map_records(records)

    assert {node["type"] for node in nodes} == {"User"}
    jane = nodes[0]
    assert jane["id"] == "jdoe"
    assert jane["name"] == "Jane Doe"
    assert jane["department"] == "Engineering"
    assert jane["title"] == "Staff Engineer"
    assert jane["manager"] == "Bob Smith"
    assert jane["groups"] == ["Engineering", "VPN"]


def test_adapter_required_field_missing_raises():
    profile = ProfileLoader.from_yaml(FIXTURES / "cmdb_profile.yaml")
    record = _load_fixture_records("cmdb_records.json")[0]
    record.pop("ci_id")

    with pytest.raises(ValueError, match="ci_id"):
        ProfileBackedEntityAdapter(profile).map_record(record)


def test_adapter_optional_field_missing_omitted():
    profile = ProfileLoader.from_yaml(FIXTURES / "cmdb_profile.yaml")
    record = _load_fixture_records("cmdb_records.json")[1]

    node = ProfileBackedEntityAdapter(profile).map_record(record)

    assert "monitoring_active" not in node
    assert "owner" not in node
    assert "data_class" not in node


def test_adapter_transformer_applied():
    profile = ProfileLoader.from_yaml(FIXTURES / "cmdb_profile.yaml")
    records = _load_fixture_records("cmdb_records.json")

    nodes = ProfileBackedEntityAdapter(profile).map_records(records)

    assert nodes[0]["criticality_score"] == 1.0
    assert nodes[2]["criticality_score"] == 0.7
    assert nodes[2]["monitoring_active"] is False


def test_node_dict_has_id_and_type():
    cmdb_profile = ProfileLoader.from_yaml(FIXTURES / "cmdb_profile.yaml")
    identity_profile = ProfileLoader.from_yaml(FIXTURES / "identity_profile.yaml")
    cmdb_nodes = ProfileBackedEntityAdapter(cmdb_profile).map_records(
        _load_fixture_records("cmdb_records.json")
    )
    identity_nodes = ProfileBackedEntityAdapter(identity_profile).map_records(
        _load_fixture_records("identity_records.json")
    )

    for node in cmdb_nodes + identity_nodes:
        assert node["id"]
        assert node["type"] in {"Asset", "User"}


def test_round_trip_yaml_to_adapter_to_node_dicts():
    profile = ProfileLoader.from_yaml(FIXTURES / "identity_profile.yaml")
    records = _load_fixture_records("identity_records.json")

    nodes = ProfileBackedEntityAdapter(profile).map_records(records)

    assert len(nodes) == 3
    assert all({"id", "type", "name"}.issubset(node) for node in nodes)


def test_validation_query_present_in_cmdb_profile():
    cmdb_profile = ProfileLoader.from_yaml(FIXTURES / "cmdb_profile.yaml")
    identity_profile = ProfileLoader.from_yaml(FIXTURES / "identity_profile.yaml")

    assert cmdb_profile.validation_query is not None
    assert "MATCH (a:Asset)" in cmdb_profile.validation_query
    assert identity_profile.validation_query is None


def test_adapter_map_records_reports_record_index_on_error():
    profile = ProfileLoader.from_yaml(FIXTURES / "cmdb_profile.yaml")
    records = _load_fixture_records("cmdb_records.json")
    records[1].pop("ci_name")

    with pytest.raises(ValueError, match="Record 1"):
        ProfileBackedEntityAdapter(profile).map_records(records)
