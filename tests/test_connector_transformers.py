import pytest

from ci_platform.connectors.transformers import (
    cmdb_criticality_to_float,
    dn_list_to_names,
    dn_to_username,
    get_transformer,
    yes_no_to_bool,
)


def test_cmdb_criticality_maps_labels_to_floats():
    assert cmdb_criticality_to_float("LOW") == 0.2
    assert cmdb_criticality_to_float("medium") == 0.4
    assert cmdb_criticality_to_float("MED") == 0.4
    assert cmdb_criticality_to_float("High") == 0.7
    assert cmdb_criticality_to_float("critical") == 1.0


def test_cmdb_criticality_maps_numeric_scale():
    assert cmdb_criticality_to_float(1) == 0.2
    assert cmdb_criticality_to_float(2) == 0.4
    assert cmdb_criticality_to_float(3) == 0.7
    assert cmdb_criticality_to_float(4) == 1.0
    assert cmdb_criticality_to_float(5) == 1.0


def test_cmdb_criticality_rejects_unknown_value():
    with pytest.raises(ValueError, match="severe"):
        cmdb_criticality_to_float("severe")


def test_yes_no_to_bool_case_insensitive():
    assert yes_no_to_bool("YES") is True
    assert yes_no_to_bool("y") is True
    assert yes_no_to_bool("True") is True
    assert yes_no_to_bool("1") is True
    assert yes_no_to_bool("NO") is False
    assert yes_no_to_bool("n") is False
    assert yes_no_to_bool("False") is False
    assert yes_no_to_bool("0") is False
    assert yes_no_to_bool(True) is True


def test_yes_no_to_bool_rejects_ambiguous_value():
    with pytest.raises(ValueError, match="maybe"):
        yes_no_to_bool("maybe")


def test_dn_to_username_extracts_cn():
    dn = "CN=Jane Doe,OU=Users,DC=example,DC=com"
    assert dn_to_username(dn) == "Jane Doe"


def test_dn_to_username_extracts_uid_when_cn_absent():
    dn = "uid=jdoe,ou=people,dc=example,dc=com"
    assert dn_to_username(dn) == "jdoe"


def test_dn_list_to_names_splits_and_extracts():
    assert dn_list_to_names(
        "CN=Finance,OU=Groups,DC=example,DC=com;CN=Approvers,OU=Groups,DC=example,DC=com"
    ) == ["Finance", "Approvers"]
    assert dn_list_to_names(
        [
            "CN=Managers,OU=Groups,DC=example,DC=com",
            "uid=auditors,ou=groups,dc=example,dc=com",
        ]
    ) == ["Managers", "auditors"]
    assert dn_list_to_names(None) == []


def test_get_transformer_rejects_unknown_name():
    with pytest.raises(ValueError, match="not_registered"):
        get_transformer("not_registered")
