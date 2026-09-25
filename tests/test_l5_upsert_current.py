from __future__ import annotations

from typing import Any

import pytest


pytestmark = pytest.mark.age


L5_CASES = [
    (
        "L5Centroid",
        {"domain": "soc", "category": "credential_access", "action": "investigate"},
        {"vector_json": "[0.1]", "delta_norm": 0.2},
        "SHAPED_BY",
    ),
    (
        "L5ConservationState",
        {"domain": "soc"},
        {"status": "GREEN"},
        "TRIGGERED_BY",
    ),
    (
        "L5DKWeight",
        {"domain": "soc"},
        {"weight_json": "[[0.1]]"},
        None,
    ),
]


def _literal(store: Any, value: object) -> str:
    return store._S(value)


def _where(store: Any, alias: str, identity: dict[str, object]) -> str:
    return " AND ".join(
        f"{alias}.{key} = {_literal(store, value)}" for key, value in identity.items()
    )


def _nodes(store: Any, label: str, identity: dict[str, object]) -> list[dict[str, Any]]:
    rows = store._run_query(
        f"""
        MATCH (n:{label})
        WHERE {_where(store, "n", identity)}
        RETURN n
        ORDER BY n.updated_at_epoch
        """
    )
    return [store._node_to_dict(row.get("n")) for row in rows]


def _edges(store: Any, edge_type: str) -> list[dict[str, Any]]:
    rows = store._run_query(
        f"""
        MATCH (n)-[r:{edge_type}]->(t)
        RETURN n, r, t
        ORDER BY n.domain, t.decision_id
        """
    )
    return [
        {
            "source": store._node_to_dict(row.get("n")),
            "relationship": store._node_to_dict(row.get("r")),
            "target": store._node_to_dict(row.get("t")),
        }
        for row in rows
    ]


def _write_decision(store: Any, decision_id: str, domain: str = "soc") -> str:
    return store.write_decision(
        domain,
        "credential_access",
        "investigate",
        0.8,
        {"signal": 1.0},
        metadata={"decision_id": decision_id},
    )


def _target_id(edge_type: str | None) -> dict[str, str]:
    return {"domain": "soc", "decision_id": f"{edge_type or 'NOEDGE'}-DEC"}


@pytest.mark.parametrize("label,identity,properties,edge_type", L5_CASES)
def test_l5_upsert_create_fresh(
    age_store: Any,
    label: str,
    identity: dict[str, object],
    properties: dict[str, object],
    edge_type: str | None,
) -> None:
    age_store._l5_upsert_current(label, identity, properties, edge_type=edge_type)

    nodes = _nodes(age_store, label, identity)
    assert len(nodes) == 1
    for key, value in {**identity, **properties}.items():
        assert nodes[0][key] == value


@pytest.mark.parametrize("label,identity,properties,edge_type", L5_CASES)
def test_l5_upsert_set_existing(
    age_store: Any,
    label: str,
    identity: dict[str, object],
    properties: dict[str, object],
    edge_type: str | None,
) -> None:
    age_store._l5_upsert_current(label, identity, {"stale": "old"}, edge_type=edge_type)
    age_store._l5_upsert_current(label, identity, properties, edge_type=edge_type)

    nodes = _nodes(age_store, label, identity)
    assert len(nodes) == 1
    for key, value in properties.items():
        assert nodes[0][key] == value


@pytest.mark.parametrize("label,identity,properties,edge_type", L5_CASES)
def test_l5_upsert_replace_edge(
    age_store: Any,
    label: str,
    identity: dict[str, object],
    properties: dict[str, object],
    edge_type: str | None,
) -> None:
    _write_decision(age_store, "OLD")
    _write_decision(age_store, _target_id(edge_type)["decision_id"])
    if edge_type:
        age_store._l5_upsert_current(
            label,
            identity,
            {"stale": "old"},
            edge_type=edge_type,
            edge_target_id={"domain": "soc", "decision_id": "OLD"},
        )

    age_store._l5_upsert_current(
        label,
        identity,
        properties,
        edge_type=edge_type,
        edge_target_id=_target_id(edge_type),
    )

    nodes = _nodes(age_store, label, identity)
    assert len(nodes) == 1
    if edge_type:
        edges = _edges(age_store, edge_type)
        assert len(edges) == 1
        assert edges[0]["target"]["decision_id"] == _target_id(edge_type)["decision_id"]
    else:
        assert not _edges(age_store, "SHAPED_BY")


@pytest.mark.parametrize("label,identity,properties,edge_type", L5_CASES)
def test_l5_upsert_cleanup_duplicates(
    age_store: Any,
    label: str,
    identity: dict[str, object],
    properties: dict[str, object],
    edge_type: str | None,
) -> None:
    _write_decision(age_store, _target_id(edge_type)["decision_id"])
    for stale in ("first", "second", "third"):
        age_store._run_query(
            f"""
            CREATE (n:{label} {{{", ".join(f"{key}: {_literal(age_store, value)}" for key, value in {**identity, "stale": stale}.items())}}})
            RETURN n
            """
        )

    age_store._l5_upsert_current(
        label,
        identity,
        properties,
        edge_type=edge_type,
        edge_target_id=_target_id(edge_type),
    )

    nodes = _nodes(age_store, label, identity)
    assert len(nodes) == 1
    for key, value in properties.items():
        assert nodes[0][key] == value
    if edge_type:
        assert len(_edges(age_store, edge_type)) == 1


@pytest.mark.parametrize("label,identity,properties,edge_type", L5_CASES)
def test_l5_upsert_missing_edge_target(
    age_store: Any,
    label: str,
    identity: dict[str, object],
    properties: dict[str, object],
    edge_type: str | None,
    caplog: pytest.LogCaptureFixture,
) -> None:
    age_store._l5_upsert_current(
        label,
        identity,
        properties,
        edge_type=edge_type,
        edge_target_id=_target_id(edge_type),
    )

    assert len(_nodes(age_store, label, identity)) == 1
    if edge_type:
        assert not _edges(age_store, edge_type)
        assert "edge target not found" in caplog.text


@pytest.mark.parametrize("label,identity,properties,edge_type", L5_CASES)
def test_l5_upsert_edge_condition_false(
    age_store: Any,
    label: str,
    identity: dict[str, object],
    properties: dict[str, object],
    edge_type: str | None,
) -> None:
    _write_decision(age_store, "OLD")
    _write_decision(age_store, _target_id(edge_type)["decision_id"])
    if edge_type:
        age_store._l5_upsert_current(
            label,
            identity,
            {"stale": "old"},
            edge_type=edge_type,
            edge_target_id={"domain": "soc", "decision_id": "OLD"},
        )

    age_store._l5_upsert_current(
        label,
        identity,
        properties,
        edge_type=edge_type,
        edge_target_id=_target_id(edge_type),
        edge_condition=False,
    )

    if edge_type:
        edges = _edges(age_store, edge_type)
        assert len(edges) == 1
        assert edges[0]["target"]["decision_id"] == "OLD"


def test_update_centroid_repeated_write_keeps_one_current_and_latest_shaped_by(
    age_store: Any,
) -> None:
    _write_decision(age_store, "DEC-1")
    _write_decision(age_store, "DEC-2")

    age_store.update_centroid("soc", "credential_access", "investigate", [0.1], 0.2, "DEC-1")
    age_store.update_centroid("soc", "credential_access", "investigate", [0.3], 0.4, "DEC-2")

    nodes = _nodes(
        age_store,
        "L5Centroid",
        {"domain": "soc", "category": "credential_access", "action": "investigate"},
    )
    assert len(nodes) == 1
    assert nodes[0]["vector_json"] == "[0.3]"
    assert nodes[0]["delta_norm"] == 0.4
    edges = _edges(age_store, "SHAPED_BY")
    assert len(edges) == 1
    assert edges[0]["target"]["decision_id"] == "DEC-2"


def test_update_conservation_repeated_write_preserves_same_status_edge_until_transition(
    age_store: Any,
) -> None:
    _write_decision(age_store, "DEC-RED")
    _write_decision(age_store, "DEC-GREEN")

    age_store.update_conservation_state(
        "soc", "RED", 0.2, 0.9, 1, 1.0, 0.9, 6, 1, 1.0, 0.9, "false", "DEC-RED", "GREEN"
    )
    age_store.update_conservation_state(
        "soc", "RED", 0.3, 0.8, 2, 1.0, 0.8, 6, 1, 1.0, 0.8, "false", "DEC-GREEN", "RED"
    )

    assert len(_nodes(age_store, "L5ConservationState", {"domain": "soc"})) == 1
    red_edges = _edges(age_store, "TRIGGERED_BY")
    assert len(red_edges) == 1
    assert red_edges[0]["target"]["decision_id"] == "DEC-RED"

    age_store.update_conservation_state(
        "soc", "GREEN", 0.4, 0.7, 3, 1.0, 0.7, 6, 2, 1.0, 0.7, "false", "DEC-GREEN", "RED"
    )

    nodes = _nodes(age_store, "L5ConservationState", {"domain": "soc"})
    assert len(nodes) == 1
    assert nodes[0]["status"] == "GREEN"
    green_edges = _edges(age_store, "TRIGGERED_BY")
    assert len(green_edges) == 1
    assert green_edges[0]["target"]["decision_id"] == "DEC-GREEN"


def test_update_dk_weights_repeated_write_keeps_one_current_and_welford_fields(
    age_store: Any,
) -> None:
    age_store.update_dk_weights("soc", [[0.1]], 4, 100.0)
    age_store.update_dk_weights(
        "soc",
        [[0.2]],
        5,
        101.0,
        welford_state={
            "confirmed_mean": [0.1],
            "confirmed_m2": [0.2],
            "overridden_mean": [0.3],
            "overridden_m2": [0.4],
            "all_mean": [0.5],
            "all_m2": [0.6],
            "n_all": 5,
        },
        n_confirmed=3,
        n_overridden=2,
        entity_group="asset",
    )

    nodes = _nodes(age_store, "L5DKWeight", {"domain": "soc"})
    assert len(nodes) == 1
    assert nodes[0]["weight_json"] == "[[0.2]]"
    assert nodes[0]["n_decisions_used"] == 5
    assert nodes[0]["confirmed_mean_json"] == "[0.1]"
    assert nodes[0]["all_m2_json"] == "[0.6]"
    assert nodes[0]["n_confirmed"] == 3
    assert nodes[0]["n_overridden"] == 2
    assert nodes[0]["entity_group"] == "asset"
