import re

import pytest

from ci_platform.graph.age_graph_store import AGEGraphStore


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


class MemoryL5Store(AGEGraphStore):
    def __init__(self):
        self.nodes = []
        self.edges = []
        self.queries = []
        self.next_id = 1

    def _S(self, value):
        if value is None:
            return "null"
        if isinstance(value, bool):
            return str(value).lower()
        if isinstance(value, (int, float)):
            return str(value)
        return "'" + str(value).replace("'", "\\'") + "'"

    def add_node(self, label, **properties):
        node = {"_id": self.next_id, "_label": label, **properties}
        self.next_id += 1
        self.nodes.append(node)
        return node

    def add_edge(self, src, edge_type, dst):
        self.edges.append({"src": src["_id"], "type": edge_type, "dst": dst["_id"]})

    def matching_nodes(self, label, identity):
        return [
            node
            for node in self.nodes
            if node["_label"] == label
            and all(node.get(key) == value for key, value in identity.items())
        ]

    def matching_edges(self, edge_type):
        return [edge for edge in self.edges if edge["type"] == edge_type]

    def _run_query(self, cypher):
        self.queries.append(cypher)
        query = " ".join(cypher.strip().split())

        if "MATCH (n:" in query and " SET " in query and "RETURN n" in query:
            label = self._match_label(query, "n")
            identity = self._where_identity(query, "n")
            properties = self._props_from_set(query)
            nodes = self.matching_nodes(label, identity)
            for node in nodes:
                node.update(properties)
            return [{"n": node} for node in nodes]

        if "CREATE (n)-[:" in query:
            source_label = self._match_label(query, "n")
            source_identity = self._where_identity(query, "n")
            target_label = self._match_label(query, "t")
            target_identity = self._where_identity(query, "t")
            edge_type = re.search(r"CREATE \(n\)-\[:([A-Za-z_][A-Za-z0-9_]*)", query).group(1)
            sources = self.matching_nodes(source_label, source_identity)
            targets = self.matching_nodes(target_label, target_identity)
            if sources and targets:
                self.add_edge(sources[0], edge_type, targets[0])
                return [{"n": sources[0], "t": targets[0]}]
            return []

        if "RETURN n" in query and "MATCH (n:" in query:
            label = self._match_label(query, "n")
            identity = self._where_identity(query, "n")
            return [{"n": node} for node in self.matching_nodes(label, identity)]

        if "MATCH (n:" in query and ")-[r]-()" in query and "DELETE r" in query:
            label = self._match_label(query, "n")
            identity = self._where_identity(query, "n")
            ids = {node["_id"] for node in self.matching_nodes(label, identity)}
            self.edges = [
                edge for edge in self.edges if edge["src"] not in ids and edge["dst"] not in ids
            ]
            return []

        if "MATCH (n:" in query and "DELETE n" in query:
            label = self._match_label(query, "n")
            identity = self._where_identity(query, "n")
            ids = {node["_id"] for node in self.matching_nodes(label, identity)}
            self.nodes = [node for node in self.nodes if node["_id"] not in ids]
            return []

        if query.startswith("CREATE (n:"):
            label = self._match_label(query, "n")
            properties = self._props_from_create(query)
            node = self.add_node(label, **properties)
            return [{"n": node}]

        if "MATCH (n:" in query and ")-[r:" in query and "DELETE r" in query:
            label = self._match_label(query, "n")
            edge_type = self._edge_type(query)
            identity = self._where_identity(query, "n")
            ids = {node["_id"] for node in self.matching_nodes(label, identity)}
            self.edges = [
                edge
                for edge in self.edges
                if not (edge["src"] in ids and edge["type"] == edge_type)
            ]
            return []

        if "MATCH (t:" in query and "RETURN t" in query:
            label = self._match_label(query, "t")
            identity = self._where_identity(query, "t")
            nodes = self.matching_nodes(label, identity)
            return [{"t": nodes[0]}] if nodes else []

        raise AssertionError(f"Unhandled query: {query}")

    def _match_label(self, query, var_name):
        match = re.search(rf"\({var_name}:([A-Za-z_][A-Za-z0-9_]*)", query)
        assert match, query
        return match.group(1)

    def _where_identity(self, query, var_name):
        pattern = rf"{var_name}\.([A-Za-z_][A-Za-z0-9_]*) = ('(?:\\'|[^'])*'|null|true|false|-?\d+(?:\.\d+)?)"
        where_segments = re.findall(
            r"WHERE (.*?)(?= MATCH | SET | WITH | RETURN | DELETE | LIMIT |$)",
            query,
        )
        search_text = " AND ".join(where_segments)
        return {
            key: self._parse_value(value)
            for key, value in re.findall(pattern, search_text)
            if not (var_name == "n" and key.startswith("_"))
        }

    def _edge_type(self, query):
        match = re.search(r"-\[r:([A-Za-z_][A-Za-z0-9_]*)\]", query)
        assert match, query
        return match.group(1)

    def _props_from_create(self, query):
        match = re.search(r"CREATE \(n:[A-Za-z_][A-Za-z0-9_]* \{(.*)\}\) RETURN n", query)
        assert match, query
        return self._parse_props(match.group(1))

    def _props_from_set(self, query):
        match = re.search(r" SET (.*) RETURN n", query)
        assert match, query
        assignments = []
        for part in self._split_props(match.group(1)):
            key, value = part.split(" = ", 1)
            assignments.append((key.split(".", 1)[1], value))
        return {key: self._parse_value(value) for key, value in assignments}

    def _parse_props(self, text):
        props = {}
        for part in self._split_props(text):
            key, value = part.split(": ", 1)
            props[key] = self._parse_value(value)
        return props

    def _split_props(self, text):
        parts = []
        current = []
        in_quote = False
        escaped = False
        for char in text:
            if escaped:
                current.append(char)
                escaped = False
                continue
            if char == "\\":
                current.append(char)
                escaped = True
                continue
            if char == "'":
                in_quote = not in_quote
            if char == "," and not in_quote:
                parts.append("".join(current).strip())
                current = []
            else:
                current.append(char)
        if current:
            parts.append("".join(current).strip())
        return parts

    def _parse_value(self, value):
        if value == "null":
            return None
        if value == "true":
            return True
        if value == "false":
            return False
        if value.startswith("'") and value.endswith("'"):
            return value[1:-1].replace("\\'", "'")
        if "." in value:
            return float(value)
        return int(value)


def _target_id(edge_type):
    return {"domain": "soc", "decision_id": f"{edge_type or 'NOEDGE'}-DEC"}


@pytest.mark.parametrize("label,identity,properties,edge_type", L5_CASES)
def test_l5_upsert_create_fresh(label, identity, properties, edge_type):
    store = MemoryL5Store()

    store._l5_upsert_current(label, identity, properties, edge_type=edge_type)

    assert len(store.matching_nodes(label, identity)) == 1
    node = store.matching_nodes(label, identity)[0]
    for key, value in {**identity, **properties}.items():
        assert node[key] == value
    assert not store.edges


@pytest.mark.parametrize("label,identity,properties,edge_type", L5_CASES)
def test_l5_upsert_set_existing(label, identity, properties, edge_type):
    store = MemoryL5Store()
    existing = store.add_node(label, **identity, stale="old")

    store._l5_upsert_current(label, identity, properties, edge_type=edge_type)

    nodes = store.matching_nodes(label, identity)
    assert len(nodes) == 1
    assert nodes[0]["_id"] == existing["_id"]
    for key, value in properties.items():
        assert nodes[0][key] == value


@pytest.mark.parametrize("label,identity,properties,edge_type", L5_CASES)
def test_l5_upsert_replace_edge(label, identity, properties, edge_type):
    store = MemoryL5Store()
    node = store.add_node(label, **identity, stale="old")
    old_decision = store.add_node("Decision", domain="soc", decision_id="OLD")
    new_decision = store.add_node("Decision", **_target_id(edge_type))
    if edge_type:
        store.add_edge(node, edge_type, old_decision)

    store._l5_upsert_current(
        label,
        identity,
        properties,
        edge_type=edge_type,
        edge_target_id=_target_id(edge_type),
    )

    assert len(store.matching_nodes(label, identity)) == 1
    if edge_type:
        assert store.matching_edges(edge_type) == [
            {"src": node["_id"], "type": edge_type, "dst": new_decision["_id"]}
        ]
    else:
        assert not store.edges


@pytest.mark.parametrize("label,identity,properties,edge_type", L5_CASES)
def test_l5_upsert_cleanup_duplicates(label, identity, properties, edge_type):
    store = MemoryL5Store()
    target = store.add_node("Decision", **_target_id(edge_type))
    first = store.add_node(label, **identity, stale="first")
    second = store.add_node(label, **identity, stale="second")
    third = store.add_node(label, **identity, stale="third")
    if edge_type:
        store.add_edge(first, edge_type, target)
        store.add_edge(second, edge_type, target)
        store.add_edge(target, edge_type, third)

    store._l5_upsert_current(
        label,
        identity,
        properties,
        edge_type=edge_type,
        edge_target_id=_target_id(edge_type),
    )

    nodes = store.matching_nodes(label, identity)
    assert len(nodes) == 1
    for key, value in properties.items():
        assert nodes[0][key] == value
    if edge_type:
        assert store.matching_edges(edge_type) == [
            {"src": nodes[0]["_id"], "type": edge_type, "dst": target["_id"]}
        ]


@pytest.mark.parametrize("label,identity,properties,edge_type", L5_CASES)
def test_l5_upsert_multiple_stale_edges(label, identity, properties, edge_type):
    store = MemoryL5Store()
    node = store.add_node(label, **identity)
    latest = store.add_node("Decision", **_target_id(edge_type))
    if edge_type:
        for index in range(4):
            old = store.add_node("Decision", domain="soc", decision_id=f"OLD-{index}")
            store.add_edge(node, edge_type, old)

    store._l5_upsert_current(
        label,
        identity,
        properties,
        edge_type=edge_type,
        edge_target_id=_target_id(edge_type),
    )

    if edge_type:
        assert store.matching_edges(edge_type) == [
            {"src": node["_id"], "type": edge_type, "dst": latest["_id"]}
        ]
    else:
        assert not store.edges


@pytest.mark.parametrize("label,identity,properties,edge_type", L5_CASES)
def test_l5_upsert_missing_edge_target(label, identity, properties, edge_type, caplog):
    store = MemoryL5Store()
    node = store.add_node(label, **identity, stale="old")

    store._l5_upsert_current(
        label,
        identity,
        properties,
        edge_type=edge_type,
        edge_target_id=_target_id(edge_type),
    )

    assert store.matching_nodes(label, identity)[0]["_id"] == node["_id"]
    assert not store.edges
    if edge_type:
        assert "edge target not found" in caplog.text


@pytest.mark.parametrize("label,identity,properties,edge_type", L5_CASES)
def test_l5_upsert_edge_condition_false(label, identity, properties, edge_type):
    store = MemoryL5Store()
    node = store.add_node(label, **identity)
    old = store.add_node("Decision", domain="soc", decision_id="OLD")
    latest = store.add_node("Decision", **_target_id(edge_type))
    if edge_type:
        store.add_edge(node, edge_type, old)

    store._l5_upsert_current(
        label,
        identity,
        properties,
        edge_type=edge_type,
        edge_target_id=_target_id(edge_type),
        edge_condition=False,
    )

    if edge_type:
        assert store.matching_edges(edge_type) == [
            {"src": node["_id"], "type": edge_type, "dst": old["_id"]}
        ]
        assert latest["_id"] not in [edge["dst"] for edge in store.edges]
    else:
        assert not store.edges


@pytest.mark.parametrize("label,identity,properties,edge_type", L5_CASES)
def test_l5_upsert_no_edge_type(label, identity, properties, edge_type):
    store = MemoryL5Store()
    store.add_node(label, **identity)
    old = store.add_node("Decision", domain="soc", decision_id="OLD")
    latest = store.add_node("Decision", **_target_id(edge_type))
    if edge_type:
        store.add_edge(store.matching_nodes(label, identity)[0], edge_type, old)

    store._l5_upsert_current(
        label,
        identity,
        properties,
        edge_type=None,
        edge_target_id=_target_id(edge_type),
    )

    if edge_type:
        assert store.matching_edges(edge_type) == [
            {"src": store.matching_nodes(label, identity)[0]["_id"], "type": edge_type, "dst": old["_id"]}
        ]
        assert latest["_id"] not in [edge["dst"] for edge in store.edges]
    else:
        assert not store.edges


@pytest.mark.parametrize("label,identity,properties,edge_type", L5_CASES)
def test_l5_upsert_edge_wanted_no_target_id(label, identity, properties, edge_type):
    store = MemoryL5Store()
    node = store.add_node(label, **identity)
    old = store.add_node("Decision", domain="soc", decision_id="OLD")
    if edge_type:
        store.add_edge(node, edge_type, old)

    store._l5_upsert_current(
        label,
        identity,
        properties,
        edge_type=edge_type,
        edge_target_id=None,
        edge_condition=True,
    )

    assert not store.edges


@pytest.mark.parametrize("label,identity,properties,edge_type", L5_CASES)
def test_l5_upsert_garbled_with_incoming_edges(label, identity, properties, edge_type):
    store = MemoryL5Store()
    source = store.add_node("Decision", domain="soc", decision_id="SOURCE")
    target = store.add_node("Decision", **_target_id(edge_type))
    first = store.add_node(label, **identity, stale="first")
    second = store.add_node(label, **identity, stale="second")
    if edge_type:
        store.add_edge(source, edge_type, first)
        store.add_edge(second, edge_type, target)

    store._l5_upsert_current(
        label,
        identity,
        properties,
        edge_type=edge_type,
        edge_target_id=_target_id(edge_type),
    )

    nodes = store.matching_nodes(label, identity)
    assert len(nodes) == 1
    if edge_type:
        assert store.matching_edges(edge_type) == [
            {"src": nodes[0]["_id"], "type": edge_type, "dst": target["_id"]}
        ]


def test_update_centroid_repeated_write_keeps_one_current_and_latest_shaped_by():
    store = MemoryL5Store()
    first_decision = store.add_node("Decision", domain="soc", decision_id="DEC-1")
    second_decision = store.add_node("Decision", domain="soc", decision_id="DEC-2")

    store.update_centroid("soc", "credential_access", "investigate", [0.1], 0.2, "DEC-1")
    store.update_centroid("soc", "credential_access", "investigate", [0.3], 0.4, "DEC-2")

    nodes = store.matching_nodes(
        "L5Centroid",
        {"domain": "soc", "category": "credential_access", "action": "investigate"},
    )
    assert len(nodes) == 1
    assert nodes[0]["vector_json"] == "[0.3]"
    assert nodes[0]["delta_norm"] == 0.4
    assert store.matching_edges("SHAPED_BY") == [
        {"src": nodes[0]["_id"], "type": "SHAPED_BY", "dst": second_decision["_id"]}
    ]
    assert first_decision["_id"] not in [edge["dst"] for edge in store.edges]


def test_update_conservation_repeated_write_preserves_same_status_edge_until_transition():
    store = MemoryL5Store()
    red_decision = store.add_node("Decision", domain="soc", decision_id="DEC-RED")
    green_decision = store.add_node("Decision", domain="soc", decision_id="DEC-GREEN")

    store.update_conservation_state(
        "soc", "RED", 0.2, 0.9, 1, 1.0, 0.9, 6, 1, 1.0, 0.9, "false", "DEC-RED", "GREEN"
    )
    store.update_conservation_state(
        "soc", "RED", 0.3, 0.8, 2, 1.0, 0.8, 6, 1, 1.0, 0.8, "false", "DEC-GREEN", "RED"
    )
    assert len(store.matching_nodes("L5ConservationState", {"domain": "soc"})) == 1
    assert store.matching_edges("TRIGGERED_BY") == [
        {"src": store.matching_nodes("L5ConservationState", {"domain": "soc"})[0]["_id"], "type": "TRIGGERED_BY", "dst": red_decision["_id"]}
    ]

    store.update_conservation_state(
        "soc", "GREEN", 0.4, 0.7, 3, 1.0, 0.7, 6, 2, 1.0, 0.7, "false", "DEC-GREEN", "RED"
    )

    nodes = store.matching_nodes("L5ConservationState", {"domain": "soc"})
    assert len(nodes) == 1
    assert nodes[0]["status"] == "GREEN"
    assert store.matching_edges("TRIGGERED_BY") == [
        {"src": nodes[0]["_id"], "type": "TRIGGERED_BY", "dst": green_decision["_id"]}
    ]


def test_update_dk_weights_repeated_write_keeps_one_current_and_welford_fields():
    store = MemoryL5Store()

    store.update_dk_weights("soc", [[0.1]], 4, 100.0)
    store.update_dk_weights(
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

    nodes = store.matching_nodes("L5DKWeight", {"domain": "soc"})
    assert len(nodes) == 1
    assert nodes[0]["weight_json"] == "[[0.2]]"
    assert nodes[0]["n_decisions_used"] == 5
    assert nodes[0]["confirmed_mean_json"] == "[0.1]"
    assert nodes[0]["all_m2_json"] == "[0.6]"
    assert nodes[0]["n_confirmed"] == 3
    assert nodes[0]["n_overridden"] == 2
    assert nodes[0]["entity_group"] == "asset"
    assert not store.edges
