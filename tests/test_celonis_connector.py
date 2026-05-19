import json
import sys
import types
from pathlib import Path

import httpx
import pytest

from ci_platform.connectors.celonis import (
    CROSS_DOMAIN_EDGES,
    INTRA_PROCESS_EDGES,
    PROCESS_NODE_TYPES,
    CelonisConfig,
    CelonisProcessConnector,
    ProcessFixture,
    ProcessManifestBuilder,
)


FIXTURE_PATH = Path(__file__).parent / "fixtures" / "celonis" / "process_fixture.json"


def _load_fixture() -> ProcessFixture:
    return ProcessFixture.from_json(FIXTURE_PATH)


def _load_manifest() -> dict:
    return ProcessManifestBuilder(_load_fixture()).build()


def test_fixture_loads_process_model():
    fixture = _load_fixture()
    assert fixture.process_models[0]["id"] == "PM-001"
    assert fixture.process_models[0]["name"] == "Purchase-to-Pay"


def test_fixture_rejects_malformed_json(tmp_path):
    fixture_path = tmp_path / "bad_process_fixture.json"
    fixture_path.write_text(
        json.dumps(
            {
                "process_models": [],
                "variants": [],
                "activities": [],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="transitions"):
        ProcessFixture.from_json(fixture_path)


def test_fixture_rejects_bad_references(tmp_path):
    data = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    data["variants"][0]["activity_ids"] = ["ACT-MISSING"]
    fixture_path = tmp_path / "bad_reference_fixture.json"
    fixture_path.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ValueError, match="activity_ids reference"):
        ProcessFixture.from_json(fixture_path)


def test_manifest_builder_produces_all_node_types():
    manifest = _load_manifest()
    node_types = {node["type"] for node in manifest["nodes"]}
    assert node_types == PROCESS_NODE_TYPES


def test_node_types_have_required_properties():
    required_by_type = {
        "ProcessModel": {
            "id",
            "name",
            "case_count",
            "variant_count",
            "source",
            "extracted_at",
        },
        "ProcessVariant": {
            "id",
            "process_model_id",
            "frequency",
            "avg_duration",
            "conformance_rate",
            "activity_ids",
        },
        "Activity": {
            "id",
            "name",
            "avg_duration",
            "automation_rate",
            "rework_rate",
        },
        "Transition": {
            "id",
            "from_activity",
            "to_activity",
            "frequency",
            "wait_time",
            "conformance",
        },
    }

    for node in _load_manifest()["nodes"]:
        assert required_by_type[node["type"]] <= set(node)


def test_nodes_use_pascal_case_type():
    for node in _load_manifest()["nodes"]:
        node_type = node["type"]
        assert node_type in PROCESS_NODE_TYPES
        assert node_type[0].isupper()
        assert "_" not in node_type


def test_intra_process_edges_connect_expected_types():
    manifest = _load_manifest()
    node_ids = {node["id"] for node in manifest["nodes"]}
    edge_types = {relationship["type"] for relationship in manifest["relationships"]}

    assert edge_types == INTRA_PROCESS_EDGES
    for relationship in manifest["relationships"]:
        assert relationship["source"] in node_ids
        assert relationship["target"] in node_ids


def test_no_cross_domain_edges():
    edge_types = {relationship["type"] for relationship in _load_manifest()["relationships"]}
    assert edge_types.isdisjoint(CROSS_DOMAIN_EDGES)


def test_manifest_shape_matches_load_manifest():
    manifest = _load_manifest()
    assert {"nodes", "relationships", "entity_map", "stats"} <= set(manifest)
    assert isinstance(manifest["nodes"], list)
    assert isinstance(manifest["relationships"], list)
    assert manifest["entity_map"] == {}
    assert isinstance(manifest["stats"], dict)


def test_manifest_stats_accurate():
    manifest = _load_manifest()
    nodes = manifest["nodes"]
    relationships = manifest["relationships"]
    stats = manifest["stats"]

    node_type_counts = {
        node_type: sum(1 for node in nodes if node["type"] == node_type)
        for node_type in sorted(PROCESS_NODE_TYPES)
    }
    edge_type_counts = {
        edge_type: sum(1 for relationship in relationships if relationship["type"] == edge_type)
        for edge_type in sorted(INTRA_PROCESS_EDGES)
    }

    assert stats["node_count"] == len(nodes)
    assert stats["relationship_count"] == len(relationships)
    assert stats["node_types"] == node_type_counts
    assert stats["edge_types"] == edge_type_counts
    assert stats["process_model_count"] == 1
    assert stats["variant_count"] == 2
    assert stats["activity_count"] == 4
    assert stats["transition_count"] == 3


def test_deterministic_output():
    fixture = _load_fixture()
    assert ProcessManifestBuilder(fixture).build() == ProcessManifestBuilder(fixture).build()


def test_celonis_module_imports_without_pycelonis():
    assert "pycelonis" not in sys.modules
    __import__("ci_platform.connectors.celonis")
    assert "pycelonis" not in sys.modules


@pytest.mark.asyncio
async def test_health_check_not_configured():
    connector = CelonisProcessConnector(
        config=CelonisConfig(use_fixture_fallback=False),
    )

    health = await connector.health_check()

    assert health == {"status": "not_configured", "source": None}


@pytest.mark.asyncio
async def test_health_check_fixture_fallback():
    connector = CelonisProcessConnector(fixture_path=FIXTURE_PATH)

    health = await connector.health_check()

    assert health["status"] == "degraded"
    assert health["source"] == "fixture"


@pytest.mark.asyncio
async def test_fetch_process_models_from_fixture():
    connector = CelonisProcessConnector(fixture_path=FIXTURE_PATH)
    await connector.connect()

    process_models = await connector.fetch_process_models()

    assert [model["id"] for model in process_models] == ["PM-001"]


@pytest.mark.asyncio
async def test_fetch_variants_activities_transitions_from_fixture():
    connector = CelonisProcessConnector(fixture_path=FIXTURE_PATH)
    await connector.connect()

    variants = await connector.fetch_variants("PM-001")
    activities = await connector.fetch_activities("PM-001", variant_id="PV-001")
    transitions = await connector.fetch_transitions("PM-001", variant_id="PV-001")

    assert {variant["id"] for variant in variants} == {"PV-001", "PV-002"}
    assert {activity["id"] for activity in activities} == {
        "ACT-001",
        "ACT-002",
        "ACT-003",
        "ACT-004",
    }
    assert {transition["id"] for transition in transitions} == {
        "TR-001",
        "TR-002",
        "TR-003",
    }


@pytest.mark.asyncio
async def test_to_process_manifest_from_fixture():
    connector = CelonisProcessConnector(fixture_path=FIXTURE_PATH)

    manifest = await connector.to_process_manifest()
    edge_types = {relationship["type"] for relationship in manifest["relationships"]}

    assert {"nodes", "relationships", "entity_map", "stats"} <= set(manifest)
    assert manifest["entity_map"] == {}
    assert edge_types.isdisjoint(CROSS_DOMAIN_EDGES)
    assert manifest["stats"]["node_count"] == len(manifest["nodes"])


def test_celonis_config_from_env(monkeypatch):
    monkeypatch.setenv("CELONIS_BASE_URL", "https://celonis.example.test")
    monkeypatch.setenv("CELONIS_API_TOKEN", "test-token")
    monkeypatch.setenv("CELONIS_DATA_POOL_ID", "pool-1")
    monkeypatch.setenv("CELONIS_PROCESS_MODEL_ID", "model-1")
    monkeypatch.setenv("CELONIS_USE_FIXTURE_FALLBACK", "off")

    config = CelonisConfig.from_env()

    assert config.base_url == "https://celonis.example.test"
    assert config.api_token == "test-token"
    assert config.data_pool_id == "pool-1"
    assert config.process_model_id == "model-1"
    assert config.use_fixture_fallback is False


def test_celonis_config_from_env_missing_is_none(monkeypatch):
    for name in [
        "CELONIS_BASE_URL",
        "CELONIS_API_TOKEN",
        "CELONIS_DATA_POOL_ID",
        "CELONIS_PROCESS_MODEL_ID",
        "CELONIS_USE_FIXTURE_FALLBACK",
    ]:
        monkeypatch.delenv(name, raising=False)

    config = CelonisConfig.from_env()

    assert config.base_url is None
    assert config.api_token is None
    assert config.data_pool_id is None
    assert config.process_model_id is None
    assert config.use_fixture_fallback is True


def test_celonis_config_from_env_rejects_ambiguous_fallback(monkeypatch):
    monkeypatch.setenv("CELONIS_USE_FIXTURE_FALLBACK", "maybe")

    with pytest.raises(ValueError, match="CELONIS_USE_FIXTURE_FALLBACK"):
        CelonisConfig.from_env()


def test_pycelonis_not_required():
    __import__("ci_platform.connectors.celonis")
    assert "pycelonis" not in sys.modules


@pytest.mark.asyncio
async def test_pycelonis_importable_configured_source_selected(monkeypatch):
    monkeypatch.setitem(sys.modules, "pycelonis", types.ModuleType("pycelonis"))
    connector = CelonisProcessConnector(
        config=CelonisConfig(
            base_url="https://fake.celonis.cloud",
            api_token="fake-token",
            use_fixture_fallback=False,
        )
    )

    await connector.connect()
    health = await connector.health_check()

    assert health == {"status": "ok", "source": "pycelonis"}


@pytest.mark.asyncio
async def test_health_check_rest_success_mocked(monkeypatch):
    fake_client = _FakeAsyncClient(_FakeResponse({"status": "ok"}))
    monkeypatch.setattr("ci_platform.connectors.celonis.httpx.AsyncClient", lambda: fake_client)
    connector = CelonisProcessConnector(
        config=CelonisConfig(
            base_url="https://celonis.example.test",
            api_token="test-token",
            use_fixture_fallback=False,
        ),
    )

    health = await connector.health_check()

    assert health == {"status": "ok", "source": "rest"}
    assert fake_client.requests[0]["url"] == "https://celonis.example.test/health"


@pytest.mark.asyncio
async def test_fetch_via_rest_mocked(monkeypatch):
    payload = {"process_models": [_load_fixture().process_models[0]]}
    fake_client = _FakeAsyncClient(_FakeResponse(payload))
    monkeypatch.setattr("ci_platform.connectors.celonis.httpx.AsyncClient", lambda: fake_client)
    connector = CelonisProcessConnector(
        config=CelonisConfig(
            base_url="https://celonis.example.test",
            api_token="test-token",
            use_fixture_fallback=False,
        ),
    )

    await connector.connect()
    process_models = await connector.fetch_process_models()

    assert [model["id"] for model in process_models] == ["PM-001"]
    assert fake_client.requests[0]["headers"]["Authorization"] == "Bearer test-token"
    assert fake_client.requests[0]["url"] == "https://celonis.example.test/process_models"


@pytest.mark.asyncio
async def test_rest_failure_falls_back_to_fixture(monkeypatch):
    fake_client = _FakeAsyncClient(error=httpx.ConnectError("network unavailable"))
    monkeypatch.setattr("ci_platform.connectors.celonis.httpx.AsyncClient", lambda: fake_client)
    connector = CelonisProcessConnector(
        config=CelonisConfig(
            base_url="https://celonis.example.test",
            api_token="test-token",
            use_fixture_fallback=True,
        ),
        fixture_path=FIXTURE_PATH,
    )

    process_models = await connector.fetch_process_models()
    health = await connector.health_check()

    assert [model["id"] for model in process_models] == ["PM-001"]
    assert health["status"] == "degraded"
    assert health["source"] == "fixture"
    assert "network unavailable" in health["reason"]


@pytest.mark.asyncio
async def test_malformed_rest_response_raises(monkeypatch):
    fake_client = _FakeAsyncClient(_FakeResponse({"unexpected": []}))
    monkeypatch.setattr("ci_platform.connectors.celonis.httpx.AsyncClient", lambda: fake_client)
    connector = CelonisProcessConnector(
        config=CelonisConfig(
            base_url="https://celonis.example.test",
            api_token="test-token",
            use_fixture_fallback=False,
        ),
    )

    with pytest.raises(ValueError, match="process_models"):
        await connector.fetch_process_models()


class _FakeResponse:
    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code

    def json(self):
        return self._payload


class _FakeAsyncClient:
    def __init__(self, response=None, error=None):
        self._response = response
        self._error = error
        self.requests = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def get(self, url, headers=None, timeout=None):
        self.requests.append({"url": url, "headers": headers, "timeout": timeout})
        if self._error:
            raise self._error
        return self._response
