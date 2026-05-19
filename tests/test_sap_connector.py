import json
from pathlib import Path

import pytest

from ci_platform.connectors.sap import (
    SAP_EDGE_TYPES,
    SAP_NODE_TYPES,
    SAPConfig,
    SAPFixture,
    SAPManifestBuilder,
    SAPODataConnector,
)


FIXTURE_DIR = Path(__file__).parent / "fixtures" / "sap"


def _load_fixture() -> SAPFixture:
    return SAPFixture.from_dir(FIXTURE_DIR)


def _load_manifest() -> dict:
    return SAPManifestBuilder(_load_fixture()).build()


def test_sap_fixture_loads_all_files():
    fixture = _load_fixture()

    assert [po["PurchaseOrder"] for po in fixture.purchase_orders] == [
        "PO-4500001234",
        "PO-4500001235",
        "PO-4500001236",
    ]
    assert [invoice["SupplierInvoice"] for invoice in fixture.invoices] == [
        "INV-5100098765",
        "INV-5100098766",
    ]
    assert [supplier["BusinessPartner"] for supplier in fixture.suppliers] == [
        "BP-0001000123",
        "BP-0001000124",
        "BP-0001000125",
    ]
    assert fixture.write_response_cache["d"]["PurchaseOrder"] == "PO-4500001234"


def test_sap_fixture_rejects_missing_required_fields(tmp_path):
    _write_fixture_dir(tmp_path)
    purchase_orders = json.loads((tmp_path / "purchase_orders.json").read_text(encoding="utf-8"))
    del purchase_orders[0]["PurchaseOrder"]
    (tmp_path / "purchase_orders.json").write_text(json.dumps(purchase_orders), encoding="utf-8")

    with pytest.raises(ValueError, match="PurchaseOrder.*PurchaseOrder"):
        SAPFixture.from_dir(tmp_path)


def test_sap_fixture_rejects_duplicate_ids(tmp_path):
    _write_fixture_dir(tmp_path)
    invoices = json.loads((tmp_path / "invoices.json").read_text(encoding="utf-8"))
    invoices[1]["SupplierInvoice"] = invoices[0]["SupplierInvoice"]
    (tmp_path / "invoices.json").write_text(json.dumps(invoices), encoding="utf-8")

    with pytest.raises(ValueError, match="duplicate SupplierInvoice"):
        SAPFixture.from_dir(tmp_path)


def test_to_load_manifest_shape():
    manifest = _load_manifest()

    assert {"nodes", "relationships", "entity_map", "stats"} <= set(manifest)
    assert isinstance(manifest["nodes"], list)
    assert isinstance(manifest["relationships"], list)
    assert manifest["entity_map"] == {}
    assert isinstance(manifest["stats"], dict)


def test_manifest_nodes_have_pascal_case_types():
    for node in _load_manifest()["nodes"]:
        node_type = node["type"]
        assert node_type in SAP_NODE_TYPES
        assert node["id"]
        assert node_type[0].isupper()
        assert "_" not in node_type


def test_manifest_edges_po_to_invoice_and_supplier():
    manifest = _load_manifest()
    node_ids = {node["id"] for node in manifest["nodes"]}
    edge_types = {relationship["type"] for relationship in manifest["relationships"]}

    assert edge_types == SAP_EDGE_TYPES
    assert {
        ("PO-4500001234", "INV-5100098765", "INVOICED_BY"),
        ("PO-4500001235", "INV-5100098766", "INVOICED_BY"),
        ("PO-4500001234", "BP-0001000123", "ORDERED_FROM"),
        ("PO-4500001235", "BP-0001000124", "ORDERED_FROM"),
        ("PO-4500001236", "BP-0001000125", "ORDERED_FROM"),
    } == {
        (relationship["source"], relationship["target"], relationship["type"])
        for relationship in manifest["relationships"]
    }
    for relationship in manifest["relationships"]:
        assert relationship["source"] in node_ids
        assert relationship["target"] in node_ids


def test_manifest_stats_accurate():
    manifest = _load_manifest()
    nodes = manifest["nodes"]
    relationships = manifest["relationships"]
    stats = manifest["stats"]

    node_type_counts = {
        node_type: sum(1 for node in nodes if node["type"] == node_type)
        for node_type in sorted(SAP_NODE_TYPES)
    }
    edge_type_counts = {
        edge_type: sum(1 for relationship in relationships if relationship["type"] == edge_type)
        for edge_type in sorted(SAP_EDGE_TYPES)
    }

    assert stats["node_count"] == len(nodes)
    assert stats["relationship_count"] == len(relationships)
    assert stats["node_types"] == node_type_counts
    assert stats["edge_types"] == edge_type_counts
    assert stats["purchase_order_count"] == 3
    assert stats["invoice_count"] == 2
    assert stats["supplier_count"] == 3


def test_no_secrets_in_fixtures():
    forbidden = ("api_key", "token", "secret", "password", "bearer")
    for path in sorted(FIXTURE_DIR.glob("*.json")):
        text = path.read_text(encoding="utf-8").lower()
        assert not any(value in text for value in forbidden), path


def test_sap_module_imports_cleanly_without_network_dependency():
    __import__("ci_platform.connectors.sap")
    source = Path("ci_platform/connectors/sap.py").read_text(encoding="utf-8")

    assert "import requests" not in source
    assert "import urllib" not in source
    assert "from urllib" not in source


def test_sap_config_from_env(monkeypatch):
    monkeypatch.setenv("SAP_BASE_URL", "https://sap.example.test")
    monkeypatch.setenv("SAP_API_KEY", "api-key")
    monkeypatch.setenv("SAP_BEARER_TOKEN", "bearer-token")
    monkeypatch.setenv("SAP_CLIENT", "100")
    monkeypatch.setenv("SAP_USE_FIXTURE_FALLBACK", "off")
    monkeypatch.setenv("SAP_WRITE_DEMO_MODE", "0")
    monkeypatch.setenv("SAP_FIXTURE_DIR", str(FIXTURE_DIR))

    config = SAPConfig.from_env()

    assert config.base_url == "https://sap.example.test"
    assert config.api_key == "api-key"
    assert config.bearer_token == "bearer-token"
    assert config.sap_client == "100"
    assert config.use_fixture_fallback is False
    assert config.write_demo_mode is False
    assert config.fixture_dir == str(FIXTURE_DIR)


def test_sap_config_from_env_missing_is_none(monkeypatch):
    for name in [
        "SAP_BASE_URL",
        "SAP_API_KEY",
        "SAP_BEARER_TOKEN",
        "SAP_OAUTH_TOKEN",
        "SAP_CLIENT",
        "SAP_USE_FIXTURE_FALLBACK",
        "SAP_WRITE_DEMO_MODE",
        "SAP_FIXTURE_DIR",
    ]:
        monkeypatch.delenv(name, raising=False)

    config = SAPConfig.from_env()

    assert config.base_url is None
    assert config.api_key is None
    assert config.bearer_token is None
    assert config.sap_client is None
    assert config.use_fixture_fallback is True
    assert config.write_demo_mode is True
    assert config.fixture_dir is None


def test_sap_config_bool_parsing(monkeypatch):
    monkeypatch.setenv("SAP_USE_FIXTURE_FALLBACK", "yes")
    monkeypatch.setenv("SAP_WRITE_DEMO_MODE", "no")
    config = SAPConfig.from_env()
    assert config.use_fixture_fallback is True
    assert config.write_demo_mode is False

    monkeypatch.setenv("SAP_USE_FIXTURE_FALLBACK", "maybe")
    with pytest.raises(ValueError, match="SAP_USE_FIXTURE_FALLBACK"):
        SAPConfig.from_env()


@pytest.mark.asyncio
async def test_health_check_not_configured():
    connector = SAPODataConnector(config=SAPConfig(use_fixture_fallback=False))

    health = await connector.health_check()

    assert health == {"status": "not_configured", "source": None}


@pytest.mark.asyncio
async def test_health_check_fixture_fallback():
    connector = SAPODataConnector(fixture_dir=FIXTURE_DIR)

    health = await connector.health_check()

    assert health == {"status": "degraded", "source": "fixture"}


@pytest.mark.asyncio
async def test_fetch_purchase_orders_from_fixture():
    connector = SAPODataConnector(fixture_dir=FIXTURE_DIR)

    purchase_orders = await connector.fetch_purchase_orders()

    assert [po["PurchaseOrder"] for po in purchase_orders] == [
        "PO-4500001234",
        "PO-4500001235",
        "PO-4500001236",
    ]


@pytest.mark.asyncio
async def test_fetch_invoices_from_fixture():
    connector = SAPODataConnector(fixture_dir=FIXTURE_DIR)

    invoices = await connector.fetch_invoices()

    assert [invoice["SupplierInvoice"] for invoice in invoices] == [
        "INV-5100098765",
        "INV-5100098766",
    ]


@pytest.mark.asyncio
async def test_fetch_suppliers_from_fixture():
    connector = SAPODataConnector(fixture_dir=FIXTURE_DIR)

    suppliers = await connector.fetch_suppliers()

    assert [supplier["BusinessPartner"] for supplier in suppliers] == [
        "BP-0001000123",
        "BP-0001000124",
        "BP-0001000125",
    ]


@pytest.mark.asyncio
async def test_fetch_via_rest_mocked(monkeypatch):
    fake_client = _FakeAsyncClient(
        _FakeResponse({"d": {"results": [_load_fixture().purchase_orders[0]]}})
    )
    monkeypatch.setattr("ci_platform.connectors.sap.httpx.AsyncClient", lambda: fake_client)
    connector = SAPODataConnector(
        config=SAPConfig(
            base_url="https://sap.example.test",
            api_key="api-key",
            bearer_token="bearer-token",
            sap_client="100",
            use_fixture_fallback=False,
        )
    )

    purchase_orders = await connector.fetch_purchase_orders()

    assert [po["PurchaseOrder"] for po in purchase_orders] == ["PO-4500001234"]
    request = fake_client.requests[0]
    assert request["url"] == (
        "https://sap.example.test/"
        "sap/opu/odata/sap/API_PURCHASEORDER_PROCESS_SRV/A_PurchaseOrder"
    )
    assert request["headers"]["APIKey"] == "api-key"
    assert request["headers"]["Authorization"] == "Bearer bearer-token"
    assert request["headers"]["sap-client"] == "100"


@pytest.mark.asyncio
async def test_rest_malformed_response_raises(monkeypatch):
    fake_client = _FakeAsyncClient(_FakeResponse({"unexpected": []}))
    monkeypatch.setattr("ci_platform.connectors.sap.httpx.AsyncClient", lambda: fake_client)
    connector = SAPODataConnector(
        config=SAPConfig(
            base_url="https://sap.example.test",
            api_key="api-key",
            use_fixture_fallback=False,
        )
    )

    with pytest.raises(ValueError, match="PurchaseOrder"):
        await connector.fetch_purchase_orders()


@pytest.mark.asyncio
async def test_rest_non_2xx_raises(monkeypatch):
    fake_client = _FakeAsyncClient(_FakeResponse({"d": {"results": []}}, status_code=503))
    monkeypatch.setattr("ci_platform.connectors.sap.httpx.AsyncClient", lambda: fake_client)
    connector = SAPODataConnector(
        config=SAPConfig(
            base_url="https://sap.example.test",
            api_key="api-key",
            use_fixture_fallback=False,
        )
    )

    with pytest.raises(ConnectionError, match="503"):
        await connector.fetch_purchase_orders()


@pytest.mark.asyncio
async def test_to_load_manifest_from_connector_fixture():
    connector = SAPODataConnector(fixture_dir=FIXTURE_DIR)

    manifest = await connector.to_load_manifest()

    assert {"nodes", "relationships", "entity_map", "stats"} <= set(manifest)
    assert manifest["stats"]["purchase_order_count"] == 3
    assert manifest["stats"]["invoice_count"] == 2
    assert manifest["stats"]["supplier_count"] == 3
    assert {relationship["type"] for relationship in manifest["relationships"]} == SAP_EDGE_TYPES


@pytest.mark.asyncio
async def test_write_update_demo_mode_returns_cached():
    connector = SAPODataConnector(fixture_dir=FIXTURE_DIR)

    result = await connector.write_update(
        "PurchaseOrder",
        "PO-4500001234",
        {"matching_parameter": "MATKL_V2_FILTER"},
        decision_id="DEC-001",
    )

    assert result["d"]["PurchaseOrder"] == "PO-4500001234"
    assert result["d"]["MatchingParameter"] == "MATKL_V2_FILTER"


@pytest.mark.asyncio
async def test_write_update_rejects_business_partner():
    connector = SAPODataConnector(fixture_dir=FIXTURE_DIR)

    with pytest.raises(ValueError, match="read-only"):
        await connector.write_update(
            "BusinessPartner",
            "BP-0001000123",
            {"routing_rule": "manual"},
        )


@pytest.mark.asyncio
async def test_write_update_rejects_empty_payload():
    connector = SAPODataConnector(fixture_dir=FIXTURE_DIR)

    with pytest.raises(ValueError, match="non-empty"):
        await connector.write_update("PurchaseOrder", "PO-4500001234", {})


@pytest.mark.asyncio
async def test_write_update_rejects_unknown_fields():
    connector = SAPODataConnector(fixture_dir=FIXTURE_DIR)

    with pytest.raises(ValueError, match="unsupported_field"):
        await connector.write_update(
            "PurchaseOrder",
            "PO-4500001234",
            {"unsupported_field": "value"},
        )


@pytest.mark.asyncio
async def test_write_update_rejects_unknown_entity_type():
    connector = SAPODataConnector(fixture_dir=FIXTURE_DIR)

    with pytest.raises(ValueError, match="Unsupported SAP write entity_type"):
        await connector.write_update("SupplierInvoice", "INV-5100098765", {"hold_status": "hold"})


@pytest.mark.asyncio
async def test_write_update_validates_before_transport(monkeypatch):
    connector = SAPODataConnector(
        config=SAPConfig(
            base_url="https://sap.example.test",
            api_key="api-key",
            write_demo_mode=False,
            use_fixture_fallback=False,
        )
    )

    async def fail_fetch():
        raise AssertionError("CSRF transport should not be called")

    async def fail_patch(path, payload):
        raise AssertionError("PATCH transport should not be called")

    monkeypatch.setattr(connector, "_fetch_csrf_token", fail_fetch)
    monkeypatch.setattr(connector, "_odata_patch", fail_patch)

    with pytest.raises(ValueError, match="unsupported_field"):
        await connector.write_update(
            "PurchaseOrder",
            "PO-4500001234",
            {"unsupported_field": "value"},
        )


@pytest.mark.asyncio
async def test_write_update_csrf_mocked(monkeypatch):
    fake_client = _FakeAsyncClient(
        get_responses=[
            _FakeResponse(
                {"d": {}},
                headers={"X-CSRF-Token": "csrf-token-1"},
                cookies={"SAP_SESSIONID": "cookie-1"},
            )
        ],
        patch_responses=[
            _FakeResponse({"d": {"Status": "updated"}}),
        ],
    )
    monkeypatch.setattr("ci_platform.connectors.sap.httpx.AsyncClient", lambda: fake_client)
    connector = SAPODataConnector(
        config=SAPConfig(
            base_url="https://sap.example.test",
            api_key="api-key",
            bearer_token="bearer-token",
            sap_client="100",
            write_demo_mode=False,
            use_fixture_fallback=False,
        )
    )

    result = await connector.write_update(
        "PurchaseOrder",
        "PO-4500001234",
        {"hold_status": "hold"},
    )

    assert result == {"d": {"Status": "updated"}}
    assert fake_client.get_requests[0]["headers"]["X-CSRF-Token"] == "Fetch"
    patch_request = fake_client.patch_requests[0]
    assert patch_request["headers"]["X-CSRF-Token"] == "csrf-token-1"
    assert patch_request["headers"]["Content-Type"] == "application/json"
    assert patch_request["cookies"] == {"SAP_SESSIONID": "cookie-1"}
    assert patch_request["json"] == {"hold_status": "hold"}
    assert patch_request["url"] == (
        "https://sap.example.test/"
        "sap/opu/odata/sap/API_PURCHASEORDER_PROCESS_SRV/"
        "A_PurchaseOrder('PO-4500001234')"
    )


@pytest.mark.asyncio
async def test_write_update_csrf_retry_on_403(monkeypatch):
    fake_client = _FakeAsyncClient(
        get_responses=[
            _FakeResponse(
                {"d": {}},
                headers={"X-CSRF-Token": "csrf-token-1"},
                cookies={"SAP_SESSIONID": "cookie-1"},
            ),
            _FakeResponse(
                {"d": {}},
                headers={"X-CSRF-Token": "csrf-token-2"},
                cookies={"SAP_SESSIONID": "cookie-2"},
            ),
        ],
        patch_responses=[
            _FakeResponse({"error": "forbidden"}, status_code=403),
            _FakeResponse({"d": {"Status": "updated"}}),
        ],
    )
    monkeypatch.setattr("ci_platform.connectors.sap.httpx.AsyncClient", lambda: fake_client)
    connector = SAPODataConnector(
        config=SAPConfig(
            base_url="https://sap.example.test",
            api_key="api-key",
            write_demo_mode=False,
            use_fixture_fallback=False,
        )
    )

    result = await connector.write_update(
        "PurchaseOrder",
        "PO-4500001234",
        {"routing_rule": "manual_review"},
    )

    assert result == {"d": {"Status": "updated"}}
    assert len(fake_client.get_requests) == 2
    assert len(fake_client.patch_requests) == 2
    assert fake_client.patch_requests[0]["headers"]["X-CSRF-Token"] == "csrf-token-1"
    assert fake_client.patch_requests[1]["headers"]["X-CSRF-Token"] == "csrf-token-2"


@pytest.mark.asyncio
async def test_write_update_second_403_raises(monkeypatch):
    fake_client = _FakeAsyncClient(
        get_responses=[
            _FakeResponse({"d": {}}, headers={"X-CSRF-Token": "csrf-token-1"}),
            _FakeResponse({"d": {}}, headers={"X-CSRF-Token": "csrf-token-2"}),
        ],
        patch_responses=[
            _FakeResponse({"error": "forbidden"}, status_code=403),
            _FakeResponse({"error": "forbidden"}, status_code=403),
        ],
    )
    monkeypatch.setattr("ci_platform.connectors.sap.httpx.AsyncClient", lambda: fake_client)
    connector = SAPODataConnector(
        config=SAPConfig(
            base_url="https://sap.example.test",
            bearer_token="bearer-token",
            write_demo_mode=False,
            use_fixture_fallback=False,
        )
    )

    with pytest.raises(ConnectionError, match="403"):
        await connector.write_update(
            "PurchaseOrder",
            "PO-4500001234",
            {"approval_threshold": 0.95},
        )


@pytest.mark.asyncio
async def test_csrf_state_instance_local(monkeypatch):
    client_one = _FakeAsyncClient(
        get_responses=[
            _FakeResponse(
                {"d": {}},
                headers={"X-CSRF-Token": "csrf-token-1"},
                cookies={"SAP_SESSIONID": "cookie-1"},
            )
        ],
        patch_responses=[_FakeResponse({"d": {"Status": "one"}})],
    )
    client_two = _FakeAsyncClient(
        get_responses=[
            _FakeResponse(
                {"d": {}},
                headers={"X-CSRF-Token": "csrf-token-2"},
                cookies={"SAP_SESSIONID": "cookie-2"},
            )
        ],
        patch_responses=[_FakeResponse({"d": {"Status": "two"}})],
    )
    clients = [client_one, client_two]
    monkeypatch.setattr(
        "ci_platform.connectors.sap.httpx.AsyncClient",
        lambda: clients[0] if len(clients) == 2 else clients[0],
    )
    connector_one = SAPODataConnector(
        config=SAPConfig(
            base_url="https://sap-one.example.test",
            api_key="api-key",
            write_demo_mode=False,
            use_fixture_fallback=False,
        )
    )

    await connector_one.write_update("PurchaseOrder", "PO-4500001234", {"hold_status": "hold"})
    clients.pop(0)
    connector_two = SAPODataConnector(
        config=SAPConfig(
            base_url="https://sap-two.example.test",
            api_key="api-key",
            write_demo_mode=False,
            use_fixture_fallback=False,
        )
    )
    await connector_two.write_update("PurchaseOrder", "PO-4500001234", {"hold_status": "hold"})

    assert connector_one._csrf_token == "csrf-token-1"
    assert connector_one._csrf_cookies == {"SAP_SESSIONID": "cookie-1"}
    assert connector_two._csrf_token == "csrf-token-2"
    assert connector_two._csrf_cookies == {"SAP_SESSIONID": "cookie-2"}


def _write_fixture_dir(target: Path) -> None:
    for path in FIXTURE_DIR.glob("*.json"):
        (target / path.name).write_text(path.read_text(encoding="utf-8"), encoding="utf-8")


class _FakeResponse:
    def __init__(self, payload, status_code=200, headers=None, cookies=None):
        self._payload = payload
        self.status_code = status_code
        self.headers = headers or {}
        self.cookies = cookies or {}

    def json(self):
        return self._payload


class _FakeAsyncClient:
    def __init__(self, response=None, error=None, get_responses=None, patch_responses=None):
        self._response = response
        self._error = error
        self._get_responses = list(get_responses or [])
        self._patch_responses = list(patch_responses or [])
        self.requests = []
        self.get_requests = []
        self.patch_requests = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def get(self, url, headers=None, timeout=None):
        request = {"url": url, "headers": headers, "timeout": timeout}
        self.requests.append(request)
        self.get_requests.append(request)
        if self._error:
            raise self._error
        if self._get_responses:
            return self._get_responses.pop(0)
        return self._response

    async def patch(self, url, headers=None, cookies=None, json=None, timeout=None):
        request = {
            "url": url,
            "headers": headers,
            "cookies": cookies,
            "json": json,
            "timeout": timeout,
        }
        self.requests.append(request)
        self.patch_requests.append(request)
        if self._error:
            raise self._error
        if self._patch_responses:
            return self._patch_responses.pop(0)
        return self._response
