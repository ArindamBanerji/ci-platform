"""SAP S/4HANA fixture parsing, manifest building, and read connector.

This module maps deterministic SAP fixture data into LoadManifest-compatible
dicts and provides a read-only OData source-selection layer. Write-back and
CSRF handling are intentionally deferred to a later implementation prompt.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from json import JSONDecodeError
from pathlib import Path
from typing import Any

import httpx


SAP_NODE_TYPES = {"PurchaseOrder", "SupplierInvoice", "BusinessPartner"}
SAP_EDGE_TYPES = {"INVOICED_BY", "ORDERED_FROM"}
WRITABLE_ENTITY_TYPES = {"PurchaseOrder"}
READ_ONLY_ENTITY_TYPES = {"BusinessPartner"}
ALLOWED_WRITE_FIELDS = {
    "matching_parameter",
    "approval_threshold",
    "routing_rule",
    "hold_status",
}
_FALSE_VALUES = {"0", "false", "no", "off"}
_TRUE_VALUES = {"1", "true", "yes", "on"}
_PURCHASE_ORDERS_PATH = (
    "/sap/opu/odata/sap/API_PURCHASEORDER_PROCESS_SRV/A_PurchaseOrder"
)
_INVOICES_PATH = (
    "/sap/opu/odata/sap/API_SUPPLIERINVOICE_PROCESS_SRV/A_SupplierInvoice"
)
_SUPPLIERS_PATH = "/sap/opu/odata/sap/API_BUSINESS_PARTNER/A_BusinessPartner"

_PURCHASE_ORDER_FIELDS = {
    "PurchaseOrder",
    "Supplier",
    "NetAmount",
    "Currency",
    "Plant",
    "Status",
}
_INVOICE_FIELDS = {
    "SupplierInvoice",
    "Supplier",
    "GrossAmount",
    "Currency",
    "MatchStatus",
}
_SUPPLIER_FIELDS = {
    "BusinessPartner",
    "BusinessPartnerFullName",
    "SupplierAlias",
    "SupplierType",
    "PlantCodes",
}


@dataclass
class SAPConfig:
    base_url: str | None = None
    api_key: str | None = None
    bearer_token: str | None = None
    sap_client: str | None = None
    use_fixture_fallback: bool = True
    write_demo_mode: bool = True
    fixture_dir: str | None = None

    @classmethod
    def from_env(cls) -> "SAPConfig":
        return cls(
            base_url=os.getenv("SAP_BASE_URL"),
            api_key=os.getenv("SAP_API_KEY"),
            bearer_token=os.getenv("SAP_BEARER_TOKEN") or os.getenv("SAP_OAUTH_TOKEN"),
            sap_client=os.getenv("SAP_CLIENT"),
            use_fixture_fallback=_parse_env_bool(
                "SAP_USE_FIXTURE_FALLBACK",
                os.getenv("SAP_USE_FIXTURE_FALLBACK"),
                default=True,
            ),
            write_demo_mode=_parse_env_bool(
                "SAP_WRITE_DEMO_MODE",
                os.getenv("SAP_WRITE_DEMO_MODE"),
                default=True,
            ),
            fixture_dir=os.getenv("SAP_FIXTURE_DIR"),
        )


@dataclass(frozen=True)
class SAPFixture:
    purchase_orders: list[dict[str, Any]]
    invoices: list[dict[str, Any]]
    suppliers: list[dict[str, Any]]
    write_response_cache: dict[str, Any]

    @classmethod
    def from_dir(cls, fixture_dir: str | Path) -> "SAPFixture":
        base = Path(fixture_dir)
        purchase_orders = _load_json_file(base / "purchase_orders.json")
        invoices = _load_json_file(base / "invoices.json")
        suppliers = _load_json_file(base / "suppliers.json")
        write_response_cache = _load_json_file(base / "write_response_cache.json")

        if not isinstance(purchase_orders, list):
            raise ValueError("SAP purchase_orders fixture must be a list")
        if not isinstance(invoices, list):
            raise ValueError("SAP invoices fixture must be a list")
        if not isinstance(suppliers, list):
            raise ValueError("SAP suppliers fixture must be a list")
        if not isinstance(write_response_cache, dict):
            raise ValueError("SAP write_response_cache fixture must be a mapping")
        if "d" not in write_response_cache:
            raise ValueError("SAP write_response_cache fixture missing required key: d")

        fixture = cls(
            purchase_orders=_copy_records(purchase_orders, "PurchaseOrder"),
            invoices=_copy_records(invoices, "SupplierInvoice"),
            suppliers=_copy_records(suppliers, "BusinessPartner"),
            write_response_cache=dict(write_response_cache),
        )
        fixture._validate()
        return fixture

    def _validate(self) -> None:
        _validate_required_fields("PurchaseOrder", self.purchase_orders, _PURCHASE_ORDER_FIELDS)
        _validate_required_fields("SupplierInvoice", self.invoices, _INVOICE_FIELDS)
        _validate_required_fields("BusinessPartner", self.suppliers, _SUPPLIER_FIELDS)
        _validate_unique_field("PurchaseOrder", self.purchase_orders, "PurchaseOrder")
        _validate_unique_field("SupplierInvoice", self.invoices, "SupplierInvoice")
        _validate_unique_field("BusinessPartner", self.suppliers, "BusinessPartner")
        for index, supplier in enumerate(self.suppliers):
            plant_codes = supplier["PlantCodes"]
            if not isinstance(plant_codes, list):
                raise ValueError(
                    f"BusinessPartner record {index} field PlantCodes must be a list"
                )


class SAPManifestBuilder:
    def __init__(self, fixture: SAPFixture):
        self._fixture = fixture

    def build(self) -> dict[str, Any]:
        nodes = self._build_nodes()
        relationships = self._build_relationships()
        return {
            "nodes": nodes,
            "relationships": relationships,
            "entity_map": {},
            "stats": self._build_stats(nodes, relationships),
        }

    def _build_nodes(self) -> list[dict[str, Any]]:
        nodes: list[dict[str, Any]] = []
        for record in self._fixture.purchase_orders:
            node = {
                **record,
                "id": record["PurchaseOrder"],
                "type": "PurchaseOrder",
                "po_number": record["PurchaseOrder"],
                "supplier": record["Supplier"],
                "amount": record["NetAmount"],
                "currency": record["Currency"],
                "plant": record["Plant"],
                "status": record["Status"],
            }
            if "MaterialGroup" in record:
                node["material_group"] = record["MaterialGroup"]
            nodes.append(node)

        for record in self._fixture.invoices:
            node = {
                **record,
                "id": record["SupplierInvoice"],
                "type": "SupplierInvoice",
                "invoice_number": record["SupplierInvoice"],
                "supplier": record["Supplier"],
                "amount": record["GrossAmount"],
                "currency": record["Currency"],
                "match_status": record["MatchStatus"],
            }
            if "ExceptionReason" in record:
                node["exception_reason"] = record["ExceptionReason"]
            nodes.append(node)

        for record in self._fixture.suppliers:
            nodes.append(
                {
                    **record,
                    "id": record["BusinessPartner"],
                    "type": "BusinessPartner",
                    "name": record["BusinessPartnerFullName"],
                    "supplier_alias": record["SupplierAlias"],
                    "supplier_type": record["SupplierType"],
                    "plant_codes": list(record["PlantCodes"]),
                }
            )
        return nodes

    def _build_relationships(self) -> list[dict[str, Any]]:
        relationships: list[dict[str, Any]] = []
        suppliers_by_name = _supplier_lookup(self._fixture.suppliers)

        for purchase_order in self._fixture.purchase_orders:
            po_id = purchase_order["PurchaseOrder"]
            supplier_name = purchase_order["Supplier"]

            for invoice in self._fixture.invoices:
                if invoice["Supplier"] == supplier_name:
                    relationships.append(
                        {
                            "source": po_id,
                            "target": invoice["SupplierInvoice"],
                            "type": "INVOICED_BY",
                        }
                    )

            supplier_id = suppliers_by_name.get(supplier_name)
            if supplier_id:
                relationships.append(
                    {
                        "source": po_id,
                        "target": supplier_id,
                        "type": "ORDERED_FROM",
                    }
                )

        return relationships

    def _build_stats(
        self,
        nodes: list[dict[str, Any]],
        relationships: list[dict[str, Any]],
    ) -> dict[str, Any]:
        node_types = {
            node_type: sum(1 for node in nodes if node["type"] == node_type)
            for node_type in sorted(SAP_NODE_TYPES)
        }
        edge_types = {
            edge_type: sum(1 for rel in relationships if rel["type"] == edge_type)
            for edge_type in sorted(SAP_EDGE_TYPES)
        }
        return {
            "node_count": len(nodes),
            "relationship_count": len(relationships),
            "node_types": node_types,
            "edge_types": edge_types,
            "purchase_order_count": len(self._fixture.purchase_orders),
            "invoice_count": len(self._fixture.invoices),
            "supplier_count": len(self._fixture.suppliers),
        }


class SAPODataConnector:
    """Read-only SAP OData connector with REST and fixture source selection."""

    def __init__(
        self,
        config: SAPConfig | None = None,
        fixture_dir: str | Path | None = None,
    ):
        self._config = config or SAPConfig()
        selected_fixture_dir = fixture_dir or self._config.fixture_dir
        self._fixture_dir = Path(selected_fixture_dir) if selected_fixture_dir else None
        self._source: str | None = None
        self._csrf_token: str | None = None
        self._csrf_cookies: dict[str, Any] = {}

    async def connect(self) -> None:
        if self._source:
            return
        if self._is_configured():
            self._source = "rest"
            return
        if self._can_use_fixture():
            self._source = "fixture"

    async def health_check(self) -> dict[str, Any]:
        await self.connect()
        if self._source == "rest":
            try:
                await self._rest_get_json("/")
            except (ConnectionError, ValueError) as exc:
                return {"status": "error", "source": "rest", "reason": str(exc)}
            return {"status": "ok", "source": "rest"}
        if self._source == "fixture":
            return {"status": "degraded", "source": "fixture"}
        return {"status": "not_configured", "source": None}

    async def fetch_purchase_orders(self) -> list[dict[str, Any]]:
        await self.connect()
        if self._source == "fixture":
            return list(self._fetch_from_fixture().purchase_orders)
        if self._source == "rest":
            return await self._odata_get_list(_PURCHASE_ORDERS_PATH, "PurchaseOrder")
        raise ConnectionError("SAPODataConnector is not configured")

    async def fetch_invoices(self) -> list[dict[str, Any]]:
        await self.connect()
        if self._source == "fixture":
            return list(self._fetch_from_fixture().invoices)
        if self._source == "rest":
            return await self._odata_get_list(_INVOICES_PATH, "SupplierInvoice")
        raise ConnectionError("SAPODataConnector is not configured")

    async def fetch_suppliers(self) -> list[dict[str, Any]]:
        await self.connect()
        if self._source == "fixture":
            return list(self._fetch_from_fixture().suppliers)
        if self._source == "rest":
            return await self._odata_get_list(_SUPPLIERS_PATH, "BusinessPartner")
        raise ConnectionError("SAPODataConnector is not configured")

    async def to_load_manifest(self) -> dict[str, Any]:
        fixture = SAPFixture(
            purchase_orders=await self.fetch_purchase_orders(),
            invoices=await self.fetch_invoices(),
            suppliers=await self.fetch_suppliers(),
            write_response_cache={"d": {}},
        )
        fixture._validate()
        return SAPManifestBuilder(fixture).build()

    async def write_update(
        self,
        entity_type: str,
        entity_id: str,
        payload: dict[str, Any],
        decision_id: str | None = None,
    ) -> dict[str, Any]:
        self._validate_write_request(entity_type, entity_id, payload)

        if self._config.write_demo_mode:
            return dict(self._fetch_from_fixture().write_response_cache)

        if not self._is_configured():
            raise ConnectionError("SAP REST source is not configured for write-back")

        if not self._csrf_token:
            await self._fetch_csrf_token()

        path = _patch_path(entity_type, entity_id)
        try:
            return await self._odata_patch(path, payload)
        except _SAPForbiddenError:
            await self._fetch_csrf_token()
            try:
                return await self._odata_patch(path, payload)
            except _SAPForbiddenError as exc:
                raise ConnectionError("SAP PATCH returned 403 after CSRF token refresh") from exc

    def _is_configured(self) -> bool:
        return bool(
            self._config.base_url
            and (self._config.api_key or self._config.bearer_token)
        )

    def _can_use_fixture(self) -> bool:
        return bool(self._config.use_fixture_fallback and self._fixture_dir)

    def _auth_headers(self) -> dict[str, str]:
        headers: dict[str, str] = {}
        if self._config.api_key:
            headers["APIKey"] = self._config.api_key
        if self._config.bearer_token:
            headers["Authorization"] = f"Bearer {self._config.bearer_token}"
        if self._config.sap_client:
            headers["sap-client"] = self._config.sap_client
        return headers

    async def _odata_get_list(self, path: str, entity_type: str) -> list[dict[str, Any]]:
        payload = await self._rest_get_json(path)
        data = payload.get("d")
        if isinstance(data, dict):
            records = data.get("results")
            if isinstance(records, list):
                return _copy_records(records, entity_type)
            return _copy_records([data], entity_type)
        raise ValueError(f"SAP OData response for {entity_type} missing object field: d")

    async def _rest_get_json(self, path: str) -> dict[str, Any]:
        if not self._config.base_url:
            raise ConnectionError("SAP REST source is not configured")
        url = f"{self._config.base_url.rstrip('/')}/{path.lstrip('/')}"
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(url, headers=self._auth_headers(), timeout=30.0)
        except httpx.HTTPError as exc:
            raise ConnectionError(f"SAP REST request failed: {exc}") from exc

        status_code = getattr(response, "status_code", None)
        if not isinstance(status_code, int) or not 200 <= status_code < 300:
            raise ConnectionError(f"SAP REST request returned status {status_code}")

        try:
            payload = response.json()
        except ValueError as exc:
            raise ValueError("SAP REST response did not contain valid JSON") from exc
        if not isinstance(payload, dict):
            raise ValueError("SAP REST response must be a JSON object")
        return payload

    async def _fetch_csrf_token(self) -> None:
        if not self._config.base_url:
            raise ConnectionError("SAP REST source is not configured for CSRF token fetch")

        headers = self._auth_headers()
        headers["X-CSRF-Token"] = "Fetch"
        url = f"{self._config.base_url.rstrip('/')}/"
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(url, headers=headers, timeout=30.0)
        except httpx.HTTPError as exc:
            raise ConnectionError(f"SAP CSRF token request failed: {exc}") from exc

        status_code = getattr(response, "status_code", None)
        if not isinstance(status_code, int) or not 200 <= status_code < 300:
            raise ConnectionError(f"SAP CSRF token request returned status {status_code}")

        token = _response_header(response, "X-CSRF-Token")
        if not token:
            raise ConnectionError("SAP CSRF token response missing X-CSRF-Token header")
        self._csrf_token = token
        self._csrf_cookies = dict(getattr(response, "cookies", {}) or {})

    async def _odata_patch(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        if not self._config.base_url:
            raise ConnectionError("SAP REST source is not configured for PATCH")
        if not self._csrf_token:
            raise ConnectionError("SAP CSRF token is not available for PATCH")

        headers = self._auth_headers()
        headers["X-CSRF-Token"] = self._csrf_token
        headers["Content-Type"] = "application/json"
        url = f"{self._config.base_url.rstrip('/')}/{path.lstrip('/')}"
        try:
            async with httpx.AsyncClient() as client:
                response = await client.patch(
                    url,
                    headers=headers,
                    cookies=self._csrf_cookies,
                    json=payload,
                    timeout=30.0,
                )
        except httpx.HTTPError as exc:
            raise ConnectionError(f"SAP PATCH request failed: {exc}") from exc

        status_code = getattr(response, "status_code", None)
        if status_code == 403:
            raise _SAPForbiddenError("SAP PATCH returned 403")
        if not isinstance(status_code, int) or not 200 <= status_code < 300:
            raise ConnectionError(f"SAP PATCH request returned status {status_code}")

        try:
            result = response.json()
        except ValueError as exc:
            raise ValueError("SAP PATCH response did not contain valid JSON") from exc
        if not isinstance(result, dict):
            raise ValueError("SAP PATCH response must be a JSON object")
        return result

    def _fetch_from_fixture(self) -> SAPFixture:
        if not self._fixture_dir:
            raise ConnectionError("SAP fixture fallback is enabled but no fixture dir was provided")
        return SAPFixture.from_dir(self._fixture_dir)

    def _validate_write_request(
        self,
        entity_type: str,
        entity_id: str,
        payload: dict[str, Any],
    ) -> None:
        if entity_type in READ_ONLY_ENTITY_TYPES:
            raise ValueError(f"{entity_type} is read-only and cannot be written")
        if entity_type not in WRITABLE_ENTITY_TYPES:
            raise ValueError(f"Unsupported SAP write entity_type: {entity_type}")
        if not isinstance(entity_id, str) or not entity_id.strip():
            raise ValueError("SAP write entity_id must be a non-empty string")
        if not isinstance(payload, dict) or not payload:
            raise ValueError("SAP write payload must be a non-empty mapping")
        unsupported = sorted(set(payload) - ALLOWED_WRITE_FIELDS)
        if unsupported:
            raise ValueError(f"Unsupported SAP write payload fields: {unsupported}")


def _load_json_file(path: Path) -> Any:
    if not path.exists():
        raise FileNotFoundError(f"SAP fixture file not found: {path}")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except JSONDecodeError as exc:
        raise ValueError(f"Invalid SAP fixture JSON in {path}: {exc}") from exc


def _copy_records(records: list[Any], record_type: str) -> list[dict[str, Any]]:
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
                raise ValueError(f"{record_type} record {index} missing required field: {field}")


def _validate_unique_field(
    record_type: str,
    records: list[dict[str, Any]],
    field: str,
) -> None:
    seen: set[Any] = set()
    for index, record in enumerate(records):
        value = record[field]
        if value in seen:
            raise ValueError(f"{record_type} record {index} has duplicate {field}: {value}")
        seen.add(value)


def _supplier_lookup(suppliers: list[dict[str, Any]]) -> dict[str, str]:
    lookup: dict[str, str] = {}
    for supplier in suppliers:
        supplier_id = supplier["BusinessPartner"]
        lookup[supplier["SupplierAlias"]] = supplier_id
        lookup[supplier["BusinessPartnerFullName"]] = supplier_id
    return lookup


def _parse_env_bool(name: str, value: str | None, default: bool) -> bool:
    if value is None:
        return default
    normalized = value.strip().lower()
    if normalized in _TRUE_VALUES:
        return True
    if normalized in _FALSE_VALUES:
        return False
    raise ValueError(f"Invalid boolean value for {name}: {value}")


class _SAPForbiddenError(ConnectionError):
    pass


def _patch_path(entity_type: str, entity_id: str) -> str:
    if entity_type == "PurchaseOrder":
        return (
            "/sap/opu/odata/sap/API_PURCHASEORDER_PROCESS_SRV/"
            f"A_PurchaseOrder('{entity_id}')"
        )
    raise ValueError(f"Unsupported SAP write entity_type: {entity_type}")


def _response_header(response: Any, name: str) -> str | None:
    headers = getattr(response, "headers", {}) or {}
    value = headers.get(name)
    if value is None:
        value = headers.get(name.lower())
    if value is None:
        return None
    return str(value)
