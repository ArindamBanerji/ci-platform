import base64
import uuid
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, Optional
from urllib.parse import urlencode

from onelogin.saml2.auth import OneLogin_Saml2_Auth


@dataclass
class SAMLConfig:
    sp_entity_id: str = "https://soccopilot.example.com/sso/metadata"
    sp_acs_url: str = "https://soccopilot.example.com/sso/acs"
    sp_sls_url: str = "https://soccopilot.example.com/sso/sls"
    idp_entity_id: str = ""
    idp_sso_url: str = ""
    idp_sls_url: str = ""
    idp_x509_cert: str = ""
    want_assertions_signed: bool = True
    authn_requests_signed: bool = True


# XML namespace constants
_NS_MD = "urn:oasis:names:tc:SAML:2.0:metadata"
_NS_SAML = "urn:oasis:names:tc:SAML:2.0:assertion"
_NS_SAMLP = "urn:oasis:names:tc:SAML:2.0:protocol"
_NS_DS = "http://www.w3.org/2000/09/xmldsig#"

# Register namespaces for clean serialisation
ET.register_namespace("md", _NS_MD)
ET.register_namespace("saml", _NS_SAML)
ET.register_namespace("samlp", _NS_SAMLP)
ET.register_namespace("ds", _NS_DS)


class SAMLService:
    def __init__(self, config: SAMLConfig):
        self._config = config

    # ── public API ───────────────────────────────────────────────────────────

    def get_sp_metadata(self) -> str:
        """Return SAML 2.0 SP metadata XML string."""
        cfg = self._config

        root = ET.Element(f"{{{_NS_MD}}}EntityDescriptor", attrib={
            "entityID": cfg.sp_entity_id,
            "xmlns:md": _NS_MD,
        })

        sp_sso = ET.SubElement(root, f"{{{_NS_MD}}}SPSSODescriptor", attrib={
            "AuthnRequestsSigned": str(cfg.authn_requests_signed).lower(),
            "WantAssertionsSigned": str(cfg.want_assertions_signed).lower(),
            "protocolSupportEnumeration": _NS_SAMLP,
        })

        ET.SubElement(sp_sso, f"{{{_NS_MD}}}AssertionConsumerService", attrib={
            "Binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
            "Location": cfg.sp_acs_url,
            "index": "1",
        })

        ET.SubElement(sp_sso, f"{{{_NS_MD}}}SingleLogoutService", attrib={
            "Binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            "Location": cfg.sp_sls_url,
        })

        return '<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(root, encoding="unicode")

    def create_authn_request(self) -> Dict:
        """Create a base64-encoded AuthnRequest and return redirect URL."""
        cfg = self._config
        request_id = f"_soccopilot_{uuid.uuid4().hex}"
        issue_instant = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        root = ET.Element(f"{{{_NS_SAMLP}}}AuthnRequest", attrib={
            "xmlns:samlp": _NS_SAMLP,
            "xmlns:saml": _NS_SAML,
            "ID": request_id,
            "Version": "2.0",
            "IssueInstant": issue_instant,
            "Destination": cfg.idp_sso_url,
            "AssertionConsumerServiceURL": cfg.sp_acs_url,
            "ProtocolBinding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
        })

        issuer = ET.SubElement(root, f"{{{_NS_SAML}}}Issuer")
        issuer.text = cfg.sp_entity_id

        xml_str = ET.tostring(root, encoding="unicode")
        encoded = base64.b64encode(xml_str.encode()).decode()

        sep = "&" if "?" in cfg.idp_sso_url else "?"
        redirect_url = cfg.idp_sso_url + sep + urlencode({"SAMLRequest": encoded})

        return {
            "request_id": request_id,
            "redirect_url": redirect_url,
            "issue_instant": issue_instant,
        }

    def validate_response(self, saml_response: str,
                          request_data: dict = None) -> Dict:
        """
        Validate a base64-encoded SAMLResponse.

        When IdP x509 cert is configured: full python3-saml
        signature verification + assertion validation.
        When not configured: returns error (no fallback).

        Args:
            saml_response: base64-encoded SAMLResponse from IdP
            request_data: dict with keys for python3-saml context:
                {"http_host": "localhost:8001",
                 "script_name": "/saml/acs",
                 "https": "off",
                 "post_data": {"SAMLResponse": saml_response}}

        Returns:
            {"valid": True/False, "user_email": str|None,
             "session_index": str|None, "attributes": dict,
             "error": str|None}
        """
        if not self._config.idp_x509_cert:
            return {
                "valid": False,
                "user_email": None,
                "session_index": None,
                "attributes": {},
                "error": "IdP x509 cert required for SAML validation",
            }
        try:
            return self._validate_with_python3_saml(saml_response, request_data)
        except Exception as exc:
            return {
                "valid": False,
                "user_email": None,
                "session_index": None,
                "attributes": {},
                "error": str(exc),
            }

    def is_configured(self) -> bool:
        """True when all required IdP details are present."""
        cfg = self._config
        return bool(cfg.idp_entity_id and cfg.idp_sso_url and cfg.idp_x509_cert)

    # ── private helpers ──────────────────────────────────────────────────────

    def _parse_xml_only(self, saml_response: str) -> Dict:
        """Parse base64 SAMLResponse XML without signature verification. Test use only."""
        try:
            decoded = base64.b64decode(saml_response).decode("utf-8")
        except Exception as exc:
            return {
                "valid": False,
                "user_email": None,
                "session_index": None,
                "attributes": {},
                "error": f"Base64 decode error: {exc}",
            }

        try:
            root = ET.fromstring(decoded)
        except ET.ParseError as exc:
            return {
                "valid": False,
                "user_email": None,
                "session_index": None,
                "attributes": {},
                "error": f"XML parse error: {exc}",
            }

        name_id = _find_text(root, [
            f".//{{{_NS_SAML}}}NameID",
            ".//NameID",
        ])

        session_index = _find_attr(root, [
            f".//{{{_NS_SAMLP}}}AuthnStatement",
            ".//AuthnStatement",
        ], "SessionIndex")

        user_email = name_id if (name_id and "@" in name_id) else None

        return {
            "valid": True,
            "user_email": user_email,
            "session_index": session_index,
            "attributes": {},
            "error": None,
        }

    def _validate_with_python3_saml(self, saml_response: str,
                                     request_data: dict) -> Dict:
        """Full signature + assertion verification via python3-saml."""
        cfg = self._config
        settings_dict = {
            "strict": False,
            "debug": False,
            "sp": {
                "entityId": cfg.sp_entity_id,
                "assertionConsumerService": {
                    "url": cfg.sp_acs_url,
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
                },
                "singleLogoutService": {
                    "url": cfg.sp_sls_url,
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
                },
                "NameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
                "x509cert": "",
                "privateKey": "",
            },
            "idp": {
                "entityId": cfg.idp_entity_id,
                "singleSignOnService": {
                    "url": cfg.idp_sso_url,
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
                },
                "singleLogoutService": {
                    "url": cfg.idp_sls_url,
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
                },
                "x509cert": cfg.idp_x509_cert,
            },
        }

        req = {
            "https": request_data.get("https", "off") if request_data else "off",
            "http_host": request_data.get("http_host", "localhost") if request_data else "localhost",
            "script_name": request_data.get("script_name", "/saml/acs") if request_data else "/saml/acs",
            "server_port": request_data.get("server_port", "443") if request_data else "443",
            "get_data": request_data.get("get_data", {}) if request_data else {},
            "post_data": {"SAMLResponse": saml_response},
        }

        auth = OneLogin_Saml2_Auth(req, old_settings=settings_dict)
        auth.process_response()

        if not auth.is_authenticated():
            return {
                "valid": False,
                "user_email": None,
                "session_index": None,
                "attributes": {},
                "error": auth.get_last_error_reason(),
            }

        name_id = auth.get_nameid()
        attributes = auth.get_attributes() or {}
        session_index = auth.get_session_index()
        user_email = name_id if (name_id and "@" in name_id) else None

        return {
            "valid": True,
            "user_email": user_email,
            "session_index": session_index,
            "attributes": attributes,
            "error": None,
        }


# ── helpers ──────────────────────────────────────────────────────────────────

def _find_text(root: ET.Element, xpaths: list) -> Optional[str]:
    for xpath in xpaths:
        el = root.find(xpath)
        if el is not None and el.text:
            return el.text.strip()
    return None


def _find_attr(root: ET.Element, xpaths: list, attr: str) -> Optional[str]:
    for xpath in xpaths:
        el = root.find(xpath)
        if el is not None and el.get(attr):
            return el.get(attr)
    return None
