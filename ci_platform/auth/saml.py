import base64
import uuid
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, Optional
from urllib.parse import urlencode


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

    def validate_response(self, saml_response: str) -> Dict:
        """
        Decode and parse a base64-encoded SAMLResponse.

        Extracts NameID as user_email. Signature verification and assertion
        decryption are delegated to python3-saml at deployment.
        """
        try:
            decoded = base64.b64decode(saml_response).decode("utf-8")
        except Exception as exc:
            return {"valid": False, "user_email": None, "user_name": None,
                    "session_index": None, "error": f"Base64 decode error: {exc}"}

        try:
            root = ET.fromstring(decoded)
        except ET.ParseError as exc:
            return {"valid": False, "user_email": None, "user_name": None,
                    "session_index": None, "error": f"XML parse error: {exc}"}

        name_id = _find_text(root, [
            f".//{{{_NS_SAML}}}NameID",
            ".//NameID",
        ])

        session_index = _find_attr(root, [
            f".//{{{_NS_SAMLP}}}AuthnStatement",
            ".//AuthnStatement",
        ], "SessionIndex")

        # Best-effort: treat NameID as email if it contains '@'
        user_email = name_id if (name_id and "@" in name_id) else None

        return {
            "valid": True,
            "user_email": user_email,
            "user_name": name_id,
            "session_index": session_index,
            "error": None,
        }

    def is_configured(self) -> bool:
        """True when all required IdP details are present."""
        cfg = self._config
        return bool(cfg.idp_entity_id and cfg.idp_sso_url and cfg.idp_x509_cert)


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
