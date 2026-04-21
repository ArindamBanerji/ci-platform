import base64

from ci_platform.auth.saml import SAMLConfig, SAMLService


def test_sp_metadata_valid_xml():
    service = SAMLService(SAMLConfig())
    metadata = service.get_sp_metadata()
    assert "<?xml" in metadata
    assert "EntityDescriptor" in metadata
    assert "AssertionConsumerService" in metadata


def test_sp_metadata_contains_entity_id():
    config = SAMLConfig(sp_entity_id="https://test.example.com/metadata")
    service = SAMLService(config)
    assert "https://test.example.com/metadata" in service.get_sp_metadata()


def test_authn_request_has_redirect():
    config = SAMLConfig(idp_sso_url="https://idp.example.com/sso")
    service = SAMLService(config)
    result = service.create_authn_request()
    assert "redirect_url" in result
    assert "request_id" in result
    assert result["redirect_url"].startswith("https://idp.example.com/sso")


def test_authn_request_unique_ids():
    config = SAMLConfig(idp_sso_url="https://idp.example.com/sso")
    service = SAMLService(config)
    r1 = service.create_authn_request()
    r2 = service.create_authn_request()
    assert r1["request_id"] != r2["request_id"]


def test_validate_invalid_response():
    service = SAMLService(SAMLConfig())
    result = service.validate_response("not-valid-base64!!!")
    assert result["valid"] is False
    assert result["error"] is not None


def test_validate_valid_response():
    # Without IdP cert, validate_response must return error (D7 REVISED: no fallback)
    saml_xml = """<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
        xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_resp1">
      <saml:Assertion>
        <saml:Subject>
          <saml:NameID>analyst@firm.com</saml:NameID>
        </saml:Subject>
      </saml:Assertion>
    </samlp:Response>"""
    encoded = base64.b64encode(saml_xml.encode()).decode()
    service = SAMLService(SAMLConfig())
    result = service.validate_response(encoded)
    assert result["valid"] is False
    assert "cert" in result["error"].lower()


def test_is_configured_false_default():
    service = SAMLService(SAMLConfig())
    assert service.is_configured() is False


def test_is_configured_true():
    config = SAMLConfig(
        idp_entity_id="https://idp.example.com",
        idp_sso_url="https://idp.example.com/sso",
        idp_x509_cert="MIIC...",
    )
    service = SAMLService(config)
    assert service.is_configured() is True


def test_validate_response_requires_cert():
    """Without IdP cert, validate_response returns error."""
    cfg = SAMLConfig(sp_entity_id="test", sp_acs_url="test")
    svc = SAMLService(cfg)
    result = svc.validate_response("dGVzdA==")
    assert result["valid"] is False
    assert "cert" in result["error"].lower()


def test_validate_response_returns_attributes_key():
    """Response dict always includes attributes key."""
    cfg = SAMLConfig(sp_entity_id="test", sp_acs_url="test")
    svc = SAMLService(cfg)
    result = svc.validate_response("dGVzdA==")
    assert "attributes" in result


def test_parse_xml_only_extracts_nameid():
    """Internal XML parser still extracts NameID."""
    saml_xml = """<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
        xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_resp1">
      <saml:Assertion>
        <saml:Subject>
          <saml:NameID>analyst@firm.com</saml:NameID>
        </saml:Subject>
      </saml:Assertion>
    </samlp:Response>"""
    encoded = base64.b64encode(saml_xml.encode()).decode()
    cfg = SAMLConfig()
    svc = SAMLService(cfg)
    result = svc._parse_xml_only(encoded)
    assert result["valid"] is True
    assert result["user_email"] == "analyst@firm.com"
