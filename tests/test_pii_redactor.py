import re

import pytest

from ci_platform.redaction.pii_redactor import PIIRedactor, RedactionStrategy


def test_ssn_hashed():
    redactor = PIIRedactor()
    clean, report = redactor.redact_text("SSN: 123-45-6789")
    assert "123-45-6789" not in clean
    assert report.total_redactions == 1
    assert report.by_type.get("ssn") == 1


def test_email_hashed():
    redactor = PIIRedactor()
    clean, report = redactor.redact_text("Contact: john@firm.com")
    assert "john@firm.com" not in clean


def test_credit_card_masked():
    redactor = PIIRedactor()
    clean, report = redactor.redact_text("Card: 4111-1111-1111-1111")
    assert "[REDACTED-CREDIT_CARD]" in clean


def test_hash_linkability():
    """Same email produces same hash across calls."""
    redactor = PIIRedactor()
    clean1, _ = redactor.redact_text("user: john@firm.com")
    clean2, _ = redactor.redact_text("alert for john@firm.com")
    hashes1 = re.findall(r"[a-f0-9]{12}", clean1)
    hashes2 = re.findall(r"[a-f0-9]{12}", clean2)
    assert len(hashes1) > 0 and hashes1[0] == hashes2[0]


def test_no_pii_passthrough():
    redactor = PIIRedactor()
    text = "Normal alert with no PII"
    clean, report = redactor.redact_text(text)
    assert clean == text
    assert report.total_redactions == 0


def test_dict_redaction_skips_exempt():
    redactor = PIIRedactor()
    data = {
        "user": "john@firm.com",
        "alert_type": "brute_force",
        "description": "SSN: 123-45-6789",
    }
    clean, report = redactor.redact_dict(data)
    assert "john@firm.com" not in clean["user"]
    assert clean["alert_type"] == "brute_force"
    assert "123-45-6789" not in clean["description"]


def test_ip_address_hashed():
    redactor = PIIRedactor()
    clean, report = redactor.redact_text("Source: 192.168.1.100")
    assert "192.168.1.100" not in clean


def test_custom_pattern():
    redactor = PIIRedactor(custom_patterns={"employee_id": r"EMP-\d{6}"})
    clean, report = redactor.redact_text("Employee EMP-123456 logged in")
    assert "EMP-123456" not in clean


def test_strategy_override():
    redactor = PIIRedactor(strategy_overrides={"email": RedactionStrategy.REMOVE})
    clean, report = redactor.redact_text("Contact: john@firm.com today")
    assert "john@firm.com" not in clean


def test_nested_dict():
    redactor = PIIRedactor()
    data = {"alert": {"user_info": {"email": "john@firm.com"}}, "alert_type": "test"}
    clean, report = redactor.redact_dict(data)
    assert "john@firm.com" not in str(clean)
    assert clean["alert_type"] == "test"
