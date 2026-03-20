from ci_platform.entity_resolution.resolver import (
    EntityResolver,
    Identifier,
    IdentifierType,
)


def test_exact_match_case_insensitive():
    resolver = EntityResolver()
    ids = [
        Identifier("john@firm.com", IdentifierType.EMAIL, "sentinel"),
        Identifier("JOHN@FIRM.COM", IdentifierType.EMAIL, "splunk"),
    ]
    entities = resolver.resolve(ids)
    assert len(entities) == 1
    assert entities[0].merge_count == 2


def test_cross_type_email_upn():
    resolver = EntityResolver()
    ids = [
        Identifier("john.smith@firm.com", IdentifierType.EMAIL, "sentinel"),
        Identifier("john.smith@firm.com", IdentifierType.UPN, "ad"),
    ]
    entities = resolver.resolve(ids)
    assert len(entities) == 1


def test_sam_to_upn_linking():
    resolver = EntityResolver()
    ids = [
        Identifier("FIRM\\jsmith", IdentifierType.SAM, "ad"),
        Identifier("jsmith@firm.com", IdentifierType.UPN, "ad"),
    ]
    entities = resolver.resolve(ids)
    assert len(entities) == 1


def test_no_merge_different_users():
    resolver = EntityResolver()
    ids = [
        Identifier("john@firm.com", IdentifierType.EMAIL, "sentinel"),
        Identifier("jane@firm.com", IdentifierType.EMAIL, "sentinel"),
    ]
    entities = resolver.resolve(ids)
    assert len(entities) == 2


def test_canonical_id_deterministic():
    resolver = EntityResolver()
    ids1 = [
        Identifier("john@firm.com", IdentifierType.EMAIL, "sentinel"),
        Identifier("FIRM\\john", IdentifierType.SAM, "ad"),
    ]
    ids2 = [
        Identifier("FIRM\\john", IdentifierType.SAM, "ad"),
        Identifier("john@firm.com", IdentifierType.EMAIL, "sentinel"),
    ]
    e1 = resolver.resolve(ids1)
    e2 = resolver.resolve(ids2)
    assert e1[0].canonical_id == e2[0].canonical_id


def test_display_name_priority():
    resolver = EntityResolver()
    ids = [
        Identifier("john@firm.com", IdentifierType.EMAIL, "sentinel"),
        Identifier("John Smith", IdentifierType.DISPLAY_NAME, "hr"),
    ]
    entities = resolver.resolve(ids)
    assert entities[0].display_name == "John Smith"


def test_hash_linking():
    """P26 hashed values with same hash resolve to same entity."""
    resolver = EntityResolver()
    ids = [
        Identifier("a1b2c3d4e5f6", IdentifierType.HASH, "alert_1"),
        Identifier("a1b2c3d4e5f6", IdentifierType.HASH, "alert_2"),
    ]
    entities = resolver.resolve(ids)
    assert len(entities) == 1
    assert entities[0].merge_count == 2


def test_completeness_score():
    resolver = EntityResolver()
    ids = [
        Identifier("john@firm.com", IdentifierType.EMAIL, "sentinel"),
        Identifier("FIRM\\john", IdentifierType.SAM, "ad"),
        Identifier("jane@firm.com", IdentifierType.EMAIL, "sentinel"),
    ]
    entities = resolver.resolve(ids)
    completeness = resolver.compute_completeness(entities)
    assert 0.0 <= completeness <= 1.0


def test_empty_input():
    resolver = EntityResolver()
    entities = resolver.resolve([])
    assert len(entities) == 0


def test_hostname_resolution():
    resolver = EntityResolver()
    ids = [
        Identifier("srv-web-01", IdentifierType.HOSTNAME, "sentinel"),
        Identifier("SRV-WEB-01", IdentifierType.HOSTNAME, "splunk"),
    ]
    entities = resolver.resolve(ids)
    assert len(entities) == 1
    assert entities[0].entity_type == "asset"
