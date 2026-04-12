"""
AGE Cypher compatibility tests — document known AGE vs Neo4j incompatibilities.

Each test encodes a lesson learned during the AGE migration (Block 8.5).
Tests run without live AGE — they verify our query patterns avoid known issues.
"""
import re
import inspect
import pytest
from ci_platform.graph import age_client


class TestAGECypherPatterns:
    """Verify AGEClient source avoids known AGE anti-patterns."""

    def _get_source(self):
        return inspect.getsource(age_client)

    def test_no_count_alias(self):
        """AGE reserves 'count' as keyword. Use 'cnt' instead."""
        source = self._get_source()
        matches = re.findall(r'AS\s+count\b', source, re.IGNORECASE)
        assert len(matches) == 0, \
            f"Found {len(matches)} 'AS count' — use 'AS cnt' instead"

    def test_no_on_create_set(self):
        """AGE does not support ON CREATE SET / ON MATCH SET."""
        source = self._get_source()
        assert "ON CREATE SET" not in source.upper(), \
            "ON CREATE SET not supported in AGE — use MATCH then CREATE"
        assert "ON MATCH SET" not in source.upper(), \
            "ON MATCH SET not supported in AGE — use MATCH then SET"

    def test_no_bare_id_property(self):
        """AGE nodes use alert_id/decision_id, not bare 'id'."""
        source = self._get_source()
        matches = re.findall(r'\{id\s*:', source)
        assert len(matches) == 0, \
            f"Found {len(matches)} bare {{id:}} — use alert_id/decision_id"

    def test_no_datetime_function(self):
        """AGE does not support datetime(). Use epoch integers."""
        source = self._get_source()
        cypher_datetime = re.findall(r"datetime\(\s*\)", source)
        assert len(cypher_datetime) == 0, \
            "datetime() not supported in AGE Cypher — use epoch integers"

    def test_no_labels_index(self):
        """AGE does not support labels(n)[0]. Use head(labels(n))."""
        source = self._get_source()
        matches = re.findall(r'labels\([^)]+\)\[', source)
        assert len(matches) == 0, \
            "labels(n)[0] not supported in AGE — use head(labels(n))"

    def test_no_not_pattern(self):
        """AGE does not support NOT (a)<-[:REL]-(). Use NOT exists()."""
        source = self._get_source()
        matches = re.findall(r'NOT\s+\([^)]*\)\s*<-', source)
        assert len(matches) == 0, \
            "NOT (a)<-[:REL]-() not supported in AGE — use NOT exists() or subquery"


class TestAGEParameterPatterns:
    """Verify parameter handling follows AGE constraints."""

    def _get_source(self):
        return inspect.getsource(age_client)

    def test_no_parameterized_list_in(self):
        """AGE does not support parameterized IN lists. Use f-string inline."""
        source = self._get_source()
        matches = re.findall(r'IN\s+\$\w+', source)
        assert len(matches) == 0, \
            "Parameterized IN lists not supported in AGE — use inline f-string"

    def test_no_tostring_function(self):
        """AGE toString() behavior differs. Avoid or cast differently."""
        source = self._get_source()
        matches = re.findall(r'toString\s*\(', source)
        assert len(matches) == 0, \
            "toString() unreliable in AGE — cast differently or avoid"
