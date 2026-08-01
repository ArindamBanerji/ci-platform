"""Contract checks for domain-scoped CI graph reads."""

import pytest

from ci_platform.graph.age_graph_store import AGEGraphStore


def test_age_store_get_decision_requires_domain() -> None:
    """A graph read cannot be invoked without an explicit domain."""
    store = object.__new__(AGEGraphStore)
    with pytest.raises(TypeError):
        getattr(store, "get_decision")("decision-without-domain")
