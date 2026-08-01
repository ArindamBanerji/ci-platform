"""Contract tests for domain-scoped AGE artifact idempotency reads."""

from __future__ import annotations

from pathlib import Path


STORE_SOURCE = Path(__file__).parents[1].joinpath(
    "ci_platform", "graph", "age_graph_store.py"
).read_text(encoding="utf-8")

ARTIFACTS = {
    "conservation_status": ("_get_conservation_status_payload", "c"),
    "fingerprint": ("_get_fingerprint_payload", "f"),
    "centroid_checkpoint": ("_get_centroid_checkpoint_payload", "c"),
    "evolution_event": ("_get_evolution_event_payload", "e"),
}


def _method_source(name: str) -> str:
    start = STORE_SOURCE.index(f"    def {name}")
    end = STORE_SOURCE.find("\n    def ", start + 1)
    return STORE_SOURCE[start:] if end == -1 else STORE_SOURCE[start:end]


def test_artifact_idempotency_domain_scoped() -> None:
    for name, alias in ARTIFACTS.values():
        source = _method_source(name)
        assert f"{alias}.domain =" in source
        assert "domain: str" in source


def test_artifact_read_uses_domain_predicate() -> None:
    for name, alias in ARTIFACTS.values():
        source = _method_source(name)
        assert f"WHERE {alias}.domain =" in source
        assert "_validated_domain(domain)" in source

