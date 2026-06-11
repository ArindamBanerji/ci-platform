from __future__ import annotations

import pytest

from ci_platform.copilot_core import (
    EntityCache,
    EntityCacheKey,
    EntityContextCacheAdapter,
)


@pytest.mark.asyncio
async def test_disabled_adapter_preserves_current_loader_path_and_does_not_store():
    cache = EntityCache(max_size=8)
    adapter = EntityContextCacheAdapter(cache, enabled=False)
    calls = 0

    async def loader():
        nonlocal calls
        calls += 1
        return {"entity_id": "U1", "risk_band": f"v{calls}"}

    first = await adapter.get_context("soc", "user", "U1", loader)
    second = await adapter.get_context("soc", "user", "U1", loader)

    assert first == {"entity_id": "U1", "risk_band": "v1"}
    assert second == {"entity_id": "U1", "risk_band": "v2"}
    assert calls == 2
    assert adapter.stats().size == 0


@pytest.mark.asyncio
async def test_enabled_adapter_matches_loader_then_hits_cache():
    cache = EntityCache(max_size=8)
    adapter = EntityContextCacheAdapter(cache, enabled=True)
    calls = 0

    async def current_graph_loader():
        nonlocal calls
        calls += 1
        return {
            "entity_id": "U1",
            "risk_band": "medium",
            "department": "finance",
        }

    graph_truth = await current_graph_loader()
    calls = 0

    first = await adapter.get_context("soc", "user", "U1", current_graph_loader)
    second = await adapter.get_context("soc", "user", "U1", current_graph_loader)

    assert first == graph_truth
    assert second == graph_truth
    assert calls == 1
    stats = adapter.stats()
    assert stats.misses == 1
    assert stats.hits == 1
    assert stats.loads == 1


@pytest.mark.asyncio
async def test_invalidation_reload_sees_updated_stable_context():
    cache = EntityCache(max_size=8)
    adapter = EntityContextCacheAdapter(cache, enabled=True)
    context = {"entity_id": "A1", "criticality": "normal"}
    calls = 0

    async def loader():
        nonlocal calls
        calls += 1
        return dict(context)

    assert await adapter.get_context("soc", "asset", "A1", loader) == {
        "entity_id": "A1",
        "criticality": "normal",
    }
    context["criticality"] = "high"
    assert adapter.invalidate("soc", "asset", "A1") is True
    assert await adapter.get_context("soc", "asset", "A1", loader) == {
        "entity_id": "A1",
        "criticality": "high",
    }
    assert calls == 2
    assert adapter.stats().invalidations == 1


def test_adapter_rejects_non_cacheable_soc_boundaries():
    adapter = EntityContextCacheAdapter(EntityCache(max_size=8), enabled=True)

    forbidden_kinds = [
        "alert",
        "subject",
        "counter",
        "proof",
        "dk",
        "l5",
        "decision",
        "outcome",
        "conservation",
    ]

    for kind in forbidden_kinds:
        with pytest.raises(ValueError):
            adapter.invalidate("soc", kind, "X1")

    for kind in [
        "counter",
        "proof",
        "dk",
        "l5",
        "decision",
        "outcome",
        "conservation",
    ]:
        with pytest.raises(ValueError):
            EntityCacheKey("soc", kind, "X1")


@pytest.mark.asyncio
async def test_cross_copilot_context_keys_are_supported_without_default_enablement():
    cache = EntityCache(max_size=8)
    adapter = EntityContextCacheAdapter(cache)
    calls = 0

    async def loader():
        nonlocal calls
        calls += 1
        return {"loaded": calls}

    for domain, kind, identifier in [
        ("soc", "user", "U1"),
        ("trading", "instrument", "SPY"),
        ("purchasing", "supplier", "S1"),
        ("dataops", "source", "SRC1"),
        ("s2p", "vendor", "V1"),
    ]:
        assert await adapter.get_context(domain, kind, identifier, loader) == {
            "loaded": calls
        }

    assert calls == 5
    assert adapter.get_status().enabled is False
    assert cache.stats().size == 0


def test_adapter_diagnostics_expose_cache_status_and_non_context_boundary():
    cache = EntityCache(max_size=2, ttl_seconds=60)
    adapter = EntityContextCacheAdapter(cache, enabled=True)
    cache.set(EntityCacheKey("soc", "user", "U1"), {"risk": "low"})

    status = adapter.get_status()
    stats = adapter.stats()

    assert status.enabled is True
    assert status.cache.max_size == 2
    assert status.cache.ttl_seconds == 60
    assert "alert" in status.non_context_kinds
    assert "subject" in status.non_context_kinds
    assert stats.size == 1
