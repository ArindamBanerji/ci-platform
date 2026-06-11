from __future__ import annotations

import asyncio

import pytest

from ci_platform.copilot_core.cache import EntityCache, EntityCacheKey


@pytest.mark.asyncio
async def test_cache_miss_calls_loader_and_hit_reuses_value():
    cache = EntityCache(max_size=4)
    calls = 0
    key = EntityCacheKey("soc", "user", "U1")

    async def loader():
        nonlocal calls
        calls += 1
        return {"risk": 0.7}

    first = await cache.get_or_load(key, loader)
    second = await cache.get_or_load(key, loader)

    assert first == {"risk": 0.7}
    assert second == {"risk": 0.7}
    assert calls == 1
    stats = cache.stats()
    assert stats.misses == 1
    assert stats.hits == 1
    assert stats.loads == 1


@pytest.mark.asyncio
async def test_loader_exception_is_not_cached():
    cache = EntityCache(max_size=4)
    calls = 0

    async def failing_loader():
        nonlocal calls
        calls += 1
        raise RuntimeError("load failed")

    with pytest.raises(RuntimeError):
        await cache.get_or_load(EntityCacheKey("soc", "asset", "A1"), failing_loader)
    with pytest.raises(RuntimeError):
        await cache.get_or_load(EntityCacheKey("soc", "asset", "A1"), failing_loader)

    assert calls == 2
    assert cache.stats().size == 0


@pytest.mark.asyncio
async def test_invalidate_removes_entry_and_reload_occurs():
    cache = EntityCache(max_size=4)
    calls = 0
    key = EntityCacheKey("soc", "entity", "E1")

    async def loader():
        nonlocal calls
        calls += 1
        return {"version": calls}

    assert await cache.get_or_load(key, loader) == {"version": 1}
    assert cache.invalidate(key) is True
    assert await cache.get_or_load(key, loader) == {"version": 2}
    assert cache.stats().invalidations == 1


def test_clear_removes_all_entries():
    cache = EntityCache(max_size=4)
    cache.set(EntityCacheKey("soc", "user", "U1"), {"risk": 1})
    cache.set(EntityCacheKey("soc", "asset", "A1"), {"criticality": 2})

    cache.clear()

    assert cache.get(EntityCacheKey("soc", "user", "U1")) is None
    assert cache.get(EntityCacheKey("soc", "asset", "A1")) is None
    assert cache.stats().size == 0


def test_bounded_lru_evicts_least_recently_used_entry():
    cache = EntityCache(max_size=2)
    user = EntityCacheKey("soc", "user", "U1")
    asset = EntityCacheKey("soc", "asset", "A1")
    vendor = EntityCacheKey("s2p", "vendor", "V1")
    cache.set(user, {"risk": 1})
    cache.set(asset, {"criticality": 2})

    assert cache.get(user) == {"risk": 1}
    cache.set(vendor, {"risk": 3})

    assert cache.get(asset) is None
    assert cache.get(user) == {"risk": 1}
    assert cache.get(vendor) == {"risk": 3}
    assert cache.stats().evictions == 1


@pytest.mark.asyncio
async def test_ttl_expiry_reloads_without_sleep():
    now = 100.0

    def time_fn() -> float:
        return now

    cache = EntityCache(max_size=4, ttl_seconds=5, time_fn=time_fn)
    calls = 0

    async def loader():
        nonlocal calls
        calls += 1
        return {"version": calls}

    key = EntityCacheKey("trading", "trader", "T1")
    assert await cache.get_or_load(key, loader) == {"version": 1}
    now = 103.0
    assert await cache.get_or_load(key, loader) == {"version": 1}
    now = 106.0
    assert await cache.get_or_load(key, loader) == {"version": 2}


def test_counter_and_proof_like_keys_are_rejected():
    cache = EntityCache(max_size=4)

    with pytest.raises(ValueError):
        EntityCacheKey("soc", "counter", "U1")
    forbidden_keys = [
        "soc:counter:U1",
        "soc:proof:D1",
        "soc:decision:D1",
        "soc:outcome:O1",
        "soc:dk:state",
        "soc:l5:centroid",
        "soc:conservation:state",
        "counter:U1",
        "proof:D1",
        "soc:counter:user:U1",
        "trading:decision:abc",
    ]

    for key in forbidden_keys:
        with pytest.raises(ValueError):
            cache.set(key, {"must": "not cache"})


def test_valid_entity_context_string_and_typed_keys_are_accepted():
    cache = EntityCache(max_size=8)

    cache.set("soc:user:U1", {"risk": 0.1})
    cache.set("soc:asset:A1", {"criticality": 0.9})
    cache.set("s2p:vendor:V1", {"risk": 0.2})
    cache.set("trading:instrument:SPY", {"sector": "ETF"})
    cache.set("dataops:source:S1", {"owner": "ops"})
    cache.set(EntityCacheKey("soc", "user", "U2"), {"risk": 0.3})

    assert cache.get("soc:user:U1") == {"risk": 0.1}
    assert cache.get(EntityCacheKey("soc", "user", "U2")) == {"risk": 0.3}


def test_constructor_rejects_invalid_bounds_and_accepts_no_ttl():
    with pytest.raises(ValueError):
        EntityCache(max_size=0)
    with pytest.raises(ValueError):
        EntityCache(max_size=-1)
    with pytest.raises(ValueError):
        EntityCache(ttl_seconds=0)
    with pytest.raises(ValueError):
        EntityCache(ttl_seconds=-1)

    cache = EntityCache(max_size=1, ttl_seconds=None)

    assert cache.get_status().ttl_seconds is None


@pytest.mark.asyncio
async def test_concurrent_same_key_get_or_load_is_single_flight():
    cache = EntityCache(max_size=4)
    calls = 0
    gate = asyncio.Event()

    async def loader():
        nonlocal calls
        calls += 1
        await gate.wait()
        return {"loaded": True}

    key = EntityCacheKey("purchasing", "supplier", "S1")
    tasks = [asyncio.create_task(cache.get_or_load(key, loader)) for _ in range(5)]
    await asyncio.sleep(0)
    gate.set()
    results = await asyncio.gather(*tasks)

    assert results == [{"loaded": True}] * 5
    assert calls == 1
    assert cache.stats().loads == 1


def test_status_exposes_diagnostics_without_route_adoption():
    cache = EntityCache(max_size=3, ttl_seconds=30, enabled=True)
    cache.set(EntityCacheKey("dataops", "pipeline", "P1"), {"owner": "ops"})

    status = cache.get_status()
    stats = cache.stats()

    assert status.enabled is True
    assert status.max_size == 3
    assert status.ttl_seconds == 30
    assert status.size == 1
    assert "counter" in status.forbidden_kinds
    assert stats.size == 1
    assert stats.max_size == 3


@pytest.mark.asyncio
async def test_disabled_cache_does_not_store_or_change_loader_behavior():
    cache = EntityCache(max_size=4, enabled=False)
    calls = 0

    async def loader():
        nonlocal calls
        calls += 1
        return {"call": calls}

    key = EntityCacheKey("s2p", "vendor", "V1")
    assert await cache.get_or_load(key, loader) == {"call": 1}
    assert await cache.get_or_load(key, loader) == {"call": 2}
    assert cache.stats().size == 0
