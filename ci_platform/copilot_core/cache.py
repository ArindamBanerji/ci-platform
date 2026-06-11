"""Entity context cache for copilot analyze hot paths.

The cache is intentionally narrow: it is for immutable or rarely-changing
entity context only. Mutable counters, proof authority, decisions, outcomes,
and DK/L5/conservation state must remain outside this cache.

Cache values should be loaded entity-context objects. Loaders should not
intentionally cache None; current get() semantics treat None as a miss.
"""

from __future__ import annotations

import asyncio
import inspect
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Hashable, Mapping, Optional


Loader = Callable[[], Any | Awaitable[Any]]

_FORBIDDEN_KINDS = {
    "counter",
    "counters",
    "decision",
    "decisions",
    "outcome",
    "outcomes",
    "proof",
    "dk",
    "l5",
    "conservation",
}


@dataclass(frozen=True)
class EntityCacheKey:
    """Typed key for recurring entity context.

    `kind` should name a cacheable entity-context family such as user, asset,
    vendor, supplier, trader, instrument, pipeline, or datasource.
    """

    domain: str
    kind: str
    identifier: str

    def __post_init__(self) -> None:
        for field_name in ("domain", "kind", "identifier"):
            if not str(getattr(self, field_name, "")).strip():
                raise ValueError(f"EntityCacheKey.{field_name} must be non-empty")
        if self.kind.strip().lower() in _FORBIDDEN_KINDS:
            raise ValueError(f"{self.kind!r} is not valid for EntityCache")

    @property
    def value(self) -> str:
        return f"{self.domain}:{self.kind}:{self.identifier}"


@dataclass(frozen=True)
class EntityCacheEntry:
    key: Hashable
    value: Any
    inserted_at: float
    last_accessed_at: float
    source: str
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class EntityCacheStats:
    hits: int
    misses: int
    loads: int
    evictions: int
    invalidations: int
    size: int
    max_size: int


@dataclass(frozen=True)
class EntityCacheStatus:
    enabled: bool
    max_size: int
    ttl_seconds: Optional[float]
    size: int
    single_flight: bool = True
    forbidden_kinds: tuple[str, ...] = tuple(sorted(_FORBIDDEN_KINDS))


class EntityCache:
    """Bounded read-through LRU cache for stable entity context."""

    def __init__(
        self,
        *,
        max_size: int = 1024,
        ttl_seconds: Optional[float] = None,
        enabled: bool = True,
        source: str = "copilot_core.entity_cache",
        time_fn: Callable[[], float] = time.monotonic,
    ) -> None:
        if max_size <= 0:
            raise ValueError("EntityCache.max_size must be positive")
        if ttl_seconds is not None and ttl_seconds <= 0:
            raise ValueError("EntityCache.ttl_seconds must be positive when set")
        self.max_size = int(max_size)
        self.ttl_seconds = ttl_seconds
        self.enabled = bool(enabled)
        self.source = source
        self._time_fn = time_fn
        self._entries: OrderedDict[Hashable, EntityCacheEntry] = OrderedDict()
        self._inflight: dict[Hashable, asyncio.Future[Any]] = {}
        self._lock = threading.RLock()
        self._hits = 0
        self._misses = 0
        self._loads = 0
        self._evictions = 0
        self._invalidations = 0

    def get(self, key: Hashable) -> Any | None:
        self._validate_key(key)
        if not self.enabled:
            return None
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                self._misses += 1
                return None
            if self._is_expired(entry):
                self._entries.pop(key, None)
                self._misses += 1
                return None
            now = self._time_fn()
            updated = EntityCacheEntry(
                key=entry.key,
                value=entry.value,
                inserted_at=entry.inserted_at,
                last_accessed_at=now,
                source=entry.source,
                metadata=entry.metadata,
            )
            self._entries[key] = updated
            self._entries.move_to_end(key)
            self._hits += 1
            return entry.value

    def set(
        self,
        key: Hashable,
        value: Any,
        metadata: Optional[Mapping[str, Any]] = None,
        *,
        source: Optional[str] = None,
    ) -> EntityCacheEntry:
        self._validate_key(key)
        now = self._time_fn()
        entry = EntityCacheEntry(
            key=key,
            value=value,
            inserted_at=now,
            last_accessed_at=now,
            source=source or self.source,
            metadata=dict(metadata or {}),
        )
        if not self.enabled:
            return entry
        with self._lock:
            self._entries[key] = entry
            self._entries.move_to_end(key)
            self._evict_if_needed()
        return entry

    async def get_or_load(
        self,
        key: Hashable,
        loader: Loader,
        *,
        metadata: Optional[Mapping[str, Any]] = None,
        source: Optional[str] = None,
    ) -> Any:
        cached = self.get(key)
        if cached is not None:
            return cached
        if not self.enabled:
            return await self._call_loader(loader)

        loop = asyncio.get_running_loop()
        with self._lock:
            future = self._inflight.get(key)
            if future is None:
                future = loop.create_future()
                self._inflight[key] = future
                owner = True
            else:
                owner = False

        if not owner:
            return await future

        try:
            value = await self._call_loader(loader)
        except Exception as exc:
            with self._lock:
                self._inflight.pop(key, None)
                if not future.done():
                    future.set_exception(exc)
                # Consume the exception stored on the future when there are no
                # waiters, while still re-raising to the owner.
                future.add_done_callback(lambda f: f.exception())
            raise

        self.set(key, value, metadata=metadata, source=source)
        with self._lock:
            self._loads += 1
            self._inflight.pop(key, None)
            if not future.done():
                future.set_result(value)
        return value

    def invalidate(self, key: Hashable) -> bool:
        self._validate_key(key)
        with self._lock:
            existed = self._entries.pop(key, None) is not None
            if existed:
                self._invalidations += 1
            return existed

    def clear(self) -> None:
        with self._lock:
            removed = len(self._entries)
            self._entries.clear()
            self._invalidations += removed

    def stats(self) -> EntityCacheStats:
        with self._lock:
            return EntityCacheStats(
                hits=self._hits,
                misses=self._misses,
                loads=self._loads,
                evictions=self._evictions,
                invalidations=self._invalidations,
                size=len(self._entries),
                max_size=self.max_size,
            )

    def get_status(self) -> EntityCacheStatus:
        with self._lock:
            return EntityCacheStatus(
                enabled=self.enabled,
                max_size=self.max_size,
                ttl_seconds=self.ttl_seconds,
                size=len(self._entries),
            )

    def _evict_if_needed(self) -> None:
        while len(self._entries) > self.max_size:
            self._entries.popitem(last=False)
            self._evictions += 1

    def _is_expired(self, entry: EntityCacheEntry) -> bool:
        return (
            self.ttl_seconds is not None
            and self._time_fn() - entry.inserted_at >= self.ttl_seconds
        )

    async def _call_loader(self, loader: Loader) -> Any:
        result = loader()
        if inspect.isawaitable(result):
            return await result
        return result

    def _validate_key(self, key: Hashable) -> None:
        if isinstance(key, EntityCacheKey):
            return
        text = str(key).strip().lower()
        if not text:
            raise ValueError("EntityCache key must be non-empty")
        parts = [part.strip() for part in text.split(":") if part.strip()]
        if not parts:
            raise ValueError("EntityCache key must be non-empty")
        # Support both "kind:id" and "domain:kind:id" string keys. Fail closed
        # only for forbidden kind positions so ordinary entity-context keys keep
        # working while counters/proof/DK/L5 state cannot enter the cache.
        candidate_kinds = {parts[0]}
        if len(parts) >= 2:
            candidate_kinds.add(parts[1])
        forbidden = candidate_kinds.intersection(_FORBIDDEN_KINDS)
        if forbidden:
            raise ValueError(
                f"{sorted(forbidden)[0]!r} keys are not valid for EntityCache"
            )
