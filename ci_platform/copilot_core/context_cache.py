"""Route integration adapter for stable entity-context caching.

This module keeps EntityCache behind an explicit opt-in adapter. It is not a
route feature flag by itself; product routes must decide when to enable it and
must keep mutable counters, alert subjects, proof authority, decisions,
outcomes, and DK/L5/conservation state out of the cache.
"""

from __future__ import annotations

import inspect
from dataclasses import dataclass
from typing import Any, Mapping, Optional

from .cache import EntityCache, EntityCacheKey, EntityCacheStats, EntityCacheStatus, Loader


_ONE_SHOT_OR_NON_CONTEXT_KINDS = {
    "alert",
    "alerts",
    "subject",
    "subjects",
}


@dataclass(frozen=True)
class EntityContextCacheStatus:
    enabled: bool
    cache: EntityCacheStatus
    non_context_kinds: tuple[str, ...] = tuple(sorted(_ONE_SHOT_OR_NON_CONTEXT_KINDS))


class EntityContextCacheAdapter:
    """Disabled-by-default adapter for stable entity context.

    When disabled, get_context() calls the supplied graph/current loader every
    time and does not populate EntityCache. When enabled, it read-through caches
    only stable entity-context keys. This class deliberately does not inspect or
    mutate product routes.
    """

    def __init__(self, cache: EntityCache, *, enabled: bool = False) -> None:
        self.cache = cache
        self.enabled = bool(enabled)

    async def get_context(
        self,
        domain: str,
        kind: str,
        identifier: str,
        loader: Loader,
        *,
        metadata: Optional[Mapping[str, Any]] = None,
        source: Optional[str] = None,
    ) -> Any:
        key = self._make_key(domain, kind, identifier)
        if not self.enabled:
            return await self._call_loader(loader)
        return await self.cache.get_or_load(
            key,
            loader,
            metadata=metadata,
            source=source or "copilot_core.entity_context_cache",
        )

    def invalidate(self, domain: str, kind: str, identifier: str) -> bool:
        key = self._make_key(domain, kind, identifier)
        return self.cache.invalidate(key)

    def clear(self) -> None:
        self.cache.clear()

    def stats(self) -> EntityCacheStats:
        return self.cache.stats()

    def get_status(self) -> EntityContextCacheStatus:
        return EntityContextCacheStatus(enabled=self.enabled, cache=self.cache.get_status())

    def _make_key(self, domain: str, kind: str, identifier: str) -> EntityCacheKey:
        normalized_kind = str(kind).strip().lower()
        if normalized_kind in _ONE_SHOT_OR_NON_CONTEXT_KINDS:
            raise ValueError(f"{kind!r} is not stable entity context")
        return EntityCacheKey(domain=domain, kind=kind, identifier=identifier)

    async def _call_loader(self, loader: Loader) -> Any:
        result = loader()
        if inspect.isawaitable(result):
            return await result
        return result
