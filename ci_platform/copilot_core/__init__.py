"""Shared copilot runtime infrastructure.

This package contains backend-neutral building blocks for the hot-path
architecture. Domain copilots should keep product-specific logic in their own
adapters and use this package only for shared runtime primitives.
"""

from .cache import (
    EntityCache,
    EntityCacheEntry,
    EntityCacheKey,
    EntityCacheStats,
    EntityCacheStatus,
)
from .background import (
    BackgroundTaskError,
    BackgroundTaskManager,
    BackgroundTaskStatus,
)
from .context_cache import EntityContextCacheAdapter, EntityContextCacheStatus
from .counters import (
    AGECounterStore,
    CounterDef,
    CounterKey,
    CounterRead,
    CounterReconciliation,
    CounterStatus,
    CounterStore,
    USE_MATERIALIZED_COUNTERS,
    soc_cross_category_counter_def,
    soc_cross_category_counter_key,
    soc_sequence_counter_def,
    soc_sequence_counter_key,
)
from .pipeline import (
    DecisionDraft,
    DecisionOutcome,
    DecisionPipeline,
    DomainProfile,
    PersistedDecision,
    Phase4TaskSpec,
    PhaseTimings,
    PipelineDiagnostics,
    PipelineInput,
    PipelineResult,
)

__all__ = [
    "AGECounterStore",
    "BackgroundTaskError",
    "BackgroundTaskManager",
    "BackgroundTaskStatus",
    "CounterDef",
    "CounterKey",
    "CounterRead",
    "CounterReconciliation",
    "CounterStatus",
    "CounterStore",
    "DecisionDraft",
    "DecisionOutcome",
    "DecisionPipeline",
    "DomainProfile",
    "EntityCache",
    "EntityCacheEntry",
    "EntityCacheKey",
    "EntityCacheStats",
    "EntityCacheStatus",
    "EntityContextCacheAdapter",
    "EntityContextCacheStatus",
    "PersistedDecision",
    "Phase4TaskSpec",
    "PhaseTimings",
    "PipelineDiagnostics",
    "PipelineInput",
    "PipelineResult",
    "USE_MATERIALIZED_COUNTERS",
    "soc_cross_category_counter_def",
    "soc_cross_category_counter_key",
    "soc_sequence_counter_def",
    "soc_sequence_counter_key",
]
