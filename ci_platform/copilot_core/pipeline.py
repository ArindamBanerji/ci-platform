"""Shared four-phase decision pipeline skeleton.

DecisionPipeline owns the domain-neutral execution order. DomainProfile owns
domain-specific subject reads, factor computation, gates, persistence, and
optional Phase-4 background work.
"""

from __future__ import annotations

import inspect
from dataclasses import dataclass, field
from time import perf_counter
from types import MappingProxyType
from typing import Any, Awaitable, Iterable, Mapping, Protocol, runtime_checkable

from .background import BackgroundTaskManager


@dataclass(frozen=True)
class PipelineInput:
    """Pipeline request input shared across copilots."""

    subject_id: str
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class DecisionDraft:
    """Decision candidate before synchronous gates and persistence."""

    action: str
    confidence: float
    factors: Mapping[str, Any]
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class DecisionOutcome:
    """Decision after synchronous gates have run."""

    action: str
    confidence: float
    factors: Mapping[str, Any]
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class PersistedDecision:
    """Synchronous persistence/proof result."""

    decision_id: str
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Phase4TaskSpec:
    """Non-decision-critical background task to submit after Phase 3."""

    awaitable: Awaitable[Any]
    name: str | None = None


@dataclass(frozen=True)
class PhaseTimings:
    """Elapsed seconds for each pipeline phase."""

    phase1_seconds: float
    phase2_seconds: float
    phase3_seconds: float
    phase4_submit_seconds: float


@dataclass(frozen=True)
class PipelineDiagnostics:
    """Safe pipeline diagnostics for tests/internal callers."""

    phase_order: tuple[str, ...]
    timings: PhaseTimings
    background_status: Mapping[str, Any]


@dataclass(frozen=True)
class PipelineResult:
    """Response-critical decision result returned by the pipeline."""

    subject_id: str
    decision_id: str
    action: str
    confidence: float
    factors: Mapping[str, Any]
    metadata: Mapping[str, Any]
    diagnostics: PipelineDiagnostics


@runtime_checkable
class DomainProfile(Protocol):
    """Domain hook protocol for the shared decision pipeline."""

    async def load_subject(self, pipeline_input: PipelineInput) -> Any:
        """Load the one-shot subject for this decision."""

    async def load_context(
        self,
        pipeline_input: PipelineInput,
        subject: Any,
    ) -> Any:
        """Load cacheable or graph-backed context needed for factors."""

    def compute_decision(
        self,
        pipeline_input: PipelineInput,
        subject: Any,
        context: Any,
    ) -> DecisionDraft:
        """Build factors and the initial action/confidence."""

    def apply_gates(
        self,
        pipeline_input: PipelineInput,
        subject: Any,
        context: Any,
        decision: DecisionDraft,
    ) -> DecisionOutcome:
        """Apply synchronous decision-critical gates."""

    async def persist_decision(
        self,
        pipeline_input: PipelineInput,
        subject: Any,
        context: Any,
        decision: DecisionOutcome,
    ) -> PersistedDecision:
        """Synchronously persist proof-authoritative decision state."""

    def phase4_tasks(
        self,
        pipeline_input: PipelineInput,
        subject: Any,
        context: Any,
        decision: DecisionOutcome,
        persisted: PersistedDecision,
    ) -> Iterable[Phase4TaskSpec | Awaitable[Any]]:
        """Return non-decision-critical background work."""


class DecisionPipeline:
    """Run the shared four-phase hot-path skeleton."""

    def __init__(
        self,
        profile: DomainProfile,
        *,
        tasks: BackgroundTaskManager | None = None,
    ) -> None:
        self.profile = profile
        self.tasks = tasks or BackgroundTaskManager()

    async def run(self, pipeline_input: PipelineInput) -> PipelineResult:
        phase_order: list[str] = []

        phase_start = perf_counter()
        phase_order.append("phase1")
        subject = await self.profile.load_subject(pipeline_input)
        context = await self.profile.load_context(pipeline_input, subject)
        phase1_seconds = perf_counter() - phase_start

        phase_start = perf_counter()
        phase_order.append("phase2")
        draft = self.profile.compute_decision(pipeline_input, subject, context)
        gated = self.profile.apply_gates(pipeline_input, subject, context, draft)
        phase2_seconds = perf_counter() - phase_start

        phase_start = perf_counter()
        phase_order.append("phase3")
        persisted = await self.profile.persist_decision(
            pipeline_input,
            subject,
            context,
            gated,
        )
        phase3_seconds = perf_counter() - phase_start

        result_factors = _freeze(gated.factors)
        result_metadata = _freeze(
            {
                **dict(gated.metadata),
                "persisted": dict(persisted.metadata),
            }
        )
        result_decision_id = persisted.decision_id
        result_action = gated.action
        result_confidence = gated.confidence

        phase_start = perf_counter()
        phase_order.append("phase4")
        for task_spec in self.profile.phase4_tasks(
            pipeline_input,
            subject,
            context,
            gated,
            persisted,
        ):
            spec = self._coerce_phase4_task(task_spec)
            self.tasks.submit(spec.awaitable, name=spec.name)
        phase4_submit_seconds = perf_counter() - phase_start

        diagnostics = PipelineDiagnostics(
            phase_order=tuple(phase_order),
            timings=PhaseTimings(
                phase1_seconds=phase1_seconds,
                phase2_seconds=phase2_seconds,
                phase3_seconds=phase3_seconds,
                phase4_submit_seconds=phase4_submit_seconds,
            ),
            background_status=_freeze(self.tasks.get_status()),
        )

        return PipelineResult(
            subject_id=pipeline_input.subject_id,
            decision_id=result_decision_id,
            action=result_action,
            confidence=result_confidence,
            factors=result_factors,
            metadata=result_metadata,
            diagnostics=diagnostics,
        )

    @staticmethod
    def _coerce_phase4_task(
        task_spec: Phase4TaskSpec | Awaitable[Any],
    ) -> Phase4TaskSpec:
        if isinstance(task_spec, Phase4TaskSpec):
            if not inspect.isawaitable(task_spec.awaitable):
                raise TypeError("Phase4TaskSpec.awaitable must be awaitable")
            return task_spec
        if not inspect.isawaitable(task_spec):
            raise TypeError("phase4_tasks() must yield awaitables or Phase4TaskSpec")
        return Phase4TaskSpec(awaitable=task_spec)


def _freeze(value: Any) -> Any:
    """Return an immutable snapshot for response-critical result fields."""

    if isinstance(value, Mapping):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(item) for item in value)
    if isinstance(value, (set, frozenset)):
        return frozenset(_freeze(item) for item in value)
    return value
