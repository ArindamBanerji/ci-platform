import asyncio
from pathlib import Path

import pytest

from ci_platform.copilot_core import (
    BackgroundTaskManager,
    DecisionDraft,
    DecisionOutcome,
    DecisionPipeline,
    PersistedDecision,
    Phase4TaskSpec,
    PipelineInput,
)


class FakeProfile:
    def __init__(self):
        self.events = []
        self.phase4_started = asyncio.Event()
        self.phase4_release = asyncio.Event()
        self.phase4_fail = False
        self.phase2_fail = False
        self.phase3_fail = False
        self.phase4_mutates_decision = False
        self.phase4_completed = False
        self.factor_vector = [0.7, 0.2]
        self.factor_details = {"thresholds": [0.3], "source": {"name": "unit"}}
        self.gate_metadata = {
            "gated": True,
            "notes": ["initial"],
            "nested": {"gate": ["sync"]},
        }
        self.persisted_metadata = {"proof": "written", "steps": ["decision"]}

    async def load_subject(self, pipeline_input):
        self.events.append("phase1:subject")
        return {"subject_id": pipeline_input.subject_id, "category": "soc"}

    async def load_context(self, pipeline_input, subject):
        self.events.append("phase1:context")
        return {"entity_id": "entity-1", "risk": 0.7}

    def compute_decision(self, pipeline_input, subject, context):
        self.events.append("phase2:compute")
        if self.phase2_fail:
            raise RuntimeError("phase2 failed")
        return DecisionDraft(
            action="investigate",
            confidence=0.81,
            factors={
                "risk": context["risk"],
                "vector": self.factor_vector,
                "details": self.factor_details,
                "tags": {"stable"},
            },
            metadata={"draft": True},
        )

    def apply_gates(self, pipeline_input, subject, context, decision):
        self.events.append("phase2:gates")
        return DecisionOutcome(
            action=decision.action,
            confidence=decision.confidence,
            factors=decision.factors,
            metadata=self.gate_metadata,
        )

    async def persist_decision(self, pipeline_input, subject, context, decision):
        self.events.append("phase3:persist")
        if self.phase3_fail:
            raise RuntimeError("phase3 failed")
        return PersistedDecision(
            decision_id=f"decision-{pipeline_input.subject_id}",
            metadata=self.persisted_metadata,
        )

    def phase4_tasks(self, pipeline_input, subject, context, decision, persisted):
        self.events.append("phase4:enumerate")

        async def telemetry():
            self.events.append("phase4:start")
            self.phase4_started.set()
            if self.phase4_mutates_decision:
                decision.factors["risk"] = 99
                decision.factors["vector"][0] = 99
                decision.factors["details"]["thresholds"].append(99)
                decision.factors["tags"].add("changed")
                decision.metadata["notes"].append("changed")
                decision.metadata["nested"]["gate"].append("changed")
                persisted.metadata["steps"].append("changed")
                context["risk"] = 99
            await self.phase4_release.wait()
            if self.phase4_fail:
                raise RuntimeError("phase4 failed")
            self.phase4_completed = True
            self.events.append("phase4:complete")

        return [Phase4TaskSpec(telemetry(), name="fake-telemetry")]


@pytest.mark.asyncio
async def test_pipeline_runs_phase_order_and_returns_result_before_phase4_completion():
    profile = FakeProfile()
    tasks = BackgroundTaskManager()
    pipeline = DecisionPipeline(profile, tasks=tasks)

    result = await pipeline.run(PipelineInput(subject_id="A1"))

    assert result.subject_id == "A1"
    assert result.decision_id == "decision-A1"
    assert result.action == "investigate"
    assert result.confidence == 0.81
    assert result.factors["risk"] == 0.7
    assert result.factors["vector"] == (0.7, 0.2)
    assert result.factors["details"]["thresholds"] == (0.3,)
    assert result.factors["tags"] == frozenset({"stable"})
    assert result.metadata["persisted"]["proof"] == "written"
    assert result.metadata["persisted"]["steps"] == ("decision",)
    assert result.diagnostics.phase_order == (
        "phase1",
        "phase2",
        "phase3",
        "phase4",
    )
    assert profile.events[:5] == [
        "phase1:subject",
        "phase1:context",
        "phase2:compute",
        "phase2:gates",
        "phase3:persist",
    ]
    assert profile.events[5] == "phase4:enumerate"
    assert tasks.get_status()["submitted"] == 1
    assert tasks.get_status()["in_flight"] == 1
    assert not profile.phase4_completed

    profile.phase4_release.set()
    await tasks.drain()
    assert profile.phase4_completed


@pytest.mark.asyncio
async def test_phase3_persistence_is_awaited_before_success_result():
    profile = FakeProfile()
    pipeline = DecisionPipeline(profile, tasks=BackgroundTaskManager())

    result = await pipeline.run(PipelineInput(subject_id="B2"))

    assert "phase3:persist" in profile.events
    assert result.decision_id == "decision-B2"
    assert profile.events.index("phase3:persist") < profile.events.index(
        "phase4:enumerate"
    )
    profile.phase4_release.set()
    await pipeline.tasks.drain()


@pytest.mark.asyncio
async def test_phase4_failure_is_captured_without_changing_result():
    profile = FakeProfile()
    profile.phase4_fail = True
    pipeline = DecisionPipeline(profile, tasks=BackgroundTaskManager())

    result = await pipeline.run(PipelineInput(subject_id="C3"))
    profile.phase4_release.set()
    await pipeline.tasks.drain()

    assert result.action == "investigate"
    assert result.confidence == 0.81
    assert result.factors["risk"] == 0.7
    assert result.factors["vector"] == (0.7, 0.2)
    status = pipeline.tasks.get_status()
    assert status["failed"] == 1
    assert status["last_errors"][0]["exception_type"] == "RuntimeError"


@pytest.mark.asyncio
async def test_phase4_cannot_mutate_returned_decision_fields():
    profile = FakeProfile()
    profile.phase4_mutates_decision = True
    pipeline = DecisionPipeline(profile, tasks=BackgroundTaskManager())

    result = await pipeline.run(PipelineInput(subject_id="D4"))
    profile.phase4_release.set()
    await pipeline.tasks.drain()

    assert result.action == "investigate"
    assert result.confidence == 0.81
    assert result.factors["risk"] == 0.7
    assert result.factors["vector"] == (0.7, 0.2)
    assert result.factors["details"]["thresholds"] == (0.3,)
    assert result.factors["details"]["source"]["name"] == "unit"
    assert result.factors["tags"] == frozenset({"stable"})
    assert result.metadata["notes"] == ("initial",)
    assert result.metadata["nested"]["gate"] == ("sync",)
    assert result.metadata["persisted"]["steps"] == ("decision",)
    with pytest.raises(TypeError):
        result.factors["risk"] = 1.0
    with pytest.raises(TypeError):
        result.factors["details"]["source"]["name"] = "changed"
    with pytest.raises(AttributeError):
        result.factors["vector"].append(1.0)
    with pytest.raises(AttributeError):
        result.metadata["notes"].append("changed")


@pytest.mark.asyncio
async def test_no_background_tasks_are_scheduled_when_phase2_fails():
    profile = FakeProfile()
    profile.phase2_fail = True
    pipeline = DecisionPipeline(profile, tasks=BackgroundTaskManager())

    with pytest.raises(RuntimeError, match="phase2 failed"):
        await pipeline.run(PipelineInput(subject_id="E5"))

    assert "phase4:enumerate" not in profile.events
    assert pipeline.tasks.get_status()["submitted"] == 0


@pytest.mark.asyncio
async def test_no_background_tasks_are_scheduled_when_phase3_fails():
    profile = FakeProfile()
    profile.phase3_fail = True
    pipeline = DecisionPipeline(profile, tasks=BackgroundTaskManager())

    with pytest.raises(RuntimeError, match="phase3 failed"):
        await pipeline.run(PipelineInput(subject_id="F6"))

    assert "phase4:enumerate" not in profile.events
    assert pipeline.tasks.get_status()["submitted"] == 0


@pytest.mark.asyncio
async def test_cross_domain_fake_profiles_can_use_pipeline():
    class DomainProfile(FakeProfile):
        def __init__(self, domain):
            super().__init__()
            self.domain = domain

        async def load_subject(self, pipeline_input):
            self.events.append(f"{self.domain}:subject")
            return {"subject_id": pipeline_input.subject_id, "domain": self.domain}

    for domain in ("soc", "trading", "purchasing", "dataops", "s2p"):
        profile = DomainProfile(domain)
        pipeline = DecisionPipeline(profile, tasks=BackgroundTaskManager())
        result = await pipeline.run(PipelineInput(subject_id=f"{domain}-1"))
        assert result.action == "investigate"
        assert profile.events[0] == f"{domain}:subject"
        profile.phase4_release.set()
        await pipeline.tasks.drain()


@pytest.mark.asyncio
async def test_phase4_tasks_must_be_awaitables():
    class BadProfile(FakeProfile):
        def phase4_tasks(self, pipeline_input, subject, context, decision, persisted):
            return [object()]

    pipeline = DecisionPipeline(BadProfile(), tasks=BackgroundTaskManager())

    with pytest.raises(TypeError, match="phase4_tasks"):
        await pipeline.run(PipelineInput(subject_id="bad"))


def test_pipeline_diagnostics_are_safe_shape():
    profile = FakeProfile()
    pipeline = DecisionPipeline(profile, tasks=BackgroundTaskManager())

    status = pipeline.tasks.get_status()

    assert set(status) == {
        "submitted",
        "completed",
        "failed",
        "cancelled",
        "in_flight",
        "last_errors",
    }


def test_package_5a_does_not_wire_soc_route():
    repo_root = Path(__file__).resolve().parents[2]
    triage_path = (
        repo_root
        / "gen-ai-roi-demo-v4-v50"
        / "backend"
        / "app"
        / "routers"
        / "triage.py"
    )
    triage_source = triage_path.read_text(encoding="utf-8")

    assert "DecisionPipeline" not in triage_source
    assert "ci_platform.copilot_core.pipeline" not in triage_source
