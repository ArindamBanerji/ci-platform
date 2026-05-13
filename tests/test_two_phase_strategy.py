from __future__ import annotations

from pathlib import Path

from ci_platform.strategy import TwoPhaseStrategy


class FakeGraphStore:
    def __init__(self, verified: int = 0, correct: int = 0):
        self.verified = verified
        self.correct = correct
        self.calls: list[str] = []

    def count_verified(self) -> int:
        self.calls.append("count_verified")
        return self.verified

    def count_correct(self) -> int:
        self.calls.append("count_correct")
        return self.correct


class FailingGraphStore:
    def count_verified(self) -> int:
        raise RuntimeError("graph unavailable")

    def count_correct(self) -> int:
        raise RuntimeError("graph unavailable")


def test_phase_a_when_no_verified():
    strategy = TwoPhaseStrategy(FakeGraphStore())

    assert strategy.get_phase() == "A"


def test_phase_a_when_low_q():
    strategy = TwoPhaseStrategy(FakeGraphStore(verified=20, correct=9))

    assert strategy.get_phase() == "A"


def test_phase_b_when_above_threshold():
    strategy = TwoPhaseStrategy(FakeGraphStore(verified=20, correct=10))

    assert strategy.get_phase() == "B"


def test_get_status_returns_all_fields():
    strategy = TwoPhaseStrategy(FakeGraphStore(verified=12, correct=9))

    assert strategy.get_status() == {
        "phase": "B",
        "verified": 12,
        "correct": 9,
        "q": 0.75,
        "min_verified": 10,
        "q_threshold": 0.5,
    }


def test_custom_threshold():
    strategy = TwoPhaseStrategy(FakeGraphStore(verified=10, correct=7), q_threshold=0.8)

    assert strategy.get_phase() == "A"
    assert strategy.get_status()["q_threshold"] == 0.8


def test_uses_graphstore_counts():
    store = FakeGraphStore(verified=11, correct=6)
    strategy = TwoPhaseStrategy(store)

    assert strategy.get_phase() == "B"
    assert store.calls == ["count_verified", "count_correct"]


def test_graphstore_failure_returns_phase_a():
    strategy = TwoPhaseStrategy(FailingGraphStore())

    assert strategy.get_phase() == "A"
    status = strategy.get_status()
    assert status["phase"] == "A"
    assert status["verified"] == 0
    assert status["correct"] == 0
    assert status["q"] == 0.0
    assert "graph unavailable" in status["error"]


def test_no_scorer_or_soc_imports():
    source = Path("ci_platform/strategy/two_phase_strategy.py").read_text(encoding="utf-8")

    assert "CompoundingScorer" not in source
    assert "copilot_sdk" not in source
    assert "domains.soc" not in source
    assert "gen-ai-roi-demo" not in source

