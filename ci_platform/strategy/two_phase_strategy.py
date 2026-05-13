"""Two-phase rollout strategy backed by GraphStore counts."""

from __future__ import annotations

from typing import Any, Protocol


class GraphStoreCounts(Protocol):
    def count_verified(self) -> int:
        ...

    def count_correct(self) -> int:
        ...


class TwoPhaseStrategy:
    """Derive phase A/B status from verified GraphStore decisions."""

    def __init__(self, graph_store: GraphStoreCounts, min_verified: int = 10, q_threshold: float = 0.5):
        self.graph_store = graph_store
        self.min_verified = max(0, int(min_verified))
        self.q_threshold = float(q_threshold)

    def get_phase(self) -> str:
        try:
            verified, correct = self._counts()
            if verified < self.min_verified:
                return "A"
            q = correct / verified if verified else 0.0
            return "B" if q >= self.q_threshold else "A"
        except Exception:
            return "A"

    def get_status(self) -> dict[str, Any]:
        try:
            verified, correct = self._counts()
            q = correct / verified if verified else 0.0
            phase = "B" if verified >= self.min_verified and q >= self.q_threshold else "A"
            return {
                "phase": phase,
                "verified": verified,
                "correct": correct,
                "q": round(q, 4),
                "min_verified": self.min_verified,
                "q_threshold": self.q_threshold,
            }
        except Exception as exc:
            return {
                "phase": "A",
                "verified": 0,
                "correct": 0,
                "q": 0.0,
                "min_verified": self.min_verified,
                "q_threshold": self.q_threshold,
                "error": str(exc),
            }

    def _counts(self) -> tuple[int, int]:
        verified = max(int(self.graph_store.count_verified()), 0)
        correct = max(int(self.graph_store.count_correct()), 0)
        return verified, min(correct, verified)

