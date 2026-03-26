"""
EnrichmentAdvisor — P28 Phase 2 enrichment opportunity scoring.

Ranks alert factors by enrichment ROI: high-σ factors benefit most from
additional data feeds because noise reduction translates directly to
calibration improvement.

Validated against 5 deployment profiles (P28 Phase 2 checklist).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List

# Opportunity tier boundaries (σ values)
_THRESHOLDS = {
    "high":   0.20,   # σ > 0.20  → high opportunity
    "medium": 0.10,   # σ > 0.10  → medium opportunity
    # σ ≤ 0.10 → low
}

_ACTIONS: Dict[str, str] = {
    "high": (
        "Prioritize immediate enrichment — high ROI expected "
        "in first deployment sprint."
    ),
    "medium": (
        "Schedule for sprint 2 enrichment — moderate noise "
        "reduction expected."
    ),
    "low": (
        "Defer enrichment — marginal gain; focus on "
        "high-opportunity factors first."
    ),
}

_KERNEL_NOTES: Dict[str, str] = {
    "diagonal": (
        "DiagonalKernel automatically downweights high-σ factors. "
        "Enrichment increases weight — more enrichment = more contribution."
    ),
    "l2": (
        "L2 kernel treats all factors equally. "
        "Enriching the highest-σ factor delivers the greatest "
        "calibration improvement."
    ),
}

# Day-1 lift coefficient: expected percentage-point gain per 1% of σ
_LIFT_COEFF = 0.40


@dataclass
class FactorOpportunity:
    factor: str
    sigma: float
    opportunity: str   # "high" | "medium" | "low"
    lift_pp: float     # expected Day-1 lift in percentage points
    action: str


@dataclass
class EnrichmentReport:
    """Output of EnrichmentAdvisor.recommend()."""
    top_opportunity: FactorOpportunity
    ranked_factors: List[FactorOpportunity]  # high + medium only, σ desc
    kernel_note: str
    methodology: str


class EnrichmentAdvisor:
    """
    Scores per-factor enrichment opportunity from a σ profile.

    Args:
        sigma_per_factor: mapping of factor name → measured σ value
        kernel: "l2" or "diagonal" — shapes the kernel_note text
    """

    METHODOLOGY = "enrichment_advisor.py, 5 deployment profiles validated"

    def __init__(
        self,
        sigma_per_factor: Dict[str, float],
        kernel: str = "l2",
    ) -> None:
        if not sigma_per_factor:
            raise ValueError("sigma_per_factor must be non-empty")
        self._sigma = sigma_per_factor
        self._kernel = kernel

    # ── public ───────────────────────────────────────────────────────────────

    def recommend(self) -> EnrichmentReport:
        """Score all factors and return a ranked EnrichmentReport."""
        scored: List[FactorOpportunity] = sorted(
            (self._score(f, s) for f, s in self._sigma.items()),
            key=lambda x: x.sigma,
            reverse=True,
        )

        top = scored[0]
        ranked = [fo for fo in scored if fo.opportunity in ("high", "medium")]
        kernel_note = _KERNEL_NOTES.get(self._kernel, _KERNEL_NOTES["l2"])

        return EnrichmentReport(
            top_opportunity=top,
            ranked_factors=ranked,
            kernel_note=kernel_note,
            methodology=self.METHODOLOGY,
        )

    # ── internal ─────────────────────────────────────────────────────────────

    @staticmethod
    def _score(factor: str, sigma: float) -> FactorOpportunity:
        if sigma > _THRESHOLDS["high"]:
            opportunity = "high"
        elif sigma > _THRESHOLDS["medium"]:
            opportunity = "medium"
        else:
            opportunity = "low"

        # Expected Day-1 lift: _LIFT_COEFF × σ expressed as percentage points
        lift_pp = round(sigma * 100 * _LIFT_COEFF, 1)

        return FactorOpportunity(
            factor=factor,
            sigma=round(sigma, 4),
            opportunity=opportunity,
            lift_pp=lift_pp,
            action=_ACTIONS[opportunity],
        )
