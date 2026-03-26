"""
Tests for EnrichmentAdvisor — P28 Phase 2 enrichment opportunity scoring.
"""
import pytest
from ci_platform.enrichment.enrichment_advisor import EnrichmentAdvisor

_SIGMA = {
    "device_trust":             0.28,
    "asset_criticality":        0.18,
    "threat_intel_enrichment":  0.07,
    "time_anomaly":             0.14,
    "pattern_history":          0.11,
    "travel_match":             0.09,
}


def test_top_opportunity_is_highest_sigma_factor():
    """Top opportunity must be the factor with the highest σ."""
    advisor = EnrichmentAdvisor(sigma_per_factor=_SIGMA, kernel="l2")
    report = advisor.recommend()
    assert report.top_opportunity.factor == "device_trust", (
        f"Expected 'device_trust' (σ=0.28), "
        f"got '{report.top_opportunity.factor}' (σ={report.top_opportunity.sigma})"
    )


def test_expected_lift_positive():
    """expected_day1_lift_pp must be > 0 for any valid sigma profile."""
    advisor = EnrichmentAdvisor(sigma_per_factor=_SIGMA, kernel="l2")
    report = advisor.recommend()
    assert report.top_opportunity.lift_pp > 0, (
        f"lift_pp must be positive, got {report.top_opportunity.lift_pp}"
    )


def test_ranked_factors_sorted_descending_by_sigma():
    """ranked_factors must be ordered σ high → low (suppressing 'low' tier)."""
    advisor = EnrichmentAdvisor(sigma_per_factor=_SIGMA, kernel="l2")
    report = advisor.recommend()
    sigmas = [fo.sigma for fo in report.ranked_factors]
    # All entries must be high or medium (low suppressed)
    for fo in report.ranked_factors:
        assert fo.opportunity in ("high", "medium"), (
            f"Factor '{fo.factor}' with opportunity='{fo.opportunity}' "
            "must not appear in ranked_factors (low suppressed)"
        )
    # Strictly non-increasing order
    for i in range(len(sigmas) - 1):
        assert sigmas[i] >= sigmas[i + 1], (
            f"ranked_factors not sorted descending: "
            f"sigmas[{i}]={sigmas[i]} < sigmas[{i+1}]={sigmas[i+1]}"
        )


def test_kernel_note_present_and_nonempty():
    """kernel_note must be a non-empty string for any kernel type."""
    for kernel in ("l2", "diagonal", "unknown_kernel"):
        advisor = EnrichmentAdvisor(sigma_per_factor=_SIGMA, kernel=kernel)
        report = advisor.recommend()
        assert isinstance(report.kernel_note, str), (
            f"kernel_note must be str for kernel='{kernel}'"
        )
        assert len(report.kernel_note) > 0, (
            f"kernel_note must be non-empty for kernel='{kernel}'"
        )
