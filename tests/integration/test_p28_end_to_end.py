"""
Integration Test 1 — P28 pipeline end-to-end.

Tests DeploymentQualifier.qualify() directly with synthetic alert data for
three discriminating conditions from MAP v4.2 Phase 2 checklist.

Each case generates N=50 alerts whose factor_vector columns have the target
per-factor standard deviations.  qualify() measures sigma from the data, so
the generated vectors must reproduce the target profile when measured.
"""
import numpy as np
import pytest

from ci_platform.onboarding.deployment_qualification import (
    DeploymentQualifier,
    SIGMA_GREEN, SIGMA_AMBER,
    SIGMA_GREEN_DIAGONAL, SIGMA_AMBER_DIAGONAL,
)

N = 50


def _make_alerts(sigma_profile, n=N, seed=42):
    """
    Synthetic alerts with per-factor standard deviations matching sigma_profile.
    Uses default_rng for reproducibility; factor values clipped to [0, 1].
    """
    rng = np.random.default_rng(seed)
    factor_matrix = rng.normal(0.5, np.array(sigma_profile), (n, len(sigma_profile)))
    factor_matrix = np.clip(factor_matrix, 0.0, 1.0)
    return [
        {"factor_vector": row.tolist(), "category": "test"}
        for row in factor_matrix
    ]


# ── Case 1 ─────────────────────────────────────────────────────────────────────

def test_case1_high_noise_diagonal_amber():
    """
    Case 1 — High-noise deployment: DiagonalKernel, AMBER, τ sweep triggered.

    sigma profile : [0.22, 0.10, 0.12, 0.18, 0.20, 0.25]
    sigma_mean    : ~0.178  → AMBER under Diagonal (0.157 < σ ≤ 0.25)
    noise_ratio   : ~2.5    → DiagonalKernel (> 1.5)
    """
    sigma_profile = [0.22, 0.10, 0.12, 0.18, 0.20, 0.25]
    alerts = _make_alerts(sigma_profile)

    qualifier = DeploymentQualifier()
    result = qualifier.qualify(alerts, kernel_recommendation="diagonal")

    # Kernel passed through unchanged
    assert result.kernel_recommendation == "diagonal", (
        f"Expected kernel_recommendation='diagonal', got '{result.kernel_recommendation}'"
    )

    # sigma_mean ~0.178 is AMBER under diagonal (0.157 < σ ≤ 0.25)
    assert result.noise.classification == "AMBER", (
        f"Expected AMBER under diagonal (SIGMA_AMBER_DIAGONAL={SIGMA_AMBER_DIAGONAL}), "
        f"got {result.noise.classification} at sigma_mean={result.noise.sigma_mean:.4f}"
    )

    # tau_sweep always populated by qualify(); must be triggered for sigma_mean > 0.12
    assert result.tau_sweep is not None, "tau_sweep must not be None after qualify()"
    assert result.tau_sweep["tau_sweep_triggered"] is True, (
        f"tau_sweep_triggered should be True: "
        f"sigma_mean={result.noise.sigma_mean:.4f} > 0.12"
    )

    # noise_ratio computed and stored
    assert result.noise_ratio is not None
    assert result.noise_ratio > 1.5, (
        f"noise_ratio={result.noise_ratio:.3f} must be > 1.5 for diagonal recommendation"
    )


# ── Case 2 ─────────────────────────────────────────────────────────────────────

def test_case2_low_noise_l2_green():
    """
    Case 2 — Low-noise centroidal deployment: L2 kernel, GREEN, τ sweep not triggered.

    sigma profile : [0.09, 0.085, 0.08, 0.095, 0.09, 0.10]
    sigma_mean    : ~0.090  → GREEN under L2 (σ ≤ 0.105)
    noise_ratio   : ~1.25   → L2 (< 1.5)
    """
    sigma_profile = [0.09, 0.085, 0.08, 0.095, 0.09, 0.10]
    alerts = _make_alerts(sigma_profile)

    qualifier = DeploymentQualifier()
    result = qualifier.qualify(alerts, kernel_recommendation="l2")

    # Kernel
    assert result.kernel_recommendation == "l2", (
        f"Expected kernel_recommendation='l2', got '{result.kernel_recommendation}'"
    )

    # sigma_mean ~0.090 is GREEN under L2 (σ ≤ SIGMA_GREEN=0.105)
    assert result.noise.classification == "GREEN", (
        f"Expected GREEN under l2 (SIGMA_GREEN={SIGMA_GREEN}), "
        f"got {result.noise.classification} at sigma_mean={result.noise.sigma_mean:.4f}"
    )

    # τ sweep must not be triggered for centroidal (sigma_mean ≤ 0.12, ratio ≤ 2.0)
    assert (
        result.tau_sweep is None
        or result.tau_sweep["recommendation"] == "use_default_010"
    ), (
        f"τ sweep must not activate for centroidal profile, "
        f"got: {result.tau_sweep}"
    )
    if result.tau_sweep is not None:
        assert result.tau_sweep["tau_sweep_triggered"] is False, (
            f"tau_sweep_triggered must be False for sigma_mean={result.noise.sigma_mean:.4f}"
        )


# ── Case 3 ─────────────────────────────────────────────────────────────────────

def test_case3_l2_amber_cross_contamination_guard():
    """
    Case 3 — Threshold isolation: L2 AMBER must not be classified as GREEN.

    sigma profile : [0.14, 0.14, 0.14, 0.14, 0.14, 0.14]
    sigma_mean    : ~0.14   → AMBER under L2 (0.105 < 0.14 ≤ 0.157)
    noise_ratio   : ~1.0    → L2 (< 1.5)

    Under DiagonalKernel this same sigma_mean (0.14 ≤ 0.157) would be GREEN.
    This test confirms the Diagonal GREEN threshold (0.157) does NOT contaminate
    L2 classification — a regression guard for CI-1 / kernel threshold isolation.
    """
    sigma_profile = [0.14, 0.14, 0.14, 0.14, 0.14, 0.14]
    alerts = _make_alerts(sigma_profile)

    qualifier = DeploymentQualifier()
    result = qualifier.qualify(alerts, kernel_recommendation="l2")

    # Kernel
    assert result.kernel_recommendation == "l2", (
        f"Expected kernel_recommendation='l2', got '{result.kernel_recommendation}'"
    )

    # sigma_mean ~0.14 must be AMBER under L2 (0.105 < σ ≤ 0.157)
    assert result.noise.classification == "AMBER", (
        f"sigma_mean={result.noise.sigma_mean:.4f} must be AMBER under L2 "
        f"(SIGMA_GREEN={SIGMA_GREEN}, SIGMA_AMBER={SIGMA_AMBER}), "
        f"got {result.noise.classification}"
    )

    # Explicit cross-contamination guard: must NOT be GREEN
    assert result.noise.classification != "GREEN", (
        f"Cross-contamination detected: sigma_mean={result.noise.sigma_mean:.4f} "
        f"classified as GREEN using Diagonal threshold (0.157) instead of L2 "
        f"GREEN threshold ({SIGMA_GREEN})"
    )

    # Sanity-check the raw sigma_mean is in the L2 AMBER band
    assert SIGMA_GREEN < result.noise.sigma_mean <= SIGMA_AMBER, (
        f"sigma_mean={result.noise.sigma_mean:.4f} not in L2 AMBER band "
        f"({SIGMA_GREEN}, {SIGMA_AMBER}]"
    )
