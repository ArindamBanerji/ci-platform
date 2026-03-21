import numpy as np
import pytest

from ci_platform.onboarding.deployment_qualification import (
    FACTOR_NAMES, SIGMA_GREEN, SIGMA_AMBER, DeploymentQualifier,
)


def _make_alerts(n: int, noise_level: float):
    rng = np.random.default_rng(42)
    alerts = []
    for _ in range(n):
        fv = np.clip(rng.normal(0.5, noise_level, 6), 0, 1).tolist()
        alerts.append({"factor_vector": fv, "category": "test"})
    return alerts


def test_green_classification():
    qualifier = DeploymentQualifier()
    alerts = _make_alerts(200, 0.08)
    result = qualifier.qualify(alerts)
    assert result.noise.classification == "GREEN"
    assert result.noise.learning_recommended is True


def test_amber_classification():
    qualifier = DeploymentQualifier()
    alerts = _make_alerts(200, 0.13)
    result = qualifier.qualify(alerts)
    assert result.noise.classification == "AMBER"
    assert result.noise.learning_recommended is True


def test_red_classification():
    qualifier = DeploymentQualifier()
    alerts = _make_alerts(200, 0.22)
    result = qualifier.qualify(alerts)
    assert result.noise.classification == "RED"
    assert result.noise.learning_recommended is False


def test_tau_sweep_returns_optimal():
    qualifier = DeploymentQualifier()
    alerts = _make_alerts(200, 0.10)
    result = qualifier.qualify(alerts)
    assert result.tau.tau_optimal in [0.05, 0.08, 0.10, 0.12, 0.15]
    assert result.tau.ece_at_optimal <= result.tau.ece_at_default


def test_remediation_sorted_by_priority():
    qualifier = DeploymentQualifier()
    alerts = _make_alerts(200, 0.20)
    result = qualifier.qualify(alerts)
    if len(result.remediations) >= 2:
        assert result.remediations[0].priority == 1
        assert result.remediations[0].current_noise >= result.remediations[1].current_noise


def test_remediation_only_noisy_factors():
    qualifier = DeploymentQualifier()
    alerts = _make_alerts(200, 0.08)
    result = qualifier.qualify(alerts)
    for r in result.remediations:
        assert r.current_noise > SIGMA_GREEN


def test_post_remediation_estimate():
    qualifier = DeploymentQualifier()
    alerts = _make_alerts(200, 0.18)
    result = qualifier.qualify(alerts)
    assert result.estimated_sigma_after_remediation < result.noise.sigma_mean


def test_would_reclassify_red_to_green():
    qualifier = DeploymentQualifier()
    alerts = _make_alerts(200, 0.16)
    result = qualifier.qualify(alerts)
    # AMBER with remediations should potentially reclassify to GREEN
    if (
        result.noise.classification == "AMBER"
        and result.estimated_sigma_after_remediation <= SIGMA_GREEN
    ):
        assert result.would_reclassify is True


def test_summary_contains_classification():
    qualifier = DeploymentQualifier()
    alerts = _make_alerts(200, 0.20)
    result = qualifier.qualify(alerts)
    assert "RED" in result.summary or "NOT recommended" in result.summary


def test_empty_alerts():
    qualifier = DeploymentQualifier()
    result = qualifier.qualify([])
    assert result.noise.classification == "RED"
    assert result.noise.learning_recommended is False


def test_category_distribution():
    alerts = [
        {"factor_vector": [0.5] * 6, "category": "credential_access"},
        {"factor_vector": [0.5] * 6, "category": "credential_access"},
        {"factor_vector": [0.5] * 6, "category": "insider_threat"},
    ]
    qualifier = DeploymentQualifier()
    result = qualifier.qualify(alerts, days_in_sample=1)
    assert result.category_distribution["credential_access"] > 0.5
    assert result.estimated_daily_volume == 3.0


def test_volume_estimation():
    qualifier = DeploymentQualifier()
    alerts = _make_alerts(300, 0.10)
    result = qualifier.qualify(alerts, days_in_sample=30)
    assert abs(result.estimated_daily_volume - 10.0) < 0.1
