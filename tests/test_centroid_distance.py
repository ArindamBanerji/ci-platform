"""
Tests for centroid_convergence.py and DeploymentQualifier.qualify_with_distance().
EXP-G1 primary γ metric — centroid_distance_to_canonical.
"""
import numpy as np
import pytest

from ci_platform.onboarding.centroid_convergence import (
    compute_centroid_distance,
    interpret_distance_trend,
)
from ci_platform.onboarding.deployment_qualification import DeploymentQualifier


def test_compute_centroid_distance_zero_for_identical():
    """Distance from a tensor to itself is exactly 0."""
    mu = np.full((6, 4, 6), 0.5)
    assert compute_centroid_distance(mu, mu) == 0.0


def test_compute_centroid_distance_correct_formula():
    """L2 norm computed correctly against known analytic value."""
    mu = np.full((6, 4, 6), 0.7)
    canonical = np.full((6, 4, 6), 0.5)
    # Each of the 144 elements differs by 0.2
    expected = float(np.linalg.norm(np.full(144, 0.2)))
    result = compute_centroid_distance(mu, canonical)
    assert abs(result - expected) < 0.001


def test_interpret_distance_trend_insufficient_data():
    """Fewer than 10 entries returns INSUFFICIENT_DATA status."""
    result = interpret_distance_trend([1.0, 0.9, 0.8])
    assert result["status"] == "INSUFFICIENT_DATA"
    assert result["alert"] is False
    assert result["consecutive_increases"] == 0


def test_interpret_distance_trend_green_decreasing():
    """Monotone decreasing sequence → GREEN with trend='decreasing'."""
    distances = [3.0 - i * 0.05 for i in range(20)]
    result = interpret_distance_trend(distances)
    assert result["status"] == "GREEN"
    assert result["trend"] == "decreasing"
    assert result["alert"] is False


def test_interpret_distance_trend_red_alert():
    """50 consecutive increases → RED with alert=True."""
    distances = [1.0 + i * 0.01 for i in range(60)]
    result = interpret_distance_trend(distances, alert_threshold=50)
    assert result["status"] == "RED"
    assert result["alert"] is True
    assert result["consecutive_increases"] >= 50
