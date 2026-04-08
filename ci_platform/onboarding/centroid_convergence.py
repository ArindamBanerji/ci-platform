"""
Centroid convergence health — EXP-G1 primary γ metric.

compute_centroid_distance(): L2 distance between current centroid tensor
and canonical (bootstrap) baseline.  Formula matches SOC backend
reconvergence_logger.py exactly:
    np.linalg.norm(mu.flatten() - canonical.flatten())

interpret_distance_trend(): classifies a chronological distance history
as GREEN / AMBER / RED and raises alert flag after `alert_threshold`
consecutive increases.

Expected behaviour during healthy convergence (from simulation):
  - Starts ~3.0 at bootstrap
  - Decreases monotonically → stabilises ~2.4 after ~600 decisions
  - ALERT if increases for 50+ consecutive decisions
"""

from __future__ import annotations

from typing import List, Optional

import numpy as np


def compute_centroid_distance(
    mu: np.ndarray,
    canonical: np.ndarray,
) -> float:
    """
    L2 distance between current centroid tensor and canonical baseline.

    Formula: ||mu - canonical||_2  (Frobenius norm over full tensor)
    Matches SOC backend reconvergence_logger.py exactly.
    """
    return float(np.linalg.norm(mu.flatten() - canonical.flatten()))


def interpret_distance_trend(
    distances: List[float],
    alert_threshold: int = 50,
) -> dict:
    """
    Interpret a chronological sequence of centroid distances.

    Args:
        distances:        list of float, chronological order (oldest first)
        alert_threshold:  consecutive increases before status → RED

    Returns dict with keys:
        status, trend, consecutive_increases, alert,
        current_distance (if ≥1 entry), distance_change_last_10, message
    """
    if len(distances) < 10:
        return {
            "status": "INSUFFICIENT_DATA",
            "trend": "unknown",
            "consecutive_increases": 0,
            "alert": False,
            "message": f"Need ≥10 decisions, have {len(distances)}",
        }

    # Count consecutive increases from the tail.
    # Need alert_threshold+1 points to observe alert_threshold consecutive pairs.
    window = (
        distances[-(alert_threshold + 1):]
        if len(distances) > alert_threshold
        else distances
    )
    consecutive = 0
    for i in range(len(window) - 1, 0, -1):
        if window[i] > window[i - 1]:
            consecutive += 1
        else:
            break

    # Overall slope over last 10
    last_10 = distances[-10:]
    trend_slope = last_10[-1] - last_10[0]

    if consecutive >= alert_threshold:
        status = "RED"
        trend = "increasing"
        alert = True
        message = (
            f"Centroid drift: distance increased {consecutive} "
            "consecutive decisions"
        )
    elif trend_slope < -0.01:
        status = "GREEN"
        trend = "decreasing"
        alert = False
        message = "Convergence healthy — centroid distance decreasing"
    elif trend_slope > 0.01:
        status = "AMBER"
        trend = "increasing"
        alert = False
        message = (
            f"Watch: centroid distance trending up "
            f"({trend_slope:+.3f} over last 10)"
        )
    else:
        status = "GREEN"
        trend = "stable"
        alert = False
        message = "Centroid distance stable — converged"

    return {
        "status": status,
        "trend": trend,
        "consecutive_increases": consecutive,
        "alert": alert,
        "current_distance": distances[-1],
        "distance_change_last_10": round(trend_slope, 4),
        "message": message,
    }
