"""
Deployment Qualification — decides whether learning is safe to enable.

Three measurements from imported alert data:
  1. σ_mean: mean factor noise across all factors
  2. τ_initial: optimal temperature from mini τ sweep
  3. Remediation report: per-factor noise + recommendations

Classification:
  GREEN  (σ ≤ 0.105): Full value. Enable learning.
  AMBER  (0.105 < σ ≤ 0.157): Marginal. Enable with caution. Remediate.
  RED    (σ > 0.157): Do NOT enable learning. Frozen scorer only.

Source: 1D noise sweep (5 personas, validated).
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional

import numpy as np

FACTOR_NAMES = [
    "travel_match", "asset_criticality", "threat_intel_enrichment",
    "time_anomaly", "pattern_history", "device_trust",
]

# Thresholds from 1D sweep
SIGMA_GREEN = 0.105
SIGMA_AMBER = 0.157
SIGMA_RED   = 0.215

# Remediation mapping: which integration reduces which factor's noise
REMEDIATION_MAP = {
    "travel_match": {
        "integration": "HR/Travel system",
        "expected_reduction": 0.30,
        "note": "Connect travel records to validate geo-anomalies",
    },
    "asset_criticality": {
        "integration": "CMDB/ServiceNow",
        "expected_reduction": 0.25,
        "note": "Import asset criticality classification",
    },
    "threat_intel_enrichment": {
        "integration": "Premium TI feed (FS-ISAC, H-ISAC)",
        "expected_reduction": 0.35,
        "note": "Higher IOC coverage reduces enrichment noise",
    },
    "time_anomaly": {
        "integration": "Shift schedule / HR system",
        "expected_reduction": 0.20,
        "note": "Known work patterns reduce false time anomalies",
    },
    "pattern_history": {
        "integration": "Second SIEM source",
        "expected_reduction": 0.25,
        "note": "More historical data stabilizes pattern baselines",
    },
    "device_trust": {
        "integration": "Defender for Endpoint / Intune",
        "expected_reduction": 0.40,
        "note": "Endpoint posture data dramatically reduces device noise",
    },
}

# τ sweep values
TAU_VALUES = [0.05, 0.08, 0.10, 0.12, 0.15]


@dataclass
class NoiseProfile:
    sigma_mean: float
    sigma_per_factor: Dict[str, float]
    classification: str           # GREEN, AMBER, RED
    learning_recommended: bool


@dataclass
class TauCalibration:
    tau_optimal: float
    ece_at_optimal: float
    ece_at_default: float         # ECE at τ=0.10
    recalibrate: bool             # True if τ_optimal != 0.10


@dataclass
class RemediationItem:
    factor: str
    current_noise: float
    integration: str
    expected_noise_after: float
    expected_reduction_pct: float
    note: str
    priority: int                 # 1=highest impact


@dataclass
class QualificationResult:
    noise: NoiseProfile
    tau: TauCalibration
    remediations: List[RemediationItem]
    estimated_sigma_after_remediation: float
    would_reclassify: bool        # True if remediation changes RED→AMBER or AMBER→GREEN
    alerts_analyzed: int
    category_distribution: Dict[str, float]
    estimated_daily_volume: float
    summary: str                  # Human-readable one-paragraph summary


class DeploymentQualifier:
    """
    Measures factor noise, sweeps τ, generates remediation report.

    Usage:
        qualifier = DeploymentQualifier()
        result = qualifier.qualify(alerts, days_in_sample=30)
    """

    def qualify(self, alerts: List[Dict], days_in_sample: int = 30) -> QualificationResult:
        noise = self.measure_noise(alerts)
        tau = self.sweep_tau(alerts, noise)
        remediations = self.generate_remediations(noise)
        cat_dist = self.compute_category_distribution(alerts)
        daily_vol = len(alerts) / max(days_in_sample, 1)

        sigma_after = self.estimate_post_remediation_sigma(noise, remediations)
        after_class = self._classify(sigma_after)
        would_reclassify = (
            after_class != noise.classification
            and noise.classification in ("AMBER", "RED")
        )

        summary = self._generate_summary(
            noise, tau, remediations, sigma_after, would_reclassify,
            daily_vol, len(alerts),
        )

        return QualificationResult(
            noise=noise,
            tau=tau,
            remediations=remediations,
            estimated_sigma_after_remediation=sigma_after,
            would_reclassify=would_reclassify,
            alerts_analyzed=len(alerts),
            category_distribution=cat_dist,
            estimated_daily_volume=daily_vol,
            summary=summary,
        )

    def measure_noise(self, alerts: List[Dict]) -> NoiseProfile:
        """σ per factor = std dev of that factor across alerts. σ_mean = mean of those."""
        if not alerts:
            return NoiseProfile(0.0, {f: 0.30 for f in FACTOR_NAMES}, "RED", False)

        factor_values: Dict[str, List[float]] = {f: [] for f in FACTOR_NAMES}
        for alert in alerts:
            fv = alert.get("factor_vector", None)
            if fv and len(fv) >= len(FACTOR_NAMES):
                for i, f in enumerate(FACTOR_NAMES):
                    factor_values[f].append(float(fv[i]))
            else:
                for f in FACTOR_NAMES:
                    val = alert.get(f, None)
                    if val is not None:
                        factor_values[f].append(float(val))

        sigma_per_factor: Dict[str, float] = {}
        for f in FACTOR_NAMES:
            vals = factor_values[f]
            sigma_per_factor[f] = float(np.std(vals)) if len(vals) >= 2 else 0.30

        sigma_mean = float(np.mean(list(sigma_per_factor.values())))
        classification = self._classify(sigma_mean)
        return NoiseProfile(
            sigma_mean=sigma_mean,
            sigma_per_factor=sigma_per_factor,
            classification=classification,
            learning_recommended=classification in ("GREEN", "AMBER"),
        )

    def sweep_tau(self, alerts: List[Dict], noise: NoiseProfile) -> TauCalibration:
        """
        Mini τ sweep. ECE proxy: ECE ≈ |σ_mean − τ×2| × 0.5 + 0.02
        (empirical fit from 1D sweep; real TD-034 uses ProfileScorer).
        """
        best_tau = 0.10
        best_ece = float("inf")
        ece_at_default = 0.10

        for tau in TAU_VALUES:
            ece = abs(noise.sigma_mean - tau * 2.0) * 0.5 + 0.02
            ece = max(0.01, min(0.30, ece))
            if tau == 0.10:
                ece_at_default = ece
            if ece < best_ece:
                best_ece = ece
                best_tau = tau

        return TauCalibration(
            tau_optimal=best_tau,
            ece_at_optimal=round(best_ece, 4),
            ece_at_default=round(ece_at_default, 4),
            recalibrate=(best_tau != 0.10),
        )

    def generate_remediations(self, noise: NoiseProfile) -> List[RemediationItem]:
        """Prioritised remediation for factors above GREEN threshold."""
        items: List[RemediationItem] = []
        for f in FACTOR_NAMES:
            current = noise.sigma_per_factor.get(f, 0.0)
            if current <= SIGMA_GREEN:
                continue
            remap = REMEDIATION_MAP.get(f, {})
            reduction = remap.get("expected_reduction", 0.20)
            items.append(RemediationItem(
                factor=f,
                current_noise=round(current, 4),
                integration=remap.get("integration", "Unknown"),
                expected_noise_after=round(current * (1 - reduction), 4),
                expected_reduction_pct=round(reduction * 100, 1),
                note=remap.get("note", ""),
                priority=0,
            ))

        items.sort(key=lambda x: x.current_noise, reverse=True)
        for i, item in enumerate(items):
            item.priority = i + 1
        return items

    def estimate_post_remediation_sigma(
        self, noise: NoiseProfile, remediations: List[RemediationItem]
    ) -> float:
        adjusted = dict(noise.sigma_per_factor)
        for r in remediations:
            adjusted[r.factor] = r.expected_noise_after
        return float(np.mean(list(adjusted.values())))

    def compute_category_distribution(self, alerts: List[Dict]) -> Dict[str, float]:
        counts: Dict[str, int] = {}
        for alert in alerts:
            cat = alert.get("category", alert.get("alert_type", "unknown"))
            counts[cat] = counts.get(cat, 0) + 1
        total = max(sum(counts.values()), 1)
        return {k: round(v / total, 3) for k, v in counts.items()}

    # ── internal ──────────────────────────────────────────────────────────────

    def _classify(self, sigma: float) -> str:
        if sigma <= SIGMA_GREEN:
            return "GREEN"
        elif sigma <= SIGMA_AMBER:
            return "AMBER"
        return "RED"

    def _generate_summary(
        self, noise: NoiseProfile, tau: TauCalibration,
        remediations: List[RemediationItem], sigma_after: float,
        would_reclassify: bool, daily_vol: float, n_alerts: int,
    ) -> str:
        s = (
            f"Analyzed {n_alerts} alerts ({daily_vol:.0f}/day). "
            f"Mean factor noise: σ={noise.sigma_mean:.3f} ({noise.classification}). "
        )
        if noise.classification == "GREEN":
            s += (
                f"Learning recommended. Optimal τ={tau.tau_optimal}. "
                f"All categories expected to converge within 60 days."
            )
        elif noise.classification == "AMBER":
            top = remediations[0] if remediations else None
            s += (
                f"Learning possible with caution. Optimal τ={tau.tau_optimal}. "
            )
            if top:
                s += (
                    f"Top remediation: {top.integration} (reduces {top.factor} "
                    f"noise from {top.current_noise:.2f} to {top.expected_noise_after:.2f}). "
                )
            if would_reclassify:
                s += f"After remediation: σ→{sigma_after:.3f} (GREEN). "
        else:  # RED
            s += (
                f"Learning NOT recommended. Frozen scorer only. "
                f"{len(remediations)} remediations available. "
            )
            if would_reclassify:
                s += (
                    f"After remediation: σ→{sigma_after:.3f} "
                    f"({self._classify(sigma_after)}). "
                    f"Connect recommended sources to enable learning."
                )
        return s
