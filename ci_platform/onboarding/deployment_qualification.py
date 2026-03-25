"""
Deployment Qualification — decides whether learning is safe to enable.

Three measurements from imported alert data:
  1. σ_mean: mean factor noise across all factors
  2. τ_initial: optimal temperature from mini τ sweep
  3. Remediation report: per-factor noise + recommendations

Classification (L2 kernel — default):
  GREEN  (σ ≤ 0.105): Full value. Enable learning.
  AMBER  (0.105 < σ ≤ 0.157): Marginal. Enable with caution. Remediate.
  RED    (σ > 0.157): Do NOT enable learning. Frozen scorer only.

Classification (DiagonalKernel — higher noise ceiling):
  GREEN  (σ ≤ 0.157): Full value. Enable learning.
  AMBER  (0.157 < σ ≤ 0.25): Marginal. Enable with caution. Remediate.
  RED    (σ > 0.25): Do NOT enable learning. Frozen scorer only.

Source: 1D noise sweep (5 personas, validated). DiagonalKernel validated by
V-MV-KERNEL factorial.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional

import numpy as np

FACTOR_NAMES = [
    "travel_match", "asset_criticality", "threat_intel_enrichment",
    "time_anomaly", "pattern_history", "device_trust",
]

# Thresholds from 1D sweep — L2 kernel (default)
SIGMA_GREEN = 0.105
SIGMA_AMBER = 0.157
SIGMA_RED   = 0.215

# Thresholds — DiagonalKernel (higher noise ceiling; validated by V-MV-KERNEL factorial)
SIGMA_GREEN_DIAGONAL = 0.157
SIGMA_AMBER_DIAGONAL = 0.25

_THRESHOLDS = {
    "l2":       (SIGMA_GREEN, SIGMA_AMBER),
    "diagonal": (SIGMA_GREEN_DIAGONAL, SIGMA_AMBER_DIAGONAL),
}

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

# τ sweep values (existing mini sweep in sweep_tau method)
TAU_VALUES = [0.05, 0.08, 0.10, 0.12, 0.15]

# τ sweep values for per-deployment Phase 3 calibration (TD-034 v2)
TAU_SWEEP_VALUES = [0.08, 0.10, 0.12, 0.15, 0.18]
ECE_GATE = 0.05


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


def _compute_ece(
    decisions: List[Dict],
    tau: float,
    n_bins: int,
) -> float:
    """
    Compute Expected Calibration Error for a given tau.
    Rescales confidence scores using softmax temperature tau.
    ECE = mean(|mean_confidence_in_bin - fraction_correct_in_bin|)
    """
    import math
    rescaled = []
    for d in decisions:
        conf = max(min(d["confidence"], 0.9999), 0.0001)
        logit = math.log(conf / (1 - conf))
        conf_tau = 1 / (1 + math.exp(-logit / tau))
        rescaled.append((conf_tau, d["correct"]))

    bins: List[List] = [[] for _ in range(n_bins)]
    for conf, correct in rescaled:
        bin_idx = min(int(conf * n_bins), n_bins - 1)
        bins[bin_idx].append((conf, correct))

    ece = 0.0
    for bin_items in bins:
        if not bin_items:
            continue
        mean_conf = sum(c for c, _ in bin_items) / len(bin_items)
        mean_acc = sum(int(ok) for _, ok in bin_items) / len(bin_items)
        ece += abs(mean_conf - mean_acc) * len(bin_items) / len(rescaled)
    return ece


def sweep_tau_for_deployment(
    shadow_decisions: List[Dict],
    tau_values: Optional[List[float]] = None,
    ece_gate: float = ECE_GATE,
    n_bins: int = 10,
) -> Dict:
    """
    Per-deployment τ calibration from first 50 shadow decisions.

    Called when: sigma_mean > 0.12 OR noise_ratio > 2.0

    Args:
        shadow_decisions: list of dicts with keys {confidence: float, correct: bool}
        tau_values: sweep values (default TAU_SWEEP_VALUES)
        ece_gate: target ECE threshold (default 0.05)
        n_bins: calibration bins (default 10)

    Returns:
        {tau_selected, ece_at_selected, gate_pass, sweep_results, recommendation}
    """
    if tau_values is None:
        tau_values = TAU_SWEEP_VALUES

    sweep_results: Dict[float, float] = {}
    for tau in tau_values:
        ece = _compute_ece(shadow_decisions, tau, n_bins)
        sweep_results[tau] = ece

    passing = {t: e for t, e in sweep_results.items() if e <= ece_gate}

    if passing:
        tau_selected = min(passing, key=passing.get)
        ece_selected = passing[tau_selected]
        gate_pass = True
    else:
        tau_selected = min(sweep_results, key=sweep_results.get)
        ece_selected = sweep_results[tau_selected]
        gate_pass = False

    return {
        "tau_selected": tau_selected,
        "ece_at_selected": round(ece_selected, 4),
        "gate_pass": gate_pass,
        "sweep_results": {str(t): round(e, 4) for t, e in sweep_results.items()},
        "recommendation": "use_selected" if gate_pass else "use_default_010",
    }


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
    kernel_recommendation: str = "l2"      # "l2" or "diagonal"
    noise_ratio: Optional[float] = None    # max(σ) / min(σ) across factors
    rationale: str = ""                    # why this kernel was chosen
    tau_sweep: Optional[Dict] = None       # Phase 3 per-deployment τ sweep result (TD-034 v2)


class DeploymentQualifier:
    """
    Measures factor noise, sweeps τ, generates remediation report.

    Usage:
        qualifier = DeploymentQualifier()
        result = qualifier.qualify(alerts, days_in_sample=30)
    """

    def qualify(
        self,
        alerts: List[Dict],
        days_in_sample: int = 30,
        kernel_recommendation: str = "l2",
        shadow_decisions: Optional[List[Dict]] = None,
    ) -> QualificationResult:
        noise = self.measure_noise(alerts, kernel_recommendation)
        tau = self.sweep_tau(alerts, noise)
        remediations = self.generate_remediations(noise)
        cat_dist = self.compute_category_distribution(alerts)
        daily_vol = len(alerts) / max(days_in_sample, 1)

        sigma_after = self.estimate_post_remediation_sigma(noise, remediations)
        after_class = self._classify(sigma_after, kernel_recommendation)
        would_reclassify = (
            after_class != noise.classification
            and noise.classification in ("AMBER", "RED")
        )

        # noise_ratio: spread of per-factor noise
        sigmas = list(noise.sigma_per_factor.values())
        sigma_min = min(sigmas) if sigmas else 0.0
        if sigmas and sigma_min > 0:
            noise_ratio: Optional[float] = round(max(sigmas) / sigma_min, 3)
        else:
            noise_ratio = None

        if noise_ratio is not None:
            if noise_ratio > 1.5:
                rationale = (
                    f"noise_ratio {noise_ratio:.1f} > 1.5 threshold "
                    f"\u2192 DiagonalKernel recommended"
                )
            else:
                rationale = (
                    f"noise_ratio {noise_ratio:.1f} \u2264 1.5 \u2192 L2 kernel sufficient"
                )
        else:
            rationale = "kernel_recommendation provided externally"

        # Phase 3: per-deployment τ sweep (TD-034 v2)
        tau_sweep_triggered = (
            noise.sigma_mean > 0.12
            or (noise_ratio is not None and noise_ratio > 2.0)
        )
        sd = shadow_decisions or []
        if tau_sweep_triggered and len(sd) >= 50:
            tau_result: Dict = sweep_tau_for_deployment(sd[:50])
        else:
            tau_result = {
                "tau_selected": 0.10,
                "ece_at_selected": None,
                "gate_pass": True,
                "sweep_results": {},
                "recommendation": "use_default_010",
            }
        tau_result["tau_sweep_triggered"] = tau_sweep_triggered

        summary = self._generate_summary(
            noise, tau, remediations, sigma_after, would_reclassify,
            daily_vol, len(alerts), kernel_recommendation,
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
            kernel_recommendation=kernel_recommendation,
            noise_ratio=noise_ratio,
            rationale=rationale,
            tau_sweep=tau_result,
        )

    def measure_noise(
        self, alerts: List[Dict], kernel_recommendation: str = "l2"
    ) -> NoiseProfile:
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
        classification = self._classify(sigma_mean, kernel_recommendation)
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

    def _classify(self, sigma: float, kernel: str = "l2") -> str:
        green, amber = _THRESHOLDS.get(kernel, _THRESHOLDS["l2"])
        if sigma <= green:
            return "GREEN"
        elif sigma <= amber:
            return "AMBER"
        return "RED"

    def _generate_summary(
        self, noise: NoiseProfile, tau: TauCalibration,
        remediations: List[RemediationItem], sigma_after: float,
        would_reclassify: bool, daily_vol: float, n_alerts: int,
        kernel: str = "l2",
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
                    f"({self._classify(sigma_after, kernel)}). "
                    f"Connect recommended sources to enable learning."
                )
        return s
