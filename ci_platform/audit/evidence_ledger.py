"""
Evidence Ledger — hash-chained audit trail for per-decision accountability.

EU AI Act Art. 15 (Robustness) compliance: each entry records the epistemic
state of the system at decision time so operators can audit behaviour under
varying conditions:

  kernel_type         — distance kernel active ("l2" | "diagonal")
  noise_zone          — deployment noise zone ("green" | "amber" | "red")
  conservation_status — learning health ("green" | "amber" | "red" | "calibrating")
  confidence          — scorer confidence at decision time

Hash chain: each entry's hash is SHA-256 over all content fields + prev_hash.
The genesis entry uses prev_hash = "0" * 64.
Adding new fields changes the hash computation — this is correct; new fields
are part of the record and the chain reflects the full content of each entry.
"""

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional


@dataclass
class LedgerEntry:
    # ── Core decision fields ───────────────────────────────────────────────
    decision_id: str
    timestamp: str                        # ISO-8601 UTC
    alert_id: str
    factor_breakdown: Dict[str, float]
    action: str                           # e.g. "escalate", "close", "monitor"
    confidence: float
    outcome: str                          # e.g. "true_positive", "false_positive", "pending"
    analyst_override: bool
    centroid_state_hash: str              # hash of centroid state at decision time

    # ── Hash chain ─────────────────────────────────────────────────────────
    prev_hash: str                        # hash of preceding entry; "0"*64 for genesis
    entry_hash: str = field(default="")  # computed after construction; do not set manually

    # ── EU AI Act Art. 15 — epistemic state fields (Optional, backward compat)
    kernel_type: Optional[str] = None           # "l2" | "diagonal"
    noise_zone: Optional[str] = None            # "green" | "amber" | "red"
    conservation_status: Optional[str] = None  # "green" | "amber" | "red" | "calibrating"

    def compute_hash(self) -> str:
        """SHA-256 over all content fields (excluding entry_hash itself) + prev_hash."""
        payload = {
            "decision_id": self.decision_id,
            "timestamp": self.timestamp,
            "alert_id": self.alert_id,
            "factor_breakdown": self.factor_breakdown,
            "action": self.action,
            "confidence": self.confidence,
            "outcome": self.outcome,
            "analyst_override": self.analyst_override,
            "centroid_state_hash": self.centroid_state_hash,
            "prev_hash": self.prev_hash,
            "kernel_type": self.kernel_type,
            "noise_zone": self.noise_zone,
            "conservation_status": self.conservation_status,
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode()).hexdigest()

    def seal(self) -> "LedgerEntry":
        """Compute and store entry_hash. Returns self for chaining."""
        self.entry_hash = self.compute_hash()
        return self

    def is_valid(self) -> bool:
        """True if the stored entry_hash matches a fresh computation."""
        return self.entry_hash == self.compute_hash()


class EvidenceLedger:
    """
    Append-only hash-chained audit ledger.

    Usage:
        ledger = EvidenceLedger()
        entry = ledger.append(
            decision_id="d-001",
            alert_id="a-123",
            factor_breakdown={"travel_match": 0.8},
            action="escalate",
            confidence=0.91,
            outcome="pending",
            analyst_override=False,
            centroid_state_hash="abc123",
            kernel_type="diagonal",
            noise_zone="amber",
            conservation_status="green",
        )
    """

    def __init__(self) -> None:
        self._entries: List[LedgerEntry] = []

    # ── public API ─────────────────────────────────────────────────────────

    def append(
        self,
        decision_id: str,
        alert_id: str,
        factor_breakdown: Dict[str, float],
        action: str,
        confidence: float,
        outcome: str,
        analyst_override: bool,
        centroid_state_hash: str,
        timestamp: Optional[str] = None,
        kernel_type: Optional[str] = None,
        noise_zone: Optional[str] = None,
        conservation_status: Optional[str] = None,
    ) -> LedgerEntry:
        """Append a new entry. Returns the sealed LedgerEntry."""
        prev_hash = self._entries[-1].entry_hash if self._entries else "0" * 64
        ts = timestamp or datetime.now(timezone.utc).isoformat()
        entry = LedgerEntry(
            decision_id=decision_id,
            timestamp=ts,
            alert_id=alert_id,
            factor_breakdown=factor_breakdown,
            action=action,
            confidence=confidence,
            outcome=outcome,
            analyst_override=analyst_override,
            centroid_state_hash=centroid_state_hash,
            prev_hash=prev_hash,
            kernel_type=kernel_type,
            noise_zone=noise_zone,
            conservation_status=conservation_status,
        ).seal()
        self._entries.append(entry)
        return entry

    def verify_chain(self) -> bool:
        """
        Verify the entire chain is intact.
        Returns True if every entry is internally valid and prev_hash links are unbroken.
        """
        expected_prev = "0" * 64
        for entry in self._entries:
            if not entry.is_valid():
                return False
            if entry.prev_hash != expected_prev:
                return False
            expected_prev = entry.entry_hash
        return True

    def __len__(self) -> int:
        return len(self._entries)

    def __iter__(self):
        return iter(self._entries)

    def entries(self) -> List[LedgerEntry]:
        return list(self._entries)
