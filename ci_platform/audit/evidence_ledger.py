"""
Evidence Ledger — hash-chained audit trail for per-decision accountability.

EU AI Act Art. 15 (Robustness) compliance: each entry records the epistemic
state of the system at decision time so operators can audit behaviour under
varying conditions:

  kernel_type         — distance kernel active ("l2" | "diagonal")
  noise_zone          — deployment noise zone ("green" | "amber" | "red")
  conservation_status — learning health ("green" | "amber" | "red" | "calibrating")
  confidence          — scorer confidence at decision time

Hash chain: each entry's hash is SHA-256 over immutable content fields + prev_hash.
Mutable post-decision fields (outcome, analyst_override) live in OutcomeEntry,
which is appended separately and cryptographically linked to the original
DecisionEntry via decision_entry_hash.
"""

import hashlib
import json
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Union


@dataclass
class LedgerEntry:
    # ── Core decision fields ───────────────────────────────────────────────
    decision_id: str
    timestamp: str                        # ISO-8601 UTC
    alert_id: str
    factor_breakdown: Dict[str, float]
    action: str                           # e.g. "escalate", "close", "monitor"
    confidence: float
    outcome: str                          # stored for display; NOT in hash (mutable)
    analyst_override: bool                # stored for display; NOT in hash (mutable)
    centroid_state_hash: str              # hash of centroid state at decision time

    # ── Hash chain ─────────────────────────────────────────────────────────
    prev_hash: str                        # hash of preceding entry; "0"*64 for genesis
    entry_hash: str = field(default="")  # computed after construction; do not set manually
    chain_index: int = 0                 # position in the chain, set by EvidenceLedger.append()

    # ── EU AI Act Art. 15 — epistemic state fields (Optional, backward compat)
    kernel_type: Optional[str] = None           # "l2" | "diagonal"
    noise_zone: Optional[str] = None            # "green" | "amber" | "red"
    conservation_status: Optional[str] = None  # "green" | "amber" | "red" | "calibrating"

    def compute_hash(self) -> str:
        payload = {
            "type": "decision",
            "chain_index": self.chain_index,
            "decision_id": self.decision_id,
            "timestamp": self.timestamp,
            "alert_id": self.alert_id,
            "factor_breakdown": self.factor_breakdown,
            "action": self.action,
            "confidence": self.confidence,
            "centroid_state_hash": self.centroid_state_hash,
            "prev_hash": self.prev_hash,
            "kernel_type": self.kernel_type,
            "noise_zone": self.noise_zone,
            "conservation_status": self.conservation_status,
        }
        return hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()

    def seal(self) -> "LedgerEntry":
        """Compute and store entry_hash. Returns self for chaining."""
        self.entry_hash = self.compute_hash()
        return self

    def is_valid(self) -> bool:
        """True if the stored entry_hash matches a fresh computation."""
        return self.entry_hash == self.compute_hash()


@dataclass
class OutcomeEntry:
    """Outcome verification event — appended when a decision's outcome is verified.
    Separate from the original DecisionEntry to preserve hash integrity."""
    chain_index: int
    decision_id: str
    decision_entry_hash: str  # cryptographic link to the sealed LedgerEntry
    outcome: str              # "correct" | "incorrect"
    analyst_override: bool
    timestamp: str
    prev_hash: str
    entry_hash: str = ""

    def compute_hash(self) -> str:
        payload = {
            "type": "outcome",
            "chain_index": self.chain_index,
            "decision_id": self.decision_id,
            "decision_entry_hash": self.decision_entry_hash,
            "outcome": self.outcome,
            "analyst_override": self.analyst_override,
            "timestamp": self.timestamp,
            "prev_hash": self.prev_hash,
        }
        return hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()

    def seal(self) -> "OutcomeEntry":
        self.entry_hash = self.compute_hash()
        return self

    def is_valid(self) -> bool:
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
        outcome = ledger.append_outcome(
            decision_id="d-001",
            decision_entry_hash=entry.entry_hash,
            outcome="correct",
        )
    """

    def __init__(self) -> None:
        self._entries: List[Union[LedgerEntry, OutcomeEntry]] = []
        self._lock = threading.Lock()

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
        """Append a new decision entry. Returns the sealed LedgerEntry."""
        with self._lock:
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
            )
            entry.chain_index = len(self._entries)
            entry.seal()
            self._entries.append(entry)
            return entry

    def append_outcome(
        self,
        decision_id: str,
        decision_entry_hash: str,
        outcome: str,
        analyst_override: bool = False,
        timestamp: Optional[str] = None,
    ) -> OutcomeEntry:
        """Append an outcome verification event to the chain.

        Multiple outcomes for the same decision_id are allowed
        (event sourcing). Consumers should use the LATEST outcome
        per decision_id when computing q or other metrics.
        """
        with self._lock:
            prev_hash = self._entries[-1].entry_hash if self._entries else "0" * 64
            known_hashes = {e.entry_hash for e in self._entries if isinstance(e, LedgerEntry)}
            if decision_entry_hash not in known_hashes:
                raise ValueError(
                    f"decision_entry_hash {decision_entry_hash[:16]}... "
                    f"does not match any sealed LedgerEntry in the chain"
                )
            ts = timestamp or datetime.now(timezone.utc).isoformat()
            entry = OutcomeEntry(
                chain_index=len(self._entries),
                decision_id=decision_id,
                decision_entry_hash=decision_entry_hash,
                outcome=outcome,
                analyst_override=analyst_override,
                timestamp=ts,
                prev_hash=prev_hash,
            )
            entry.seal()
            self._entries.append(entry)
            return entry

    def verify_chain(self) -> bool:
        """Verify chain integrity: every entry is internally valid and prev_hash links are unbroken."""
        if not self._entries:
            return True

        for i, entry in enumerate(self._entries):
            if not entry.is_valid():
                return False
            if i > 0:
                expected_prev = self._entries[i - 1].entry_hash
                if entry.prev_hash != expected_prev:
                    return False

        return True

    def __len__(self) -> int:
        return len(self._entries)

    def __iter__(self):
        return iter(self._entries)

    def entries(self) -> List[Union[LedgerEntry, OutcomeEntry]]:
        return list(self._entries)
