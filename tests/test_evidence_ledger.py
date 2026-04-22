"""Tests for the Evidence Ledger (hash-chained audit trail)."""
import pytest

from ci_platform.audit.evidence_ledger import EvidenceLedger, LedgerEntry, OutcomeEntry


# ── helpers ───────────────────────────────────────────────────────────────────

def _base_kwargs(**overrides):
    base = dict(
        decision_id="d-001",
        alert_id="a-100",
        factor_breakdown={"travel_match": 0.75, "device_trust": 0.50},
        action="escalate",
        confidence=0.88,
        outcome="pending",
        analyst_override=False,
        centroid_state_hash="deadbeef" * 8,
    )
    base.update(overrides)
    return base


# ── hash chain correctness ────────────────────────────────────────────────────

def test_genesis_entry_prev_hash_is_zeros():
    ledger = EvidenceLedger()
    entry = ledger.append(**_base_kwargs())
    assert entry.prev_hash == "0" * 64


def test_second_entry_links_to_first():
    ledger = EvidenceLedger()
    e1 = ledger.append(**_base_kwargs(decision_id="d-001"))
    e2 = ledger.append(**_base_kwargs(decision_id="d-002"))
    assert e2.prev_hash == e1.entry_hash


def test_verify_chain_intact():
    ledger = EvidenceLedger()
    for i in range(5):
        ledger.append(**_base_kwargs(decision_id=f"d-{i:03d}", alert_id=f"a-{i}"))
    assert ledger.verify_chain() is True


def test_verify_chain_detects_tampering():
    ledger = EvidenceLedger()
    ledger.append(**_base_kwargs(decision_id="d-001"))
    ledger.append(**_base_kwargs(decision_id="d-002"))
    # Tamper with the first entry's action field directly
    ledger.entries()[0].action = "close"
    assert ledger.verify_chain() is False


def test_entry_hash_is_deterministic():
    ledger = EvidenceLedger()
    e = ledger.append(**_base_kwargs(timestamp="2026-01-01T00:00:00+00:00"))
    assert e.entry_hash == e.compute_hash()


def test_len_and_iter():
    ledger = EvidenceLedger()
    for i in range(3):
        ledger.append(**_base_kwargs(decision_id=f"d-{i}"))
    assert len(ledger) == 3
    ids = [e.decision_id for e in ledger]
    assert ids == ["d-0", "d-1", "d-2"]


# ── EU AI Act Art. 15 — epistemic state fields ────────────────────────────────

def test_ledger_entry_includes_kernel_type():
    """kernel_type is stored on the entry and included in the hash."""
    ledger = EvidenceLedger()
    entry = ledger.append(**_base_kwargs(kernel_type="diagonal"))
    assert entry.kernel_type == "diagonal"
    assert entry.is_valid()

    # Changing kernel_type must invalidate the stored hash
    entry.kernel_type = "l2"
    assert not entry.is_valid()


def test_ledger_entry_includes_noise_zone():
    """noise_zone is stored on the entry and included in the hash."""
    ledger = EvidenceLedger()
    entry = ledger.append(**_base_kwargs(noise_zone="amber"))
    assert entry.noise_zone == "amber"
    assert entry.is_valid()

    entry.noise_zone = "red"
    assert not entry.is_valid()


def test_ledger_entry_backward_compatible_none_defaults():
    """Entries created without the new fields default all three to None."""
    ledger = EvidenceLedger()
    entry = ledger.append(**_base_kwargs())   # no kernel_type / noise_zone / conservation_status
    assert entry.kernel_type is None
    assert entry.noise_zone is None
    assert entry.conservation_status is None
    # Chain must still verify correctly
    assert ledger.verify_chain() is True


# ── conservation_status ───────────────────────────────────────────────────────

def test_conservation_status_stored_and_hashed():
    ledger = EvidenceLedger()
    entry = ledger.append(**_base_kwargs(conservation_status="calibrating"))
    assert entry.conservation_status == "calibrating"
    assert entry.is_valid()

    entry.conservation_status = "green"
    assert not entry.is_valid()


def test_all_three_epistemic_fields_together():
    ledger = EvidenceLedger()
    entry = ledger.append(
        **_base_kwargs(
            kernel_type="l2",
            noise_zone="green",
            conservation_status="green",
        )
    )
    assert entry.kernel_type == "l2"
    assert entry.noise_zone == "green"
    assert entry.conservation_status == "green"
    assert ledger.verify_chain() is True


def test_mixed_entries_chain_verifies():
    """Some entries have epistemic fields, some do not — chain still valid."""
    ledger = EvidenceLedger()
    ledger.append(**_base_kwargs(decision_id="d-001"))                          # no new fields
    ledger.append(**_base_kwargs(decision_id="d-002", kernel_type="diagonal"))  # partial
    ledger.append(**_base_kwargs(                                                # all three
        decision_id="d-003",
        kernel_type="l2",
        noise_zone="amber",
        conservation_status="calibrating",
    ))
    assert ledger.verify_chain() is True


# ── OutcomeEntry / dual-entry chain ───────────────────────────────────────────

def test_outcome_entry_appended_to_chain():
    ledger = EvidenceLedger()
    entry = ledger.append(
        decision_id="DEC-001", timestamp="2026-04-21T00:00:00",
        alert_id="ALT-001", factor_breakdown={},
        action="escalate", confidence=0.85,
        outcome="pending", analyst_override=False,
        centroid_state_hash="abc123", kernel_type="diagonal",
        noise_zone="low", conservation_status="GREEN"
    )
    outcome = ledger.append_outcome(
        decision_id="DEC-001",
        decision_entry_hash=entry.entry_hash,
        outcome="correct",
        analyst_override=False,
    )
    assert len(ledger.entries()) == 2
    assert isinstance(ledger.entries()[0], LedgerEntry)
    assert isinstance(ledger.entries()[1], OutcomeEntry)
    assert outcome.decision_entry_hash == entry.entry_hash
    assert ledger.verify_chain()


def test_outcome_entry_tamper_detected():
    ledger = EvidenceLedger()
    entry = ledger.append(
        decision_id="DEC-001", timestamp="2026-04-21T00:00:00",
        alert_id="ALT-001", factor_breakdown={},
        action="escalate", confidence=0.85,
        outcome="pending", analyst_override=False,
        centroid_state_hash="abc123", kernel_type="diagonal",
        noise_zone="low", conservation_status="GREEN"
    )
    outcome = ledger.append_outcome(
        decision_id="DEC-001",
        decision_entry_hash=entry.entry_hash,
        outcome="correct",
        analyst_override=False,
    )
    outcome.outcome = "incorrect"
    assert not outcome.is_valid()
    assert not ledger.verify_chain()


def test_chain_index_monotonic():
    ledger = EvidenceLedger()
    e1 = ledger.append(
        decision_id="DEC-001", timestamp="2026-04-21T00:00:00",
        alert_id="ALT-001", factor_breakdown={},
        action="escalate", confidence=0.85,
        outcome="pending", analyst_override=False,
        centroid_state_hash="abc", kernel_type="diagonal",
        noise_zone="low", conservation_status="GREEN"
    )
    o1 = ledger.append_outcome(
        decision_id="DEC-001",
        decision_entry_hash=e1.entry_hash,
        outcome="correct", analyst_override=False,
    )
    e2 = ledger.append(
        decision_id="DEC-002", timestamp="2026-04-21T00:00:00",
        alert_id="ALT-002", factor_breakdown={},
        action="investigate", confidence=0.7,
        outcome="pending", analyst_override=False,
        centroid_state_hash="def", kernel_type="diagonal",
        noise_zone="low", conservation_status="GREEN"
    )
    assert e1.chain_index == 0
    assert o1.chain_index == 1
    assert e2.chain_index == 2
    assert ledger.verify_chain()


def test_decision_hash_excludes_outcome():
    """Mutating outcome on a sealed LedgerEntry should NOT break is_valid()
    because outcome is no longer in the hash."""
    ledger = EvidenceLedger()
    entry = ledger.append(
        decision_id="DEC-001", timestamp="2026-04-21T00:00:00",
        alert_id="ALT-001", factor_breakdown={},
        action="escalate", confidence=0.85,
        outcome="pending", analyst_override=False,
        centroid_state_hash="abc", kernel_type="diagonal",
        noise_zone="low", conservation_status="GREEN"
    )
    entry.outcome = "correct"
    assert entry.is_valid()  # outcome not in hash


def test_decision_hash_excludes_analyst_override():
    """Mutating analyst_override on a sealed LedgerEntry should NOT break is_valid()."""
    ledger = EvidenceLedger()
    entry = ledger.append(
        decision_id="DEC-001", timestamp="2026-04-21",
        alert_id="ALT-001", factor_breakdown={},
        action="escalate", confidence=0.85,
        outcome="pending", analyst_override=False,
        centroid_state_hash="abc", kernel_type="diagonal",
        noise_zone="low", conservation_status="GREEN"
    )
    entry.analyst_override = True
    assert entry.is_valid()


def test_append_outcome_on_empty_ledger_raises():
    """Cannot append an outcome to an empty ledger — there's no decision to link to."""
    ledger = EvidenceLedger()
    with pytest.raises(ValueError, match="does not match"):
        ledger.append_outcome(
            decision_id="DEC-001",
            decision_entry_hash="nonexistent_hash",
            outcome="correct",
            analyst_override=False,
        )


def test_append_outcome_rejects_unknown_hash():
    """append_outcome with a hash that doesn't match any LedgerEntry raises ValueError."""
    ledger = EvidenceLedger()
    ledger.append(
        decision_id="DEC-001", timestamp="2026-04-21",
        alert_id="ALT-001", factor_breakdown={},
        action="escalate", confidence=0.85,
        outcome="pending", analyst_override=False,
        centroid_state_hash="abc", kernel_type="diagonal",
        noise_zone="low", conservation_status="GREEN"
    )
    with pytest.raises(ValueError, match="does not match"):
        ledger.append_outcome(
            decision_id="DEC-001",
            decision_entry_hash="wrong_hash_value",
            outcome="correct",
            analyst_override=False,
        )


def test_multiple_outcomes_for_same_decision():
    """Multiple outcomes for the same decision_id are allowed (event sourcing)."""
    ledger = EvidenceLedger()
    entry = ledger.append(
        decision_id="DEC-001", timestamp="2026-04-21",
        alert_id="ALT-001", factor_breakdown={},
        action="escalate", confidence=0.85,
        outcome="pending", analyst_override=False,
        centroid_state_hash="abc", kernel_type="diagonal",
        noise_zone="low", conservation_status="GREEN"
    )
    o1 = ledger.append_outcome(
        decision_id="DEC-001",
        decision_entry_hash=entry.entry_hash,
        outcome="correct", analyst_override=False,
    )
    o2 = ledger.append_outcome(
        decision_id="DEC-001",
        decision_entry_hash=entry.entry_hash,
        outcome="incorrect", analyst_override=True,
    )
    assert len(ledger.entries()) == 3
    assert o1.chain_index == 1
    assert o2.chain_index == 2
    assert ledger.verify_chain()


def test_verify_chain_detects_chain_index_tampering():
    """Mutating chain_index on a sealed entry should break is_valid()."""
    ledger = EvidenceLedger()
    entry = ledger.append(
        decision_id="DEC-001", timestamp="2026-04-21",
        alert_id="ALT-001", factor_breakdown={},
        action="escalate", confidence=0.85,
        outcome="pending", analyst_override=False,
        centroid_state_hash="abc", kernel_type="diagonal",
        noise_zone="low", conservation_status="GREEN"
    )
    entry.chain_index = 99
    assert not entry.is_valid()
    assert not ledger.verify_chain()
