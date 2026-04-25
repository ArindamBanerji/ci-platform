from concurrent.futures import ThreadPoolExecutor

from ci_platform.audit.evidence_ledger import EvidenceLedger, OutcomeEntry


def _append_decision(ledger: EvidenceLedger, idx: int):
    return ledger.append(
        decision_id=f"DEC-{idx:03d}",
        alert_id=f"ALERT-{idx:03d}",
        factor_breakdown={f"factor_{idx}": 1.0},
        action="escalate",
        confidence=0.75,
        outcome="pending",
        analyst_override=False,
        centroid_state_hash=f"centroid-{idx:03d}",
    )


def test_concurrent_appends_unique_chain_indices():
    ledger = EvidenceLedger()
    with ThreadPoolExecutor(max_workers=12) as executor:
        entries = list(executor.map(lambda i: _append_decision(ledger, i), range(20)))

    chain_indices = [entry.chain_index for entry in entries]
    assert len(chain_indices) == 20
    assert len(set(chain_indices)) == 20
    assert sorted(chain_indices) == list(range(20))
    assert ledger.verify_chain() is True


def test_concurrent_append_and_outcome_no_corruption():
    ledger = EvidenceLedger()
    decisions = [_append_decision(ledger, idx) for idx in range(8)]

    def append_outcome(entry):
        return ledger.append_outcome(
            decision_id=entry.decision_id,
            decision_entry_hash=entry.entry_hash,
            outcome="correct",
            analyst_override=False,
        )

    with ThreadPoolExecutor(max_workers=10) as executor:
        outcomes = list(executor.map(append_outcome, decisions))

    decision_hashes = {entry.entry_hash for entry in decisions}
    assert ledger.verify_chain() is True
    assert all(isinstance(outcome, OutcomeEntry) for outcome in outcomes)
    assert all(outcome.decision_entry_hash in decision_hashes for outcome in outcomes)


def test_sequential_append_chain_integrity():
    ledger = EvidenceLedger()
    entries = [_append_decision(ledger, idx) for idx in range(10)]

    assert ledger.verify_chain() is True
    assert entries[0].prev_hash == "0" * 64
    for idx in range(1, len(entries)):
        assert entries[idx].prev_hash == entries[idx - 1].entry_hash


def test_interleaved_append_and_outcome_concurrent():
    ledger = EvidenceLedger()
    # Seed 5 decisions sequentially so outcomes have valid targets.
    seed_decisions = [_append_decision(ledger, idx) for idx in range(5)]
    seed_hashes = {entry.entry_hash for entry in seed_decisions}

    def new_decision(idx):
        return ("decision", _append_decision(ledger, idx + 100))

    def new_outcome(entry):
        outcome = ledger.append_outcome(
            decision_id=entry.decision_id,
            decision_entry_hash=entry.entry_hash,
            outcome="correct",
            analyst_override=False,
        )
        return ("outcome", outcome)

    tasks = [lambda i=i: new_decision(i) for i in range(5)] + [
        lambda e=e: new_outcome(e) for e in seed_decisions
    ]

    with ThreadPoolExecutor(max_workers=10) as executor:
        results = list(executor.map(lambda fn: fn(), tasks))

    assert ledger.verify_chain() is True

    all_entries = list(ledger.entries()) if hasattr(ledger, "entries") else []
    # Chain indices of every entry (decisions + outcomes) must be unique.
    chain_indices = [e.chain_index for e in all_entries]
    assert len(chain_indices) == len(set(chain_indices))

    outcome_entries = [e for e in all_entries if hasattr(e, "decision_entry_hash")]
    for outcome in outcome_entries:
        assert outcome.decision_entry_hash in seed_hashes
