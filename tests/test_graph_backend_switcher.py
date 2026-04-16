"""
tests/test_graph_backend_switcher.py

Signature-parity tests: verify AGEClient methods accept every kwarg
that production callers in gen-ai-roi-demo-v4-v50 actually pass.

Uses psycopg mocks — tests signature acceptance only, not query correctness.
If a test raises TypeError, the method signature is missing a parameter.
"""
import asyncio
from unittest.mock import MagicMock, patch

import pytest


def _mock_conn():
    """Return a mock psycopg connection context manager returning empty rows."""
    cur = MagicMock()
    cur.fetchall.return_value = []
    conn = MagicMock()
    conn.__enter__ = MagicMock(return_value=conn)
    conn.__exit__ = MagicMock(return_value=False)
    conn.execute.return_value = cur
    return conn


def _age_client():
    """Return an AGEClient with no real DSN (mocked connection)."""
    from ci_platform.graph.age_client import AGEClient
    client = AGEClient.__new__(AGEClient)
    client._dsn = "postgresql://localhost:5432/test"
    client._graph = "test_graph"
    return client


# ── create_decision_trace ─────────────────────────────────────────────────────

def test_create_decision_trace_accepts_evolution_kwargs():
    """
    Exact kwargs from gen-ai-roi-demo-v4-v50/backend/app/routers/evolution.py:417-437.
    A TypeError here means the AGEClient signature is missing a parameter.
    """
    client = _age_client()
    with patch("ci_platform.graph.age_client.psycopg.connect", return_value=_mock_conn()):
        asyncio.run(client.create_decision_trace(
            decision_id="DEC-SIGTEST1",
            alert_id="ALT-SIGTEST1",
            action="escalate",
            confidence=0.87,
            category="lateral_movement",
            reasoning="User executed lateral movement commands across three hosts",
            pattern_id="PAT-007",
            playbook_id="PLAY-003",
            nodes_consulted=47,
            context_snapshot={
                "user": {"name": "jdoe", "risk_score": 0.9},
                "asset": {"hostname": "ws-01", "criticality": "high"},
            },
        ))


def test_create_decision_trace_stores_reasoning_in_node():
    """Reasoning is written into the Decision node, not silently dropped."""
    client = _age_client()
    conn = _mock_conn()
    with patch("ci_platform.graph.age_client.psycopg.connect", return_value=conn):
        asyncio.run(client.create_decision_trace(
            decision_id="DEC-SIGTEST2",
            alert_id="ALT-SIGTEST2",
            action="suppress",
            confidence=0.55,
            reasoning="Low-confidence suppression",
            pattern_id="PAT-001",
            playbook_id="PLAY-001",
            nodes_consulted=12,
            context_snapshot={"user": {"name": "bob"}},
        ))
    # The SQL sent to the DB should contain the reasoning value
    all_sql = " ".join(
        str(call[0][0])
        for call in conn.execute.call_args_list
        if call[0]
    )
    assert "reasoning" in all_sql, "reasoning param missing from Cypher query"
    assert "nodes_consulted" in all_sql, "nodes_consulted param missing from Cypher query"


# ── create_evolution_event ────────────────────────────────────────────────────

def test_create_evolution_event_accepts_evolution_kwargs():
    """
    Exact kwargs from gen-ai-roi-demo-v4-v50/backend/app/routers/evolution.py:258-267.
    A TypeError here means the AGEClient signature is missing a parameter.
    """
    client = _age_client()
    with patch("ci_platform.graph.age_client.psycopg.connect", return_value=_mock_conn()):
        result = asyncio.run(client.create_evolution_event(
            event_id="EVO-SIGTEST1",
            event_type="pattern_confidence_shift",
            triggered_by="DEC-SIGTEST1",
            before_state="low_risk",
            after_state="high_risk",
            description="Risk score elevated by lateral movement pattern",
            impact=0.7,
            magnitude=0.4,
        ))
    assert result is True


def test_create_evolution_event_legacy_signature_still_works():
    """
    Internal callers using alert_id/entity_id/action/verified_correct
    must continue to work (backward compat).
    """
    client = _age_client()
    conn = _mock_conn()
    with patch("ci_platform.graph.age_client.psycopg.connect", return_value=conn):
        result = asyncio.run(client.create_evolution_event(
            alert_id="ALT-LEGACY",
            entity_id="ENT-LEGACY",
            action="escalate",
            verified_correct=True,
            impact=0.5,
            magnitude=0.3,
        ))
    assert result is True
    # A DB call should have been made (the legacy path runs Cypher)
    assert conn.execute.call_count >= 1
