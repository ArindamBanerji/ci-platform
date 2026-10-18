"""R-01/R-02/R-03 regressions, including real AGE round trips."""
from __future__ import annotations

import math
import os

import pytest

from ci_platform.graph.age_client import (
    AGEClient, _BOUNDED_JSON_FIELDS, _check_safe_cypher, _decode_bounded_value,
)
from ci_platform.graph.age_sdk_adapter import BoundedAGEGraphStoreAdapter
from ci_platform.graph.bounded_projection_migration import _canonical_literal, migrate
from copilot_sdk.graph.memory_store import InMemoryGraphStore
from copilot_sdk.graph.query import DecisionFilter, DecisionPageRequest
from tests.test_bounded_projection_age import DOMAIN, adapter, raw_store, write


live = pytest.mark.skipif(not os.getenv("GRAPH_DSN"), reason="GRAPH_DSN not configured")
LEGACY_TEXTS = (
    "Explain MERGE (n) in the journal", "DELETE old records note from meeting",
    "We need to CREATE a plan for Q3", "SET the meeting for Tuesday",
    "MATCH the invoice to the PO", "Normal journal entry without keywords",
    "Used REMOVE command in bash",
)


@pytest.mark.parametrize("field,value,expected", [
    ("decision_id", "null", "null"), ("decision_id", "true", "true"),
    ("decision_id", "123", "123"), ("decision_id", "", ""),
    ("notes", "{looks like json}", "{looks like json}"),
    ("journal", '{"key": "val"}', {"key": "val"}),
    ("journal", "null", None),
    ("notes", '{"key": "val"}', '{"key": "val"}'),
    ("source", "[]", "[]"), ("_cursor_id", "null", "null"),
    ("metadata", '{"notes":"null"}', {"notes": "null"}),
])
def test_bounded_field_decoder_preserves_string_identity(field, value, expected):
    result = _decode_bounded_value(field, value)
    assert result == expected and type(result) is type(expected)
    assert "decision_id" not in _BOUNDED_JSON_FIELDS


@pytest.mark.parametrize("field", ["pnl", "entry_price", "exit_price", "confidence"])
@pytest.mark.parametrize("encoded", ["inf", "-inf", "nan"])
def test_old_nonfinite_canonical_encoding_still_decodes(field, encoded):
    value = _decode_bounded_value(field, encoded)
    assert type(value) is float
    assert math.isnan(value) if encoded == "nan" else value == float(encoded)
    assert _decode_bounded_value("notes", encoded) == encoded


@pytest.mark.parametrize("text", LEGACY_TEXTS + (
    "escaped ' quote \\ MERGE (n)", "SET n = {}", 'a "MERGE (n)" note',
))
def test_guard_ignores_bound_text_in_reads_and_writes(text):
    literal = AGEClient.serialize_for_age(text)
    _check_safe_cypher(f"RETURN {literal} AS notes")
    _check_safe_cypher(f"CREATE (d:Decision {{notes: {literal}}}) RETURN d")


@pytest.mark.parametrize("prefix", ["", "// MERGE (ignored)\n", "/* SET x = {} */ "])
@pytest.mark.parametrize("statement", ["MERGE (n:Decision) RETURN n", "MATCH (n) SET n = {} RETURN n"])
def test_guard_still_rejects_executable_unsupported_writes(prefix, statement):
    with pytest.raises(ValueError, match="Forbidden"):
        _check_safe_cypher(prefix + statement)


@live
@pytest.mark.parametrize("descending", [False, True])
@pytest.mark.parametrize("order_by", ["created_at", "verified_at"])
@pytest.mark.parametrize("projection", ["summary", "full"])
def test_literal_string_ids_progress_through_every_cursor_page(adapter, descending, order_by, projection):
    ids = ["null", "z", "true", "123", "[]", '{"a":1}']
    for name in ids:
        write(adapter, name)
        adapter.write_outcome(name, "buy", True, {"verified_at": 2}, domain=DOMAIN)
    seen = []
    after = None
    for _ in ids:  # Bounded loop fails instead of hanging if a cursor repeats.
        page = adapter.query_decisions(DOMAIN, projection=projection, page=DecisionPageRequest(
            limit=1, descending=descending, order_by=order_by, after=after,
        ))
        assert len(page.items) == 1
        name = page.items[0]["decision_id"]
        assert isinstance(name, str) and name not in seen
        seen.append(name)
        if page.has_more:
            assert page.next_cursor is not None and page.next_cursor.decision_id == name
        after = page.next_cursor
    assert not page.has_more and after is None
    assert seen == sorted(ids, reverse=descending)


@live
def test_journal_plain_text_and_structured_fields_have_feed_parity(adapter):
    write(adapter, "null", notes='{"not": "json"}', reflection="null",
          options_factors={"notes": "null", "values": [1, 2]}, tags=[" [] "])
    direct = adapter.query_decisions(DOMAIN, projection="journal").items[0]
    feed = adapter.get_decision_changes(DOMAIN, after_generation=0, projection="journal").events[0]["payload"]
    assert direct == feed
    assert direct["notes"] == '{"not": "json"}' and direct["reflection"] == "null"
    assert direct["options_factors"] == {"notes": "null", "values": [1, 2]}
    assert direct["tags"] == ["[]"]


@live
@pytest.mark.parametrize("value", [float("inf"), float("-inf"), float("nan"), 0.0, 1.5, -99.9])
def test_native_numeric_round_trip_and_direct_feed_memory_parity(adapter, value):
    # Exercise the actual write expression and result decoder, not a simulation.
    literal = _canonical_literal(adapter._store, value)
    rows = adapter._store._run(adapter._store._client.run_transaction(
        lambda tx: tx.run_bounded_cypher(f"RETURN {literal} AS pnl"),
    ))
    values = [rows[0]["pnl"]]
    memory = InMemoryGraphStore()
    for store in (adapter, memory):
        write(store, "d", pnl=value, entry_price=value, exit_price=value)
        for projection in ("journal", "full"):
            direct = store.query_decisions(DOMAIN, projection=projection).items[0]
            feed = store.get_decision_changes(DOMAIN, after_generation=0, projection=projection).events[0]["payload"]
            values.extend(record[field] for record in (direct, feed) for field in ("pnl", "entry_price", "exit_price"))
    for actual in values:
        assert type(actual) is float
        assert math.isnan(actual) if math.isnan(value) else actual == value


@live
@pytest.mark.parametrize("encoded", ["inf", "-inf", "nan"])
def test_existing_string_encoded_journal_rows_remain_readable(adapter, encoded):
    write(adapter, "old", pnl=float(encoded), entry_price=float(encoded), exit_price=float(encoded))
    # Simulate P2b's already-persisted canonical representation, without rewriting evidence.
    def old_encoding(tx):
        literal = adapter._store._S(encoded)
        return tx.run_bounded_cypher(
            f"MATCH (d:Decision) SET d._bp_pnl = {literal}, d._bp_entry_price = {literal}, d._bp_exit_price = {literal} RETURN d"
        )
    adapter._store._run(adapter._store._client.run_transaction(old_encoding))
    direct = adapter.query_decisions(DOMAIN, projection="journal").items[0]
    for field in ("pnl", "entry_price", "exit_price"):
        assert type(direct[field]) is float
        assert math.isnan(direct[field]) if encoded == "nan" else direct[field] == float(encoded)


@live
def test_keyword_text_backfill_and_activated_writes(raw_store):
    for i, text in enumerate(LEGACY_TEXTS):
        write(raw_store, f"old{i}", notes=text)
    assert migrate(raw_store, DOMAIN)["events_created"] == len(LEGACY_TEXTS)
    bounded = BoundedAGEGraphStoreAdapter(store=raw_store, domain=DOMAIN)
    for i, text in enumerate(LEGACY_TEXTS):
        write(bounded, f"new{i}", notes=text)
    direct = bounded.query_decisions(DOMAIN, projection="journal").items
    assert sorted(row["notes"] for row in direct) == sorted(LEGACY_TEXTS * 2)
    assert len(bounded.get_decision_changes(DOMAIN, after_generation=0).events) == 14


@live
@pytest.mark.parametrize("attempt", [
    "'; DROP TABLE decisions; --",
    'MERGE (n:Decision {id: "evil"}) RETURN n',
    'CREATE (n:Malicious) RETURN n',
    "'} ) CREATE (n:Malicious) // $$ $bounded$",
])
def test_injected_statements_remain_data_on_public_write(adapter, attempt):
    write(adapter, "safe", notes=attempt, ticker=attempt)
    row = adapter.query_decisions(DOMAIN, projection="journal", filters=DecisionFilter(ticker=attempt)).items[0]
    assert row["notes"] == attempt
    assert adapter.count_decisions(DOMAIN) == 1
    rows = adapter._store._run(adapter._store._client.run_transaction(
        lambda tx: tx.run_bounded_cypher("MATCH (n:Malicious) RETURN count(n) AS cnt"),
    ))
    assert rows == [{"cnt": 0}]
