"""Namespace reservation and bounded activation composition regressions."""

from __future__ import annotations

import inspect
import re
from typing import Any, Callable, cast

import pytest

from ci_platform.graph.age_graph_store import AGEGraphStore, AGEGraphStoreTransaction
from ci_platform.graph.bounded_projection_migration import (
    ActivationAbsentError,
    VERSION,
    ready,
)
from copilot_sdk.graph.memory_store import InMemoryGraphStore
from copilot_sdk.graph.namespace import GraphStoreNamespace, _InternalNamespace


RESERVED_ALIAS = "jmns__61726d__scoring"


@pytest.fixture
def age_store(monkeypatch: pytest.MonkeyPatch) -> AGEGraphStore:
    monkeypatch.setattr("ci_platform.graph.age_graph_store.AGEClient", lambda **_: object())
    return AGEGraphStore(dsn="postgresql://example/test", graph_name="test_graph")


def _required_write_kwargs(
    method: Callable[..., Any], reserved: str = RESERVED_ALIAS,
) -> dict[str, object]:
    signature = inspect.signature(method)
    kwargs: dict[str, object] = {}
    for name, parameter in signature.parameters.items():
        if name == "domain":
            kwargs[name] = reserved
        elif name == "source_domain":
            kwargs[name] = reserved
        elif name == "target_domain":
            kwargs[name] = "ordinary_domain"
        elif parameter.default is inspect.Parameter.empty:
            kwargs[name] = object()
    return kwargs


def _assert_raw_reserved_domain_rejected(method: Callable[..., Any]) -> None:
    with pytest.raises(ValueError, match="reserved.*jmns__|jmns__.*reserved"):
        method(**_required_write_kwargs(method))


def _assert_forged_domain_rejected(method: Callable[..., Any]) -> None:
    class Forged(str):
        _copilot_namespace_internal = True

    with pytest.raises(ValueError, match="reserved.*jmns__|jmns__.*reserved"):
        method(**_required_write_kwargs(method, Forged(RESERVED_ALIAS)))


class _Store:
    class _Client:
        _graph = "namespace_activation_test"

    _client = _Client()

    @staticmethod
    def _S(value: Any) -> str:
        return repr(value)

    @staticmethod
    def _node_to_dict(value: Any) -> dict[str, Any]:
        return dict(value)


class _TransactionFacadeStore:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def _record(self, name: str, kwargs: dict[str, Any]) -> None:
        self.calls.append((name, kwargs))

    def _write_decision_impl(self, **kwargs: Any) -> str:
        self._record("write_decision", kwargs)
        return "decision-id"

    def _write_outcome_impl(self, **kwargs: Any) -> None:
        self._record("write_outcome", kwargs)

    def _update_centroid_impl(self, **kwargs: Any) -> None:
        self._record("update_centroid", kwargs)

    def _write_outcome_and_update_centroid_impl(self, **kwargs: Any) -> None:
        self._record("write_outcome_and_update_centroid", kwargs)

    def _write_centroid_checkpoint_impl(self, **kwargs: Any) -> None:
        self._record("write_centroid_checkpoint", kwargs)


def _transaction_facade() -> tuple[AGEGraphStoreTransaction, _TransactionFacadeStore]:
    store = _TransactionFacadeStore()
    facade = AGEGraphStoreTransaction(cast(AGEGraphStore, store), cast(Any, object()))
    return facade, store


def _forged_reserved_domain() -> str:
    class Forged(str):
        _copilot_namespace_internal = True

    return Forged("jmns__forged__domain")


class _Transaction:
    def __init__(self, activated: set[str]) -> None:
        self.anchors = {
            domain: {"domain": domain, "generation": 0, "version": VERSION}
            for domain in activated
        }
        self.markers = set(activated)

    def execute_sql(self, sql: str, parameters: tuple[Any, ...]) -> None:
        assert "pg_advisory_xact_lock_shared" in sql
        assert parameters

    @staticmethod
    def _where_domain(cypher: str) -> str:
        match = re.search(r"\.domain = '([^']+)'", cypher)
        assert match is not None, cypher
        return match.group(1)

    def run_cypher(self, cypher: str) -> list[dict[str, Any]]:
        domain = self._where_domain(cypher)
        anchor = self.anchors.get(domain)
        return [] if anchor is None else [{"s": anchor}]

    def run_bounded_cypher(self, cypher: str) -> list[dict[str, Any]]:
        if "MATCH (a:BoundedActivation)" in cypher:
            domain = self._where_domain(cypher)
            return [{"a": {"domain": domain, "version": VERSION}}] if domain in self.markers else []
        if "MATCH (d:Decision)" in cypher:
            return []
        if "CREATE (s:BoundedDomain" in cypher:
            match = re.search(r"domain: '([^']+)'", cypher)
            assert match is not None, cypher
            domain = match.group(1)
            self.anchors[domain] = {
                "domain": domain, "generation": 0, "version": VERSION,
            }
            return [{"s": self.anchors[domain]}]
        raise AssertionError(f"unexpected bounded query: {cypher}")


def _physical(namespace: str, domain: str) -> str:
    wrapper = GraphStoreNamespace(InMemoryGraphStore(), namespace)
    return cast(str, wrapper._domain(domain))


def test_age_rejects_raw_reserved_domain_but_accepts_namespace_tag() -> None:
    raw = "jmns__61726d__scoring"

    with pytest.raises(ValueError, match="reserved for namespace routing"):
        AGEGraphStore._validated_write_domain(raw)
    assert AGEGraphStore._validated_write_domain(_physical("arm", "scoring")) == raw


def test_activated_base_initializes_namespaced_physical_domain() -> None:
    transaction = _Transaction({"s2p"})
    physical = _physical("arm", "s2p")

    anchor = ready(cast(Any, _Store()), cast(Any, transaction), physical)

    assert anchor == {
        "domain": str(physical), "generation": 0, "version": VERSION,
    }
    assert str(physical) in transaction.anchors


def test_unactivated_base_rejects_namespaced_physical_domain() -> None:
    transaction = _Transaction(set())

    with pytest.raises(ActivationAbsentError, match="not activated"):
        ready(cast(Any, _Store()), cast(Any, transaction), _physical("arm", "trading"))


def test_multiple_namespaces_get_independent_generation_anchors() -> None:
    transaction = _Transaction({"s2p"})
    arm = _physical("arm", "s2p")
    hand = _physical("hand", "s2p")

    ready(cast(Any, _Store()), cast(Any, transaction), arm)
    ready(cast(Any, _Store()), cast(Any, transaction), hand)

    assert arm != hand
    assert str(arm) in transaction.anchors
    assert str(hand) in transaction.anchors
    assert transaction.anchors[str(arm)] is not transaction.anchors[str(hand)]


def test_internal_namespace_passes_guard(age_store: AGEGraphStore) -> None:
    domain = _InternalNamespace("jmns__x__y")
    try:
        age_store.write_decision(domain=domain, category="risk", action="accept", confidence=0.8, factors={})
    except ValueError as exc:
        if "reserved" in str(exc).lower() or "jmns__" in str(exc):
            pytest.fail(f"guard rejected internal namespace: {exc}")
        raise
    except Exception:
        pass


def test_forged_subclass_rejected_by_write_decision(age_store: AGEGraphStore) -> None:
    _assert_forged_domain_rejected(age_store.write_decision)


def test_save_evolution_rejects_raw_reserved_domain(age_store: AGEGraphStore) -> None:
    _assert_raw_reserved_domain_rejected(age_store.save_evolution)


def test_delete_evolution_rejects_raw_reserved_domain(age_store: AGEGraphStore) -> None:
    _assert_raw_reserved_domain_rejected(age_store.delete_evolution)


def test_save_evolution_state_rejects_raw_reserved_domain(age_store: AGEGraphStore) -> None:
    _assert_raw_reserved_domain_rejected(age_store.save_evolution_state)


def test_save_posterior_rejects_raw_reserved_domain(age_store: AGEGraphStore) -> None:
    _assert_raw_reserved_domain_rejected(age_store.save_posterior)


def test_delete_posterior_rejects_raw_reserved_domain(age_store: AGEGraphStore) -> None:
    _assert_raw_reserved_domain_rejected(age_store.delete_posterior)


def test_save_promotion_rejects_raw_reserved_domain(age_store: AGEGraphStore) -> None:
    _assert_raw_reserved_domain_rejected(age_store.save_promotion)


def test_delete_promotion_rejects_raw_reserved_domain(age_store: AGEGraphStore) -> None:
    _assert_raw_reserved_domain_rejected(age_store.delete_promotion)


def test_save_ledger_rejects_raw_reserved_domain(age_store: AGEGraphStore) -> None:
    _assert_raw_reserved_domain_rejected(age_store.save_ledger)


def test_delete_ledger_rejects_raw_reserved_domain(age_store: AGEGraphStore) -> None:
    _assert_raw_reserved_domain_rejected(age_store.delete_ledger)


def test_save_governance_rejects_raw_reserved_domain(age_store: AGEGraphStore) -> None:
    _assert_raw_reserved_domain_rejected(age_store.save_governance)


def test_delete_governance_rejects_raw_reserved_domain(age_store: AGEGraphStore) -> None:
    _assert_raw_reserved_domain_rejected(age_store.delete_governance)


def test_write_decision_rejects_raw_reserved_domain(age_store: AGEGraphStore) -> None:
    _assert_raw_reserved_domain_rejected(age_store.write_decision)


def test_write_governed_decision_rejects_raw_reserved_domain(age_store: AGEGraphStore) -> None:
    _assert_raw_reserved_domain_rejected(age_store.write_governed_decision)


def test_write_outcome_rejects_raw_reserved_domain(age_store: AGEGraphStore) -> None:
    _assert_raw_reserved_domain_rejected(age_store.write_outcome)


def test_write_outcome_and_update_centroid_rejects_raw_reserved_domain(age_store: AGEGraphStore) -> None:
    _assert_raw_reserved_domain_rejected(age_store.write_outcome_and_update_centroid)


def test_write_observation_rejects_raw_reserved_domain(age_store: AGEGraphStore) -> None:
    _assert_raw_reserved_domain_rejected(age_store.write_observation)


def test_write_conservation_status_rejects_raw_reserved_domain(age_store: AGEGraphStore) -> None:
    _assert_raw_reserved_domain_rejected(age_store.write_conservation_status)


def test_write_fingerprint_rejects_raw_reserved_domain(age_store: AGEGraphStore) -> None:
    _assert_raw_reserved_domain_rejected(age_store.write_fingerprint)


def test_write_centroid_checkpoint_rejects_raw_reserved_domain(age_store: AGEGraphStore) -> None:
    _assert_raw_reserved_domain_rejected(age_store.write_centroid_checkpoint)


def test_append_evidence_receipt_rejects_raw_reserved_domain(age_store: AGEGraphStore) -> None:
    _assert_raw_reserved_domain_rejected(age_store.append_evidence_receipt)


def test_write_evolution_event_rejects_raw_reserved_domain(age_store: AGEGraphStore) -> None:
    _assert_raw_reserved_domain_rejected(age_store.write_evolution_event)


def test_write_transfer_pattern_rejects_raw_reserved_domain(age_store: AGEGraphStore) -> None:
    _assert_raw_reserved_domain_rejected(age_store.write_transfer_pattern)
    kwargs = _required_write_kwargs(age_store.write_transfer_pattern)
    kwargs["source_domain"] = "ordinary_domain"
    kwargs["target_domain"] = RESERVED_ALIAS
    with pytest.raises(ValueError, match="reserved.*jmns__|jmns__.*reserved"):
        age_store.write_transfer_pattern(**kwargs)  # type: ignore[arg-type]


def test_link_entity_rejects_raw_reserved_domain(age_store: AGEGraphStore) -> None:
    _assert_raw_reserved_domain_rejected(age_store.link_entity)


def test_update_centroid_rejects_raw_reserved_domain(age_store: AGEGraphStore) -> None:
    _assert_raw_reserved_domain_rejected(age_store.update_centroid)


def test_update_dk_weights_rejects_raw_reserved_domain(age_store: AGEGraphStore) -> None:
    _assert_raw_reserved_domain_rejected(age_store.update_dk_weights)


def test_update_conservation_state_rejects_raw_reserved_domain(age_store: AGEGraphStore) -> None:
    _assert_raw_reserved_domain_rejected(age_store.update_conservation_state)


def test_save_centroids_rejects_raw_reserved_domain(age_store: AGEGraphStore) -> None:
    _assert_raw_reserved_domain_rejected(age_store.save_centroids)


def test_save_evolution_event_rejects_raw_reserved_domain(age_store: AGEGraphStore) -> None:
    _assert_raw_reserved_domain_rejected(age_store.save_evolution_event)


def test_link_decision_to_entity_rejects_raw_reserved_domain(age_store: AGEGraphStore) -> None:
    _assert_raw_reserved_domain_rejected(age_store.link_decision_to_entity)


def test_prune_evolution_events_rejects_raw_reserved_domain(age_store: AGEGraphStore) -> None:
    _assert_raw_reserved_domain_rejected(age_store.prune_evolution_events)


def test_archive_old_decisions_rejects_raw_reserved_domain(age_store: AGEGraphStore) -> None:
    _assert_raw_reserved_domain_rejected(age_store.archive_old_decisions)


def test_archive_decisions_rejects_raw_reserved_domain(age_store: AGEGraphStore) -> None:
    _assert_raw_reserved_domain_rejected(age_store.archive_decisions)


def test_domain_scoped_reset_rejects_raw_reserved_domain(age_store: AGEGraphStore) -> None:
    _assert_raw_reserved_domain_rejected(age_store.domain_scoped_reset)


def test_write_entity_enrichment_rejects_raw_reserved_domain(age_store: AGEGraphStore) -> None:
    _assert_raw_reserved_domain_rejected(age_store.write_entity_enrichment)


def test_transaction_write_outcome_rejects_raw_reserved_domain() -> None:
    transaction, _ = _transaction_facade()
    with pytest.raises(ValueError, match="reserved"):
        transaction.write_outcome(domain="jmns__forged__domain")


def test_transaction_write_outcome_rejects_forged_subclass() -> None:
    transaction, _ = _transaction_facade()
    with pytest.raises(ValueError, match="reserved"):
        transaction.write_outcome(domain=_forged_reserved_domain())


def test_transaction_update_centroid_rejects_raw_reserved_domain() -> None:
    transaction, _ = _transaction_facade()
    with pytest.raises(ValueError, match="reserved"):
        transaction.update_centroid(domain="jmns__forged__domain")


def test_transaction_update_centroid_rejects_forged_subclass() -> None:
    transaction, _ = _transaction_facade()
    with pytest.raises(ValueError, match="reserved"):
        transaction.update_centroid(domain=_forged_reserved_domain())


def test_transaction_write_outcome_and_update_centroid_rejects_raw_reserved_domain() -> None:
    transaction, _ = _transaction_facade()
    with pytest.raises(ValueError, match="reserved"):
        transaction.write_outcome_and_update_centroid(domain="jmns__forged__domain")


def test_transaction_write_outcome_and_update_centroid_rejects_forged_subclass() -> None:
    transaction, _ = _transaction_facade()
    with pytest.raises(ValueError, match="reserved"):
        transaction.write_outcome_and_update_centroid(domain=_forged_reserved_domain())


def test_transaction_write_centroid_checkpoint_rejects_raw_reserved_domain() -> None:
    transaction, _ = _transaction_facade()
    with pytest.raises(ValueError, match="reserved"):
        transaction.write_centroid_checkpoint(domain="jmns__forged__domain")


def test_transaction_write_centroid_checkpoint_rejects_forged_subclass() -> None:
    transaction, _ = _transaction_facade()
    with pytest.raises(ValueError, match="reserved"):
        transaction.write_centroid_checkpoint(domain=_forged_reserved_domain())


def test_transaction_write_decision_allows_normal_domain() -> None:
    transaction, store = _transaction_facade()
    result = transaction.write_decision(domain="ordinary_domain")

    assert result == "decision-id"
    assert store.calls[0][0] == "write_decision"
    assert store.calls[0][1]["domain"] == "ordinary_domain"


def test_transaction_internal_namespace_passes_guard() -> None:
    transaction, store = _transaction_facade()
    domain = _InternalNamespace("jmns__x__y")

    transaction.update_centroid(domain=domain)

    assert store.calls[0][0] == "update_centroid"
    assert store.calls[0][1]["domain"] is domain
