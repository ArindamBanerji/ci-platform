"""
ci_platform.graph — Shared graph client for all copilots.

Usage (SOC, S2P, any future copilot):
    from ci_platform.graph import get_graph_client
    graph = get_graph_client()
    results = await graph.run_query("MATCH (n:Alert) RETURN n", {})
"""
from ci_platform.graph.age_client import (
    AGEClient,
    close_all_graph_clients,
    get_graph_client,
    reset_graph_client,
    reset_graph_clients,
)
from ci_platform.graph.age_graph_store import AGEGraphStore
from ci_platform.graph.age_sdk_adapter import AGEGraphStoreAdapter

__all__ = [
    "AGEClient",
    "AGEGraphStore",
    "AGEGraphStoreAdapter",
    "close_all_graph_clients",
    "get_graph_client",
    "reset_graph_client",
    "reset_graph_clients",
]
