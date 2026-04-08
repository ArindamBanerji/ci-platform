"""
ci_platform.graph — Shared graph client for all copilots.

Usage (SOC, S2P, any future copilot):
    from ci_platform.graph import get_graph_client
    graph = get_graph_client()
    results = await graph.run_query("MATCH (n:Alert) RETURN n", {})
"""
from ci_platform.graph.age_client import AGEClient, get_graph_client

__all__ = ["AGEClient", "get_graph_client"]
