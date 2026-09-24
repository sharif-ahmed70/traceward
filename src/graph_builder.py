"""Graph Builder module for TraceWard network topology and risk overlay.

Parses data/network/network.json and overlays system-level risk metrics
to prepare an annotated directed graph for A* attack path detection.
"""

import json
from pathlib import Path
import pandas as pd


def load_network_topology(network_path="data/network/network.json"):
    """Load network nodes and edges from network.json."""
    path = Path(network_path)
    if not path.exists():
        raise FileNotFoundError(f"Network file not found: {network_path}")

    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    return data.get("nodes", []), data.get("edges", [])


def build_graph(
    network_path="data/network/network.json",
    risk_summary_path="artifacts/risk/system_risk_summary.csv",
):
    """Construct an annotated directed graph from network topology and risk metrics.

    Returns:
        dict containing:
          - nodes: list of node dicts with attached risk metrics
          - edges: list of edge dicts (source, target, weight)
          - adjacency: dict mapping node_id -> list of neighboring node_ids
          - risk_map: dict mapping system_id -> normalized_risk score
    """
    nodes, edges = load_network_topology(network_path)

    # Load system risk metrics if available
    risk_map = {}
    risk_file = Path(risk_summary_path)
    if risk_file.exists():
        risk_df = pd.read_csv(risk_file)
        for _, row in risk_df.iterrows():
            risk_map[row["system_id"]] = float(row.get("normalized_risk", 0.5))

    # Build adjacency list
    adjacency = {node["id"]: [] for node in nodes}
    for edge in edges:
        src = edge["source"]
        dst = edge["target"]
        if src in adjacency:
            adjacency[src].append(dst)

    # Annotate nodes
    annotated_nodes = []
    for node in nodes:
        node_id = node["id"]
        node_risk = risk_map.get(node_id, 0.25)
        annotated_nodes.append({
            **node,
            "risk_score": node_risk,
        })

    return {
        "nodes": annotated_nodes,
        "edges": edges,
        "adjacency": adjacency,
        "risk_map": risk_map,
    }


if __name__ == "__main__":
    graph = build_graph()
    print(f"Graph constructed: {len(graph['nodes'])} nodes, {len(graph['edges'])} edges.")
