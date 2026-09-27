"""Graph Builder module for TraceWard network topology and risk overlay.

Parses data/network/network.json and overlays system-level risk metrics
to prepare an annotated directed graph for A* attack path detection.
"""

import csv
import json
from pathlib import Path

RISK_LABEL_SCORES = {
    "Low": 0.25,
    "Medium": 0.50,
    "High": 0.75,
    "Critical": 1.00,
}


def load_network_topology(network_path="data/network/network.json"):
    """Load network nodes and edges from network.json."""
    path = Path(network_path)
    if not path.exists():
        raise FileNotFoundError(f"Network file not found: {network_path}")

    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    nodes = data.get("nodes", [])
    edges = data.get("edges", [])
    if not nodes:
        raise ValueError("Network topology must contain at least one node.")

    return nodes, edges


def load_system_risk_map(risk_summary_path="artifacts/risk/system_risk_summary.csv"):
    """Load system-level risk metrics keyed by system_id."""
    risk_map = {}
    risk_details = {}
    risk_file = Path(risk_summary_path)

    if not risk_file.exists():
        return risk_map, risk_details

    with open(risk_file, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            sys_id = (row.get("system_id") or "").strip()
            if not sys_id:
                continue

            norm_val = row.get("normalized_risk")
            if norm_val not in (None, ""):
                score = float(norm_val)
            else:
                label = (row.get("highest_risk") or row.get("predicted_risk") or "Medium").strip().capitalize()
                score = RISK_LABEL_SCORES.get(label, 0.50)

            score = max(0.25, min(1.0, round(score, 4)))
            risk_map[sys_id] = score
            risk_details[sys_id] = {
                "normalized_risk": score,
                "highest_risk": row.get("highest_risk", "Medium"),
                "vulnerability_count": int(float(row.get("vulnerability_count", 0) or 0)),
            }

    return risk_map, risk_details


def build_graph(
    network_path="data/network/network.json",
    risk_summary_path="artifacts/risk/system_risk_summary.csv",
):
    """Construct an annotated directed graph from network topology and risk metrics."""
    nodes, edges = load_network_topology(network_path)
    risk_map, risk_details = load_system_risk_map(risk_summary_path)

    node_ids = {node["id"] for node in nodes if "id" in node}
    adjacency = {node["id"]: [] for node in nodes}

    annotated_nodes = []
    for node in nodes:
        node_id = node["id"]
        default_risk = 0.25 if node_id == "INTERNET" else round(min(1.0, max(0.25, node.get("criticality", 2) * 0.15)), 2)
        node_risk = risk_map.get(node_id, default_risk)
        risk_map.setdefault(node_id, node_risk)
        details = risk_details.get(node_id, {})

        annotated_nodes.append({
            **node,
            "risk_score": node_risk,
            "highest_risk": details.get("highest_risk", "Low" if node_id == "INTERNET" else "Medium"),
            "vulnerability_count": details.get("vulnerability_count", 0),
        })

    annotated_edges = []
    edge_weights = {}
    for edge in edges:
        src = edge["source"]
        dst = edge["target"]
        if src not in node_ids or dst not in node_ids:
            raise ValueError(f"Edge references unknown system_id: {src} -> {dst}")

        adjacency[src].append(dst)
        base_cost = float(edge.get("base_cost", 1.0))
        target_risk = risk_map.get(dst, 0.5)
        weight = max(0.5, round(base_cost * (1.25 - 0.5 * target_risk), 2))

        annotated_edge = {
            **edge,
            "base_cost": base_cost,
            "weight": weight,
        }
        annotated_edges.append(annotated_edge)
        edge_weights[(src, dst)] = weight

    return {
        "nodes": annotated_nodes,
        "edges": annotated_edges,
        "adjacency": adjacency,
        "edge_weights": edge_weights,
        "risk_map": risk_map,
    }


if __name__ == "__main__":
    graph = build_graph()
    print(f"Graph constructed: {len(graph['nodes'])} nodes, {len(graph['edges'])} edges.")
