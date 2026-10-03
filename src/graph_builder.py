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


def vulnerability_ease(row):
    """Exploitation ease of one encoded vulnerability in [0, 1] (1 = trivial to exploit).

    Averages the four attacker-side CVSS factors: low attack complexity, no privileges
    required, no user interaction, and high exploit probability.
    """
    return (
        (1 - row["attack_complexity"])
        + (1 - row["privileges_required"] / 2)
        + (1 - row["user_interaction"])
        + row["exploit_probability"]
    ) / 4


def load_exploitability(vulns_path="data/processed/vulnerabilities_processed.csv"):
    """Return per-system exploitability metrics from the encoded vulnerability inventory.

    Returns:
        (exploit_map, entry_vuln_map):
          - exploit_map: system_id -> mean exploitation ease of its vulnerabilities
          - entry_vuln_map: system_id -> details of the easiest vulnerability on that system
    """
    path = Path(vulns_path)
    if not path.exists():
        return {}, {}

    df = pd.read_csv(path)
    df["ease"] = df.apply(vulnerability_ease, axis=1)

    exploit_map = {}
    entry_vuln_map = {}
    for system_id, group in df.groupby("system_id"):
        exploit_map[system_id] = round(float(group["ease"].mean()), 3)
        best = group.sort_values(["ease", "vuln_id"], ascending=[False, True]).iloc[0]
        entry_vuln_map[system_id] = {
            "vuln_id": best["vuln_id"],
            "ease": round(float(best["ease"]), 3),
            "exploit_probability": float(best["exploit_probability"]),
        }
    return exploit_map, entry_vuln_map


def build_graph(
    network_path="data/network/network.json",
    risk_summary_path="artifacts/risk/system_risk_summary.csv",
    vulns_path="data/processed/vulnerabilities_processed.csv",
):
    """Construct an annotated directed graph from network topology and risk metrics.

    Returns:
        dict containing:
          - nodes: list of node dicts with attached risk metrics
          - edges: list of edge dicts (source, target, base_cost)
          - adjacency: dict mapping node_id -> list of neighboring node_ids
          - risk_map: dict mapping system_id -> normalized_risk score (from KNN predictions)
          - exploit_map: dict mapping system_id -> mean CVSS exploitation ease
          - entry_vuln_map: dict mapping system_id -> easiest vulnerability on that system
    """
    nodes, edges = load_network_topology(network_path)
    exploit_map, entry_vuln_map = load_exploitability(vulns_path)

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
            "exploitability": exploit_map.get(node_id),
        })

    return {
        "nodes": annotated_nodes,
        "edges": edges,
        "adjacency": adjacency,
        "risk_map": risk_map,
        "exploit_map": exploit_map,
        "entry_vuln_map": entry_vuln_map,
    }


if __name__ == "__main__":
    graph = build_graph()
    print(f"Graph constructed: {len(graph['nodes'])} nodes, {len(graph['edges'])} edges.")
