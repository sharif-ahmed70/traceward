"""FinBank network topology loader and validator.

Provides a compatibility shim around the existing TraceWard graph conventions
so the FinBank environment can construct risk-weighted graphs without
modifying the core A* module.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pandas as pd

from src.finbank_env import load_finbank_systems, validate_finbank_systems


REQUIRED_NODE_FIELDS = {
    "id",
    "name",
    "type",
    "criticality",
    "internet_exposed",
}

REQUIRED_EDGE_FIELDS = {
    "source",
    "target",
    "base_cost",
}

EXPECTED_EDGES = (
    ("INTERNET", "WEB01"),
    ("INTERNET", "VPN01"),
    ("WEB01", "APP01"),
    ("APP01", "AUTH01"),
    ("APP01", "DB01"),
    ("VPN01", "AUTH01"),
    ("AUTH01", "APP01"),
    ("EMP01", "AUTH01"),
    ("DB01", "BACKUP01"),
)

EXPECTED_NODE_IDS = (
    "INTERNET",
    "WEB01",
    "APP01",
    "AUTH01",
    "VPN01",
    "EMP01",
    "DB01",
    "BACKUP01",
)


def _load_finbank_network(path: str | Path = "data/finbank/network.json") -> dict[str, Any]:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"FinBank network file not found: {path}")
    with open(p, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError("FinBank network JSON must be a JSON object.")
    if "nodes" not in data or "edges" not in data:
        raise ValueError("FinBank network JSON must contain 'nodes' and 'edges' lists.")
    return data


def _validate_nodes(nodes: list[dict[str, Any]]) -> None:
    if not isinstance(nodes, list):
        raise ValueError("'nodes' must be a list.")
    if len(nodes) == 0:
        raise ValueError("'nodes' list is empty.")
    node_ids = []
    for node in nodes:
        if not isinstance(node, dict):
            raise ValueError("Each node must be a JSON object.")
        missing = REQUIRED_NODE_FIELDS - set(node.keys())
        if missing:
            raise ValueError(f"Node missing required fields: {sorted(missing)}")
        node_ids.append(str(node["id"]))
    unique_ids = set(node_ids)
    if len(node_ids) != len(unique_ids):
        raise ValueError("Duplicate node IDs found in FinBank network.")


def _validate_edges(edges: list[dict[str, Any]], node_ids: set[str]) -> None:
    if not isinstance(edges, list):
        raise ValueError("'edges' must be a list.")
    seen_edges: set[tuple[str, str]] = set()
    for edge in edges:
        if not isinstance(edge, dict):
            raise ValueError("Each edge must be a JSON object.")
        missing = REQUIRED_EDGE_FIELDS - set(edge.keys())
        if missing:
            raise ValueError(f"Edge missing required fields: {sorted(missing)}")
        src = str(edge["source"])
        tgt = str(edge["target"])
        if src not in node_ids:
            raise ValueError(f"Edge source '{src}' is not a defined node.")
        if tgt not in node_ids:
            raise ValueError(f"Edge target '{tgt}' is not a defined node.")
        edge_key = (src, tgt)
        if edge_key in seen_edges:
            raise ValueError(f"Duplicate directed edge found: {src} -> {tgt}")
        seen_edges.add(edge_key)


def validate_finbank_network(path: str | Path = "data/finbank/network.json") -> dict[str, Any]:
    data = _load_finbank_network(path)
    _validate_nodes(data["nodes"])
    _validate_edges(data["edges"], {str(node["id"]) for node in data["nodes"]})
    return data


def load_finbank_network(path: str | Path = "data/finbank/network.json") -> dict[str, Any]:
    return _load_finbank_network(path)


def build_finbank_graph(
    network_path: str | Path = "data/finbank/network.json",
    risk_summary_path: str | Path | None = None,
) -> dict[str, Any]:
    """Construct a risk-weighted FinBank graph compatible with TraceWard A*.

    Returns a dict with the same keys as TraceWard's build_graph():
      - nodes
      - edges
      - adjacency
      - risk_map

    This allows astar_search.astar_search() to operate on FinBank data
    without modification.
    """
    data = validate_finbank_network(network_path)
    nodes = data["nodes"]
    edges = data["edges"]

    adjacency: dict[str, list[str]] = {str(node["id"]): [] for node in nodes}
    for edge in edges:
        src = str(edge["source"])
        tgt = str(edge["target"])
        if src in adjacency:
            adjacency[src].append(tgt)

    annotated_nodes = []
    for node in nodes:
        annotated_nodes.append({
            "id": str(node["id"]),
            "name": str(node["name"]),
            "type": str(node["type"]),
            "criticality": int(node["criticality"]),
            "internet_exposed": bool(node["internet_exposed"]),
        })

    risk_map: dict[str, float] = {}
    if risk_summary_path is not None:
        p = Path(risk_summary_path)
        if p.exists():
            risk_df = pd.read_csv(p)
            for _, row in risk_df.iterrows():
                risk_map[str(row["system_id"])] = float(row.get("normalized_risk", 0.5))

    return {
        "nodes": annotated_nodes,
        "edges": edges,
        "adjacency": adjacency,
        "risk_map": risk_map,
    }


def get_finbank_edge_count(path: str | Path = "data/finbank/network.json") -> int:
    data = validate_finbank_network(path)
    return len(data["edges"])


def get_finbank_node_count(path: str | Path = "data/finbank/network.json") -> int:
    data = validate_finbank_network(path)
    return len(data["nodes"])
