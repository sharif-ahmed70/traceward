"""A* Search module for TraceWard defensive attack path analysis.

Finds the critical vulnerability traversal path across the enterprise network
from an untrusted entry point (e.g. INTERNET) to internal assets (e.g. DB01).
"""

import heapq
import json
from pathlib import Path
from src.graph_builder import build_graph


def heuristic(node: str, goal: str) -> float:
    """Admissible heuristic estimate to goal node."""
    return 0.0 if node == goal else 0.5


def astar_search(graph: dict, start: str = "INTERNET", goal: str = "DB01") -> dict:
    """Execute A* search over the risk-weighted topology graph."""
    adjacency = graph.get("adjacency", {})
    risk_map = graph.get("risk_map", {})
    edge_weights = graph.get("edge_weights", {})

    if start not in adjacency:
        raise ValueError(f"Start node '{start}' not in network graph.")
    if goal not in adjacency:
        raise ValueError(f"Goal node '{goal}' not in network graph.")

    queue = [(heuristic(start, goal), 0.0, start, [start])]
    best_g = {start: 0.0}

    while queue:
        f_score, g_cost, current, path = heapq.heappop(queue)

        if current == goal:
            return {
                "start": start,
                "goal": goal,
                "path": path,
                "total_cost": round(g_cost, 2),
            }

        if g_cost > best_g.get(current, float("inf")):
            continue

        for neighbor in adjacency.get(current, []):
            if (current, neighbor) in edge_weights:
                step_cost = float(edge_weights[(current, neighbor)])
            else:
                neighbor_risk = risk_map.get(neighbor, 0.5)
                step_cost = max(0.5, round(2.0 - neighbor_risk, 2))

            new_g = round(g_cost + step_cost, 4)
            if new_g < best_g.get(neighbor, float("inf")):
                best_g[neighbor] = new_g
                new_f = new_g + heuristic(neighbor, goal)
                heapq.heappush(queue, (new_f, new_g, neighbor, path + [neighbor]))

    raise ValueError(f"No attack path found from '{start}' to '{goal}'.")


def run_astar(
    graph=None,
    start="INTERNET",
    goal="DB01",
    output_path="artifacts/astar/attack_path.json",
    network_path="data/network/network.json",
    risk_summary_path="artifacts/risk/system_risk_summary.csv",
):
    """Run A* search and export the attack path to JSON."""
    if graph is None:
        graph = build_graph(
            network_path=network_path,
            risk_summary_path=risk_summary_path,
        )

    result = astar_search(graph, start=start, goal=goal)

    out_file = Path(output_path)
    out_file.parent.mkdir(parents=True, exist_ok=True)
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)

    return result


if __name__ == "__main__":
    path_result = run_astar()
    print(f"Attack path found: {' -> '.join(path_result['path'])} (Cost: {path_result['total_cost']})")
