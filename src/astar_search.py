"""A* search algorithm to find the most concerning attack paths in the network graph."""
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
    # Zero heuristic guarantees finding the shortest cost path (Dijkstra behavior),
    # admissible for all graph configurations.
    return 0.0 if node == goal else 1.0


def astar_search(graph: dict, start: str = "INTERNET", goal: str = "DB01") -> dict:
    """Execute A* search over the risk-weighted topology graph.

    Lower traversal cost corresponds to higher vulnerability exposure / lower defensive resistance.
    """
    adjacency = graph.get("adjacency", {})
    risk_map = graph.get("risk_map", {})

    if start not in adjacency:
        raise ValueError(f"Start node '{start}' not in network graph.")

    # Priority queue stores tuples of: (f_score, current_cost, current_node, path)
    queue = [(heuristic(start, goal), 0.0, start, [start])]
    visited = set()

    while queue:
        f_score, g_cost, current, path = heapq.heappop(queue)

        if current == goal:
            return {
                "start": start,
                "goal": goal,
                "path": path,
                "total_cost": round(g_cost, 2),
            }

        if current in visited:
            continue
        visited.add(current)

        for neighbor in adjacency.get(current, []):
            if neighbor not in visited:
                # Traversal cost: baseline step cost (1.0) adjusted by neighbor risk
                neighbor_risk = risk_map.get(neighbor, 0.5)
                # Higher risk -> easier path for adversary (lower defensive resistance)
                step_cost = max(0.5, round(2.0 - neighbor_risk, 2))
                new_g = g_cost + step_cost
                new_f = new_g + heuristic(neighbor, goal)
                heapq.heappush(queue, (new_f, new_g, neighbor, path + [neighbor]))

    raise ValueError(f"No attack path found from '{start}' to '{goal}'.")


def run_astar(
    graph=None,
    start="INTERNET",
    goal="DB01",
    output_path="artifacts/astar/attack_path.json",
):
    """Run A* search and export the attack path to JSON."""
    if graph is None:
        graph = build_graph()

    result = astar_search(graph, start=start, goal=goal)

    out_file = Path(output_path)
    out_file.parent.mkdir(parents=True, exist_ok=True)
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)

    return result


if __name__ == "__main__":
    path_result = run_astar()
    print(f"Attack path found: {' -> '.join(path_result['path'])} (Cost: {path_result['total_cost']})")
