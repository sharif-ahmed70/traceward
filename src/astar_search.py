"""A* Search module for TraceWard defensive attack path analysis.

Finds the lowest-cost (easiest) attack path across the enterprise network from an
untrusted entry point (e.g. INTERNET) to a critical asset (e.g. DB01).

Edge cost model (lower cost = easier for the attacker):

    ease(v)   = 0.5 * risk(v) + 0.5 * exploitability(v)          in [0, 1]
    c(u, v)   = base_cost(u, v) * (1.5 - ease(v))

  - base_cost(u, v): network accessibility of the hop, from data/network/network.json
  - risk(v): normalized KNN-predicted risk of the target system
  - exploitability(v): mean CVSS exploitation ease of the target's vulnerabilities
    (attack complexity, privileges required, user interaction, exploit probability)

Heuristic:

    h(n) = c_min * hops(n, goal)

  c_min is the cheapest edge cost in the graph and hops(n, goal) is the minimum number
  of hops from n to the goal (reverse BFS). Every remaining hop costs at least c_min,
  so h never overestimates (admissible), and h(n) <= c(n, n') + h(n') holds for every
  edge (consistent). Nodes that cannot reach the goal get h = inf and are pruned.
"""

import heapq
import json
import math
from collections import deque
from pathlib import Path
from src.graph_builder import build_graph

DEFAULT_BASE_COST = 2.0
DEFAULT_RISK = 0.5


def edge_ease(graph: dict, target: str) -> float:
    """Attacker ease of compromising `target` in [0, 1]."""
    risk = graph.get("risk_map", {}).get(target, DEFAULT_RISK)
    exploit = graph.get("exploit_map", {}).get(target)
    if exploit is None:
        return risk
    return 0.5 * risk + 0.5 * exploit


def edge_cost(graph: dict, source: str, target: str) -> float:
    """Attack cost of moving from `source` to `target`."""
    base = DEFAULT_BASE_COST
    for edge in graph.get("edges", []):
        if edge["source"] == source and edge["target"] == target:
            base = float(edge.get("base_cost", DEFAULT_BASE_COST))
            break
    return round(base * (1.5 - edge_ease(graph, target)), 2)


def _edge_cost_table(graph: dict) -> dict:
    adjacency = graph.get("adjacency", {})
    return {
        (u, v): edge_cost(graph, u, v)
        for u, neighbors in adjacency.items()
        for v in neighbors
    }


def hops_to_goal(graph: dict, goal: str) -> dict:
    """Minimum hop count from every node to `goal` (reverse BFS)."""
    reverse = {}
    for u, neighbors in graph.get("adjacency", {}).items():
        for v in neighbors:
            reverse.setdefault(v, []).append(u)

    hops = {goal: 0}
    queue = deque([goal])
    while queue:
        node = queue.popleft()
        for prev in reverse.get(node, []):
            if prev not in hops:
                hops[prev] = hops[node] + 1
                queue.append(prev)
    return hops


def make_heuristic(graph: dict, goal: str, costs: dict = None):
    """Build the admissible, consistent heuristic h(n) = c_min * hops(n, goal)."""
    costs = costs if costs is not None else _edge_cost_table(graph)
    c_min = min(costs.values()) if costs else 0.0
    hops = hops_to_goal(graph, goal)

    def h(node: str) -> float:
        if node not in hops:
            return math.inf
        return round(c_min * hops[node], 2)

    return h


def heuristic(node: str, goal: str, graph: dict = None) -> float:
    """Heuristic estimate of remaining attack cost from `node` to `goal`."""
    if node == goal:
        return 0.0
    if graph is None:
        return 0.0
    return make_heuristic(graph, goal)(node)


def _search(graph: dict, start: str, goal: str, h, algorithm: str) -> dict:
    """Best-first graph search ordered by f(n) = g(n) + h(n)."""
    adjacency = graph.get("adjacency", {})
    if start not in adjacency:
        raise ValueError(f"Start node '{start}' not in network graph.")

    costs = _edge_cost_table(graph)
    counter = 0  # tie-breaker keeps heap ordering deterministic
    h_start = h(start)
    open_list = [(h_start, 0.0, counter, start, [start])]
    best_g = {start: 0.0}
    closed = set()
    trace = []
    nodes_generated = 1

    while open_list:
        f_score, g_cost, _, current, path = heapq.heappop(open_list)
        if current in closed:
            continue

        trace.append({
            "step": len(trace) + 1,
            "node": current,
            "g": round(g_cost, 2),
            "h": h(current),
            "f": round(f_score, 2),
            "open_size": len(open_list),
        })

        if current == goal:
            hops = [
                {
                    "source": u,
                    "target": v,
                    "cost": costs[(u, v)],
                    "entry_vuln": graph.get("entry_vuln_map", {}).get(v, {}).get("vuln_id"),
                }
                for u, v in zip(path, path[1:])
            ]
            return {
                "algorithm": algorithm,
                "start": start,
                "goal": goal,
                "path": path,
                "total_cost": round(g_cost, 2),
                "hops": hops,
                "nodes_expanded": len(trace),
                "nodes_generated": nodes_generated,
                "trace": trace,
            }

        closed.add(current)
        for neighbor in adjacency.get(current, []):
            if neighbor in closed:
                continue
            h_n = h(neighbor)
            if math.isinf(h_n):
                continue  # cannot reach the goal from here
            new_g = round(g_cost + costs[(current, neighbor)], 2)
            if new_g < best_g.get(neighbor, math.inf):
                best_g[neighbor] = new_g
                counter += 1
                nodes_generated += 1
                heapq.heappush(open_list, (new_g + h_n, new_g, counter, neighbor, path + [neighbor]))

    raise ValueError(f"No attack path found from '{start}' to '{goal}'.")


def astar_search(graph: dict, start: str = "INTERNET", goal: str = "DB01") -> dict:
    """A* search with the admissible hop-based heuristic."""
    result = _search(graph, start, goal, make_heuristic(graph, goal), "A*")
    result["heuristic"] = "h(n) = c_min x hops(n, goal)"
    return result


def ucs_search(graph: dict, start: str = "INTERNET", goal: str = "DB01") -> dict:
    """Uniform Cost Search (A* with h = 0), the uninformed baseline."""
    result = _search(graph, start, goal, lambda n: 0.0, "Uniform Cost Search")
    result["heuristic"] = "h(n) = 0"
    return result


def bfs_search(graph: dict, start: str = "INTERNET", goal: str = "DB01") -> dict:
    """Breadth-First Search: fewest hops, ignoring attack cost."""
    adjacency = graph.get("adjacency", {})
    if start not in adjacency:
        raise ValueError(f"Start node '{start}' not in network graph.")

    queue = deque([[start]])
    visited = {start}
    expanded = 0
    while queue:
        path = queue.popleft()
        expanded += 1
        if path[-1] == goal:
            cost = sum(edge_cost(graph, u, v) for u, v in zip(path, path[1:]))
            return {
                "algorithm": "Breadth-First Search",
                "start": start,
                "goal": goal,
                "path": path,
                "total_cost": round(cost, 2),
                "nodes_expanded": expanded,
                "heuristic": "none (hop count)",
            }
        for neighbor in adjacency.get(path[-1], []):
            if neighbor not in visited:
                visited.add(neighbor)
                queue.append(path + [neighbor])

    raise ValueError(f"No attack path found from '{start}' to '{goal}'.")


def enumerate_attack_paths(graph: dict, start: str = "INTERNET", goal: str = "DB01") -> list:
    """All simple attack paths from start to goal, cheapest first (for verification)."""
    adjacency = graph.get("adjacency", {})
    paths = []

    def dfs(node, path):
        if node == goal:
            cost = sum(edge_cost(graph, u, v) for u, v in zip(path, path[1:]))
            paths.append({"path": list(path), "total_cost": round(cost, 2), "hops": len(path) - 1})
            return
        for neighbor in adjacency.get(node, []):
            if neighbor not in path:
                path.append(neighbor)
                dfs(neighbor, path)
                path.pop()

    dfs(start, [start])
    return sorted(paths, key=lambda p: (p["total_cost"], p["hops"]))


def compare_search_algorithms(graph: dict, start: str = "INTERNET", goal: str = "DB01") -> list:
    """Run A*, UCS and BFS on the same graph and summarize the results."""
    optimal = enumerate_attack_paths(graph, start, goal)[0]["total_cost"]
    rows = []
    for fn in (astar_search, ucs_search, bfs_search):
        res = fn(graph, start, goal)
        rows.append({
            "algorithm": res["algorithm"],
            "path": " -> ".join(res["path"]),
            "total_cost": res["total_cost"],
            "hops": len(res["path"]) - 1,
            "nodes_expanded": res["nodes_expanded"],
            "optimal": math.isclose(res["total_cost"], optimal),
        })
    return rows


def run_astar(
    graph=None,
    start="INTERNET",
    goal="DB01",
    output_path="artifacts/astar/attack_path.json",
):
    """Run A* search and export the attack path (with search trace) to JSON."""
    if graph is None:
        graph = build_graph()

    result = astar_search(graph, start=start, goal=goal)
    result["alternative_paths"] = enumerate_attack_paths(graph, start, goal)
    result["comparison"] = compare_search_algorithms(graph, start, goal)

    out_file = Path(output_path)
    out_file.parent.mkdir(parents=True, exist_ok=True)
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)

    return result


if __name__ == "__main__":
    path_result = run_astar()
    print(f"Attack path found: {' -> '.join(path_result['path'])} (Cost: {path_result['total_cost']})")
    for row in path_result["comparison"]:
        print(f"  {row['algorithm']:<22} cost={row['total_cost']:<6} expanded={row['nodes_expanded']}")
