"""What-If Scenario Simulation module for TraceWard defensive risk forecasting.

Applies simulated remediation (patching) effects to isolated copies of the
baseline system risk and network graph, recomputes risk-aware A* attack paths,
and measures before/after security improvements without modifying baseline data.
Network connectivity is preserved (no edges are artificially severed).
"""

from __future__ import annotations

import copy
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.graph_builder import build_graph
from src.astar_search import astar_search, enumerate_attack_paths


def simulate_patch_impact(
    target_system: str,
    baseline_risk_df: Optional[pd.DataFrame] = None,
    baseline_graph: Optional[Dict[str, Any]] = None,
    risk_reduction_factor: float = 0.5,
    start_node: str = "INTERNET",
    goal_node: str = "DB01",
) -> Dict[str, Any]:
    """Simulate applying a security patch to a specific enterprise system.

    Evaluates the security impact on:
      1. Target system normalized risk score.
      2. Adversary traversal cost and attack path via risk-aware A* search.

    Crucially:
      - All calculations operate on deep copies; baseline data remains unmodified.
      - Network connectivity is preserved; hardening increases defensive traversal resistance
        rather than severing network topology.

    Args:
        target_system: System identifier to simulate patching (e.g. 'WEB01', 'APP01', 'DB01').
        baseline_risk_df: DataFrame of system risk summaries (loaded from disk if None).
        baseline_graph: Network graph dict (built from topology if None).
        risk_reduction_factor: Proportional reduction in risk (0.0 to 1.0, default 0.5 = 50% risk drop).
        start_node: Entry node for attack path search.
        goal_node: Crown-jewel target node for attack path search.

    Returns:
        dict containing baseline vs. simulated metrics, path comparison, and defense delta.
    """
    # 1. Load or copy baseline risk DataFrame
    if baseline_risk_df is None:
        risk_path = Path("artifacts/risk/system_risk_summary.csv")
        if not risk_path.exists():
            raise FileNotFoundError(f"Baseline risk summary not found at {risk_path}")
        risk_df = pd.read_csv(risk_path)
    else:
        risk_df = baseline_risk_df.copy(deep=True)

    # 2. Load or copy baseline graph
    if baseline_graph is None:
        graph = build_graph()
    else:
        graph = copy.deepcopy(baseline_graph)

    # Verify target system exists in baseline
    if target_system not in risk_df["system_id"].values:
        raise ValueError(f"Target system '{target_system}' not found in system risk summary.")

    # 3. Compute baseline attack path
    baseline_path_result = astar_search(graph, start=start_node, goal=goal_node)

    # 4. Extract baseline metrics for the target system
    target_row = risk_df.loc[risk_df["system_id"] == target_system].iloc[0]
    base_normalized_risk = float(target_row["normalized_risk"])
    base_avg_risk = float(target_row["average_risk_score"])
    base_highest_risk = str(target_row["highest_risk"])

    # 5. Create simulated copy and apply documented patch effect
    sim_risk_df = risk_df.copy(deep=True)
    # Patch effect: reduces normalized risk proportionally, bounded by minimum base risk 0.25
    sim_normalized_risk = max(0.25, round(base_normalized_risk * (1.0 - risk_reduction_factor), 3))
    sim_avg_risk = max(1.0, round(base_avg_risk * (1.0 - risk_reduction_factor), 3))
    sim_highest_risk = "Medium" if base_highest_risk == "Critical" else (
        "Low" if base_highest_risk in ("High", "Medium") else "Low"
    )

    # Update simulated DataFrame row
    idx = sim_risk_df.index[sim_risk_df["system_id"] == target_system].tolist()[0]
    sim_risk_df.at[idx, "normalized_risk"] = sim_normalized_risk
    sim_risk_df.at[idx, "average_risk_score"] = sim_avg_risk
    sim_risk_df.at[idx, "highest_risk"] = sim_highest_risk

    # 6. Update simulated graph copy (preserve all edges and adjacency)
    sim_graph = copy.deepcopy(graph)
    sim_graph["risk_map"][target_system] = sim_normalized_risk
    # A patch also removes exploitable weaknesses, lowering attacker ease on that host.
    exploit_map = sim_graph.get("exploit_map", {})
    if target_system in exploit_map:
        exploit_map[target_system] = round(exploit_map[target_system] * (1.0 - risk_reduction_factor), 3)
    for node in sim_graph["nodes"]:
        if node["id"] == target_system:
            node["risk_score"] = sim_normalized_risk

    # 7. Recompute A* search on the simulated graph
    sim_path_result = astar_search(sim_graph, start=start_node, goal=goal_node)

    # 8. Compute security improvement deltas
    risk_delta = round(base_normalized_risk - sim_normalized_risk, 3)
    cost_delta = round(sim_path_result["total_cost"] - baseline_path_result["total_cost"], 2)
    path_changed = baseline_path_result["path"] != sim_path_result["path"]

    # 9. Build descriptive explanation
    on_baseline_path = target_system in baseline_path_result["path"]
    if on_baseline_path:
        if path_changed:
            impact_summary = (
                f"Patching {target_system} increased defensive resistance along the primary attack path, "
                f"forcing the adversary onto an alternate route ({' -> '.join(sim_path_result['path'])}) "
                 f"with an increased traversal cost of +{cost_delta:.2f}."
            )
        else:
            impact_summary = (
                f"Patching {target_system} hardened the node on the active attack path, "
                f"increasing adversary traversal cost by +{cost_delta:.2f} (from {baseline_path_result['total_cost']} "
                f"to {sim_path_result['total_cost']})."
            )
    else:
        impact_summary = (
            f"Patching {target_system} reduced its individual system risk by {risk_delta:.3f}, "
            f"but {target_system} was not on the critical attack path from {start_node} to {goal_node}. "
            f"Path cost remains {baseline_path_result['total_cost']}."
        )

    return {
        "status": "success",
        "target_system": target_system,
        "risk_reduction_factor": risk_reduction_factor,
        "baseline": {
            "system_risk": {
                "system_id": target_system,
                "normalized_risk": base_normalized_risk,
                "average_risk_score": base_avg_risk,
                "highest_risk": base_highest_risk,
            },
            "attack_path": baseline_path_result["path"],
            "path_cost": baseline_path_result["total_cost"],
        },
        "simulated": {
            "system_risk": {
                "system_id": target_system,
                "normalized_risk": sim_normalized_risk,
                "average_risk_score": sim_avg_risk,
                "highest_risk": sim_highest_risk,
            },
            "attack_path": sim_path_result["path"],
            "path_cost": sim_path_result["total_cost"],
        },
        "deltas": {
            "risk_reduction": risk_delta,
            "path_cost_increase": cost_delta,
            "path_diverted": path_changed,
            "target_was_on_path": on_baseline_path,
        },
        "explanation": impact_summary,
        "simulated_risk_df": sim_risk_df,
    }



# ---------------------------------------------------------------------------
# Security action simulator: patch weaknesses, cut connections, isolate hosts
# ---------------------------------------------------------------------------

def _node_name(graph: Dict[str, Any], node_id: str) -> str:
    for node in graph.get("nodes", []):
        if node["id"] == node_id:
            return node.get("name", node_id)
    return node_id


def _describe_path(graph: Dict[str, Any], path) -> str:
    return " → ".join(_node_name(graph, n) for n in path)


def apply_actions(graph: Dict[str, Any], actions) -> Dict[str, Any]:
    """Return a deep copy of `graph` with the security actions applied.

    Supported actions:
      {"type": "patch",   "system": "WEB01", "vuln_ids": ["V0036", ...]}
      {"type": "block",   "source": "WEB01", "target": "APP01"}
      {"type": "isolate", "system": "APP01"}

    Patching removes the listed vulnerabilities: the host's exploitability is recomputed
    from the remaining ones, and its predicted risk shrinks in proportion to the
    vulnerabilities removed. A fully patched host keeps a residual risk of 0.05.
    """
    sim = copy.deepcopy(graph)
    adjacency = sim["adjacency"]

    for action in actions:
        kind = action["type"]
        if kind == "patch":
            system = action["system"]
            eases = sim.get("vuln_ease_map", {}).get(system, {})
            total = len(eases)
            for vid in action.get("vuln_ids", []):
                eases.pop(vid, None)
            if total:
                remaining = len(eases)
                sim.setdefault("exploit_map", {})[system] = (
                    round(sum(eases.values()) / remaining, 3) if remaining else 0.0
                )
                base_risk = sim.get("risk_map", {}).get(system, 0.5)
                sim.setdefault("risk_map", {})[system] = round(max(0.05, base_risk * remaining / total), 3)
        elif kind == "block":
            src, dst = action["source"], action["target"]
            if dst in adjacency.get(src, []):
                adjacency[src].remove(dst)
            sim["edges"] = [e for e in sim["edges"] if not (e["source"] == src and e["target"] == dst)]
        elif kind == "isolate":
            system = action["system"]
            adjacency[system] = []
            for neighbors in adjacency.values():
                if system in neighbors:
                    neighbors.remove(system)
            sim["edges"] = [e for e in sim["edges"] if system not in (e["source"], e["target"])]
        else:
            raise ValueError(f"Unknown action type: {kind}")
    return sim


def describe_action(graph: Dict[str, Any], action: Dict[str, Any]) -> str:
    """Plain-language description of one action."""
    kind = action["type"]
    if kind == "patch":
        count = len(action.get("vuln_ids", []))
        total = len(graph.get("vuln_ease_map", {}).get(action["system"], {}))
        return f"Fix {count} of {total} weaknesses on the {_node_name(graph, action['system'])}"
    if kind == "block":
        return (f"Cut the connection from the {_node_name(graph, action['source'])} "
                f"to the {_node_name(graph, action['target'])}")
    return f"Disconnect the {_node_name(graph, action['system'])} from the network"


def _try_path(graph, start, goal):
    try:
        return astar_search(graph, start=start, goal=goal)
    except ValueError:
        return None


def find_chokepoints(graph: Dict[str, Any], start: str = "INTERNET", goal: str = "DB01") -> Dict[str, list]:
    """Hosts and connections that every attack path must pass through.

    Removing any one of them leaves the attacker with no route to the goal.
    """
    if _try_path(graph, start, goal) is None:
        return {"hosts": [], "connections": []}
    hosts = [
        node for node in graph["adjacency"]
        if node not in (start, goal)
        and _try_path(apply_actions(graph, [{"type": "isolate", "system": node}]), start, goal) is None
    ]
    connections = [
        (u, v) for u, neighbors in graph["adjacency"].items() for v in neighbors
        if _try_path(apply_actions(graph, [{"type": "block", "source": u, "target": v}]), start, goal) is None
    ]
    return {"hosts": hosts, "connections": connections}


def simulate_actions(
    actions,
    graph: Optional[Dict[str, Any]] = None,
    start: str = "INTERNET",
    goal: str = "DB01",
) -> Dict[str, Any]:
    """Re-run A* after a set of security actions and explain the outcome in plain language.

    Outcome is one of:
      - "blocked":   no attack path to the goal remains
      - "rerouted":  the attacker must switch to a different path
      - "harder":    same path, but it costs the attacker more effort
      - "unchanged": the actions do not affect the easiest attack path
    """
    graph = graph if graph is not None else build_graph()
    baseline = astar_search(graph, start=start, goal=goal)
    sim_graph = apply_actions(graph, actions)
    simulated = _try_path(sim_graph, start, goal)
    goal_name = _node_name(graph, goal)

    if simulated is None:
        outcome = "blocked"
        effort_change = None
        headline = f"Attack blocked: the attacker can no longer reach the {goal_name}."
        explanation = (
            "After these actions there is no route left from the internet to the "
            f"{goal_name}. Every possible path has been cut off."
        )
    else:
        effort_change = round(
            (simulated["total_cost"] - baseline["total_cost"]) / baseline["total_cost"] * 100, 1
        )
        if simulated["path"] != baseline["path"]:
            outcome = "rerouted"
            headline = f"The attacker found another way in (+{effort_change}% effort)."
            explanation = (
                "The original route is closed, but the attacker can still reach the "
                f"{goal_name} through: {_describe_path(graph, simulated['path'])}."
            )
        elif effort_change > 0:
            outcome = "harder"
            headline = f"Same route, but {effort_change}% harder for the attacker."
            explanation = (
                "The attacker still uses the same route, but it now takes more effort. "
                "This slows an attack down without stopping it."
            )
        else:
            outcome = "unchanged"
            headline = "No change: the easiest attack route is not affected."
            explanation = "These actions do not touch the route the attacker is most likely to use."

    return {
        "outcome": outcome,
        "headline": headline,
        "explanation": explanation,
        "actions": [describe_action(graph, a) for a in actions],
        "baseline": {
            "path": baseline["path"],
            "path_names": _describe_path(graph, baseline["path"]),
            "cost": baseline["total_cost"],
        },
        "simulated": {
            "path": simulated["path"] if simulated else None,
            "path_names": _describe_path(graph, simulated["path"]) if simulated else None,
            "cost": simulated["total_cost"] if simulated else None,
        },
        "effort_change_pct": effort_change,
        "routes_before": len(enumerate_attack_paths(graph, start, goal)),
        "routes_after": len(enumerate_attack_paths(sim_graph, start, goal)),
        "sim_graph": sim_graph,
    }

if __name__ == "__main__":
    print("Testing What-If Patch Simulation on WEB01...")
    res = simulate_patch_impact("WEB01", risk_reduction_factor=0.5)
    print("Explanation:", res["explanation"])
    print("Baseline Cost:", res["baseline"]["path_cost"], "-> Simulated Cost:", res["simulated"]["path_cost"])
    print("Cost Delta (Defensive Gain):", res["deltas"]["path_cost_increase"])
