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
from src.astar_search import astar_search


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


if __name__ == "__main__":
    print("Testing What-If Patch Simulation on WEB01...")
    res = simulate_patch_impact("WEB01", risk_reduction_factor=0.5)
    print("Explanation:", res["explanation"])
    print("Baseline Cost:", res["baseline"]["path_cost"], "-> Simulated Cost:", res["simulated"]["path_cost"])
    print("Cost Delta (Defensive Gain):", res["deltas"]["path_cost_increase"])
