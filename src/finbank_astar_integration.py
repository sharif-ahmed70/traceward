"""FinBank attack scenario integration with TraceWard A* path analysis.

For each simulated FinBank incident:
  1. Identify the entry point.
  2. Identify the target critical asset.
  3. Build the FinBank graph.
  4. Run the existing A* path calculation.
  5. Return the simulated attack path.
  6. Identify the systems and vulnerabilities along that path.

All returned paths are labeled as simulated attack paths or risk-weighted
attack paths. This module performs no real attack detection.
"""

from __future__ import annotations

from typing import Any, Optional

from src.astar_search import astar_search
from src.finbank_network import build_finbank_graph
from src.finbank_env import get_finbank_system
from src.attack_simulator.scenarios import (
    AttackScenario,
    get_finbank_scenario,
)


def run_scenario_attack_path(
    scenario_id: str,
    graph: Optional[dict[str, Any]] = None,
    start: Optional[str] = None,
    goal: Optional[str] = None,
    include_vulnerabilities: bool = False,
    inventory: Optional[Any] = None,
) -> dict[str, Any]:
    """Run A* attack path analysis for a single FinBank scenario.

    Args:
        scenario_id: The FinBank scenario identifier.
        graph: Pre-built graph dict. Built from FinBank data if None.
        start: Override entry point. Uses scenario entry_point if None.
        goal: Override goal node. Uses scenario last target_system if None.
        include_vulnerabilities: If True, include vulnerability info along path.
        inventory: Vulnerability inventory DataFrame for vulnerability lookup.

    Returns:
        Dict containing the simulated attack path, risk-weighted attack path,
        entry point, target critical asset, and systems along the path.
    """
    scenario = get_finbank_scenario(scenario_id)

    if graph is None:
        graph = build_finbank_graph()

    entry_point = start if start is not None else scenario.entry_point
    critical_asset = goal if goal is not None else scenario.target_systems[-1]

    astar_result = astar_search(graph, start=entry_point, goal=critical_asset)

    systems_along_path = []
    for node_id in astar_result["path"]:
        system = get_finbank_system(node_id)
        systems_along_path.append({
            "system_id": node_id,
            "display_name": system["display_name"],
            "type": system["type"],
            "criticality": system["criticality"],
            "internet_exposed": system["internet_exposed"],
        })

    result = {
        "scenario_id": scenario_id,
        "entry_point": entry_point,
        "target_critical_asset": critical_asset,
        "simulated_attack_path": astar_result["path"],
        "risk_weighted_attack_path": astar_result["path"],
        "total_risk_cost": astar_result["total_cost"],
        "systems_along_path": systems_along_path,
        "scenario_target_systems": list(scenario.target_systems),
    }

    if include_vulnerabilities and inventory is not None:
        vulnerabilities_along_path = []
        for node_id in astar_result["path"]:
            vulns = inventory[inventory["system_id"] == node_id]
            vulnerabilities_along_path.append({
                "system_id": node_id,
                "vulnerability_count": int(len(vulns)),
                "vulnerability_ids": vulns["vuln_id"].tolist() if len(vulns) > 0 else [],
            })
        result["vulnerabilities_along_path"] = vulnerabilities_along_path

    return result


def run_all_finbank_scenario_paths(
    graph: Optional[dict[str, Any]] = None,
    include_vulnerabilities: bool = False,
    inventory: Optional[Any] = None,
) -> list[dict[str, Any]]:
    """Run A* attack path analysis for all FinBank scenarios.

    Args:
        graph: Pre-built graph dict. Built from FinBank data if None.
        include_vulnerabilities: If True, include vulnerability info along paths.
        inventory: Vulnerability inventory DataFrame for vulnerability lookup.

    Returns:
        List of result dicts, one per scenario.
    """
    from src.attack_simulator.scenarios import build_finbank_scenarios

    scenarios = build_finbank_scenarios()
    results = []
    for scenario in scenarios:
        result = run_scenario_attack_path(
            scenario.scenario_id,
            graph=graph,
            include_vulnerabilities=include_vulnerabilities,
            inventory=inventory,
        )
        results.append(result)
    return results


def get_systems_on_path(path: list[str]) -> list[dict[str, Any]]:
    """Get system metadata for nodes along a given attack path.

    Args:
        path: List of system IDs representing an attack path.

    Returns:
        List of system metadata dicts for each node in the path.
    """
    systems = []
    for node_id in path:
        system = get_finbank_system(node_id)
        systems.append({
            "system_id": node_id,
            "display_name": system["display_name"],
            "type": system["type"],
            "criticality": system["criticality"],
            "internet_exposed": system["internet_exposed"],
        })
    return systems


def get_vulnerabilities_on_path(
    path: list[str],
    inventory: Any,
) -> list[dict[str, Any]]:
    """Get vulnerability information for systems along a given attack path.

    Args:
        path: List of system IDs representing an attack path.
        inventory: Vulnerability inventory DataFrame.

    Returns:
        List of vulnerability info dicts for each system in the path.
    """
    vulnerabilities = []
    for node_id in path:
        vulns = inventory[inventory["system_id"] == node_id]
        vulnerabilities.append({
            "system_id": node_id,
            "vulnerability_count": int(len(vulns)),
            "vulnerability_ids": vulns["vuln_id"].tolist() if len(vulns) > 0 else [],
        })
    return vulnerabilities
