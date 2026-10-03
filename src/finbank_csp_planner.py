"""FinBank-aware CSP remediation planner extension.

Extends the existing TraceWard CSP remediation planner to support simulated
FinBank incidents. Builds a prioritized remediation task set from incident
context and delegates scheduling to the existing backtracking CSP solver.

Returns a feasible remediation schedule under the configured constraints.
This module does not claim mathematical optimality; the underlying solver
returns a feasible schedule, not an optimized one.
"""

from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

import pandas as pd

from src.csp_solver import (
    CSPCase,
    VulnerabilityTask,
    solve_csp,
    validate_case,
    SYSTEM_TEAM_MAP,
    DEFAULT_TIME_SLOTS,
)
from src.incident_correlator import Incident
from src.finbank_env import get_finbank_system


PRIORITY_RANK = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}


def _attack_path_position(system_id: str, attack_path: list[str]) -> int:
    """Return the position of a system in the attack path (0-indexed).

    Systems not on the path receive a large index so they are scheduled later.
    INTERNET is excluded from position ranking.
    """
    if system_id == "INTERNET":
        return len(attack_path)
    try:
        return attack_path.index(system_id)
    except ValueError:
        return len(attack_path)


def _compute_task_priority(
    vuln_risk: str,
    system_criticality: int,
    attack_path_position: int,
    internet_exposed: bool,
) -> int:
    """Compute a numeric priority score for sorting tasks.

    Lower score = higher scheduling priority.
    """
    risk_score = PRIORITY_RANK.get(vuln_risk, 99)
    path_score = max(0, attack_path_position)
    criticality_score = max(0, 5 - system_criticality)
    exposure_score = 0 if internet_exposed else 1
    return (risk_score * 100) + (path_score * 10) + criticality_score + exposure_score


def build_finbank_remediation_case(
    incident: Incident,
    inventory: pd.DataFrame,
    attack_path: list[str],
    systems: Optional[dict[str, dict[str, Any]]] = None,
    time_slots: Tuple[str, ...] = DEFAULT_TIME_SLOTS,
    extra_constraints: Optional[Dict[str, Any]] = None,
) -> Tuple[CSPCase, Dict[str, Any]]:
    """Build a CSP remediation case for a simulated FinBank incident.

    Args:
        incident: Structured Incident object from the incident correlator.
        inventory: FinBank vulnerability inventory DataFrame.
        attack_path: Ordered list of system IDs from A* attack path.
        systems: Optional system metadata mapping. Loaded from FinBank env if None.
        time_slots: Available scheduling time slots.
        extra_constraints: Optional dict for additional constraints (reserved for
            future extension; current implementation preserves existing CSP constraints).

    Returns:
        Tuple of (CSPCase, metadata) where metadata includes selection statistics,
        attack-path context, and priority information.
    """
    if systems is None:
        from src.finbank_env import load_finbank_systems
        systems = load_finbank_systems()

    required_inventory_cols = {"vuln_id", "system_id", "risk_label"}
    missing = required_inventory_cols - set(inventory.columns)
    if missing:
        raise ValueError(f"Inventory missing required columns: {sorted(missing)}")

    inventory_index = inventory.set_index("vuln_id").to_dict("index")

    task_candidates = []
    for vuln_id in incident.related_vulnerabilities:
        if vuln_id not in inventory_index:
            continue
        row = inventory_index[vuln_id]
        system_id = str(row["system_id"])
        risk_label = str(row.get("risk_label", "Medium"))

        system_info = get_finbank_system(system_id, systems)
        criticality = int(system_info.get("criticality", 3))
        internet_exposed = bool(system_info.get("internet_exposed", False))
        path_pos = _attack_path_position(system_id, attack_path)

        task_candidates.append({
            "vuln_id": vuln_id,
            "system_id": system_id,
            "risk_label": risk_label,
            "criticality": criticality,
            "internet_exposed": internet_exposed,
            "attack_path_position": path_pos,
            "priority_score": _compute_task_priority(
                risk_label, criticality, path_pos, internet_exposed
            ),
        })

    task_candidates.sort(key=lambda c: c["priority_score"])

    selected_vuln_ids = []
    seen_systems = set()
    for candidate in task_candidates:
        if candidate["system_id"] not in seen_systems:
            selected_vuln_ids.append(candidate["vuln_id"])
            seen_systems.add(candidate["system_id"])

    vuln_id_to_row = {c["vuln_id"]: c for c in task_candidates}
    selected_candidates = [vuln_id_to_row[v] for v in selected_vuln_ids if v in vuln_id_to_row]

    web_task_id = None
    db_task_id = None
    for candidate in selected_candidates:
        if candidate["system_id"] == "WEB01":
            web_task_id = candidate["vuln_id"]
        if candidate["system_id"] == "DB01":
            db_task_id = candidate["vuln_id"]

    tasks = []
    for candidate in selected_candidates:
        sys_id = candidate["system_id"]
        v_id = candidate["vuln_id"]
        team = SYSTEM_TEAM_MAP.get(sys_id, "Security Team")
        deps = ()
        if sys_id == "APP01" and web_task_id and web_task_id != v_id:
            deps = (web_task_id,)
        elif sys_id == "BACKUP01" and db_task_id and db_task_id != v_id:
            deps = (db_task_id,)

        tasks.append(
            VulnerabilityTask(
                vuln_id=v_id,
                system_id=sys_id,
                priority=candidate["risk_label"],
                required_team=team,
                duration_slots=1,
                depends_on=deps,
            )
        )

    available_teams = tuple(sorted({t.required_team for t in tasks}))
    case = CSPCase(
        vulnerabilities=tuple(tasks),
        available_teams=available_teams,
        time_slots=time_slots,
    )

    if extra_constraints is not None:
        validate_case(case)

    attack_path_systems = [n for n in attack_path if n != "INTERNET"]
    metadata = {
        "source": "finbank_incident",
        "incident_id": incident.incident_id,
        "scenario_id": incident.scenario_id,
        "entry_point": incident.entry_point,
        "attack_path": attack_path,
        "attack_path_systems": attack_path_systems,
        "selected_task_count": len(tasks),
        "total_related_vulnerabilities": len(incident.related_vulnerabilities),
        "pending_backlog_count": len(incident.related_vulnerabilities) - len(tasks),
        "selection_rule": (
            "Selected one representative vulnerability per affected system, "
            "prioritizing systems on the active attack path and higher-criticality assets. "
            "Dependencies enforce perimeter fixes before internal progression."
        ),
        "selected_tasks": [
            {
                "vuln_id": t.vuln_id,
                "system_id": t.system_id,
                "priority": t.priority,
                "team": t.required_team,
                "depends_on": list(t.depends_on),
                "attack_path_position": next(
                    (c["attack_path_position"] for c in selected_candidates if c["vuln_id"] == t.vuln_id),
                    len(attack_path),
                ),
            }
            for t in tasks
        ],
    }

    return case, metadata


def run_finbank_remediation_plan(
    incident: Incident,
    inventory: pd.DataFrame,
    attack_path: list[str],
    systems: Optional[dict[str, dict[str, Any]]] = None,
    time_slots: Tuple[str, ...] = DEFAULT_TIME_SLOTS,
    raise_on_infeasible: bool = False,
    extra_constraints: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Build and solve a FinBank incident remediation plan.

    Args:
        incident: Structured Incident object from the incident correlator.
        inventory: FinBank vulnerability inventory DataFrame.
        attack_path: Ordered list of system IDs from A* attack path.
        systems: Optional system metadata mapping.
        time_slots: Available scheduling time slots.
        raise_on_infeasible: If True, raise ValueError when no feasible schedule exists.
        extra_constraints: Optional dict for additional constraints.

    Returns:
        Dict containing a feasible remediation schedule under the configured constraints,
        along with incident context and selection metadata.
    """
    case, metadata = build_finbank_remediation_case(
        incident=incident,
        inventory=inventory,
        attack_path=attack_path,
        systems=systems,
        time_slots=time_slots,
        extra_constraints=extra_constraints,
    )

    result = solve_csp(case, raise_on_infeasible=raise_on_infeasible)
    result["metadata"] = metadata
    result["description"] = (
        "feasible remediation schedule under the configured constraints"
    )
    return result


def run_finbank_scenario_remediation(
    scenario_id: str,
    inventory: Optional[pd.DataFrame] = None,
    attack_path: Optional[list[str]] = None,
    graph: Optional[dict[str, Any]] = None,
    systems: Optional[dict[str, dict[str, Any]]] = None,
    time_slots: Tuple[str, ...] = DEFAULT_TIME_SLOTS,
    raise_on_infeasible: bool = False,
) -> Dict[str, Any]:
    """Convenience function: run full FinBank scenario remediation by scenario ID.

    Simulates the attack, correlates the incident, builds the attack path,
    and produces a feasible remediation schedule.

    Args:
        scenario_id: FinBank scenario identifier.
        inventory: Optional vulnerability inventory. Generated if None.
        attack_path: Optional attack path list. Computed via A* if None.
        graph: Optional pre-built graph for A* computation.
        systems: Optional system metadata mapping.
        time_slots: Available scheduling time slots.
        raise_on_infeasible: If True, raise ValueError when no feasible schedule exists.

    Returns:
        Dict containing the feasible remediation schedule and incident context.
    """
    from src.attack_simulator.simulator import simulate_finbank_attack
    from src.incident_correlator import correlate_single_scenario
    from src.finbank_astar_integration import run_scenario_attack_path

    if inventory is None:
        from src.finbank_assignment import assign_finbank_vulnerabilities
        inventory = assign_finbank_vulnerabilities()

    events = simulate_finbank_attack(scenario_id, inventory=inventory)
    incident = correlate_single_scenario(scenario_id, events, inventory, systems)

    if attack_path is None:
        path_result = run_scenario_attack_path(
            scenario_id, graph=graph, include_vulnerabilities=False
        )
        attack_path = path_result["simulated_attack_path"]

    return run_finbank_remediation_plan(
        incident=incident,
        inventory=inventory,
        attack_path=attack_path,
        systems=systems,
        time_slots=time_slots,
        raise_on_infeasible=raise_on_infeasible,
    )
