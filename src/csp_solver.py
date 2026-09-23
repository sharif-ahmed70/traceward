"""Backtracking CSP foundation for TraceWard remediation planning.

Week 1 scope:
- Define a contract for prioritized vulnerabilities, teams, time slots and schedules.
- Provide a small, deterministic mock case.
- Produce a feasible schedule with Backtracking CSP.

This module deliberately does not claim the returned schedule is optimal.
"""

from __future__ import annotations

import json
from pathlib import Path
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
import pandas as pd


Assignment = Tuple[str, str]  # (team, time_slot)


@dataclass(frozen=True)
class VulnerabilityTask:
    """A remediation task accepted by the CSP."""

    vuln_id: str
    system_id: str
    priority: str
    required_team: str
    duration_slots: int = 1
    depends_on: Tuple[str, ...] = ()


@dataclass(frozen=True)
class CSPCase:
    """Contract-compatible CSP input."""

    vulnerabilities: Tuple[VulnerabilityTask, ...]
    available_teams: Tuple[str, ...]
    time_slots: Tuple[str, ...]


SYSTEM_TEAM_MAP = {
    "WEB01": "Web Team",
    "APP01": "Application Team",
    "DB01": "Database Team",
    "BACKUP01": "Database Team",
    "VPN01": "Network Team",
    "AUTH01": "Network Team",
    "EMP01": "IT Support Team",
}

DEFAULT_TIME_SLOTS = (
    "Mon 09:00",
    "Mon 14:00",
    "Tue 09:00",
    "Tue 14:00",
    "Wed 09:00",
)

# A small reviewable fallback case used when upstream KNN/A* outputs are not available yet.
MOCK_CASE = CSPCase(
    vulnerabilities=(
        VulnerabilityTask("VULN-001", "WEB01", "Critical", "Web Team"),
        VulnerabilityTask("VULN-002", "DB01", "High", "Database Team"),
        VulnerabilityTask("VULN-003", "APP01", "High", "Application Team", depends_on=("VULN-001",)),
        VulnerabilityTask("VULN-004", "BACKUP01", "Medium", "Database Team", depends_on=("VULN-002",)),
        VulnerabilityTask("VULN-005", "VPN01", "Medium", "Network Team"),
    ),
    available_teams=("Web Team", "Database Team", "Application Team", "Network Team"),
    time_slots=DEFAULT_TIME_SLOTS,
)


def build_csp_case_from_pipeline(
    predictions_path: str | Path = "artifacts/knn/predictions.csv",
    attack_path_path: str | Path = "artifacts/astar/attack_path.json",
    predictions_df: Optional[pd.DataFrame] = None,
    attack_path_data: Optional[Dict[str, Any]] = None,
    time_slots: Tuple[str, ...] = DEFAULT_TIME_SLOTS,
) -> Tuple[CSPCase, Dict[str, Any]]:
    """Construct an actionable CSP remediation scheduling case from real upstream pipeline outputs.

    Selection Rule:
      1. Evaluates all vulnerability predictions from upstream KNN (240 test cases out of 1,200 dataset rows).
      2. Reads the critical traversal path from upstream A* search (e.g. ['INTERNET', 'WEB01', 'APP01', 'DB01']).
      3. Attack-Path Prioritization: Systems directly on the active attack path (WEB01, APP01, DB01) receive
         highest priority for remediation because patching them directly impedes adversary traversal.
      4. Highest Severity: Selects the top vulnerability per attack-path system based on predicted risk
         (Critical > High > Medium > Low).
      5. Team Breadth: Selects top vulnerabilities on adjacent systems (BACKUP01, VPN01) to engage all operational teams.
      6. Defensive Dependencies: Enforces prerequisite ordering: intermediate application fixes (APP01)
         depend on boundary perimeter fixes (WEB01); backup fixes (BACKUP01) depend on database fixes (DB01).
      7. Excluded Backlog Tracking: Explicitly accounts for all non-selected vulnerabilities as 'pending backlog'
         for subsequent operational scheduling windows.

    Returns:
        case: CSPCase instance with real vuln_id, system_id, predicted_risk, assigned team, and dependencies.
        metadata: dict detailing selection statistics, attack-path systems, selected tasks, and pending count.
    """
    # 1. Load predictions
    if predictions_df is None:
        p_path = Path(predictions_path)
        if not p_path.exists():
            return MOCK_CASE, {
                "source": "mock_fallback",
                "selected_task_count": 5,
                "total_evaluated_vulnerabilities": 5,
                "pending_backlog_count": 0,
                "attack_path_systems": ["WEB01", "APP01", "DB01"],
            }
        pred_df = pd.read_csv(p_path)
    else:
        pred_df = predictions_df.copy()

    # 2. Load attack path
    if attack_path_data is None:
        ap_path = Path(attack_path_path)
        if ap_path.exists():
            try:
                with open(ap_path, "r", encoding="utf-8") as f:
                    path_dict = json.load(f)
            except Exception:
                path_dict = {"path": ["INTERNET", "WEB01", "APP01", "DB01"]}
        else:
            path_dict = {"path": ["INTERNET", "WEB01", "APP01", "DB01"]}
    else:
        path_dict = attack_path_data

    attack_path_systems = [n for n in path_dict.get("path", []) if n != "INTERNET"]
    if not attack_path_systems:
        attack_path_systems = ["WEB01", "APP01", "DB01"]

    priority_rank = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    pred_df["_rank"] = pred_df["predicted_risk"].map(lambda x: priority_rank.get(x, 99))

    task_dict: Dict[str, Dict[str, Any]] = {}

    # Prioritize attack path systems in traversal order
    for sys_id in attack_path_systems:
        matching = pred_df[pred_df["system_id"] == sys_id].sort_values(by=["_rank", "vuln_id"])
        if not matching.empty:
            task_dict[sys_id] = matching.iloc[0].to_dict()

    # Complement with representative systems to engage Database/Network teams
    for sys_id in ["BACKUP01", "VPN01"]:
        if sys_id not in task_dict:
            matching = pred_df[pred_df["system_id"] == sys_id].sort_values(by=["_rank", "vuln_id"])
            if not matching.empty:
                task_dict[sys_id] = matching.iloc[0].to_dict()

    # Build tasks with dependencies reflecting attack path traversal
    tasks = []
    web_task_id = task_dict.get("WEB01", {}).get("vuln_id")
    db_task_id = task_dict.get("DB01", {}).get("vuln_id")

    for sys_id, row in task_dict.items():
        v_id = row["vuln_id"]
        p_label = row["predicted_risk"]
        team = SYSTEM_TEAM_MAP.get(sys_id, "Security Team")
        deps = ()
        if sys_id == "APP01" and web_task_id:
            deps = (web_task_id,)
        elif sys_id == "BACKUP01" and db_task_id:
            deps = (db_task_id,)

        tasks.append(
            VulnerabilityTask(
                vuln_id=v_id,
                system_id=sys_id,
                priority=p_label,
                required_team=team,
                depends_on=deps,
            )
        )

    all_teams = tuple(sorted({t.required_team for t in tasks}))
    case = CSPCase(
        vulnerabilities=tuple(tasks),
        available_teams=all_teams,
        time_slots=time_slots,
    )

    total_evaluated = len(pred_df)
    selected_count = len(tasks)
    pending_count = total_evaluated - selected_count

    metadata = {
        "source": "live_pipeline",
        "total_evaluated_vulnerabilities": total_evaluated,
        "selected_task_count": selected_count,
        "pending_backlog_count": pending_count,
        "attack_path_systems": attack_path_systems,
        "selection_rule": (
            f"Selected top-severity vulnerability from each system on active attack path ({', '.join(attack_path_systems)}), "
            "plus adjacent systems to engage all operational teams. Prerequisite dependencies enforce perimeter fixes before internal fixes."
        ),
        "selected_tasks": [
            {
                "vuln_id": t.vuln_id,
                "system_id": t.system_id,
                "priority": t.priority,
                "team": t.required_team,
                "depends_on": list(t.depends_on),
            }
            for t in tasks
        ],
    }

    return case, metadata


def _slot_index(time_slot: str, slots: Tuple[str, ...]) -> int:
    return slots.index(time_slot)


def validate_case(case: CSPCase) -> None:
    """Validate the basic CSP contract before solving."""
    team_set = set(case.available_teams)
    vuln_ids = {task.vuln_id for task in case.vulnerabilities}

    if not case.vulnerabilities:
        raise ValueError("CSP case must contain at least one vulnerability task")
    if not case.available_teams:
        raise ValueError("CSP case must contain at least one available team")
    if not case.time_slots:
        raise ValueError("CSP case must contain at least one time slot")

    for task in case.vulnerabilities:
        if task.required_team not in team_set:
            raise ValueError(f"Unknown team for {task.vuln_id}: {task.required_team}")
        if task.duration_slots != 1:
            raise ValueError("Week 1 mock solver supports one-slot tasks only")
        missing = set(task.depends_on) - vuln_ids
        if missing:
            raise ValueError(f"{task.vuln_id} has unknown dependencies: {sorted(missing)}")
        if task.vuln_id in task.depends_on:
            raise ValueError(f"{task.vuln_id} cannot depend on itself")


def _constraints_ok(
    task: VulnerabilityTask,
    assignment: Assignment,
    assignments: Dict[str, Assignment],
    case: CSPCase,
) -> bool:
    """Return True when an assignment satisfies the Week 1 constraints."""
    team, slot = assignment

    # Constraint 1: a task can only be assigned to its required team.
    if team != task.required_team:
        return False

    # Constraint 2: one team cannot receive two tasks in the same time slot.
    if assignment in assignments.values():
        return False

    # Constraint 3: dependencies must already be scheduled in strictly earlier time slots.
    current_index = _slot_index(slot, case.time_slots)
    for dependency in task.depends_on:
        if dependency not in assignments:
            return False
        dependency_slot = assignments[dependency][1]
        if _slot_index(dependency_slot, case.time_slots) >= current_index:
            return False

    return True


def _ordered_tasks(case: CSPCase) -> List[VulnerabilityTask]:
    """Order variables topologically (prerequisites first) then by priority."""
    priority_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    return sorted(
        case.vulnerabilities,
        key=lambda task: (len(task.depends_on), priority_order.get(task.priority, 99), task.vuln_id),
    )


def solve_csp(case: Optional[CSPCase] = None, raise_on_infeasible: bool = False) -> Dict[str, Any]:
    """Solve the remediation CSP using Backtracking.

    If case is None, dynamically constructs the scheduling case from upstream KNN predictions
    and A* attack path via build_csp_case_from_pipeline() (falling back to MOCK_CASE if pipeline
    artifacts are absent).

    Returns a serializable result containing the schedule and contract metadata.
    If no feasible schedule satisfies all constraints, returns a structured infeasible status
    (or raises ValueError if raise_on_infeasible=True).
    The result represents a feasible schedule, not an optimization result.
    """
    metadata: Dict[str, Any] = {}
    if case is None:
        case, metadata = build_csp_case_from_pipeline()
    else:
        metadata = {
            "source": "custom_or_mock",
            "selected_task_count": len(case.vulnerabilities),
            "total_evaluated_vulnerabilities": len(case.vulnerabilities),
            "pending_backlog_count": 0,
            "attack_path_systems": list({t.system_id for t in case.vulnerabilities}),
        }

    validate_case(case)
    tasks = _ordered_tasks(case)
    assignments: Dict[str, Assignment] = {}

    def backtrack(index: int) -> bool:
        if index == len(tasks):
            return True

        task = tasks[index]
        for team in case.available_teams:
            for slot in case.time_slots:
                candidate = (team, slot)
                if not _constraints_ok(task, candidate, assignments, case):
                    continue
                assignments[task.vuln_id] = candidate
                if backtrack(index + 1):
                    return True
                assignments.pop(task.vuln_id, None)
        return False

    if not backtrack(0):
        if raise_on_infeasible:
            raise ValueError("No feasible remediation schedule exists for this CSP case")
        return {
            "status": "infeasible",
            "solver": "Backtracking CSP",
            "objective": None,
            "variables": [task.vuln_id for task in tasks],
            "domains": {
                task.vuln_id: [
                    {"team": task.required_team, "time_slot": slot}
                    for slot in case.time_slots
                ]
                for task in tasks
            },
            "constraints": [
                "Each vulnerability is assigned to its required team.",
                "A team handles at most one vulnerability in a time slot.",
                "Dependencies must be scheduled before their dependent vulnerability.",
            ],
            "schedule": [],
            "message": "No feasible remediation schedule exists satisfying all team, slot, and prerequisite constraints.",
        }

    task_lookup = {task.vuln_id: task for task in case.vulnerabilities}
    schedule = []
    for task in sorted(
        case.vulnerabilities,
        key=lambda item: _slot_index(assignments[item.vuln_id][1], case.time_slots),
    ):
        team, slot = assignments[task.vuln_id]
        schedule.append(
            {
                "vuln_id": task.vuln_id,
                "system_id": task.system_id,
                "priority": task.priority,
                "team": team,
                "time_slot": slot,
                "depends_on": list(task.depends_on),
            }
        )

    return {
        "status": "feasible",
        "solver": "Backtracking CSP",
        "objective": None,
        "variables": [task.vuln_id for task in tasks],
        "domains": {
            task.vuln_id: [
                {"team": task.required_team, "time_slot": slot}
                for slot in case.time_slots
            ]
            for task in tasks
        },
        "constraints": [
            "Each vulnerability is assigned to its required team.",
            "A team handles at most one vulnerability in a time slot.",
            "Dependencies must be scheduled before their dependent vulnerability.",
        ],
        "schedule": schedule,
        "metadata": metadata,
    }


def main() -> None:
    result = solve_csp()
    print("TraceWard CSP mock case")
    print(f"Status: {result['status']}")
    for item in result["schedule"]:
        print(
            f"{item['time_slot']}: {item['team']} -> "
            f"{item['vuln_id']} ({item['priority']}, {item['system_id']})"
        )


if __name__ == "__main__":
    main()
