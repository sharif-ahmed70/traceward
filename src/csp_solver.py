"""Backtracking CSP foundation for TraceWard remediation planning.

Week 1 scope:
- Define a contract for prioritized vulnerabilities, teams, time slots and schedules.
- Provide a small, deterministic mock case.
- Produce a feasible schedule with Backtracking CSP.

This module deliberately does not claim the returned schedule is optimal.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple


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


# A small reviewable case used when upstream KNN/A* outputs are not available yet.
MOCK_CASE = CSPCase(
    vulnerabilities=(
        VulnerabilityTask("VULN-001", "WEB01", "Critical", "Web Team"),
        VulnerabilityTask("VULN-002", "DB01", "High", "Database Team"),
        VulnerabilityTask("VULN-003", "APP01", "High", "Application Team", depends_on=("VULN-001",)),
        VulnerabilityTask("VULN-004", "BACKUP01", "Medium", "Database Team", depends_on=("VULN-002",)),
        VulnerabilityTask("VULN-005", "VPN01", "Medium", "Network Team"),
    ),
    available_teams=("Web Team", "Database Team", "Application Team", "Network Team"),
    time_slots=(
        "Mon 09:00",
        "Mon 14:00",
        "Tue 09:00",
        "Tue 14:00",
        "Wed 09:00",
    ),
)


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

    # Constraint 3: dependencies must already be scheduled earlier.
    current_index = _slot_index(slot, case.time_slots)
    for dependency in task.depends_on:
        if dependency in assignments:
            dependency_slot = assignments[dependency][1]
            if _slot_index(dependency_slot, case.time_slots) >= current_index:
                return False

    return True


def _ordered_tasks(case: CSPCase) -> List[VulnerabilityTask]:
    """Choose constrained/high-priority variables first for a small practical CSP."""
    priority_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    return sorted(
        case.vulnerabilities,
        key=lambda task: (priority_order.get(task.priority, 99), -len(task.depends_on), task.vuln_id),
    )


def solve_csp(case: CSPCase = MOCK_CASE) -> Dict[str, Any]:
    """Solve the supplied remediation CSP using Backtracking.

    Returns a serializable result containing the schedule and contract metadata.
    The result represents a feasible schedule, not an optimization result.
    """
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
        raise ValueError("No feasible remediation schedule exists for this CSP case")

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
