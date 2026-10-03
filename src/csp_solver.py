"""Backtracking CSP remediation planner for TraceWard.

Formulation
-----------
- Variables: one remediation task per selected vulnerability.
- Domains:   (team, time_slot) pairs.
- Constraints:
    C1 Team qualification (unary)   task is handled only by its required team
    C2 Team availability (binary)   a team patches at most one system per slot
    C3 Patch dependency (binary)    prerequisite patch is in a strictly earlier slot
    C4 Maintenance window (unary)   listed systems may only restart after business hours
    C5 Downtime restriction (binary) listed critical systems are never offline together
    C6 Daily capacity (global)      at most N patches per day
    C7 Attack-path priority (unary) A* attack-path tasks finish before a deadline slot

C1-C3 always apply. C4-C7 apply when the case carries `CSPConstraints`.

Search improvements (each can be toggled for evaluation):
- MRV with Degree heuristic tie-break for variable ordering
- Forward Checking after every assignment
- AC-3 arc consistency as preprocessing

The solver returns a feasible schedule, not an optimal one.
"""

from __future__ import annotations

import json
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import pandas as pd


Assignment = Tuple[str, str]  # (team, time_slot)

PRIORITY_RANK = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}


@dataclass(frozen=True)
class VulnerabilityTask:
    """A remediation task accepted by the CSP."""

    vuln_id: str
    system_id: str
    priority: str
    required_team: str
    duration_slots: int = 1
    depends_on: Tuple[str, ...] = ()
    on_attack_path: bool = False


@dataclass(frozen=True)
class CSPConstraints:
    """Real-world operational restrictions (C4-C7)."""

    business_hours: Tuple[int, int] = (9, 18)
    after_hours_only_systems: Tuple[str, ...] = ()
    max_patches_per_day: Optional[int] = None
    no_concurrent_downtime: Tuple[str, ...] = ()
    attack_path_deadline: Optional[str] = None


@dataclass(frozen=True)
class CSPCase:
    """Contract-compatible CSP input."""

    vulnerabilities: Tuple[VulnerabilityTask, ...]
    available_teams: Tuple[str, ...]
    time_slots: Tuple[str, ...]
    constraints: Optional[CSPConstraints] = field(default=None)


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

CONSTRAINTS_PATH = Path("data/constraints.json")

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


# ---------------------------------------------------------------------------
# Case construction
# ---------------------------------------------------------------------------

def load_constraint_config(path: str | Path = CONSTRAINTS_PATH) -> Dict[str, Any]:
    """Load the operational constraint configuration (data/constraints.json)."""
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def constraints_from_config(config: Dict[str, Any]) -> CSPConstraints:
    return CSPConstraints(
        business_hours=tuple(config.get("business_hours", (9, 18))),
        after_hours_only_systems=tuple(config.get("after_hours_only_systems", ())),
        max_patches_per_day=config.get("max_patches_per_day"),
        no_concurrent_downtime=tuple(config.get("no_concurrent_downtime", ())),
        attack_path_deadline=config.get("attack_path_deadline"),
    )


def build_csp_case_from_pipeline(
    predictions_path: str | Path = "artifacts/knn/predictions.csv",
    attack_path_path: str | Path = "artifacts/astar/attack_path.json",
    predictions_df: Optional[pd.DataFrame] = None,
    attack_path_data: Optional[Dict[str, Any]] = None,
    time_slots: Optional[Tuple[str, ...]] = None,
    constraints_path: str | Path = CONSTRAINTS_PATH,
) -> Tuple[CSPCase, Dict[str, Any]]:
    """Construct the remediation CSP from KNN predictions, the A* path and constraints.json.

    Selection rule:
      1. Systems on the A* attack path get the top-N most severe predicted vulnerabilities
         (tasks_per_attack_path_system); they are flagged `on_attack_path` and must meet
         the attack-path deadline.
      2. Every other system gets its top-M vulnerability (tasks_per_other_system).
      3. System-level dependencies from constraints.json (e.g. APP01 after WEB01) become
         task dependencies on the first task of the prerequisite system.
      4. All other predictions are reported as pending backlog.
    """
    if predictions_df is None:
        p_path = Path(predictions_path)
        if not p_path.exists():
            return MOCK_CASE, {
                "source": "mock_fallback",
                "selected_task_count": len(MOCK_CASE.vulnerabilities),
                "total_evaluated_vulnerabilities": len(MOCK_CASE.vulnerabilities),
                "pending_backlog_count": 0,
                "attack_path_systems": ["WEB01", "APP01", "DB01"],
            }
        pred_df = pd.read_csv(p_path)
    else:
        pred_df = predictions_df.copy()

    if attack_path_data is None:
        try:
            with open(attack_path_path, "r", encoding="utf-8") as f:
                path_dict = json.load(f)
        except (OSError, ValueError):
            path_dict = {"path": ["INTERNET", "WEB01", "APP01", "DB01"]}
    else:
        path_dict = attack_path_data

    attack_path_systems = [n for n in path_dict.get("path", []) if n != "INTERNET"]
    if not attack_path_systems:
        attack_path_systems = ["WEB01", "APP01", "DB01"]

    config = load_constraint_config(constraints_path)
    slots = tuple(time_slots or config["time_slots"])
    per_path = int(config.get("tasks_per_attack_path_system", 2))
    per_other = int(config.get("tasks_per_other_system", 1))

    pred_df["_rank"] = pred_df["predicted_risk"].map(lambda x: PRIORITY_RANK.get(x, 99))

    system_order = attack_path_systems + sorted(
        s for s in pred_df["system_id"].unique() if s not in attack_path_systems
    )
    selected: Dict[str, List[Dict[str, Any]]] = {}
    for sys_id in system_order:
        limit = per_path if sys_id in attack_path_systems else per_other
        matching = pred_df[pred_df["system_id"] == sys_id].sort_values(by=["_rank", "vuln_id"])
        if not matching.empty:
            selected[sys_id] = matching.head(limit).to_dict("records")

    first_task = {sys_id: rows[0]["vuln_id"] for sys_id, rows in selected.items()}
    system_deps: Dict[str, List[str]] = {}
    for dependent, prerequisite in config.get("dependencies", []):
        system_deps.setdefault(dependent, []).append(prerequisite)

    tasks = []
    for sys_id, rows in selected.items():
        deps = tuple(first_task[p] for p in system_deps.get(sys_id, []) if p in first_task)
        for row in rows:
            tasks.append(
                VulnerabilityTask(
                    vuln_id=row["vuln_id"],
                    system_id=sys_id,
                    priority=row["predicted_risk"],
                    required_team=SYSTEM_TEAM_MAP.get(sys_id, "Security Team"),
                    depends_on=deps,
                    on_attack_path=sys_id in attack_path_systems,
                )
            )

    case = CSPCase(
        vulnerabilities=tuple(tasks),
        available_teams=tuple(sorted({t.required_team for t in tasks})),
        time_slots=slots,
        constraints=constraints_from_config(config),
    )

    metadata = {
        "source": "live_pipeline",
        "total_evaluated_vulnerabilities": len(pred_df),
        "selected_task_count": len(tasks),
        "pending_backlog_count": len(pred_df) - len(tasks),
        "attack_path_systems": attack_path_systems,
        "selection_rule": (
            f"Top {per_path} most severe vulnerabilities on each A* attack-path system "
            f"({', '.join(attack_path_systems)}) and top {per_other} on every other system. "
            "Dependencies enforce perimeter fixes before internal fixes."
        ),
        "selected_tasks": [
            {
                "vuln_id": t.vuln_id,
                "system_id": t.system_id,
                "priority": t.priority,
                "team": t.required_team,
                "depends_on": list(t.depends_on),
                "on_attack_path": t.on_attack_path,
            }
            for t in tasks
        ],
    }
    return case, metadata


# ---------------------------------------------------------------------------
# Constraint model
# ---------------------------------------------------------------------------

def _slot_index(time_slot: str, slots: Tuple[str, ...]) -> int:
    return slots.index(time_slot)


def slot_day(time_slot: str) -> str:
    return time_slot.split()[0]


def slot_hour(time_slot: str) -> int:
    return int(time_slot.split()[1].split(":")[0])


def is_business_hours(time_slot: str, business_hours: Tuple[int, int] = (9, 18)) -> bool:
    start, end = business_hours
    return start <= slot_hour(time_slot) < end


def validate_case(case: CSPCase) -> None:
    """Validate the CSP contract before solving."""
    team_set = set(case.available_teams)
    vuln_ids = {task.vuln_id for task in case.vulnerabilities}

    if not case.vulnerabilities:
        raise ValueError("CSP case must contain at least one vulnerability task")
    if not case.available_teams:
        raise ValueError("CSP case must contain at least one available team")
    if not case.time_slots:
        raise ValueError("CSP case must contain at least one time slot")
    if len(vuln_ids) != len(case.vulnerabilities):
        raise ValueError("CSP case contains duplicate vulnerability IDs")

    for task in case.vulnerabilities:
        if task.required_team not in team_set:
            raise ValueError(f"Unknown team for {task.vuln_id}: {task.required_team}")
        if task.duration_slots != 1:
            raise ValueError("Solver supports one-slot tasks only")
        missing = set(task.depends_on) - vuln_ids
        if missing:
            raise ValueError(f"{task.vuln_id} has unknown dependencies: {sorted(missing)}")
        if task.vuln_id in task.depends_on:
            raise ValueError(f"{task.vuln_id} cannot depend on itself")

    deadline = case.constraints.attack_path_deadline if case.constraints else None
    if deadline is not None and deadline not in case.time_slots:
        raise ValueError(f"Attack-path deadline '{deadline}' is not a time slot")

    _topological_order(case)  # raises on dependency cycles


def _topological_order(case: CSPCase) -> List[VulnerabilityTask]:
    """Kahn's algorithm; ties broken by attack-path flag, priority, then ID."""
    tasks = {t.vuln_id: t for t in case.vulnerabilities}
    indegree = {v: len(t.depends_on) for v, t in tasks.items()}
    children: Dict[str, List[str]] = {v: [] for v in tasks}
    for t in case.vulnerabilities:
        for dep in t.depends_on:
            children[dep].append(t.vuln_id)

    def key(v):
        t = tasks[v]
        return (not t.on_attack_path, PRIORITY_RANK.get(t.priority, 99), v)

    ready = sorted((v for v, d in indegree.items() if d == 0), key=key)
    order = []
    while ready:
        v = ready.pop(0)
        order.append(tasks[v])
        for child in children[v]:
            indegree[child] -= 1
            if indegree[child] == 0:
                ready.append(child)
        ready.sort(key=key)

    if len(order) != len(tasks):
        raise ValueError("Dependency cycle detected among remediation tasks")
    return order


def _unary_ok(task: VulnerabilityTask, value: Assignment, case: CSPCase) -> bool:
    """C1, C4, C7."""
    team, slot = value
    if team != task.required_team:
        return False
    c = case.constraints
    if c is None:
        return True
    if task.system_id in c.after_hours_only_systems and is_business_hours(slot, c.business_hours):
        return False
    if task.on_attack_path and c.attack_path_deadline is not None:
        if _slot_index(slot, case.time_slots) > _slot_index(c.attack_path_deadline, case.time_slots):
            return False
    return True


def _binary_ok(a: VulnerabilityTask, va: Assignment, b: VulnerabilityTask, vb: Assignment, case: CSPCase) -> bool:
    """C2, C3, C5 between two assigned tasks."""
    if va == vb:  # C2: same team in the same slot
        return False
    ia = _slot_index(va[1], case.time_slots)
    ib = _slot_index(vb[1], case.time_slots)
    if b.vuln_id in a.depends_on and not ib < ia:  # C3
        return False
    if a.vuln_id in b.depends_on and not ia < ib:
        return False
    c = case.constraints
    if c is not None and ia == ib and a.system_id != b.system_id:  # C5
        group = c.no_concurrent_downtime
        if a.system_id in group and b.system_id in group:
            return False
    return True


def _constrained_pairs(case: CSPCase) -> Dict[str, set]:
    """Neighbors in the constraint graph (tasks sharing a binary constraint)."""
    group = case.constraints.no_concurrent_downtime if case.constraints else ()
    neighbors = {t.vuln_id: set() for t in case.vulnerabilities}
    tasks = case.vulnerabilities
    for i, a in enumerate(tasks):
        for b in tasks[i + 1:]:
            if (
                a.required_team == b.required_team
                or a.vuln_id in b.depends_on
                or b.vuln_id in a.depends_on
                or (a.system_id in group and b.system_id in group)
            ):
                neighbors[a.vuln_id].add(b.vuln_id)
                neighbors[b.vuln_id].add(a.vuln_id)
    return neighbors


def _constraint_descriptions(case: CSPCase) -> List[str]:
    lines = [
        "Each vulnerability is assigned to its required team.",
        "A team handles at most one vulnerability in a time slot.",
        "Dependencies must be scheduled before their dependent vulnerability.",
    ]
    c = case.constraints
    if c is None:
        return lines
    if c.after_hours_only_systems:
        lines.append(
            f"Maintenance window: {', '.join(c.after_hours_only_systems)} may only be patched outside "
            f"business hours ({c.business_hours[0]:02d}:00-{c.business_hours[1]:02d}:00)."
        )
    if c.no_concurrent_downtime:
        lines.append(f"Downtime restriction: no two of {', '.join(c.no_concurrent_downtime)} offline in the same slot.")
    if c.max_patches_per_day is not None:
        lines.append(f"Resource limit: at most {c.max_patches_per_day} patches per day.")
    if c.attack_path_deadline is not None:
        lines.append(f"Priority: A* attack-path vulnerabilities must be patched by {c.attack_path_deadline}.")
    return lines


def verify_schedule(case: CSPCase, schedule: List[Dict[str, Any]]) -> List[str]:
    """Independently check a schedule against every constraint; returns violations."""
    tasks = {t.vuln_id: t for t in case.vulnerabilities}
    assigned = {item["vuln_id"]: (item["team"], item["time_slot"]) for item in schedule}
    violations = []

    for vid in tasks:
        if vid not in assigned:
            violations.append(f"{vid} is not scheduled")
    for vid, value in assigned.items():
        if not _unary_ok(tasks[vid], value, case):
            violations.append(f"{vid} violates a team, maintenance-window or deadline constraint")
    ids = list(assigned)
    for i, a in enumerate(ids):
        for b in ids[i + 1:]:
            if not _binary_ok(tasks[a], assigned[a], tasks[b], assigned[b], case):
                violations.append(f"{a} and {b} conflict (team, dependency or downtime)")
    c = case.constraints
    if c is not None and c.max_patches_per_day is not None:
        per_day: Dict[str, int] = {}
        for _, slot in assigned.values():
            per_day[slot_day(slot)] = per_day.get(slot_day(slot), 0) + 1
        for day, count in per_day.items():
            if count > c.max_patches_per_day:
                violations.append(f"{day} has {count} patches (limit {c.max_patches_per_day})")
    return violations


# ---------------------------------------------------------------------------
# Solver
# ---------------------------------------------------------------------------

def _ac3(domains: Dict[str, List[Assignment]], tasks: Dict[str, VulnerabilityTask],
         neighbors: Dict[str, set], case: CSPCase, stats: Dict[str, int]) -> bool:
    """AC-3 over the binary constraints. Returns False if a domain is wiped out."""
    queue = deque((xi, xj) for xi in neighbors for xj in neighbors[xi])
    while queue:
        xi, xj = queue.popleft()
        revised = False
        for vi in list(domains[xi]):
            supported = False
            for vj in domains[xj]:
                stats["constraint_checks"] += 1
                if _binary_ok(tasks[xi], vi, tasks[xj], vj, case):
                    supported = True
                    break
            if not supported:
                domains[xi].remove(vi)
                stats["ac3_pruned"] += 1
                revised = True
        if revised:
            if not domains[xi]:
                return False
            for xk in neighbors[xi] - {xj}:
                queue.append((xk, xi))
    return True


def _solve(case: CSPCase, use_mrv: bool, use_degree: bool, use_forward_checking: bool,
           use_ac3: bool) -> Tuple[Optional[Dict[str, Assignment]], Dict[str, Any]]:
    tasks = {t.vuln_id: t for t in case.vulnerabilities}
    # MRV falls back to dependency-aware order on ties; plain backtracking keeps the input order.
    static_order = [t.vuln_id for t in (_topological_order(case) if use_mrv else case.vulnerabilities)]
    neighbors = _constrained_pairs(case)
    max_per_day = case.constraints.max_patches_per_day if case.constraints else None
    stats = {"assignments": 0, "backtracks": 0, "constraint_checks": 0, "ac3_pruned": 0, "fc_pruned": 0}

    # Node consistency: domains start with values that satisfy the unary constraints.
    domains = {
        vid: [
            (team, slot)
            for slot in case.time_slots
            for team in case.available_teams
            if _unary_ok(tasks[vid], (team, slot), case)
        ]
        for vid in static_order
    }
    stats["initial_domain_size"] = sum(len(d) for d in domains.values())

    if use_ac3 and not _ac3(domains, tasks, neighbors, case, stats):
        return None, stats

    assignment: Dict[str, Assignment] = {}
    day_load: Dict[str, int] = {}

    def consistent(vid: str, value: Assignment) -> bool:
        if max_per_day is not None and day_load.get(slot_day(value[1]), 0) >= max_per_day:
            return False
        for other in neighbors[vid]:
            if other in assignment:
                stats["constraint_checks"] += 1
                if not _binary_ok(tasks[vid], value, tasks[other], assignment[other], case):
                    return False
        return True

    def select_variable(current: Dict[str, List[Assignment]]) -> str:
        unassigned = [v for v in static_order if v not in assignment]
        if not use_mrv:
            return unassigned[0]

        def remaining(v):
            if use_forward_checking:
                return len(current[v])
            return sum(1 for val in current[v] if consistent(v, val))

        def degree(v):
            return sum(1 for n in neighbors[v] if n not in assignment) if use_degree else 0

        return min(unassigned, key=lambda v: (remaining(v), -degree(v), static_order.index(v)))

    def forward_check(vid: str, value: Assignment, current: Dict[str, List[Assignment]]):
        pruned = {v: list(vals) for v, vals in current.items()}
        day = slot_day(value[1])
        day_full = max_per_day is not None and day_load.get(day, 0) >= max_per_day
        for other in pruned:
            if other in assignment:
                continue
            kept = []
            for val in pruned[other]:
                if day_full and slot_day(val[1]) == day:
                    continue
                if other in neighbors[vid]:
                    stats["constraint_checks"] += 1
                    if not _binary_ok(tasks[other], val, tasks[vid], value, case):
                        continue
                kept.append(val)
            stats["fc_pruned"] += len(pruned[other]) - len(kept)
            if not kept:
                return None
            pruned[other] = kept
        return pruned

    def backtrack(current: Dict[str, List[Assignment]]) -> bool:
        if len(assignment) == len(tasks):
            return True
        vid = select_variable(current)
        for value in current[vid]:  # earliest slot first
            if not consistent(vid, value):
                continue
            stats["assignments"] += 1
            assignment[vid] = value
            day = slot_day(value[1])
            day_load[day] = day_load.get(day, 0) + 1

            next_domains = current
            if use_forward_checking:
                next_domains = forward_check(vid, value, current)
            if next_domains is not None and backtrack(next_domains):
                return True

            day_load[day] -= 1
            del assignment[vid]
            stats["backtracks"] += 1
        return False

    solved = backtrack(domains)
    return (dict(assignment) if solved else None), stats


def solve_csp(
    case: Optional[CSPCase] = None,
    raise_on_infeasible: bool = False,
    use_mrv: bool = True,
    use_degree: bool = True,
    use_forward_checking: bool = True,
    use_ac3: bool = True,
) -> Dict[str, Any]:
    """Solve the remediation CSP using Backtracking search.

    If case is None, the case is built from upstream KNN predictions, the A* attack path
    and data/constraints.json via build_csp_case_from_pipeline().

    Returns a serializable result with the schedule, the CSP formulation, search statistics
    and metadata. If no schedule satisfies all constraints the status is "infeasible"
    (or ValueError is raised when raise_on_infeasible=True).
    """
    if case is None:
        case, metadata = build_csp_case_from_pipeline()
    else:
        metadata = {
            "source": "custom_or_mock",
            "selected_task_count": len(case.vulnerabilities),
            "total_evaluated_vulnerabilities": len(case.vulnerabilities),
            "pending_backlog_count": 0,
            "attack_path_systems": sorted({t.system_id for t in case.vulnerabilities if t.on_attack_path}),
        }

    validate_case(case)
    assignments, stats = _solve(case, use_mrv, use_degree, use_forward_checking, use_ac3)
    order = _topological_order(case)
    heuristics = [
        name for name, on in (
            ("MRV", use_mrv), ("Degree", use_mrv and use_degree),
            ("Forward Checking", use_forward_checking), ("AC-3", use_ac3),
        ) if on
    ]

    result: Dict[str, Any] = {
        "solver": "Backtracking CSP",
        "heuristics": heuristics,
        "objective": None,
        "variables": [task.vuln_id for task in order],
        "domains": {
            task.vuln_id: [
                {"team": task.required_team, "time_slot": slot}
                for slot in case.time_slots
                if _unary_ok(task, (task.required_team, slot), case)
            ]
            for task in order
        },
        "constraints": _constraint_descriptions(case),
        "stats": stats,
        "metadata": metadata,
    }

    if assignments is None:
        if raise_on_infeasible:
            raise ValueError("No feasible remediation schedule exists for this CSP case")
        result.update({
            "status": "infeasible",
            "schedule": [],
            "message": "No feasible remediation schedule exists satisfying all constraints.",
        })
        return result

    business_hours = case.constraints.business_hours if case.constraints else (9, 18)
    schedule = []
    for task in sorted(
        case.vulnerabilities,
        key=lambda item: (_slot_index(assignments[item.vuln_id][1], case.time_slots), item.required_team),
    ):
        team, slot = assignments[task.vuln_id]
        schedule.append({
            "vuln_id": task.vuln_id,
            "system_id": task.system_id,
            "priority": task.priority,
            "team": team,
            "time_slot": slot,
            "day": slot_day(slot),
            "window": "Business hours" if is_business_hours(slot, business_hours) else "After hours",
            "on_attack_path": task.on_attack_path,
            "depends_on": list(task.depends_on),
        })

    result.update({
        "status": "feasible",
        "schedule": schedule,
        "violations": verify_schedule(case, schedule),
    })
    return result


CSP_STRATEGIES = (
    ("Plain Backtracking", dict(use_mrv=False, use_degree=False, use_forward_checking=False, use_ac3=False)),
    ("Backtracking + MRV/Degree", dict(use_mrv=True, use_degree=True, use_forward_checking=False, use_ac3=False)),
    ("Backtracking + Forward Checking", dict(use_mrv=False, use_degree=False, use_forward_checking=True, use_ac3=False)),
    ("MRV/Degree + Forward Checking", dict(use_mrv=True, use_degree=True, use_forward_checking=True, use_ac3=False)),
    ("MRV/Degree + FC + AC-3", dict(use_mrv=True, use_degree=True, use_forward_checking=True, use_ac3=True)),
)


def compare_csp_strategies(case: Optional[CSPCase] = None) -> List[Dict[str, Any]]:
    """Solve the same case with each search strategy and report effort metrics."""
    if case is None:
        case, _ = build_csp_case_from_pipeline()
    rows = []
    for name, options in CSP_STRATEGIES:
        started = time.perf_counter()
        res = solve_csp(case, **options)
        elapsed_ms = round((time.perf_counter() - started) * 1000, 3)
        stats = res["stats"]
        rows.append({
            "strategy": name,
            "status": res["status"],
            "assignments": stats["assignments"],
            "backtracks": stats["backtracks"],
            "constraint_checks": stats["constraint_checks"],
            "pruned_values": stats["ac3_pruned"] + stats["fc_pruned"],
            "time_ms": elapsed_ms,
            "constraints_satisfied": res["status"] == "feasible" and not res["violations"],
        })
    return rows


def main() -> None:
    result = solve_csp()
    print(f"TraceWard CSP remediation plan — status: {result['status']}")
    for item in result["schedule"]:
        print(
            f"{item['time_slot']} ({item['window']}): {item['team']} -> "
            f"{item['vuln_id']} ({item['priority']}, {item['system_id']})"
        )
    for row in compare_csp_strategies():
        print(row)


if __name__ == "__main__":
    main()
