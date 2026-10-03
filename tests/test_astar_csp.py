import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.astar_search import (
    astar_search,
    bfs_search,
    edge_cost,
    enumerate_attack_paths,
    make_heuristic,
    ucs_search,
)
from src.csp_solver import (
    CSPCase,
    CSPConstraints,
    VulnerabilityTask,
    compare_csp_strategies,
    solve_csp,
    verify_schedule,
)
from src.graph_builder import build_graph


def toy_graph():
    """Proposal section 11 example: Path A cost 5, Path B cost 12."""
    edges = [
        ("INTERNET", "WEB", 1), ("WEB", "APP", 2), ("APP", "DB", 2),
        ("INTERNET", "EMP", 3), ("EMP", "INT", 4), ("INT", "APP", 3),
        ("INTERNET", "ISOLATED", 1),
    ]
    adjacency = {n: [] for n in ("INTERNET", "WEB", "APP", "DB", "EMP", "INT", "ISOLATED")}
    for u, v, _ in edges:
        adjacency[u].append(v)
    return {
        "adjacency": adjacency,
        "edges": [{"source": u, "target": v, "base_cost": c} for u, v, c in edges],
        # ease 0.5 -> multiplier 1.0, so edge cost == base_cost
        "risk_map": {n: 0.5 for n in adjacency},
        "exploit_map": {n: 0.5 for n in adjacency},
    }


class TestAStar(unittest.TestCase):
    def test_toy_graph_finds_proposal_path(self):
        res = astar_search(toy_graph(), "INTERNET", "DB")
        self.assertEqual(res["path"], ["INTERNET", "WEB", "APP", "DB"])
        self.assertEqual(res["total_cost"], 5.0)

    def test_heuristic_is_admissible_and_consistent(self):
        graph = build_graph()
        h = make_heuristic(graph, "DB01")
        for node in graph["adjacency"]:
            paths = enumerate_attack_paths(graph, node, "DB01") if node != "DB01" else [{"total_cost": 0}]
            if paths:
                self.assertLessEqual(h(node), paths[0]["total_cost"] + 1e-9)
            for nxt in graph["adjacency"][node]:
                if h(nxt) != float("inf"):
                    self.assertLessEqual(h(node), edge_cost(graph, node, nxt) + h(nxt) + 1e-9)

    def test_dead_end_is_pruned(self):
        h = make_heuristic(toy_graph(), "DB")
        self.assertEqual(h("ISOLATED"), float("inf"))

    def test_astar_matches_exhaustive_optimum_and_expands_less(self):
        graph = build_graph()
        best = enumerate_attack_paths(graph)[0]
        a = astar_search(graph)
        u = ucs_search(graph)
        self.assertEqual(a["path"], best["path"])
        self.assertAlmostEqual(a["total_cost"], best["total_cost"])
        self.assertAlmostEqual(u["total_cost"], best["total_cost"])
        self.assertLessEqual(a["nodes_expanded"], u["nodes_expanded"])

    def test_trace_and_hops_reported(self):
        res = astar_search(build_graph())
        self.assertEqual(res["trace"][-1]["node"], "DB01")
        for step in res["trace"]:
            self.assertAlmostEqual(step["f"], round(step["g"] + step["h"], 2), places=2)
        self.assertEqual(len(res["hops"]), len(res["path"]) - 1)
        self.assertAlmostEqual(sum(h["cost"] for h in res["hops"]), res["total_cost"], places=2)

    def test_bfs_finds_fewest_hops(self):
        res = bfs_search(toy_graph(), "INTERNET", "DB")
        self.assertEqual(len(res["path"]) - 1, 3)

    def test_higher_risk_lowers_edge_cost(self):
        graph = toy_graph()
        before = edge_cost(graph, "INTERNET", "WEB")
        graph["risk_map"]["WEB"] = 0.9
        self.assertLess(edge_cost(graph, "INTERNET", "WEB"), before)


def constrained_case():
    tasks = (
        VulnerabilityTask("V-WEB", "WEB01", "Critical", "Web Team", on_attack_path=True),
        VulnerabilityTask("V-APP", "APP01", "High", "Application Team", depends_on=("V-WEB",), on_attack_path=True),
        VulnerabilityTask("V-DB", "DB01", "Critical", "Database Team", depends_on=("V-APP",), on_attack_path=True),
        VulnerabilityTask("V-BAK", "BACKUP01", "High", "Database Team", depends_on=("V-DB",)),
        VulnerabilityTask("V-AUTH", "AUTH01", "Medium", "Network Team"),
    )
    return CSPCase(
        vulnerabilities=tasks,
        available_teams=("Web Team", "Application Team", "Database Team", "Network Team"),
        time_slots=("Mon 10:00", "Mon 15:00", "Mon 20:00", "Tue 10:00", "Tue 15:00", "Tue 20:00", "Wed 20:00"),
        constraints=CSPConstraints(
            after_hours_only_systems=("DB01", "BACKUP01", "AUTH01"),
            max_patches_per_day=3,
            no_concurrent_downtime=("DB01", "BACKUP01", "AUTH01"),
            attack_path_deadline="Mon 20:00",
        ),
    )


class TestCSP(unittest.TestCase):
    def test_constrained_case_is_feasible_and_verified(self):
        case = constrained_case()
        res = solve_csp(case)
        self.assertEqual(res["status"], "feasible")
        self.assertEqual(res["violations"], [])
        self.assertEqual(verify_schedule(case, res["schedule"]), [])
        slots = {item["vuln_id"]: item for item in res["schedule"]}
        self.assertEqual(slots["V-DB"]["window"], "After hours")
        self.assertEqual(slots["V-DB"]["time_slot"], "Mon 20:00")

    def test_daily_capacity_is_respected(self):
        res = solve_csp(constrained_case())
        per_day = {}
        for item in res["schedule"]:
            per_day[item["day"]] = per_day.get(item["day"], 0) + 1
        self.assertTrue(all(count <= 3 for count in per_day.values()))

    def test_all_strategies_agree_on_feasibility(self):
        rows = compare_csp_strategies(constrained_case())
        self.assertTrue(all(r["status"] == "feasible" and r["constraints_satisfied"] for r in rows))

    def test_maintenance_window_makes_case_infeasible(self):
        case = CSPCase(
            vulnerabilities=(VulnerabilityTask("V-DB", "DB01", "Critical", "Database Team"),),
            available_teams=("Database Team",),
            time_slots=("Mon 10:00", "Mon 15:00"),
            constraints=CSPConstraints(after_hours_only_systems=("DB01",)),
        )
        for options in ({}, {"use_mrv": False, "use_forward_checking": False, "use_ac3": False}):
            self.assertEqual(solve_csp(case, **options)["status"], "infeasible")

    def test_dependency_cycle_rejected(self):
        case = CSPCase(
            vulnerabilities=(
                VulnerabilityTask("A", "WEB01", "High", "Web Team", depends_on=("B",)),
                VulnerabilityTask("B", "WEB01", "High", "Web Team", depends_on=("A",)),
            ),
            available_teams=("Web Team",),
            time_slots=("Mon 10:00", "Mon 15:00"),
        )
        with self.assertRaises(ValueError):
            solve_csp(case)

    def test_verify_schedule_detects_violation(self):
        case = constrained_case()
        bad = [{"vuln_id": t.vuln_id, "team": t.required_team, "time_slot": "Mon 10:00"} for t in case.vulnerabilities]
        self.assertTrue(verify_schedule(case, bad))


if __name__ == "__main__":
    unittest.main()
