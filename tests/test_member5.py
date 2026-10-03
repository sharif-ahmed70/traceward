import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.csp_solver import solve_csp
from src.explainability import explain_attack_path, explain_patch_priority, explain_risk


class TestMember5(unittest.TestCase):
    def test_csp_returns_feasible_schedule(self):
        result = solve_csp()
        self.assertEqual(result["status"], "feasible")
        self.assertIsNone(result["objective"])
        self.assertEqual(len(result["schedule"]), result["metadata"]["selected_task_count"])
        self.assertEqual(result["violations"], [])

        occupied = [(item["team"], item["time_slot"]) for item in result["schedule"]]
        self.assertEqual(len(occupied), len(set(occupied)))

    def test_csp_dependencies_are_ordered(self):
        result = solve_csp()
        from src.csp_solver import load_constraint_config
        index = {slot: i for i, slot in enumerate(load_constraint_config()["time_slots"])}
        slots = {item["vuln_id"]: index[item["time_slot"]] for item in result["schedule"]}
        has_deps = False
        for item in result["schedule"]:
            for dep in item.get("depends_on", []):
                has_deps = True
                self.assertLess(slots[dep], slots[item["vuln_id"]])
        self.assertTrue(has_deps, "Expected at least one scheduled task to have prerequisite dependencies")

    def test_explainability_contracts(self):
        risk = explain_risk("VULN-001", "WEB01", "Critical", risk_factors=["High severity"])
        path = explain_attack_path("INTERNET", "DB01", ["INTERNET", "WEB01", "DB01"], 5.0)
        patch = explain_patch_priority("VULN-001", "WEB01", "Critical", scheduled_slot="Mon 09:00", team="Web Team")

        self.assertEqual(risk["decision"], "Critical")
        self.assertEqual(path["path"][-1], "DB01")
        self.assertEqual(patch["priority"], "Critical")


if __name__ == "__main__":
    unittest.main()
