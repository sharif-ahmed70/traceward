import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.graph_builder import build_graph
from src.what_if_simulation import apply_actions, find_chokepoints, simulate_actions


class TestActionSimulator(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.graph = build_graph()

    def test_no_actions_is_unchanged(self):
        res = simulate_actions([], self.graph)
        self.assertEqual(res["outcome"], "unchanged")
        self.assertEqual(res["routes_before"], res["routes_after"])

    def test_isolating_chokepoint_blocks_attack(self):
        res = simulate_actions([{"type": "isolate", "system": "APP01"}], self.graph)
        self.assertEqual(res["outcome"], "blocked")
        self.assertIsNone(res["simulated"]["path"])
        self.assertEqual(res["routes_after"], 0)

    def test_cutting_connection_reroutes(self):
        res = simulate_actions([{"type": "block", "source": "WEB01", "target": "APP01"}], self.graph)
        self.assertEqual(res["outcome"], "rerouted")
        self.assertNotIn(("WEB01", "APP01"), list(zip(res["simulated"]["path"], res["simulated"]["path"][1:])))
        self.assertGreater(res["effort_change_pct"], 0)

    def test_patching_all_weaknesses_makes_attack_harder(self):
        vulns = list(self.graph["vuln_ease_map"]["WEB01"])
        res = simulate_actions([{"type": "patch", "system": "WEB01", "vuln_ids": vulns}], self.graph)
        self.assertEqual(res["outcome"], "harder")
        self.assertGreater(res["effort_change_pct"], 0)

    def test_actions_do_not_modify_original_graph(self):
        before = {k: list(v) for k, v in self.graph["adjacency"].items()}
        apply_actions(self.graph, [{"type": "isolate", "system": "WEB01"}])
        self.assertEqual(self.graph["adjacency"], before)

    def test_chokepoints(self):
        points = find_chokepoints(self.graph)
        self.assertEqual(points["hosts"], ["APP01"])
        self.assertIn(("APP01", "DB01"), points["connections"])

    def test_unknown_action_rejected(self):
        with self.assertRaises(ValueError):
            apply_actions(self.graph, [{"type": "reboot", "system": "WEB01"}])


if __name__ == "__main__":
    unittest.main()
