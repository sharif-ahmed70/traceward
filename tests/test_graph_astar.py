"""Unit tests for TraceWard Graph Builder and A* Search modules."""

import json
import tempfile
import unittest
from pathlib import Path

from src.graph_builder import build_graph, load_network_topology
from src.astar_search import astar_search, run_astar


class TestGraphAndAStar(unittest.TestCase):
    """Positive and boundary tests for Week 2 Graph + A* integration."""

    def test_load_topology_and_build_risk_aware_graph(self):
        """Positive test: Graph loads from network.json and attaches risk by system_id."""
        with tempfile.TemporaryDirectory() as tmpdir:
            risk_csv = Path(tmpdir) / "system_risk_summary.csv"
            risk_csv.write_text(
                "system_id,vulnerability_count,highest_risk,average_risk_score,normalized_risk,critical_count,high_or_critical_count\n"
                "WEB01,4,High,3.0,0.75,0,3\n"
                "APP01,5,Critical,3.6,0.90,2,4\n"
                "DB01,3,Critical,4.0,1.00,3,3\n",
                encoding="utf-8",
            )

            nodes, edges = load_network_topology("data/network/network.json")
            self.assertGreater(len(nodes), 0)
            self.assertGreater(len(edges), 0)

            graph = build_graph(
                network_path="data/network/network.json",
                risk_summary_path=str(risk_csv),
            )
            self.assertEqual(graph["risk_map"]["WEB01"], 0.75)
            self.assertEqual(graph["risk_map"]["APP01"], 0.90)
            self.assertEqual(graph["risk_map"]["DB01"], 1.00)

            out_json = Path(tmpdir) / "attack_path.json"
            result = run_astar(graph=graph, start="INTERNET", goal="DB01", output_path=str(out_json))

            self.assertEqual(result["start"], "INTERNET")
            self.assertEqual(result["goal"], "DB01")
            self.assertEqual(result["path"], ["INTERNET", "WEB01", "APP01", "DB01"])
            self.assertGreater(result["total_cost"], 0)
            self.assertTrue(out_json.exists())

            saved = json.loads(out_json.read_text(encoding="utf-8"))
            self.assertEqual(saved["path"], ["INTERNET", "WEB01", "APP01", "DB01"])

    def test_invalid_start_or_goal_raises_value_error(self):
        """Boundary/invalid-input test: Unknown start or goal node raises ValueError."""
        graph = build_graph()

        with self.assertRaises(ValueError):
            astar_search(graph, start="UNKNOWN_ENTRY", goal="DB01")

        with self.assertRaises(ValueError):
            astar_search(graph, start="INTERNET", goal="UNKNOWN_TARGET")


if __name__ == "__main__":
    unittest.main()
