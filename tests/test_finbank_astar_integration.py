"""Tests for FinBank attack scenario integration with A* path analysis.

Verifies that the A* module finds the expected simulated attack paths
for the FinBank topology and that the integration layer correctly
orchestrates scenario-driven path analysis.
"""

from __future__ import annotations

import unittest

from src.astar_search import astar_search
from src.finbank_network import build_finbank_graph
from src.finbank_astar_integration import (
    get_systems_on_path,
    get_vulnerabilities_on_path,
    run_all_finbank_scenario_paths,
    run_scenario_attack_path,
)
from src.finbank_assignment import assign_finbank_vulnerabilities


class TestFinBankAStarAttackPaths(unittest.TestCase):
    """A* must find expected simulated attack paths over the FinBank graph."""

    @classmethod
    def setUpClass(cls):
        cls.graph = build_finbank_graph()

    def test_internet_web01_app01_db01_path(self):
        result = astar_search(self.graph, start="INTERNET", goal="DB01")
        self.assertEqual(
            result["path"],
            ["INTERNET", "WEB01", "APP01", "DB01"],
        )

    def test_vpn01_auth01_app01_db01_path(self):
        result = astar_search(self.graph, start="VPN01", goal="DB01")
        self.assertEqual(
            result["path"],
            ["VPN01", "AUTH01", "APP01", "DB01"],
        )

    def test_internet_web01_app01_db01_backup01_path(self):
        result = astar_search(self.graph, start="INTERNET", goal="BACKUP01")
        self.assertEqual(
            result["path"],
            ["INTERNET", "WEB01", "APP01", "DB01", "BACKUP01"],
        )


class TestFinBankScenarioIntegrationPaths(unittest.TestCase):
    """Scenario-driven A* paths must match expected routes."""

    @classmethod
    def setUpClass(cls):
        cls.graph = build_finbank_graph()

    def test_customer_portal_compromise_attack_path(self):
        result = run_scenario_attack_path(
            "customer_portal_compromise", graph=self.graph
        )
        self.assertEqual(
            result["simulated_attack_path"],
            ["INTERNET", "WEB01", "APP01", "DB01"],
        )
        self.assertEqual(result["entry_point"], "INTERNET")
        self.assertEqual(result["target_critical_asset"], "DB01")
        self.assertEqual(
            result["risk_weighted_attack_path"],
            result["simulated_attack_path"],
        )

    def test_remote_access_compromise_attack_path(self):
        result = run_scenario_attack_path(
            "remote_access_compromise", graph=self.graph
        )
        self.assertEqual(result["entry_point"], "INTERNET")
        self.assertEqual(result["target_critical_asset"], "DB01")
        self.assertEqual(result["simulated_attack_path"][0], "INTERNET")
        self.assertEqual(result["simulated_attack_path"][-1], "DB01")

    def test_backup_targeting_attack_path(self):
        result = run_scenario_attack_path(
            "backup_targeting", graph=self.graph
        )
        self.assertEqual(
            result["simulated_attack_path"],
            ["INTERNET", "WEB01", "APP01", "DB01", "BACKUP01"],
        )
        self.assertEqual(result["entry_point"], "INTERNET")
        self.assertEqual(result["target_critical_asset"], "BACKUP01")


class TestFinBankIntegrationSystemsAlongPath(unittest.TestCase):
    """Systems along the attack path must be correctly identified."""

    @classmethod
    def setUpClass(cls):
        cls.graph = build_finbank_graph()

    def test_systems_along_web_to_db_path(self):
        result = run_scenario_attack_path(
            "customer_portal_compromise", graph=self.graph
        )
        systems = result["systems_along_path"]
        self.assertEqual(len(systems), 4)
        self.assertEqual(systems[0]["system_id"], "INTERNET")
        self.assertEqual(systems[-1]["system_id"], "DB01")
        self.assertEqual(systems[1]["display_name"], "Customer Web Portal")

    def test_get_systems_on_path_helper(self):
        path = ["INTERNET", "WEB01", "APP01", "DB01"]
        systems = get_systems_on_path(path)
        self.assertEqual(len(systems), 4)
        self.assertEqual(systems[0]["system_id"], "INTERNET")
        self.assertEqual(systems[-1]["system_id"], "DB01")
        for entry in systems:
            self.assertIn("display_name", entry)
            self.assertIn("criticality", entry)
            self.assertIn("internet_exposed", entry)


class TestFinBankIntegrationVulnerabilitiesAlongPath(unittest.TestCase):
    """Vulnerabilities along the attack path must be correctly identified."""

    @classmethod
    def setUpClass(cls):
        cls.graph = build_finbank_graph()
        cls.inventory = assign_finbank_vulnerabilities()

    def test_vulnerabilities_along_web_to_db_path(self):
        result = run_scenario_attack_path(
            "customer_portal_compromise",
            graph=self.graph,
            include_vulnerabilities=True,
            inventory=self.inventory,
        )
        self.assertIn("vulnerabilities_along_path", result)
        vulns = result["vulnerabilities_along_path"]
        self.assertEqual(len(vulns), 4)
        for entry in vulns:
            self.assertIn("system_id", entry)
            self.assertIn("vulnerability_count", entry)
            self.assertIn("vulnerability_ids", entry)

    def test_get_vulnerabilities_on_path_helper(self):
        path = ["INTERNET", "WEB01", "APP01", "DB01"]
        vulns = get_vulnerabilities_on_path(path, self.inventory)
        self.assertEqual(len(vulns), 4)
        for entry in vulns:
            self.assertIn("system_id", entry)
            self.assertIn("vulnerability_count", entry)


class TestFinBankIntegrationAllScenarios(unittest.TestCase):
    """All FinBank scenarios must produce valid A* attack paths."""

    @classmethod
    def setUpClass(cls):
        cls.graph = build_finbank_graph()
        cls.results = run_all_finbank_scenario_paths(graph=cls.graph)

    def test_all_scenarios_return_paths(self):
        self.assertEqual(len(self.results), 4)

    def test_all_paths_start_with_entry_point(self):
        for result in self.results:
            self.assertEqual(result["simulated_attack_path"][0], result["entry_point"])

    def test_all_paths_end_with_critical_asset(self):
        for result in self.results:
            self.assertEqual(
                result["simulated_attack_path"][-1], result["target_critical_asset"]
            )

    def test_all_paths_have_cost(self):
        for result in self.results:
            self.assertGreater(result["total_risk_cost"], 0.0)

    def test_all_paths_have_systems(self):
        for result in self.results:
            self.assertGreater(len(result["systems_along_path"]), 0)


class TestFinBankIntegrationTerminology(unittest.TestCase):
    """Result dict must use simulated/risk-weighted attack path terminology."""

    @classmethod
    def setUpClass(cls):
        cls.graph = build_finbank_graph()

    def test_result_contains_simulated_attack_path_key(self):
        result = run_scenario_attack_path(
            "customer_portal_compromise", graph=self.graph
        )
        self.assertIn("simulated_attack_path", result)

    def test_result_contains_risk_weighted_attack_path_key(self):
        result = run_scenario_attack_path(
            "customer_portal_compromise", graph=self.graph
        )
        self.assertIn("risk_weighted_attack_path", result)

    def test_result_contains_entry_point_and_critical_asset(self):
        result = run_scenario_attack_path(
            "customer_portal_compromise", graph=self.graph
        )
        self.assertIn("entry_point", result)
        self.assertIn("target_critical_asset", result)

    def test_result_contains_systems_along_path(self):
        result = run_scenario_attack_path(
            "customer_portal_compromise", graph=self.graph
        )
        self.assertIn("systems_along_path", result)


if __name__ == "__main__":
    unittest.main()
