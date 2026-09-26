"""Comprehensive integration tests for the FinBank simulation pipeline.

Covers all 12 requested areas:
  1. FinBank environment
  2. topology
  3. vulnerability assignment
  4. attack scenarios
  5. event generation
  6. incident correlation
  7. KNN integration
  8. operational predictions
  9. attack path
  10. remediation plan
  11. what-if simulation
  12. end-to-end simulation
"""

from __future__ import annotations

import unittest
from pathlib import Path

from src.attack_simulator.scenarios import build_finbank_scenarios, get_finbank_scenario
from src.attack_simulator.simulator import simulate_finbank_attack
from src.finbank_assignment import assign_finbank_vulnerabilities
from src.finbank_astar_integration import run_scenario_attack_path
from src.finbank_csp_planner import run_finbank_remediation_plan
from src.finbank_env import load_finbank_systems, validate_finbank_systems
from src.finbank_network import build_finbank_graph, load_finbank_network
from src.finbank_predictor import predict_full_inventory
from src.finbank_simulation import run_finbank_simulation
from src.incident_correlator import correlate_single_scenario
from src.risk_engine import build_system_risk_summary
from src.what_if_simulation import simulate_patch_impact


class TestFinBankEnvironment(unittest.TestCase):
    """1. FinBank environment."""

    def test_environment_loads_without_error(self):
        systems = load_finbank_systems()
        self.assertIsInstance(systems, dict)
        self.assertTrue(len(systems) > 0)

    def test_environment_validation_succeeds(self):
        systems = load_finbank_systems()
        validate_finbank_systems(systems)

    def test_environment_contains_required_systems(self):
        systems = load_finbank_systems()
        required = {
            "INTERNET",
            "WEB01",
            "APP01",
            "AUTH01",
            "VPN01",
            "EMP01",
            "DB01",
            "BACKUP01",
        }
        self.assertSetEqual(required, set(systems.keys()))

    def test_environment_fields_are_present(self):
        systems = load_finbank_systems()
        for system_id, entry in systems.items():
            self.assertIn("system_id", entry)
            self.assertIn("display_name", entry)
            self.assertIn("type", entry)
            self.assertIn("criticality", entry)
            self.assertIn("internet_exposed", entry)
            self.assertIn("description", entry)

    def test_environment_does_not_mutate_on_load(self):
        path = "data/finbank/finbank_systems.json"
        original = Path(path).read_text(encoding="utf-8")
        load_finbank_systems()
        current = Path(path).read_text(encoding="utf-8")
        self.assertEqual(original, current)


class TestFinBankTopology(unittest.TestCase):
    """2. Topology."""

    def test_network_loads_without_error(self):
        network = load_finbank_network()
        self.assertIn("nodes", network)
        self.assertIn("edges", network)

    def test_graph_builds_without_error(self):
        graph = build_finbank_graph()
        self.assertIn("nodes", graph)
        self.assertIn("edges", graph)
        self.assertIn("adjacency", graph)
        self.assertIn("risk_map", graph)

    def test_topology_contains_expected_nodes(self):
        network = load_finbank_network()
        node_ids = {str(node["id"]) for node in network["nodes"]}
        expected = {
            "INTERNET", "WEB01", "APP01", "AUTH01", "VPN01", "EMP01", "DB01", "BACKUP01"
        }
        self.assertSetEqual(expected, node_ids)

    def test_topology_contains_expected_edges(self):
        network = load_finbank_network()
        edges = {(str(e["source"]), str(e["target"])) for e in network["edges"]}
        expected_edges = {
            ("INTERNET", "WEB01"),
            ("INTERNET", "VPN01"),
            ("WEB01", "APP01"),
            ("APP01", "AUTH01"),
            ("APP01", "DB01"),
            ("VPN01", "AUTH01"),
            ("AUTH01", "APP01"),
            ("EMP01", "AUTH01"),
            ("DB01", "BACKUP01"),
        }
        self.assertSetEqual(expected_edges, edges)

    def test_topology_file_is_not_mutated(self):
        path = Path("data/finbank/network.json")
        original = path.read_text(encoding="utf-8")
        build_finbank_graph()
        current = path.read_text(encoding="utf-8")
        self.assertEqual(original, current)


class TestFinBankVulnerabilityAssignment(unittest.TestCase):
    """3. Vulnerability assignment."""

    def test_assignment_produces_1200_records(self):
        df = assign_finbank_vulnerabilities()
        self.assertEqual(len(df), 1200)

    def test_assignment_preserves_vulnerability_ids(self):
        import pandas as pd
        original = pd.read_csv("data/raw/vulnerabilities.csv", keep_default_na=False)
        assigned = assign_finbank_vulnerabilities()
        self.assertListEqual(original["vuln_id"].tolist(), assigned["vuln_id"].tolist())

    def test_assignment_uses_only_valid_systems(self):
        from src.finbank_env import _default_finbank_systems
        valid_systems = set(_default_finbank_systems().keys())
        df = assign_finbank_vulnerabilities()
        assigned_systems = set(df["system_id"].tolist())
        invalid = assigned_systems - valid_systems
        self.assertFalse(invalid, f"Invalid system_ids: {invalid}")

    def test_assignment_is_deterministic(self):
        df1 = assign_finbank_vulnerabilities()
        df2 = assign_finbank_vulnerabilities()
        import pandas as pd
        pd.testing.assert_frame_equal(df1, df2)

    def test_assignment_has_required_columns(self):
        df = assign_finbank_vulnerabilities()
        required = {
            "vuln_id", "system_id", "risk_label", "description",
            "attack_complexity", "privileges_required", "user_interaction",
            "confidentiality_impact", "integrity_impact", "availability_impact",
            "exploit_probability",
        }
        self.assertTrue(required.issubset(set(df.columns)))


class TestFinBankAttackScenarios(unittest.TestCase):
    """4. Attack scenarios."""

    def test_four_scenarios_exist(self):
        scenarios = build_finbank_scenarios()
        self.assertEqual(len(scenarios), 4)

    def test_required_scenario_ids_exist(self):
        scenarios = build_finbank_scenarios()
        by_id = {s.scenario_id: s for s in scenarios}
        required = {
            "customer_portal_compromise",
            "employee_compromise",
            "remote_access_compromise",
            "backup_targeting",
        }
        self.assertSetEqual(required, set(by_id.keys()))

    def test_customer_portal_compromise_path(self):
        scenario = get_finbank_scenario("customer_portal_compromise")
        self.assertEqual(scenario.target_systems, ("WEB01", "APP01", "DB01"))

    def test_employee_compromise_path(self):
        scenario = get_finbank_scenario("employee_compromise")
        self.assertEqual(scenario.target_systems, ("EMP01", "AUTH01", "APP01", "DB01"))

    def test_remote_access_compromise_path(self):
        scenario = get_finbank_scenario("remote_access_compromise")
        self.assertEqual(scenario.target_systems, ("VPN01", "AUTH01", "APP01", "DB01"))

    def test_backup_targeting_path(self):
        scenario = get_finbank_scenario("backup_targeting")
        self.assertEqual(scenario.target_systems, ("WEB01", "APP01", "DB01", "BACKUP01"))

    def test_scenarios_are_deterministic(self):
        first = build_finbank_scenarios()
        second = build_finbank_scenarios()
        self.assertEqual(len(first), len(second))
        for a, b in zip(first, second):
            self.assertEqual(a.scenario_id, b.scenario_id)
            self.assertEqual(a.target_systems, b.target_systems)
            self.assertEqual(len(a.events), len(b.events))


class TestFinBankEventGeneration(unittest.TestCase):
    """5. Event generation."""

    def test_events_have_required_columns(self):
        inventory = assign_finbank_vulnerabilities()
        df = simulate_finbank_attack("customer_portal_compromise", inventory=inventory)
        required = {
            "event_id", "scenario_id", "timestamp", "source", "target",
            "event_type", "vulnerability_id", "severity", "description",
        }
        self.assertTrue(required.issubset(set(df.columns)))

    def test_event_count_matches_scenario_steps(self):
        inventory = assign_finbank_vulnerabilities()
        df = simulate_finbank_attack("customer_portal_compromise", inventory=inventory)
        self.assertEqual(len(df), 3)

    def test_event_timestamps_are_increasing(self):
        inventory = assign_finbank_vulnerabilities()
        df = simulate_finbank_attack("customer_portal_compromise", inventory=inventory)
        self.assertTrue((df["timestamp"].diff().iloc[1:] > 0).all())

    def test_event_sources_and_targets_are_valid_systems(self):
        inventory = assign_finbank_vulnerabilities()
        df = simulate_finbank_attack("customer_portal_compromise", inventory=inventory)
        valid_systems = {
            "INTERNET", "WEB01", "APP01", "AUTH01", "VPN01", "EMP01", "DB01", "BACKUP01"
        }
        invalid_sources = set(df["source"]) - valid_systems
        invalid_targets = set(df["target"]) - valid_systems
        self.assertFalse(invalid_sources, f"Invalid sources: {invalid_sources}")
        self.assertFalse(invalid_targets, f"Invalid targets: {invalid_targets}")

    def test_event_descriptions_are_non_empty(self):
        inventory = assign_finbank_vulnerabilities()
        df = simulate_finbank_attack("customer_portal_compromise", inventory=inventory)
        self.assertTrue((df["description"].astype(str).str.strip() != "").all())

    def test_event_generation_is_deterministic(self):
        inventory = assign_finbank_vulnerabilities()
        df1 = simulate_finbank_attack("customer_portal_compromise", inventory=inventory)
        df2 = simulate_finbank_attack("customer_portal_compromise", inventory=inventory)
        import pandas as pd
        pd.testing.assert_frame_equal(df1, df2)


class TestFinBankIncidentCorrelation(unittest.TestCase):
    """6. Incident correlation."""

    def test_one_incident_per_scenario(self):
        inventory = assign_finbank_vulnerabilities()
        events = simulate_finbank_attack("customer_portal_compromise", inventory=inventory)
        incidents = correlate_single_scenario("customer_portal_compromise", events, inventory)
        self.assertIsNotNone(incidents)

    def test_incident_entry_point_matches_first_event_source(self):
        inventory = assign_finbank_vulnerabilities()
        events = simulate_finbank_attack("customer_portal_compromise", inventory=inventory)
        incident = correlate_single_scenario("customer_portal_compromise", events, inventory)
        self.assertEqual(incident.entry_point, events.iloc[0]["source"])

    def test_incident_affected_systems_match_event_targets(self):
        inventory = assign_finbank_vulnerabilities()
        events = simulate_finbank_attack("employee_compromise", inventory=inventory)
        incident = correlate_single_scenario("employee_compromise", events, inventory)
        event_targets = set(events["target"].tolist())
        for system_id in incident.affected_systems:
            self.assertIn(system_id, event_targets)

    def test_incident_related_vulnerabilities_are_valid(self):
        inventory = assign_finbank_vulnerabilities()
        valid_vuln_ids = set(inventory["vuln_id"].tolist())
        events = simulate_finbank_attack("backup_targeting", inventory=inventory)
        incident = correlate_single_scenario("backup_targeting", events, inventory)
        invalid = set(incident.related_vulnerabilities) - valid_vuln_ids
        self.assertFalse(invalid, f"Invalid vuln_ids: {invalid}")

    def test_incident_critical_assets_are_subset_of_affected_systems(self):
        inventory = assign_finbank_vulnerabilities()
        events = simulate_finbank_attack("backup_targeting", inventory=inventory)
        incident = correlate_single_scenario("backup_targeting", events, inventory)
        affected_set = set(incident.affected_systems)
        for asset in incident.critical_assets_affected:
            self.assertIn(asset, affected_set)


class TestFinBankKNNIntegration(unittest.TestCase):
    """7. KNN integration."""

    def test_predictions_contain_required_columns(self):
        predictions = predict_full_inventory()
        required = {"vuln_id", "system_id", "predicted_risk"}
        self.assertTrue(required.issubset(set(predictions.columns)))

    def test_predictions_have_1200_rows(self):
        predictions = predict_full_inventory()
        self.assertEqual(len(predictions), 1200)

    def test_predictions_use_valid_risk_labels(self):
        predictions = predict_full_inventory()
        valid_labels = {"Low", "Medium", "High", "Critical"}
        invalid = set(predictions["predicted_risk"]) - valid_labels
        self.assertFalse(invalid, f"Invalid labels: {invalid}")

    def test_predictions_are_deterministic(self):
        df1 = predict_full_inventory()
        df2 = predict_full_inventory()
        import pandas as pd
        pd.testing.assert_frame_equal(df1, df2)


class TestFinBankOperationalPredictions(unittest.TestCase):
    """8. Operational predictions."""

    def test_operational_predictions_cover_full_inventory(self):
        predictions = predict_full_inventory()
        self.assertEqual(len(predictions), 1200)

    def test_operational_predictions_have_unique_vuln_ids(self):
        predictions = predict_full_inventory()
        self.assertEqual(predictions["vuln_id"].nunique(), 1200)

    def test_operational_predictions_file_is_created(self):
        from src.finbank_predictor import OUTPUT_PREDICTIONS_PATH
        predict_full_inventory()
        self.assertTrue(OUTPUT_PREDICTIONS_PATH.exists())


class TestFinBankAttackPath(unittest.TestCase):
    """9. Attack path."""

    def test_customer_portal_compromise_path(self):
        graph = build_finbank_graph()
        result = run_scenario_attack_path("customer_portal_compromise", graph=graph)
        self.assertEqual(
            result["simulated_attack_path"],
            ["INTERNET", "WEB01", "APP01", "DB01"],
        )

    def test_backup_targeting_path(self):
        graph = build_finbank_graph()
        result = run_scenario_attack_path("backup_targeting", graph=graph)
        self.assertEqual(
            result["simulated_attack_path"],
            ["INTERNET", "WEB01", "APP01", "DB01", "BACKUP01"],
        )

    def test_attack_path_has_positive_cost(self):
        graph = build_finbank_graph()
        result = run_scenario_attack_path("customer_portal_compromise", graph=graph)
        self.assertGreater(result["total_risk_cost"], 0.0)

    def test_attack_path_start_matches_entry_point(self):
        graph = build_finbank_graph()
        result = run_scenario_attack_path("remote_access_compromise", graph=graph)
        self.assertEqual(result["simulated_attack_path"][0], result["entry_point"])

    def test_attack_path_end_matches_target(self):
        graph = build_finbank_graph()
        result = run_scenario_attack_path("remote_access_compromise", graph=graph)
        self.assertEqual(result["simulated_attack_path"][-1], result["target_critical_asset"])


class TestFinBankRemediationPlan(unittest.TestCase):
    """10. Remediation plan."""

    def test_customer_portal_compromise_plan_is_feasible(self):
        inventory = assign_finbank_vulnerabilities()
        events = simulate_finbank_attack("customer_portal_compromise", inventory=inventory)
        incident = correlate_single_scenario("customer_portal_compromise", events, inventory)
        attack_path = ["INTERNET", "WEB01", "APP01", "DB01"]
        result = run_finbank_remediation_plan(incident, inventory, attack_path)
        self.assertEqual(result["status"], "feasible")

    def test_remediation_schedule_has_expected_keys(self):
        inventory = assign_finbank_vulnerabilities()
        events = simulate_finbank_attack("customer_portal_compromise", inventory=inventory)
        incident = correlate_single_scenario("customer_portal_compromise", events, inventory)
        attack_path = ["INTERNET", "WEB01", "APP01", "DB01"]
        result = run_finbank_remediation_plan(incident, inventory, attack_path)
        for item in result["schedule"]:
            for key in ("vuln_id", "system_id", "priority", "team", "time_slot", "depends_on"):
                self.assertIn(key, item)

    def test_remediation_has_no_team_slot_conflicts(self):
        inventory = assign_finbank_vulnerabilities()
        events = simulate_finbank_attack("customer_portal_compromise", inventory=inventory)
        incident = correlate_single_scenario("customer_portal_compromise", events, inventory)
        attack_path = ["INTERNET", "WEB01", "APP01", "DB01"]
        result = run_finbank_remediation_plan(incident, inventory, attack_path)
        assignments = [(item["team"], item["time_slot"]) for item in result["schedule"]]
        self.assertEqual(len(assignments), len(set(assignments)))

    def test_remediation_dependencies_are_valid(self):
        inventory = assign_finbank_vulnerabilities()
        events = simulate_finbank_attack("customer_portal_compromise", inventory=inventory)
        incident = correlate_single_scenario("customer_portal_compromise", events, inventory)
        attack_path = ["INTERNET", "WEB01", "APP01", "DB01"]
        result = run_finbank_remediation_plan(incident, inventory, attack_path)
        vuln_ids = {item["vuln_id"] for item in result["schedule"]}
        for item in result["schedule"]:
            for dep in item.get("depends_on", []):
                self.assertIn(dep, vuln_ids)


class TestFinBankWhatIfSimulation(unittest.TestCase):
    """11. What-if simulation."""

    def test_patch_impact_on_path_increases_cost(self):
        res = simulate_patch_impact("WEB01", risk_reduction_factor=0.5)
        self.assertEqual(res["status"], "success")
        self.assertGreater(res["simulated"]["path_cost"], res["baseline"]["path_cost"])

    def test_patch_impact_reduces_risk(self):
        res = simulate_patch_impact("APP01", risk_reduction_factor=0.5)
        self.assertLess(res["simulated"]["system_risk"]["normalized_risk"], res["baseline"]["system_risk"]["normalized_risk"])

    def test_patch_impact_does_not_mutate_baseline(self):
        import pandas as pd
        risk_path = Path("artifacts/risk/system_risk_summary.csv")
        before = pd.read_csv(risk_path)
        simulate_patch_impact("DB01", risk_reduction_factor=0.5)
        after = pd.read_csv(risk_path)
        pd.testing.assert_frame_equal(before, after)

    def test_patch_impact_invalid_system_raises(self):
        with self.assertRaises(ValueError):
            simulate_patch_impact("NON_EXISTENT_SYSTEM")

    def test_patch_impact_deltas_are_consistent(self):
        res = simulate_patch_impact("WEB01", risk_reduction_factor=0.5)
        base_risk = res["baseline"]["system_risk"]["normalized_risk"]
        sim_risk = res["simulated"]["system_risk"]["normalized_risk"]
        self.assertAlmostEqual(res["deltas"]["risk_reduction"], base_risk - sim_risk, places=3)


class TestFinBankEndToEndSimulation(unittest.TestCase):
    """12. End-to-end simulation."""

    def test_all_four_scenarios_run_successfully(self):
        for scenario_id in (
            "customer_portal_compromise",
            "employee_compromise",
            "remote_access_compromise",
            "backup_targeting",
        ):
            with self.subTest(scenario_id=scenario_id):
                result = run_finbank_simulation(scenario_id)
                self.assertIsInstance(result.scenario, dict)
                self.assertIsInstance(result.events, list)
                self.assertIsInstance(result.incident, dict)
                self.assertIsInstance(result.affected_systems, list)
                self.assertIsInstance(result.related_vulnerabilities, list)
                self.assertIsInstance(result.predicted_risks, list)
                self.assertIsInstance(result.attack_path, dict)
                self.assertIsInstance(result.remediation_plan, dict)

    def test_end_to_end_scenario_consistency(self):
        result = run_finbank_simulation("customer_portal_compromise")

        self.assertEqual(result.scenario["scenario_id"], "customer_portal_compromise")
        self.assertEqual(result.incident["scenario_id"], "customer_portal_compromise")
        for event in result.events:
            self.assertEqual(event["scenario_id"], "customer_portal_compromise")

    def test_end_to_end_no_network_requests(self):
        import socket
        original_socket = socket.socket
        socket_calls = []

        def tracking_socket(*args, **kwargs):
            socket_calls.append((args, kwargs))
            return original_socket(*args, **kwargs)

        socket.socket = tracking_socket
        try:
            run_finbank_simulation("customer_portal_compromise")
        finally:
            socket.socket = original_socket
        self.assertFalse(socket_calls, "Simulation made network requests")

    def test_end_to_end_does_not_mutate_input_data(self):
        risk_path = Path("artifacts/risk/system_risk_summary.csv")
        before = risk_path.read_text(encoding="utf-8")
        run_finbank_simulation("customer_portal_compromise")
        after = risk_path.read_text(encoding="utf-8")
        self.assertEqual(before, after)

    def test_end_to_end_remediation_plan_is_feasible(self):
        for scenario_id in (
            "customer_portal_compromise",
            "employee_compromise",
            "remote_access_compromise",
            "backup_targeting",
        ):
            with self.subTest(scenario_id=scenario_id):
                result = run_finbank_simulation(scenario_id)
                self.assertEqual(result.remediation_plan["status"], "feasible")


if __name__ == "__main__":
    unittest.main()
