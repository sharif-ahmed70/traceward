"""Integration and artifact tests for the unified FinBank simulation service."""

from __future__ import annotations

import json
import shutil
import unittest
from pathlib import Path

from src.finbank_simulation import (
    ALL_SCENARIO_IDS,
    ATTACK_PATHS_DIR,
    ARTIFACTS_BASE,
    EVENTS_DIR,
    INCIDENTS_DIR,
    REMEDIATION_PLANS_DIR,
    SCENARIO_DIR,
    SimulationResult,
    regenerate_all_finbank_artifacts,
    run_finbank_simulation,
    save_simulation_artifacts,
)
from src.finbank_assignment import assign_finbank_vulnerabilities


class TestFinBankSimulationIntegration(unittest.TestCase):
    """Run complete scenarios through the unified simulation pipeline."""

    def test_all_scenarios_produce_complete_results(self):
        for scenario_id in ALL_SCENARIO_IDS:
            with self.subTest(scenario_id=scenario_id):
                result = run_finbank_simulation(scenario_id)
                self.assertIsInstance(result, SimulationResult)
                self.assertEqual(result.scenario["scenario_id"], scenario_id)
                self.assertTrue(len(result.events) > 0)
                self.assertIn("incident_id", result.incident)
                self.assertTrue(len(result.affected_systems) > 0)
                self.assertTrue(len(result.related_vulnerabilities) > 0)
                self.assertTrue(len(result.predicted_risks) > 0)
                self.assertIn("simulated_attack_path", result.attack_path)
                self.assertIn("status", result.remediation_plan)

    def test_customer_portal_compromise_produces_expected_path(self):
        result = run_finbank_simulation("customer_portal_compromise")

        self.assertEqual(result.scenario["scenario_id"], "customer_portal_compromise")
        self.assertIn("WEB01", result.affected_systems)
        self.assertIn("APP01", result.affected_systems)
        self.assertIn("DB01", result.affected_systems)
        self.assertEqual(result.attack_path["entry_point"], "INTERNET")
        self.assertEqual(result.attack_path["target_critical_asset"], "DB01")
        self.assertEqual(
            result.attack_path["simulated_attack_path"][0], "INTERNET"
        )
        self.assertEqual(
            result.attack_path["simulated_attack_path"][-1], "DB01"
        )

    def test_backup_targeting_includes_backup01(self):
        result = run_finbank_simulation("backup_targeting")

        self.assertIn("BACKUP01", result.affected_systems)
        self.assertEqual(
            result.attack_path["target_critical_asset"], "BACKUP01"
        )
        self.assertEqual(
            result.attack_path["simulated_attack_path"][-1], "BACKUP01"
        )

    def test_employee_compromise_path(self):
        result = run_finbank_simulation("employee_compromise")

        self.assertIn("EMP01", result.affected_systems)
        self.assertIn("AUTH01", result.affected_systems)
        self.assertEqual(result.attack_path["entry_point"], "INTERNET")

    def test_remote_access_compromise_path(self):
        result = run_finbank_simulation("remote_access_compromise")

        self.assertIn("VPN01", result.affected_systems)
        self.assertIn("AUTH01", result.affected_systems)
        self.assertEqual(result.attack_path["entry_point"], "INTERNET")

    def test_simulation_is_deterministic(self):
        result1 = run_finbank_simulation("customer_portal_compromise")
        result2 = run_finbank_simulation("customer_portal_compromise")

        self.assertEqual(result1.scenario, result2.scenario)
        self.assertEqual(result1.events, result2.events)
        self.assertEqual(result1.incident, result2.incident)
        self.assertEqual(
            result1.affected_systems, result2.affected_systems
        )
        self.assertEqual(
            result1.related_vulnerabilities, result2.related_vulnerabilities
        )
        self.assertEqual(result1.predicted_risks, result2.predicted_risks)
        self.assertEqual(result1.attack_path, result2.attack_path)
        self.assertEqual(
            result1.remediation_plan, result2.remediation_plan
        )

    def test_predicted_risks_use_valid_labels(self):
        valid_labels = {"Low", "Medium", "High", "Critical"}
        result = run_finbank_simulation("customer_portal_compromise")
        for prediction in result.predicted_risks:
            self.assertIn(
                prediction["predicted_risk"],
                valid_labels,
            )

    def test_remediation_plan_is_feasible(self):
        for scenario_id in ALL_SCENARIO_IDS:
            with self.subTest(scenario_id=scenario_id):
                result = run_finbank_simulation(scenario_id)
                self.assertEqual(
                    result.remediation_plan["status"], "feasible"
                )
                self.assertTrue(
                    len(result.remediation_plan["schedule"]) > 0
                )

    def test_affected_systems_are_subset_of_attack_path(self):
        result = run_finbank_simulation("customer_portal_compromise")
        attack_path_set = set(
            s for s in result.attack_path["simulated_attack_path"] if s != "INTERNET"
        )
        for system_id in result.affected_systems:
            self.assertIn(system_id, attack_path_set)


class TestFinBankArtifactGeneration(unittest.TestCase):
    """Verify FinBank simulation artifacts are generated correctly."""

    def setUp(self):
        for d in (
            SCENARIO_DIR,
            EVENTS_DIR,
            INCIDENTS_DIR,
            ATTACK_PATHS_DIR,
            REMEDIATION_PLANS_DIR,
        ):
            if d.exists():
                shutil.rmtree(d)
            d.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        for d in (
            SCENARIO_DIR,
            EVENTS_DIR,
            INCIDENTS_DIR,
            ATTACK_PATHS_DIR,
            REMEDIATION_PLANS_DIR,
        ):
            if d.exists():
                shutil.rmtree(d)

    def test_save_simulation_artifacts_creates_readable_json_files(self):
        result = run_finbank_simulation("customer_portal_compromise")
        paths = save_simulation_artifacts(result, "customer_portal_compromise")

        dir_map = {
            "scenario": SCENARIO_DIR,
            "events": EVENTS_DIR,
            "incident": INCIDENTS_DIR,
            "attack_path": ATTACK_PATHS_DIR,
            "remediation_plan": REMEDIATION_PLANS_DIR,
        }
        for name, path in paths.items():
            self.assertTrue(
                path.exists(), f"{name} artifact not created: {path}"
            )
            self.assertTrue(
                path.is_file(), f"{name} artifact is not a file: {path}"
            )
            self.assertEqual(
                path.parent, dir_map[name], f"{name} artifact in wrong directory"
            )

            data = json.loads(path.read_text(encoding="utf-8"))
            if name == "scenario":
                self.assertIn("scenario_id", data)
            elif name == "events":
                self.assertIsInstance(data, list)
                self.assertTrue(len(data) > 0)
            elif name == "incident":
                self.assertIn("incident_id", data)
            elif name == "attack_path":
                self.assertIn("simulated_attack_path", data)
            elif name == "remediation_plan":
                self.assertIn("status", data)

    def test_regenerate_all_artifacts_creates_all_scenarios(self):
        saved = regenerate_all_finbank_artifacts()

        self.assertEqual(set(saved.keys()), set(ALL_SCENARIO_IDS))
        for sid in ALL_SCENARIO_IDS:
            for name in (
                "scenario",
                "events",
                "incident",
                "attack_path",
                "remediation_plan",
            ):
                self.assertTrue(
                    saved[sid][name].exists(),
                    f"Missing {name} for {sid}",
                )

            scenario_data = json.loads(
                saved[sid]["scenario"].read_text(encoding="utf-8")
            )
            self.assertEqual(
                scenario_data["scenario_id"], sid, f"Wrong scenario ID in {sid}"
            )

    def test_regenerate_all_artifacts_is_deterministic(self):
        saved1 = regenerate_all_finbank_artifacts()
        saved2 = regenerate_all_finbank_artifacts()

        for sid in ALL_SCENARIO_IDS:
            for name in (
                "scenario",
                "events",
                "incident",
                "attack_path",
                "remediation_plan",
            ):
                p1 = saved1[sid][name]
                p2 = saved2[sid][name]
                self.assertEqual(
                    p1.read_text(encoding="utf-8"),
                    p2.read_text(encoding="utf-8"),
                    f"Determinism failed for {sid}/{name}",
                )

    def test_regenerate_subset_of_scenarios(self):
        saved = regenerate_all_finbank_artifacts(
            ("customer_portal_compromise", "backup_targeting")
        )

        self.assertEqual(
            set(saved.keys()),
            {"customer_portal_compromise", "backup_targeting"},
        )
        self.assertTrue(
            (SCENARIO_DIR / "customer_portal_compromise.json").exists()
        )
        self.assertTrue((SCENARIO_DIR / "backup_targeting.json").exists())
        self.assertFalse((SCENARIO_DIR / "employee_compromise.json").exists())

    def test_saved_artifacts_reside_in_new_finbank_tree(self):
        result = run_finbank_simulation("customer_portal_compromise")
        paths = save_simulation_artifacts(result, "customer_portal_compromise")

        allowed_bases = {
            SCENARIO_DIR,
            EVENTS_DIR,
            INCIDENTS_DIR,
            ATTACK_PATHS_DIR,
            REMEDIATION_PLANS_DIR,
        }
        for name, path in paths.items():
            self.assertTrue(
                any(path.parent == base for base in allowed_bases),
                f"{name} artifact saved outside expected FinBank subdirectory: {path}",
            )

    def test_artifacts_do_not_overwrite_unrelated_files(self):
        unrelated = ARTIFACTS_BASE / "unrelated_file.txt"
        unrelated.write_text("keep me", encoding="utf-8")

        result = run_finbank_simulation("customer_portal_compromise")
        save_simulation_artifacts(result, "customer_portal_compromise")

        self.assertTrue(
            unrelated.exists(),
            "FinBank artifact generation should not remove unrelated files.",
        )
        self.assertEqual(unrelated.read_text(encoding="utf-8"), "keep me")


class TestFinBankPipelineIntegration(unittest.TestCase):
    """Test the full FinBank pipeline from environment to remediation plan."""

    def test_full_pipeline_components_are_consistent(self):
        result = run_finbank_simulation("customer_portal_compromise")

        incident_entry = result.incident.get("entry_point")
        attack_entry = result.attack_path.get("entry_point")
        self.assertEqual(incident_entry, attack_entry)

        incident_assets = set(result.incident.get("critical_assets_affected", []))
        path_target = result.attack_path.get("target_critical_asset")
        self.assertIn(path_target, incident_assets)

        affected_set = set(result.affected_systems)
        path_systems = set(
            s for s in result.attack_path.get("simulated_attack_path", [])
            if s != "INTERNET"
        )
        self.assertTrue(
            affected_set.issubset(path_systems),
            f"Affected systems {affected_set} should be subset of path systems {path_systems}",
        )

    def test_event_targets_align_with_attack_path(self):
        result = run_finbank_simulation("customer_portal_compromise")
        event_targets = [e["target"] for e in result.events]
        attack_path = result.attack_path.get("simulated_attack_path", [])

        for target in event_targets:
            self.assertIn(target, attack_path)

    def test_related_vulnerabilities_are_valid_inventory_ids(self):
        result = run_finbank_simulation("customer_portal_compromise")
        inventory = assign_finbank_vulnerabilities()
        valid_vuln_ids = set(inventory["vuln_id"].tolist())
        for vuln_id in result.related_vulnerabilities:
            self.assertIn(vuln_id, valid_vuln_ids)

    def test_attack_path_metrics_are_positive(self):
        result = run_finbank_simulation("customer_portal_compromise")
        self.assertGreater(result.attack_path["total_risk_cost"], 0.0)
        self.assertGreater(len(result.attack_path["simulated_attack_path"]), 1)

    def test_remediation_schedule_has_no_team_conflicts(self):
        result = run_finbank_simulation("customer_portal_compromise")
        schedule = result.remediation_plan.get("schedule", [])
        assignments = [(item["team"], item["time_slot"]) for item in schedule]
        self.assertEqual(len(assignments), len(set(assignments)))

    def test_remediation_dependencies_reference_valid_tasks(self):
        result = run_finbank_simulation("customer_portal_compromise")
        schedule = result.remediation_plan.get("schedule", [])
        vuln_ids = {item["vuln_id"] for item in schedule}
        for item in schedule:
            for dep in item.get("depends_on", []):
                self.assertIn(dep, vuln_ids)


if __name__ == "__main__":
    unittest.main()
