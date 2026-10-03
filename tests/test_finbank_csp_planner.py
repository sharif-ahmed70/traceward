"""Tests for the FinBank-aware CSP remediation planner extension."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import pandas as pd

from src.csp_solver import (
    CSPCase,
    VulnerabilityTask,
    solve_csp,
    validate_case,
    SYSTEM_TEAM_MAP,
    DEFAULT_TIME_SLOTS,
    MOCK_CASE,
)
from src.finbank_csp_planner import (
    _attack_path_position,
    _compute_task_priority,
    build_finbank_remediation_case,
    run_finbank_remediation_plan,
    run_finbank_scenario_remediation,
)
from src.incident_correlator import Incident, correlate_incidents, correlate_single_scenario
from src.attack_simulator.simulator import simulate_finbank_attack
from src.finbank_assignment import assign_finbank_vulnerabilities


class TestAttackPathPosition(unittest.TestCase):
    """Attack-path position helper must rank systems correctly."""

    def test_internet_excluded(self):
        path = ["INTERNET", "WEB01", "APP01", "DB01"]
        self.assertEqual(_attack_path_position("INTERNET", path), len(path))

    def test_system_on_path_returns_index(self):
        path = ["INTERNET", "WEB01", "APP01", "DB01"]
        self.assertEqual(_attack_path_position("WEB01", path), 1)
        self.assertEqual(_attack_path_position("APP01", path), 2)
        self.assertEqual(_attack_path_position("DB01", path), 3)

    def test_system_off_path_returns_large_index(self):
        path = ["INTERNET", "WEB01", "APP01", "DB01"]
        self.assertEqual(_attack_path_position("VPN01", path), len(path))

    def test_empty_path_returns_large_index(self):
        self.assertEqual(_attack_path_position("WEB01", []), 0)


class TestComputeTaskPriority(unittest.TestCase):
    """Priority scoring must rank tasks as expected."""

    def test_critical_on_critical_exposed_scores_lowest(self):
        score = _compute_task_priority("Critical", 5, 0, True)
        self.assertLess(score, 100)

    def test_low_on_non_critical_off_path_scores_highest(self):
        score = _compute_task_priority("Low", 1, 99, False)
        self.assertGreater(score, 300)

    def test_higher_risk_has_lower_score(self):
        score_critical = _compute_task_priority("Critical", 4, 1, False)
        score_high = _compute_task_priority("High", 4, 1, False)
        score_medium = _compute_task_priority("Medium", 4, 1, False)
        score_low = _compute_task_priority("Low", 4, 1, False)
        self.assertLess(score_critical, score_high)
        self.assertLess(score_high, score_medium)
        self.assertLess(score_medium, score_low)

    def test_earlier_path_position_has_lower_score(self):
        score_early = _compute_task_priority("High", 4, 0, False)
        score_late = _compute_task_priority("High", 4, 3, False)
        self.assertLess(score_early, score_late)

    def test_higher_criticality_has_lower_score(self):
        score_high_crit = _compute_task_priority("High", 5, 1, False)
        score_low_crit = _compute_task_priority("High", 1, 1, False)
        self.assertLess(score_high_crit, score_low_crit)

    def test_internet_exposed_has_lower_score(self):
        score_exposed = _compute_task_priority("High", 4, 1, True)
        score_internal = _compute_task_priority("High", 4, 1, False)
        self.assertLess(score_exposed, score_internal)


class TestBuildFinbankRemediationCase(unittest.TestCase):
    """Case builder must produce valid CSP cases from incident data."""

    @classmethod
    def setUpClass(cls):
        cls.inventory = assign_finbank_vulnerabilities()
        cls.events = simulate_finbank_attack("customer_portal_compromise", inventory=cls.inventory)
        cls.incidents = correlate_incidents(cls.events, cls.inventory)
        cls.incident = cls.incidents[0]
        cls.attack_path = ["INTERNET", "WEB01", "APP01", "DB01"]

    def test_returns_csp_case_and_metadata(self):
        case, metadata = build_finbank_remediation_case(
            self.incident, self.inventory, self.attack_path
        )
        self.assertIsInstance(case, CSPCase)
        self.assertIsInstance(metadata, dict)

    def test_case_has_valid_tasks(self):
        case, _ = build_finbank_remediation_case(
            self.incident, self.inventory, self.attack_path
        )
        self.assertGreater(len(case.vulnerabilities), 0)
        for task in case.vulnerabilities:
            self.assertIn(task.required_team, SYSTEM_TEAM_MAP.values())

    def test_case_validates_successfully(self):
        case, _ = build_finbank_remediation_case(
            self.incident, self.inventory, self.attack_path
        )
        validate_case(case)

    def test_metadata_contains_expected_keys(self):
        _, metadata = build_finbank_remediation_case(
            self.incident, self.inventory, self.attack_path
        )
        for key in (
            "source",
            "incident_id",
            "scenario_id",
            "entry_point",
            "attack_path",
            "attack_path_systems",
            "selected_task_count",
            "total_related_vulnerabilities",
            "pending_backlog_count",
            "selection_rule",
            "selected_tasks",
        ):
            self.assertIn(key, metadata)

    def test_metadata_incident_id_matches(self):
        _, metadata = build_finbank_remediation_case(
            self.incident, self.inventory, self.attack_path
        )
        self.assertEqual(metadata["incident_id"], self.incident.incident_id)

    def test_attack_path_systems_excludes_internet(self):
        _, metadata = build_finbank_remediation_case(
            self.incident, self.inventory, self.attack_path
        )
        self.assertNotIn("INTERNET", metadata["attack_path_systems"])

    def test_selected_tasks_have_attack_path_position(self):
        _, metadata = build_finbank_remediation_case(
            self.incident, self.inventory, self.attack_path
        )
        for task in metadata["selected_tasks"]:
            self.assertIn("attack_path_position", task)

    def test_one_task_per_affected_system(self):
        _, metadata = build_finbank_remediation_case(
            self.incident, self.inventory, self.attack_path
        )
        system_ids = [t["system_id"] for t in metadata["selected_tasks"]]
        self.assertEqual(len(system_ids), len(set(system_ids)))

    def test_dependencies_reference_selected_tasks(self):
        case, _ = build_finbank_remediation_case(
            self.incident, self.inventory, self.attack_path
        )
        all_vuln_ids = {t.vuln_id for t in case.vulnerabilities}
        for task in case.vulnerabilities:
            for dep in task.depends_on:
                self.assertIn(dep, all_vuln_ids)

    def test_extra_constraints_accepted(self):
        case, _ = build_finbank_remediation_case(
            self.incident, self.inventory, self.attack_path, extra_constraints={}
        )
        self.assertIsInstance(case, CSPCase)

    def test_missing_inventory_columns_raises(self):
        bad_inventory = pd.DataFrame({"vuln_id": ["V1"], "system_id": ["WEB01"]})
        with self.assertRaises(ValueError):
            build_finbank_remediation_case(
                self.incident, bad_inventory, self.attack_path
            )

    def test_backup_targeting_scenario(self):
        events = simulate_finbank_attack("backup_targeting", inventory=self.inventory)
        incident = correlate_single_scenario("backup_targeting", events, self.inventory)
        attack_path = ["INTERNET", "WEB01", "APP01", "DB01", "BACKUP01"]
        case, metadata = build_finbank_remediation_case(
            incident, self.inventory, attack_path
        )
        validate_case(case)
        self.assertGreater(len(case.vulnerabilities), 0)


class TestRunFinbankRemediationPlan(unittest.TestCase):
    """Full plan runner must return feasible schedules with expected structure."""

    @classmethod
    def setUpClass(cls):
        cls.inventory = assign_finbank_vulnerabilities()
        cls.events = simulate_finbank_attack("customer_portal_compromise", inventory=cls.inventory)
        cls.incidents = correlate_incidents(cls.events, cls.inventory)
        cls.incident = cls.incidents[0]
        cls.attack_path = ["INTERNET", "WEB01", "APP01", "DB01"]

    def test_returns_feasible_status(self):
        result = run_finbank_remediation_plan(
            self.incident, self.inventory, self.attack_path
        )
        self.assertEqual(result["status"], "feasible")

    def test_contains_description(self):
        result = run_finbank_remediation_plan(
            self.incident, self.inventory, self.attack_path
        )
        self.assertEqual(
            result["description"],
            "feasible remediation schedule under the configured constraints",
        )

    def test_contains_metadata(self):
        result = run_finbank_remediation_plan(
            self.incident, self.inventory, self.attack_path
        )
        self.assertIn("metadata", result)
        self.assertIn("incident_id", result["metadata"])

    def test_schedule_has_expected_keys(self):
        result = run_finbank_remediation_plan(
            self.incident, self.inventory, self.attack_path
        )
        for item in result["schedule"]:
            for key in (
                "vuln_id",
                "system_id",
                "priority",
                "team",
                "time_slot",
                "depends_on",
            ):
                self.assertIn(key, item)

    def test_schedule_sorted_by_time_slot(self):
        result = run_finbank_remediation_plan(
            self.incident, self.inventory, self.attack_path
        )
        slots = [item["time_slot"] for item in result["schedule"]]
        self.assertEqual(slots, sorted(slots, key=lambda s: DEFAULT_TIME_SLOTS.index(s)))

    def test_no_duplicate_team_slot_assignments(self):
        result = run_finbank_remediation_plan(
            self.incident, self.inventory, self.attack_path
        )
        occupied = [(item["team"], item["time_slot"]) for item in result["schedule"]]
        self.assertEqual(len(occupied), len(set(occupied)))

    def test_dependencies_respected_in_schedule(self):
        result = run_finbank_remediation_plan(
            self.incident, self.inventory, self.attack_path
        )
        slot_index = {slot: i for i, slot in enumerate(DEFAULT_TIME_SLOTS)}
        slots = {item["vuln_id"]: slot_index[item["time_slot"]] for item in result["schedule"]}
        for item in result["schedule"]:
            for dep in item.get("depends_on", []):
                if dep in slots:
                    self.assertLess(slots[dep], slots[item["vuln_id"]])

    def test_infeasible_case_returns_status(self):
        overconstrained = CSPCase(
            vulnerabilities=(
                VulnerabilityTask("VULN-001", "WEB01", "Critical", "Web Team"),
                VulnerabilityTask("VULN-002", "APP01", "High", "Web Team"),
            ),
            available_teams=("Web Team",),
            time_slots=("Mon 09:00",),
        )
        result = solve_csp(overconstrained, raise_on_infeasible=False)
        self.assertEqual(result["status"], "infeasible")

    def test_raise_on_infeasible_raises(self):
        overconstrained = CSPCase(
            vulnerabilities=(
                VulnerabilityTask("VULN-001", "WEB01", "Critical", "Web Team"),
                VulnerabilityTask("VULN-002", "APP01", "High", "Web Team"),
            ),
            available_teams=("Web Team",),
            time_slots=("Mon 09:00",),
        )
        with self.assertRaises(ValueError):
            solve_csp(overconstrained, raise_on_infeasible=True)


class TestRunFinbankScenarioRemediation(unittest.TestCase):
    """Convenience function must run end-to-end for FinBank scenarios."""

    def test_customer_portal_compromise_returns_feasible(self):
        result = run_finbank_scenario_remediation("customer_portal_compromise")
        self.assertEqual(result["status"], "feasible")
        self.assertIn("metadata", result)
        self.assertEqual(
            result["description"],
            "feasible remediation schedule under the configured constraints",
        )

    def test_remote_access_compromise_returns_feasible(self):
        result = run_finbank_scenario_remediation("remote_access_compromise")
        self.assertEqual(result["status"], "feasible")

    def test_backup_targeting_returns_feasible(self):
        result = run_finbank_scenario_remediation("backup_targeting")
        self.assertEqual(result["status"], "feasible")

    def test_employee_compromise_returns_feasible(self):
        result = run_finbank_scenario_remediation("employee_compromise")
        self.assertEqual(result["status"], "feasible")

    def test_schedule_non_empty(self):
        result = run_finbank_scenario_remediation("customer_portal_compromise")
        self.assertGreater(len(result["schedule"]), 0)

    def test_metadata_has_scenario_id(self):
        result = run_finbank_scenario_remediation("customer_portal_compromise")
        self.assertEqual(result["metadata"]["scenario_id"], "customer_portal_compromise")


class TestFinbankCSPPreservesExistingBehavior(unittest.TestCase):
    """Existing CSP behavior must remain unchanged."""

    def test_mock_case_still_solves(self):
        result = solve_csp(MOCK_CASE)
        self.assertEqual(result["status"], "feasible")
        self.assertEqual(len(result["schedule"]), 5)

    def test_solve_csp_default_builds_from_pipeline(self):
        result = solve_csp()
        self.assertIn("status", result)
        self.assertIn("schedule", result)

    def test_validate_case_accepts_valid_case(self):
        validate_case(MOCK_CASE)

    def test_validate_case_rejects_empty_vulnerabilities(self):
        bad_case = CSPCase(
            vulnerabilities=(),
            available_teams=("Web Team",),
            time_slots=DEFAULT_TIME_SLOTS,
        )
        with self.assertRaises(ValueError):
            validate_case(bad_case)

    def test_validate_case_rejects_empty_teams(self):
        bad_case = CSPCase(
            vulnerabilities=(VulnerabilityTask("V1", "WEB01", "Critical", "Web Team"),),
            available_teams=(),
            time_slots=DEFAULT_TIME_SLOTS,
        )
        with self.assertRaises(ValueError):
            validate_case(bad_case)

    def test_validate_case_rejects_empty_time_slots(self):
        bad_case = CSPCase(
            vulnerabilities=(VulnerabilityTask("V1", "WEB01", "Critical", "Web Team"),),
            available_teams=("Web Team",),
            time_slots=(),
        )
        with self.assertRaises(ValueError):
            validate_case(bad_case)

    def test_system_team_map_contains_expected_teams(self):
        expected_teams = {"Web Team", "Application Team", "Database Team", "Network Team", "IT Support Team"}
        self.assertTrue(expected_teams.issubset(set(SYSTEM_TEAM_MAP.values())))


if __name__ == "__main__":
    unittest.main()
