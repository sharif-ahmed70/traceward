"""Unit tests for deterministic FinBank attack scenarios."""

from __future__ import annotations

import unittest

from src.attack_simulator.scenarios import (
    AttackScenario,
    build_finbank_scenarios,
    get_finbank_scenario,
    scenario_to_dict,
)
from src.attack_simulator.events import EventType


class TestFinBankScenariosExist(unittest.TestCase):
    """All four required FinBank scenarios must be present."""

    @classmethod
    def setUpClass(cls):
        cls.scenarios = build_finbank_scenarios()
        cls.by_id = {s.scenario_id: s for s in cls.scenarios}

    def test_four_scenarios_exist(self):
        self.assertEqual(len(self.scenarios), 4)

    def test_required_scenario_ids_exist(self):
        required = {
            "customer_portal_compromise",
            "employee_compromise",
            "remote_access_compromise",
            "backup_targeting",
        }
        self.assertSetEqual(required, set(self.by_id.keys()))


class TestFinBankScenarioPaths(unittest.TestCase):
    """Each scenario's target path must match the expected route."""

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


class TestFinBankScenarioSchema(unittest.TestCase):
    """Scenarios must expose the required fields."""

    def test_scenario_fields_populated(self):
        scenario = get_finbank_scenario("customer_portal_compromise")
        self.assertTrue(scenario.scenario_id)
        self.assertTrue(scenario.name)
        self.assertTrue(scenario.description)
        self.assertTrue(scenario.entry_point)
        self.assertTrue(scenario.target_systems)
        self.assertTrue(scenario.events)

    def test_entry_point_matches_first_event_source(self):
        for scenario in build_finbank_scenarios():
            self.assertEqual(scenario.entry_point, scenario.events[0].source)

    def test_events_have_required_fields(self):
        scenario = get_finbank_scenario("remote_access_compromise")
        for event in scenario.events:
            self.assertTrue(event.event_id)
            self.assertTrue(event.scenario_id)
            self.assertIsInstance(event.timestamp, int)
            self.assertTrue(event.source)
            self.assertTrue(event.target)
            self.assertIn(event.event_type, {e.value for e in EventType})
            self.assertIn(event.severity, {"Low", "Medium", "High", "Critical"})


class TestFinBankScenarioDeterminism(unittest.TestCase):
    """Repeated scenario builds must be identical."""

    def test_scenarios_are_deterministic(self):
        first = build_finbank_scenarios()
        second = build_finbank_scenarios()
        self.assertEqual(len(first), len(second))
        for a, b in zip(first, second):
            self.assertEqual(a.scenario_id, b.scenario_id)
            self.assertEqual(a.target_systems, b.target_systems)
            self.assertEqual(len(a.events), len(b.events))
            for ea, eb in zip(a.events, b.events):
                self.assertEqual(ea.event_id, eb.event_id)
                self.assertEqual(ea.source, eb.source)
                self.assertEqual(ea.target, eb.target)
                self.assertEqual(ea.timestamp, eb.timestamp)


class TestFinBankScenarioSerialization(unittest.TestCase):
    """Serialized scenario dicts should preserve expected structure."""

    def test_scenario_to_dict_contains_expected_keys(self):
        scenario = get_finbank_scenario("backup_targeting")
        data = scenario_to_dict(scenario)
        for key in ("scenario_id", "name", "description", "entry_point", "target_systems", "events"):
            self.assertIn(key, data)

    def test_scenario_to_dict_event_count_matches(self):
        scenario = get_finbank_scenario("employee_compromise")
        data = scenario_to_dict(scenario)
        self.assertEqual(len(data["events"]), len(scenario.events))
        self.assertEqual(data["events"][0]["source"], "INTERNET")


if __name__ == "__main__":
    unittest.main()
