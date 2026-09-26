"""Unit tests for the TraceWard incident correlator."""

from __future__ import annotations

import pandas as pd
import unittest

from src.incident_correlator import (
    REQUIRED_EVENT_COLUMNS,
    REQUIRED_INVENTORY_COLUMNS,
    Incident,
    correlate_incidents,
    correlate_single_scenario,
    incident_to_dict,
)
from src.attack_simulator.simulator import simulate_finbank_attack
from src.finbank_assignment import assign_finbank_vulnerabilities


class TestIncidentCorrelatorSingleScenario(unittest.TestCase):
    """Correlator should produce one incident per scenario."""

    @classmethod
    def setUpClass(cls):
        cls.inventory = assign_finbank_vulnerabilities()
        cls.events = simulate_finbank_attack("customer_portal_compromise", inventory=cls.inventory)
        cls.incidents = correlate_incidents(cls.events, cls.inventory)

    def test_one_incident_produced(self):
        self.assertEqual(len(self.incidents), 1)

    def test_incident_scenario_id_matches(self):
        self.assertEqual(self.incidents[0].scenario_id, "customer_portal_compromise")

    def test_incident_entry_point(self):
        self.assertEqual(self.incidents[0].entry_point, "INTERNET")

    def test_incident_event_count(self):
        self.assertEqual(self.incidents[0].event_count, 3)


class TestIncidentCorrelatorMultipleAffectedSystems(unittest.TestCase):
    """Incident should identify all affected systems from the event chain."""

    @classmethod
    def setUpClass(cls):
        cls.inventory = assign_finbank_vulnerabilities()
        cls.events = simulate_finbank_attack("employee_compromise", inventory=cls.inventory)
        cls.incident = correlate_incidents(cls.events, cls.inventory)[0]

    def test_affected_systems_match_scenario_path(self):
        expected = ("EMP01", "AUTH01", "APP01", "DB01")
        self.assertEqual(self.incident.affected_systems, expected)

    def test_related_vulnerabilities_exist_for_affected_systems(self):
        valid_vuln_ids = set(self.inventory["vuln_id"].tolist())
        invalid = set(self.incident.related_vulnerabilities) - valid_vuln_ids
        self.assertFalse(invalid, f"Invalid vulnerability IDs in related_vulnerabilities: {invalid}")


class TestIncidentCorrelatorInvalidVulnerabilityIds(unittest.TestCase):
    """Events referencing non-existent vulnerabilities should still correlate."""

    def test_events_with_invalid_vulnerability_ids(self):
        inventory = assign_finbank_vulnerabilities()
        events = simulate_finbank_attack("customer_portal_compromise", inventory=inventory)
        events.loc[events.index[0], "vulnerability_id"] = "INVALID_VULN_ID"
        incidents = correlate_incidents(events, inventory)
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0].event_count, 3)


class TestIncidentCorrelatorDuplicateEvents(unittest.TestCase):
    """Duplicate events should be deduplicated before correlation."""

    def test_duplicate_events_are_deduplicated(self):
        inventory = assign_finbank_vulnerabilities()
        events = simulate_finbank_attack("customer_portal_compromise", inventory=inventory)
        duplicate = events.iloc[[0]].copy()
        events = pd.concat([events, duplicate], ignore_index=True)
        incidents = correlate_incidents(events, inventory)
        self.assertEqual(incidents[0].event_count, 3)


class TestIncidentCorrelatorCriticalAssetIdentification(unittest.TestCase):
    """Critical assets affected should include high-criticality and internet-exposed systems."""

    @classmethod
    def setUpClass(cls):
        cls.inventory = assign_finbank_vulnerabilities()
        cls.events = simulate_finbank_attack("backup_targeting", inventory=cls.inventory)
        cls.incident = correlate_incidents(cls.events, cls.inventory)[0]

    def test_critical_assets_include_high_criticality(self):
        for system_id in self.incident.critical_assets_affected:
            self.assertIn(system_id, self.incident.affected_systems)

    def test_internet_exposed_systems_are_critical_assets(self):
        internet_exposed = {"WEB01", "VPN01"}
        for system_id in internet_exposed:
            if system_id in self.incident.affected_systems:
                self.assertIn(system_id, self.incident.critical_assets_affected)

    def test_backup_targeting_includes_backup01_as_critical_asset(self):
        self.assertIn("BACKUP01", self.incident.critical_assets_affected)


class TestIncidentCorrelatorSingleScenarioLookup(unittest.TestCase):
    """correlate_single_scenario should return the matching incident or raise."""

    @classmethod
    def setUpClass(cls):
        cls.inventory = assign_finbank_vulnerabilities()
        cls.events = simulate_finbank_attack("remote_access_compromise", inventory=cls.inventory)

    def test_single_scenario_returns_incident(self):
        incident = correlate_single_scenario("remote_access_compromise", self.events, self.inventory)
        self.assertEqual(incident.scenario_id, "remote_access_compromise")

    def test_single_scenario_unknown_raises(self):
        with self.assertRaises(KeyError):
            correlate_single_scenario("unknown_scenario", self.events, self.inventory)


class TestIncidentCorrelatorSerialization(unittest.TestCase):
    """incident_to_dict should preserve all incident fields."""

    @classmethod
    def setUpClass(cls):
        cls.inventory = assign_finbank_vulnerabilities()
        cls.events = simulate_finbank_attack("customer_portal_compromise", inventory=cls.inventory)
        cls.incident = correlate_incidents(cls.events, cls.inventory)[0]

    def test_incident_to_dict_contains_expected_keys(self):
        data = incident_to_dict(self.incident)
        for key in (
            "incident_id",
            "scenario_id",
            "entry_point",
            "affected_systems",
            "related_vulnerabilities",
            "event_count",
            "critical_assets_affected",
            "attack_sequence",
        ):
            self.assertIn(key, data)

    def test_incident_to_dict_event_count_matches(self):
        data = incident_to_dict(self.incident)
        self.assertEqual(data["event_count"], self.incident.event_count)
        self.assertEqual(len(data["attack_sequence"]), self.incident.event_count)


if __name__ == "__main__":
    unittest.main()
