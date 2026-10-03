"""Unit tests for the fictional FinBank attack simulator."""

from __future__ import annotations

import subprocess
import socket
import unittest
from pathlib import Path

import pandas as pd

from src.attack_simulator.simulator import (
    FIXED_SEED,
    OUTPUT_PATH,
    _select_vulnerability,
    simulate_all_finbank_scenarios,
    simulate_finbank_attack,
)
from src.finbank_assignment import assign_finbank_vulnerabilities


class TestFinBankSimulatorDeterministicOutput(unittest.TestCase):
    """Repeated simulator runs must produce identical event sequences."""

    @classmethod
    def setUpClass(cls):
        cls.inventory = assign_finbank_vulnerabilities()

    def test_customer_portal_compromise_is_deterministic(self):
        df1 = simulate_finbank_attack("customer_portal_compromise", inventory=self.inventory)
        df2 = simulate_finbank_attack("customer_portal_compromise", inventory=self.inventory)
        pd.testing.assert_frame_equal(df1, df2)

    def test_all_scenarios_are_deterministic(self):
        df1 = simulate_all_finbank_scenarios(inventory=self.inventory)
        df2 = simulate_all_finbank_scenarios(inventory=self.inventory)
        pd.testing.assert_frame_equal(df1, df2)


class TestFinBankSimulatorEventOrdering(unittest.TestCase):
    """Events must follow the scenario path order and have increasing timestamps."""

    @classmethod
    def setUpClass(cls):
        cls.inventory = assign_finbank_vulnerabilities()

    def test_customer_portal_compromise_ordering(self):
        df = simulate_finbank_attack("customer_portal_compromise", inventory=self.inventory)
        self.assertEqual(df.iloc[0]["source"], "INTERNET")
        self.assertEqual(df.iloc[0]["target"], "WEB01")
        self.assertEqual(df.iloc[1]["source"], "WEB01")
        self.assertEqual(df.iloc[1]["target"], "APP01")
        self.assertEqual(df.iloc[2]["source"], "APP01")
        self.assertEqual(df.iloc[2]["target"], "DB01")
        self.assertTrue((df["timestamp"].diff().iloc[1:] > 0).all())

    def test_backup_targeting_final_event_type(self):
        df = simulate_finbank_attack("backup_targeting", inventory=self.inventory)
        last_event = df.iloc[-1]
        self.assertEqual(last_event["event_type"], "backup_targeting")
        self.assertEqual(last_event["target"], "BACKUP01")


class TestFinBankSimulatorValidSystems(unittest.TestCase):
    """All event sources and targets must be valid FinBank systems."""

    @classmethod
    def setUpClass(cls):
        cls.inventory = assign_finbank_vulnerabilities()
        cls.df = simulate_all_finbank_scenarios(inventory=cls.inventory)

    def test_all_sources_are_valid_finbank_systems(self):
        valid_systems = {
            "INTERNET", "WEB01", "APP01", "AUTH01", "VPN01", "EMP01", "DB01", "BACKUP01"
        }
        invalid = set(self.df["source"]) - valid_systems
        self.assertFalse(invalid, f"Invalid source systems: {invalid}")

    def test_all_targets_are_valid_finbank_systems(self):
        valid_systems = {
            "INTERNET", "WEB01", "APP01", "AUTH01", "VPN01", "EMP01", "DB01", "BACKUP01"
        }
        invalid = set(self.df["target"]) - valid_systems
        self.assertFalse(invalid, f"Invalid target systems: {invalid}")


class TestFinBankSimulatorReferencedVulnerabilitiesExist(unittest.TestCase):
    """Referenced vulnerability IDs must exist in the inventory."""

    @classmethod
    def setUpClass(cls):
        cls.inventory = assign_finbank_vulnerabilities()
        cls.valid_vuln_ids = set(cls.inventory["vuln_id"].tolist())

    def test_customer_portal_compromise_vulnerabilities_exist(self):
        df = simulate_finbank_attack("customer_portal_compromise", inventory=self.inventory)
        referenced = set(df["vulnerability_id"].dropna().tolist())
        invalid = referenced - self.valid_vuln_ids
        self.assertFalse(invalid, f"Referenced vulnerabilities not in inventory: {invalid}")

    def test_all_scenarios_reference_valid_vulnerabilities(self):
        df = simulate_all_finbank_scenarios(inventory=self.inventory)
        referenced = set(df["vulnerability_id"].dropna().tolist())
        invalid = referenced - self.valid_vuln_ids
        self.assertFalse(invalid, f"Referenced vulnerabilities not in inventory: {invalid}")


class TestFinBankSimulatorNoExternalNetworkActivity(unittest.TestCase):
    """Simulator must not perform network connections, subprocesses, or socket operations."""

    def test_simulator_does_not_open_sockets(self):
        original_socket = socket.socket
        socket_calls = []

        def tracking_socket(*args, **kwargs):
            socket_calls.append((args, kwargs))
            return original_socket(*args, **kwargs)

        socket.socket = tracking_socket
        try:
            inventory = assign_finbank_vulnerabilities()
            simulate_finbank_attack("customer_portal_compromise", inventory=inventory)
        finally:
            socket.socket = original_socket
        self.assertFalse(socket_calls, "Simulator attempted to open sockets.")

    def test_simulator_does_not_spawn_subprocesses(self):
        original_popen = subprocess.Popen
        popen_calls = []

        def tracking_popen(*args, **kwargs):
            popen_calls.append((args, kwargs))
            return original_popen(*args, **kwargs)

        subprocess.Popen = tracking_popen
        try:
            inventory = assign_finbank_vulnerabilities()
            simulate_finbank_attack("customer_portal_compromise", inventory=inventory)
        finally:
            subprocess.Popen = original_popen
        self.assertFalse(popen_calls, "Simulator attempted to spawn subprocesses.")


class TestFinBankSimulatorOutputArtifact(unittest.TestCase):
    """Simulator must write results to the expected artifact path."""

    @classmethod
    def setUpClass(cls):
        cls.inventory = assign_finbank_vulnerabilities()
        cls.df = simulate_finbank_attack("customer_portal_compromise", inventory=cls.inventory)

    def test_output_file_created(self):
        self.assertTrue(OUTPUT_PATH.exists(), f"Expected output file not created at {OUTPUT_PATH}")

    def test_output_contains_required_columns(self):
        required = {
            "event_id", "scenario_id", "timestamp", "source", "target",
            "event_type", "vulnerability_id", "severity", "description",
        }
        self.assertTrue(required.issubset(set(self.df.columns)))

    def test_output_event_count_matches_scenario(self):
        scenario_steps = 3
        self.assertEqual(len(self.df), scenario_steps)


if __name__ == "__main__":
    unittest.main()
