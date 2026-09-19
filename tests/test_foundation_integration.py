"""Integration contract tests for the TraceWard shared foundation."""

import json
from pathlib import Path
import unittest
import pandas as pd

import main

RAW_PATH = Path("data/raw/vulnerabilities.csv")
PROCESSED_PATH = Path("data/processed/vulnerabilities_processed.csv")
NETWORK_PATH = Path("data/network/network.json")

LEAKAGE_COLUMNS = [
    "hidden_risk_score",
    "risk_score",
    "computed_cvss_score",
    "cvss_score",
]


class TestFoundationIntegration(unittest.TestCase):
    """Test suite verifying cross-module repository foundation integrity."""

    @classmethod
    def setUpClass(cls):
        cls.raw_df = pd.read_csv(RAW_PATH, keep_default_na=False)
        cls.proc_df = pd.read_csv(PROCESSED_PATH, keep_default_na=False)
        with open(NETWORK_PATH, "r", encoding="utf-8") as f:
            cls.network = json.load(f)
        cls.node_ids = {node["id"] for node in cls.network.get("nodes", [])}

    def test_01_raw_file_exists(self):
        self.assertTrue(RAW_PATH.exists(), "Raw vulnerabilities file missing.")

    def test_02_processed_file_exists(self):
        self.assertTrue(PROCESSED_PATH.exists(), "Processed vulnerabilities file missing.")

    def test_03_network_json_exists(self):
        self.assertTrue(NETWORK_PATH.exists(), "Network topology JSON missing.")

    def test_04_raw_dataset_has_1200_rows(self):
        self.assertEqual(len(self.raw_df), 1200)

    def test_05_processed_dataset_has_1200_rows(self):
        self.assertEqual(len(self.proc_df), 1200)

    def test_06_raw_and_processed_row_counts_match(self):
        self.assertEqual(len(self.raw_df), len(self.proc_df))

    def test_07_raw_dataset_has_11_columns(self):
        self.assertEqual(self.raw_df.shape[1], 11)

    def test_08_processed_dataset_has_10_columns(self):
        self.assertEqual(self.proc_df.shape[1], 10)

    def test_09_vuln_ids_remain_unique(self):
        self.assertTrue(self.raw_df["vuln_id"].is_unique)
        self.assertTrue(self.proc_df["vuln_id"].is_unique)

    def test_10_vulnerability_systems_exist_in_network(self):
        raw_systems = set(self.raw_df["system_id"])
        proc_systems = set(self.proc_df["system_id"])
        self.assertTrue(raw_systems.issubset(self.node_ids))
        self.assertTrue(proc_systems.issubset(self.node_ids))

    def test_11_network_contains_8_nodes(self):
        self.assertEqual(len(self.network.get("nodes", [])), 8)

    def test_12_network_contains_9_directed_edges(self):
        self.assertEqual(len(self.network.get("edges", [])), 9)

    def test_13_network_contains_internet(self):
        self.assertIn("INTERNET", self.node_ids)

    def test_14_no_hidden_leakage_columns_in_raw(self):
        for col in LEAKAGE_COLUMNS:
            self.assertNotIn(col, self.raw_df.columns)

    def test_15_no_hidden_leakage_columns_in_processed(self):
        for col in LEAKAGE_COLUMNS:
            self.assertNotIn(col, self.proc_df.columns)

    def test_16_get_foundation_status_returns_expected_counts(self):
        status = main.get_foundation_status()
        self.assertEqual(status["raw_records"], 1200)
        self.assertEqual(status["processed_records"], 1200)
        self.assertEqual(status["network_nodes"], 8)
        self.assertEqual(status["network_edges"], 9)

    def test_17_validate_foundation_succeeds(self):
        self.assertTrue(main.validate_foundation())


if __name__ == "__main__":
    unittest.main()
