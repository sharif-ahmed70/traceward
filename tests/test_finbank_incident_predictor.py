"""Unit tests for the FinBank incident predictor."""

from __future__ import annotations

import unittest

import pandas as pd

from src.finbank_incident_predictor import (
    FINBANK_PROCESSED_DATA_PATH,
    KNN_MODEL_PATH,
    _load_model,
    _load_processed_data,
    predict_incident_risks,
    predict_incident_risks_from_inventory,
)
from src.incident_correlator import correlate_incidents
from src.attack_simulator.simulator import simulate_finbank_attack
from src.finbank_assignment import assign_finbank_vulnerabilities


class TestFinbankIncidentPredictorLoadFunctions(unittest.TestCase):
    """Test data and model loading."""

    def test_load_processed_data(self):
        df = _load_processed_data()
        self.assertIn("vuln_id", df.columns)
        self.assertIn("risk_label", df.columns)
        self.assertEqual(len(df), 1200)

    def test_load_model(self):
        model = _load_model()
        self.assertTrue(hasattr(model, "predict"))

    def test_load_model_missing_path_raises(self):
        with self.assertRaises(FileNotFoundError):
            _load_model("artifacts/knn/nonexistent_model.joblib")


class TestFinbankIncidentPredictorPrediction(unittest.TestCase):
    """Test risk prediction for incident vulnerabilities."""

    def test_predict_incident_risks_returns_expected_columns(self):
        vuln_ids = ["V0001", "V0002", "V0003"]
        results = predict_incident_risks(vuln_ids)
        expected_cols = {"vuln_id", "system_id", "predicted_risk", "risk_label"}
        self.assertTrue(expected_cols.issubset(set(results.columns)))

    def test_predict_incident_risks_row_count_matches_input(self):
        vuln_ids = ["V0001", "V0002", "V0003"]
        results = predict_incident_risks(vuln_ids)
        self.assertEqual(len(results), len(vuln_ids))

    def test_predict_incident_risks_valid_risk_labels(self):
        vuln_ids = ["V0001", "V0002", "V0003"]
        results = predict_incident_risks(vuln_ids)
        valid_labels = {"Low", "Medium", "High", "Critical"}
        invalid = set(results["predicted_risk"]) - valid_labels
        self.assertFalse(invalid, f"Invalid predicted risk labels: {invalid}")

    def test_predict_incident_risks_preserves_vuln_id_order(self):
        vuln_ids = ["V0001", "V0002", "V0003"]
        results = predict_incident_risks(vuln_ids)
        self.assertListEqual(results["vuln_id"].tolist(), vuln_ids)

    def test_predict_incident_risks_unknown_vuln_id_raises(self):
        with self.assertRaises(KeyError):
            predict_incident_risks(["UNKNOWN_VULN_ID"])


class TestFinbankIncidentPredictorFromInventory(unittest.TestCase):
    """Test prediction via FinBank inventory pathway."""

    @classmethod
    def setUpClass(cls):
        cls.inventory = assign_finbank_vulnerabilities()

    def test_predict_from_inventory_matches_direct(self):
        vuln_ids = ["V0001", "V0002", "V0003"]
        direct = predict_incident_risks(vuln_ids)
        from_inventory = predict_incident_risks_from_inventory(vuln_ids, inventory=self.inventory)
        self.assertEqual(len(direct), len(from_inventory))
        self.assertListEqual(direct["vuln_id"].tolist(), from_inventory["vuln_id"].tolist())
        self.assertListEqual(direct["predicted_risk"].tolist(), from_inventory["predicted_risk"].tolist())
        self.assertListEqual(direct["risk_label"].tolist(), from_inventory["risk_label"].tolist())

    def test_predict_from_inventory_invalid_vuln_id_raises(self):
        with self.assertRaises(ValueError):
            predict_incident_risks_from_inventory(["INVALID_ID"], inventory=self.inventory)

    def test_predict_from_inventory_missing_file_raises(self):
        with self.assertRaises(FileNotFoundError):
            predict_incident_risks_from_inventory(["V0001"], inventory_path="artifacts/finbank/nonexistent.csv")


class TestFinbankIncidentPredictorIntegrationWithIncident(unittest.TestCase):
    """End-to-end: incident -> related vulnerabilities -> KNN predictions."""

    @classmethod
    def setUpClass(cls):
        cls.inventory = assign_finbank_vulnerabilities()
        cls.events = simulate_finbank_attack("customer_portal_compromise", inventory=cls.inventory)
        cls.incidents = correlate_incidents(cls.events, cls.inventory)

    def test_incident_related_vulnerabilities_predictable(self):
        incident = self.incidents[0]
        vuln_ids = list(incident.related_vulnerabilities)
        results = predict_incident_risks(vuln_ids)
        self.assertEqual(len(results), len(vuln_ids))
        self.assertListEqual(results["vuln_id"].tolist(), vuln_ids)

    def test_predicted_risks_are_valid_labels(self):
        incident = self.incidents[0]
        vuln_ids = list(incident.related_vulnerabilities)
        results = predict_incident_risks(vuln_ids)
        valid_labels = {"Low", "Medium", "High", "Critical"}
        invalid = set(results["predicted_risk"]) - valid_labels
        self.assertFalse(invalid, f"Invalid predicted risk labels: {invalid}")

    def test_system_ids_match_inventory(self):
        incident = self.incidents[0]
        vuln_ids = list(incident.related_vulnerabilities)
        results = predict_incident_risks_from_inventory(vuln_ids, inventory=self.inventory)
        inventory_by_vuln = self.inventory.set_index("vuln_id")["system_id"].to_dict()
        for _, row in results.iterrows():
            self.assertEqual(row["system_id"], inventory_by_vuln[row["vuln_id"]])


if __name__ == "__main__":
    unittest.main()
