"""Regression tests for FinBank operational predictions and evaluation separation."""

from __future__ import annotations

import unittest
from pathlib import Path

import pandas as pd

from src.finbank_predictor import (
    OUTPUT_PREDICTIONS_PATH,
    _load_model,
    _load_processed_data,
    load_finbank_predictions,
    predict_full_inventory,
)
from src.risk_engine import build_system_risk_summary


class TestFinBankOperationalPredictions(unittest.TestCase):
    """Operational predictions must cover the full 1200-record inventory."""

    @classmethod
    def setUpClass(cls):
        cls.predictions = predict_full_inventory()

    def test_operational_predictions_has_1200_rows(self):
        self.assertEqual(len(self.predictions), 1200)

    def test_operational_predictions_has_required_columns(self):
        required = {"vuln_id", "system_id", "actual_risk", "predicted_risk"}
        self.assertTrue(required.issubset(set(self.predictions.columns)))

    def test_operational_predictions_no_null_vuln_ids(self):
        self.assertFalse(self.predictions["vuln_id"].isnull().any())
        self.assertFalse((self.predictions["vuln_id"].astype(str).str.strip() == "").any())

    def test_operational_predictions_valid_risk_labels(self):
        valid = {"Low", "Medium", "High", "Critical"}
        invalid = set(self.predictions["predicted_risk"]) - valid
        self.assertFalse(invalid, f"Invalid predicted risk labels: {invalid}")

    def test_operational_predictions_file_created(self):
        self.assertTrue(OUTPUT_PREDICTIONS_PATH.exists())

    def test_operational_predictions_unique_vuln_ids(self):
        self.assertEqual(self.predictions["vuln_id"].nunique(), 1200)


class TestFinBankNoTestLeakage(unittest.TestCase):
    """Evaluation must still use the held-out test set, not the full inventory."""

    def test_test_predictions_still_exist(self):
        test_path = Path("artifacts/knn/predictions.csv")
        self.assertTrue(test_path.exists(), "Existing test predictions artifact should still exist.")

    def test_test_predictions_has_240_rows(self):
        test_path = Path("artifacts/knn/predictions.csv")
        if test_path.exists():
            df = pd.read_csv(test_path, keep_default_na=False)
            self.assertEqual(len(df), 240)

    def test_operational_predictions_include_records_outside_test_set(self):
        test_path = Path("artifacts/knn/predictions.csv")
        if test_path.exists():
            test_df = pd.read_csv(test_path, keep_default_na=False)
            test_vuln_ids = set(test_df["vuln_id"].tolist())
            op_predictions = predict_full_inventory()
            op_vuln_ids = set(op_predictions["vuln_id"].tolist())
            non_test_vulns = op_vuln_ids - test_vuln_ids
            self.assertTrue(len(non_test_vulns) > 0, "Operational predictions should include records beyond the test set.")

    def test_operational_predictions_are_deterministic(self):
        df1 = predict_full_inventory()
        df2 = predict_full_inventory()
        pd.testing.assert_frame_equal(df1, df2)


class TestFinBankRiskEngineWithOperationalPredictions(unittest.TestCase):
    """Risk engine should accept FinBank operational predictions."""

    @classmethod
    def setUpClass(cls):
        cls.predictions = predict_full_inventory()
        cls.risk_summary = build_system_risk_summary(
            predictions_path="artifacts/finbank/finbank_predictions.csv",
            output_path="artifacts/risk/finbank_system_risk_summary.csv",
        )

    def test_risk_summary_has_all_systems(self):
        expected_systems = {"WEB01", "APP01", "AUTH01", "VPN01", "EMP01", "DB01", "BACKUP01"}
        self.assertSetEqual(expected_systems, set(self.risk_summary["system_id"].tolist()))

    def test_risk_summary_has_required_columns(self):
        required = {
            "system_id", "vulnerability_count", "highest_risk",
            "average_risk_score", "normalized_risk", "critical_count", "high_or_critical_count"
        }
        self.assertTrue(required.issubset(set(self.risk_summary.columns)))

    def test_risk_summary_vulnerability_counts_sum_to_1200(self):
        self.assertEqual(self.risk_summary["vulnerability_count"].sum(), 1200)


class TestFinBankPredictorLoading(unittest.TestCase):
    """Test data and model loading for operational predictions."""

    def test_load_processed_data(self):
        df = _load_processed_data()
        self.assertEqual(len(df), 1200)

    def test_load_model(self):
        model = _load_model()
        self.assertTrue(hasattr(model, "predict"))

    def test_load_finbank_predictions(self):
        predict_full_inventory()
        df = load_finbank_predictions()
        self.assertEqual(len(df), 1200)


if __name__ == "__main__":
    unittest.main()
