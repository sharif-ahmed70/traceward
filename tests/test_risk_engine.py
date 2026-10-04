"""Unit tests for the system risk engine module."""

from pathlib import Path
import tempfile
import unittest
import pandas as pd

from src.risk_engine import (
    risk_label_to_score,
    validate_predictions,
    add_numeric_risk,
    summarize_system_risk,
    build_system_risk_summary,
    SUMMARY_COLUMNS,
)


class TestRiskEngine(unittest.TestCase):
    """Test suite for risk engine scoring, validation, and system summary aggregation."""

    def setUp(self):
        # Sample predictions for testing
        self.sample_df = pd.DataFrame({
            "vuln_id": ["V001", "V002", "V003", "V004", "V005"],
            "system_id": ["WEB01", "WEB01", "WEB01", "DB01", "DB01"],
            "predicted_risk": ["Critical", "High", "Low", "Critical", "Critical"],
        })

    def test_01_low_maps_to_1(self):
        self.assertEqual(risk_label_to_score("Low"), 1)

    def test_02_medium_maps_to_2(self):
        self.assertEqual(risk_label_to_score("Medium"), 2)

    def test_03_high_maps_to_3(self):
        self.assertEqual(risk_label_to_score("High"), 3)

    def test_04_critical_maps_to_4(self):
        self.assertEqual(risk_label_to_score("Critical"), 4)

    def test_05_invalid_label_raises_value_error(self):
        with self.assertRaises(ValueError):
            risk_label_to_score("Severe")
        with self.assertRaises(ValueError):
            risk_label_to_score("")

    def test_06_missing_required_prediction_column_raises_value_error(self):
        incomplete_df = pd.DataFrame({
            "vuln_id": ["V001"],
            "system_id": ["WEB01"],
        })
        with self.assertRaises(ValueError):
            validate_predictions(incomplete_df)

    def test_07_invalid_predicted_risk_raises_value_error(self):
        bad_df = pd.DataFrame({
            "vuln_id": ["V001"],
            "system_id": ["WEB01"],
            "predicted_risk": ["Unknown"],
        })
        with self.assertRaises(ValueError):
            validate_predictions(bad_df)

    def test_08_add_numeric_risk_does_not_modify_original_df(self):
        df_copy = self.sample_df.copy()
        scored = add_numeric_risk(df_copy)
        self.assertNotIn("risk_score", df_copy.columns)
        self.assertIn("risk_score", scored.columns)
        self.assertEqual(list(scored["risk_score"]), [4, 3, 1, 4, 4])

    def test_09_system_vulnerability_count_is_correct(self):
        summary = summarize_system_risk(self.sample_df)
        web_row = summary[summary["system_id"] == "WEB01"].iloc[0]
        db_row = summary[summary["system_id"] == "DB01"].iloc[0]
        self.assertEqual(web_row["vulnerability_count"], 3)
        self.assertEqual(db_row["vulnerability_count"], 2)

    def test_10_highest_risk_selection_is_correct(self):
        summary = summarize_system_risk(self.sample_df)
        web_row = summary[summary["system_id"] == "WEB01"].iloc[0]
        self.assertEqual(web_row["highest_risk"], "Critical")

    def test_11_average_risk_score_is_correct(self):
        # WEB01 scores: 4 (Critical), 3 (High), 1 (Low) -> mean = 8/3 = 2.667
        summary = summarize_system_risk(self.sample_df)
        web_row = summary[summary["system_id"] == "WEB01"].iloc[0]
        self.assertEqual(web_row["average_risk_score"], 2.667)

    def test_12_normalized_risk_is_correct(self):
        # WEB01 normalized: 2.667 / 4 = 0.667
        # DB01 normalized: (4+4)/2 / 4 = 1.000
        summary = summarize_system_risk(self.sample_df)
        web_row = summary[summary["system_id"] == "WEB01"].iloc[0]
        db_row = summary[summary["system_id"] == "DB01"].iloc[0]
        self.assertEqual(web_row["normalized_risk"], 0.667)
        self.assertEqual(db_row["normalized_risk"], 1.000)

    def test_13_critical_count_is_correct(self):
        summary = summarize_system_risk(self.sample_df)
        web_row = summary[summary["system_id"] == "WEB01"].iloc[0]
        db_row = summary[summary["system_id"] == "DB01"].iloc[0]
        self.assertEqual(web_row["critical_count"], 1)
        self.assertEqual(db_row["critical_count"], 2)

    def test_14_high_or_critical_count_is_correct(self):
        summary = summarize_system_risk(self.sample_df)
        web_row = summary[summary["system_id"] == "WEB01"].iloc[0]
        db_row = summary[summary["system_id"] == "DB01"].iloc[0]
        # WEB01: 1 Critical + 1 High = 2
        self.assertEqual(web_row["high_or_critical_count"], 2)
        # DB01: 2 Critical + 0 High = 2
        self.assertEqual(db_row["high_or_critical_count"], 2)

    def test_15_multiple_systems_produce_one_row_per_system(self):
        summary = summarize_system_risk(self.sample_df)
        self.assertEqual(len(summary), 2)
        self.assertEqual(set(summary["system_id"]), {"WEB01", "DB01"})

    def test_16_output_sorting_follows_normalized_risk_descending(self):
        summary = summarize_system_risk(self.sample_df)
        # DB01 (1.0) should come before WEB01 (0.667)
        self.assertEqual(summary.iloc[0]["system_id"], "DB01")
        self.assertEqual(summary.iloc[1]["system_id"], "WEB01")

    def test_17_build_system_risk_summary_creates_expected_csv(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            input_csv = Path(temp_dir) / "test_predictions.csv"
            output_csv = Path(temp_dir) / "output" / "system_risk_summary.csv"

            self.sample_df.to_csv(input_csv, index=False, encoding="utf-8")

            summary_df = build_system_risk_summary(
                input_path=str(input_csv),
                output_path=str(output_csv),
            )

            self.assertTrue(output_csv.exists())
            loaded = pd.read_csv(output_csv)
            self.assertEqual(list(loaded.columns), SUMMARY_COLUMNS)
            self.assertEqual(len(loaded), 2)
            self.assertEqual(loaded.iloc[0]["system_id"], "DB01")


if __name__ == "__main__":
    unittest.main()


class TestContextualPriority(unittest.TestCase):
    def test_same_class_differs_by_system(self):
        from src.risk_engine import contextual_priority
        db = {"criticality": 5, "internet_exposed": False}
        pc = {"criticality": 2, "internet_exposed": False}
        on_path = contextual_priority("High", db, on_attack_path=True)
        workstation = contextual_priority("High", pc)
        self.assertEqual(on_path["level"], "Urgent")
        self.assertEqual(workstation["level"], "Medium")
        self.assertGreater(on_path["score"], workstation["score"])

    def test_reasons_explain_each_factor(self):
        from src.risk_engine import contextual_priority
        res = contextual_priority("Critical", {"criticality": 4, "internet_exposed": True}, True, True)
        self.assertEqual(len(res["reasons"]), 5)
        self.assertEqual(res["level"], "Urgent")
