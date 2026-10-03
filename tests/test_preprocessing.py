"""Unit tests for the vulnerability preprocessing module."""

import unittest
import tempfile
import os
import numpy as np
import pandas as pd

from src.preprocessing import (
    load_raw_data,
    validate_raw_data,
    encode_features,
    preprocess_vulnerabilities,
    PROCESSED_COLUMNS,
    ALLOWED_RISK_LABELS,
)


class TestPreprocessing(unittest.TestCase):
    """Test suite for preprocessing validation and feature encoding."""

    def setUp(self):
        self.raw_path = "data/raw/vulnerabilities.csv"
        self.processed_path = "data/processed/vulnerabilities_processed.csv"

    def test_1_raw_sample_dataset_loads(self):
        """Confirm raw dataset loads successfully into a DataFrame."""
        df = load_raw_data(self.raw_path)
        self.assertIsInstance(df, pd.DataFrame)
        self.assertFalse(df.empty)

    def test_2_processed_row_count_matches_raw(self):
        """Confirm processed output row count matches raw dataset row count."""
        raw_df = load_raw_data(self.raw_path)
        processed = preprocess_vulnerabilities(self.raw_path, self.processed_path)
        self.assertEqual(len(processed), len(raw_df))

    def test_3_output_columns_are_exactly_correct(self):
        """Confirm processed columns match the agreed contract in exact order."""
        processed = preprocess_vulnerabilities(self.raw_path, self.processed_path)
        self.assertEqual(list(processed.columns), PROCESSED_COLUMNS)
        self.assertNotIn("description", processed.columns)

    def test_4_encoded_ml_features_are_numeric(self):
        """Confirm all 7 security features are numeric after encoding."""
        processed = preprocess_vulnerabilities(self.raw_path, self.processed_path)
        numeric_features = [
            "attack_complexity",
            "privileges_required",
            "user_interaction",
            "confidentiality_impact",
            "integrity_impact",
            "availability_impact",
            "exploit_probability",
        ]
        for col in numeric_features:
            self.assertTrue(
                np.issubdtype(processed[col].dtype, np.number),
                f"Column {col} is not numeric.",
            )

    def test_5_exploit_probability_range(self):
        """Confirm exploit_probability values remain between 0.0 and 1.0."""
        processed = preprocess_vulnerabilities(self.raw_path, self.processed_path)
        probs = processed["exploit_probability"]
        self.assertTrue((probs >= 0.0).all() and (probs <= 1.0).all())

    def test_6_risk_label_remains_text(self):
        """Confirm risk_label remains categorical text and is not encoded or modified."""
        processed = preprocess_vulnerabilities(self.raw_path, self.processed_path)
        self.assertTrue(pd.api.types.is_string_dtype(processed["risk_label"]))

    def test_7_only_allowed_risk_labels_remain(self):
        """Confirm only Low, Medium, High, Critical exist in risk_label."""
        processed = preprocess_vulnerabilities(self.raw_path, self.processed_path)
        labels = set(processed["risk_label"])
        self.assertTrue(labels.issubset(ALLOWED_RISK_LABELS))

    def test_8_invalid_category_causes_value_error(self):
        """Confirm invalid categorical value raises a ValueError."""
        df = load_raw_data(self.raw_path)
        df.loc[0, "attack_complexity"] = "Severe"
        with self.assertRaises(ValueError):
            validate_raw_data(df)

    def test_9_duplicate_vuln_id_causes_value_error(self):
        """Confirm duplicate vuln_id raises a ValueError."""
        df = load_raw_data(self.raw_path)
        df.loc[1, "vuln_id"] = df.loc[0, "vuln_id"]
        with self.assertRaises(ValueError):
            validate_raw_data(df)

    def test_10_positive_valid_dataset_end_to_end(self):
        """Confirm a manually constructed valid dataset passes full pipeline."""
        data = {
            "vuln_id": ["V001", "V002"],
            "system_id": ["SYS01", "SYS02"],
            "attack_complexity": ["Low", "High"],
            "privileges_required": ["None", "Low"],
            "user_interaction": ["None", "Required"],
            "confidentiality_impact": ["None", "High"],
            "integrity_impact": ["Low", "None"],
            "availability_impact": ["High", "Low"],
            "exploit_probability": [0.5, 1.0],
            "risk_label": ["Medium", "Critical"],
            "description": ["Desc A", "Desc B"],
        }
        df = pd.DataFrame(data)
        validate_raw_data(df)
        processed = encode_features(df)

        self.assertEqual(len(processed), 2)
        self.assertEqual(list(processed.columns), PROCESSED_COLUMNS)
        self.assertEqual(processed.loc[0, "vuln_id"], "V001")
        self.assertEqual(processed.loc[0, "risk_label"], "Medium")
        self.assertEqual(processed.loc[0, "attack_complexity"], 0)
        self.assertEqual(processed.loc[1, "attack_complexity"], 1)
        self.assertEqual(processed.loc[0, "privileges_required"], 0)
        self.assertEqual(processed.loc[1, "privileges_required"], 1)

    def test_11_exploit_probability_boundary_values(self):
        """Confirm boundary values 0.0 and 1.0 are accepted."""
        df = load_raw_data(self.raw_path)
        df.loc[0, "exploit_probability"] = 0.0
        df.loc[1, "exploit_probability"] = 1.0
        validate_raw_data(df)

    def test_12_exploit_probability_out_of_range_negative_raises(self):
        """Confirm negative exploit_probability raises ValueError."""
        df = load_raw_data(self.raw_path)
        df.loc[0, "exploit_probability"] = -0.1
        with self.assertRaises(ValueError):
            validate_raw_data(df)

    def test_13_exploit_probability_out_of_range_above_one_raises(self):
        """Confirm exploit_probability > 1.0 raises ValueError."""
        df = load_raw_data(self.raw_path)
        df.loc[0, "exploit_probability"] = 1.5
        with self.assertRaises(ValueError):
            validate_raw_data(df)

    def test_14_preservation_of_identifier_and_label_columns(self):
        """Confirm vuln_id, system_id, and risk_label are preserved exactly."""
        processed = preprocess_vulnerabilities(self.raw_path, self.processed_path)
        raw_df = load_raw_data(self.raw_path)

        self.assertIn("vuln_id", processed.columns)
        self.assertIn("system_id", processed.columns)
        self.assertIn("risk_label", processed.columns)

        pd.testing.assert_series_equal(
            processed["vuln_id"].reset_index(drop=True),
            raw_df["vuln_id"].reset_index(drop=True),
        )
        pd.testing.assert_series_equal(
            processed["system_id"].reset_index(drop=True),
            raw_df["system_id"].reset_index(drop=True),
        )
        pd.testing.assert_series_equal(
            processed["risk_label"].reset_index(drop=True),
            raw_df["risk_label"].reset_index(drop=True),
        )

    def test_15_output_contains_exactly_processed_columns(self):
        """Confirm output DataFrame contains only the agreed processed columns."""
        processed = preprocess_vulnerabilities(self.raw_path, self.processed_path)
        self.assertEqual(list(processed.columns), PROCESSED_COLUMNS)
        self.assertEqual(len(processed.columns), len(PROCESSED_COLUMNS))

    def test_16_invalid_risk_label_raises_error(self):
        """Confirm invalid risk_label values raise ValueError."""
        df = load_raw_data(self.raw_path)
        df.loc[0, "risk_label"] = "Invalid"
        with self.assertRaises(ValueError):
            validate_raw_data(df)

    def test_17_missing_required_columns_raises_error(self):
        """Confirm missing required columns raise ValueError."""
        df = load_raw_data(self.raw_path).drop(columns=["description"])
        with self.assertRaises(ValueError):
            validate_raw_data(df)

    def test_18_empty_cells_raise_error(self):
        """Confirm empty string cells raise ValueError."""
        df = load_raw_data(self.raw_path)
        df.loc[0, "description"] = ""
        with self.assertRaises(ValueError):
            validate_raw_data(df)

    def test_19_full_pipeline_writes_csv(self):
        """Confirm preprocess_vulnerabilities writes a valid CSV file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            out_path = os.path.join(tmpdir, "processed.csv")
            result = preprocess_vulnerabilities(self.raw_path, out_path)
            self.assertTrue(os.path.exists(out_path))
            loaded = pd.read_csv(out_path, encoding="utf-8")
            self.assertEqual(len(loaded), len(result))
            self.assertEqual(list(loaded.columns), PROCESSED_COLUMNS)


if __name__ == "__main__":
    unittest.main()
