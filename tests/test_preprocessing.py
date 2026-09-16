"""Unit tests for the vulnerability preprocessing module."""

import unittest
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

    def test_2_processed_row_count_remains_16(self):
        """Confirm processed output contains exactly 16 vulnerability records."""
        processed = preprocess_vulnerabilities(self.raw_path, self.processed_path)
        self.assertEqual(len(processed), 16)

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


if __name__ == "__main__":
    unittest.main()
