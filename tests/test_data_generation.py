"""Unit tests for synthetic vulnerability data generation."""

from pathlib import Path
import tempfile
import unittest
import pandas as pd

from src.data_generation import generate_training_data

EXPECTED_COLUMNS = [
    "vuln_id",
    "system_id",
    "attack_complexity",
    "privileges_required",
    "user_interaction",
    "confidentiality_impact",
    "integrity_impact",
    "availability_impact",
    "exploit_probability",
    "risk_label",
    "description",
]

LEAKAGE_COLUMNS = [
    "hidden_risk_score",
    "risk_score",
    "computed_cvss_score",
    "cvss_score",
]


class TestDataGeneration(unittest.TestCase):
    """Test suite validating synthetic training data generation requirements."""

    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.temp_csv = Path(cls.temp_dir.name) / "test_vulnerabilities.csv"
        cls.df = generate_training_data(
            output_path=cls.temp_csv,
            samples_per_class=300,
            seed=42,
        )

    @classmethod
    def tearDownClass(cls):
        cls.temp_dir.cleanup()

    def test_a_dataset_size(self):
        """Confirm total rows equal 1,200 when generating 300 samples per class."""
        self.assertEqual(len(self.df), 1200)

    def test_b_unique_ids(self):
        """Confirm vuln_id values are completely unique across the dataset."""
        self.assertTrue(self.df["vuln_id"].is_unique)
        self.assertEqual(self.df["vuln_id"].nunique(), 1200)

    def test_c_required_columns(self):
        """Confirm dataset contains all required columns in the exact specified order."""
        self.assertEqual(list(self.df.columns), EXPECTED_COLUMNS)

    def test_d_balanced_classes(self):
        """Confirm class distribution has exactly 300 records for each risk category."""
        counts = self.df["risk_label"].value_counts().to_dict()
        for label in ["Low", "Medium", "High", "Critical"]:
            self.assertEqual(
                counts.get(label, 0),
                300,
                f"Expected 300 for {label}, got {counts.get(label, 0)}",
            )

    def test_e_exploit_probability(self):
        """Confirm exploit_probability values are numeric and within [0.0, 1.0]."""
        probs = self.df["exploit_probability"].astype(float)
        self.assertTrue((probs >= 0.0).all() and (probs <= 1.0).all())

    def test_f_valid_systems(self):
        """Confirm all generated system_id values belong to the allowed systems list."""
        allowed_systems = {
            "WEB01",
            "APP01",
            "AUTH01",
            "VPN01",
            "EMP01",
            "DB01",
            "BACKUP01",
        }
        actual_systems = set(self.df["system_id"])
        self.assertTrue(actual_systems.issubset(allowed_systems))

    def test_g_reproducibility(self):
        """Confirm generating twice with seed=42 produces identical records for at least the first 10 rows."""
        temp_csv_1 = Path(self.temp_dir.name) / "repro_1.csv"
        temp_csv_2 = Path(self.temp_dir.name) / "repro_2.csv"

        df1 = generate_training_data(
            output_path=temp_csv_1,
            samples_per_class=50,
            seed=42,
        )
        df2 = generate_training_data(
            output_path=temp_csv_2,
            samples_per_class=50,
            seed=42,
        )

        pd.testing.assert_frame_equal(df1.head(10), df2.head(10))

    def test_h_leakage_check(self):
        """Confirm the internal calculated risk score does not appear in the saved dataset."""
        for col in LEAKAGE_COLUMNS:
            self.assertNotIn(col, self.df.columns)


if __name__ == "__main__":
    unittest.main()
