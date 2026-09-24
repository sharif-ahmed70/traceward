"""Unit tests for K-Means clustering and structural profile analysis."""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import pandas as pd
from src.kmeans_clustering import (
    FEATURE_COLUMNS,
    compare_k_values,
    compute_cluster_profiles,
    run_kmeans,
    select_best_k,
)


class TestKMeansClustering(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data_path = Path("data/processed/vulnerabilities_processed.csv")
        cls.df = pd.read_csv(cls.data_path)
        cls.assignments = run_kmeans(data_path=str(cls.data_path))

    def test_01_feature_columns_match_contract(self):
        """Confirm exactly the 7 agreed security features are specified."""
        self.assertEqual(len(FEATURE_COLUMNS), 7)
        self.assertNotIn("vuln_id", FEATURE_COLUMNS)
        self.assertNotIn("system_id", FEATURE_COLUMNS)
        self.assertNotIn("risk_label", FEATURE_COLUMNS)
        self.assertNotIn("description", FEATURE_COLUMNS)

    def test_02_assignments_row_count_matches_dataset(self):
        """Confirm output cluster assignments match the 1,200 vulnerability records."""
        self.assertEqual(len(self.assignments), len(self.df))
        self.assertEqual(len(self.assignments), 1200)

    def test_03_assignments_columns_and_identifiers(self):
        """Confirm cluster assignments contain vuln_id, system_id, and cluster_id."""
        self.assertEqual(list(self.assignments.columns), ["vuln_id", "system_id", "cluster_id"])
        self.assertTrue((self.assignments["vuln_id"] == self.df["vuln_id"]).all())
        self.assertTrue((self.assignments["system_id"] == self.df["system_id"]).all())

    def test_04_cluster_ids_valid_range(self):
        """Confirm cluster IDs are non-negative integers."""
        import numpy as np
        unique_clusters = set(self.assignments["cluster_id"].unique())
        self.assertTrue(all(isinstance(c, (int, np.integer)) for c in unique_clusters))
        self.assertEqual({int(c) for c in unique_clusters}, {0, 1, 2, 3})

    def test_05_candidate_comparison_generates_valid_metrics(self):
        """Confirm compare_k_values generates metrics for candidate K=2..8."""
        from sklearn.preprocessing import StandardScaler

        X = self.df[FEATURE_COLUMNS]
        X_scaled = StandardScaler().fit_transform(X)
        metrics = compare_k_values(X_scaled, k_range=range(2, 6))

        self.assertEqual(list(metrics.columns), ["k", "inertia", "silhouette_score"])
        self.assertEqual(len(metrics), 4)
        # Inertia must decrease monotonically with increasing K
        self.assertTrue((metrics["inertia"].diff().dropna() < 0).all())

    def test_06_artifacts_exist_and_nonempty(self):
        """Confirm all required analysis artifact files are generated on disk."""
        artifacts_dir = Path("artifacts/kmeans")
        required_files = [
            "cluster_assignments.csv",
            "k_selection_metrics.csv",
            "elbow_plot.png",
            "silhouette_plot.png",
            "cluster_profiles.csv",
            "cluster_analysis.txt",
        ]
        for fname in required_files:
            fpath = artifacts_dir / fname
            self.assertTrue(fpath.exists(), f"Missing artifact: {fname}")
            self.assertGreater(fpath.stat().st_size, 0, f"Empty artifact: {fname}")


if __name__ == "__main__":
    unittest.main()
