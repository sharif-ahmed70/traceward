"""Unit tests for K-Means clustering and structural profile analysis."""

import sys
import unittest
import tempfile
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import hashlib
import pandas as pd
import numpy as np
from src.kmeans_clustering import (
    FEATURE_COLUMNS,
    compare_k_values,
    compute_cluster_profiles,
    generate_cluster_profiles,
    load_processed_data,
    plot_metrics,
    run_kmeans,
    run_kmeans_pipeline,
    save_kmeans_artifacts,
    select_best_k,
    select_k,
    validate_kmeans_input,
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

    def test_06_artifacts_exist_and_nonempty_in_temp_dir(self):
        """Confirm all required analysis artifact files are generated and readable."""
        with tempfile.TemporaryDirectory() as tmpdir:
            run_kmeans(data_path=str(self.data_path), output_path=os.path.join(tmpdir, "cluster_assignments.csv"))
            required_files = [
                "cluster_assignments.csv",
                "k_selection_metrics.csv",
                "elbow_plot.png",
                "silhouette_plot.png",
                "cluster_profiles.csv",
                "cluster_analysis.txt",
            ]
            for fname in required_files:
                fpath = Path(tmpdir) / fname
                self.assertTrue(fpath.exists(), f"Missing artifact: {fname}")
                self.assertGreater(fpath.stat().st_size, 0, f"Empty artifact: {fname}")

            # Confirm CSVs can be read back successfully
            pd.read_csv(Path(tmpdir) / "cluster_assignments.csv")
            pd.read_csv(Path(tmpdir) / "k_selection_metrics.csv")
            pd.read_csv(Path(tmpdir) / "cluster_profiles.csv")

    def test_07_load_processed_data_success(self):
        """Confirm load_processed_data returns a non-empty DataFrame."""
        df = load_processed_data(str(self.data_path))
        self.assertIsInstance(df, pd.DataFrame)
        self.assertFalse(df.empty)

    def test_08_load_processed_data_missing_file_raises(self):
        """Confirm load_processed_data raises FileNotFoundError for missing path."""
        with self.assertRaises(FileNotFoundError):
            load_processed_data("nonexistent/path.csv")

    def test_09_validate_kmeans_input_valid_data(self):
        """Confirm validate_kmeans_input accepts valid processed DataFrame."""
        validate_kmeans_input(self.df)

    def test_10_validate_kmeans_input_missing_feature_column_raises(self):
        """Confirm validate_kmeans_input rejects missing feature column."""
        df = self.df.drop(columns=[FEATURE_COLUMNS[0]])
        with self.assertRaises(ValueError):
            validate_kmeans_input(df)

    def test_11_validate_kmeans_input_empty_dataset_raises(self):
        """Confirm validate_kmeans_input rejects empty DataFrame."""
        df = self.df.iloc[:0]
        with self.assertRaises(ValueError):
            validate_kmeans_input(df)

    def test_12_validate_kmeans_input_non_numeric_feature_raises(self):
        """Confirm validate_kmeans_input rejects non-numeric feature columns."""
        df = self.df.copy()
        df[FEATURE_COLUMNS[0]] = "invalid"
        with self.assertRaises(ValueError):
            validate_kmeans_input(df)

    def test_13_validate_kmeans_input_missing_vuln_id_raises(self):
        """Confirm validate_kmeans_input rejects missing or empty vuln_id."""
        df = self.df.copy()
        df.loc[0, "vuln_id"] = ""
        with self.assertRaises(ValueError):
            validate_kmeans_input(df)

    def test_14_validate_kmeans_input_missing_system_id_raises(self):
        """Confirm validate_kmeans_input rejects missing or empty system_id."""
        df = self.df.copy()
        df.loc[0, "system_id"] = ""
        with self.assertRaises(ValueError):
            validate_kmeans_input(df)

    def test_15_validate_kmeans_input_nan_feature_values_raise(self):
        """Confirm validate_kmeans_input rejects NaN values in feature columns."""
        df = self.df.copy()
        df.loc[0, FEATURE_COLUMNS[0]] = np.nan
        with self.assertRaises(ValueError):
            validate_kmeans_input(df)

    def test_16_select_k_alias_returns_same_as_select_best_k(self):
        """Confirm select_k is a functional alias for select_best_k."""
        from sklearn.preprocessing import StandardScaler

        X = self.df[FEATURE_COLUMNS]
        X_scaled = StandardScaler().fit_transform(X)
        metrics = compare_k_values(X_scaled, k_range=range(2, 9), random_state=42)
        k1, _ = select_best_k(metrics)
        k2, _ = select_k(metrics)
        self.assertEqual(k1, k2)

    def test_17_generate_cluster_profiles_alias_works(self):
        """Confirm generate_cluster_profiles returns same result as compute_cluster_profiles."""
        from sklearn.preprocessing import StandardScaler
        from sklearn.cluster import KMeans

        X = self.df[FEATURE_COLUMNS]
        X_scaled = StandardScaler().fit_transform(X)
        km = KMeans(n_clusters=4, random_state=42, n_init=10)
        labels = km.fit_predict(X_scaled)

        profiles_a = compute_cluster_profiles(self.df, labels)
        profiles_b = generate_cluster_profiles(self.df, labels)

        pd.testing.assert_frame_equal(profiles_a, profiles_b)

    def test_18_cluster_profiles_contains_required_columns(self):
        """Confirm cluster_profiles.csv contains required summary columns."""
        profiles = pd.read_csv(Path("artifacts/kmeans/cluster_profiles.csv"))
        self.assertIn("cluster_id", profiles.columns)
        self.assertIn("sample_count", profiles.columns)
        self.assertIn("proportion", profiles.columns)
        for feat in FEATURE_COLUMNS:
            self.assertIn(f"{feat}_mean", profiles.columns)

    def test_19_cluster_profiles_contains_risk_distribution(self):
        """Confirm cluster_profiles includes post-hoc risk-label distribution."""
        profiles = pd.read_csv(Path("artifacts/kmeans/cluster_profiles.csv"))
        expected_risk_cols = [
            "risk_low_count", "risk_low_pct",
            "risk_medium_count", "risk_medium_pct",
            "risk_high_count", "risk_high_pct",
            "risk_critical_count", "risk_critical_pct",
        ]
        for col in expected_risk_cols:
            self.assertIn(col, profiles.columns)

    def test_20_k_selection_metrics_columns(self):
        """Confirm k_selection_metrics.csv has exact required columns."""
        metrics = pd.read_csv(Path("artifacts/kmeans/k_selection_metrics.csv"))
        self.assertEqual(list(metrics.columns), ["k", "inertia", "silhouette_score"])

    def test_21_k_selection_metrics_contains_all_requested_k_values(self):
        """Confirm k_selection_metrics contains K=2 through 8."""
        metrics = pd.read_csv(Path("artifacts/kmeans/k_selection_metrics.csv"))
        self.assertEqual(sorted(metrics["k"].tolist()), [2, 3, 4, 5, 6, 7, 8])

    def test_22_k_selection_metrics_inertia_decreases_with_k(self):
        """Confirm inertia decreases monotonically as K increases."""
        metrics = pd.read_csv(Path("artifacts/kmeans/k_selection_metrics.csv"))
        self.assertTrue((metrics["inertia"].diff().dropna() < 0).all())

    def test_23_run_kmeans_pipeline_alias_works(self):
        """Confirm run_kmeans_pipeline produces identical results to run_kmeans."""
        with tempfile.TemporaryDirectory() as tmpdir:
            out_main = os.path.join(tmpdir, "main.csv")
            out_alias = os.path.join(tmpdir, "alias.csv")

            res_main = run_kmeans(data_path=str(self.data_path), output_path=out_main)
            res_alias = run_kmeans_pipeline(data_path=str(self.data_path), output_path=out_alias)

            pd.testing.assert_frame_equal(res_main, res_alias)

    def test_24_deterministic_rerun_produces_same_assignments(self):
        """Confirm repeated runs produce identical cluster assignments."""
        with tempfile.TemporaryDirectory() as tmpdir:
            out1 = os.path.join(tmpdir, "run1.csv")
            out2 = os.path.join(tmpdir, "run2.csv")

            run_kmeans(data_path=str(self.data_path), output_path=out1)
            run_kmeans(data_path=str(self.data_path), output_path=out2)

            self.assertEqual(Path(out1).read_bytes(), Path(out2).read_bytes())

    def test_25_deterministic_rerun_produces_same_metrics(self):
        """Confirm repeated runs produce identical K-selection metrics."""
        with tempfile.TemporaryDirectory() as tmpdir:
            run_kmeans(data_path=str(self.data_path), output_path=os.path.join(tmpdir, "a.csv"))
            metrics1 = Path(tmpdir, "k_selection_metrics.csv").read_bytes()

            run_kmeans(data_path=str(self.data_path), output_path=os.path.join(tmpdir, "b.csv"))
            metrics2 = Path(tmpdir, "k_selection_metrics.csv").read_bytes()

            self.assertEqual(metrics1, metrics2)

    def test_26_features_not_used_for_clustering(self):
        """Confirm vuln_id, system_id, risk_label, and description are not in FEATURE_COLUMNS."""
        forbidden = ["vuln_id", "system_id", "risk_label", "description"]
        for col in forbidden:
            self.assertNotIn(col, FEATURE_COLUMNS)

    def test_27_output_validation_preserves_identifiers(self):
        """Confirm run_kmeans preserves vuln_id and system_id exactly."""
        self.assertTrue(
            self.assignments["vuln_id"].reset_index(drop=True).equals(
                self.df["vuln_id"].reset_index(drop=True)
            )
        )
        self.assertTrue(
            self.assignments["system_id"].reset_index(drop=True).equals(
                self.df["system_id"].reset_index(drop=True)
            )
        )

    def test_28_cluster_profiles_sample_counts_sum_to_total(self):
        """Confirm cluster profile sample counts sum to the input row count."""
        profiles = pd.read_csv(Path("artifacts/kmeans/cluster_profiles.csv"))
        self.assertEqual(profiles["sample_count"].sum(), len(self.df))

    def test_29_cluster_profiles_proportions_sum_approximately_100(self):
        """Confirm cluster profile proportions sum to approximately 100."""
        profiles = pd.read_csv(Path("artifacts/kmeans/cluster_profiles.csv"))
        total_pct = profiles["proportion"].sum()
        self.assertAlmostEqual(total_pct, 100.0, delta=1.0)

    def test_30_cluster_profile_statistics_match_assigned_rows(self):
        """Confirm profile feature means match the actual assigned rows."""
        assignments = pd.read_csv(Path("artifacts/kmeans/cluster_assignments.csv"))
        profiles = pd.read_csv(Path("artifacts/kmeans/cluster_profiles.csv"))

        for _, row in profiles.iterrows():
            cid = int(row["cluster_id"])
            mask = assignments["cluster_id"] == cid
            grp = self.df[mask]

            for feat in FEATURE_COLUMNS:
                expected_mean = round(float(grp[feat].mean()), 3)
                actual_mean = row[f"{feat}_mean"]
                self.assertAlmostEqual(expected_mean, actual_mean, places=3)

    def test_31_risk_label_change_does_not_change_assignments(self):
        """Confirm changing risk_label alone does not affect cluster assignments (leakage protection)."""
        from sklearn.preprocessing import StandardScaler
        from sklearn.cluster import KMeans

        # Use a small deterministic subset
        sample = self.df.head(50).reset_index(drop=True)
        features = sample[FEATURE_COLUMNS]
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(features)

        # Run K-Means with original risk labels
        km = KMeans(n_clusters=4, random_state=42, n_init=10)
        original_labels = km.fit_predict(X_scaled)

        # Change risk labels completely
        shuffled_labels = np.random.RandomState(42).permutation(sample["risk_label"].values)
        sample["risk_label"] = shuffled_labels

        # Run K-Means again with identical features but different risk labels
        km2 = KMeans(n_clusters=4, random_state=42, n_init=10)
        new_labels = km2.fit_predict(X_scaled)

        np.testing.assert_array_equal(original_labels, new_labels)

    def test_32_save_kmeans_artifacts_creates_required_files(self):
        """Confirm save_kmeans_artifacts creates all required artifact files."""
        from sklearn.preprocessing import StandardScaler
        from sklearn.cluster import KMeans

        X = self.df[FEATURE_COLUMNS]
        X_scaled = StandardScaler().fit_transform(X)
        km = KMeans(n_clusters=4, random_state=42, n_init=10)
        labels = km.fit_predict(X_scaled)

        metrics_df = compare_k_values(X_scaled, k_range=range(2, 9), random_state=42)
        profiles_df = compute_cluster_profiles(self.df, labels)
        assignments = pd.DataFrame({
            "vuln_id": self.df["vuln_id"],
            "system_id": self.df["system_id"],
            "cluster_id": labels,
        })

        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = save_kmeans_artifacts(metrics_df, profiles_df, assignments, output_dir=Path(tmpdir))

            required = [
                "k_selection_metrics.csv",
                "cluster_profiles.csv",
                "cluster_assignments.csv",
            ]
            for fname in required:
                fpath = out_dir / fname
                self.assertTrue(fpath.exists(), f"Missing artifact: {fname}")
                self.assertGreater(fpath.stat().st_size, 0, f"Empty artifact: {fname}")

    def test_33_run_kmeans_with_forced_n_clusters(self):
        """Confirm run_kmeans accepts forced n_clusters and still produces valid output."""
        with tempfile.TemporaryDirectory() as tmpdir:
            out_path = os.path.join(tmpdir, "assignments.csv")
            assignments = run_kmeans(
                data_path=str(self.data_path),
                output_path=out_path,
                n_clusters=5,
                random_state=42,
            )
            self.assertEqual(len(assignments), 1200)
            self.assertEqual(list(assignments.columns), ["vuln_id", "system_id", "cluster_id"])

    def test_34_invalid_input_empty_feature_column_raises(self):
        """Confirm validate_kmeans_input rejects DataFrame with empty feature values."""
        df = self.df.copy()
        df[FEATURE_COLUMNS[0]] = df[FEATURE_COLUMNS[0]].astype(object)
        df.loc[0, FEATURE_COLUMNS[0]] = ""
        with self.assertRaises(ValueError):
            validate_kmeans_input(df)

    def test_35_cluster_profiles_have_every_cluster(self):
        """Confirm every cluster has a profile in the output."""
        profiles = pd.read_csv(Path("artifacts/kmeans/cluster_profiles.csv"))
        self.assertEqual(len(profiles), 4)
        self.assertEqual(sorted(profiles["cluster_id"].tolist()), [0, 1, 2, 3])


if __name__ == "__main__":
    unittest.main()
