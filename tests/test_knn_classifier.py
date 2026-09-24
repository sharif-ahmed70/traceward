"""Unit tests for KNN risk classification module and model evaluation."""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import pandas as pd
from sklearn.pipeline import Pipeline
from src.knn_classifier import (
    FEATURE_COLUMNS,
    evaluate_model,
    get_features_and_target,
    load_data,
    predict_and_export,
    split_data,
    train_and_select_k,
)


class TestKNNClassifier(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.df = load_data()
        cls.X, cls.y, cls.ids = get_features_and_target(cls.df)
        cls.X_tr, cls.X_te, cls.y_tr, cls.y_te, cls.id_tr, cls.id_te = split_data(
            cls.X, cls.y, cls.ids, test_size=0.2, random_state=42
        )
        cls.model, cls.best_k = train_and_select_k(cls.X_tr, cls.y_tr)

    def test_01_feature_columns_match_contract(self):
        """Confirm the 7 agreed security features are selected."""
        self.assertEqual(list(self.X.columns), FEATURE_COLUMNS)
        self.assertEqual(len(FEATURE_COLUMNS), 7)

    def test_02_target_is_risk_label(self):
        """Confirm target is risk_label with four balanced classes."""
        self.assertEqual(self.y.name, "risk_label")
        self.assertEqual(set(self.y.unique()), {"Low", "Medium", "High", "Critical"})

    def test_03_split_proportions(self):
        """Confirm stratified 80/20 train/test split sizes."""
        self.assertEqual(len(self.X_tr), 960)
        self.assertEqual(len(self.X_te), 240)

    def test_04_no_identifiers_in_features(self):
        """Confirm identifiers and descriptions are completely excluded from X."""
        self.assertNotIn("vuln_id", self.X.columns)
        self.assertNotIn("system_id", self.X.columns)
        self.assertNotIn("description", self.X.columns)

    def test_05_cv_selection_and_pipeline_structure(self):
        """Confirm selected model is a Pipeline with internal scaling and valid K."""
        self.assertIsInstance(self.model, Pipeline)
        self.assertIn("scaler", self.model.named_steps)
        self.assertIn("knn", self.model.named_steps)
        self.assertIn(self.best_k, [3, 5, 7, 9])
        self.assertEqual(self.model.named_steps["knn"].n_neighbors, self.best_k)

    def test_06_model_generalization_soundness(self):
        """Confirm held-out test accuracy is substantially above random guess (0.25)."""
        acc = self.model.score(self.X_te, self.y_te)
        self.assertGreater(acc, 0.65)

    def test_07_artifacts_and_predictions_export(self):
        """Confirm all expected artifacts and prediction CSV files are exported."""
        metrics = evaluate_model(self.model, self.X_te, self.y_te, selected_k=self.best_k)
        preds = predict_and_export(self.model, self.X_te, self.y_te, self.id_te)

        self.assertEqual(len(preds), 240)
        self.assertEqual(
            list(preds.columns),
            ["vuln_id", "system_id", "actual_risk", "predicted_risk"],
        )

        artifacts_dir = Path("artifacts/knn")
        required_files = [
            "k_selection_cv.csv",
            "evaluation_report.txt",
            "confusion_matrix.png",
            "predictions.csv",
            "test_predictions.csv",
        ]
        for fname in required_files:
            fpath = artifacts_dir / fname
            self.assertTrue(fpath.exists(), f"Missing KNN artifact: {fname}")
            self.assertGreater(fpath.stat().st_size, 0, f"Empty KNN artifact: {fname}")


if __name__ == "__main__":
    unittest.main()
