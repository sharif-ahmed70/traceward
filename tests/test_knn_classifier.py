import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import pandas as pd
from src.knn_classifier import (
    load_data,
    get_features_and_target,
    split_data,
    train_and_select_k,
    evaluate_model,
    predict_and_export,
)

EXPECTED_FEATURES = [
    "attack_complexity",
    "privileges_required",
    "user_interaction",
    "confidentiality_impact",
    "integrity_impact",
    "availability_impact",
    "exploit_probability",
]


class TestKNNClassifier(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.df = load_data()
        cls.X, cls.y, cls.ids = get_features_and_target(cls.df)
        cls.X_tr, cls.X_te, cls.y_tr, cls.y_te, cls.id_tr, cls.id_te = split_data(
            cls.X, cls.y, cls.ids, test_size=0.2, random_state=42
        )

    def test_01_feature_columns_match_contract(self):
        self.assertEqual(list(self.X.columns), EXPECTED_FEATURES)

    def test_02_target_is_risk_label(self):
        self.assertEqual(self.y.name, "risk_label")
        self.assertEqual(set(self.y.unique()), {"Low", "Medium", "High", "Critical"})

    def test_03_split_proportions(self):
        self.assertEqual(len(self.X_tr), 960)
        self.assertEqual(len(self.X_te), 240)

    def test_04_no_identifiers_in_features(self):
        self.assertNotIn("vuln_id", self.X.columns)
        self.assertNotIn("system_id", self.X.columns)
        self.assertNotIn("description", self.X.columns)

    def test_05_model_accuracy_above_threshold(self):
        model, best_k = train_and_select_k(self.X_tr, self.y_tr, self.X_te, self.y_te)
        self.assertIn(best_k, [3, 5, 7, 9])
        acc = model.score(self.X_te, self.y_te)
        self.assertGreater(acc, 0.70)

    def test_06_predictions_export(self):
        model, _ = train_and_select_k(self.X_tr, self.y_tr, self.X_te, self.y_te)
        preds = predict_and_export(model, self.X_te, self.y_te, self.id_te)
        self.assertEqual(len(preds), 240)
        self.assertEqual(
            list(preds.columns),
            ["vuln_id", "system_id", "actual_risk", "predicted_risk"],
        )


if __name__ == "__main__":
    unittest.main()

