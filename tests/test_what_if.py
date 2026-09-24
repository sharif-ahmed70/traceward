"""Unit tests for What-If scenario simulation and integrated live inference."""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import pandas as pd
from src.what_if_simulation import simulate_patch_impact
from src.knn_classifier import LABELS, predict_single_vulnerability
from src.csp_solver import CSPCase, VulnerabilityTask, solve_csp


class TestWhatIfSimulation(unittest.TestCase):
    def test_01_simulate_patch_on_path_increases_traversal_cost(self):
        """Confirm patching a system on the attack path increases adversary traversal cost."""
        res = simulate_patch_impact("WEB01", risk_reduction_factor=0.5)
        self.assertEqual(res["status"], "success")
        self.assertEqual(res["target_system"], "WEB01")

        # System risk should decrease
        base_risk = res["baseline"]["system_risk"]["normalized_risk"]
        sim_risk = res["simulated"]["system_risk"]["normalized_risk"]
        self.assertLess(sim_risk, base_risk)
        self.assertAlmostEqual(res["deltas"]["risk_reduction"], base_risk - sim_risk, places=3)

        # Adversary cost should increase (defensive gain)
        base_cost = res["baseline"]["path_cost"]
        sim_cost = res["simulated"]["path_cost"]
        self.assertGreater(sim_cost, base_cost)
        self.assertGreater(res["deltas"]["path_cost_increase"], 0.0)

    def test_02_baseline_data_remains_unmodified(self):
        """Confirm that simulation runs strictly on copies and does not alter disk artifacts."""
        risk_path = Path("artifacts/risk/system_risk_summary.csv")
        before_df = pd.read_csv(risk_path)
        simulate_patch_impact("APP01", risk_reduction_factor=0.6)
        after_df = pd.read_csv(risk_path)
        pd.testing.assert_frame_equal(before_df, after_df)

    def test_03_invalid_target_system_raises_value_error(self):
        """Confirm simulation rejects unknown system identifiers."""
        with self.assertRaises(ValueError):
            simulate_patch_impact("NON_EXISTENT_SERVER")

    def test_04_knn_live_inference_predicts_valid_class(self):
        """Confirm fitted KNN pipeline accepts new inputs and returns valid class & probabilities."""
        sample_features = {
            "attack_complexity": 0,
            "privileges_required": 0,
            "user_interaction": 0,
            "confidentiality_impact": 2,
            "integrity_impact": 2,
            "availability_impact": 2,
            "exploit_probability": 0.95,
        }
        res = predict_single_vulnerability(sample_features)
        self.assertIn(res["predicted_risk"], LABELS)
        self.assertEqual(res["predicted_risk"], "Critical")
        probs = res["probabilities"]
        self.assertEqual(set(probs.keys()), set(LABELS))
        self.assertAlmostEqual(sum(probs.values()), 1.0, places=3)

    def test_05_knn_live_inference_missing_feature_raises_value_error(self):
        """Confirm missing feature in new prediction input raises ValueError."""
        incomplete_features = {
            "attack_complexity": 0,
            "privileges_required": 0,
        }
        with self.assertRaises(ValueError):
            predict_single_vulnerability(incomplete_features)

    def test_06_csp_infeasible_case_handled_clearly(self):
        """Confirm CSP solver handles overconstrained schedules with a clear infeasible status."""
        overconstrained_case = CSPCase(
            vulnerabilities=(
                VulnerabilityTask("VULN-001", "WEB01", "Critical", "Web Team"),
                VulnerabilityTask("VULN-002", "DB01", "High", "Web Team"),
            ),
            available_teams=("Web Team",),
            time_slots=("Mon 09:00",),  # Only 1 slot for 2 tasks assigned to the same team
        )
        res = solve_csp(overconstrained_case, raise_on_infeasible=False)
        self.assertEqual(res["status"], "infeasible")
        self.assertEqual(len(res["schedule"]), 0)
        self.assertIn("No feasible remediation schedule exists", res["message"])


if __name__ == "__main__":
    unittest.main()

