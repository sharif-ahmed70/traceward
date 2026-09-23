"""Unit tests for TraceWard Structured Explainability Engine."""

from __future__ import annotations

import unittest
from src.explainability import (
    compute_feature_contributions,
    explain_attack_path,
    explain_patch_priority,
    explain_risk,
    explain_vulnerability,
    generate_recommended_action,
    generate_risk_factors,
    get_system_context,
)


class TestExplainabilityEngine(unittest.TestCase):
    """Test suite verifying explainability schemas, attributions, and compatibility."""

    def test_get_system_context_crown_jewel(self):
        ctx = get_system_context("DB01")
        self.assertEqual(ctx["system_id"], "DB01")
        self.assertEqual(ctx["name"], "Database Server")
        self.assertEqual(ctx["type"], "Database")
        self.assertEqual(ctx["criticality"], 5)
        self.assertIn("Crown Jewel", ctx["criticality_label"])
        self.assertFalse(ctx["internet_exposed"])
        self.assertIn("Internal", ctx["exposure_scope"])

    def test_get_system_context_perimeter(self):
        ctx = get_system_context("WEB01")
        self.assertEqual(ctx["system_id"], "WEB01")
        self.assertEqual(ctx["criticality"], 4)
        self.assertTrue(ctx["internet_exposed"])
        self.assertIn("Perimeter-Facing", ctx["exposure_scope"])

    def test_get_system_context_unknown_fallback(self):
        ctx = get_system_context("UNKNOWN_SYS_99")
        self.assertEqual(ctx["system_id"], "UNKNOWN_SYS_99")
        self.assertEqual(ctx["criticality"], 3)
        self.assertFalse(ctx["internet_exposed"])

    def test_compute_feature_contributions_bounds(self):
        features = {
            "attack_complexity": 0,
            "privileges_required": 0,
            "user_interaction": 0,
            "confidentiality_impact": 2,
            "integrity_impact": 2,
            "availability_impact": 2,
            "exploit_probability": 0.95,
        }
        res = compute_feature_contributions(features)
        subscores = res["subscores"]
        contributions = res["contributions"]

        self.assertIn("exploitability_score", subscores)
        self.assertIn("impact_score", subscores)
        self.assertGreaterEqual(subscores["exploitability_score"], 0.0)
        self.assertLessEqual(subscores["exploitability_score"], 1.0)
        self.assertGreaterEqual(subscores["impact_score"], 0.0)
        self.assertLessEqual(subscores["impact_score"], 1.0)

        # Max impact should equal 1.0
        self.assertEqual(subscores["impact_score"], 1.0)

        # Check all 7 feature keys present in contributions
        expected_keys = {
            "attack_complexity",
            "privileges_required",
            "user_interaction",
            "confidentiality_impact",
            "integrity_impact",
            "availability_impact",
            "exploit_probability",
        }
        self.assertEqual(set(contributions.keys()), expected_keys)
        for k, v in contributions.items():
            self.assertIn("direction", v)
            self.assertIn("rationale", v)
            self.assertIn("normalized_risk", v)

    def test_generate_risk_factors(self):
        features = {
            "attack_complexity": 0,
            "privileges_required": 0,
            "user_interaction": 0,
            "confidentiality_impact": 2,
            "integrity_impact": 1,
            "availability_impact": 2,
            "exploit_probability": 0.85,
        }
        asset_ctx = get_system_context("DB01")
        factors = generate_risk_factors(features, asset_ctx, "Critical")

        factor_text = " ".join(factors)
        self.assertIn("Unauthenticated Access", factor_text)
        self.assertIn("Low Attack Complexity", factor_text)
        self.assertIn("Autonomous Exploitation", factor_text)
        self.assertIn("High Exploit Probability", factor_text)
        self.assertIn("High Confidentiality Loss", factor_text)
        self.assertIn("Crown-Jewel Asset", factor_text)

    def test_generate_recommended_action_critical_crown_jewel(self):
        asset_ctx = get_system_context("DB01")
        subscores = {"primary_driver": "Impact (CIA Triad)"}
        action = generate_recommended_action("Critical", asset_ctx, subscores)
        self.assertIn("Emergency Remediation", action)
        self.assertIn("24h", action)

    def test_generate_recommended_action_perimeter(self):
        asset_ctx = get_system_context("WEB01")
        subscores = {"primary_driver": "Exploitability (Attack Ease)"}
        action = generate_recommended_action("High", asset_ctx, subscores)
        self.assertIn("Perimeter Defense", action)

    def test_explain_vulnerability_dataset_lookup(self):
        # V1136 is a real record in vulnerabilities_processed.csv on DB01
        res = explain_vulnerability("V1136", "DB01", "Critical", vote_share=1.0)

        # Check required schema fields
        self.assertEqual(res["vulnerability_id"], "V1136")
        self.assertEqual(res["system_id"], "DB01")
        self.assertEqual(res["predicted_risk"], "Critical")
        self.assertIsInstance(res["risk_factors"], list)
        self.assertGreater(len(res["risk_factors"]), 0)
        self.assertIn("feature_contributions", res)
        self.assertIn("subscores", res)
        self.assertIn("asset_context", res)
        self.assertIn("recommended_action", res)

        # Backward compatibility assertions
        self.assertEqual(res["vuln_id"], "V1136")
        self.assertEqual(res["decision"], "Critical")
        self.assertEqual(res["evidence"], res["risk_factors"])
        self.assertIn("summary", res)
        self.assertIn("human_readable", res)

    def test_explain_risk_backward_compatibility(self):
        # Legacy contract verification
        res = explain_risk(
            "VULN-001",
            "WEB01",
            "Critical",
            risk_factors=["High severity input feature"],
            cluster_id=2,
        )
        self.assertEqual(res["decision"], "Critical")
        self.assertEqual(res["vuln_id"], "VULN-001")
        self.assertEqual(res["system_id"], "WEB01")
        # Legacy custom factor preserved
        self.assertIn("High severity input feature", res["evidence"])
        self.assertIn("cluster 2", res["cluster_context"])
        # New enriched fields available
        self.assertIn("asset_context", res)
        self.assertIn("recommended_action", res)
        self.assertIn("feature_contributions", res)

    def test_legacy_path_and_patch_contracts(self):
        path = explain_attack_path("INTERNET", "DB01", ["INTERNET", "WEB01", "DB01"], 5.0)
        patch = explain_patch_priority("V0036", "WEB01", "Critical", scheduled_slot="Mon 09:00", team="Web Team")

        self.assertEqual(path["path"][-1], "DB01")
        self.assertEqual(path["total_cost"], 5.0)
        self.assertEqual(patch["priority"], "Critical")
        self.assertEqual(patch["scheduled_slot"], "Mon 09:00")
        self.assertEqual(patch["team"], "Web Team")

    def test_explain_attack_path_structured_schema(self):
        path_list = ["INTERNET", "WEB01", "APP01", "DB01"]
        res = explain_attack_path("INTERNET", "DB01", path_list, 4.08)

        # Legacy fields
        self.assertEqual(res["type"], "attack_path")
        self.assertEqual(res["start"], "INTERNET")
        self.assertEqual(res["goal"], "DB01")
        self.assertEqual(res["path"], path_list)
        self.assertEqual(res["total_cost"], 4.08)
        self.assertIn("4.08", res["summary"])

        # Enriched structured fields
        self.assertEqual(res["entry_point"], "INTERNET")
        self.assertEqual(res["target_asset"], "DB01")
        self.assertEqual(res["hop_count"], 3)
        self.assertIn("attack_logic", res)
        self.assertIn("business_impact", res)
        self.assertIn("DB01", res["business_impact"])
        self.assertIn("A*", res["attack_logic"])

        # Path nodes schema validation
        self.assertEqual(len(res["path_nodes"]), 4)
        expected_keys = {
            "node_id", "name", "type", "role", "criticality", "criticality_label",
            "internet_exposed", "phase", "step_cost", "cumulative_cost",
            "risk_score", "risk_level", "risk_reason", "vulnerability_count"
        }
        for node in res["path_nodes"]:
            self.assertTrue(expected_keys.issubset(set(node.keys())))

        # First node (Ingress)
        first = res["path_nodes"][0]
        self.assertEqual(first["node_id"], "INTERNET")
        self.assertEqual(first["step_cost"], 0.0)
        self.assertIn("Ingress", first["phase"])

        # Intermediate node (Lateral)
        intermediate = res["path_nodes"][2]
        self.assertEqual(intermediate["node_id"], "APP01")
        self.assertIn("Lateral", intermediate["phase"])

        # Final node (Crown Jewel)
        last = res["path_nodes"][3]
        self.assertEqual(last["node_id"], "DB01")
        self.assertIn("Crown Jewel", last["phase"])
        self.assertEqual(last["criticality"], 5)

    def test_explain_attack_path_empty_and_single_node(self):
        empty_res = explain_attack_path("INTERNET", "DB01", [])
        self.assertEqual(empty_res["hop_count"], 0)
        self.assertEqual(len(empty_res["path_nodes"]), 0)

        single_res = explain_attack_path("DB01", "DB01", ["DB01"])
        self.assertEqual(single_res["hop_count"], 0)
        self.assertEqual(len(single_res["path_nodes"]), 1)

    def test_explain_patch_priority_corridor_task(self):
        res = explain_patch_priority(
            "V0036",
            "WEB01",
            "Critical",
            scheduled_slot="Mon 09:00",
            team="Web Team",
            depends_on=[],
        )

        # Legacy fields
        self.assertEqual(res["type"], "patch_priority")
        self.assertEqual(res["vuln_id"], "V0036")
        self.assertEqual(res["system_id"], "WEB01")
        self.assertEqual(res["priority"], "Critical")
        self.assertEqual(res["scheduled_slot"], "Mon 09:00")
        self.assertEqual(res["team"], "Web Team")
        self.assertIn("V0036 on WEB01", res["summary"])

        # Structured schema
        self.assertEqual(res["vulnerability_id"], "V0036")
        self.assertEqual(res["risk_level"], "Critical")
        self.assertTrue(res["attack_path_relevance"]["is_on_attack_path"])
        self.assertIn("Perimeter", res["attack_path_relevance"]["path_role"])
        self.assertIn("WEB01", res["attack_path_relevance"]["rationale"])
        self.assertEqual(res["prerequisites"], [])
        self.assertIn("opening window", res["scheduling_reason"])
        self.assertIn("recommended_action", res)
        self.assertIn("subscores", res)
        self.assertEqual(res["asset_context"]["criticality"], 4)

    def test_explain_patch_priority_dependent_task(self):
        res = explain_patch_priority(
            "V0426",
            "APP01",
            "Critical",
            scheduled_slot="Mon 14:00",
            team="Application Team",
            depends_on=["V0036"],
        )

        self.assertEqual(res["vulnerability_id"], "V0426")
        self.assertTrue(res["attack_path_relevance"]["is_on_attack_path"])
        self.assertIn("Lateral", res["attack_path_relevance"]["path_role"])
        self.assertEqual(res["prerequisites"], ["V0036"])
        self.assertIn("temporal dependency", res["scheduling_reason"])
        self.assertIn("V0036", res["scheduling_reason"])

    def test_explain_patch_priority_defense_in_depth(self):
        res = explain_patch_priority(
            "V0186",
            "VPN01",
            "Critical",
            scheduled_slot="Mon 09:00",
            team="Network Team",
            depends_on=[],
        )

        self.assertEqual(res["vulnerability_id"], "V0186")
        self.assertFalse(res["attack_path_relevance"]["is_on_attack_path"])
        self.assertIn("Defense-in-Depth", res["attack_path_relevance"]["path_role"])
        self.assertIn("adjacent", res["attack_path_relevance"]["rationale"])


if __name__ == "__main__":
    unittest.main()

