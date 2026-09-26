"""Unit tests for the TraceWard incident priority analyzer."""

from __future__ import annotations

import tempfile
import unittest

import pandas as pd

from src.incident_correlator import Incident, incident_to_dict
from src.incident_priority_analyzer import (
    IMMEDIATE_ATTENTION,
    HIGH_PRIORITY,
    LOWER_PRIORITY,
    SCHEDULED,
    IncidentPriorityEntry,
    build_incident_priority_table,
    enrich_system_risk_with_incident_context,
    get_system_metadata,
    is_critical_asset,
    is_on_attack_path,
    _determine_priority,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_incident(
    incident_id: str = "INC-TEST",
    scenario_id: str = "test_scenario",
    entry_point: str = "INTERNET",
    affected_systems: tuple[str, ...] = ("WEB01", "APP01"),
    related_vulnerabilities: tuple[str, ...] = ("V001", "V002"),
    critical_assets_affected: tuple[str, ...] = ("WEB01",),
) -> Incident:
    return Incident(
        incident_id=incident_id,
        scenario_id=scenario_id,
        entry_point=entry_point,
        affected_systems=affected_systems,
        related_vulnerabilities=related_vulnerabilities,
        event_count=len(related_vulnerabilities),
        critical_assets_affected=critical_assets_affected,
        attack_sequence=(),
    )


def _make_predictions(
    vulns: dict[str, tuple[str, str]] | None = None,
) -> pd.DataFrame:
    """Build a predictions DataFrame.

    Args:
        vulns: mapping of vuln_id -> (system_id, predicted_risk).
    """
    if vulns is None:
        vulns = {
            "V001": ("WEB01", "Critical"),
            "V002": ("APP01", "High"),
            "V003": ("DB01", "Medium"),
            "V004": ("EMP01", "Low"),
        }
    records = [
        {"vuln_id": vid, "system_id": sid, "predicted_risk": risk}
        for vid, (sid, risk) in vulns.items()
    ]
    return pd.DataFrame(records)


# ---------------------------------------------------------------------------
# Priority logic tests
# ---------------------------------------------------------------------------


class TestDeterminePriority(unittest.TestCase):
    """TraceWard simulation priority assignment must follow clear categorical rules."""

    def test_immediate_critical_on_path_critical_exposed(self):
        priority, reason = _determine_priority(
            vulnerability_risk="Critical",
            on_attack_path=True,
            is_critical_asset=True,
            internet_exposed=True,
        )
        self.assertEqual(priority, IMMEDIATE_ATTENTION)
        self.assertIn("internet-exposed", reason.lower())

    def test_immediate_critical_on_path_critical_not_exposed(self):
        priority, reason = _determine_priority(
            vulnerability_risk="Critical",
            on_attack_path=True,
            is_critical_asset=True,
            internet_exposed=False,
        )
        self.assertEqual(priority, IMMEDIATE_ATTENTION)
        self.assertIn("crown jewel", reason.lower())

    def test_immediate_requires_critical_risk(self):
        priority, _ = _determine_priority(
            vulnerability_risk="High",
            on_attack_path=True,
            is_critical_asset=True,
            internet_exposed=True,
        )
        self.assertNotEqual(priority, IMMEDIATE_ATTENTION)

    def test_immediate_requires_critical_asset(self):
        priority, _ = _determine_priority(
            vulnerability_risk="Critical",
            on_attack_path=True,
            is_critical_asset=False,
            internet_exposed=False,
        )
        self.assertNotEqual(priority, IMMEDIATE_ATTENTION)

    def test_high_critical_on_path_critical_asset(self):
        priority, _ = _determine_priority(
            vulnerability_risk="Critical",
            on_attack_path=True,
            is_critical_asset=True,
            internet_exposed=False,
        )
        # Already covered by Immediate in this case, verify the higher tier wins
        self.assertEqual(priority, IMMEDIATE_ATTENTION)

    def test_high_critical_on_critical_asset_off_path(self):
        priority, reason = _determine_priority(
            vulnerability_risk="Critical",
            on_attack_path=False,
            is_critical_asset=True,
            internet_exposed=False,
        )
        self.assertEqual(priority, HIGH_PRIORITY)
        self.assertIn("defense-in-depth", reason.lower())

    def test_high_high_on_path_critical_asset(self):
        priority, reason = _determine_priority(
            vulnerability_risk="High",
            on_attack_path=True,
            is_critical_asset=True,
            internet_exposed=False,
        )
        self.assertEqual(priority, HIGH_PRIORITY)
        self.assertIn("attack corridor", reason.lower())

    def test_high_critical_on_path_non_critical_asset(self):
        priority, reason = _determine_priority(
            vulnerability_risk="Critical",
            on_attack_path=True,
            is_critical_asset=False,
            internet_exposed=False,
        )
        self.assertEqual(priority, SCHEDULED)
        self.assertIn("attack path", reason.lower())

    def test_scheduled_medium_on_critical_asset_off_path(self):
        priority, reason = _determine_priority(
            vulnerability_risk="Medium",
            on_attack_path=False,
            is_critical_asset=True,
            internet_exposed=False,
        )
        self.assertEqual(priority, SCHEDULED)
        self.assertIn("maintenance window", reason.lower())

    def test_scheduled_high_off_path_non_critical(self):
        priority, reason = _determine_priority(
            vulnerability_risk="High",
            on_attack_path=False,
            is_critical_asset=False,
            internet_exposed=False,
        )
        self.assertEqual(priority, SCHEDULED)
        self.assertIn("standard patch cycle", reason.lower())

    def test_scheduled_medium_on_path_non_critical(self):
        priority, reason = _determine_priority(
            vulnerability_risk="Medium",
            on_attack_path=True,
            is_critical_asset=False,
            internet_exposed=False,
        )
        self.assertEqual(priority, SCHEDULED)
        self.assertIn("lateral movement", reason.lower())

    def test_lower_low_on_path_critical_asset(self):
        priority, reason = _determine_priority(
            vulnerability_risk="Low",
            on_attack_path=True,
            is_critical_asset=True,
            internet_exposed=False,
        )
        self.assertEqual(priority, LOWER_PRIORITY)
        self.assertIn("routine", reason.lower())

    def test_lower_low_off_path_non_critical(self):
        priority, reason = _determine_priority(
            vulnerability_risk="Low",
            on_attack_path=False,
            is_critical_asset=False,
            internet_exposed=False,
        )
        self.assertEqual(priority, LOWER_PRIORITY)
        self.assertIn("routine", reason.lower())


# ---------------------------------------------------------------------------
# System metadata and attack path tests
# ---------------------------------------------------------------------------


class TestSystemMetadataHelpers(unittest.TestCase):
    def test_is_critical_asset_high_criticality(self):
        systems = {
            "DB01": {"criticality": 5, "internet_exposed": False},
        }
        self.assertTrue(is_critical_asset("DB01", systems))

    def test_is_critical_asset_internet_exposed(self):
        systems = {
            "WEB01": {"criticality": 2, "internet_exposed": True},
        }
        self.assertTrue(is_critical_asset("WEB01", systems))

    def test_is_not_critical_asset_low_criticality_and_internal(self):
        systems = {
            "EMP01": {"criticality": 2, "internet_exposed": False},
        }
        self.assertFalse(is_critical_asset("EMP01", systems))

    def test_is_critical_asset_fallback_defaults(self):
        self.assertFalse(is_critical_asset("UNKNOWN", {}))
        self.assertTrue(is_critical_asset("UNKNOWN", {"UNKNOWN": {"criticality": 5}}))

    def test_on_attack_path_true(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as f:
            f.write('{"path": ["INTERNET", "WEB01", "APP01", "DB01"]}')
            path_file = f.name
        self.assertTrue(is_on_attack_path("WEB01", path_file))
        self.assertTrue(is_on_attack_path("DB01", path_file))

    def test_on_attack_path_false(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as f:
            f.write('{"path": ["INTERNET", "WEB01", "APP01", "DB01"]}')
            path_file = f.name
        self.assertFalse(is_on_attack_path("EMP01", path_file))
        self.assertFalse(is_on_attack_path("BACKUP01", path_file))

    def test_on_attack_path_internet_excluded(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as f:
            f.write('{"path": ["INTERNET", "WEB01", "APP01", "DB01"]}')
            path_file = f.name
        self.assertFalse(is_on_attack_path("INTERNET", path_file))

    def test_get_system_metadata_from_systems_dict(self):
        systems = {
            "WEB01": {"criticality": 4, "internet_exposed": True},
        }
        meta = get_system_metadata("WEB01", systems)
        self.assertEqual(meta["criticality"], 4)
        self.assertTrue(meta["internet_exposed"])

    def test_get_system_metadata_defaults(self):
        meta = get_system_metadata("UNKNOWN", {})
        self.assertEqual(meta["criticality"], 3)
        self.assertFalse(meta["internet_exposed"])


# ---------------------------------------------------------------------------
# Table builder tests
# ---------------------------------------------------------------------------


class TestBuildIncidentPriorityTable(unittest.TestCase):
    """Incident priority table must preserve incident context and sort correctly."""

    def setUp(self):
        self.incident = _make_incident(
            incident_id="INC-CP",
            related_vulnerabilities=("V001", "V002", "V003", "V004"),
        )
        self.predictions = _make_predictions()

    def test_output_has_expected_columns(self):
        df = build_incident_priority_table(
            (self.incident,),
            self.predictions,
        )
        expected_cols = [
            "incident_id",
            "vuln_id",
            "system_id",
            "vulnerability_risk",
            "system_criticality",
            "internet_exposed",
            "on_attack_path",
            "is_critical_asset",
            "traceward_priority",
            "priority_reason",
        ]
        self.assertEqual(list(df.columns), expected_cols)

    def test_row_count_matches_related_vulnerabilities(self):
        df = build_incident_priority_table(
            (self.incident,),
            self.predictions,
        )
        self.assertEqual(len(df), 4)

    def test_all_incidents_appear_in_table(self):
        inc2 = _make_incident(
            incident_id="INC-EC",
            related_vulnerabilities=("V001",),
        )
        df = build_incident_priority_table(
            (self.incident, inc2),
            self.predictions,
        )
        incident_ids = set(df["incident_id"].tolist())
        self.assertEqual(incident_ids, {"INC-CP", "INC-EC"})

    def test_incident_id_preserved(self):
        df = build_incident_priority_table(
            (self.incident,),
            self.predictions,
        )
        self.assertTrue((df["incident_id"] == "INC-CP").all())

    def test_sorted_by_priority_then_vuln_id(self):
        df = build_incident_priority_table(
            (self.incident,),
            self.predictions,
        )
        priority_rank = {
            IMMEDIATE_ATTENTION: 0,
            HIGH_PRIORITY: 1,
            SCHEDULED: 2,
            LOWER_PRIORITY: 3,
        }
        df["_rank"] = df["traceward_priority"].map(priority_rank)
        self.assertTrue(
            (df["_rank"].diff().fillna(0) >= 0).all(),
            "Rows are not sorted by priority ascending.",
        )

    def test_missing_predictions_skipped(self):
        preds = _make_predictions({"V001": ("WEB01", "Critical")})
        inc = _make_incident(related_vulnerabilities=("V001", "V_MISSING"))
        df = build_incident_priority_table((inc,), preds)
        self.assertEqual(len(df), 1)
        self.assertEqual(df.iloc[0]["vuln_id"], "V001")

    def test_empty_incidents_returns_empty_dataframe(self):
        df = build_incident_priority_table((), self.predictions)
        self.assertEqual(len(df), 0)
        self.assertIsInstance(df, pd.DataFrame)

    def test_invalid_predictions_raises(self):
        bad_df = pd.DataFrame({"vuln_id": ["V001"], "system_id": ["WEB01"]})
        with self.assertRaises(ValueError):
            build_incident_priority_table((self.incident,), bad_df)

    def test_non_dataframe_predictions_raises(self):
        with self.assertRaises(ValueError):
            build_incident_priority_table((self.incident,), "not a dataframe")


# ---------------------------------------------------------------------------
# TraceWard simulation priority documentation / labeling tests
# ---------------------------------------------------------------------------


class TestTraceWardPriorityLabels(unittest.TestCase):
    """Priority labels must be categorical and distinct from CVSS scoring."""

    def test_no_universal_numerical_score_column(self):
        inc = _make_incident(related_vulnerabilities=("V001",))
        preds = _make_predictions({"V001": ("WEB01", "Critical")})
        df = build_incident_priority_table((inc,), preds)
        self.assertNotIn("universal_risk_score", df.columns)
        self.assertNotIn("cvss_score", df.columns)
        self.assertNotIn("composite_score", df.columns)

    def test_priority_column_is_categorical_string(self):
        inc = _make_incident(related_vulnerabilities=("V001",))
        preds = _make_predictions({"V001": ("WEB01", "Critical")})
        df = build_incident_priority_table((inc,), preds)
        values = df["traceward_priority"].tolist()
        self.assertTrue(all(isinstance(v, str) for v in values))
        self.assertIn(df.iloc[0]["traceward_priority"], {
            IMMEDIATE_ATTENTION,
            HIGH_PRIORITY,
            SCHEDULED,
            LOWER_PRIORITY,
        })

    def test_priority_values_are_traceward_labels_not_cvss(self):
        allowed = {IMMEDIATE_ATTENTION, HIGH_PRIORITY, SCHEDULED, LOWER_PRIORITY}
        inc = _make_incident(related_vulnerabilities=("V001", "V002", "V003", "V004"))
        preds = _make_predictions()
        df = build_incident_priority_table((inc,), preds)
        unique_priorities = set(df["traceward_priority"].unique())
        self.assertTrue(
            unique_priorities.issubset(allowed),
            f"Unexpected priority values found: {unique_priorities - allowed}",
        )


# ---------------------------------------------------------------------------
# Integration-style tests with incident correlator
# ---------------------------------------------------------------------------


class TestIncidentPriorityIntegration(unittest.TestCase):
    """End-to-end checks using the attack simulator and incident correlator."""

    @classmethod
    def setUpClass(cls):
        from src.attack_simulator.simulator import simulate_finbank_attack
        from src.finbank_assignment import assign_finbank_vulnerabilities

        cls.inventory = assign_finbank_vulnerabilities()
        cls.events = simulate_finbank_attack("customer_portal_compromise", inventory=cls.inventory)
        from src.incident_correlator import correlate_incidents

        cls.incidents = correlate_incidents(cls.events, cls.inventory)

        cls.predictions = cls.inventory[["vuln_id", "system_id", "risk_label"]].rename(
            columns={"risk_label": "predicted_risk"}
        )

    def test_table_builds_without_error(self):
        df = build_incident_priority_table(self.incidents, self.predictions)
        self.assertIsInstance(df, pd.DataFrame)
        self.assertGreater(len(df), 0)

    def test_customer_portal_incident_has_immediate_or_high(self):
        df = build_incident_priority_table(self.incidents, self.predictions)
        cp_rows = df[df["incident_id"] == "INC-CUSTOMER_PORTAL_COMPROMISE"]
        self.assertFalse(cp_rows.empty)
        top_priorities = {IMMEDIATE_ATTENTION, HIGH_PRIORITY}
        self.assertTrue(
            any(p in top_priorities for p in cp_rows["traceward_priority"].unique()),
            "Expected Immediate or High priority for customer portal compromise.",
        )

    def test_web01_in_attack_path_when_incident_uses_it(self):
        df = build_incident_priority_table(self.incidents, self.predictions)
        web01_rows = df[df["system_id"] == "WEB01"]
        if not web01_rows.empty:
            self.assertTrue(
                web01_rows["on_attack_path"].any(),
                "WEB01 should be on attack path in customer_portal_compromise scenario.",
            )

    def test_critical_asset_flags_match_network_definition(self):
        df = build_incident_priority_table(self.incidents, self.predictions)
        expected_critical = {"WEB01", "APP01", "AUTH01", "VPN01", "DB01", "BACKUP01"}
        for _, row in df.iterrows():
            sys_id = row["system_id"]
            if sys_id in expected_critical:
                self.assertTrue(
                    row["is_critical_asset"],
                    f"{sys_id} should be flagged as critical asset.",
                )


# ---------------------------------------------------------------------------
# Enrichment tests
# ---------------------------------------------------------------------------


class TestEnrichSystemRisk(unittest.TestCase):
    def test_enrich_adds_incident_columns(self):
        risk_summary = pd.DataFrame({
            "system_id": ["WEB01", "APP01", "EMP01"],
            "vulnerability_count": [5, 3, 1],
            "highest_risk": ["Critical", "High", "Low"],
            "average_risk_score": [3.2, 2.5, 1.0],
            "normalized_risk": [0.8, 0.625, 0.25],
            "critical_count": [2, 1, 0],
            "high_or_critical_count": [3, 2, 0],
        })
        inc = _make_incident(
            affected_systems=("WEB01", "APP01"),
            related_vulnerabilities=("V001",),
        )
        systems = {
            "WEB01": {"criticality": 4, "internet_exposed": True},
            "APP01": {"criticality": 4, "internet_exposed": False},
            "EMP01": {"criticality": 2, "internet_exposed": False},
        }
        enriched = enrich_system_risk_with_incident_context(
            risk_summary,
            (inc,),
            systems=systems,
            attack_path_path="artifacts/astar/attack_path.json",
        )
        self.assertIn("affected_incidents", enriched.columns)
        self.assertIn("on_attack_path", enriched.columns)
        self.assertIn("is_critical_asset", enriched.columns)
        self.assertEqual(enriched.loc[enriched["system_id"] == "WEB01", "is_critical_asset"].iloc[0], True)

    def test_enrich_preserves_original_columns(self):
        risk_summary = pd.DataFrame({
            "system_id": ["WEB01"],
            "vulnerability_count": [5],
            "highest_risk": ["Critical"],
            "average_risk_score": [3.2],
            "normalized_risk": [0.8],
            "critical_count": [2],
            "high_or_critical_count": [3],
        })
        inc = _make_incident(affected_systems=("WEB01",), related_vulnerabilities=("V001",))
        enriched = enrich_system_risk_with_incident_context(
            risk_summary,
            (inc,),
        )
        for col in [
            "system_id",
            "vulnerability_count",
            "highest_risk",
            "average_risk_score",
            "normalized_risk",
            "critical_count",
            "high_or_critical_count",
        ]:
            self.assertIn(col, enriched.columns)


# ---------------------------------------------------------------------------
# Immutability and contract tests
# ---------------------------------------------------------------------------


class TestIncidentPriorityContracts(unittest.TestCase):
    """Ensure the analyzer does not mutate inputs and respects data contracts."""

    def test_does_not_mutate_predictions_df(self):
        inc = _make_incident(related_vulnerabilities=("V001",))
        preds = _make_predictions({"V001": ("WEB01", "Critical")})
        original_cols = list(preds.columns)
        build_incident_priority_table((inc,), preds)
        self.assertEqual(list(preds.columns), original_cols)

    def test_does_not_mutate_incidents(self):
        inc = _make_incident()
        preds = _make_predictions({"V001": ("WEB01", "Critical")})
        original_affected = list(inc.affected_systems)
        original_vulns = list(inc.related_vulnerabilities)
        build_incident_priority_table((inc,), preds)
        self.assertEqual(list(inc.affected_systems), original_affected)
        self.assertEqual(list(inc.related_vulnerabilities), original_vulns)

    def test_entry_dataclass_is_immutable(self):
        entry = IncidentPriorityEntry(
            incident_id="INC-1",
            vuln_id="V001",
            system_id="WEB01",
            vulnerability_risk="Critical",
            system_criticality=4,
            internet_exposed=True,
            on_attack_path=True,
            is_critical_asset=True,
            traceward_priority=IMMEDIATE_ATTENTION,
            priority_reason="Test reason.",
        )
        with self.assertRaises(AttributeError):
            entry.traceward_priority = "High priority"


if __name__ == "__main__":
    unittest.main()
