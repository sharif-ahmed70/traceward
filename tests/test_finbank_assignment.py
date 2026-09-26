"""Unit tests for the FinBank vulnerability assignment layer."""

from __future__ import annotations

import hashlib
from pathlib import Path
import tempfile
import unittest

import pandas as pd

from src.finbank_assignment import (
    FIXED_SEED,
    OUTPUT_INVENTORY_PATH,
    RAW_VULNERABILITIES_PATH,
    SYSTEM_WEIGHTS,
    _build_weighted_assignment,
    assign_finbank_vulnerabilities,
    get_finbank_assignment_summary,
)
from src.finbank_env import _default_finbank_systems


class TestFinBankDeterministicAssignment(unittest.TestCase):
    """Repeated runs with the same seed must produce identical assignments."""

    def test_deterministic_assignment(self):
        df1 = assign_finbank_vulnerabilities(seed=FIXED_SEED)
        df2 = assign_finbank_vulnerabilities(seed=FIXED_SEED)
        pd.testing.assert_frame_equal(df1, df2)

    def test_different_seed_produces_different_assignment(self):
        df1 = assign_finbank_vulnerabilities(seed=FIXED_SEED)
        df2 = assign_finbank_vulnerabilities(seed=FIXED_SEED + 1)
        self.assertFalse(df1["system_id"].equals(df2["system_id"]))


class TestFinBankAll1200VulnerabilitiesPreserved(unittest.TestCase):
    """All 1200 original vulnerability records must be present."""

    def test_row_count_preserved(self):
        df = assign_finbank_vulnerabilities()
        self.assertEqual(len(df), 1200)

    def test_vuln_ids_unchanged(self):
        original = pd.read_csv(RAW_VULNERABILITIES_PATH, keep_default_na=False)
        assigned = assign_finbank_vulnerabilities()
        self.assertListEqual(original["vuln_id"].tolist(), assigned["vuln_id"].tolist())

    def test_output_file_has_1200_rows(self):
        assign_finbank_vulnerabilities()
        df = pd.read_csv(OUTPUT_INVENTORY_PATH, keep_default_na=False)
        self.assertEqual(len(df), 1200)


class TestFinBankNoDuplicateVulnIds(unittest.TestCase):
    """Assigned inventory must contain unique vuln_id values."""

    def test_no_duplicate_vuln_ids(self):
        df = assign_finbank_vulnerabilities()
        self.assertTrue(df["vuln_id"].is_unique)


class TestFinBankEveryVulnerabilityHasValidSystemId(unittest.TestCase):
    """Every assigned vulnerability must reference a valid FinBank system."""

    @classmethod
    def setUpClass(cls):
        cls.valid_systems = set(_default_finbank_systems().keys())
        cls.df = assign_finbank_vulnerabilities()

    def test_all_system_ids_are_valid_finbank_systems(self):
        assigned_systems = set(self.df["system_id"].tolist())
        invalid = assigned_systems - self.valid_systems
        self.assertFalse(invalid, f"Invalid system_ids found: {invalid}")

    def test_no_empty_system_ids(self):
        self.assertFalse((self.df["system_id"].astype(str).str.strip() == "").any())


class TestFinBankEverySystemReceivesAtLeastOneVulnerability(unittest.TestCase):
    """Every FinBank system must appear in the assigned inventory."""

    @classmethod
    def setUpClass(cls):
        cls.df = assign_finbank_vulnerabilities()
        cls.valid_systems = set(_default_finbank_systems().keys())

    def test_every_finbank_system_receives_vulnerabilities(self):
        assigned_systems = set(self.df["system_id"].tolist())
        missing = self.valid_systems - assigned_systems
        self.assertFalse(missing, f"FinBank systems with no vulnerabilities: {missing}")


class TestFinBankAssignmentSummary(unittest.TestCase):
    """Summary helper must report counts per system."""

    def test_summary_contains_all_systems(self):
        df = assign_finbank_vulnerabilities()
        summary = get_finbank_assignment_summary(df)
        self.assertSetEqual(set(summary["system_id"].tolist()), set(_default_finbank_systems().keys()))

    def test_summary_counts_sum_to_total(self):
        df = assign_finbank_vulnerabilities()
        summary = get_finbank_assignment_summary(df)
        self.assertEqual(summary["vulnerability_count"].sum(), 1200)


class TestFinBankAssignmentEdgeCases(unittest.TestCase):
    """Edge cases for assignment robustness."""

    def test_weighted_assignment_length(self):
        assignments = _build_weighted_assignment(total_records=1200, seed=FIXED_SEED)
        self.assertEqual(len(assignments), 1200)

    def test_assignment_uses_only_valid_systems(self):
        assignments = _build_weighted_assignment(total_records=1200, seed=FIXED_SEED)
        valid_systems = {sys_id for sys_id, _ in SYSTEM_WEIGHTS}
        invalid = set(assignments) - valid_systems
        self.assertFalse(invalid, f"Invalid system_ids in assignment: {invalid}")

    def test_assignment_is_deterministic_for_same_seed(self):
        a1 = _build_weighted_assignment(total_records=1200, seed=99)
        a2 = _build_weighted_assignment(total_records=1200, seed=99)
        self.assertListEqual(a1, a2)

    def test_assignment_changes_with_seed(self):
        a1 = _build_weighted_assignment(total_records=1200, seed=1)
        a2 = _build_weighted_assignment(total_records=1200, seed=2)
        self.assertNotEqual(a1, a2)


if __name__ == "__main__":
    unittest.main()
