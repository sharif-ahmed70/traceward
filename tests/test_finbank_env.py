"""Unit tests for the FinBank environment configuration module."""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from src.finbank_env import (
    REQUIRED_SYSTEM_FIELDS,
    _default_finbank_systems,
    get_finbank_system,
    is_internet_exposed,
    list_finbank_systems,
    load_finbank_systems,
    validate_finbank_systems,
)


class TestFinBankSystemsExist(unittest.TestCase):
    """All required FinBank systems must be present."""

    @classmethod
    def setUpClass(cls):
        cls.systems = load_finbank_systems()
        validate_finbank_systems(cls.systems)

    def test_required_systems_exist(self):
        required = {
            "INTERNET",
            "WEB01",
            "APP01",
            "AUTH01",
            "VPN01",
            "EMP01",
            "DB01",
            "BACKUP01",
        }
        self.assertSetEqual(required, set(self.systems.keys()))


class TestFinBankSystemIdsAreUnique(unittest.TestCase):
    """System IDs must be unique within the FinBank configuration."""

    def test_unique_system_ids(self):
        systems = load_finbank_systems()
        ids = list(systems.keys())
        self.assertEqual(len(ids), len(set(ids)))


class TestFinBankCriticalityExists(unittest.TestCase):
    """Every FinBank system must define an integer criticality."""

    @classmethod
    def setUpClass(cls):
        cls.systems = load_finbank_systems()

    def test_all_systems_have_criticality(self):
        for system_id, entry in self.systems.items():
            self.assertIn("criticality", entry, f"Missing criticality for {system_id}")
            self.assertIsInstance(entry["criticality"], int, f"criticality for {system_id} must be an integer")


class TestFinBankInternetExposureExists(unittest.TestCase):
    """Every FinBank system must define a boolean internet_exposure flag."""

    @classmethod
    def setUpClass(cls):
        cls.systems = load_finbank_systems()

    def test_all_systems_have_internet_exposed(self):
        for system_id, entry in self.systems.items():
            self.assertIn("internet_exposed", entry, f"Missing internet_exposed for {system_id}")
            self.assertIsInstance(entry["internet_exposed"], bool, f"internet_exposed for {system_id} must be a boolean")

    def test_known_exposure_values(self):
        expected_exposed = {"INTERNET", "WEB01", "VPN01"}
        expected_internal = {"APP01", "AUTH01", "EMP01", "DB01", "BACKUP01"}
        for system_id in expected_exposed:
            self.assertTrue(
                is_internet_exposed(system_id, self.systems),
                f"{system_id} should be internet exposed",
            )
        for system_id in expected_internal:
            self.assertFalse(
                is_internet_exposed(system_id, self.systems),
                f"{system_id} should not be internet exposed",
            )


class TestFinBankValidation(unittest.TestCase):
    """Validation behavior for edge cases."""

    def test_validate_empty_raises(self):
        with self.assertRaises(ValueError):
            validate_finbank_systems({})

    def test_validate_missing_required_system_raises(self):
        systems = {
            "WEB01": _default_finbank_systems()["WEB01"],
            "APP01": _default_finbank_systems()["APP01"],
        }
        with self.assertRaises(ValueError):
            validate_finbank_systems(systems)

    def test_validate_missing_field_raises(self):
        systems = {
            system_id: {k: v for k, v in entry.items() if k != "description"}
            for system_id, entry in _default_finbank_systems().items()
        }
        with self.assertRaises(ValueError):
            validate_finbank_systems(systems)

    def test_load_from_json_file(self):
        data = _default_finbank_systems()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
            json.dump(data, f)
            tmp_path = f.name
        try:
            loaded = load_finbank_systems(tmp_path)
            self.assertSetEqual(set(data.keys()), set(loaded.keys()))
        finally:
            Path(tmp_path).unlink()

    def test_get_finbank_system_known(self):
        systems = load_finbank_systems()
        entry = get_finbank_system("DB01", systems)
        self.assertEqual(entry["display_name"], "Customer / Business Database")

    def test_get_finbank_system_unknown_raises(self):
        with self.assertRaises(KeyError):
            get_finbank_system("UNKNOWN_SYSTEM")

    def test_list_finbank_systems_returns_all(self):
        systems = load_finbank_systems()
        all_systems = list_finbank_systems(systems)
        self.assertEqual(len(all_systems), len(systems))


if __name__ == "__main__":
    unittest.main()
