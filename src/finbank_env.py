"""FinBank fictional organization environment configuration.

Defines the systems, criticality, exposure, and metadata for the FinBank
enterprise topology used by the attack simulation module.

This module does not modify the existing TraceWard network implementation.
It provides a parallel, simulation-specific asset registry that reuses the
same system identifiers and topology conventions.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

REQUIRED_SYSTEM_FIELDS = {
    "system_id",
    "display_name",
    "type",
    "criticality",
    "internet_exposed",
    "description",
}


def _default_finbank_systems() -> dict[str, dict[str, Any]]:
    return {
        "INTERNET": {
            "system_id": "INTERNET",
            "display_name": "Internet",
            "type": "External",
            "criticality": 1,
            "internet_exposed": True,
            "description": "Untrusted external network environment representing the public Internet ingress point.",
        },
        "WEB01": {
            "system_id": "WEB01",
            "display_name": "Customer Web Portal",
            "type": "Server",
            "criticality": 4,
            "internet_exposed": True,
            "description": "Public-facing customer web portal hosting FinBank's online banking interface.",
        },
        "APP01": {
            "system_id": "APP01",
            "display_name": "Banking Application Server",
            "type": "Server",
            "criticality": 4,
            "internet_exposed": False,
            "description": "Core banking application server processing transactions and business logic.",
        },
        "AUTH01": {
            "system_id": "AUTH01",
            "display_name": "Authentication / Identity Server",
            "type": "Server",
            "criticality": 5,
            "internet_exposed": False,
            "description": "Central authentication and identity management service for customers and employees.",
        },
        "VPN01": {
            "system_id": "VPN01",
            "display_name": "Remote Access Gateway",
            "type": "Gateway",
            "criticality": 4,
            "internet_exposed": True,
            "description": "Secure remote access gateway for authorized FinBank employee connectivity.",
        },
        "EMP01": {
            "system_id": "EMP01",
            "display_name": "Employee Workstation",
            "type": "Workstation",
            "criticality": 2,
            "internet_exposed": False,
            "description": "Standard employee endpoint used for internal FinBank operations and administration.",
        },
        "DB01": {
            "system_id": "DB01",
            "display_name": "Customer / Business Database",
            "type": "Database",
            "criticality": 5,
            "internet_exposed": False,
            "description": "Primary database housing customer accounts, transactions, and sensitive financial records.",
        },
        "BACKUP01": {
            "system_id": "BACKUP01",
            "display_name": "Backup Infrastructure",
            "type": "Server",
            "criticality": 5,
            "internet_exposed": False,
            "description": "Backup and recovery infrastructure containing historical snapshots of core financial data.",
        },
    }


def load_finbank_systems(path: str | Path = "data/finbank/finbank_systems.json") -> dict[str, dict[str, Any]]:
    """Load FinBank system definitions from a JSON file.

    If the file does not exist, falls back to the built-in FinBank defaults.
    """
    p = Path(path)
    if p.exists():
        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            return data
        raise ValueError(f"FinBank systems file must contain a JSON object, got {type(data).__name__}.")
    return _default_finbank_systems()


def validate_finbank_systems(systems: dict[str, dict[str, Any]]) -> None:
    """Validate that all required FinBank systems exist and satisfy schema rules."""
    if not systems:
        raise ValueError("FinBank systems configuration is empty.")

    system_ids = list(systems.keys())
    if len(system_ids) != len(set(system_ids)):
        raise ValueError("Duplicate system_id values found in FinBank systems configuration.")

    required_systems = {
        "INTERNET",
        "WEB01",
        "APP01",
        "AUTH01",
        "VPN01",
        "EMP01",
        "DB01",
        "BACKUP01",
    }
    missing = required_systems - set(system_ids)
    if missing:
        raise ValueError(f"Missing required FinBank systems: {sorted(missing)}")

    for system_id, entry in systems.items():
        missing_fields = REQUIRED_SYSTEM_FIELDS - set(entry.keys())
        if missing_fields:
            raise ValueError(f"System '{system_id}' is missing required fields: {sorted(missing_fields)}")

        if not isinstance(entry.get("criticality"), int):
            raise ValueError(f"System '{system_id}' criticality must be an integer.")

        if not isinstance(entry.get("internet_exposed"), bool):
            raise ValueError(f"System '{system_id}' internet_exposed must be a boolean.")


def get_finbank_system(system_id: str, systems: dict[str, dict[str, Any]] | None = None) -> dict[str, Any]:
    """Return a single FinBank system entry by system_id."""
    if systems is None:
        systems = load_finbank_systems()
    if system_id not in systems:
        raise KeyError(f"Unknown FinBank system_id: '{system_id}'")
    return systems[system_id]


def list_finbank_systems(systems: dict[str, dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    """Return all FinBank system entries as a list preserving insertion order."""
    if systems is None:
        systems = load_finbank_systems()
    return list(systems.values())


def is_internet_exposed(system_id: str, systems: dict[str, dict[str, Any]] | None = None) -> bool:
    """Return whether the specified FinBank system is internet exposed."""
    return bool(get_finbank_system(system_id, systems).get("internet_exposed", False))
