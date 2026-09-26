"""Incident correlator for TraceWard FinBank attack simulation.

Correlates simulated attack events with the FinBank vulnerability inventory
and environment to produce structured incident objects.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

import pandas as pd

from src.finbank_env import load_finbank_systems


REQUIRED_EVENT_COLUMNS = {
    "event_id",
    "scenario_id",
    "timestamp",
    "source",
    "target",
    "event_type",
    "vulnerability_id",
    "severity",
    "description",
}

REQUIRED_INVENTORY_COLUMNS = {
    "vuln_id",
    "system_id",
    "risk_label",
}


@dataclass(frozen=True)
class Incident:
    """Structured incident object produced by the correlator."""

    incident_id: str
    scenario_id: str
    entry_point: str
    affected_systems: tuple[str, ...]
    related_vulnerabilities: tuple[str, ...]
    event_count: int
    critical_assets_affected: tuple[str, ...]
    attack_sequence: tuple[dict[str, Any], ...]


def _validate_events(events: pd.DataFrame) -> None:
    missing = REQUIRED_EVENT_COLUMNS - set(events.columns)
    if missing:
        raise ValueError(f"Simulated events missing required columns: {sorted(missing)}")


def _validate_inventory(inventory: pd.DataFrame) -> None:
    missing = REQUIRED_INVENTORY_COLUMNS - set(inventory.columns)
    if missing:
        raise ValueError(f"Vulnerability inventory missing required columns: {sorted(missing)}")


def _deduplicate_events(events: pd.DataFrame) -> pd.DataFrame:
    return events.drop_duplicates(subset=["scenario_id", "timestamp", "source", "target", "event_type", "vulnerability_id"]).reset_index(drop=True)


def _identify_critical_assets(affected_systems: tuple[str, ...], systems: dict[str, dict[str, Any]]) -> tuple[str, ...]:
    critical_assets = []
    for system_id in affected_systems:
        system_info = systems.get(system_id, {})
        criticality = int(system_info.get("criticality", 1))
        internet_exposed = bool(system_info.get("internet_exposed", False))
        if criticality >= 4 or internet_exposed:
            critical_assets.append(system_id)
    return tuple(critical_assets)


def correlate_incidents(
    events: pd.DataFrame,
    inventory: pd.DataFrame,
    systems: Optional[dict[str, dict[str, Any]]] = None,
) -> tuple[Incident, ...]:
    """Correlate simulated attack events into structured incident objects.

    Args:
        events: DataFrame of simulated attack events.
        inventory: DataFrame of FinBank vulnerability inventory.
        systems: Optional FinBank systems dictionary. Loaded from default if None.

    Returns:
        Tuple of Incident objects, one per scenario_id.
    """
    _validate_events(events)
    _validate_inventory(inventory)

    events = _deduplicate_events(events)

    if systems is None:
        systems = load_finbank_systems()

    valid_vuln_ids = set(inventory["vuln_id"].tolist())
    inventory_by_system = inventory.groupby("system_id")["vuln_id"].apply(lambda x: tuple(sorted(x))).to_dict()

    incidents = []
    for scenario_id, group in events.groupby("scenario_id", sort=False):
        group = group.sort_values(by="timestamp").reset_index(drop=True)

        entry_point = str(group.iloc[0]["source"])
        affected_systems = tuple(dict.fromkeys(group["target"].tolist()))

        related_vulnerabilities = set()
        for target in affected_systems:
            related_vulnerabilities.update(inventory_by_system.get(target, ()))
        related_vulnerabilities = tuple(sorted(related_vulnerabilities))

        critical_assets_affected = _identify_critical_assets(affected_systems, systems)

        attack_sequence = []
        for _, row in group.iterrows():
            attack_sequence.append({
                "event_id": str(row["event_id"]),
                "timestamp": int(row["timestamp"]),
                "source": str(row["source"]),
                "target": str(row["target"]),
                "event_type": str(row["event_type"]),
                "vulnerability_id": str(row["vulnerability_id"]) if pd.notna(row["vulnerability_id"]) else None,
                "severity": str(row["severity"]),
            })

        incident = Incident(
            incident_id=f"INC-{scenario_id.upper()}",
            scenario_id=str(scenario_id),
            entry_point=entry_point,
            affected_systems=affected_systems,
            related_vulnerabilities=related_vulnerabilities,
            event_count=len(group),
            critical_assets_affected=critical_assets_affected,
            attack_sequence=tuple(attack_sequence),
        )
        incidents.append(incident)

    return tuple(incidents)


def correlate_single_scenario(
    scenario_id: str,
    events: pd.DataFrame,
    inventory: pd.DataFrame,
    systems: Optional[dict[str, dict[str, Any]]] = None,
) -> Incident:
    """Correlate events for a single scenario_id."""
    incidents = correlate_incidents(events, inventory, systems)
    for incident in incidents:
        if incident.scenario_id == scenario_id:
            return incident
    raise KeyError(f"No incident found for scenario_id: '{scenario_id}'")


def incident_to_dict(incident: Incident) -> dict[str, Any]:
    """Serialize an incident to a dictionary."""
    return {
        "incident_id": incident.incident_id,
        "scenario_id": incident.scenario_id,
        "entry_point": incident.entry_point,
        "affected_systems": list(incident.affected_systems),
        "related_vulnerabilities": list(incident.related_vulnerabilities),
        "event_count": incident.event_count,
        "critical_assets_affected": list(incident.critical_assets_affected),
        "attack_sequence": list(incident.attack_sequence),
    }


if __name__ == "__main__":
    events_path = "artifacts/finbank/simulated_events.csv"
    inventory_path = "artifacts/finbank/finbank_vulnerability_inventory.csv"

    events_df = pd.read_csv(events_path, keep_default_na=False)
    inventory_df = pd.read_csv(inventory_path, keep_default_na=False)

    incidents = correlate_incidents(events_df, inventory_df)
    for incident in incidents:
        print(f"Incident: {incident.incident_id}")
        print(f"  Scenario: {incident.scenario_id}")
        print(f"  Affected systems: {incident.affected_systems}")
        print(f"  Related vulnerabilities: {len(incident.related_vulnerabilities)}")
        print(f"  Critical assets affected: {incident.critical_assets_affected}")
        print()
