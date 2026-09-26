"""Incident-aware analysis layer for TraceWard.

Extends the existing risk engine with active simulated incident context.
For each vulnerability in an active incident, computes:

  - vulnerability risk
  - affected system
  - system criticality
  - internet exposure
  - whether the vulnerability is on the simulated attack path
  - whether the system is a critical asset

Produces a categorical incident priority table using TraceWard simulation
priority labels:

  - Immediate attention
  - High priority
  - Scheduled
  - Lower priority

These are TraceWard simulation priorities, NOT CVSS scores, NOT universal
numerical risk scores, and NOT intended as substitutes for formal vulnerability
scoring frameworks.
"""

from __future__ import annotations

import functools
from dataclasses import dataclass
from typing import Any

import pandas as pd

from src.incident_correlator import Incident
from src.risk_engine import summarize_system_risk


IMMEDIATE_ATTENTION = "Immediate attention"
HIGH_PRIORITY = "High priority"
SCHEDULED = "Scheduled"
LOWER_PRIORITY = "Lower priority"


@dataclass(frozen=True)
class IncidentPriorityEntry:
    """Single (incident, vulnerability) priority assessment."""

    incident_id: str
    vuln_id: str
    system_id: str
    vulnerability_risk: str
    system_criticality: int
    internet_exposed: bool
    on_attack_path: bool
    is_critical_asset: bool
    traceward_priority: str
    priority_reason: str


# ---------------------------------------------------------------------------
# Cached lookups
# ---------------------------------------------------------------------------


@functools.lru_cache(maxsize=1)
def _load_network_nodes(network_path: str = "data/network/network.json") -> dict[str, dict[str, Any]]:
    """Load and index network nodes from network.json."""
    from pathlib import Path
    import json

    p = Path(network_path)
    if not p.exists():
        return {}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        nodes = data.get("nodes", [])
        return {node["id"]: node for node in nodes if "id" in node}
    except Exception:
        return {}


@functools.lru_cache(maxsize=1)
def _load_attack_path_nodes(attack_path_path: str = "artifacts/astar/attack_path.json") -> list[str]:
    """Load ordered node identifiers from the active A* attack path artifact."""
    from pathlib import Path
    import json

    p = Path(attack_path_path)
    if not p.exists():
        return []
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return list(data.get("path", []))
    except Exception:
        return []


# ---------------------------------------------------------------------------
# System metadata helpers
# ---------------------------------------------------------------------------


def get_system_metadata(
    system_id: str,
    systems: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Return metadata for a system, falling back to conservative defaults."""
    if systems and system_id in systems:
        entry = systems[system_id]
        return {
            "system_id": system_id,
            "criticality": int(entry.get("criticality", 3)),
            "internet_exposed": bool(entry.get("internet_exposed", False)),
        }

    nodes = _load_network_nodes()
    if system_id in nodes:
        node = nodes[system_id]
        return {
            "system_id": system_id,
            "criticality": int(node.get("criticality", 3)),
            "internet_exposed": bool(node.get("internet_exposed", False)),
        }

    return {
        "system_id": system_id,
        "criticality": 3,
        "internet_exposed": False,
    }


def is_critical_asset(system_id: str, systems: dict[str, dict[str, Any]] | None = None) -> bool:
    """Return whether the system qualifies as a critical asset.

    Critical asset definition: criticality >= 4 OR internet_exposed == True.
    """
    meta = get_system_metadata(system_id, systems)
    return bool(meta.get("criticality", 3) >= 4 or meta.get("internet_exposed", False))


def is_on_attack_path(system_id: str, attack_path_path: str = "artifacts/astar/attack_path.json") -> bool:
    """Return whether the system lies on the active A* attack path (excluding INTERNET)."""
    if system_id == "INTERNET":
        return False
    path_nodes = _load_attack_path_nodes(attack_path_path)
    return system_id in path_nodes


# ---------------------------------------------------------------------------
# Priority logic
# ---------------------------------------------------------------------------


def _determine_priority(
    vulnerability_risk: str,
    on_attack_path: bool,
    is_critical_asset: bool,
    internet_exposed: bool,
) -> tuple[str, str]:
    """Determine the TraceWard simulation priority and a short reasoning string.

    Priority tiers:
      - Immediate attention: Critical vuln on critical asset actively traversed
        by the simulated attacker. Internet-exposed variants are the highest
        urgency because they represent the attacker's current or imminent
        perimeter objective.
      - High priority: Critical vuln on critical asset, or High/Critical vuln
        on a critical asset in the attack corridor.
      - Scheduled: Elevated risk on critical asset or any risk on a system in
        the active attack path that does not already warrant a higher tier.
      - Lower priority: Low risk on non-critical assets outside the active
        attack path. Routine maintenance is sufficient.
    """
    risk = str(vulnerability_risk)

    if risk == "Critical":
        if is_critical_asset and on_attack_path:
            if internet_exposed:
                return (
                    IMMEDIATE_ATTENTION,
                    "Critical vulnerability on internet-exposed crown jewel actively traversed "
                    "by simulated attacker. This represents the attacker's current or imminent objective.",
                )
            return (
                IMMEDIATE_ATTENTION,
                "Critical vulnerability on crown jewel within the active attack corridor. "
                "Compromise would yield maximum enterprise impact.",
            )

    if risk in ("High", "Critical"):
        if on_attack_path and is_critical_asset:
            return (
                HIGH_PRIORITY,
                "High/Critical vulnerability on critical asset in the active attack corridor. "
                "Attacker traversal toward high-value target detected.",
            )
        if risk == "Critical" and is_critical_asset:
            return (
                HIGH_PRIORITY,
                "Critical vulnerability on crown jewel asset outside the current attack path. "
                "Defense-in-depth remediation prevents future corridor formation.",
            )

    if risk in ("Medium", "High", "Critical"):
        if on_attack_path:
            return (
                SCHEDULED,
                "Vulnerability on system within active attack path. "
                "Remediation reduces attacker lateral movement options.",
            )
        if is_critical_asset:
            return (
                SCHEDULED,
                "Elevated risk vulnerability on critical asset. "
                "Schedule in next operational maintenance window.",
            )
        return (
            SCHEDULED,
            "Medium/High vulnerability; include in standard patch cycle.",
        )

    return (
        LOWER_PRIORITY,
        "Low risk vulnerability on non-critical asset outside active attack path. "
        "Routine maintenance window sufficient.",
    )


# ---------------------------------------------------------------------------
# Table builder
# ---------------------------------------------------------------------------


def build_incident_priority_table(
    incidents: tuple[Incident, ...],
    predictions_df: pd.DataFrame,
    systems: dict[str, dict[str, Any]] | None = None,
    attack_path_path: str = "artifacts/astar/attack_path.json",
    network_path: str = "data/network/network.json",
) -> pd.DataFrame:
    """Build an incident-aware priority table.

    For each vulnerability associated with each incident, computes the
    TraceWard simulation priority and supporting categorical context.

    Args:
        incidents: Tuple of Incident objects from the incident correlator.
        predictions_df: DataFrame of vulnerability predictions with at least
            the columns ``vuln_id``, ``system_id``, and ``predicted_risk``.
        systems: Optional mapping of system_id to system metadata. If None,
            loaded from the FinBank environment defaults.
        attack_path_path: Path to the A* attack path JSON artifact.
        network_path: Path to the network topology JSON.

    Returns:
        DataFrame with one row per (incident, vulnerability) pair, sorted by
        a stable priority order: Immediate attention first, then High priority,
        Scheduled, and Lower priority.
    """
    if not isinstance(predictions_df, pd.DataFrame):
        raise ValueError("predictions_df must be a pandas DataFrame.")

    required_pred_cols = {"vuln_id", "system_id", "predicted_risk"}
    missing = required_pred_cols - set(predictions_df.columns)
    if missing:
        raise ValueError(f"predictions_df is missing required columns: {sorted(missing)}")

    if systems is None:
        from src.finbank_env import load_finbank_systems

        systems = load_finbank_systems()

    predictions_index = predictions_df.set_index("vuln_id").to_dict("index")

    records: list[dict[str, Any]] = []
    for incident in incidents:
        for vuln_id in incident.related_vulnerabilities:
            pred = predictions_index.get(vuln_id)
            if pred is None:
                continue

            system_id = str(pred.get("system_id", "UNKNOWN"))
            vulnerability_risk = str(pred.get("predicted_risk", "Medium"))

            meta = get_system_metadata(system_id, systems)
            system_criticality = int(meta.get("criticality", 3))
            internet_exposed = bool(meta.get("internet_exposed", False))
            on_path = is_on_attack_path(system_id, attack_path_path)
            critical_asset = is_critical_asset(system_id, systems)

            priority, reason = _determine_priority(
                vulnerability_risk=vulnerability_risk,
                on_attack_path=on_path,
                is_critical_asset=critical_asset,
                internet_exposed=internet_exposed,
            )

            records.append(
                {
                    "incident_id": incident.incident_id,
                    "vuln_id": vuln_id,
                    "system_id": system_id,
                    "vulnerability_risk": vulnerability_risk,
                    "system_criticality": system_criticality,
                    "internet_exposed": internet_exposed,
                    "on_attack_path": on_path,
                    "is_critical_asset": critical_asset,
                    "traceward_priority": priority,
                    "priority_reason": reason,
                }
            )

    df = pd.DataFrame(records)

    priority_order = {
        IMMEDIATE_ATTENTION: 0,
        HIGH_PRIORITY: 1,
        SCHEDULED: 2,
        LOWER_PRIORITY: 3,
    }
    if not df.empty:
        df["_priority_sort"] = df["traceward_priority"].map(priority_order)
        df = df.sort_values(
            by=["incident_id", "_priority_sort", "vuln_id"],
            ascending=[True, True, True],
        ).reset_index(drop=True)
        df = df.drop(columns=["_priority_sort"])

    return df


# ---------------------------------------------------------------------------
# Convenience: enrich existing system risk summary with incident context
# ---------------------------------------------------------------------------


def enrich_system_risk_with_incident_context(
    risk_summary_df: pd.DataFrame,
    incidents: tuple[Incident, ...],
    systems: dict[str, dict[str, Any]] | None = None,
    attack_path_path: str = "artifacts/astar/attack_path.json",
) -> pd.DataFrame:
    """Augment an existing system risk summary with incident-specific context.

    This function does not modify the original risk_engine outputs. It produces
    an enriched view that joins system risk metrics with incident-aware flags.

    Args:
        risk_summary_df: Output from ``summarize_system_risk``.
        incidents: Tuple of Incident objects.
        systems: Optional system metadata mapping.
        attack_path_path: Path to attack path artifact.

    Returns:
        Enriched DataFrame with incident context columns.
    """
    if systems is None:
        from src.finbank_env import load_finbank_systems

        systems = load_finbank_systems()

    affected_by_incident: dict[str, list[str]] = {}
    for incident in incidents:
        for sys_id in incident.affected_systems:
            affected_by_incident.setdefault(sys_id, []).append(incident.incident_id)

    path_nodes = set(_load_attack_path_nodes(attack_path_path))
    if "INTERNET" in path_nodes:
        path_nodes.discard("INTERNET")

    enriched = risk_summary_df.copy()
    enriched["affected_incidents"] = enriched["system_id"].apply(
        lambda sid: ", ".join(sorted(affected_by_incident.get(sid, [])))
    )
    enriched["on_attack_path"] = enriched["system_id"].apply(lambda sid: sid in path_nodes)
    enriched["is_critical_asset"] = enriched["system_id"].apply(
        lambda sid: is_critical_asset(sid, systems)
    )

    return enriched


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    """Demonstrate the incident priority analyzer on the FinBank pipeline."""
    from src.attack_simulator.simulator import simulate_all_finbank_scenarios
    from src.incident_correlator import correlate_incidents
    from src.finbank_assignment import assign_finbank_vulnerabilities

    inventory = assign_finbank_vulnerabilities()
    events = simulate_all_finbank_scenarios(inventory)
    incidents = correlate_incidents(events, inventory)

    predictions = pd.DataFrame(
        {
            "vuln_id": inventory["vuln_id"].tolist(),
            "system_id": inventory["system_id"].tolist(),
            "predicted_risk": ["Critical", "High", "Medium", "Low"] * (len(inventory) // 4 + 1),
        }
    )
    predictions = predictions.iloc[: len(inventory)].copy()
    predictions["predicted_risk"] = inventory["risk_label"].tolist()

    table = build_incident_priority_table(incidents, predictions)
    print(table.to_string(index=False))


if __name__ == "__main__":
    main()
