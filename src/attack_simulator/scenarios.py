"""Deterministic fictional FinBank attack scenario definitions.

Each scenario describes a simulated, fictional attack path through the
FinBank environment. No real exploitation, scanning, or execution logic
is included; scenarios are storyboard definitions only.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

from src.attack_simulator.events import (
    AttackEvent,
    EventType,
    create_event,
    event_to_dict,
)


@dataclass(frozen=True)
class AttackScenario:
    """Immutable fictional attack scenario definition."""

    scenario_id: str
    name: str
    description: str
    entry_point: str
    target_systems: tuple[str, ...]
    events: tuple[AttackEvent, ...]


def _make_event(
    event_id: str,
    timestamp: int,
    source: str,
    target: str,
    event_type: EventType,
    vulnerability_id: Optional[str] = None,
    severity: str = "Medium",
    description: str = "",
) -> AttackEvent:
    return create_event(
        event_id=event_id,
        scenario_id="PLACEHOLDER",
        timestamp=timestamp,
        source=source,
        target=target,
        event_type=event_type,
        vulnerability_id=vulnerability_id,
        severity=severity,
        description=description,
    )


def _build_customer_portal_compromise() -> tuple[str, tuple[str, ...], tuple[AttackEvent, ...]]:
    scenario_id = "customer_portal_compromise"
    entry_point = "INTERNET"
    target_systems = ("WEB01", "APP01", "DB01")
    events = (
        _make_event(
            "EVT-CUST-01",
            1,
            "INTERNET",
            "WEB01",
            EventType.INITIAL_ACCESS,
            severity="High",
            description="Simulated external ingress toward the customer web portal.",
        ),
        _make_event(
            "EVT-CUST-02",
            2,
            "WEB01",
            "APP01",
            EventType.LATERAL_MOVEMENT,
            severity="High",
            description="Simulated lateral movement from web tier to application tier.",
        ),
        _make_event(
            "EVT-CUST-03",
            3,
            "APP01",
            "DB01",
            EventType.DATA_ACCESS,
            severity="Critical",
            description="Simulated unauthorized access to customer and business data.",
        ),
    )
    return scenario_id, target_systems, events


def _build_employee_compromise() -> tuple[str, tuple[str, ...], tuple[AttackEvent, ...]]:
    scenario_id = "employee_compromise"
    entry_point = "INTERNET"
    target_systems = ("EMP01", "AUTH01", "APP01", "DB01")
    events = (
        _make_event(
            "EVT-EMP-01",
            1,
            "INTERNET",
            "EMP01",
            EventType.INITIAL_ACCESS,
            severity="Medium",
            description="Simulated phishing-derived access on an employee endpoint.",
        ),
        _make_event(
            "EVT-EMP-02",
            2,
            "EMP01",
            "AUTH01",
            EventType.CREDENTIAL_ACCESS,
            severity="High",
            description="Simulated credential harvesting from an employee workstation.",
        ),
        _make_event(
            "EVT-EMP-03",
            3,
            "AUTH01",
            "APP01",
            EventType.LATERAL_MOVEMENT,
            severity="High",
            description="Simulated lateral movement from identity to application tier.",
        ),
        _make_event(
            "EVT-EMP-04",
            4,
            "APP01",
            "DB01",
            EventType.DATA_ACCESS,
            severity="Critical",
            description="Simulated unauthorized access to customer and business data.",
        ),
    )
    return scenario_id, target_systems, events


def _build_remote_access_compromise() -> tuple[str, tuple[str, ...], tuple[AttackEvent, ...]]:
    scenario_id = "remote_access_compromise"
    entry_point = "INTERNET"
    target_systems = ("VPN01", "AUTH01", "APP01", "DB01")
    events = (
        _make_event(
            "EVT-VPN-01",
            1,
            "INTERNET",
            "VPN01",
            EventType.INITIAL_ACCESS,
            severity="High",
            description="Simulated abuse of remote access gateway ingress.",
        ),
        _make_event(
            "EVT-VPN-02",
            2,
            "VPN01",
            "AUTH01",
            EventType.CREDENTIAL_ACCESS,
            severity="High",
            description="Simulated credential access against the identity provider.",
        ),
        _make_event(
            "EVT-VPN-03",
            3,
            "AUTH01",
            "APP01",
            EventType.PRIVILEGE_ESCALATION,
            severity="High",
            description="Simulated privilege escalation from identity to application tier.",
        ),
        _make_event(
            "EVT-VPN-04",
            4,
            "APP01",
            "DB01",
            EventType.DATA_ACCESS,
            severity="Critical",
            description="Simulated unauthorized access to customer and business data.",
        ),
    )
    return scenario_id, target_systems, events


def _build_backup_targeting() -> tuple[str, tuple[str, ...], tuple[AttackEvent, ...]]:
    scenario_id = "backup_targeting"
    entry_point = "INTERNET"
    target_systems = ("WEB01", "APP01", "DB01", "BACKUP01")
    events = (
        _make_event(
            "EVT-BACKUP-01",
            1,
            "INTERNET",
            "WEB01",
            EventType.INITIAL_ACCESS,
            severity="High",
            description="Simulated external ingress via the customer portal.",
        ),
        _make_event(
            "EVT-BACKUP-02",
            2,
            "WEB01",
            "APP01",
            EventType.LATERAL_MOVEMENT,
            severity="High",
            description="Simulated lateral movement from web tier to application tier.",
        ),
        _make_event(
            "EVT-BACKUP-03",
            3,
            "APP01",
            "DB01",
            EventType.DATA_ACCESS,
            severity="Critical",
            description="Simulated unauthorized access to primary customer and business data.",
        ),
        _make_event(
            "EVT-BACKUP-04",
            4,
            "DB01",
            "BACKUP01",
            EventType.BACKUP_TARGETING,
            severity="Critical",
            description="Simulated targeting of backup infrastructure for data exfiltration or destruction.",
        ),
    )
    return scenario_id, target_systems, events


def build_finbank_scenarios() -> tuple[AttackScenario, ...]:
    """Return all deterministic FinBank attack scenarios."""
    scenarios = []

    for builder in (
        _build_customer_portal_compromise,
        _build_employee_compromise,
        _build_remote_access_compromise,
        _build_backup_targeting,
    ):
        scenario_id, target_systems, events = builder()
        first_event = events[0]
        scenarios.append(
            AttackScenario(
                scenario_id=scenario_id,
                name=scenario_id.replace("_", " ").title(),
                description=f"Fictional simulated scenario: {scenario_id.replace('_', ' ')}.",
                entry_point=first_event.source,
                target_systems=target_systems,
                events=events,
            )
        )

    return tuple(scenarios)


def get_finbank_scenario(scenario_id: str) -> AttackScenario:
    """Return a single scenario by id."""
    for scenario in build_finbank_scenarios():
        if scenario.scenario_id == scenario_id:
            return scenario
    raise KeyError(f"Unknown FinBank attack scenario: '{scenario_id}'")


def scenario_to_dict(scenario: AttackScenario) -> dict[str, object]:
    """Serialize a scenario to a dictionary."""
    return {
        "scenario_id": scenario.scenario_id,
        "name": scenario.name,
        "description": scenario.description,
        "entry_point": scenario.entry_point,
        "target_systems": list(scenario.target_systems),
        "events": [event_to_dict(event) for event in scenario.events],
    }


if __name__ == "__main__":
    for scenario in build_finbank_scenarios():
        print(f"Scenario: {scenario.scenario_id}")
        print(f"  Path: {' -> '.join(scenario.target_systems)}")
        print(f"  Events: {len(scenario.events)}")
        print()
