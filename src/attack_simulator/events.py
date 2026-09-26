"""Simulated attack-event model for TraceWard.

Defines a fictional, non-exploitative event representation used by the
attack simulator. Events are synthetic security scenarios only and do not
contain real exploitation logic, payloads, or network-scanning behavior.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class EventType(str, Enum):
    """Allowed fictional attack-event types."""

    INITIAL_ACCESS = "initial_access"
    VULNERABILITY_EXPLOITATION = "vulnerability_exploitation"
    LATERAL_MOVEMENT = "lateral_movement"
    CREDENTIAL_ACCESS = "credential_access"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DATA_ACCESS = "data_access"
    BACKUP_TARGETING = "backup_targeting"


SUPPORTED_EVENT_TYPES = [e.value for e in EventType]

SEVERITY_LEVELS = {"Low", "Medium", "High", "Critical"}


@dataclass(frozen=True)
class AttackEvent:
    """Immutable simulated attack event."""

    event_id: str
    scenario_id: str
    timestamp: int
    source: str
    target: str
    event_type: str
    vulnerability_id: Optional[str] = None
    severity: str = "Medium"
    description: str = ""


def _validate_event_type(event_type: str) -> None:
    if event_type not in SUPPORTED_EVENT_TYPES:
        raise ValueError(
            f"Unsupported event_type '{event_type}'. "
            f"Allowed values: {SUPPORTED_EVENT_TYPES}"
        )


def _validate_severity(severity: str) -> None:
    if severity not in SEVERITY_LEVELS:
        raise ValueError(
            f"Invalid severity '{severity}'. "
            f"Allowed values: {sorted(SEVERITY_LEVELS)}"
        )


def create_event(
    event_id: str,
    scenario_id: str,
    timestamp: int,
    source: str,
    target: str,
    event_type: str,
    vulnerability_id: Optional[str] = None,
    severity: str = "Medium",
    description: str = "",
) -> AttackEvent:
    """Create and validate a simulated attack event."""
    _validate_event_type(event_type)
    _validate_severity(severity)
    return AttackEvent(
        event_id=event_id,
        scenario_id=scenario_id,
        timestamp=int(timestamp),
        source=source,
        target=target,
        event_type=event_type,
        vulnerability_id=vulnerability_id,
        severity=severity,
        description=description,
    )


def event_to_dict(event: AttackEvent) -> dict[str, object]:
    """Serialize an event to a dictionary."""
    return {
        "event_id": event.event_id,
        "scenario_id": event.scenario_id,
        "timestamp": event.timestamp,
        "source": event.source,
        "target": event.target,
        "event_type": event.event_type,
        "vulnerability_id": event.vulnerability_id,
        "severity": event.severity,
        "description": event.description,
    }


if __name__ == "__main__":
    sample = create_event(
        event_id="EVT-001",
        scenario_id="SCENARIO-ALPHA",
        timestamp=1,
        source="INTERNET",
        target="WEB01",
        event_type="initial_access",
        severity="High",
        description="Simulated external reconnaissance and ingress attempt.",
    )
    print(event_to_dict(sample))
