"""TraceWard attack simulator package.

Provides fictional simulated attack event modeling only.
No real exploitation, scanning, payloads, or malware logic is included.
"""

from __future__ import annotations

from src.attack_simulator.events import (
    SEVERITY_LEVELS,
    SUPPORTED_EVENT_TYPES,
    AttackEvent,
    EventType,
    create_event,
    event_to_dict,
)

__all__ = [
    "AttackEvent",
    "EventType",
    "create_event",
    "event_to_dict",
    "SEVERITY_LEVELS",
    "SUPPORTED_EVENT_TYPES",
]
