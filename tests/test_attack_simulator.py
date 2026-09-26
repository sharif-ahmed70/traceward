"""Unit tests for the TraceWard attack simulator event model."""

from __future__ import annotations

import unittest

from src.attack_simulator import (
    SEVERITY_LEVELS,
    SUPPORTED_EVENT_TYPES,
    AttackEvent,
    create_event,
    event_to_dict,
)


class TestAttackEventSchema(unittest.TestCase):
    """Event representation must expose the required fields."""

    def test_event_has_required_fields(self):
        event = create_event(
            event_id="EVT-1",
            scenario_id="S1",
            timestamp=1,
            source="INTERNET",
            target="WEB01",
            event_type="initial_access",
        )
        self.assertEqual(event.event_id, "EVT-1")
        self.assertEqual(event.scenario_id, "S1")
        self.assertEqual(event.timestamp, 1)
        self.assertEqual(event.source, "INTERNET")
        self.assertEqual(event.target, "WEB01")
        self.assertEqual(event.event_type, "initial_access")
        self.assertIsNone(event.vulnerability_id)
        self.assertEqual(event.severity, "Medium")
        self.assertEqual(event.description, "")


class TestAttackEventTypeValidation(unittest.TestCase):
    """Only supported event types should be accepted."""

    def test_supported_event_types_accepted(self):
        for event_type in SUPPORTED_EVENT_TYPES:
            event = create_event(
                event_id="EVT-SUPPORTED",
                scenario_id="S1",
                timestamp=1,
                source="INTERNET",
                target="WEB01",
                event_type=event_type,
            )
            self.assertEqual(event.event_type, event_type)

    def test_unsupported_event_type_raises(self):
        with self.assertRaises(ValueError):
            create_event(
                event_id="EVT-BAD",
                scenario_id="S1",
                timestamp=1,
                source="INTERNET",
                target="WEB01",
                event_type="malware_execution",
            )


class TestAttackEventSeverityValidation(unittest.TestCase):
    """Severity must be one of the allowed levels."""

    def test_valid_severity_accepted(self):
        for severity in sorted(SEVERITY_LEVELS):
            event = create_event(
                event_id="EVT-SEVERITY",
                scenario_id="S1",
                timestamp=1,
                source="INTERNET",
                target="WEB01",
                event_type="initial_access",
                severity=severity,
            )
            self.assertEqual(event.severity, severity)

    def test_invalid_severity_raises(self):
        with self.assertRaises(ValueError):
            create_event(
                event_id="EVT-SEVERITY-BAD",
                scenario_id="S1",
                timestamp=1,
                source="INTERNET",
                target="WEB01",
                event_type="initial_access",
                severity="Invalid",
            )


class TestAttackEventNullableVulnerabilityId(unittest.TestCase):
    """vulnerability_id should be optional."""

    def test_null_vulnerability_id_allowed(self):
        event = create_event(
            event_id="EVT-NULL-VULN",
            scenario_id="S1",
            timestamp=1,
            source="INTERNET",
            target="WEB01",
            event_type="initial_access",
            vulnerability_id=None,
        )
        self.assertIsNone(event.vulnerability_id)

    def test_string_vulnerability_id_allowed(self):
        event = create_event(
            event_id="EVT-VULN",
            scenario_id="S1",
            timestamp=1,
            source="INTERNET",
            target="WEB01",
            event_type="vulnerability_exploitation",
            vulnerability_id="V0001",
        )
        self.assertEqual(event.vulnerability_id, "V0001")


class TestAttackEventSerialization(unittest.TestCase):
    """event_to_dict should preserve all fields."""

    def test_event_to_dict_round_trip(self):
        event = create_event(
            event_id="EVT-DICT",
            scenario_id="SCENARIO-ALPHA",
            timestamp=5,
            source="WEB01",
            target="APP01",
            event_type="lateral_movement",
            vulnerability_id="V0002",
            severity="High",
            description="Simulated pivot from web tier to application tier.",
        )
        data = event_to_dict(event)
        self.assertEqual(data["event_id"], "EVT-DICT")
        self.assertEqual(data["scenario_id"], "SCENARIO-ALPHA")
        self.assertEqual(data["timestamp"], 5)
        self.assertEqual(data["source"], "WEB01")
        self.assertEqual(data["target"], "APP01")
        self.assertEqual(data["event_type"], "lateral_movement")
        self.assertEqual(data["vulnerability_id"], "V0002")
        self.assertEqual(data["severity"], "High")
        self.assertEqual(data["description"], "Simulated pivot from web tier to application tier.")


if __name__ == "__main__":
    unittest.main()
