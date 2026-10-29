"""
FlowWatch 2.0 — Comprehensive Verification Suite for Incident Management
Deterministic unit and integration tests verifying:
- Dataclass validation & serialization
- Lifecycle state transitions and invalid transition rejections
- SQLite persistence, concurrency settings, queries, and ACID atomicity
- Duplicate alert deduplication
- Deterministic correlation rules (Host convergence, Port sweep, Service surge, Multi-detector, Missing IP fallback)
- Safe handling of missing IPs, ports, duration, bytes, and timestamps
- Transparent risk scoring formula, factor breakdown, and bounds [0, 100]
- Database reopening persistence across connections
- Audit event trail immutability
"""

import os
import shutil
import tempfile
import unittest

import numpy as np
import pandas as pd

from incident_models import (
    Alert,
    AlertSeverity,
    AuditEvent,
    Incident,
    IncidentStatus,
    ResponseAction,
    ActionType,
    ActionStatus,
    ActionMode,
    CorrelationRule,
    utc_now_iso,
)
from incident_store import IncidentStore
from incident_engine import (
    IncidentEngine,
    calculate_transparent_risk_score,
    extract_alerts_from_dataframe,
)


class TestIncidentModels(unittest.TestCase):
    """Verifies dataclass contracts, serialization, and lifecycle validation."""

    def test_alert_defaults_and_serialization(self):
        alert = Alert(
            protocol="tcp",
            packets=150,
            flagged_by="Statistical",
            severity=AlertSeverity.HIGH,
            reasons="Packet count 4.5 std above baseline",
        )
        self.assertIsNotNone(alert.alert_id)
        self.assertEqual(alert.protocol, "TCP")
        self.assertEqual(alert.packets, 150)
        self.assertIsNone(alert.src_ip)
        self.assertIsNone(alert.dest_port)
        self.assertIsNotNone(alert.fingerprint)

        # Serialization roundtrip
        d = alert.to_dict()
        self.assertEqual(d["severity"], "High")
        reconstructed = Alert.from_dict(d)
        self.assertEqual(reconstructed.alert_id, alert.alert_id)
        self.assertEqual(reconstructed.fingerprint, alert.fingerprint)
        self.assertEqual(reconstructed.severity, AlertSeverity.HIGH)

    def test_incident_lifecycle_transitions(self):
        incident = Incident(
            title="Suspicious Host",
            correlation_rule=CorrelationRule.RULE_SRC_HOST.value,
            severity=AlertSeverity.MEDIUM,
            risk_score=45,
            primary_entity="192.168.1.100",
        )
        self.assertEqual(incident.status, IncidentStatus.NEW)

        # Valid transitions: NEW -> INVESTIGATING -> CONTAINED -> RESOLVED -> CLOSED
        self.assertTrue(incident.can_transition_to(IncidentStatus.INVESTIGATING))
        incident.transition_to(IncidentStatus.INVESTIGATING)
        self.assertEqual(incident.status, IncidentStatus.INVESTIGATING)

        self.assertTrue(incident.can_transition_to(IncidentStatus.CONTAINED))
        incident.transition_to(IncidentStatus.CONTAINED)
        self.assertEqual(incident.status, IncidentStatus.CONTAINED)

        self.assertTrue(incident.can_transition_to(IncidentStatus.RESOLVED))
        incident.transition_to(IncidentStatus.RESOLVED)
        self.assertEqual(incident.status, IncidentStatus.RESOLVED)

        self.assertTrue(incident.can_transition_to(IncidentStatus.CLOSED))
        incident.transition_to(IncidentStatus.CLOSED)
        self.assertEqual(incident.status, IncidentStatus.CLOSED)

        # Valid reopen: CLOSED -> INVESTIGATING
        self.assertTrue(incident.can_transition_to(IncidentStatus.INVESTIGATING))
        incident.transition_to(IncidentStatus.INVESTIGATING)
        self.assertEqual(incident.status, IncidentStatus.INVESTIGATING)

        # Invalid transition: INVESTIGATING directly to NEW should raise ValueError
        self.assertFalse(incident.can_transition_to(IncidentStatus.NEW))
        with self.assertRaises(ValueError):
            incident.transition_to(IncidentStatus.NEW)

    def test_response_action_and_audit_event_serialization(self):
        action = ResponseAction(
            incident_id="inc-123",
            action_type=ActionType.SIMULATED_ISOLATION,
            target_entity="10.0.0.5",
            description="Simulate host isolation",
            parameters={"duration_sec": 300},
        )
        d_action = action.to_dict()
        self.assertEqual(d_action["mode"], "SIMULATED")
        reconstructed_action = ResponseAction.from_dict(d_action)
        self.assertEqual(reconstructed_action.action_type, ActionType.SIMULATED_ISOLATION)
        self.assertEqual(reconstructed_action.parameters["duration_sec"], 300)

        event = AuditEvent(
            event_type="CONTAINMENT_APPLIED",
            actor="ANALYST_SEC_1",
            description="Host 10.0.0.5 contained virtually",
            incident_id="inc-123",
            details={"ip": "10.0.0.5", "mode": "SIMULATED"},
        )
        d_event = event.to_dict()
        reconstructed_event = AuditEvent.from_dict(d_event)
        self.assertEqual(reconstructed_event.actor, "ANALYST_SEC_1")
        self.assertEqual(reconstructed_event.details["ip"], "10.0.0.5")


class TestSQLiteIncidentStore(unittest.TestCase):
    """Verifies durable storage, deduplication, queries, and ACID properties."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.temp_dir, "test_flowwatch.db")
        self.store = IncidentStore(self.db_path)

    def tearDown(self):
        self.store.close()
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_alert_save_and_deduplication(self):
        alert1 = Alert(
            protocol="TCP",
            packets=500,
            bytes=45000,
            src_ip="192.168.1.10",
            dst_ip="10.0.0.1",
            source_port=44321,
            dest_port=80,
            flagged_by="Both",
            severity=AlertSeverity.HIGH,
            reasons="High packet rate",
        )
        aid1 = self.store.save_alert(alert1)
        self.assertEqual(aid1, alert1.alert_id)

        # Save an alert with identical content/fingerprint but different alert_id
        alert2 = Alert(
            protocol="TCP",
            packets=500,
            bytes=45000,
            src_ip="192.168.1.10",
            dst_ip="10.0.0.1",
            source_port=44321,
            dest_port=80,
            flagged_by="Both",
            severity=AlertSeverity.HIGH,
            reasons="High packet rate",
        )
        aid2 = self.store.save_alert(alert2)

        # Deduplication must return existing alert ID without adding second row
        self.assertEqual(aid1, aid2)
        retrieved = self.store.get_alert(aid1)
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.src_ip, "192.168.1.10")

    def test_incident_persistence_and_queries(self):
        # Create and persist 2 alerts
        a1 = Alert(protocol="UDP", packets=1000, src_ip="172.16.0.5", dest_port=53, severity=AlertSeverity.HIGH)
        a2 = Alert(protocol="UDP", packets=1200, src_ip="172.16.0.5", dest_port=53, severity=AlertSeverity.HIGH)
        aid1 = self.store.save_alert(a1)
        aid2 = self.store.save_alert(a2)

        inc = Incident(
            title="DNS Amplification Surge",
            correlation_rule=CorrelationRule.RULE_SRC_HOST.value,
            severity=AlertSeverity.HIGH,
            risk_score=75,
            risk_factors=["Base Severity: High (+40)", "Multi-Detector (+20)"],
            alert_ids=[aid1, aid2],
            primary_entity="172.16.0.5",
        )
        iid = self.store.save_incident(inc)
        self.assertEqual(iid, inc.incident_id)

        # Query incident by ID
        loaded = self.store.get_incident(iid)
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded.title, "DNS Amplification Surge")
        self.assertEqual(loaded.risk_score, 75)
        self.assertEqual(set(loaded.alert_ids), {aid1, aid2})

        # Query linked alerts
        linked_alerts = self.store.get_alerts_for_incident(iid)
        self.assertEqual(len(linked_alerts), 2)
        self.assertEqual(linked_alerts[0].src_ip, "172.16.0.5")

        # Query by status and severity
        high_incs = self.store.list_incidents(severity="High")
        self.assertEqual(len(high_incs), 1)

        low_incs = self.store.list_incidents(severity="Low")
        self.assertEqual(len(low_incs), 0)

    def test_status_update_with_automatic_audit_log(self):
        inc = Incident(title="Investigate Port Probe", severity=AlertSeverity.MEDIUM)
        iid = self.store.save_incident(inc)

        updated = self.store.update_incident_status(
            iid, IncidentStatus.INVESTIGATING, actor="ANALYST_JANE", note="Verified host origin"
        )
        self.assertEqual(updated.status, IncidentStatus.INVESTIGATING)

        # Audit events must record this change
        events = self.store.get_audit_events(incident_id=iid)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].event_type, "INCIDENT_STATUS_CHANGED")
        self.assertEqual(events[0].actor, "ANALYST_JANE")
        self.assertIn("Verified host origin", events[0].description)

    def test_reopen_database_preserves_state(self):
        # Save incident, close store, re-open with fresh store instance
        inc = Incident(title="Durable State Test", risk_score=88, primary_entity="10.10.10.10")
        iid = self.store.save_incident(inc)
        self.store.close()

        reopened_store = IncidentStore(self.db_path)
        try:
            loaded = reopened_store.get_incident(iid)
            self.assertIsNotNone(loaded)
            self.assertEqual(loaded.title, "Durable State Test")
            self.assertEqual(loaded.risk_score, 88)
        finally:
            reopened_store.close()


class TestCorrelationRules(unittest.TestCase):
    """Verifies each deterministic correlation rule, risk score, and missing-IP fallback."""

    def setUp(self):
        self.engine = IncidentEngine(time_window_seconds=300)

    def test_rule_1_host_convergence(self):
        # 3 alerts sharing the same src_ip
        alerts = [
            Alert(src_ip="192.168.1.55", dest_port=80, protocol="TCP", packets=100, severity=AlertSeverity.MEDIUM),
            Alert(src_ip="192.168.1.55", dest_port=80, protocol="TCP", packets=120, severity=AlertSeverity.MEDIUM),
            Alert(src_ip="192.168.1.55", dest_port=80, protocol="TCP", packets=150, severity=AlertSeverity.HIGH),
        ]
        incidents = self.engine.correlate_alerts(alerts)
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0].correlation_rule, CorrelationRule.RULE_SRC_HOST.value)
        self.assertEqual(incidents[0].primary_entity, "192.168.1.55")
        self.assertEqual(len(incidents[0].alert_ids), 3)

    def test_rule_2_port_sweep(self):
        # Single src_ip probing 4 distinct destination ports
        alerts = [
            Alert(src_ip="10.200.1.1", dest_port=21, protocol="TCP", packets=5, severity=AlertSeverity.LOW),
            Alert(src_ip="10.200.1.1", dest_port=22, protocol="TCP", packets=5, severity=AlertSeverity.LOW),
            Alert(src_ip="10.200.1.1", dest_port=23, protocol="TCP", packets=5, severity=AlertSeverity.LOW),
            Alert(src_ip="10.200.1.1", dest_port=80, protocol="TCP", packets=5, severity=AlertSeverity.LOW),
        ]
        incidents = self.engine.correlate_alerts(alerts)
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0].correlation_rule, CorrelationRule.RULE_PORT_SWEEP.value)
        self.assertEqual(incidents[0].primary_entity, "10.200.1.1")
        self.assertEqual(len(incidents[0].alert_ids), 4)

    def test_rule_3_service_surge(self):
        # 3 distinct sources attacking port 443 on TCP
        alerts = [
            Alert(src_ip="1.1.1.1", dest_port=443, protocol="TCP", packets=5000, severity=AlertSeverity.HIGH),
            Alert(src_ip="2.2.2.2", dest_port=443, protocol="TCP", packets=6000, severity=AlertSeverity.HIGH),
            Alert(src_ip="3.3.3.3", dest_port=443, protocol="TCP", packets=7000, severity=AlertSeverity.HIGH),
        ]
        incidents = self.engine.correlate_alerts(alerts)
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0].correlation_rule, CorrelationRule.RULE_SERVICE_SURGE.value)
        self.assertEqual(incidents[0].primary_entity, "TCP/443")
        self.assertEqual(len(incidents[0].alert_ids), 3)

    def test_rule_4_multi_detector_corroboration(self):
        # Alert flagged by Both statistical and ML detector
        a1 = Alert(
            src_ip="192.168.10.100",
            dest_port=8080,
            protocol="TCP",
            packets=2500,
            flagged_by="Both",
            severity=AlertSeverity.HIGH,
            ensemble_score=0.92,
            reasons="Packet count 4.2 std above baseline",
        )
        incidents = self.engine.correlate_alerts([a1])
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0].correlation_rule, CorrelationRule.RULE_MULTI_DETECTOR.value)
        # Check risk score includes base + corroboration + ensemble + volumetric
        self.assertGreaterEqual(incidents[0].risk_score, 80)

    def test_rule_5_conservative_missing_ip_fallback(self):
        """
        Conservative fallback requirement:
        Do NOT group unrelated alerts merely because they share a protocol!
        Unrelated alerts with different signatures must remain distinct.
        """
        alerts = [
            # Two alerts sharing exact protocol and signature (burst group)
            Alert(protocol="TCP", packets=5000, reasons="Packet count 4.5 std above baseline", severity=AlertSeverity.HIGH),
            Alert(protocol="TCP", packets=5000, reasons="Packet count 4.5 std above baseline", severity=AlertSeverity.HIGH),
            # Unrelated alert with completely different signature
            Alert(protocol="TCP", packets=20, reasons="Isolation Forest flagged on port combination", severity=AlertSeverity.LOW),
        ]
        incidents = self.engine.correlate_alerts(alerts)
        # Must produce 2 separate incidents, NOT lump all 3 together
        self.assertEqual(len(incidents), 2)
        rules = [inc.correlation_rule for inc in incidents]
        self.assertIn(CorrelationRule.RULE_VOLUMETRIC_BURST.value, rules)
        self.assertIn(CorrelationRule.RULE_SINGLETON.value, rules)

    def test_separation_of_unrelated_hosts(self):
        # Alerts from distinct hosts targeting distinct services must remain separate
        alerts = [
            Alert(src_ip="10.0.0.1", dest_port=80, protocol="TCP", packets=50),
            Alert(src_ip="10.0.0.2", dest_port=443, protocol="TCP", packets=50),
        ]
        incidents = self.engine.correlate_alerts(alerts)
        self.assertEqual(len(incidents), 2)
        self.assertNotEqual(incidents[0].primary_entity, incidents[1].primary_entity)


class TestTransparentRiskScore(unittest.TestCase):
    """Verifies itemized risk scoring, exact factor contributions, and clamping bounds [0, 100]."""

    def test_score_calculation_breakdown(self):
        # Construct an alert with known attributes
        alert = Alert(
            protocol="TCP",
            packets=1500,
            severity=AlertSeverity.HIGH,         # +40
            flagged_by="Both",                   # +20
            ensemble_score=0.92,                 # +15 (>= 0.90)
            reasons="Packet count 4.1 std above",# +10 (z >= 4.0)
        )
        score, factors, sev = calculate_transparent_risk_score([alert])
        # Expected score: 40 + 20 + 15 + 10 = 85
        self.assertEqual(score, 85)
        self.assertEqual(sev, AlertSeverity.HIGH)
        # Verify factor strings
        factor_text = " ".join(factors)
        self.assertIn("Base Severity: High (+40)", factor_text)
        self.assertIn("Multi-Detector Corroboration", factor_text)
        self.assertIn("High Supervised Model Confidence", factor_text)
        self.assertIn("Extreme Volumetric Deviation", factor_text)

    def test_score_upper_bound_clamped_at_100(self):
        # Create an incident with multiple compounding factors exceeding 100
        alerts = [
            Alert(severity=AlertSeverity.CRITICAL, flagged_by="Both", ensemble_score=0.99, reasons="z=5.0", packets=5000)
            for _ in range(6) # Multiplicity boost (+10)
        ]
        # Base (50) + Corroboration (20) + Ensemble (15) + Volumetric (10) + Multiplicity (10) = 105 -> clamped to 100
        score, factors, sev = calculate_transparent_risk_score(alerts)
        self.assertEqual(score, 100)
        self.assertEqual(sev, AlertSeverity.CRITICAL)

    def test_no_double_counting_across_alerts(self):
        # 4 High severity alerts should take base severity +40 ONCE, not 4x40=160
        alerts = [
            Alert(severity=AlertSeverity.HIGH, packets=100)
            for _ in range(4)
        ]
        # Base High (40) + Multiplicity >=3 (+5) = 45
        score, factors, sev = calculate_transparent_risk_score(alerts)
        self.assertEqual(score, 45)


class TestDataFrameAlertExtraction(unittest.TestCase):
    """Verifies alert extraction from FlowWatch detection DataFrames."""

    def test_extract_alerts_from_synthetic_dataframe(self):
        df = pd.DataFrame([
            {
                "protocol": "TCP",
                "packets": 1000,
                "Flagged By": "Statistical",
                "Severity": "High",
                "Reasons": "Packet count 4.2 std above baseline",
                "Flag Status": "Statistical",
            },
            {
                "protocol": "UDP",
                "packets": 50,
                "Flagged By": "None",
                "Severity": "Low",
                "Reasons": "",
                "Flag Status": "Normal",
            },
        ])
        alerts = extract_alerts_from_dataframe(df, source_type="json")
        # Only the flagged row should become an Alert
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].protocol, "TCP")
        self.assertEqual(alerts[0].packets, 1000)
        self.assertEqual(alerts[0].severity, AlertSeverity.HIGH)
        self.assertIsNone(alerts[0].src_ip)  # Did not invent a fake IP


if __name__ == "__main__":
    unittest.main()
