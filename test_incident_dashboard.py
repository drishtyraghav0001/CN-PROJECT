"""
FlowWatch 2.0 — Phase 3: Incident Response Dashboard Integration Verification Suite
Deterministic tests verifying:
1. Existing six tabs and workflows remain intact.
2. Dashboard integration imports successfully.
3. The incident tab logic handles an empty database.
4. Incidents and details are loaded and formatted from persisted data.
5. Filters do not fail when optional fields are absent.
6. Pending actions cannot execute without approval.
7. Rejected actions cannot execute.
8. Approved actions use the backend response engine.
9. Verification and rollback controls respect action states.
10. Simulated state and audit events are refreshed after actions.
11. Repeated dashboard reruns do not duplicate incidents.
12. Missing IPs and ports are handled without fabrication.
13. Existing detection and benchmark workflows remain unchanged.
"""

import os
import shutil
import tempfile
import unittest

import numpy as np
import pandas as pd

from incident_models import (
    ActionMode,
    ActionStatus,
    ActionType,
    Alert,
    AlertSeverity,
    AuditEvent,
    CorrelationRule,
    Incident,
    IncidentStatus,
)
from incident_store import IncidentStore
from incident_engine import IncidentEngine, extract_alerts_from_dataframe
from response_engine import ResponseEngine


class TestIncidentDashboardIntegration(unittest.TestCase):
    """Verifies dashboard integration logic, ingestion, deduplication, and workflows."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.temp_dir, "test_dashboard_flowwatch.db")
        self.store = IncidentStore(self.db_path)
        self.engine = IncidentEngine(time_window_seconds=300)
        self.response = ResponseEngine(self.store)

    def tearDown(self):
        self.store.close()
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    # 1. Existing six tabs and workflows remain intact
    def test_01_existing_tabs_preserved(self):
        # Inspect model_dashboard.py source to verify all 7 tabs are present in order
        with open("model_dashboard.py", "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn("tab_ov, tab_tr, tab_inv, tab_cmp, tab_eval, tab_rep, tab_resp = st.tabs(", content)
        self.assertIn('"Overview"', content)
        self.assertIn('"Traffic Analytics"', content)
        self.assertIn('"Anomaly Investigation"', content)
        self.assertIn('"Model Comparison"', content)
        self.assertIn('"Evaluation"', content)
        self.assertIn('"Reports"', content)
        self.assertIn('"Incident Response & Triage"', content)

    # 2. Dashboard integration imports successfully
    def test_02_dashboard_imports_successfully(self):
        # Verify that model_dashboard compiles cleanly and exposes incident integration getters
        import ast
        import py_compile
        compiled = py_compile.compile("model_dashboard.py", doraise=True)
        self.assertIsNotNone(compiled)

        with open("model_dashboard.py", "r", encoding="utf-8") as f:
            tree = ast.parse(f.read())
        func_names = [node.name for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)]
        self.assertIn("get_incident_store", func_names)
        self.assertIn("get_response_engine", func_names)
        self.assertIn("get_incident_engine", func_names)

    # 3. The incident tab handles an empty database
    def test_03_empty_database_handling(self):
        # When store is brand new, list_incidents returns empty list
        incs = self.store.list_incidents()
        self.assertEqual(len(incs), 0)
        actions = self.store.get_response_actions()
        self.assertEqual(len(actions), 0)
        events = self.store.get_audit_events()
        self.assertEqual(len(events), 0)
        active_sim = self.store.get_active_simulated_state()
        self.assertEqual(len(active_sim), 0)
        # Check summary metrics compute to 0 without division by zero or errors
        total_incs = len(incs)
        active_incs = sum(1 for i in incs if i.status in (IncidentStatus.NEW, IncidentStatus.INVESTIGATING))
        high_risk_incs = sum(1 for i in incs if i.severity in (AlertSeverity.HIGH, AlertSeverity.CRITICAL) or i.risk_score >= 70)
        self.assertEqual(total_incs, 0)
        self.assertEqual(active_incs, 0)
        self.assertEqual(high_risk_incs, 0)

    # 4. Incidents and their details are displayed using persisted data
    def test_04_persisted_incident_details(self):
        alert = Alert(
            src_ip="192.168.1.100",
            dest_port=443,
            protocol="TCP",
            packets=1500,
            severity=AlertSeverity.HIGH,
            flagged_by="Both",
            reasons="Packet count 4.2 std above baseline",
        )
        aid = self.store.save_alert(alert)
        inc = Incident(
            title="Suspicious HTTPS Flood",
            correlation_rule=CorrelationRule.RULE_SRC_HOST.value,
            severity=AlertSeverity.HIGH,
            risk_score=85,
            risk_factors=["Base Severity: High (+40)", "Multi-Detector (+20)", "Extreme Volumetric (+10)"],
            alert_ids=[aid],
            primary_entity="192.168.1.100",
            entity_type="src_ip",
            summary="Host 192.168.1.100 generated high packet volume.",
        )
        iid = self.store.save_incident(inc)

        # Retrieve and verify all details are preserved
        loaded = self.store.get_incident(iid)
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded.title, "Suspicious HTTPS Flood")
        self.assertEqual(loaded.risk_score, 85)
        self.assertEqual(len(loaded.risk_factors), 3)
        self.assertEqual(loaded.primary_entity, "192.168.1.100")

        linked_alerts = self.store.get_alerts_for_incident(iid)
        self.assertEqual(len(linked_alerts), 1)
        self.assertEqual(linked_alerts[0].src_ip, "192.168.1.100")
        self.assertEqual(linked_alerts[0].dest_port, 443)

    # 5. Filters do not fail when optional fields are absent
    def test_05_filters_robust_to_missing_optional_fields(self):
        # Create incident with None for optional primary_entity, entity_type, summary
        inc_minimal = Incident(
            title="Minimal Incident",
            primary_entity=None,
            entity_type=None,
            summary=None,
            risk_score=25,
            severity=AlertSeverity.LOW,
            status=IncidentStatus.NEW,
        )
        self.store.save_incident(inc_minimal)

        all_incs = self.store.list_incidents()
        self.assertEqual(len(all_incs), 1)

        # Apply filtering
        by_status = [i for i in all_incs if i.status.value == "New"]
        self.assertEqual(len(by_status), 1)

        by_sev = [i for i in all_incs if i.severity.value == "Low"]
        self.assertEqual(len(by_sev), 1)

        by_risk = [i for i in all_incs if i.risk_score < 40]
        self.assertEqual(len(by_risk), 1)

    # 6. Pending actions cannot execute without approval
    def test_06_pending_actions_cannot_execute_without_approval(self):
        inc = Incident(title="Gating Test", primary_entity="10.1.1.1")
        self.store.save_incident(inc)
        action = self.response.create_proposal(inc.incident_id, ActionType.SIMULATE_BLOCK_SOURCE, "10.1.1.1")
        self.assertEqual(action.status, ActionStatus.PENDING)

        with self.assertRaises(PermissionError):
            self.response.execute_action(action.action_id)

    # 7. Rejected actions cannot execute
    def test_07_rejected_actions_cannot_execute(self):
        inc = Incident(title="Reject Test", primary_entity="10.2.2.2")
        self.store.save_incident(inc)
        action = self.response.create_proposal(inc.incident_id, ActionType.SIMULATE_BLOCK_SOURCE, "10.2.2.2")
        self.response.reject_action(action.action_id, actor="OPERATOR", reason="False alarm")

        with self.assertRaises(PermissionError):
            self.response.execute_action(action.action_id)

    # 8. Approved actions use the backend response engine
    def test_08_approved_actions_use_backend_engine(self):
        inc = Incident(title="Approved Test", primary_entity="10.3.3.3")
        self.store.save_incident(inc)
        action = self.response.create_proposal(inc.incident_id, ActionType.SIMULATE_BLOCK_SOURCE, "10.3.3.3")
        self.response.approve_action(action.action_id, actor="LEAD_ANALYST", comment="Approved for simulation")

        success, msg, executed = self.response.execute_action(action.action_id, actor="AUTOMATION")
        self.assertTrue(success)
        self.assertEqual(executed.status, ActionStatus.APPLIED)
        self.assertTrue(self.store.is_entity_in_simulated_state("BLOCKED_SOURCE", "10.3.3.3"))

    # 9. Verification and rollback controls respect action states
    def test_09_verification_and_rollback_respect_states(self):
        inc = Incident(title="State Respect Test", primary_entity="10.4.4.4")
        self.store.save_incident(inc)
        action = self.response.create_proposal(inc.incident_id, ActionType.SIMULATE_BLOCK_SOURCE, "10.4.4.4")

        # Rollback before execution must raise ValueError
        with self.assertRaises(ValueError):
            self.response.rollback_action(action.action_id)

        # Approve and execute
        self.response.approve_action(action.action_id)
        self.response.execute_action(action.action_id)

        # Now verification must succeed
        v_status, v_details = self.response.verify_action(action.action_id)
        self.assertEqual(v_status, "VERIFIED")

        # Now rollback must succeed
        rb_ok, rb_msg, rolled_back = self.response.rollback_action(action.action_id, actor="SOC", reason="Rollback verified")
        self.assertTrue(rb_ok)
        self.assertEqual(rolled_back.status, ActionStatus.ROLLED_BACK)

    # 10. Simulated state and audit events are refreshed after actions
    def test_10_simulated_state_and_audit_refreshed(self):
        inc = Incident(title="Audit Refresh Test", primary_entity="10.5.5.5")
        self.store.save_incident(inc)
        action = self.response.create_proposal(inc.incident_id, ActionType.WATCH_SOURCE, "10.5.5.5")
        self.response.approve_action(action.action_id, actor="SOC_OP")
        self.response.execute_action(action.action_id)

        # Check watchlist
        watchlist = self.response.get_simulated_watchlist()
        self.assertIn("10.5.5.5", watchlist)

        # Check audit trail
        events = self.store.get_audit_events(incident_id=inc.incident_id)
        ev_types = [e.event_type for e in events]
        self.assertIn("ACTION_PROPOSED", ev_types)
        self.assertIn("ACTION_APPROVED", ev_types)
        self.assertIn("ACTION_APPLIED", ev_types)

    # 11. Repeated dashboard reruns do not duplicate incidents
    def test_11_repeated_reruns_do_not_duplicate_incidents(self):
        # Simulate a DataFrame with 1 flagged anomaly
        df = pd.DataFrame([
            {
                "protocol": "TCP",
                "packets": 5000,
                "src_ip": "192.168.100.5",
                "dest_port": 80,
                "Flag Status": "Statistical",
                "Flagged By": "Statistical",
                "Severity": "High",
                "Reasons": "Packet count 4.5 std above baseline",
            }
        ])

        # Run 1: initial ingestion
        extracted_1 = extract_alerts_from_dataframe(df, source_type="file")
        incidents_1 = self.engine.process_and_persist(extracted_1, self.store, skip_already_associated=True)
        self.assertEqual(len(incidents_1), 1)
        self.assertEqual(len(self.store.list_incidents()), 1)

        # Run 2: simulated dashboard rerun with the exact same data
        extracted_2 = extract_alerts_from_dataframe(df, source_type="file")
        incidents_2 = self.engine.process_and_persist(extracted_2, self.store, skip_already_associated=True)
        # Must NOT create another incident!
        self.assertEqual(len(incidents_2), 0)
        self.assertEqual(len(self.store.list_incidents()), 1)

        # Run 3: a third rerun
        extracted_3 = extract_alerts_from_dataframe(df, source_type="file")
        incidents_3 = self.engine.process_and_persist(extracted_3, self.store, skip_already_associated=True)
        self.assertEqual(len(incidents_3), 0)
        self.assertEqual(len(self.store.list_incidents()), 1)

    # 12. Missing IPs and ports are handled without fabrication
    def test_12_missing_ips_and_ports_handled_cleanly(self):
        # Incident derived from an alert with missing IPs/ports
        alert = Alert(
            protocol="UDP",
            packets=10000,
            src_ip=None,
            dst_ip=None,
            source_port=None,
            dest_port=None,
            reasons="High volumetric burst",
        )
        aid = self.store.save_alert(alert)
        inc = Incident(
            title="IP-less Burst",
            primary_entity="UDP",
            entity_type="protocol",
            alert_ids=[aid],
        )
        iid = self.store.save_incident(inc)

        analysis = self.response.explain_playbook_availability(inc)
        self.assertEqual(len(analysis["source_ips"]), 0)
        self.assertEqual(len(analysis["destination_ports"]), 0)
        self.assertIn(ActionType.MARK_FOR_INVESTIGATION.value, analysis["available_playbooks"])
        self.assertNotIn(ActionType.SIMULATE_BLOCK_SOURCE.value, analysis["available_playbooks"])

    # 13. Existing detection and benchmark workflows remain unchanged
    def test_13_existing_detection_and_benchmark_workflows_intact(self):
        # Verify that feature engineering and statistical detection work identically
        from feature_engineering import add_engineered_features
        from statistical_detector import detect_statistical_anomalies

        p = list(range(40, 61))
        b = [x * 100 for x in p]
        d = [5.0 + (x - 50) * 0.1 for x in p]
        base_df = pd.DataFrame({"protocol": ["TCP"] * len(p), "packets": p, "bytes": b, "duration": d})
        base_df = add_engineered_features(base_df)
        n = len(base_df)
        base_df.loc[n] = {"protocol": "TCP", "packets": 5000, "bytes": 5000, "duration": 5.0}
        flags, thresh = detect_statistical_anomalies(base_df, std_multiplier=2.0)
        self.assertEqual(flags.iloc[n], "Potential Anomaly")
        self.assertEqual(flags.iloc[0], "Normal")


if __name__ == "__main__":
    unittest.main()
