"""
FlowWatch 2.0 - End-to-End Workflow Verification Suite
Validates the complete 12-step lifecycle from ingestion to simulated response,
rollback, audit persistence, deduplication, edge cases, and original tab compatibility.
Uses strictly temporary SQLite storage to prevent modifying user runtime data.
"""

import os
import shutil
import tempfile
import unittest
import pandas as pd
import numpy as np

from data_loader import load_network_data
from pcap_loader import load_pcap_data
from statistical_detector import detect_statistical_anomalies
from ml_detector import detect_anomalies
from explainability import add_explanations
from incident_models import (
    Alert,
    AlertSeverity,
    Incident,
    ResponseAction,
    AuditEvent,
    IncidentStatus,
    ActionStatus,
    ActionType,
    ActionMode,
)
from incident_store import IncidentStore
from incident_engine import IncidentEngine, extract_alerts_from_dataframe
from response_engine import ResponseEngine


class TestFlowWatchEndToEndWorkflow(unittest.TestCase):
    """End-to-end integration test validating FlowWatch 2.0 requirements."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="flowwatch_e2e_")
        self.db_path = os.path.join(self.temp_dir, "test_e2e.db")
        self.store = IncidentStore(self.db_path)
        self.incident_engine = IncidentEngine()
        self.response_engine = ResponseEngine(self.store)

    def tearDown(self):
        self.store.close()
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_complete_12_step_workflow(self):
        """Execute and verify the full 12-step detection-to-response lifecycle."""
        # 1. Load supported sample traffic dataset
        json_path = os.path.join(os.path.dirname(__file__), "network_traffic.json")
        self.assertTrue(os.path.exists(json_path), f"Sample file not found: {json_path}")
        df_raw = load_network_data(json_path)
        self.assertGreater(len(df_raw), 0, "Loaded dataset is empty")

        # 2. Run existing detection pipeline
        from feature_engineering import add_engineered_features
        df_proc = add_engineered_features(df_raw.copy())
        df_proc["Statistical Result"], stat_thresh = detect_statistical_anomalies(df_proc)
        ml_res = detect_anomalies(df_proc, use_engineered_features=False)
        df_proc["ML Result"] = ml_res["ml_status"].values
        df_explained = add_explanations(df_proc, threshold=stat_thresh)
        df_explained["Flag Status"] = df_explained["Flagged By"].replace({"None": "Normal"})

        self.assertIn("Flag Status", df_explained.columns)
        self.assertIn("Reasons", df_explained.columns)
        flagged_df = df_explained[df_explained["Flag Status"] != "Normal"]
        self.assertGreater(len(flagged_df), 0, "Pipeline flagged zero anomalies")

        # 3. Confirm flagged rows become persisted alerts and correlated incidents
        extracted_alerts = extract_alerts_from_dataframe(df_explained, source_type="json")
        self.assertGreater(len(extracted_alerts), 0, "No alerts extracted from flagged rows")

        created_incidents = self.incident_engine.process_and_persist(
            extracted_alerts,
            store=self.store,
            skip_already_associated=True,
        )
        self.assertGreater(len(created_incidents), 0, "No incidents created from alerts")

        all_incidents = self.store.list_incidents()
        self.assertGreater(len(all_incidents), 0, "No incidents stored in database")

        target_incident = all_incidents[0]
        self.assertIsNotNone(target_incident.incident_id)
        self.assertEqual(target_incident.status, IncidentStatus.NEW)

        # 4. Confirm incident risk scores and explanations are displayed/stored correctly
        self.assertGreaterEqual(target_incident.risk_score, 0.0)
        self.assertLessEqual(target_incident.risk_score, 100.0)
        self.assertTrue(len(target_incident.risk_factors) > 0)
        self.assertTrue(target_incident.summary)

        # 5. Select incident and propose suitable response actions
        proposals = self.response_engine.propose_actions(target_incident.incident_id, auto_save=True)
        self.assertGreater(len(proposals), 0, "No response actions proposed")

        proposed_action = proposals[0]
        self.assertIsNotNone(proposed_action.action_id)

        # 6. Confirm the action remains pending until explicit approval
        self.assertEqual(proposed_action.status, ActionStatus.PENDING)
        with self.assertRaises(PermissionError):
            # Attempt execution without approval must raise PermissionError
            self.response_engine.execute_action(proposed_action.action_id, actor="analyst_test")

        # Verify incident status has NOT changed to CONTAINED
        fresh_inc = self.store.get_incident(target_incident.incident_id)
        self.assertNotEqual(fresh_inc.status, IncidentStatus.CONTAINED)

        # 7. Confirm a rejected action cannot execute
        proposal_to_reject = proposals[1] if len(proposals) > 1 else self.response_engine.create_proposal(
            target_incident.incident_id,
            ActionType.WATCH_SOURCE,
            target_entity="10.0.0.99",
        )
        rejected = self.response_engine.reject_action(
            proposal_to_reject.action_id,
            actor="security_lead",
            reason="Unnecessary action for this asset",
        )
        self.assertEqual(rejected.status, ActionStatus.REJECTED)
        with self.assertRaises(PermissionError):
            self.response_engine.execute_action(rejected.action_id, actor="security_lead")

        # 8. Approve and execute an eligible simulated response
        # Find or create a containable proposal (e.g. SIMULATE_BLOCK_SOURCE)
        contain_proposal = next((p for p in proposals if p.action_type == ActionType.SIMULATE_BLOCK_SOURCE), None)
        if not contain_proposal:
            contain_proposal = self.response_engine.create_proposal(
                target_incident.incident_id,
                ActionType.SIMULATE_BLOCK_SOURCE,
                target_entity=target_incident.primary_entity or "192.168.1.100",
            )

        approved_action = self.response_engine.approve_action(
            contain_proposal.action_id,
            actor="secops_supervisor",
            comment="Approved for simulated containment",
        )
        self.assertEqual(approved_action.status, ActionStatus.APPROVED)

        success, msg, executed_action = self.response_engine.execute_action(
            approved_action.action_id,
            actor="secops_operator",
        )
        self.assertTrue(success)
        self.assertEqual(executed_action.status, ActionStatus.APPLIED)
        self.assertEqual(executed_action.mode, ActionMode.SIMULATED)

        # 9. Verify simulated state and inspect audit trail
        is_blocked = self.store.is_entity_in_simulated_state("BLOCKED_SOURCE", executed_action.target_entity)
        self.assertTrue(is_blocked, "Target entity was not recorded as active in simulated state")

        # Confirm containment on the incident
        inc_after_exec = self.store.get_incident(target_incident.incident_id)
        self.assertEqual(inc_after_exec.status, IncidentStatus.CONTAINED)

        # Audit events must be populated
        audit_events = self.store.get_audit_events(incident_id=target_incident.incident_id)
        action_audit_events = [e for e in audit_events if e.action_id == executed_action.action_id]
        self.assertGreater(len(action_audit_events), 0)

        # 10. Roll back the action and confirm prior simulated state is restored
        success_rb, msg_rb, rolled_back = self.response_engine.rollback_action(
            executed_action.action_id,
            actor="secops_supervisor",
            reason="Incident resolved; testing rollback verification",
        )
        self.assertTrue(success_rb)
        self.assertEqual(rolled_back.status, ActionStatus.ROLLED_BACK)

        is_blocked_after = self.store.is_entity_in_simulated_state("BLOCKED_SOURCE", executed_action.target_entity)
        self.assertFalse(is_blocked_after, "Simulated state was not deactivated after rollback")

        inc_after_rollback = self.store.get_incident(target_incident.incident_id)
        self.assertIn(inc_after_rollback.status, [IncidentStatus.RESOLVED, IncidentStatus.INVESTIGATING])

        # 11. Refresh or rerun dashboard ingestion and confirm zero duplicate ingestion
        extracted_alerts_rerun = extract_alerts_from_dataframe(df_explained, source_type="json")
        rerun_incidents = self.incident_engine.process_and_persist(
            extracted_alerts_rerun,
            store=self.store,
            skip_already_associated=True,
        )
        self.assertEqual(len(rerun_incidents), 0, "Duplicate incidents created on rerun!")

        # 12. Confirm all original pipeline detectors remain functional and compatible
        csv_path = os.path.join(os.path.dirname(__file__), "network_traffic_test.csv")
        pcap_path = os.path.join(os.path.dirname(__file__), "sample_traffic.pcap")
        if os.path.exists(csv_path):
            df_csv = load_network_data(csv_path)
            stat_res, stat_t = detect_statistical_anomalies(df_csv)
            df_csv["Statistical Result"] = stat_res
            df_csv["ML Result"] = detect_anomalies(df_csv)["ml_status"].values
            res_csv = add_explanations(df_csv, threshold=stat_t)
            res_csv["Flag Status"] = res_csv["Flagged By"].replace({"None": "Normal"})
            self.assertIn("Flag Status", res_csv.columns)
        if os.path.exists(pcap_path):
            df_pcap, pcap_stats = load_pcap_data(pcap_path)
            stat_res, stat_t = detect_statistical_anomalies(df_pcap)
            df_pcap["Statistical Result"] = stat_res
            df_pcap["ML Result"] = detect_anomalies(df_pcap)["ml_status"].values
            res_pcap = add_explanations(df_pcap, threshold=stat_t)
            res_pcap["Flag Status"] = res_pcap["Flagged By"].replace({"None": "Normal"})
            self.assertIn("Flag Status", res_pcap.columns)

    def test_edge_cases_and_robustness(self):
        """Test missing IPs, missing ports, empty datasets, and invalid state transitions."""
        # A. Missing IP addresses and missing ports
        data_missing_fields = {
            "protocol": ["TCP", "UDP"],
            "packets": [50000, 10],
            "Flag Status": ["Extreme Anomaly", "Normal"],
            "Reasons": ["Extreme burst", ""],
        }
        df_sparse = pd.DataFrame(data_missing_fields)
        sparse_alerts = extract_alerts_from_dataframe(df_sparse)
        self.assertEqual(len(sparse_alerts), 1)
        self.assertIsNone(sparse_alerts[0].src_ip)
        self.assertIsNone(sparse_alerts[0].dest_port)

        sparse_incidents = self.incident_engine.process_and_persist(sparse_alerts, store=self.store)
        self.assertEqual(len(sparse_incidents), 1)
        self.assertIn("TCP flow", sparse_incidents[0].primary_entity)

        # B. Empty dataset
        df_empty = pd.DataFrame(columns=["protocol", "packets", "Flag Status", "Reasons"])
        empty_alerts = extract_alerts_from_dataframe(df_empty)
        self.assertEqual(len(empty_alerts), 0)
        empty_incidents = self.incident_engine.process_and_persist(empty_alerts, store=self.store)
        self.assertEqual(len(empty_incidents), 0)

        # C. Invalid incident state transitions
        inc = Incident(
            title="Transition test",
            severity="High",
            primary_entity="192.168.1.99",
            status=IncidentStatus.NEW,
        )
        self.store.save_incident(inc)

        # Transition directly to CLOSED
        inc_closed = self.store.update_incident_status(inc.incident_id, IncidentStatus.CLOSED)
        self.assertEqual(inc_closed.status, IncidentStatus.CLOSED)

        # Transitioning from CLOSED directly to RESOLVED or NEW is an invalid transition
        with self.assertRaises(ValueError):
            self.store.update_incident_status(inc.incident_id, IncidentStatus.RESOLVED)

        with self.assertRaises(ValueError):
            self.store.update_incident_status(inc.incident_id, IncidentStatus.NEW)

        # D. Invalid action transition: cannot roll back an action that is PENDING
        pending_act = self.response_engine.create_proposal(
            incident_id=inc.incident_id,
            action_type=ActionType.SIMULATE_BLOCK_SOURCE,
            target_entity="192.168.1.99",
        )
        with self.assertRaises(ValueError):
            self.response_engine.rollback_action(pending_act.action_id, actor="analyst")


if __name__ == "__main__":
    unittest.main()
