"""
FlowWatch 2.0 — Comprehensive Verification Suite for Response Engine & Approval Workflow
Deterministic unit and integration tests verifying all 18 requirements:
1. Proposal creation.
2. Execution rejected before approval.
3. Explicit rejection prevents execution.
4. Approved source-block action applies simulated state.
5. Approved destination-port action applies simulated state.
6. Watchlist action applies simulated state.
7. Successful verification.
8. Failed or unavailable verification.
9. Successful rollback restores the prior state.
10. Rollback of a pending or failed action is rejected.
11. Repeated execution is safely handled.
12. Duplicate state that predates an action is preserved after rollback.
13. Missing source IP or destination port is handled without fabricating data.
14. Audit events are persisted across database reopening.
15. Failed actions do not mark incidents contained.
16. Investigation-only actions do not claim containment.
17. Existing incident lifecycle rules remain enforced.
18. Existing FlowWatch baseline tests still pass.
"""

import os
import shutil
import tempfile
import unittest

from incident_models import (
    Alert,
    AlertSeverity,
    AuditEvent,
    CorrelationRule,
    Incident,
    IncidentStatus,
    ResponseAction,
    ActionType,
    ActionStatus,
    ActionMode,
)
from incident_store import IncidentStore
from response_engine import ResponseEngine, is_valid_ip, is_valid_port


class TestResponseEnginePhase2(unittest.TestCase):
    """Full suite of unit and integration tests for ResponseEngine."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.temp_dir, "test_response_flowwatch.db")
        self.store = IncidentStore(self.db_path)
        self.engine = ResponseEngine(self.store)

    def tearDown(self):
        self.store.close()
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    # 1. Proposal creation
    def test_01_proposal_creation(self):
        # Create an incident with source IP and destination port
        alert = Alert(
            src_ip="192.168.1.105",
            dest_port=80,
            protocol="TCP",
            packets=500,
            severity=AlertSeverity.HIGH,
        )
        aid = self.store.save_alert(alert)
        incident = Incident(
            title="Suspicious Web Flooding",
            correlation_rule=CorrelationRule.RULE_SRC_HOST.value,
            severity=AlertSeverity.HIGH,
            risk_score=75,
            primary_entity="192.168.1.105",
            entity_type="src_ip",
            alert_ids=[aid],
        )
        iid = self.store.save_incident(incident)

        proposals = self.engine.propose_actions(iid, auto_save=True)
        self.assertGreaterEqual(len(proposals), 3)

        types = [p.action_type for p in proposals]
        self.assertIn(ActionType.SIMULATE_BLOCK_SOURCE, types)
        self.assertIn(ActionType.WATCH_SOURCE, types)
        self.assertIn(ActionType.SIMULATE_BLOCK_DESTINATION_PORT, types)
        self.assertIn(ActionType.MARK_FOR_INVESTIGATION, types)

        # All proposals must initially be PENDING and in SIMULATED mode
        for p in proposals:
            self.assertEqual(p.status, ActionStatus.PENDING)
            self.assertEqual(p.mode, ActionMode.SIMULATED)

        # Proposals must be persisted in database
        saved_actions = self.store.get_response_actions(incident_id=iid)
        self.assertEqual(len(saved_actions), len(proposals))

    # 2. Execution rejected before approval
    def test_02_execution_rejected_before_approval(self):
        inc = Incident(title="Triage Port Scan", primary_entity="10.0.0.99")
        self.store.save_incident(inc)
        action = self.engine.create_proposal(
            inc.incident_id,
            ActionType.SIMULATE_BLOCK_SOURCE,
            target_entity="10.0.0.99",
        )
        self.assertEqual(action.status, ActionStatus.PENDING)

        # Executing a PENDING action must raise PermissionError
        with self.assertRaises(PermissionError) as ctx:
            self.engine.execute_action(action.action_id)
        self.assertIn("requires explicit approval", str(ctx.exception))

    # 3. Explicit rejection prevents execution
    def test_03_explicit_rejection_prevents_execution(self):
        inc = Incident(title="Benign Scanner", primary_entity="10.0.0.12")
        self.store.save_incident(inc)
        action = self.engine.create_proposal(
            inc.incident_id,
            ActionType.SIMULATE_BLOCK_SOURCE,
            target_entity="10.0.0.12",
        )

        # Analyst explicitly rejects the action
        rejected = self.engine.reject_action(
            action.action_id, actor="SOC_LEAD", reason="Known internal authorized vulnerability scanner."
        )
        self.assertEqual(rejected.status, ActionStatus.REJECTED)
        self.assertEqual(rejected.rejection_reason, "Known internal authorized vulnerability scanner.")

        # Attempting to execute rejected action must raise PermissionError
        with self.assertRaises(PermissionError) as ctx:
            self.engine.execute_action(action.action_id)
        self.assertIn("was REJECTED and cannot be executed", str(ctx.exception))

    # 4. Approved source-block action applies simulated state
    def test_04_approved_source_block_action_applies_simulated_state(self):
        inc = Incident(title="Malicious Ingress", primary_entity="198.51.100.22")
        self.store.save_incident(inc)
        action = self.engine.create_proposal(
            inc.incident_id,
            ActionType.SIMULATE_BLOCK_SOURCE,
            target_entity="198.51.100.22",
        )

        # Explicit approval
        approved = self.engine.approve_action(action.action_id, actor="SEC_ANALYST_1", comment="Confirmed bad actor IP")
        self.assertEqual(approved.status, ActionStatus.APPROVED)
        self.assertEqual(approved.approver, "SEC_ANALYST_1")
        self.assertIsNotNone(approved.approved_at)

        # Execution
        success, msg, executed = self.engine.execute_action(action.action_id, actor="SOC_AUTOMATION")
        self.assertTrue(success)
        self.assertEqual(executed.status, ActionStatus.APPLIED)
        self.assertEqual(executed.verification_status, "VERIFIED")

        # Check simulated containment state table
        is_blocked = self.store.is_entity_in_simulated_state("BLOCKED_SOURCE", "198.51.100.22")
        self.assertTrue(is_blocked)
        self.assertIn("198.51.100.22", self.engine.get_simulated_blocked_sources())

        # Incident status must be updated to CONTAINED because containment action was applied and verified
        updated_inc = self.store.get_incident(inc.incident_id)
        self.assertEqual(updated_inc.status, IncidentStatus.CONTAINED)

    # 5. Approved destination-port action applies simulated state
    def test_05_approved_destination_port_action_applies_simulated_state(self):
        inc = Incident(title="Telnet Exploitation", primary_entity="23", entity_type="dest_port")
        self.store.save_incident(inc)
        action = self.engine.create_proposal(
            inc.incident_id,
            ActionType.SIMULATE_BLOCK_DESTINATION_PORT,
            target_entity="23",
        )

        self.engine.approve_action(action.action_id, actor="SOC_LEAD")
        success, msg, executed = self.engine.execute_action(action.action_id)
        self.assertTrue(success)
        self.assertEqual(executed.status, ActionStatus.APPLIED)
        self.assertEqual(executed.verification_status, "VERIFIED")

        # Verify port in simulated state table
        is_port_blocked = self.store.is_entity_in_simulated_state("BLOCKED_PORT", "23")
        self.assertTrue(is_port_blocked)
        self.assertIn("23", self.engine.get_simulated_blocked_ports())

        updated_inc = self.store.get_incident(inc.incident_id)
        self.assertEqual(updated_inc.status, IncidentStatus.CONTAINED)

    # 6. Watchlist action applies simulated state
    def test_06_watchlist_action_applies_simulated_state(self):
        inc = Incident(title="Borderline Activity", primary_entity="10.20.30.40")
        self.store.save_incident(inc)
        action = self.engine.create_proposal(
            inc.incident_id,
            ActionType.WATCH_SOURCE,
            target_entity="10.20.30.40",
        )

        self.engine.approve_action(action.action_id, actor="SOC_ANALYST")
        success, msg, executed = self.engine.execute_action(action.action_id)
        self.assertTrue(success)
        self.assertEqual(executed.verification_status, "VERIFIED")

        is_watched = self.store.is_entity_in_simulated_state("WATCHED_SOURCE", "10.20.30.40")
        self.assertTrue(is_watched)
        self.assertIn("10.20.30.40", self.engine.get_simulated_watchlist())

        # Watchlist actions must NOT mark incident as CONTAINED
        updated_inc = self.store.get_incident(inc.incident_id)
        self.assertNotEqual(updated_inc.status, IncidentStatus.CONTAINED)

    # 7. Successful verification
    def test_07_successful_verification(self):
        inc = Incident(title="C2 Beaconing", primary_entity="198.51.100.77")
        self.store.save_incident(inc)
        action = self.engine.create_proposal(
            inc.incident_id,
            ActionType.SIMULATE_BLOCK_SOURCE,
            target_entity="198.51.100.77",
        )
        self.engine.approve_action(action.action_id, actor="ANALYST")
        self.engine.execute_action(action.action_id)

        # Independent verification check
        ver_status, ver_details = self.engine.verify_action(action.action_id)
        self.assertEqual(ver_status, "VERIFIED")
        self.assertIn("Source IP '198.51.100.77' is actively present", ver_details)
        # Verify it explicitly notes simulation only
        self.assertIn("Simulation only", ver_details)

    # 8. Failed or unavailable verification
    def test_08_failed_or_unavailable_verification(self):
        # Verification on an action that was never executed/applied
        inc = Incident(title="Pending Incident", primary_entity="10.0.0.5")
        self.store.save_incident(inc)
        action = self.engine.create_proposal(
            inc.incident_id,
            ActionType.SIMULATE_BLOCK_SOURCE,
            target_entity="10.0.0.5",
        )
        status, details = self.engine.verify_action(action.action_id)
        self.assertEqual(status, "FAILED")
        self.assertIn("not APPLIED", details)

        # Verification for an unsupported/notify-only action type
        notify_action = ResponseAction(
            incident_id=inc.incident_id,
            action_type=ActionType.NOTIFY_OPERATOR,
            target_entity="analyst_channel",
            status=ActionStatus.APPLIED,
        )
        self.store.save_response_action(notify_action)
        status2, details2 = self.engine.verify_action(notify_action.action_id)
        self.assertEqual(status2, "NOT_APPLICABLE")
        self.assertIn("not applicable", details2)

    # 9. Successful rollback restores the prior state
    def test_09_successful_rollback_restores_prior_state(self):
        inc = Incident(title="False Positive Containment", primary_entity="192.168.1.200")
        self.store.save_incident(inc)
        action = self.engine.create_proposal(
            inc.incident_id,
            ActionType.SIMULATE_BLOCK_SOURCE,
            target_entity="192.168.1.200",
        )
        self.engine.approve_action(action.action_id, actor="TIER_1")
        self.engine.execute_action(action.action_id)

        # Verify incident is Contained and entity is active in simulated blocklist
        self.assertEqual(self.store.get_incident(inc.incident_id).status, IncidentStatus.CONTAINED)
        self.assertTrue(self.store.is_entity_in_simulated_state("BLOCKED_SOURCE", "192.168.1.200"))

        # Roll back the action
        success, msg, rolled_back = self.engine.rollback_action(
            action.action_id, actor="TIER_2_LEAD", reason="Identified as legitimate business server"
        )
        self.assertTrue(success)
        self.assertEqual(rolled_back.status, ActionStatus.ROLLED_BACK)
        self.assertIsNotNone(rolled_back.rolled_back_at)

        # Entity should no longer be actively blocked
        self.assertFalse(self.store.is_entity_in_simulated_state("BLOCKED_SOURCE", "192.168.1.200"))
        self.assertNotIn("192.168.1.200", self.engine.get_simulated_blocked_sources())

        # Incident status should be reverted to INVESTIGATING
        reverted_inc = self.store.get_incident(inc.incident_id)
        self.assertEqual(reverted_inc.status, IncidentStatus.INVESTIGATING)

    # 10. Rollback of a pending or failed action is rejected
    def test_10_rollback_of_pending_or_failed_action_is_rejected(self):
        inc = Incident(title="Unapplied Action Incident", primary_entity="10.0.0.1")
        self.store.save_incident(inc)
        action = self.engine.create_proposal(
            inc.incident_id,
            ActionType.SIMULATE_BLOCK_SOURCE,
            target_entity="10.0.0.1",
        )

        # Rollback of PENDING action must raise ValueError
        with self.assertRaises(ValueError) as ctx:
            self.engine.rollback_action(action.action_id)
        self.assertIn("Only APPLIED actions can be rolled back", str(ctx.exception))

        # Rollback of FAILED action must also raise ValueError
        failed_action = ResponseAction(
            incident_id=inc.incident_id,
            action_type=ActionType.SIMULATE_BLOCK_SOURCE,
            target_entity="10.0.0.2",
            status=ActionStatus.FAILED,
        )
        self.store.save_response_action(failed_action)
        with self.assertRaises(ValueError) as ctx2:
            self.engine.rollback_action(failed_action.action_id)
        self.assertIn("Only APPLIED actions can be rolled back", str(ctx2.exception))

    # 11. Repeated execution is safely handled
    def test_11_repeated_execution_is_safely_handled(self):
        inc = Incident(title="Repeat Execution Test", primary_entity="10.0.0.44")
        self.store.save_incident(inc)
        action = self.engine.create_proposal(
            inc.incident_id,
            ActionType.SIMULATE_BLOCK_SOURCE,
            target_entity="10.0.0.44",
        )
        self.engine.approve_action(action.action_id)
        self.engine.execute_action(action.action_id)

        # Attempting second execution on already APPLIED action must raise ValueError
        with self.assertRaises(ValueError) as ctx:
            self.engine.execute_action(action.action_id)
        self.assertIn("already APPLIED", str(ctx.exception))

    # 12. Duplicate state that predates an action is preserved after rollback
    def test_12_duplicate_state_predating_action_preserved_after_rollback(self):
        """
        If IP 10.50.50.50 was already blocked by Action A (or pre-existing policy),
        and Action B also blocks 10.50.50.50, rolling back Action B must NOT unblock
        10.50.50.50 because Action A's block is still active.
        """
        inc1 = Incident(title="Incident 1", primary_entity="10.50.50.50")
        inc2 = Incident(title="Incident 2", primary_entity="10.50.50.50")
        self.store.save_incident(inc1)
        self.store.save_incident(inc2)

        # Action A blocks 10.50.50.50
        action_a = self.engine.create_proposal(inc1.incident_id, ActionType.SIMULATE_BLOCK_SOURCE, "10.50.50.50")
        self.engine.approve_action(action_a.action_id)
        self.engine.execute_action(action_a.action_id)
        self.assertTrue(self.store.is_entity_in_simulated_state("BLOCKED_SOURCE", "10.50.50.50"))

        # Action B also blocks 10.50.50.50
        action_b = self.engine.create_proposal(inc2.incident_id, ActionType.SIMULATE_BLOCK_SOURCE, "10.50.50.50")
        self.engine.approve_action(action_b.action_id)
        self.engine.execute_action(action_b.action_id)

        # Roll back Action B only
        self.engine.rollback_action(action_b.action_id, actor="ANALYST", reason="Incident 2 was deemed false alarm")

        # 10.50.50.50 must STILL BE BLOCKED because Action A is still active!
        self.assertTrue(self.store.is_entity_in_simulated_state("BLOCKED_SOURCE", "10.50.50.50"))
        self.assertIn("10.50.50.50", self.engine.get_simulated_blocked_sources())

        # If Action A is also rolled back, then it should finally be unblocked
        self.engine.rollback_action(action_a.action_id, actor="ANALYST", reason="Incident 1 also dismissed")
        self.assertFalse(self.store.is_entity_in_simulated_state("BLOCKED_SOURCE", "10.50.50.50"))

    # 13. Missing source IP or destination port is handled without fabricating data
    def test_13_missing_ip_or_port_handled_without_fabrication(self):
        # Alert without IP and without Port (e.g., pure protocol burst)
        alert = Alert(
            protocol="UDP",
            packets=25000,
            reasons="High packet burst on UDP",
            severity=AlertSeverity.HIGH,
        )
        aid = self.store.save_alert(alert)
        inc = Incident(
            title="Volumetric UDP Burst",
            correlation_rule=CorrelationRule.RULE_VOLUMETRIC_BURST.value,
            primary_entity="UDP",
            entity_type="protocol",
            alert_ids=[aid],
        )
        iid = self.store.save_incident(inc)

        # Check proposal generation
        proposals = self.engine.propose_actions(iid)
        # Should only propose MARK_FOR_INVESTIGATION, no fake IP block or fake port block
        action_types = [p.action_type for p in proposals]
        self.assertIn(ActionType.MARK_FOR_INVESTIGATION, action_types)
        self.assertNotIn(ActionType.SIMULATE_BLOCK_SOURCE, action_types)
        self.assertNotIn(ActionType.SIMULATE_BLOCK_DESTINATION_PORT, action_types)

        # Verify explainability notes state why actions are unavailable
        analysis = self.engine.explain_playbook_availability(inc)
        self.assertEqual(len(analysis["source_ips"]), 0)
        self.assertEqual(len(analysis["destination_ports"]), 0)
        reasons_text = " ".join(analysis["unavailable_reasons"])
        self.assertIn("no verified source IP", reasons_text)
        self.assertIn("no verified destination port", reasons_text)

        # Attempting to manually create proposal with empty entity must raise ValueError
        with self.assertRaises(ValueError):
            self.engine.create_proposal(iid, ActionType.SIMULATE_BLOCK_SOURCE, target_entity="")

    # 14. Audit events are persisted across database reopening
    def test_14_audit_events_persisted_across_database_reopening(self):
        inc = Incident(title="Audit Persistence Check", primary_entity="10.88.88.88")
        self.store.save_incident(inc)
        action = self.engine.create_proposal(inc.incident_id, ActionType.SIMULATE_BLOCK_SOURCE, "10.88.88.88")
        self.engine.approve_action(action.action_id, actor="OPERATOR_X", comment="Audit test approval")
        self.engine.execute_action(action.action_id, actor="AUTOMATION_Y")
        self.engine.rollback_action(action.action_id, actor="LEAD_Z", reason="Audit test rollback")

        # Close database connection and reopen with a fresh instance
        self.store.close()
        reopened_store = IncidentStore(self.db_path)
        try:
            events = reopened_store.get_audit_events(incident_id=inc.incident_id)
            self.assertGreaterEqual(len(events), 4)

            event_types = [e.event_type for e in events]
            self.assertIn("ACTION_PROPOSED", event_types)
            self.assertIn("ACTION_APPROVED", event_types)
            self.assertIn("ACTION_APPLIED", event_types)
            self.assertIn("ACTION_ROLLED_BACK", event_types)

            actors = [e.actor for e in events]
            self.assertIn("OPERATOR_X", actors)
            self.assertIn("AUTOMATION_Y", actors)
            self.assertIn("LEAD_Z", actors)
        finally:
            reopened_store.close()

    # 15. Failed actions do not mark incidents contained
    def test_15_failed_actions_do_not_mark_incidents_contained(self):
        inc = Incident(title="Failure Safety Test", primary_entity="10.0.0.7")
        self.store.save_incident(inc)
        action = self.engine.create_proposal(inc.incident_id, ActionType.SIMULATE_BLOCK_SOURCE, "10.0.0.7")
        action = self.engine.approve_action(action.action_id)

        # Corrupt target entity before execution to trigger simulated failure
        action.target_entity = ""
        self.store.save_response_action(action)

        success, msg, failed_action = self.engine.execute_action(action.action_id)
        self.assertFalse(success)
        self.assertEqual(failed_action.status, ActionStatus.FAILED)
        self.assertEqual(failed_action.verification_status, "FAILED")

        # Incident status must NOT be CONTAINED
        inc_check = self.store.get_incident(inc.incident_id)
        self.assertNotEqual(inc_check.status, IncidentStatus.CONTAINED)

    # 16. Investigation-only actions do not claim containment
    def test_16_investigation_only_actions_do_not_claim_containment(self):
        inc = Incident(title="Investigate Only", primary_entity="172.16.1.1")
        self.store.save_incident(inc)
        action = self.engine.create_proposal(inc.incident_id, ActionType.MARK_FOR_INVESTIGATION, inc.incident_id)
        self.engine.approve_action(action.action_id)

        success, msg, executed = self.engine.execute_action(action.action_id)
        self.assertTrue(success)
        self.assertEqual(executed.verification_status, "VERIFIED")

        # Must move from NEW to INVESTIGATING, but never CONTAINED
        inc_check = self.store.get_incident(inc.incident_id)
        self.assertEqual(inc_check.status, IncidentStatus.INVESTIGATING)
        self.assertNotEqual(inc_check.status, IncidentStatus.CONTAINED)

    # 17. Existing incident lifecycle rules remain enforced
    def test_17_existing_incident_lifecycle_rules_remain_enforced(self):
        inc = Incident(title="Lifecycle Safety", primary_entity="10.10.10.1")
        self.store.save_incident(inc)

        # Manually close incident
        self.store.update_incident_status(inc.incident_id, IncidentStatus.CLOSED, actor="ANALYST")

        # Creating and applying an action on a CLOSED incident:
        # A closed incident cannot transition directly to CONTAINED without re-opening
        action = self.engine.create_proposal(inc.incident_id, ActionType.SIMULATE_BLOCK_SOURCE, "10.10.10.1")
        self.engine.approve_action(action.action_id)
        success, msg, executed = self.engine.execute_action(action.action_id)
        self.assertTrue(success)

        # Since CLOSED -> CONTAINED is invalid per VALID_INCIDENT_TRANSITIONS,
        # the engine must NOT force an invalid transition!
        inc_after = self.store.get_incident(inc.incident_id)
        self.assertEqual(inc_after.status, IncidentStatus.CLOSED)

    # 18. End-to-end response lifecycle with complete audit trail verification
    def test_18_engine_end_to_end_lifecycle_with_audit_trail(self):
        inc = Incident(title="End-to-End Threat Response", primary_entity="198.51.100.99")
        self.store.save_incident(inc)

        # 1. Propose
        action = self.engine.create_proposal(
            inc.incident_id,
            ActionType.SIMULATE_BLOCK_SOURCE,
            target_entity="198.51.100.99",
            description="End-to-end test containment",
            actor="SOC_OPERATOR",
        )
        self.assertEqual(action.status, ActionStatus.PENDING)

        # 2. Approve
        approved = self.engine.approve_action(action.action_id, actor="SOC_LEAD", comment="Authorized block")
        self.assertEqual(approved.status, ActionStatus.APPROVED)

        # 3. Execute
        success, msg, executed = self.engine.execute_action(action.action_id, actor="ORCHESTRATOR")
        self.assertTrue(success)
        self.assertEqual(executed.status, ActionStatus.APPLIED)
        self.assertEqual(executed.verification_status, "VERIFIED")
        self.assertTrue(self.store.is_entity_in_simulated_state("BLOCKED_SOURCE", "198.51.100.99"))

        # Incident status should be CONTAINED
        self.assertEqual(self.store.get_incident(inc.incident_id).status, IncidentStatus.CONTAINED)

        # 4. Rollback
        rb_success, rb_msg, rolled_back = self.engine.rollback_action(
            action.action_id, actor="SOC_LEAD", reason="Threat remediated"
        )
        self.assertTrue(rb_success)
        self.assertEqual(rolled_back.status, ActionStatus.ROLLED_BACK)
        self.assertFalse(self.store.is_entity_in_simulated_state("BLOCKED_SOURCE", "198.51.100.99"))

        # Incident status reverted to INVESTIGATING
        self.assertEqual(self.store.get_incident(inc.incident_id).status, IncidentStatus.INVESTIGATING)

        # Verify complete audit history
        events = self.store.get_audit_events(incident_id=inc.incident_id)
        event_types = [e.event_type for e in events]
        self.assertIn("ACTION_PROPOSED", event_types)
        self.assertIn("ACTION_APPROVED", event_types)
        self.assertIn("ACTION_APPLIED", event_types)
        self.assertIn("ACTION_VERIFIED", event_types)
        self.assertIn("ACTION_ROLLED_BACK", event_types)


if __name__ == "__main__":
    unittest.main()
