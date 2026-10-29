"""
FlowWatch 2.0 — Safe Response Engine, Approval Workflow, and Rollback
Implements modular, approval-gated simulated incident response.
Strictly SIMULATED mode: no operating-system changes, no firewall modifications,
no subprocess execution, and no real network interference.
"""

from typing import Any, Dict, List, Optional, Set, Tuple, Union

from incident_models import (
    ActionMode,
    ActionStatus,
    ActionType,
    AuditEvent,
    Incident,
    IncidentStatus,
    ResponseAction,
    utc_now_iso,
)
from incident_store import IncidentStore


CONTAINMENT_ACTION_TYPES: Set[ActionType] = {
    ActionType.SIMULATE_BLOCK_SOURCE,
    ActionType.SIMULATE_BLOCK_DESTINATION_PORT,
    ActionType.SIMULATED_ISOLATION,
    ActionType.SIMULATED_BLOCK_PORT,
}


def is_valid_ip(val: Optional[str]) -> bool:
    """Validates that a string represents a plausible, non-empty IP address entity."""
    if not val or not isinstance(val, str):
        return False
    s = val.strip()
    if not s or s.upper() in ("TCP", "UDP", "ICMP", "NETWORK", "NONE", "UNKNOWN"):
        return False
    # Reject strings with colons or slashes if they are service keys like "TCP/80"
    if "/" in s:
        return False
    # Plausible IPv4 or IPv6 check (contains at least one dot or colon)
    parts = s.split(".")
    if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        return True
    if ":" in s:  # IPv6 representation
        return True
    return False


def is_valid_port(val: Any) -> bool:
    """Validates that a value represents a valid TCP/UDP port (1-65535)."""
    if val is None:
        return False
    try:
        p = int(val)
        return 1 <= p <= 65535
    except (ValueError, TypeError):
        return False


class ResponseEngine:
    """
    Simulated Response Engine for FlowWatch 2.0.
    Provides approval-based workflow, playbook proposals, simulated containment,
    post-execution state verification, and safe state rollback.
    """

    def __init__(self, store: IncidentStore):
        self.store = store

    # ---------------- Playbook Proposals ----------------
    def explain_playbook_availability(
        self,
        incident: Incident,
    ) -> Dict[str, Any]:
        """
        Analyzes an incident and its alerts to explain which actions can or cannot
        be proposed, preventing data fabrication for missing IPs or ports.
        """
        alerts = self.store.get_alerts_for_incident(incident.incident_id)

        # Source IP discovery
        candidate_ips: Set[str] = set()
        if is_valid_ip(incident.primary_entity) and incident.entity_type == "src_ip":
            candidate_ips.add(incident.primary_entity.strip())
        for a in alerts:
            if is_valid_ip(a.src_ip):
                candidate_ips.add(a.src_ip.strip())

        # Destination Port discovery
        candidate_ports: Set[int] = set()
        if is_valid_port(incident.primary_entity) and incident.entity_type == "dest_port":
            candidate_ports.add(int(incident.primary_entity))
        elif incident.primary_entity and "/" in incident.primary_entity:
            # Handle format "TCP/80"
            parts = incident.primary_entity.split("/")
            if len(parts) == 2 and is_valid_port(parts[1]):
                candidate_ports.add(int(parts[1]))

        for a in alerts:
            if is_valid_port(a.dest_port):
                candidate_ports.add(int(a.dest_port))

        available = []
        unavailable = []

        if candidate_ips:
            available.append(ActionType.SIMULATE_BLOCK_SOURCE.value)
            available.append(ActionType.WATCH_SOURCE.value)
        else:
            unavailable.append(
                f"{ActionType.SIMULATE_BLOCK_SOURCE.value}: Incident contains no verified source IP address in evidence."
            )
            unavailable.append(
                f"{ActionType.WATCH_SOURCE.value}: Incident contains no verified source IP address in evidence."
            )

        if candidate_ports:
            available.append(ActionType.SIMULATE_BLOCK_DESTINATION_PORT.value)
        else:
            unavailable.append(
                f"{ActionType.SIMULATE_BLOCK_DESTINATION_PORT.value}: Incident contains no verified destination port in evidence."
            )

        # Investigation is always available
        available.append(ActionType.MARK_FOR_INVESTIGATION.value)

        return {
            "source_ips": sorted(list(candidate_ips)),
            "destination_ports": sorted(list(candidate_ports)),
            "available_playbooks": available,
            "unavailable_reasons": unavailable,
        }

    def propose_actions(
        self,
        incident: Union[Incident, str],
        auto_save: bool = True,
        actor: str = "SYSTEM",
    ) -> List[ResponseAction]:
        """
        Generates safe response action proposals based on confirmed evidence.
        Never fabricates IPs or ports. Only proposes valid, executable actions.
        """
        if isinstance(incident, str):
            inc_obj = self.store.get_incident(incident)
            if not inc_obj:
                raise KeyError(f"Incident with ID '{incident}' not found.")
            incident = inc_obj

        analysis = self.explain_playbook_availability(incident)
        proposals: List[ResponseAction] = []

        # 1. Propose Source IP Actions if source IP exists
        for ip in analysis["source_ips"]:
            proposals.append(
                ResponseAction(
                    incident_id=incident.incident_id,
                    action_type=ActionType.SIMULATE_BLOCK_SOURCE,
                    target_entity=ip,
                    mode=ActionMode.SIMULATED,
                    status=ActionStatus.PENDING,
                    description=f"Simulate blocking malicious source host {ip} in isolated simulation table.",
                    parameters={
                        "ip": ip,
                        "playbook": "SIMULATE_BLOCK_SOURCE",
                        "unavailability_notes": analysis["unavailable_reasons"],
                    },
                )
            )
            proposals.append(
                ResponseAction(
                    incident_id=incident.incident_id,
                    action_type=ActionType.WATCH_SOURCE,
                    target_entity=ip,
                    mode=ActionMode.SIMULATED,
                    status=ActionStatus.PENDING,
                    description=f"Add source host {ip} to simulated surveillance watchlist.",
                    parameters={
                        "ip": ip,
                        "playbook": "WATCH_SOURCE",
                        "unavailability_notes": analysis["unavailable_reasons"],
                    },
                )
            )

        # 2. Propose Destination Port Actions if destination port exists
        for port in analysis["destination_ports"]:
            proposals.append(
                ResponseAction(
                    incident_id=incident.incident_id,
                    action_type=ActionType.SIMULATE_BLOCK_DESTINATION_PORT,
                    target_entity=str(port),
                    mode=ActionMode.SIMULATED,
                    status=ActionStatus.PENDING,
                    description=f"Simulate blocking targeted destination port {port} in isolated simulation table.",
                    parameters={
                        "port": port,
                        "playbook": "SIMULATE_BLOCK_DESTINATION_PORT",
                        "unavailability_notes": analysis["unavailable_reasons"],
                    },
                )
            )

        # 3. Always propose Mark for Investigation
        proposals.append(
            ResponseAction(
                incident_id=incident.incident_id,
                action_type=ActionType.MARK_FOR_INVESTIGATION,
                target_entity=incident.incident_id,
                mode=ActionMode.SIMULATED,
                status=ActionStatus.PENDING,
                description=f"Mark incident {incident.incident_id} for deeper analyst investigation without containment.",
                parameters={
                    "incident_id": incident.incident_id,
                    "playbook": "MARK_FOR_INVESTIGATION",
                    "unavailability_notes": analysis["unavailable_reasons"],
                },
            )
        )

        if auto_save:
            for action in proposals:
                self.store.save_response_action(action)
                self.store.log_audit_event(
                    AuditEvent(
                        event_type="ACTION_PROPOSED",
                        actor=actor,
                        description=f"Proposed simulated action '{action.action_type.value}' targeting '{action.target_entity}'.",
                        incident_id=incident.incident_id,
                        action_id=action.action_id,
                        details={
                            "action_type": action.action_type.value,
                            "target_entity": action.target_entity,
                            "mode": action.mode.value,
                        },
                    )
                )

        return proposals

    def create_proposal(
        self,
        incident_id: str,
        action_type: ActionType,
        target_entity: str,
        description: str = "",
        parameters: Optional[Dict[str, Any]] = None,
        actor: str = "ANALYST",
    ) -> ResponseAction:
        """Creates and persists an explicit response proposal."""
        incident = self.store.get_incident(incident_id)
        if not incident:
            raise KeyError(f"Incident with ID '{incident_id}' not found.")

        # Guard against fabricating empty entity values
        if not target_entity or not str(target_entity).strip():
            raise ValueError(f"Cannot propose action '{action_type.value}' with an empty target entity.")

        # Validate IP/port specific targets
        if action_type in (ActionType.SIMULATE_BLOCK_SOURCE, ActionType.WATCH_SOURCE):
            if not is_valid_ip(target_entity):
                raise ValueError(
                    f"Invalid target IP '{target_entity}' for action {action_type.value}. Must be a valid IP address."
                )
        elif action_type in (ActionType.SIMULATE_BLOCK_DESTINATION_PORT, ActionType.SIMULATED_BLOCK_PORT):
            if not is_valid_port(target_entity):
                raise ValueError(
                    f"Invalid target port '{target_entity}' for action {action_type.value}. Must be between 1 and 65535."
                )

        action = ResponseAction(
            incident_id=incident_id,
            action_type=action_type,
            target_entity=str(target_entity).strip(),
            mode=ActionMode.SIMULATED,
            status=ActionStatus.PENDING,
            description=description or f"Proposed {action_type.value} on {target_entity}",
            parameters=parameters or {},
        )
        self.store.save_response_action(action)
        self.store.log_audit_event(
            AuditEvent(
                event_type="ACTION_PROPOSED",
                actor=actor,
                description=f"Custom proposed simulated action '{action.action_type.value}' on '{action.target_entity}'.",
                incident_id=incident_id,
                action_id=action.action_id,
                details={"action_type": action.action_type.value, "target_entity": action.target_entity},
            )
        )
        return action

    # ---------------- Approval & Rejection Workflow ----------------
    def approve_action(
        self,
        action_id: str,
        actor: str = "ANALYST",
        comment: str = "",
    ) -> ResponseAction:
        """
        Explicitly approves a PENDING response action.
        Raises ValueError if the action is not in PENDING state.
        """
        action = self.store.get_response_action(action_id)
        if not action:
            raise KeyError(f"Response action '{action_id}' not found.")

        if action.status != ActionStatus.PENDING:
            raise ValueError(
                f"Action '{action_id}' has status '{action.status.value}'. Only PENDING actions can be approved."
            )

        action.transition_to(ActionStatus.APPROVED)
        action.approver = actor
        action.approved_at = utc_now_iso()
        if comment:
            action.parameters["approval_comment"] = comment

        self.store.save_response_action(action)
        self.store.log_audit_event(
            AuditEvent(
                event_type="ACTION_APPROVED",
                actor=actor,
                description=f"Action '{action.action_type.value}' targeting '{action.target_entity}' approved. {comment}".strip(),
                incident_id=action.incident_id,
                action_id=action.action_id,
                details={"actor": actor, "comment": comment},
            )
        )
        return action

    def reject_action(
        self,
        action_id: str,
        actor: str = "ANALYST",
        reason: str = "",
    ) -> ResponseAction:
        """
        Explicitly rejects a PENDING response action without executing it.
        Raises ValueError if the action is not in PENDING state.
        """
        action = self.store.get_response_action(action_id)
        if not action:
            raise KeyError(f"Response action '{action_id}' not found.")

        if action.status != ActionStatus.PENDING:
            raise ValueError(
                f"Action '{action_id}' has status '{action.status.value}'. Only PENDING actions can be rejected."
            )

        action.transition_to(ActionStatus.REJECTED)
        action.rejection_reason = reason
        if reason:
            action.parameters["rejection_reason"] = reason

        self.store.save_response_action(action)
        self.store.log_audit_event(
            AuditEvent(
                event_type="ACTION_REJECTED",
                actor=actor,
                description=f"Action '{action.action_type.value}' targeting '{action.target_entity}' rejected. Reason: {reason}".strip(),
                incident_id=action.incident_id,
                action_id=action.action_id,
                details={"actor": actor, "reason": reason},
            )
        )
        return action

    # ---------------- Execution & Verification ----------------
    def execute_action(
        self,
        action_id: str,
        actor: str = "SYSTEM",
    ) -> Tuple[bool, str, ResponseAction]:
        """
        Executes an APPROVED action in SIMULATED mode only.
        Enforces approval gating, isolation, verification, and audit logging.
        Returns:
            (success: bool, message: str, updated_action: ResponseAction)
        """
        action = self.store.get_response_action(action_id)
        if not action:
            raise KeyError(f"Response action '{action_id}' not found.")

        # Lifecycle state gating
        if action.status == ActionStatus.PENDING:
            raise PermissionError(
                f"Execution rejected: Action '{action_id}' is PENDING and requires explicit approval before execution."
            )
        if action.status == ActionStatus.REJECTED:
            raise PermissionError(
                f"Execution rejected: Action '{action_id}' was REJECTED and cannot be executed."
            )
        if action.status == ActionStatus.APPLIED:
            raise ValueError(
                f"Execution rejected: Action '{action_id}' is already APPLIED. Actions cannot be applied a second time."
            )
        if action.status != ActionStatus.APPROVED:
            raise ValueError(
                f"Execution rejected: Action '{action_id}' has status '{action.status.value}'. Must be APPROVED."
            )

        # Mode gating: Phase 2 permits SIMULATED ONLY
        if action.mode != ActionMode.SIMULATED:
            raise PermissionError(
                f"Execution refused: FlowWatch Phase 2 only permits SIMULATED mode. Mode '{action.mode.value}' is disabled."
            )

        # Execute simulated state transition
        try:
            if action.action_type in (ActionType.SIMULATE_BLOCK_SOURCE, ActionType.SIMULATED_ISOLATION):
                if not action.target_entity:
                    raise ValueError("Cannot execute block source: target IP entity is empty.")
                self.store.add_simulated_state(
                    state_type="BLOCKED_SOURCE",
                    entity_value=action.target_entity,
                    action_id=action.action_id,
                    incident_id=action.incident_id,
                )

            elif action.action_type in (ActionType.SIMULATE_BLOCK_DESTINATION_PORT, ActionType.SIMULATED_BLOCK_PORT):
                if not action.target_entity:
                    raise ValueError("Cannot execute block destination port: target port entity is empty.")
                self.store.add_simulated_state(
                    state_type="BLOCKED_PORT",
                    entity_value=str(action.target_entity),
                    action_id=action.action_id,
                    incident_id=action.incident_id,
                )

            elif action.action_type in (ActionType.WATCH_SOURCE, ActionType.FLAG_WATCHLIST):
                if not action.target_entity:
                    raise ValueError("Cannot execute watch source: target IP entity is empty.")
                self.store.add_simulated_state(
                    state_type="WATCHED_SOURCE",
                    entity_value=action.target_entity,
                    action_id=action.action_id,
                    incident_id=action.incident_id,
                )

            elif action.action_type == ActionType.MARK_FOR_INVESTIGATION:
                self.store.add_simulated_state(
                    state_type="INVESTIGATION",
                    entity_value=action.incident_id,
                    action_id=action.action_id,
                    incident_id=action.incident_id,
                )
                # Mark incident as INVESTIGATING if currently NEW
                inc = self.store.get_incident(action.incident_id)
                if inc and inc.status == IncidentStatus.NEW and inc.can_transition_to(IncidentStatus.INVESTIGATING):
                    self.store.update_incident_status(
                        action.incident_id,
                        IncidentStatus.INVESTIGATING,
                        actor=actor,
                        note="Marked for investigation via simulated playbook.",
                    )

            # Transition action status to APPLIED
            action.transition_to(ActionStatus.APPLIED)
            action.executed_at = utc_now_iso()
            action.execution_log = (
                f"Simulated execution succeeded: Action '{action.action_type.value}' applied to '{action.target_entity}'."
            )
            self.store.save_response_action(action)

            # Perform post-execution verification against simulated state
            ver_status, ver_details = self.verify_action(action.action_id, auto_audit=True)
            action.verification_status = ver_status
            action.verification_details = ver_details
            self.store.save_response_action(action)

            # Incident status integration: Only mark CONTAINED if containment action applied and verified
            if action.action_type in CONTAINMENT_ACTION_TYPES and ver_status == "VERIFIED":
                inc = self.store.get_incident(action.incident_id)
                if inc and inc.can_transition_to(IncidentStatus.CONTAINED):
                    self.store.update_incident_status(
                        action.incident_id,
                        IncidentStatus.CONTAINED,
                        actor=actor,
                        note=f"Simulated containment action '{action.action_id}' applied and verified.",
                    )

            self.store.log_audit_event(
                AuditEvent(
                    event_type="ACTION_APPLIED",
                    actor=actor,
                    description=f"Action '{action.action_type.value}' executed in SIMULATED mode. Target: '{action.target_entity}'.",
                    incident_id=action.incident_id,
                    action_id=action.action_id,
                    details={
                        "mode": "SIMULATED",
                        "target_entity": action.target_entity,
                        "verification_status": ver_status,
                    },
                )
            )
            return True, action.execution_log, action

        except Exception as e:
            # Action failed: record failure without claiming containment
            try:
                action.transition_to(ActionStatus.FAILED)
            except Exception:
                action.status = ActionStatus.FAILED
            action.execution_log = f"Simulated execution failed: {str(e)}"
            action.verification_status = "FAILED"
            action.verification_details = f"Execution failed: {str(e)}"
            self.store.save_response_action(action)

            self.store.log_audit_event(
                AuditEvent(
                    event_type="ACTION_FAILED",
                    actor=actor,
                    description=f"Action '{action.action_type.value}' execution failed: {str(e)}",
                    incident_id=action.incident_id,
                    action_id=action.action_id,
                    details={"error": str(e), "mode": "SIMULATED"},
                )
            )
            return False, str(e), action

    def verify_action(
        self,
        action_id: str,
        auto_audit: bool = True,
    ) -> Tuple[str, str]:
        """
        Verifies whether a simulated action achieved its intended effect.
        Distinguishes:
            - 'VERIFIED': verified successfully in isolated simulated state.
            - 'FAILED': verification failed.
            - 'NOT_APPLICABLE': verification unavailable or not applicable.

        Note: Verification strictly checks the simulated database state table.
        It does NOT claim that real network traffic was blocked.
        """
        action = self.store.get_response_action(action_id)
        if not action:
            return "FAILED", f"Response action '{action_id}' not found."

        if action.status != ActionStatus.APPLIED:
            return (
                "FAILED",
                f"Action '{action_id}' is in status '{action.status.value}', not APPLIED; verification cannot succeed.",
            )

        status = "FAILED"
        details = ""

        if action.action_type in (ActionType.SIMULATE_BLOCK_SOURCE, ActionType.SIMULATED_ISOLATION):
            if self.store.is_entity_in_simulated_state("BLOCKED_SOURCE", action.target_entity):
                status = "VERIFIED"
                details = (
                    f"Simulated containment verified: Source IP '{action.target_entity}' is actively present "
                    f"in simulated blocked-source state table. (Simulation only; no real network rules modified.)"
                )
            else:
                status = "FAILED"
                details = f"Simulated verification failed: Source IP '{action.target_entity}' not found in active blocked sources."

        elif action.action_type in (ActionType.SIMULATE_BLOCK_DESTINATION_PORT, ActionType.SIMULATED_BLOCK_PORT):
            if self.store.is_entity_in_simulated_state("BLOCKED_PORT", str(action.target_entity)):
                status = "VERIFIED"
                details = (
                    f"Simulated containment verified: Destination port '{action.target_entity}' is actively present "
                    f"in simulated blocked-port state table. (Simulation only; no real network rules modified.)"
                )
            else:
                status = "FAILED"
                details = f"Simulated verification failed: Destination port '{action.target_entity}' not found in active blocked ports."

        elif action.action_type in (ActionType.WATCH_SOURCE, ActionType.FLAG_WATCHLIST):
            if self.store.is_entity_in_simulated_state("WATCHED_SOURCE", action.target_entity):
                status = "VERIFIED"
                details = (
                    f"Simulated watchlist verified: Source IP '{action.target_entity}' is actively present "
                    f"in simulated surveillance watchlist."
                )
            else:
                status = "FAILED"
                details = f"Simulated verification failed: Source IP '{action.target_entity}' not found in active watchlist."

        elif action.action_type == ActionType.MARK_FOR_INVESTIGATION:
            inc = self.store.get_incident(action.incident_id)
            has_inv_state = self.store.is_entity_in_simulated_state("INVESTIGATION", action.incident_id)
            if (inc and inc.status == IncidentStatus.INVESTIGATING) or has_inv_state:
                status = "VERIFIED"
                details = f"Investigation state verified: Incident '{action.incident_id}' is marked for investigation."
            else:
                status = "FAILED"
                details = f"Investigation verification failed: Incident '{action.incident_id}' not marked investigating."

        else:
            status = "NOT_APPLICABLE"
            details = f"Verification unavailable or not applicable for action type '{action.action_type.value}'."

        if auto_audit:
            self.store.log_audit_event(
                AuditEvent(
                    event_type="ACTION_VERIFIED",
                    actor="SYSTEM",
                    description=f"Action verification outcome: {status}. {details}",
                    incident_id=action.incident_id,
                    action_id=action.action_id,
                    details={"verification_status": status, "verification_details": details},
                )
            )

        return status, details

    # ---------------- Safe Rollback Workflow ----------------
    def rollback_action(
        self,
        action_id: str,
        actor: str = "ANALYST",
        reason: str = "",
    ) -> Tuple[bool, str, ResponseAction]:
        """
        Safely rolls back an APPLIED response action.
        Restores prior simulated state without removing states that predated this action.
        Reverts incident status from CONTAINED to INVESTIGATING if no other active containment exists.
        """
        action = self.store.get_response_action(action_id)
        if not action:
            raise KeyError(f"Response action '{action_id}' not found.")

        if action.status != ActionStatus.APPLIED:
            raise ValueError(
                f"Rollback rejected: Action '{action_id}' has status '{action.status.value}'. "
                f"Only APPLIED actions can be rolled back."
            )

        # Roll back isolated simulated state rows belonging to this action
        reverted_count = self.store.rollback_simulated_state(action_id)

        # Transition action status to ROLLED_BACK
        action.transition_to(ActionStatus.ROLLED_BACK)
        action.rolled_back_at = utc_now_iso()
        action.execution_log = (
            (action.execution_log or "") + f"\n[ROLLBACK] Reverted by {actor}. Reason: {reason} ({reverted_count} simulated rows reverted)."
        ).strip()
        action.verification_status = "ROLLED_BACK"
        action.verification_details = f"Simulated state reverted: {reason}"
        self.store.save_response_action(action)

        # Revert incident status conservatively if applicable
        if action.action_type in CONTAINMENT_ACTION_TYPES:
            has_other_containment = self.store.has_other_active_containment(
                action.incident_id, exclude_action_id=action.action_id
            )
            if not has_other_containment:
                inc = self.store.get_incident(action.incident_id)
                if inc and inc.status == IncidentStatus.CONTAINED and inc.can_transition_to(IncidentStatus.INVESTIGATING):
                    self.store.update_incident_status(
                        action.incident_id,
                        IncidentStatus.INVESTIGATING,
                        actor=actor,
                        note=f"Reverted from Contained to Investigating: Containment action '{action_id}' was rolled back.",
                    )

        self.store.log_audit_event(
            AuditEvent(
                event_type="ACTION_ROLLED_BACK",
                actor=actor,
                description=f"Action '{action.action_type.value}' rolled back. Reason: {reason}".strip(),
                incident_id=action.incident_id,
                action_id=action.action_id,
                details={
                    "actor": actor,
                    "reason": reason,
                    "reverted_simulated_rows": reverted_count,
                    "previous_status": "Applied",
                },
            )
        )

        return True, f"Simulated action '{action_id}' successfully rolled back ({reverted_count} rows reverted).", action

    # ---------------- State Inspection Helpers ----------------
    def get_simulated_blocked_sources(self) -> List[str]:
        """Returns the distinct list of actively blocked source IPs in simulation."""
        rows = self.store.get_active_simulated_state("BLOCKED_SOURCE")
        return sorted(list({r["entity_value"] for r in rows}))

    def get_simulated_blocked_ports(self) -> List[str]:
        """Returns the distinct list of actively blocked destination ports in simulation."""
        rows = self.store.get_active_simulated_state("BLOCKED_PORT")
        return sorted(list({r["entity_value"] for r in rows}))

    def get_simulated_watchlist(self) -> List[str]:
        """Returns the distinct list of watched source IPs in simulation."""
        rows = self.store.get_active_simulated_state("WATCHED_SOURCE")
        return sorted(list({r["entity_value"] for r in rows}))

    def get_simulated_state_summary(self) -> Dict[str, Any]:
        """Returns an aggregated snapshot of the active simulated state."""
        return {
            "blocked_sources": self.get_simulated_blocked_sources(),
            "blocked_ports": self.get_simulated_blocked_ports(),
            "watched_sources": self.get_simulated_watchlist(),
            "total_active_entries": len(self.store.get_active_simulated_state()),
        }
