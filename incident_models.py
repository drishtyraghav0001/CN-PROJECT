"""
FlowWatch 2.0 — Incident Management Data Models & Contracts
Defines typed dataclasses, enumerations, lifecycle states, and validation logic
for alerts, incidents, response actions, and audit events.
Completely independent of Streamlit and UI code.
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
from typing import Any, Dict, List, Optional, Set
import uuid


class AlertSeverity(str, Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"

    @classmethod
    def from_string(cls, val: str) -> "AlertSeverity":
        normalized = str(val).strip().capitalize()
        for member in cls:
            if member.value == normalized:
                return member
        return cls.LOW


class IncidentStatus(str, Enum):
    NEW = "New"
    INVESTIGATING = "Investigating"
    CONTAINED = "Contained"
    RESOLVED = "Resolved"
    CLOSED = "Closed"

    @classmethod
    def from_string(cls, val: str) -> "IncidentStatus":
        normalized = str(val).strip().capitalize()
        for member in cls:
            if member.value == normalized:
                return member
        return cls.NEW


class ActionType(str, Enum):
    # Phase 2 Safe Simulated Playbook Action Types
    WATCH_SOURCE = "WATCH_SOURCE"                                      # Add source IP to simulated watchlist
    SIMULATE_BLOCK_SOURCE = "SIMULATE_BLOCK_SOURCE"                    # Mark source IP as blocked in simulated state
    SIMULATE_BLOCK_DESTINATION_PORT = "SIMULATE_BLOCK_DESTINATION_PORT"# Mark dest port as blocked in simulated state
    MARK_FOR_INVESTIGATION = "MARK_FOR_INVESTIGATION"                  # Mark incident for investigation without containment
    # Backward-compatible actions
    SIMULATED_ISOLATION = "SIMULATED_ISOLATION"                        # Isolate source host (alias for block source)
    SIMULATED_BLOCK_PORT = "SIMULATED_BLOCK_PORT"                      # Block destination port
    SIMULATED_RATE_LIMIT = "SIMULATED_RATE_LIMIT"                      # Throttle anomalous flow
    FLAG_WATCHLIST = "FLAG_WATCHLIST"                                  # Add entity to monitor watchlist
    NOTIFY_OPERATOR = "NOTIFY_OPERATOR"                                # Emit alert notification


class ActionStatus(str, Enum):
    PENDING = "Pending"
    APPROVED = "Approved"
    REJECTED = "Rejected"
    APPLIED = "Applied"
    FAILED = "Failed"
    ROLLED_BACK = "Rolled Back"


# Explicit valid lifecycle transitions for ResponseAction status
VALID_ACTION_TRANSITIONS: Dict[ActionStatus, Set[ActionStatus]] = {
    ActionStatus.PENDING: {ActionStatus.APPROVED, ActionStatus.REJECTED},
    ActionStatus.APPROVED: {ActionStatus.APPLIED, ActionStatus.FAILED},
    ActionStatus.APPLIED: {ActionStatus.ROLLED_BACK},
    ActionStatus.REJECTED: set(),
    ActionStatus.FAILED: set(),
    ActionStatus.ROLLED_BACK: set(),
}


class ActionMode(str, Enum):
    SIMULATED = "SIMULATED"
    LIVE = "LIVE"


class CorrelationRule(str, Enum):
    RULE_SRC_HOST = "RULE_SRC_HOST"                    # Repeated alerts from same source IP
    RULE_PORT_SWEEP = "RULE_PORT_SWEEP"                # Single source targeting >= 3 distinct ports
    RULE_SERVICE_SURGE = "RULE_SERVICE_SURGE"          # >= 3 distinct sources targeting same port/proto
    RULE_MULTI_DETECTOR = "RULE_MULTI_DETECTOR"        # Corroborated by Statistical + ML + Ensemble
    RULE_VOLUMETRIC_BURST = "RULE_VOLUMETRIC_BURST"    # High-volume burst signature (IP-less fallback)
    RULE_SINGLETON = "RULE_SINGLETON"                  # Standalone un-correlated anomaly alert


# Explicit valid lifecycle transitions for Incident status
VALID_INCIDENT_TRANSITIONS: Dict[IncidentStatus, Set[IncidentStatus]] = {
    IncidentStatus.NEW: {
        IncidentStatus.INVESTIGATING,
        IncidentStatus.CONTAINED,
        IncidentStatus.CLOSED,
    },
    IncidentStatus.INVESTIGATING: {
        IncidentStatus.CONTAINED,
        IncidentStatus.RESOLVED,
        IncidentStatus.CLOSED,
    },
    IncidentStatus.CONTAINED: {
        IncidentStatus.RESOLVED,
        IncidentStatus.INVESTIGATING,
        IncidentStatus.CLOSED,
    },
    IncidentStatus.RESOLVED: {
        IncidentStatus.CLOSED,
        IncidentStatus.INVESTIGATING,
    },
    IncidentStatus.CLOSED: {
        IncidentStatus.INVESTIGATING,  # Re-opening an incident on new evidence
    },
}


def utc_now_iso() -> str:
    """Returns current UTC timestamp in strict ISO 8601 format."""
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Alert:
    """
    Standardized, normalized FlowWatch alert entity.
    Accommodates both minimal 2-column synthetic sources and rich 5-tuple live captures.
    """
    alert_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(default_factory=utc_now_iso)
    source_type: str = "file"                          # "live", "pcap", "csv", "json"
    protocol: str = "TCP"
    packets: int = 0
    flagged_by: str = "Statistical"                    # "Statistical", "ML", "Both"
    severity: AlertSeverity = AlertSeverity.LOW
    reasons: str = ""

    # Optional networking & flow attributes (source-dependent)
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    source_port: Optional[int] = None
    dest_port: Optional[int] = None
    bytes: Optional[int] = None
    duration: Optional[float] = None
    flow_id: Optional[str] = None
    ensemble_score: Optional[float] = None
    fingerprint: Optional[str] = None

    def __post_init__(self):
        if not isinstance(self.severity, AlertSeverity):
            self.severity = AlertSeverity.from_string(str(self.severity))
        self.protocol = str(self.protocol).strip().upper() or "TCP"
        try:
            self.packets = max(0, int(self.packets))
        except (ValueError, TypeError):
            self.packets = 0

        if self.source_port is not None:
            try:
                self.source_port = int(self.source_port)
            except (ValueError, TypeError):
                self.source_port = None

        if self.dest_port is not None:
            try:
                self.dest_port = int(self.dest_port)
            except (ValueError, TypeError):
                self.dest_port = None

        if self.bytes is not None:
            try:
                self.bytes = max(0, int(self.bytes))
            except (ValueError, TypeError):
                self.bytes = None

        if self.duration is not None:
            try:
                self.duration = max(0.0, float(self.duration))
            except (ValueError, TypeError):
                self.duration = None

        if self.ensemble_score is not None:
            try:
                self.ensemble_score = float(self.ensemble_score)
            except (ValueError, TypeError):
                self.ensemble_score = None

        if not self.fingerprint:
            self.fingerprint = self.compute_fingerprint()

    def compute_fingerprint(self) -> str:
        """Computes a deterministic hash fingerprint for alert deduplication."""
        components = [
            self.source_type,
            self.protocol,
            str(self.packets),
            str(self.bytes or ""),
            str(self.src_ip or ""),
            str(self.dst_ip or ""),
            str(self.source_port or ""),
            str(self.dest_port or ""),
            self.flagged_by,
            self.reasons,
        ]
        raw_key = "|".join(components)
        return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Alert":
        clean = dict(data)
        if "severity" in clean and clean["severity"]:
            clean["severity"] = AlertSeverity.from_string(clean["severity"])
        return cls(**clean)


@dataclass
class Incident:
    """
    Correlated network security incident grouping related alerts.
    """
    incident_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    title: str = ""
    correlation_rule: str = CorrelationRule.RULE_SINGLETON.value
    created_at: str = field(default_factory=utc_now_iso)
    updated_at: str = field(default_factory=utc_now_iso)
    status: IncidentStatus = IncidentStatus.NEW
    severity: AlertSeverity = AlertSeverity.LOW
    risk_score: int = 0                                # 0-100 deterministic heuristic index
    risk_factors: List[str] = field(default_factory=list)
    alert_ids: List[str] = field(default_factory=list)

    # Entity context
    primary_entity: Optional[str] = None               # e.g., "192.168.1.50" or "TCP/80"
    entity_type: Optional[str] = None                  # "src_ip", "dst_ip", "dest_port", "protocol"
    summary: Optional[str] = None
    assigned_to: Optional[str] = None

    def __post_init__(self):
        if not isinstance(self.status, IncidentStatus):
            self.status = IncidentStatus.from_string(str(self.status))
        if not isinstance(self.severity, AlertSeverity):
            self.severity = AlertSeverity.from_string(str(self.severity))
        try:
            self.risk_score = max(0, min(100, int(self.risk_score)))
        except (ValueError, TypeError):
            self.risk_score = 0
        if not self.title:
            self.title = f"Security Incident [{self.correlation_rule}] - {self.primary_entity or 'Network'}"

    def can_transition_to(self, new_status: IncidentStatus) -> bool:
        """Validates if transitioning to new_status is permitted by the lifecycle state machine."""
        if not isinstance(new_status, IncidentStatus):
            new_status = IncidentStatus.from_string(str(new_status))
        if self.status == new_status:
            return True
        allowed = VALID_INCIDENT_TRANSITIONS.get(self.status, set())
        return new_status in allowed

    def transition_to(self, new_status: IncidentStatus) -> None:
        """
        Transitions the incident to a new lifecycle state.
        Raises ValueError if transition is invalid.
        """
        if not isinstance(new_status, IncidentStatus):
            new_status = IncidentStatus.from_string(str(new_status))
        if not self.can_transition_to(new_status):
            raise ValueError(
                f"Invalid lifecycle transition: Cannot move incident from '{self.status.value}' to '{new_status.value}'. "
                f"Allowed target states: {[s.value for s in VALID_INCIDENT_TRANSITIONS.get(self.status, set())]}"
            )
        self.status = new_status
        self.updated_at = utc_now_iso()

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value
        d["severity"] = self.severity.value
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Incident":
        clean = dict(data)
        if "status" in clean and clean["status"]:
            clean["status"] = IncidentStatus.from_string(clean["status"])
        if "severity" in clean and clean["severity"]:
            clean["severity"] = AlertSeverity.from_string(clean["severity"])
        if "risk_factors" in clean and isinstance(clean["risk_factors"], str):
            try:
                clean["risk_factors"] = json.loads(clean["risk_factors"])
            except Exception:
                clean["risk_factors"] = [clean["risk_factors"]]
        if "alert_ids" in clean and isinstance(clean["alert_ids"], str):
            try:
                clean["alert_ids"] = json.loads(clean["alert_ids"])
            except Exception:
                clean["alert_ids"] = [clean["alert_ids"]]
        return cls(**clean)


@dataclass
class ResponseAction:
    """
    Containment or mitigation action tied to an incident.
    Defaults to SIMULATED mode.
    """
    action_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    incident_id: str = ""
    action_type: ActionType = ActionType.SIMULATED_ISOLATION
    target_entity: str = ""                            # e.g., "192.168.1.50"
    mode: ActionMode = ActionMode.SIMULATED
    status: ActionStatus = ActionStatus.PENDING
    created_at: str = field(default_factory=utc_now_iso)
    executed_at: Optional[str] = None
    rolled_back_at: Optional[str] = None
    description: str = ""
    parameters: Dict[str, Any] = field(default_factory=dict)
    execution_log: str = ""
    approver: Optional[str] = None
    approved_at: Optional[str] = None
    rejection_reason: Optional[str] = None
    verification_status: Optional[str] = None
    verification_details: Optional[str] = None

    def __post_init__(self):
        if not isinstance(self.action_type, ActionType):
            self.action_type = ActionType(str(self.action_type))
        if not isinstance(self.mode, ActionMode):
            self.mode = ActionMode(str(self.mode))
        if not isinstance(self.status, ActionStatus):
            self.status = ActionStatus(str(self.status))

    def can_transition_to(self, new_status: ActionStatus) -> bool:
        """Validates if transitioning to new_status is permitted by the action lifecycle state machine."""
        if not isinstance(new_status, ActionStatus):
            new_status = ActionStatus(str(new_status))
        if self.status == new_status:
            return True
        allowed = VALID_ACTION_TRANSITIONS.get(self.status, set())
        return new_status in allowed

    def transition_to(self, new_status: ActionStatus) -> None:
        """
        Transitions the action to a new lifecycle state.
        Raises ValueError if transition is invalid.
        """
        if not isinstance(new_status, ActionStatus):
            new_status = ActionStatus(str(new_status))
        if not self.can_transition_to(new_status):
            raise ValueError(
                f"Invalid action lifecycle transition: Cannot move action from '{self.status.value}' to '{new_status.value}'. "
                f"Allowed target states: {[s.value for s in VALID_ACTION_TRANSITIONS.get(self.status, set())]}"
            )
        self.status = new_status

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["action_type"] = self.action_type.value
        d["mode"] = self.mode.value
        d["status"] = self.status.value
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ResponseAction":
        clean = dict(data)
        if "action_type" in clean:
            clean["action_type"] = ActionType(clean["action_type"])
        if "mode" in clean:
            clean["mode"] = ActionMode(clean["mode"])
        if "status" in clean:
            clean["status"] = ActionStatus(clean["status"])
        if "parameters" in clean and isinstance(clean["parameters"], str):
            try:
                clean["parameters"] = json.loads(clean["parameters"])
            except Exception:
                clean["parameters"] = {}
        return cls(**clean)


@dataclass
class AuditEvent:
    """
    Immutable audit record tracking operational and triage events.
    """
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(default_factory=utc_now_iso)
    event_type: str = "INCIDENT_CREATED"
    actor: str = "SYSTEM"                              # "SYSTEM" or "ANALYST"
    description: str = ""
    incident_id: Optional[str] = None
    action_id: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AuditEvent":
        clean = dict(data)
        if "details" in clean and isinstance(clean["details"], str):
            try:
                clean["details"] = json.loads(clean["details"])
            except Exception:
                clean["details"] = {}
        return cls(**clean)
