"""
FlowWatch 2.0 — SQLite Incident & Audit Persistence Layer
Implements ACID-compliant, zero-external-dependency durable storage using
Python's standard library `sqlite3`. Manages schema migration, parameterized
queries, alert deduplication, incident lifecycle tracking, and immutable audit logs.
"""

from contextlib import contextmanager
import json
import os
import sqlite3
import threading
from typing import Any, Dict, List, Optional, Set

from incident_models import (
    Alert,
    AlertSeverity,
    AuditEvent,
    Incident,
    IncidentStatus,
    ResponseAction,
    ActionStatus,
    ActionMode,
    ActionType,
    utc_now_iso,
)


DEFAULT_DB_PATH = "flowwatch.db"


class IncidentStore:
    """
    Thread-safe, transaction-oriented SQLite persistence store for FlowWatch 2.0.
    Supports in-memory mode (':memory:') and disk-based database paths.
    """

    def __init__(self, db_path: str = DEFAULT_DB_PATH):
        self.db_path = db_path
        self._lock = threading.Lock()
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(
            self.db_path,
            timeout=10.0,
            check_same_thread=False,
            isolation_level=None,  # Autocommit mode; transactions managed via BEGIN/COMMIT
        )
        conn.row_factory = sqlite3.Row
        with conn:
            conn.execute("PRAGMA foreign_keys = ON;")
            conn.execute("PRAGMA busy_timeout = 5000;")
            if self.db_path != ":memory:":
                try:
                    conn.execute("PRAGMA journal_mode = WAL;")
                    conn.execute("PRAGMA synchronous = NORMAL;")
                except sqlite3.OperationalError:
                    pass
        return conn

    def _init_db(self):
        """Initializes tables, constraints, and performance indexes."""
        with self._lock, self._get_connection() as conn:
            conn.execute("BEGIN TRANSACTION;")
            try:
                # 1. Alerts Table
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS alerts (
                        alert_id TEXT PRIMARY KEY,
                        timestamp TEXT NOT NULL,
                        source_type TEXT NOT NULL,
                        protocol TEXT NOT NULL,
                        packets INTEGER NOT NULL,
                        bytes INTEGER,
                        duration REAL,
                        src_ip TEXT,
                        dst_ip TEXT,
                        source_port INTEGER,
                        dest_port INTEGER,
                        flagged_by TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        reasons TEXT,
                        flow_id TEXT,
                        ensemble_score REAL,
                        fingerprint TEXT UNIQUE NOT NULL
                    );
                    """
                )
                conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_src_ip ON alerts(src_ip);")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_fingerprint ON alerts(fingerprint);")

                # 2. Incidents Table
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS incidents (
                        incident_id TEXT PRIMARY KEY,
                        title TEXT NOT NULL,
                        correlation_rule TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL,
                        status TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        risk_score INTEGER NOT NULL,
                        risk_factors TEXT NOT NULL,
                        primary_entity TEXT,
                        entity_type TEXT,
                        summary TEXT,
                        assigned_to TEXT
                    );
                    """
                )
                conn.execute("CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity);")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_incidents_created_at ON incidents(created_at);")

                # 3. Incident <-> Alert Association Table
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS incident_alerts (
                        incident_id TEXT NOT NULL,
                        alert_id TEXT NOT NULL,
                        PRIMARY KEY (incident_id, alert_id),
                        FOREIGN KEY (incident_id) REFERENCES incidents(incident_id) ON DELETE CASCADE,
                        FOREIGN KEY (alert_id) REFERENCES alerts(alert_id) ON DELETE CASCADE
                    );
                    """
                )

                # 4. Response Actions Table
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS response_actions (
                        action_id TEXT PRIMARY KEY,
                        incident_id TEXT NOT NULL,
                        action_type TEXT NOT NULL,
                        target_entity TEXT NOT NULL,
                        mode TEXT NOT NULL,
                        status TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        executed_at TEXT,
                        rolled_back_at TEXT,
                        description TEXT,
                        parameters TEXT,
                        execution_log TEXT,
                        approver TEXT,
                        approved_at TEXT,
                        rejection_reason TEXT,
                        verification_status TEXT,
                        verification_details TEXT,
                        FOREIGN KEY (incident_id) REFERENCES incidents(incident_id) ON DELETE CASCADE
                    );
                    """
                )
                conn.execute("CREATE INDEX IF NOT EXISTS idx_actions_incident ON response_actions(incident_id);")

                # Schema migration check for response_actions table if pre-existing
                existing_action_cols = {row["name"] for row in conn.execute("PRAGMA table_info(response_actions);").fetchall()}
                for col_name in ("approver", "approved_at", "rejection_reason", "verification_status", "verification_details"):
                    if col_name not in existing_action_cols:
                        conn.execute(f"ALTER TABLE response_actions ADD COLUMN {col_name} TEXT;")

                # 5. Simulated Containment State Table
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS simulated_containment_state (
                        state_id INTEGER PRIMARY KEY AUTOINCREMENT,
                        state_type TEXT NOT NULL,
                        entity_value TEXT NOT NULL,
                        action_id TEXT NOT NULL,
                        incident_id TEXT,
                        created_at TEXT NOT NULL,
                        status TEXT NOT NULL DEFAULT 'ACTIVE',
                        was_prior_state INTEGER NOT NULL DEFAULT 0
                    );
                    """
                )
                conn.execute("CREATE INDEX IF NOT EXISTS idx_sim_state_type_val ON simulated_containment_state(state_type, entity_value, status);")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_sim_state_action ON simulated_containment_state(action_id);")

                # 6. Immutable Audit Events Table
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS audit_events (
                        event_id TEXT PRIMARY KEY,
                        timestamp TEXT NOT NULL,
                        event_type TEXT NOT NULL,
                        actor TEXT NOT NULL,
                        description TEXT NOT NULL,
                        incident_id TEXT,
                        action_id TEXT,
                        details TEXT
                    );
                    """
                )
                conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_events(timestamp);")
                conn.execute("COMMIT;")
            except Exception:
                conn.execute("ROLLBACK;")
                raise

    # ---------------- Alert Operations ----------------
    def save_alert(self, alert: Alert) -> str:
        """
        Persists an alert. If an alert with the same deterministic fingerprint
        already exists, returns the existing alert's ID without creating a duplicate.
        """
        with self._lock, self._get_connection() as conn:
            cursor = conn.cursor()
            # Check for existing duplicate by fingerprint
            cursor.execute("SELECT alert_id FROM alerts WHERE fingerprint = ?;", (alert.fingerprint,))
            row = cursor.fetchone()
            if row:
                return row["alert_id"]

            conn.execute("BEGIN TRANSACTION;")
            try:
                cursor.execute(
                    """
                    INSERT INTO alerts (
                        alert_id, timestamp, source_type, protocol, packets, bytes,
                        duration, src_ip, dst_ip, source_port, dest_port,
                        flagged_by, severity, reasons, flow_id, ensemble_score, fingerprint
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    (
                        alert.alert_id,
                        alert.timestamp,
                        alert.source_type,
                        alert.protocol,
                        alert.packets,
                        alert.bytes,
                        alert.duration,
                        alert.src_ip,
                        alert.dst_ip,
                        alert.source_port,
                        alert.dest_port,
                        alert.flagged_by,
                        alert.severity.value,
                        alert.reasons,
                        alert.flow_id,
                        alert.ensemble_score,
                        alert.fingerprint,
                    ),
                )
                conn.execute("COMMIT;")
                return alert.alert_id
            except Exception:
                conn.execute("ROLLBACK;")
                raise

    def get_alert(self, alert_id: str) -> Optional[Alert]:
        """Retrieves a single alert by ID."""
        with self._lock, self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM alerts WHERE alert_id = ?;", (alert_id,))
            row = cursor.fetchone()
            if not row:
                return None
            return self._row_to_alert(row)

    def get_associated_alert_ids(self, alert_ids: List[str]) -> Set[str]:
        """Returns the subset of alert_ids that are already linked to an incident in incident_alerts."""
        if not alert_ids:
            return set()
        with self._lock, self._get_connection() as conn:
            cursor = conn.cursor()
            associated = set()
            chunk_size = 500
            for i in range(0, len(alert_ids), chunk_size):
                chunk = alert_ids[i:i + chunk_size]
                placeholders = ",".join("?" for _ in chunk)
                cursor.execute(
                    f"SELECT DISTINCT alert_id FROM incident_alerts WHERE alert_id IN ({placeholders});",
                    tuple(chunk),
                )
                for r in cursor.fetchall():
                    associated.add(r["alert_id"])
            return associated

    def _row_to_alert(self, row: sqlite3.Row) -> Alert:
        return Alert(
            alert_id=row["alert_id"],
            timestamp=row["timestamp"],
            source_type=row["source_type"],
            protocol=row["protocol"],
            packets=row["packets"],
            bytes=row["bytes"],
            duration=row["duration"],
            src_ip=row["src_ip"],
            dst_ip=row["dst_ip"],
            source_port=row["source_port"],
            dest_port=row["dest_port"],
            flagged_by=row["flagged_by"],
            severity=AlertSeverity.from_string(row["severity"]),
            reasons=row["reasons"] or "",
            flow_id=row["flow_id"],
            ensemble_score=row["ensemble_score"],
            fingerprint=row["fingerprint"],
        )

    # ---------------- Incident Operations ----------------
    def save_incident(self, incident: Incident) -> str:
        """Saves or updates an incident and its linked alerts atomically."""
        with self._lock, self._get_connection() as conn:
            conn.execute("BEGIN TRANSACTION;")
            try:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT INTO incidents (
                        incident_id, title, correlation_rule, created_at, updated_at,
                        status, severity, risk_score, risk_factors, primary_entity,
                        entity_type, summary, assigned_to
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(incident_id) DO UPDATE SET
                        title = excluded.title,
                        correlation_rule = excluded.correlation_rule,
                        updated_at = excluded.updated_at,
                        status = excluded.status,
                        severity = excluded.severity,
                        risk_score = excluded.risk_score,
                        risk_factors = excluded.risk_factors,
                        primary_entity = excluded.primary_entity,
                        entity_type = excluded.entity_type,
                        summary = excluded.summary,
                        assigned_to = excluded.assigned_to;
                    """,
                    (
                        incident.incident_id,
                        incident.title,
                        incident.correlation_rule,
                        incident.created_at,
                        incident.updated_at,
                        incident.status.value,
                        incident.severity.value,
                        incident.risk_score,
                        json.dumps(incident.risk_factors),
                        incident.primary_entity,
                        incident.entity_type,
                        incident.summary,
                        incident.assigned_to,
                    ),
                )

                # Link associated alerts
                for aid in incident.alert_ids:
                    cursor.execute(
                        """
                        INSERT OR IGNORE INTO incident_alerts (incident_id, alert_id)
                        VALUES (?, ?);
                        """,
                        (incident.incident_id, aid),
                    )

                conn.execute("COMMIT;")
                return incident.incident_id
            except Exception:
                conn.execute("ROLLBACK;")
                raise

    def get_incident(self, incident_id: str) -> Optional[Incident]:
        """Loads an incident by ID along with its associated alert IDs."""
        with self._lock, self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM incidents WHERE incident_id = ?;", (incident_id,))
            row = cursor.fetchone()
            if not row:
                return None

            cursor.execute("SELECT alert_id FROM incident_alerts WHERE incident_id = ?;", (incident_id,))
            alert_ids = [r["alert_id"] for r in cursor.fetchall()]

            return Incident(
                incident_id=row["incident_id"],
                title=row["title"],
                correlation_rule=row["correlation_rule"],
                created_at=row["created_at"],
                updated_at=row["updated_at"],
                status=IncidentStatus.from_string(row["status"]),
                severity=AlertSeverity.from_string(row["severity"]),
                risk_score=row["risk_score"],
                risk_factors=json.loads(row["risk_factors"]) if row["risk_factors"] else [],
                alert_ids=alert_ids,
                primary_entity=row["primary_entity"],
                entity_type=row["entity_type"],
                summary=row["summary"],
                assigned_to=row["assigned_to"],
            )

    def list_incidents(
        self,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> List[Incident]:
        """Queries incidents with optional status and severity filtering."""
        with self._lock, self._get_connection() as conn:
            cursor = conn.cursor()
            clauses, params = [], []
            if status:
                clauses.append("status = ?")
                params.append(IncidentStatus.from_string(status).value)
            if severity:
                clauses.append("severity = ?")
                params.append(AlertSeverity.from_string(severity).value)

            where_str = f"WHERE {' AND '.join(clauses)}" if clauses else ""
            query = f"""
                SELECT * FROM incidents
                {where_str}
                ORDER BY risk_score DESC, created_at DESC
                LIMIT ? OFFSET ?;
            """
            params.extend([max(1, limit), max(0, offset)])
            cursor.execute(query, tuple(params))
            rows = cursor.fetchall()

            incidents = []
            for row in rows:
                iid = row["incident_id"]
                c2 = conn.cursor()
                c2.execute("SELECT alert_id FROM incident_alerts WHERE incident_id = ?;", (iid,))
                a_ids = [r["alert_id"] for r in c2.fetchall()]

                incidents.append(
                    Incident(
                        incident_id=iid,
                        title=row["title"],
                        correlation_rule=row["correlation_rule"],
                        created_at=row["created_at"],
                        updated_at=row["updated_at"],
                        status=IncidentStatus.from_string(row["status"]),
                        severity=AlertSeverity.from_string(row["severity"]),
                        risk_score=row["risk_score"],
                        risk_factors=json.loads(row["risk_factors"]) if row["risk_factors"] else [],
                        alert_ids=a_ids,
                        primary_entity=row["primary_entity"],
                        entity_type=row["entity_type"],
                        summary=row["summary"],
                        assigned_to=row["assigned_to"],
                    )
                )
            return incidents

    def update_incident_status(
        self,
        incident_id: str,
        new_status: IncidentStatus,
        actor: str = "SYSTEM",
        note: str = "",
    ) -> Incident:
        """
        Transitions an incident status verifying valid lifecycle states.
        Automatically emits an immutable AuditEvent record.
        """
        incident = self.get_incident(incident_id)
        if not incident:
            raise KeyError(f"Incident with ID '{incident_id}' not found.")

        old_status = incident.status
        incident.transition_to(new_status)
        self.save_incident(incident)

        # Log audit trail
        self.log_audit_event(
            AuditEvent(
                event_type="INCIDENT_STATUS_CHANGED",
                actor=actor,
                description=f"Status changed from '{old_status.value}' to '{new_status.value}'. {note}".strip(),
                incident_id=incident_id,
                details={"old_status": old_status.value, "new_status": new_status.value, "note": note},
            )
        )
        return incident

    def get_alerts_for_incident(self, incident_id: str) -> List[Alert]:
        """Fetches all underlying Alert objects associated with an incident."""
        with self._lock, self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT a.* FROM alerts a
                INNER JOIN incident_alerts ia ON a.alert_id = ia.alert_id
                WHERE ia.incident_id = ?
                ORDER BY a.timestamp ASC;
                """,
                (incident_id,),
            )
            return [self._row_to_alert(r) for r in cursor.fetchall()]

    # ---------------- Response Action Operations ----------------
    def _row_to_response_action(self, r: sqlite3.Row) -> ResponseAction:
        keys = r.keys()
        return ResponseAction(
            action_id=r["action_id"],
            incident_id=r["incident_id"],
            action_type=ActionType(r["action_type"]),
            target_entity=r["target_entity"],
            mode=ActionMode(r["mode"]),
            status=ActionStatus(r["status"]),
            created_at=r["created_at"],
            executed_at=r["executed_at"],
            rolled_back_at=r["rolled_back_at"],
            description=r["description"] or "",
            parameters=json.loads(r["parameters"]) if r["parameters"] else {},
            execution_log=r["execution_log"] or "",
            approver=r["approver"] if "approver" in keys else None,
            approved_at=r["approved_at"] if "approved_at" in keys else None,
            rejection_reason=r["rejection_reason"] if "rejection_reason" in keys else None,
            verification_status=r["verification_status"] if "verification_status" in keys else None,
            verification_details=r["verification_details"] if "verification_details" in keys else None,
        )

    def save_response_action(self, action: ResponseAction) -> str:
        """Persists a response action atomically."""
        with self._lock, self._get_connection() as conn:
            conn.execute("BEGIN TRANSACTION;")
            try:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT INTO response_actions (
                        action_id, incident_id, action_type, target_entity, mode,
                        status, created_at, executed_at, rolled_back_at, description,
                        parameters, execution_log, approver, approved_at, rejection_reason,
                        verification_status, verification_details
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(action_id) DO UPDATE SET
                        target_entity = excluded.target_entity,
                        status = excluded.status,
                        executed_at = excluded.executed_at,
                        rolled_back_at = excluded.rolled_back_at,
                        description = excluded.description,
                        parameters = excluded.parameters,
                        execution_log = excluded.execution_log,
                        approver = excluded.approver,
                        approved_at = excluded.approved_at,
                        rejection_reason = excluded.rejection_reason,
                        verification_status = excluded.verification_status,
                        verification_details = excluded.verification_details;
                    """,
                    (
                        action.action_id,
                        action.incident_id,
                        action.action_type.value,
                        action.target_entity,
                        action.mode.value,
                        action.status.value,
                        action.created_at,
                        action.executed_at,
                        action.rolled_back_at,
                        action.description,
                        json.dumps(action.parameters),
                        action.execution_log,
                        action.approver,
                        action.approved_at,
                        action.rejection_reason,
                        action.verification_status,
                        action.verification_details,
                    ),
                )
                conn.execute("COMMIT;")
                return action.action_id
            except Exception:
                conn.execute("ROLLBACK;")
                raise

    def get_response_action(self, action_id: str) -> Optional[ResponseAction]:
        """Loads a single response action by action_id."""
        with self._lock, self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM response_actions WHERE action_id = ?;", (action_id,))
            row = cursor.fetchone()
            if not row:
                return None
            return self._row_to_response_action(row)

    def get_response_actions(self, incident_id: Optional[str] = None) -> List[ResponseAction]:
        """Fetches response actions, optionally filtered by incident."""
        with self._lock, self._get_connection() as conn:
            cursor = conn.cursor()
            if incident_id:
                cursor.execute(
                    "SELECT * FROM response_actions WHERE incident_id = ? ORDER BY created_at DESC;",
                    (incident_id,),
                )
            else:
                cursor.execute("SELECT * FROM response_actions ORDER BY created_at DESC;")

            return [self._row_to_response_action(r) for r in cursor.fetchall()]

    # ---------------- Simulated State Operations ----------------
    def add_simulated_state(
        self,
        state_type: str,
        entity_value: str,
        action_id: str,
        incident_id: Optional[str] = None,
    ) -> int:
        """
        Records an active simulated state entry.
        Tracks if the entity was already active prior to this action,
        ensuring rollback only reverts what this action changed.
        """
        with self._lock, self._get_connection() as conn:
            conn.execute("BEGIN TRANSACTION;")
            try:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    SELECT COUNT(*) FROM simulated_containment_state
                    WHERE state_type = ? AND entity_value = ? AND status = 'ACTIVE';
                    """,
                    (state_type, str(entity_value)),
                )
                prior_count = cursor.fetchone()[0]
                was_prior = 1 if prior_count > 0 else 0

                cursor.execute(
                    """
                    INSERT INTO simulated_containment_state (
                        state_type, entity_value, action_id, incident_id, created_at, status, was_prior_state
                    ) VALUES (?, ?, ?, ?, ?, 'ACTIVE', ?);
                    """,
                    (
                        state_type,
                        str(entity_value),
                        action_id,
                        incident_id,
                        utc_now_iso(),
                        was_prior,
                    ),
                )
                state_id = cursor.lastrowid
                conn.execute("COMMIT;")
                return state_id
            except Exception:
                conn.execute("ROLLBACK;")
                raise

    def rollback_simulated_state(self, action_id: str) -> int:
        """
        Marks all active simulated state entries created by action_id as ROLLED_BACK.
        Pre-existing/prior states created by other actions remain ACTIVE.
        Returns the number of affected rows.
        """
        with self._lock, self._get_connection() as conn:
            conn.execute("BEGIN TRANSACTION;")
            try:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    UPDATE simulated_containment_state
                    SET status = 'ROLLED_BACK'
                    WHERE action_id = ? AND status = 'ACTIVE';
                    """,
                    (action_id,),
                )
                affected = cursor.rowcount
                conn.execute("COMMIT;")
                return affected
            except Exception:
                conn.execute("ROLLBACK;")
                raise

    def is_entity_in_simulated_state(self, state_type: str, entity_value: str) -> bool:
        """Checks if an entity currently has an ACTIVE simulated state."""
        with self._lock, self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT COUNT(*) FROM simulated_containment_state
                WHERE state_type = ? AND entity_value = ? AND status = 'ACTIVE';
                """,
                (state_type, str(entity_value)),
            )
            return cursor.fetchone()[0] > 0

    def get_active_simulated_state(self, state_type: Optional[str] = None) -> List[Dict[str, Any]]:
        """Returns all currently ACTIVE simulated state entries, optionally filtered by state_type."""
        with self._lock, self._get_connection() as conn:
            cursor = conn.cursor()
            if state_type:
                cursor.execute(
                    """
                    SELECT * FROM simulated_containment_state
                    WHERE state_type = ? AND status = 'ACTIVE'
                    ORDER BY created_at DESC;
                    """,
                    (state_type,),
                )
            else:
                cursor.execute(
                    """
                    SELECT * FROM simulated_containment_state
                    WHERE status = 'ACTIVE'
                    ORDER BY created_at DESC;
                    """
                )
            rows = cursor.fetchall()
            return [dict(r) for r in rows]

    def get_simulated_state_history(self, entity_value: Optional[str] = None) -> List[Dict[str, Any]]:
        """Returns historical simulated state entries (active and rolled back)."""
        with self._lock, self._get_connection() as conn:
            cursor = conn.cursor()
            if entity_value:
                cursor.execute(
                    """
                    SELECT * FROM simulated_containment_state
                    WHERE entity_value = ?
                    ORDER BY created_at DESC;
                    """,
                    (str(entity_value),),
                )
            else:
                cursor.execute(
                    """
                    SELECT * FROM simulated_containment_state
                    ORDER BY created_at DESC;
                    """
                )
            rows = cursor.fetchall()
            return [dict(r) for r in rows]

    def has_other_active_containment(self, incident_id: str, exclude_action_id: Optional[str] = None) -> bool:
        """
        Checks if an incident has any other APPLIED containment actions.
        """
        containment_types = (
            ActionType.SIMULATE_BLOCK_SOURCE.value,
            ActionType.SIMULATE_BLOCK_DESTINATION_PORT.value,
            ActionType.SIMULATED_ISOLATION.value,
            ActionType.SIMULATED_BLOCK_PORT.value,
        )
        with self._lock, self._get_connection() as conn:
            cursor = conn.cursor()
            placeholders = ",".join("?" for _ in containment_types)
            query = f"""
                SELECT COUNT(*) FROM response_actions
                WHERE incident_id = ?
                  AND status = '{ActionStatus.APPLIED.value}'
                  AND action_type IN ({placeholders})
            """
            params = [incident_id] + list(containment_types)
            if exclude_action_id:
                query += " AND action_id != ?"
                params.append(exclude_action_id)
            cursor.execute(query, tuple(params))
            return cursor.fetchone()[0] > 0

    # ---------------- Audit Operations ----------------
    def log_audit_event(self, event: AuditEvent) -> str:
        """Appends an immutable audit record."""
        with self._lock, self._get_connection() as conn:
            conn.execute("BEGIN TRANSACTION;")
            try:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT INTO audit_events (
                        event_id, timestamp, event_type, actor, description,
                        incident_id, action_id, details
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    (
                        event.event_id,
                        event.timestamp,
                        event.event_type,
                        event.actor,
                        event.description,
                        event.incident_id,
                        event.action_id,
                        json.dumps(event.details),
                    ),
                )
                conn.execute("COMMIT;")
                return event.event_id
            except Exception:
                conn.execute("ROLLBACK;")
                raise

    def get_audit_events(self, incident_id: Optional[str] = None, limit: int = 100) -> List[AuditEvent]:
        """Queries historical audit records in descending chronological order."""
        with self._lock, self._get_connection() as conn:
            cursor = conn.cursor()
            if incident_id:
                cursor.execute(
                    "SELECT * FROM audit_events WHERE incident_id = ? ORDER BY timestamp DESC LIMIT ?;",
                    (incident_id, max(1, limit)),
                )
            else:
                cursor.execute(
                    "SELECT * FROM audit_events ORDER BY timestamp DESC LIMIT ?;",
                    (max(1, limit),),
                )

            events = []
            for r in cursor.fetchall():
                events.append(
                    AuditEvent(
                        event_id=r["event_id"],
                        timestamp=r["timestamp"],
                        event_type=r["event_type"],
                        actor=r["actor"],
                        description=r["description"],
                        incident_id=r["incident_id"],
                        action_id=r["action_id"],
                        details=json.loads(r["details"]) if r["details"] else {},
                    )
                )
            return events

    def close(self):
        """Clean close hook."""
        pass
