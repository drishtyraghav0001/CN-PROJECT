"""
FlowWatch 2.0 — Incident Correlation Engine & Transparent Risk Scorer
Implements deterministic, rule-based correlation of security alerts into
actionable incidents with itemized, non-probabilistic heuristic risk scoring.
"""

from collections import defaultdict
import datetime
from typing import Any, Dict, List, Optional, Set, Tuple
import uuid

import numpy as np
import pandas as pd

from incident_models import (
    Alert,
    AlertSeverity,
    AuditEvent,
    CorrelationRule,
    Incident,
    IncidentStatus,
    utc_now_iso,
)


def extract_alerts_from_dataframe(df: pd.DataFrame, source_type: str = "file") -> List[Alert]:
    """
    Safely inspects a FlowWatch DataFrame after detection and extracts
    standardized Alert objects for all flagged records.
    Never invents source IPs or fake timestamps.
    """
    if df.empty:
        return []

    # Identify flagged rows: check Flag Status, Flagged By, Statistical Result, ML Result
    is_flagged = pd.Series(False, index=df.index)
    if "Flag Status" in df.columns:
        is_flagged = is_flagged | (df["Flag Status"] != "Normal")
    elif "Flagged By" in df.columns:
        is_flagged = is_flagged | (df["Flagged By"].isin(["Statistical", "ML", "Both"]))
    
    if "Statistical Result" in df.columns:
        is_flagged = is_flagged | (df["Statistical Result"] == "Potential Anomaly")
    if "ML Result" in df.columns:
        is_flagged = is_flagged | (df["ML Result"] == "Potential Anomaly")
    if "Ensemble Result" in df.columns:
        is_flagged = is_flagged | (df["Ensemble Result"] == "Potential Anomaly")

    flagged_df = df[is_flagged]
    alerts = []

    now_iso = utc_now_iso()

    for idx, row in flagged_df.iterrows():
        # Core mandatory fields
        protocol = str(row.get("protocol", "TCP")).strip().upper() or "TCP"
        packets = row.get("packets", 0)
        flagged_by = str(row.get("Flagged By", row.get("flagged_by", "Statistical")))
        severity_str = str(row.get("Severity", row.get("severity", "Low")))
        reasons = str(row.get("Reasons", row.get("reasons", "")))

        # Optional networking fields
        src_ip = str(row["src_ip"]).strip() if "src_ip" in row and pd.notna(row["src_ip"]) and str(row["src_ip"]).strip() else None
        dst_ip = str(row["dst_ip"]).strip() if "dst_ip" in row and pd.notna(row["dst_ip"]) and str(row["dst_ip"]).strip() else None

        source_port = None
        if "source_port" in row and pd.notna(row["source_port"]):
            try:
                sp = int(row["source_port"])
                if sp > 0:
                    source_port = sp
            except (ValueError, TypeError):
                pass

        dest_port = None
        if "dest_port" in row and pd.notna(row["dest_port"]):
            try:
                dp = int(row["dest_port"])
                if dp > 0:
                    dest_port = dp
            except (ValueError, TypeError):
                pass

        bytes_val = None
        if "bytes" in row and pd.notna(row["bytes"]):
            try:
                bytes_val = max(0, int(row["bytes"]))
            except (ValueError, TypeError):
                pass

        duration_val = None
        if "duration" in row and pd.notna(row["duration"]):
            try:
                duration_val = max(0.0, float(row["duration"]))
            except (ValueError, TypeError):
                pass

        ens_score = None
        if "Ensemble Score" in row and pd.notna(row["Ensemble Score"]):
            try:
                ens_score = float(row["Ensemble Score"])
            except (ValueError, TypeError):
                pass

        # Optional flow ID (derived from 5-tuple if available)
        flow_id = None
        if src_ip and dst_ip and dest_port:
            flow_id = f"{src_ip}:{source_port or 0}->{dst_ip}:{dest_port}/{protocol}"

        alert = Alert(
            timestamp=now_iso,
            source_type=source_type,
            protocol=protocol,
            packets=packets,
            bytes=bytes_val,
            duration=duration_val,
            src_ip=src_ip,
            dst_ip=dst_ip,
            source_port=source_port,
            dest_port=dest_port,
            flagged_by=flagged_by,
            severity=AlertSeverity.from_string(severity_str),
            reasons=reasons,
            flow_id=flow_id,
            ensemble_score=ens_score,
        )
        alerts.append(alert)

    return alerts


def calculate_transparent_risk_score(alerts: List[Alert]) -> Tuple[int, List[str], AlertSeverity]:
    """
    Computes a deterministic 0-100 heuristic risk prioritization score.
    Explicitly documented as an explainable heuristic, NOT an attack probability.
    Prevents double-counting overlapping evidence.

    Returns:
      (score: int, itemized_factors: List[str], incident_severity: AlertSeverity)
    """
    if not alerts:
        return 0, ["No alerts associated (0)"], AlertSeverity.LOW

    factors = []
    total_score = 0

    # 1. Base Severity Contribution (highest severity among alerts, counted once)
    severities = [a.severity for a in alerts]
    if AlertSeverity.CRITICAL in severities:
        base_pts = 50
        inc_sev = AlertSeverity.CRITICAL
        factors.append("Base Severity: Critical (+50)")
    elif AlertSeverity.HIGH in severities:
        base_pts = 40
        inc_sev = AlertSeverity.HIGH
        factors.append("Base Severity: High (+40)")
    elif AlertSeverity.MEDIUM in severities:
        base_pts = 25
        inc_sev = AlertSeverity.MEDIUM
        factors.append("Base Severity: Medium (+25)")
    else:
        base_pts = 15
        inc_sev = AlertSeverity.LOW
        factors.append("Base Severity: Low (+15)")
    total_score += base_pts

    # 2. Multi-Detector Corroboration (counted once per incident)
    has_both = any(a.flagged_by == "Both" for a in alerts)
    distinct_detectors = set()
    for a in alerts:
        if a.flagged_by in ("Statistical", "Both"):
            distinct_detectors.add("Statistical")
        if a.flagged_by in ("ML", "Both"):
            distinct_detectors.add("ML")
        if a.ensemble_score is not None and a.ensemble_score >= 0.75:
            distinct_detectors.add("SupervisedEnsemble")

    if has_both or len(distinct_detectors) >= 2:
        total_score += 20
        factors.append("Multi-Detector Corroboration: Independent algorithms flagged anomaly (+20)")

    # 3. Supervised Confidence Boost (max ensemble score, counted once)
    valid_scores = [a.ensemble_score for a in alerts if a.ensemble_score is not None]
    if valid_scores:
        max_ens = max(valid_scores)
        if max_ens >= 0.90:
            total_score += 15
            factors.append(f"High Supervised Model Confidence: score {max_ens:.2f} >= 0.90 (+15)")
        elif max_ens >= 0.75:
            total_score += 10
            factors.append(f"Moderate Supervised Model Confidence: score {max_ens:.2f} >= 0.75 (+10)")

    # 4. Volumetric & Statistical Deviation Boost (counted once)
    has_extreme_z = any("4." in a.reasons or "5." in a.reasons or "std above" in a.reasons for a in alerts)
    has_extreme_pkts = any(a.packets >= 1000 for a in alerts)
    if has_extreme_z or has_extreme_pkts:
        total_score += 10
        factors.append("Extreme Volumetric Deviation: z-score >= 4.0 or high packet spike (+10)")

    # 5. Multiplicity & Persistence Boost (counted once)
    n_alerts = len(alerts)
    if n_alerts >= 5:
        total_score += 10
        factors.append(f"Threat Multiplicity: {n_alerts} correlated alerts in incident (+10)")
    elif n_alerts >= 3:
        total_score += 5
        factors.append(f"Threat Multiplicity: {n_alerts} correlated alerts in incident (+5)")

    # Bound strictly between 0 and 100
    final_score = int(np.clip(total_score, 0, 100))
    factors.append(f"Total Heuristic Risk Score: {final_score}/100 [Prioritization index, not probability]")

    return final_score, factors, inc_sev


class IncidentEngine:
    """
    Correlates raw FlowWatch alerts into structured security incidents
    using deterministic rules and transparent risk scoring.
    """

    def __init__(self, time_window_seconds: int = 300):
        self.time_window_seconds = time_window_seconds

    def correlate_alerts(self, alerts: List[Alert]) -> List[Incident]:
        """
        Executes deterministic correlation passes across a batch of alerts.
        Ensures every alert is linked to an incident, preserves traceability,
        and uses conservative fallback for alerts missing IP addresses.
        """
        if not alerts:
            return []

        incidents: List[Incident] = []
        assigned_alert_ids: Set[str] = set()

        # Pass 1: Port-Sweep Correlation
        # Trigger: Same src_ip targeting >= 3 distinct dest_ports
        src_to_ports: Dict[str, Set[int]] = defaultdict(set)
        src_to_alerts: Dict[str, List[Alert]] = defaultdict(list)
        for a in alerts:
            if a.src_ip and a.dest_port is not None:
                src_to_ports[a.src_ip].add(a.dest_port)
                src_to_alerts[a.src_ip].append(a)

        for src_ip, dports in src_to_ports.items():
            if len(dports) >= 3:
                matched_alerts = [a for a in src_to_alerts[src_ip] if a.alert_id not in assigned_alert_ids]
                if len(matched_alerts) >= 3:
                    score, factors, sev = calculate_transparent_risk_score(matched_alerts)
                    incident = Incident(
                        title=f"Horizontal Port Sweep Detected from Host {src_ip}",
                        correlation_rule=CorrelationRule.RULE_PORT_SWEEP.value,
                        severity=sev,
                        risk_score=score,
                        risk_factors=factors,
                        alert_ids=[a.alert_id for a in matched_alerts],
                        primary_entity=src_ip,
                        entity_type="src_ip",
                        summary=f"Host {src_ip} probed {len(dports)} distinct destination ports ({sorted(list(dports))[:5]}).",
                    )
                    incidents.append(incident)
                    for a in matched_alerts:
                        assigned_alert_ids.add(a.alert_id)

        # Pass 2: Service-Surge Correlation (DDoS / Distributed Flood)
        # Trigger: >= 3 distinct sources targeting the identical dest_port and protocol
        svc_to_sources: Dict[Tuple[int, str], Set[str]] = defaultdict(set)
        svc_to_alerts: Dict[Tuple[int, str], List[Alert]] = defaultdict(list)
        for a in alerts:
            if a.alert_id not in assigned_alert_ids and a.dest_port is not None and a.src_ip:
                key = (a.dest_port, a.protocol)
                svc_to_sources[key].add(a.src_ip)
                svc_to_alerts[key].append(a)

        for (dport, proto), sources in svc_to_sources.items():
            if len(sources) >= 3:
                matched_alerts = [a for a in svc_to_alerts[(dport, proto)] if a.alert_id not in assigned_alert_ids]
                if len(matched_alerts) >= 3:
                    score, factors, sev = calculate_transparent_risk_score(matched_alerts)
                    incident = Incident(
                        title=f"Distributed Surge on Service {proto}/{dport}",
                        correlation_rule=CorrelationRule.RULE_SERVICE_SURGE.value,
                        severity=sev,
                        risk_score=score,
                        risk_factors=factors,
                        alert_ids=[a.alert_id for a in matched_alerts],
                        primary_entity=f"{proto}/{dport}",
                        entity_type="dest_port",
                        summary=f"{len(sources)} distinct hosts generated anomalous traffic surges targeting port {dport}.",
                    )
                    incidents.append(incident)
                    for a in matched_alerts:
                        assigned_alert_ids.add(a.alert_id)

        # Pass 3: Endpoint Host Convergence Correlation
        # Trigger: Multiple alerts sharing the same src_ip
        host_to_alerts: Dict[str, List[Alert]] = defaultdict(list)
        for a in alerts:
            if a.alert_id not in assigned_alert_ids and a.src_ip:
                host_to_alerts[a.src_ip].append(a)

        for src_ip, host_alerts in host_to_alerts.items():
            if len(host_alerts) >= 2:
                score, factors, sev = calculate_transparent_risk_score(host_alerts)
                incident = Incident(
                    title=f"Host Threat Activity: {src_ip}",
                    correlation_rule=CorrelationRule.RULE_SRC_HOST.value,
                    severity=sev,
                    risk_score=score,
                    risk_factors=factors,
                    alert_ids=[a.alert_id for a in host_alerts],
                    primary_entity=src_ip,
                    entity_type="src_ip",
                    summary=f"Repeated suspicious flow activity ({len(host_alerts)} alerts) originating from host {src_ip}.",
                )
                incidents.append(incident)
                for a in host_alerts:
                    assigned_alert_ids.add(a.alert_id)

        # Pass 4: Multi-Model Threat Flag
        # Trigger: Alert has high confidence multi-model corroboration (flagged_by == 'Both' or high ensemble score)
        unassigned_alerts = [a for a in alerts if a.alert_id not in assigned_alert_ids]
        for a in unassigned_alerts:
            is_corroborated = a.flagged_by == "Both" or (a.ensemble_score is not None and a.ensemble_score >= 0.85)
            if is_corroborated:
                score, factors, sev = calculate_transparent_risk_score([a])
                entity = a.src_ip or f"{a.protocol}:{a.dest_port or a.packets}"
                incident = Incident(
                    title=f"Multi-Detector Corroborated Anomaly: {entity}",
                    correlation_rule=CorrelationRule.RULE_MULTI_DETECTOR.value,
                    severity=sev,
                    risk_score=score,
                    risk_factors=factors,
                    alert_ids=[a.alert_id],
                    primary_entity=entity,
                    entity_type="src_ip" if a.src_ip else "protocol",
                    summary=f"Independent anomaly corroboration by {a.flagged_by}. {a.reasons}".strip(),
                )
                incidents.append(incident)
                assigned_alert_ids.add(a.alert_id)

        # Pass 5: Conservative Fallback for Missing IP / Singletons
        # Requirement: Do NOT group unrelated alerts merely because they share a protocol!
        # Only group alerts if they share protocol AND identical reason signature / volumetric pattern.
        remaining = [a for a in alerts if a.alert_id not in assigned_alert_ids]
        
        # Group remaining by exact (protocol, reasons) signature
        sig_groups: Dict[Tuple[str, str], List[Alert]] = defaultdict(list)
        for a in remaining:
            sig_groups[(a.protocol, a.reasons)].append(a)

        for (proto, reason_sig), sig_alerts in sig_groups.items():
            if len(sig_alerts) >= 2 and reason_sig:
                # Grouped only because they share the identical anomalous signature pattern
                score, factors, sev = calculate_transparent_risk_score(sig_alerts)
                incident = Incident(
                    title=f"Volumetric Signature Pattern: {proto}",
                    correlation_rule=CorrelationRule.RULE_VOLUMETRIC_BURST.value,
                    severity=sev,
                    risk_score=score,
                    risk_factors=factors,
                    alert_ids=[a.alert_id for a in sig_alerts],
                    primary_entity=proto,
                    entity_type="protocol",
                    summary=f"Coordinated burst of {len(sig_alerts)} flows sharing signature: {reason_sig}",
                )
                incidents.append(incident)
                for a in sig_alerts:
                    assigned_alert_ids.add(a.alert_id)
            else:
                # Standalone un-correlated singleton incident
                for a in sig_alerts:
                    score, factors, sev = calculate_transparent_risk_score([a])
                    entity = a.src_ip or f"{proto} flow ({a.packets} pkts)"
                    incident = Incident(
                        title=f"Isolated Network Anomaly: {entity}",
                        correlation_rule=CorrelationRule.RULE_SINGLETON.value,
                        severity=sev,
                        risk_score=score,
                        risk_factors=factors,
                        alert_ids=[a.alert_id],
                        primary_entity=entity,
                        entity_type="src_ip" if a.src_ip else "protocol",
                        summary=f"Isolated anomaly detected by {a.flagged_by}. {a.reasons}".strip(),
                    )
                    incidents.append(incident)
                    assigned_alert_ids.add(a.alert_id)

        return incidents

    def process_and_persist(
        self,
        alerts: List[Alert],
        store: Any,
        skip_already_associated: bool = True,
    ) -> List[Incident]:
        """
        Coordinates full pipeline: persists raw alerts (with deduplication),
        computes correlations, writes incidents, and records audit trails.
        When skip_already_associated is True, prevents re-correlating alerts
        that are already linked to an existing incident on repeated runs.
        """
        if not alerts:
            return []

        # 1. Save all alerts into SQLite (deduplicating via fingerprint)
        persisted_alerts = []
        for a in alerts:
            aid = store.save_alert(a)
            # Ensure alert retains exact ID stored
            a.alert_id = aid
            persisted_alerts.append(a)

        # 2. Filter out alerts already associated with an incident
        alerts_to_correlate = persisted_alerts
        if skip_already_associated and hasattr(store, "get_associated_alert_ids"):
            all_aids = [a.alert_id for a in persisted_alerts]
            associated_aids = store.get_associated_alert_ids(all_aids)
            alerts_to_correlate = [a for a in persisted_alerts if a.alert_id not in associated_aids]

        if not alerts_to_correlate:
            return []

        # 3. Correlate unassociated alerts into incidents
        incidents = self.correlate_alerts(alerts_to_correlate)

        # 4. Persist incidents and audit events
        for inc in incidents:
            store.save_incident(inc)
            store.log_audit_event(
                AuditEvent(
                    event_type="INCIDENT_CREATED",
                    actor="SYSTEM",
                    description=f"Created incident '{inc.title}' via {inc.correlation_rule} with {len(inc.alert_ids)} alerts. Risk: {inc.risk_score}/100.",
                    incident_id=inc.incident_id,
                    details={
                        "rule": inc.correlation_rule,
                        "risk_score": inc.risk_score,
                        "risk_factors": inc.risk_factors,
                        "alert_count": len(inc.alert_ids),
                    },
                )
            )

        return incidents
