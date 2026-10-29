# FlowWatch 2.0 — Network Threat Detection, Investigation, and Simulated Response Platform

## About
FlowWatch 2.0 is an intelligent Computer Networks project that analyzes network traffic, flags unusual activity, explains each anomaly, correlates related alerts into actionable security incidents, and provides an approval-gated, simulated response and rollback engine. Results are visualized across a seven-tab interactive Streamlit dashboard backed by persistent SQLite storage.

> [!IMPORTANT]
> **Academic Prototype & Safe Simulation Notice:**
> - Flagged records represent anomalous flow patterns, not confirmed malicious attacks.
> - Incident risk scores are deterministic, itemized heuristic priority ratings (0–100), not calibrated Bayesian attack probabilities.
> - Containment actions operate strictly in `SIMULATED` mode within SQLite state tables; FlowWatch **never** modifies host OS firewall rules, issues `iptables`/`netsh` commands, or drops real network packets.

---

## Key Features

### 1. Ingestion & Preprocessing
- **File Ingestion**: Standard CSV and JSON network logs with column validation and negative packet checks.
- **Streaming PCAP Aggregation**: Aggregates raw `.pcap`/`.pcapng` packets into bidirectional 5-tuple flows (`src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`) with packet capping and payload omission for privacy.
- **Benchmark Formats**: Auto-detects and seamlessly maps UNSW-NB15 and CIC-IDS2017 schemas.
- **Live Monitoring**: Real-time packet sniffing using Scapy's `AsyncSniffer`, Windows network adapter auto-discovery (`scapy.arch.windows`), rolling memory windows, temporal bandwidth metrics, and session alert history.
- **Feature Engineering**: Calculates rate and volume metrics (`packets_per_sec`, `bytes_per_sec`, `bytes_per_packet`) with complete zero-division and non-finite protection.

### 2. Multi-Tier Anomaly Detection & Explainability
- **Statistical Detector**: Multi-feature continuous testing across packets, bytes, duration, and rates with Mean+Std or robust Median+MAD baselines, plus Gaussian Bonferroni multiple-testing control.
- **Isolation Forest**: High-dimensional tree isolation for multivariate outlier discovery with automated column median imputation.
- **Supervised Ensembles**: Pre-trained Random Forest + HistGradientBoosting models calibrated across operational false-positive rate (FPR) targets (0.1%, 0.5%, 1.0%, 5.0%).
- **Transparent Attribution**: Categorizes detections into `Statistical`, `ML`, `Both`, or `None`, grades severity (`Low`, `Medium`, `High`), and provides human-readable z-score explanations.

### 3. Incident Correlation & Heuristic Risk Scoring (FlowWatch 2.0)
- **Multi-Pass Rule Correlation**:
  - *Rule 1 (Port Sweep)*: Single source targeting $\ge 3$ distinct destination ports.
  - *Rule 2 (Service Surge)*: $\ge 3$ distinct sources targeting the same port/protocol.
  - *Rule 3 (Endpoint Convergence)*: Multiple suspicious flows originating from the same host.
  - *Rule 4 (Multi-Detector Corroboration)*: High-confidence flags corroborated across statistical and ML tiers.
  - *Rule 5 (Volumetric Pattern / Singleton Fallback)*: Safe grouping on identical signature without cross-protocol contamination; singletons preserved.
- **Transparent Risk Index**: Itemized heuristic breakdown (multi-detector corroboration, high severity, volumetric surge, port diversity) yielding a 0–100 score.

### 4. Approval-Gated Simulated Response & Safe Rollback (FlowWatch 2.0)
- **Safe Simulated Playbooks**: `WATCH_SOURCE`, `SIMULATE_BLOCK_SOURCE`, `SIMULATE_BLOCK_DESTINATION_PORT`, `MARK_FOR_INVESTIGATION`.
- **Strict Approval Gating**: Proposed actions enter `PENDING` status. Execution is rejected unless explicitly approved by an authorized analyst or supervisor; rejected actions cannot execute.
- **Active Verification**: Checks that simulated containment tables accurately reflect requested blocks.
- **Non-Destructive Rollback**: Rollbacks restore prior state without removing pre-existing containment applied by other actions (`was_prior_state` isolation).
- **Immutable Audit Trail**: Logs every proposal, approval, rejection, execution, verification, and rollback with timestamps, actor IDs, and details.

### 5. Seven-Tab Interactive Security Center
1. **Overview**: Metric cards, protocol distribution, and overall anomaly rates.
2. **Traffic Analytics**: Log-scale volume scatter plots and engineered rate characteristics.
3. **Anomaly Investigation**: Flagged flow table with severity filters, reason breakdowns, and live session logs.
4. **Model Comparison**: Side-by-side detection matrix, agreement Venn diagrams, and ensemble score tuning.
5. **Evaluation**: Benchmark evaluation switcher between UNSW-NB15 and CIC-IDS2017 with PR curves and category recall.
6. **Reports**: Printable summary reports and CSV data exports.
7. **Incident Response & Triage**: Correlated incident triage queue, risk score inspect panels, approval-gated response workflow, simulated containment tables, and immutable audit logs.

---

## Technologies
- **Core Language**: Python 3.12
- **Dashboard & UI**: Streamlit, Plotly Express
- **Machine Learning & Stats**: Scikit-learn, SciPy, NumPy, Pandas, Joblib
- **Packet & Network Analysis**: Scapy (PcapReader, AsyncSniffer), Npcap (Windows)
- **Storage & Auditing**: SQLite3 (Standard Library, WAL mode, transactional ACID compliance)

---

## How to Run

### Installation
```powershell
pip install -r requirements.txt
```

### Launch the Security Center
```powershell
py -3.12 -m streamlit run model_dashboard.py
```
Streamlit will launch locally at `http://localhost:8501`.

*Note for live packet capture on Windows:* Install [Npcap](https://npcap.com) in "WinPcap API-compatible mode" and run your terminal as Administrator.

---

## Verification Test Commands

Run the full automated test suite:
```powershell
# 1. Main FlowWatch 12-stage baseline test suite
py -3.12 test_suite.py

# 2. Incident correlation, lifecycle, and store verification (17 tests)
py -3.12 test_incident_response.py

# 3. Response engine, approval gating, simulated state, and rollback (18 tests)
py -3.12 test_response_engine.py

# 4. Dashboard tab 7 integration, deduplication, and filters (13 tests)
py -3.12 test_incident_dashboard.py

# 5. End-to-end 12-step workflow integration test (2 tests)
py -3.12 test_e2e_workflow.py

# 6. Syntax and byte-compilation validation
py -3.12 -m py_compile model_dashboard.py incident_models.py incident_store.py incident_engine.py response_engine.py

# 7. Whitespace and Git diff check
git diff --check
```

---

## Documentation & Technical Review Guides
- [ARCHITECTURE.md](file:///d:/Fall%20Semester%20(2026-27)%20Semester%205/Computer%20Networks/CN%20Project/CN-PROJECT/ARCHITECTURE.md) — Complete end-to-end architectural data flow, SQLite schema, correlation state machines, and Mermaid diagrams.
- [DEMO_GUIDE.md](file:///d:/Fall%20Semester%20(2026-27)%20Semester%205/Computer%20Networks/CN%20Project/CN-PROJECT/DEMO_GUIDE.md) — 8–10 minute demonstration walkthrough for faculty review, file walkthroughs, and expected outcomes.
- [PROJECT_REVIEW_QA.md](file:///d:/Fall%20Semester%20(2026-27)%20Semester%205/Computer%20Networks/CN%20Project/CN-PROJECT/PROJECT_REVIEW_QA.md) — Comprehensive technical defense questions and answers covering networking, ML, benchmarks, response safety, and limitations.

---

## Project Structure
- `model_dashboard.py` — Multi-tab Streamlit dashboard (Tabs 1–7)
- `incident_models.py` — Dataclasses, enums, lifecycle validation for alerts, incidents, actions, and audit logs
- `incident_store.py` — ACID SQLite persistence, deduplication, simulated state, and audit queries
- `incident_engine.py` — Alert extraction, rule correlation, and transparent heuristic risk scoring
- `response_engine.py` — Approval gating, simulated playbook execution, verification, and rollback
- `data_loader.py`, `pcap_loader.py` — File parsers and streaming 5-tuple flow aggregator
- `live_monitor.py` — Scapy live capture daemon, adapter auto-discovery, rolling statistics
- `statistical_detector.py` — Continuous multi-feature statistical detector with Bonferroni correction
- `ml_detector.py` — Isolation Forest anomaly detector
- `feature_engineering.py` — Division-safe network rate and volume feature engineering
- `explainability.py` — Z-score deviation calculations, human-readable reason strings, severity grading
- `evaluation.py`, `evaluate_cic.py` — UNSW-NB15 and CIC-IDS2017 benchmark evaluation pipelines
- `flow_ensemble_model.joblib` — Trained supervised flow ensemble
- `test_suite.py`, `test_incident_response.py`, `test_response_engine.py`, `test_incident_dashboard.py`, `test_e2e_workflow.py` — Test suites

---

## Known Limitations
1. **Simulation Boundaries**: FlowWatch 2.0 response actions are strictly simulated in SQLite database tables. They do not alter real OS routing tables, firewall rules, or hardware switches.
2. **Flow Aggregation**: Packet-to-flow aggregation is performed in user-space Python using Scapy rather than hardware-accelerated NetFlow/IPFIX/Zeek sensors; throughput is bounded accordingly.
3. **Supervised Generalization**: Supervised models detect attack families present in benchmark training data; zero-day exploits rely on unsupervised Isolation Forest and statistical detection tiers.
4. **Laboratory Benchmarks**: UNSW-NB15 and CIC-IDS2017 are synthetic research datasets; reported precision and recall reflect controlled laboratory benchmarks rather than dynamic live production networks.
5. **Live Capture Permissions**: Live capture requires Npcap in WinPcap-compatible mode and elevated Administrator privileges on Windows.
