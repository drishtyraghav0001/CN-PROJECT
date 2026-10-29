# FlowWatch 2.0 — Final Project Demonstration Guide

This guide provides a structured, foolproof **8–10 minute demonstration sequence** for academic presentations, viva voce examinations, and technical project reviews of **FlowWatch 2.0**.

---

## 1. Prerequisites & Launch Commands

### System Requirements:
- Python 3.12
- Dependencies installed from `requirements.txt`
- (Optional, for Live Capture): Windows with [Npcap](https://npcap.com) installed in "WinPcap API-compatible mode".

### Quick Environment Check:
```powershell
py -3.12 --version
py -3.12 -c "import streamlit, pandas, scapy, sklearn, plotly, joblib, scipy, sqlite3; print('All core dependencies verified.')"
```

### Launch the FlowWatch Security Center:
```powershell
py -3.12 -m streamlit run model_dashboard.py
```
> [!NOTE]
> Streamlit will launch the dashboard in your default browser at `http://localhost:8501`.
> If Streamlit is already running, open `http://localhost:8501` directly in your browser.

---

## 2. Recommended 8–10 Minute Demonstration Script

| Time | Phase | Target Tab / Action | What to Say and Demonstrate |
|---|---|---|---|
| **0:00 – 1:00** | **Introduction & Problem Statement** | Overview / Header | Explain the challenge of modern network anomaly detection: high packet volumes, subtle low-and-slow exfiltration, and the limitation of pure signature or single-model detectors. Introduce FlowWatch 2.0 as a complete defense-in-depth platform combining continuous detection, explainability, incident correlation, transparent risk scoring, and approval-gated simulated response. |
| **1:00 – 2:30** | **Baseline Ingestion & Statistical Detection** | Sidebar -> File Upload: `network_traffic.json` | 1. Upload `network_traffic.json`.<br>2. Point out the **Overview metrics** (10 records analyzed, 1 flagged).<br>3. Toggle between **Mean + Std** and **Median + MAD** in the sidebar to show how threshold multipliers operate.<br>4. Explain that `network_traffic.json` has only packet counts, showing graceful backward-compatible handling without rate features. |
| **2:30 – 4:00** | **Feature Engineering & Explainability** | Sidebar -> File Upload: `network_traffic_test.csv` | 1. Upload `network_traffic_test.csv` (20 records with packets, bytes, duration, ports).<br>2. Point to the **Traffic Analytics** tab: show the log-scale scatter plot (Packets vs Bytes) and the three engineered rate features (`packets_per_sec`, `bytes_per_sec`, `bytes_per_packet`).<br>3. Open **Anomaly Investigation** tab: show the flagged records table with **Severity** (`Low`, `Medium`, `High`) and human-readable **Reasons** (e.g., *"Packet count 4.1 std above baseline"*).<br>4. Highlight the attribution filter: filter by "Statistical only", "ML only", or "Both". |
| **4:00 – 5:30** | **PCAP 5-Tuple Aggregation & Flow Ensemble** | Sidebar -> File Upload: `sample_traffic.pcap` | 1. Upload `sample_traffic.pcap`.<br>2. Point to the info banner: **575 packets streamed into 7 bidirectional 5-tuple flows**.<br>3. Explain that payloads are never stored, protecting user privacy.<br>4. Open **Model Comparison** tab: show the **Supervised Flow Model (`flow_ensemble_model.joblib`)**.<br>5. Select operating points in the sidebar (e.g., `0.1% FPR target` vs `1.0% FPR target`) to demonstrate false-alarm tuning for security analysts. |
| **5:30 – 6:45** | **Benchmark Evaluation Tab (UNSW vs CIC)** | Main Tabs -> **Evaluation** | 1. Click the **Evaluation** tab.<br>2. Use the radio toggle to switch between **UNSW-NB15** and **CIC-IDS2017**.<br>3. Show the **Precision vs Recall Scatter Plot** (demonstrating why supervised models cluster at the top-right while unsupervised models trade precision for novel anomaly coverage).<br>4. Review **Top Random Forest Feature Importances** (e.g., `dest_port`, `bytes_per_packet`, `duration`).<br>5. Show **Per-Category Recall** for specific attacks (e.g., PortScan, DoS, Web Attacks).<br>6. Discuss the **train/test distribution shift** documented in the evaluation caption. |
| **6:45 – 8:45** | **Incident Response & Triage (FlowWatch 2.0)** | Main Tabs -> **Incident Response & Triage** | 1. Click the **Incident Response & Triage** tab.<br>2. Point to the **Incident Queue**: show how raw alerts were automatically correlated into high-level incidents (e.g., Port Sweep or Host Threat Activity).<br>3. Expand an incident: review the **Transparent Risk Score** (0–100) and inspect the itemized factor breakdown (e.g., multi-detector agreement, port diversity).<br>4. **Approval Gating**: Select the incident, generate response proposals (`SIMULATE_BLOCK_SOURCE`). Point out that the action is `PENDING` and **cannot execute** without explicit approval.<br>5. **Approval & Execution**: Approve the action as `SOC_SUPERVISOR` and click **Execute (Simulated)**.<br>6. Show the **Simulated Containment State Table**: verify that the entity is actively marked as blocked.<br>7. Show the **Immutable Audit Trail**: inspect the timestamped audit log entry.<br>8. **Safe Rollback**: Click **Roll Back Action** to restore prior state without modifying real OS firewall rules. |
| **8:45 – 10:00** | **Live Monitoring & Architecture Wrap-Up** | Sidebar -> Mode: **Live monitoring** | 1. Switch sidebar to **Live monitoring**.<br>2. Show adapter auto-discovery (`Wi-Fi`, `Ethernet`, or Default interface).<br>3. (If Npcap + Admin available): Click **Start**, generate traffic (browse a website), observe rolling packet count, temporal line charts, and the deduplicated session alert log.<br>4. (If Admin not available): Explain the defensive fallback and show the pre-computed test verification.<br>5. Conclude with project strengths, SQLite persistence, and defense-in-depth architecture. |

---

## 3. Sample Files Walkthrough & Expected Observations

### 1. `network_traffic.json` (Minimal Synthetic Sample)
- **File Contents**: 10 records, only `Protocol` and `Packets`.
- **Expected Behavior**:
  - Exactly 1 record flagged (`Protocol: TCP, Packets: 1000`).
  - Baseline mean $\approx 181.0$, std $\approx 287.8$.
  - Correlated into an isolated incident in Tab 7.

### 2. `network_traffic_test.csv` (Multi-Feature Synthetic Log)
- **File Contents**: 20 records with `packets`, `bytes`, `duration`, `source_port`.
- **Expected Behavior**:
  - Feature engineering computes `packets_per_sec`, `bytes_per_sec`, `bytes_per_packet`.
  - Flags records with volume bursts and excessive duration.
  - Reason strings display exact standard deviations above baseline.

### 3. `sample_traffic.pcap` (Raw Packet Capture)
- **File Contents**: 575 raw packets generated by `generate_sample_pcap.py`.
- **Expected Behavior**:
  - Streams into **7 bidirectional flows**.
  - Single-packet DNS/HTTP flows have duration `0.0`.
  - Flow ensemble model (`flow_ensemble_model.joblib`) scores all 7 flows without crashing.

### 4. `cic_sample.csv` (Real-World Intrusion Benchmark Flows)
- **File Contents**: Extracted from CIC-IDS2017 with raw Canadian Institute for Cybersecurity column headers.
- **Expected Behavior**:
  - Auto-detected as CIC-IDS2017 and transformed into FlowWatch schema.
  - Ground truth `label` and `attack_cat` are extracted into validation metrics and stripped from detection inputs.

---

## 4. Key Defense Points to Emphasize

When examiners ask questions during your demo, emphasize these 4 principles:

1. **Detection vs Attribution**:
   - Detection flags whether a flow is statistically or geometrically anomalous.
   - Attribution explains *which* model flagged it and *why* via calculated z-score deviations.
2. **Heuristic Risk Prioritization vs Attack Probability**:
   - The 0–100 risk score is an itemized heuristic index designed to help analysts prioritize high-urgency incidents.
   - It is **not** a Bayesian posterior probability of compromise.
3. **Correlation vs Ground Truth**:
   - Incident correlation groups flows based on deterministic spatial and temporal rules (e.g., port sweep, service surge).
   - It does not assume attribution without corroboration.
4. **Simulated Response vs Real Firewall Modification**:
   - FlowWatch 2.0 containment actions run strictly in `SIMULATED` mode inside SQLite.
   - This provides safe rehearsal, verification, and auditability without risking disruption of real host network connectivity.

---

## 5. Troubleshooting & Fallbacks

### Issue 1: "Port 8501 is already in use"
- **Solution**: Open `http://localhost:8501` in your browser (the existing server is already active).
- Or run on another port:
  ```powershell
  py -3.12 -m streamlit run model_dashboard.py --server.port 8502
  ```

### Issue 2: Live Monitoring Fails to Start
- **Cause**: Npcap not installed or non-elevated terminal.
- **Solution**: Switch to "File upload" mode in the sidebar and demonstrate `sample_traffic.pcap` or `cic_sample.csv`. Mention that live capture requires administrative socket access via Npcap.

### Issue 3: Incident Response Table is Empty
- **Cause**: File has not been processed or has 0 flagged rows.
- **Solution**: Upload `network_traffic_test.csv` or `sample_traffic.pcap`. Detection automatically extracts alerts and populates the incident table in Tab 7.
