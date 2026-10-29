# FlowWatch — Technical Review & Defense Q&A

This document provides rigorous, academically grounded questions and answers prepared for project defense, viva voce examinations, and technical faculty review. All answers reflect the actual FlowWatch codebase, algorithms, and evaluation artifacts.

---

## 1. Problem Statement & Objectives

### Q1: What specific problem in Computer Networks does FlowWatch address?
**Answer:**
Modern enterprise networks generate massive volumes of high-speed packet traffic. Traditional signature-based Network Intrusion Detection Systems (NIDS) like Snort or Suricata rely on known byte patterns, making them ineffective against zero-day exploits, novel malware variants, and volumetric anomalies (such as SYN floods, UDP amplification, and slow exfiltration). Conversely, purely black-box machine learning approaches often suffer from unacceptably high false-positive rates and lack interpretability, causing "alert fatigue" in Security Operations Centers (SOCs).

FlowWatch addresses this by implementing a **hybrid, defense-in-depth architecture**:
1. It aggregates packets into lightweight, privacy-preserving 5-tuple network flows without recording sensitive payload data.
2. It combines **unsupervised statistical testing** (transparent, low overhead), **unsupervised tree isolation** (multivariate outlier discovery), and **supervised ensemble classification** (calibrated low-false-alarm detection of known attacks).
3. It explains *why* each anomaly was flagged using calculated feature standard deviations and severity grading.

### Q2: What are the primary objectives of the FlowWatch project?
**Answer:**
- **Protocol & Traffic Ingestion**: Support structured network logs (CSV, JSON), raw packet captures (PCAP/PCAPNG), benchmark datasets (UNSW-NB15, CIC-IDS2017), and live adapter capture.
- **Continuous Flow Representation**: Extract bidirectional flow volume, duration, and derived rate metrics (`packets/sec`, `bytes/sec`, `bytes/packet`).
- **Multi-Method Anomaly Detection**: Implement statistical bounds with multiple-testing correction, tree-based isolation, and pre-trained supervised flow ensembles.
- **Explainability**: Bridge the gap between detection and triage by generating attribution labels (`Statistical`, `ML`, `Both`) and human-readable z-score explanations.
- **Empirical Validation**: Benchmark performance on real-world intrusion datasets (UNSW-NB15 and CIC-IDS2017) across strict false-positive rate (FPR) constraints.

---

## 2. System Architecture & Module Responsibilities

### Q3: How is the codebase structured, and what is the responsibility of each module?
**Answer:**
FlowWatch follows a modular pipeline design:
- `model_dashboard.py`: Interactive multi-tab Streamlit dashboard providing visualization, user filtering, operating point selection, and reporting.
- `data_loader.py`: Ingestion, schema validation, and sanitization of JSON and CSV files.
- `pcap_loader.py`: Streaming PCAP/PCAPNG parser that groups packets into 5-tuple flows with packet capping and privacy preservation.
- `live_monitor.py`: Background daemon thread wrapping Scapy's `AsyncSniffer`, Windows adapter auto-discovery, rolling time windows, and deduplicated session alert logging.
- `feature_engineering.py`: Computes traffic rate and volume features with strict division-by-zero protection.
- `statistical_detector.py`: Continuous multi-feature statistical detector implementing Mean+Std, Median+MAD, and Gaussian Bonferroni FWER control.
- `ml_detector.py`: Isolation Forest anomaly detector with automated column median imputation.
- `explainability.py`: Z-score deviation calculation, severity grading, and human-readable reason string synthesis.
- `evaluation.py`: UNSW-NB15 evaluation pipeline, train/test split management, and extended feature preprocessing (`transform_with_spec`).
- `evaluate_cic.py`: CIC-IDS2017 benchmark pipeline with attack label normalization, cross-category recall tracking, and flow ensemble calibration.
- `test_suite.py`: 12-stage automated verification suite covering edge cases, model compatibility, missing artifacts, and interface fallbacks.

---

## 3. Detection Paradigms & Algorithm Details

### Q4: Why include three distinct detection approaches rather than relying on one?
**Answer:**
No single anomaly detection paradigm is universally optimal in network security:
1. **Statistical Detector (Unsupervised / Univariate)**: Extremely fast, fully transparent, and deterministic. Ideal for sudden volumetric spikes (e.g., DoS, brute force), but blind to subtle multidimensional correlations where no single metric exceeds thresholds.
2. **Isolation Forest (Unsupervised / Multivariate)**: Capable of detecting complex, non-linear relationships across multiple dimensions (e.g., low packet count combined with anomalous port or duration). Crucially, it does not require attack labels and can flag novel zero-day patterns. However, it can produce false alarms on benign bursty traffic.
3. **Supervised Flow Ensemble (Supervised / Calibrated)**: Trained on labelled benign and malicious flows. By calibrating operating points against false-positive rates (e.g., 0.1% or 0.5% FPR targets), it achieves near-zero false alarms (over 99.8% precision) on known attack families, but cannot generalize to attacks fundamentally different from training distributions.

Combining them creates a **defense-in-depth triad**: flows flagged by *Both* provide high-confidence alerts, while flows flagged by *ML only* highlight subtle novel anomalies.

### Q5: How do the Mean+Std and Median+MAD baseline modes differ mathematically?
**Answer:**
- **Mean + Standard Deviation (`mean_std`)**:
  $$\mu = \frac{1}{N}\sum_{i=1}^N x_i, \quad \sigma = \sqrt{\frac{1}{N-1}\sum_{i=1}^N (x_i - \mu)^2}$$
  $$\text{Threshold} = \mu + k \cdot \sigma$$
  Assumes approximately Gaussian distributions. However, sample mean and variance have a **breakdown point of 0%**—meaning a single extreme attack spike in the ingestion buffer pulls the mean upward and inflates the standard deviation, potentially masking subsequent anomalies (masking effect).
- **Median + Median Absolute Deviation (`median_mad`)**:
  $$\tilde{x} = \text{median}(x), \quad \text{MAD} = \text{median}(|x_i - \tilde{x}|)$$
  $$\hat{\sigma} = 1.4826 \cdot \text{MAD}$$
  $$\text{Threshold} = \tilde{x} + k \cdot \hat{\sigma}$$
  The factor $1.4826$ ensures asymptotic consistency with the standard deviation under normal distributions ($\frac{1}{\Phi^{-1}(0.75)} \approx 1.4826$). Median and MAD have a **breakdown point of 50%**, meaning up to half the sample can consist of extreme outliers without corrupting the baseline location and scale estimates.

### Q6: What is the Bonferroni adjustment, and why is it needed in multi-feature traffic detection?
**Answer:**
When testing a single feature at critical multiplier $k=2.0$, the false positive rate under a standard normal distribution is $\alpha = 1 - \Phi(2.0) \approx 0.02275$ (2.28%).

If an intrusion detector independently evaluates $m = 6$ continuous flow features (`packets`, `bytes`, `duration`, `packets_per_sec`, `bytes_per_sec`, `bytes_per_packet`), the probability that at least one feature triggers a false alarm on benign traffic (the Family-Wise Error Rate, FWER) inflates dramatically:
$$\text{FWER} = 1 - (1 - \alpha)^m = 1 - (1 - 0.02275)^6 \approx 12.9\%$$

This would result in roughly 1 out of every 8 benign flows being falsely flagged.

To control the FWER at the intended significance $\alpha$, FlowWatch applies the Bonferroni inequality:
$$\alpha_{\text{adj}} = \frac{\alpha}{m} = \frac{0.02275}{6} \approx 0.00379$$
The adjusted critical multiplier is computed via the inverse survival function:
$$k_{\text{adj}} = \Phi^{-1}(1 - \alpha_{\text{adj}}) \approx \Phi^{-1}(1 - 0.00379) \approx 2.67$$
By raising the threshold from $2.0\sigma$ to $2.67\sigma$, the overall false alarm rate across all 6 tested features is strictly bounded back to $\le 2.28\%$.

### Q7: How does Isolation Forest detect anomalies, and why is it suited for network traffic?
**Answer:**
Isolation Forest (Liu et al., 2008) operates on the principle that anomalies are "few and different." Rather than constructing a profile of normal instances (like One-Class SVM or Gaussian Mixture Models), it explicitly isolates anomalies:
1. It builds an ensemble of completely randomized binary search trees (Isolation Trees / iTrees).
2. At each node, a feature is randomly selected, and a random split value is chosen between that feature's minimum and maximum values.
3. Anomalous network flows possess extreme or unusual attribute combinations, meaning they become separated from the bulk of the data in very few random partitions (shallow tree depth). Normal clustered flows require significantly more recursive splits to isolate.
4. The anomaly score $s(x, n)$ is a monotonic function of the expected path length $E(h(x))$ across 100 trees:
   $$s(x, n) = 2^{-\frac{E(h(x))}{c(n)}}$$
   Where $c(n)$ is the average path length of an unsuccessful search in a Binary Search Tree constructed over $n$ instances.
5. In network traffic, where attacks often exhibit high dimensionality and multimodal clustering, Isolation Forest exhibits linear time complexity $\mathcal{O}(t \cdot \psi \log \psi)$ and low memory overhead, making it well-suited for streaming flow analysis.

---

## 4. Supervised Ensemble & Feature Engineering

### Q8: What models constitute the Supervised Flow Ensemble (`flow_ensemble_model.joblib`), and what are its exact input features?
**Answer:**
The flow ensemble combines two high-performing supervised estimators:
1. **Random Forest Classifier**: An ensemble of 200 de-correlated decision trees with balanced bootstrap subsampling.
2. **HistGradientBoosting Classifier**: A histogram-based gradient boosted decision tree algorithm that bins continuous features into 256 discrete integer bins, enabling efficient gradient calculation and native non-finite value handling.

**Standardized 10-Feature Flow Input Vector**:
1. `packets` (total flow packet count)
2. `bytes` (total flow byte volume)
3. `duration` (flow duration in seconds)
4. `packets_per_sec` (packet throughput rate)
5. `bytes_per_sec` (bandwidth throughput rate)
6. `bytes_per_packet` (average payload/packet ratio)
7. `source_port` (transport-layer ephemeral/service port)
8. `dest_port` (target service port, e.g., 80, 443, 22)
9. `proto_tcp` (one-hot indicator: 1.0 if TCP, else 0.0)
10. `proto_udp` (one-hot indicator: 1.0 if UDP, else 0.0)

Both models output positive-class probabilities $P(y=1 \mid x)$, which are averaged:
$$S(x) = \frac{P_{\text{RF}}(y=1 \mid x) + P_{\text{HGB}}(y=1 \mid x)}{2}$$

### Q9: Why is supervised learning alone insufficient for enterprise network intrusion detection?
**Answer:**
Supervised learning operates under the **closed-world assumption**—it presumes that all testing traffic belongs to classes represented in the training labels. In network security:
- **Zero-Day Vulnerabilities**: New exploits and attack variants emerge continuously. A supervised model trained exclusively on known attacks will classify an unprecedented zero-day attack as "Normal" if its flow statistics resemble benign traffic more than known attack templates.
- **Label Inaccuracy and Noise**: Public intrusion datasets frequently suffer from mislabeled flows, synthetic artifacts, and outdated traffic profiles.
- **Distribution Shift**: Benign network behavior naturally drifts over time due to OS updates, new application rollouts, and changing user activity patterns.

FlowWatch resolves this by pairing the supervised ensemble with unsupervised statistical bounds and Isolation Forest, ensuring novel deviations are flagged even when the supervised model assigns a low probability.

---

## 5. Metrics & Benchmark Evaluation

### Q10: Define Precision, Recall, F1-Score, and False-Positive Rate in the context of network security. Why is FPR critical?
**Answer:**
Given:
- $\text{TP}$ (True Positives): Malicious flows correctly flagged as anomalies.
- $\text{FP}$ (False Positives): Benign flows incorrectly flagged as anomalies (false alarms).
- $\text{TN}$ (True Negatives): Benign flows correctly passed as normal.
- $\text{FN}$ (False Negatives): Malicious flows missed by the detector.

1. **Precision**: $\frac{\text{TP}}{\text{TP} + \text{FP}}$ — Out of all flows alerted by the system, what fraction were genuine attacks? High precision eliminates wasted analyst triage time.
2. **Recall (Detection Rate)**: $\frac{\text{TP}}{\text{TP} + \text{FN}}$ — Out of all actual attacks traversing the network, what fraction did the system catch? High recall prevents breaches from going unnoticed.
3. **F1-Score**: $2 \cdot \frac{\text{Precision} \cdot \text{Recall}}{\text{Precision} + \text{Recall}}$ — The harmonic mean balancing precision and recall.
4. **False-Positive Rate (FPR)**: $\frac{\text{FP}}{\text{FP} + \text{TN}}$ — The fraction of benign flows incorrectly flagged.

**Why FPR is critical in network security**:
In high-throughput enterprise networks processing millions of flows per day, an algorithm with an seemingly impressive 99% accuracy and 1% FPR will generate 10,000 false alarms every million flows. This triggers severe **alert fatigue**, leading human analysts to ignore or disable detection alerts. Consequently, FlowWatch prioritizes operating points calibrated to strict FPR targets (e.g., $0.1\%$ or $0.5\%$).

### Q11: How do the UNSW-NB15 and CIC-IDS2017 benchmark datasets compare?
**Answer:**

| Attribute | UNSW-NB15 (Cyber Range Lab, ADFA) | CIC-IDS2017 (Canadian Institute for Cybersecurity) |
|---|---|---|
| **Creation Year** | 2015 | 2017 |
| **Generation Tool** | IXIA PerfectStorm synthetic traffic generator | B-Profile system generating realistic user behavior |
| **Attack Categories** | 9 families: Fuzzers, Analysis, Backdoors, DoS, Exploits, Generic, Reconnaissance, Shellcode, Worms | 7 traffic profiles over 8 days: Brute Force (FTP/SSH), DoS/DDoS, Web Attacks, Infiltration, Botnet, PortScan |
| **Dataset Size** | 257,673 total pre-split records (175,341 train / 82,332 test) | ~2.83M raw flows; FlowWatch evaluates a stratified 56,193-flow balanced subset |
| **Key Research Characteristic** | Severe train/test distribution shift; test set contains newer attack variants not present in training | High class imbalance in raw data; subtle multi-stage attack scenarios (e.g., Heartbleed, Infiltration) |

### Q12: What verified results did FlowWatch achieve on these benchmarks?
**Answer:**
From the saved evaluation artifacts (`evaluation_results.csv` and `evaluation_cic_results.csv`):

**UNSW-NB15 (82,332 test records: 37,000 normal, 45,332 attacks)**:
- **Statistical Detector (Mean + Std)**: Precision 34.7%, Recall 0.69%, FPR 1.61% (flags only extreme outliers).
- **Semi-Supervised Isolation Forest**: Precision 79.3%, Recall 44.5%, F1 57.0%, FPR 14.2%.
- **Supervised RF+GB Extended Ensemble (0.1% target FPR)**: Precision **99.7%**, Recall **82.6%**, F1 **90.4%**, Test FPR **0.29%** (37,440 TP, only 108 FP out of 37,000 normal records).

**CIC-IDS2017 (16,858 test records: 8,400 normal, 8,458 attacks)**:
- **Statistical Detector (Mean + Std)**: Precision 49.4%, Recall 10.3%, F1 17.0%, FPR 10.6%.
- **Semi-Supervised Isolation Forest**: Precision 66.2%, Recall 19.4%, F1 30.0%, FPR 9.95%.
- **Supervised RF+GB Flow Ensemble (0.1% target FPR)**: Precision **99.9%**, Recall **79.0%**, F1 **88.2%**, Test FPR **0.11%** (6,679 TP, only 9 FP out of 8,400 normal records).
- **Supervised RF+GB Flow Ensemble (threshold 0.5)**: Precision **98.1%**, Recall **99.1%**, F1 **98.6%**, Test FPR **1.94%** (8,380 TP, 163 FP).

---

## 6. Packet Capture, Flow Extraction & Networking Fundamentals

### Q13: What constitutes a network flow, and how does FlowWatch construct 5-tuples from raw packets?
**Answer:**
In networking, a flow is a unidirectional or bidirectional sequence of packets sharing common addressing attributes transferred between two endpoints during a specific time interval.

FlowWatch constructs **bidirectional 5-tuple flows**:
$$\text{Flow Key} = (\text{Src IP}, \text{Dst IP}, \text{Src Port}, \text{Dst Port}, \text{Protocol})$$
- In `pcap_loader.py` and `live_monitor.py`, as each packet arrives:
  1. The IP layer (IPv4 or IPv6) extracts source and destination addresses.
  2. The transport layer extracts ports (TCP or UDP) or maps ICMP/Other. DNS traffic is recognized on UDP port 53.
  3. The flow dictionary is queried with the key. If absent, a new flow record is initialized with start timestamp $t_0$, last seen timestamp $t_1$, packet count $1$, and byte count $len(\text{packet})$.
  4. If present, packet count increments, byte count accumulates, and $t_1 = \max(t_1, t_{\text{pkt}})$.
  5. Flow duration is computed as $t_1 - t_0$ (evaluating to $0.0$ for single-packet flows).
  6. **Privacy Guarantee**: Raw packet payloads are never stored in memory or written to disk. Only metadata metrics are retained.

### Q14: What system prerequisites and permissions are required for live monitoring?
**Answer:**
- **Raw Sockets & Promiscuous Capture Driver**: Standard user applications cannot read raw Ethernet frames. On Windows, packet capture requires the **Npcap driver** installed in "WinPcap API-compatible mode".
- **Administrator Privileges**: Binding to network interfaces and opening packet capture handles (`pcap_open_live`) requires elevated Administrator privileges on Windows (or `CAP_NET_RAW` / `CAP_NET_ADMIN` on Linux).
- **Defensive Degradation**: If Npcap or Administrator rights are absent, FlowWatch catches the runtime driver exception, degrades gracefully, and provides clear diagnostic guidance without crashing the application.

---

## 7. Limitations & Future Work

### Q15: What are the current technical limitations of FlowWatch, and how would they be improved in future revisions?
**Answer:**
1. **Simplified Flow Reassembly**: FlowWatch performs flow aggregation based on arrival timestamps without maintaining a full stateful TCP reassembly engine (like Zeek or Suricata). Out-of-order packets and TCP retransmissions are counted as raw volume.
   - *Future Work*: Integrate a stateful TCP tracking state machine to monitor window sizing, TCP flags (RST, FIN, SYN-ACK latencies), and connection teardown status.
2. **Memory Footprint on High-Speed 10Gbps+ Links**: The Python/Scapy capture implementation utilizes Python's Global Interpreter Lock (GIL) and user-space socket copies. While suitable for campus, lab, and branch monitoring, it would experience packet drops on saturated multi-gigabit links.
   - *Future Work*: Implement a high-speed C/Rust capture probe utilizing DPDK (Data Plane Development Kit) or AF_XDP, streaming aggregated NetFlow/IPFIX records to FlowWatch via Kafka.
3. **Encrypted Traffic Inspection**: FlowWatch relies exclusively on flow metadata (packet counts, inter-arrival times, ports, and byte distributions). While effective against volumetric attacks and port scanning, it cannot inspect encrypted TLS payloads.
   - *Future Work*: Incorporate TLS handshake fingerprinting (JA3 / JA4 fingerprints) and sequence-of-packet-lengths-and-times (SPLT) analysis to identify encrypted malware traffic without breaking TLS encryption.

---

## 8. FlowWatch 2.0: Incident Correlation, Heuristic Risk Scoring, Simulated Response & Safety Controls

### Q16: Why was an Incident Management layer added to FlowWatch 2.0 instead of simply listing raw alerts?
**Answer:**
In real-world enterprise networks, intrusion detection sensors produce hundreds or thousands of low-level alerts per hour. Listing raw alerts overwhelms analysts (the "alert fatigue" phenomenon) and obscures multi-stage attacks:
- A single port scan can trigger hundreds of individual flow alerts across distinct destination ports.
- A distributed DoS flood triggers multiple alerts targeting the same service port.

FlowWatch 2.0 introduces an **Incident Correlation Engine** (`incident_engine.py`) that aggregates related alerts into a single cohesive security incident. This elevates the analyst's workflow from viewing disconnected packet bursts to triaging high-level operational threats with clear primary entities, summaries, and containment options.

### Q17: How does FlowWatch 2.0 correlate alerts, and what are the specific correlation rules?
**Answer:**
Correlation is deterministic and rule-based across five distinct passes:
1. **Rule 1 (Horizontal Port Sweep)**: Triggers when a single source IP generates alerts across $\ge 3$ distinct destination ports. Identifies host reconnaissance.
2. **Rule 2 (Distributed Service Surge)**: Triggers when $\ge 3$ distinct source hosts generate anomalous flows targeting the identical destination port and protocol. Identifies coordinated DDoS or brute force floods.
3. **Rule 3 (Endpoint Host Convergence)**: Triggers when multiple alerts ($\ge 2$) share the same source IP. Aggregates repeated anomalous behavior originating from an internal or external host.
4. **Rule 4 (Multi-Detector Corroboration)**: Corroborates alerts flagged independently by multiple detection algorithms (`flagged_by == 'Both'` or supervised ensemble probability $\ge 0.85$).
5. **Rule 5 (Volumetric Signature Pattern / Singleton Fallback)**: For alerts lacking IP addresses, groups flows only if they share both the protocol and the identical anomaly reason signature. Truly standalone alerts remain isolated singletons, preventing false cross-protocol grouping.

### Q18: What is the mathematical and conceptual difference between an Anomaly Score and a Heuristic Risk Score?
**Answer:**
Examiners frequently confuse these two metrics:
- **Anomaly Score / Probability**:
  - Computed at the **individual flow level**.
  - In Isolation Forest, it represents average tree path length ($s(x, n) \in [0, 1]$). In the supervised ensemble, it represents the calibrated model probability of matching known intrusion classes ($P(y=1 \mid x) \in [0, 1]$).
  - It answers: *"How statistically or geometrically unusual is this specific flow compared to baseline traffic?"*
- **Heuristic Risk Score**:
  - Computed at the **incident level**.
  - It is an itemized, deterministic priority rating bounded between $0$ and $100$:
    $$\text{Risk Score} = \min\left(100, \text{Base Severity} + \text{Multi-Detector Bonus} + \text{Volume Bonus} + \text{Port Diversity Bonus}\right)$$
  - It is **not** a calibrated Bayesian probability of compromise. Instead, it is an operational triage metric designed to help SOC operators order their response queue based on threat corroboration, volume, and blast radius.

### Q19: Why does FlowWatch 2.0 use simulated containment rather than executing real OS firewall commands (`iptables` / `netsh`)?
**Answer:**
Executing live OS or firewall modifications from an academic prototype introduces catastrophic real-world operational risks:
1. **Accidental Denial of Service**: A false positive could isolate a critical domain controller, DNS server, default gateway, or the analyst's own SSH connection.
2. **Privilege & System Integrity**: Modifying host firewall tables requires kernel or root-level capabilities, expanding the attack surface of the monitoring application.
3. **Rehearsal & Verification**: Modern SecOps platforms (SOAR) emphasize safe simulation and human-in-the-loop rehearsal before automated enforcement.

FlowWatch 2.0 executes response actions strictly in `SIMULATED` mode inside isolated SQLite state tables (`simulated_containment_state`). It tracks simulated blocked hosts, blocked ports, and surveillance watchlists, verifies their state, and provides safe rollback without modifying host networking.

### Q20: How does the Approval Gating state machine enforce security and prevent unauthorized execution?
**Answer:**
FlowWatch 2.0 implements strict state machine gating:
- Every proposed response action starts in the `PENDING` state.
- Calling `execute_action()` on a `PENDING` action immediately raises `PermissionError` (*"Execution rejected: Action is PENDING and requires explicit approval before execution"*).
- An authorized analyst or supervisor must explicitly call `approve_action(action_id, actor, comment)`, transitioning it to `APPROVED`.
- If an action is rejected via `reject_action(action_id, actor, reason)`, its status moves to `REJECTED`, permanently blocking execution.
- Actions can only be executed once; repeated execution of an `APPLIED` action raises `ValueError`.

### Q21: How does rollback work, and how does the engine ensure prior active containment states are not accidentally revoked?
**Answer:**
A common flaw in naive containment systems is that rolling back Action B on an IP also unblocks the IP even if Action A had separately blocked it earlier.

FlowWatch 2.0 prevents this through **Prior-State Isolation (`was_prior_state`)**:
1. When an action is applied to an entity, the engine checks whether that entity was already `ACTIVE` in `simulated_containment_state`.
2. If it was already active, the new entry is flagged with `was_prior_state = 1`.
3. When `rollback_action(action_id)` is invoked, it updates **only** the rows associated with that specific `action_id` to `ROLLED_BACK`.
4. If prior active entries exist for that entity from another action, the entity remains active in the simulated state table.
5. Additionally, the incident status transitions from `CONTAINED` back to `INVESTIGATING` only if no other active containment actions remain associated with that incident.

### Q22: How does SQLite persistence handle deduplication and prevent duplicate incidents across dashboard refreshes?
**Answer:**
- **Alert Fingerprinting**: Each extracted alert is assigned a deterministic SHA-256 fingerprint based on flow coordinates and detector attribution. During database insertion, conflicting fingerprints are safely ignored (`INSERT OR IGNORE`).
- **Incident Association Protection**: When the dashboard reruns (e.g. user changes a filter or timer fires), `IncidentEngine.process_and_persist(..., skip_already_associated=True)` queries `IncidentStore.get_associated_alert_ids()`. Any alerts already linked to an existing incident are excluded from re-correlation, preventing duplicate incident creation on UI refreshes.

### Q23: What are the differences between automated test results and manual UI verification in this project?
**Answer:**
- **Automated Tests**: Unit and integration test suites (`test_suite.py`, `test_incident_response.py`, `test_response_engine.py`, `test_incident_dashboard.py`, `test_e2e_workflow.py`) run in headless Python processes using temporary SQLite databases (`tempfile.mkdtemp()`). They deterministically verify algorithmic correctness, schema constraints, approval gating, rollback logic, and deduplication.
- **Manual UI Verification**: Done interactively in a web browser against the active Streamlit dashboard (`http://localhost:8501`). It verifies visual layout, metric card styling, Plotly chart responsiveness, dropdown and button interactions, and user feedback rendering. Automated headless tests prove logic correctness; manual verification confirms human user experience.

