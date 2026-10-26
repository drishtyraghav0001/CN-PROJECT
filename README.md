# FlowWatch — Network Traffic Monitoring and Anomaly Detection

## About
FlowWatch is a Computer Networks project that analyzes network traffic, flags unusual patterns, explains why each record was flagged, and presents the results in an interactive Streamlit dashboard. It is a prototype: flagged records are unusual patterns, not confirmed cyberattacks.

## Features
- **Two data-source modes**
  - File upload: CSV, JSON, PCAP/PCAPNG (packets are aggregated into 5-tuple flows with Scapy), and UNSW-NB15/CIC-IDS2017 format CSVs (mapped automatically).
  - Live monitoring: continuous real-time capture with Scapy `AsyncSniffer`, auto-discovered Windows network interfaces, rolling flow statistics, time-series traffic rate tracking, and an audit-ready session alert history log.
- **Three-Tier Detection Engine**
  - Multi-feature statistical detector across continuous metrics (packets, bytes, duration, packets/sec, bytes/sec, bytes/packet) with Bonferroni multiple-testing control and Mean+Std or robust Median+MAD baselines.
  - Isolation Forest on all numerical traffic features with automated median imputation.
  - Supervised Ensembles (Random Forest + Gradient Boosting):
    - Extended feature ensemble for full UNSW-NB15 datasets (60 features).
    - Flow-level ensemble (`flow_ensemble_model.joblib`) compatible with standard PCAP and live capture features.
- **Feature engineering:** packets/sec, bytes/sec and bytes/packet, computed safely without division by zero.
- **Explainable flags:** attribution (Statistical / ML / Both / None), severity grading (Low / Medium / High), and human-readable reason strings built from calculated feature deviations.
- **Dashboard tabs:** Overview, Traffic Analytics (with real-time temporal trend charts in live mode), Anomaly Investigation (with persistent session alert log), Model Comparison, Evaluation (multi-dataset switcher between UNSW-NB15 and CIC-IDS2017), Reports.
- **Sidebar controls:** std multiplier, baseline mode, Bonferroni adjustment toggle, ML contamination, engineered-features toggle, protocol and flagged-by filters, live monitoring window/refresh rate, interface selector, and ensemble operating points.
- **Multi-dataset evaluation:** Precision, recall, F1, false-positive rate, and per-category attack recall across both UNSW-NB15 and CIC-IDS2017 benchmarks.
- **Exports:** CSV of full comparison reports, flagged anomalies, and live session alert logs.

## Technologies
Python, Streamlit, Pandas, NumPy, Scikit-learn, Scapy, Joblib, SciPy, Npcap (Windows, for live capture).

## How to Run
```bash
pip install -r requirements.txt
python -m streamlit run model_dashboard.py
```
For live monitoring on Windows, install [Npcap](https://npcap.com) (WinPcap API-compatible mode) and run the terminal as Administrator. The dashboard automatically discovers available network adapters (e.g. Wi-Fi, Ethernet).

Run verification tests:
```bash
python test_suite.py
```

Run benchmarks (optional; uses datasets in `data/`):
```bash
python evaluation.py       # Evaluates UNSW-NB15
python evaluate_cic.py     # Evaluates CIC-IDS2017
```

## Project Structure
- `model_dashboard.py` — Multi-tab Streamlit dashboard
- `data_loader.py`, `pcap_loader.py` — File input and PCAP streaming flow aggregation
- `live_monitor.py` — Live capture sniffer, adapter auto-discovery, rolling statistics, alert log
- `statistical_detector.py` — Multi-feature continuous statistical detector with Bonferroni correction
- `ml_detector.py` — Isolation Forest anomaly detector
- `feature_engineering.py` — Rate and volume feature engineering
- `explainability.py` — Deviation calculations, human-readable reason strings, severity grading
- `evaluation.py` — UNSW-NB15 evaluation pipeline and extended ensemble
- `evaluate_cic.py` — CIC-IDS2017 benchmark evaluation pipeline
- `generate_sample_pcap.py` — Creates `sample_traffic.pcap`
- `test_suite.py` — Verification test suite (10/10 tests passing)

## Evaluation

### 1. UNSW-NB15 Benchmark
Trained on the UNSW-NB15 training split (175,341 records) and evaluated on the official test split (82,332 records: 37,000 normal, 45,332 attacks).

| Method | Precision | Recall | F1 | Test FPR |
|---|---|---|---|---|
| Statistical (Mean + Std) | 0.350 | 0.007 | 0.014 | 1.6% |
| Isolation Forest (semi-supervised) | 0.793 | 0.445 | 0.570 | 14.2% |
| Isolation Forest (extended features, 10% target) | 0.823 | 0.645 | 0.723 | 17.0% |
| Random Forest (0.1% FPR target) | 0.997 | 0.793 | 0.883 | 0.3% |
| Gradient Boosting (0.1% FPR target) | 0.993 | 0.847 | 0.915 | 0.7% |
| RF+GB Extended Ensemble (0.1% FPR target) | 0.997 | 0.826 | 0.904 | 0.3% |
| RF+GB Flow Ensemble (0.1% FPR target, live-compatible) | 0.998 | 0.665 | 0.798 | 0.15% |
| RF+GB Flow Ensemble (1.0% FPR target, live-compatible) | 0.977 | 0.833 | 0.899 | 2.4% |

### 2. CIC-IDS2017 Benchmark
Evaluated across all 8 traffic captures (DDoS, PortScan, DoS Hulk/GoldenEye/Slowloris, Patator, Web Attacks, Bot, Infiltration) on a balanced 56,193-record sampled subset (39,335 train / 16,858 test):

| Method | Precision | Recall | F1 | Test FPR |
|---|---|---|---|---|
| Statistical (Mean + Std) | 0.494 | 0.103 | 0.170 | 10.6% |
| Statistical (Median + MAD) | 0.542 | 0.977 | 0.697 | 83.2% |
| Isolation Forest (Semi-Supervised) | 0.662 | 0.194 | 0.300 | 10.0% |
| RF+GB Ensemble (0.1% FPR target) | 0.999 | 0.790 | 0.882 | 0.1% |
| RF+GB Ensemble (1.0% FPR target) | 0.988 | 0.973 | 0.981 | 1.2% |
| RF+GB Ensemble (threshold 0.5) | 0.981 | 0.991 | 0.986 | 1.9% |

## Limitations
- Flow aggregation from PCAP and live capture is simplified, not a full NetFlow/Zeek pipeline.
- Supervised models only recognise attack types represented in training data; Isolation Forest and statistical testing can flag novel unlabelled behaviour.
- Both UNSW-NB15 and CIC-IDS2017 are lab-generated synthetic benchmarks; metrics demonstrate comparative model performance rather than guaranteed real-world deployment efficacy.
- Live monitoring requires Administrator rights and Npcap on Windows and should strictly be run on authorized networks.