# FlowWatch — Network Traffic Monitoring and Anomaly Detection

## About
FlowWatch is a Computer Networks project that analyzes network traffic, flags unusual patterns, explains why each record was flagged, and presents the results in an interactive Streamlit dashboard. It is a prototype: flagged records are unusual patterns, not confirmed cyberattacks.

## Features
- **Two data-source modes**
  - File upload: CSV, JSON, PCAP/PCAPNG (packets are aggregated into flows with Scapy), and UNSW-NB15-format CSVs (mapped automatically).
  - Live monitoring: continuous capture with no timer, analysed over a rolling window with start/stop controls. Only flow statistics are kept; payloads are never stored.
- **Detectors**
  - Statistical detector on packet count (mean + std, or robust median + MAD).
  - Isolation Forest on all available numeric features.
  - Supervised RF + Gradient Boosting ensemble with precision-focused operating points (UNSW-format files only).
- **Feature engineering:** packets/sec, bytes/sec and bytes/packet, computed only when the required columns exist (no division by zero).
- **Explainable flags:** each flagged record shows which method flagged it (Statistical / ML / Both), a severity level, and a reason built only from calculated feature deviations.
- **Dashboard tabs:** Overview, Traffic Analytics, Anomaly Investigation, Model Comparison, Evaluation, Reports.
- **Sidebar controls:** std multiplier, baseline mode, ML contamination, engineered-features toggle, protocol and flagged-by filters, live-monitoring window and refresh rate, ensemble operating point.
- **Evaluation on labelled data:** precision, recall, F1, false-positive rate and per-category recall via `evaluation.py`.
- **Exports:** CSV of the full comparison report and of flagged records.

## Technologies
Python, Streamlit, Pandas, NumPy, Scikit-learn, Scapy, Joblib, Npcap (Windows, for live capture).

## How to Run
```bash
pip install -r requirements.txt
python -m streamlit run model_dashboard.py
```
For live monitoring on Windows, install [Npcap](https://npcap.com) (WinPcap API-compatible mode) and run the terminal as Administrator. Only monitor traffic you are authorized to capture.

Run the evaluation (optional; needs the UNSW-NB15 train and test CSVs in `data/`):
```bash
python evaluation.py
```
This writes `evaluation_results.csv`, `evaluation_results.json` and `ensemble_model.joblib`, which the dashboard uses.

## Project Structure
- `model_dashboard.py` — Streamlit dashboard
- `data_loader.py`, `pcap_loader.py` — file input loading
- `live_monitor.py` — continuous live capture and rolling flow aggregation
- `statistical_detector.py`, `ml_detector.py` — statistical and Isolation Forest detectors
- `feature_engineering.py` — rate and volume features
- `explainability.py` — reasons, flagged-by, severity
- `evaluation.py` — labelled-data evaluation and ensemble training
- `generate_sample_pcap.py` — creates `sample_traffic.pcap`
- `test_suite.py` — tests

## Evaluation
`evaluation.py` trains on the UNSW-NB15 training split and reports metrics on the official test split (82,332 records: 37,000 normal, 45,332 attacks). Labels are never used as model features, and alert thresholds are chosen on held-out training data, never on the test set.

| Method | Precision | Recall | F1 | Test FPR |
|---|---|---|---|---|
| Statistical (Mean + Std) | 0.35 | 0.007 | 0.014 | 1.6% |
| Isolation Forest (semi-supervised) | 0.79 | 0.445 | 0.570 | 14.2% |
| Isolation Forest (extended features, 10% target) | 0.82 | 0.645 | 0.723 | 17.0% |
| Random Forest (0.1% FPR target) | 0.997 | 0.793 | 0.883 | 0.3% |
| Gradient Boosting (0.1% FPR target) | 0.993 | 0.847 | 0.915 | 0.7% |
| RF+GB Ensemble (0.1% FPR target) | 0.997 | 0.826 | 0.904 | 0.3% |
| RF+GB Ensemble (0.2% FPR target) | 0.993 | 0.859 | 0.921 | 0.7% |
| RF+GB Ensemble (1% FPR target) | 0.962 | 0.910 | 0.935 | 4.4% |

Key findings:
- Packet count alone is a weak signal: the statistical detectors detect almost no UNSW attacks.
- Training Isolation Forest on all records (unsupervised) fails because UNSW's training set is about 68% attacks; fitting on normal traffic only is the fair setup.
- Supervised models reach precision above 0.99 at strict thresholds. The RF+GB ensemble is slightly better than either model alone, but the differences are small and come from a single train/test split.
- Test false-positive rates are 2 to 4 times higher than their targets because of UNSW-NB15's known train/test distribution shift. False-positive-rate targets transfer to the test set better than precision targets, because precision depends on the share of attacks.
- Fuzzers are the hardest category (recall about 0.25 to 0.5 at strict thresholds).
- Most important features for the Random Forest: `sttl`, `ct_state_ttl`, `bytes_per_sec`, `sload`, `packets_per_sec`.

If no real dataset is in `data/`, a small synthetic one is generated and clearly marked as synthetic; those results only demonstrate the method.

## Limitations
- Flow aggregation from PCAP and live capture is simplified, not a full NetFlow/Zeek pipeline.
- The statistical detector tests packet count only.
- Isolation Forest can flag a record on a feature combination no single feature explains, so some flagged rows have an empty reason.
- The supervised ensemble needs UNSW-NB15-style features, so it applies to labelled UNSW-format files only, not to PCAP or live flows.
- Supervised models only recognise attack types seen in training; Isolation Forest can flag novel behaviour, so FlowWatch presents both as a hybrid.
- UNSW-NB15 is a lab-generated dataset; the results are not evidence of real-world performance.
- Live monitoring needs Npcap and Administrator rights on Windows and should only be used on authorized traffic. Detection re-runs on a rolling window, so short windows give unstable statistics.

## Future Improvements
- Per-feature statistical detection.
- Evaluation on additional datasets (e.g., CIC-IDS2017).
- Time-based trend charts and an alert log for live monitoring.
- A supervised model trained on features that live capture can actually produce.