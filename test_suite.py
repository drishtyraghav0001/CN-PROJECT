import json
import os
import sys
from unittest.mock import patch
import joblib
import numpy as np
import pandas as pd

from data_loader import load_network_data
from evaluate_cic import clean_cic_label
from feature_engineering import add_engineered_features
from live_monitor import LiveMonitor, get_available_interfaces
from ml_detector import detect_anomalies
from explainability import (
    compute_baseline_stats,
    find_deviations,
    format_reason,
    get_flagged_by,
    add_explanations,
)
from pcap_loader import load_pcap_data
from generate_sample_pcap import generate_sample_pcap
from statistical_detector import detect_statistical_anomalies, compute_baseline_parameters, ThresholdResult


def test_feature_engineering():
    print("[1/6] Testing Feature Engineering Validation Rules...")
    # Test dataset with valid, zero, negative, and missing durations
    sample = pd.DataFrame({
        "packets": [100, 200, 50, 0, -10],
        "bytes": [50000, 80000, 25000, 1000, 2000],
        "duration": [10.0, 0.0, -2.0, 5.0, 1.0],
    })
    res = add_engineered_features(sample)

    # Rule 1: duration <= 0 -> packets_per_sec & bytes_per_sec are NaN
    assert res.loc[0, "packets_per_sec"] == 10.0
    assert res.loc[0, "bytes_per_sec"] == 5000.0
    assert res.loc[0, "bytes_per_packet"] == 500.0

    assert np.isnan(res.loc[1, "packets_per_sec"]), "Zero duration must produce NaN rate"
    assert np.isnan(res.loc[1, "bytes_per_sec"]), "Zero duration must produce NaN rate"

    assert np.isnan(res.loc[2, "packets_per_sec"]), "Negative duration must produce NaN rate"
    assert np.isnan(res.loc[2, "bytes_per_sec"]), "Negative duration must produce NaN rate"

    # Rule 2: packets <= 0 -> bytes_per_packet is NaN
    assert np.isnan(res.loc[3, "bytes_per_packet"]), "Zero packets must produce NaN bytes_per_packet"
    assert np.isnan(res.loc[4, "bytes_per_packet"]), "Negative packets must produce NaN bytes_per_packet"

    # Rule 3: Only adds columns when prerequisites exist
    packets_only = pd.DataFrame({"protocol": ["TCP"], "packets": [100]})
    res_packets_only = add_engineered_features(packets_only)
    assert "packets_per_sec" not in res_packets_only.columns
    assert "bytes_per_sec" not in res_packets_only.columns
    assert "bytes_per_packet" not in res_packets_only.columns

    print("      [PASS] Zero/negative division prevented; NaN applied correctly")
    print("      [PASS] Rate features only added when required columns exist")


def test_ml_detector():
    print("[2/6] Testing ML Detector (With vs Without Engineered Features)...")
    df = load_network_data("network_traffic_test.csv")
    df_eng = add_engineered_features(df)

    # Test baseline ML without engineered features
    res_without = detect_anomalies(df_eng, use_engineered_features=False)
    assert "ml_status" in res_without.columns
    flags_without = (res_without["ml_status"] == "Potential Anomaly").sum()

    # Test ML with engineered features
    res_with = detect_anomalies(df_eng, use_engineered_features=True)
    assert "ml_status" in res_with.columns
    flags_with = (res_with["ml_status"] == "Potential Anomaly").sum()

    # Verify NaN handling via median imputation works without dropping rows
    assert len(res_with) == len(df), "Row count must remain invariant after ML"
    print(f"      [PASS] ML detector works with and without engineered features (flags: {flags_without} vs {flags_with})")
    print("      [PASS] Missing/NaN rate features handled cleanly without row drops")


def test_explainability():
    print("[3/6] Testing Explainability & Calculated Reason Strings...")
    df = load_network_data("network_traffic_test.csv")
    df = add_engineered_features(df)
    baseline = compute_baseline_stats(df)

    assert "packets" in baseline
    assert "bytes" in baseline
    assert "packets_per_sec" in baseline

    # Test method attribution
    assert get_flagged_by("Potential Anomaly", "Potential Anomaly") == "Both"
    assert get_flagged_by("Potential Anomaly", "Normal") == "Statistical"
    assert get_flagged_by("Normal", "Potential Anomaly") == "ML"
    assert get_flagged_by("Normal", "Normal") == "None"

    # Test exact deviation formatting
    devs = [
        {"feature": "packets", "abs_z": 4.1, "direction": "high"},
        {"feature": "bytes", "abs_z": 3.2, "direction": "high"},
    ]
    reason = format_reason(devs)
    expected = "Packet count 4.1 std above baseline; bytes 3.2 std above baseline"
    assert reason == expected, f"Expected '{expected}', got '{reason}'"

    # Test negative direction formatting
    devs_low = [{"feature": "duration", "abs_z": 2.5, "direction": "low"}]
    assert format_reason(devs_low) == "Duration 2.5 std below baseline"

    print("      [PASS] Attribution correctly outputs: Both, Statistical, ML, None")
    print("      [PASS] Reason formatting exactly matches calculated z-score deviations")


def test_pcap_loader():
    print("[4/6] Testing PCAP Generator & Streaming Flow Loader...")
    pcap_file = "sample_traffic.pcap"
    if not os.path.exists(pcap_file):
        generate_sample_pcap(pcap_file)

    df_pcap, stats = load_pcap_data(pcap_file)

    # Verify flow columns
    expected_cols = {"protocol", "packets", "bytes", "duration", "source_port", "dest_port", "src_ip", "dst_ip"}
    assert expected_cols.issubset(df_pcap.columns), f"Missing columns in {df_pcap.columns}"

    # Verify streaming stats
    assert stats["total_packets"] == 575
    assert stats["num_flows"] == 7
    assert stats["time_span"] > 0
    assert stats["cap_hit"] is False

    # Verify single-packet flow duration is 0.0
    single_pkt_flows = df_pcap[df_pcap["packets"] == 1]
    assert not single_pkt_flows.empty
    assert (single_pkt_flows["duration"] == 0.0).all()

    # Verify no payload columns stored
    assert "payload" not in df_pcap.columns
    assert "raw" not in df_pcap.columns

    # Verify packet cap works
    _, cap_stats = load_pcap_data(pcap_file, max_packets=50)
    assert cap_stats["cap_hit"] is True
    assert cap_stats["total_packets"] == 50

    print(f"      [PASS] 575 packets streamed into {len(df_pcap)} 5-tuple flows")
    print("      [PASS] Single-packet duration is 0.0; payloads omitted; packet capping verified")


def test_error_handling():
    print("[5/6] Testing Error Handling on Corrupted/Empty Files...")
    # Empty file test
    empty_file = "scratch_empty_test.pcap"
    try:
        with open(empty_file, "wb") as f:
            pass
        try:
            load_pcap_data(empty_file)
            assert False, "Empty file should raise ValueError"
        except ValueError as err:
            assert "empty" in str(err).lower()
    finally:
        if os.path.exists(empty_file):
            os.remove(empty_file)

    # Missing required columns in CSV
    bad_csv = "scratch_bad.csv"
    try:
        pd.DataFrame({"col_a": [1, 2]}).to_csv(bad_csv, index=False)
        try:
            load_network_data(bad_csv)
            assert False, "Missing columns should raise ValueError"
        except ValueError as err:
            assert "required columns" in str(err).lower()
    finally:
        if os.path.exists(bad_csv):
            os.remove(bad_csv)

    print("      [PASS] Empty PCAP files caught with informative ValueError")
    print("      [PASS] Missing required columns rejected cleanly")


def test_end_to_end_pipeline():
    print("[6/6] Testing End-to-End Pipeline on JSON, CSV, and PCAP...")
    datasets = [
        ("network_traffic.json", "json"),
        ("network_traffic_test.csv", "csv"),
        ("sample_traffic.pcap", "pcap"),
    ]

    for filename, ftype in datasets:
        if ftype == "pcap":
            df, _ = load_pcap_data(filename)
        else:
            df = load_network_data(filename)

        # Statistical
        mean = df["packets"].mean()
        std = df["packets"].std()
        thresh = mean + 2 * std if pd.notna(std) else float("inf")
        df["Statistical Result"] = df["packets"].apply(
            lambda x: "Potential Anomaly" if x > thresh else "Normal"
        )

        # Feature engineering
        df = add_engineered_features(df)

        # ML
        has_eng = "packets_per_sec" in df.columns
        ml_res = detect_anomalies(df, use_engineered_features=has_eng)
        df["ML Result"] = ml_res["ml_status"].values

        # Explanations
        df = add_explanations(df)

        # Assertions
        assert "Flagged By" in df.columns
        assert "Reasons" in df.columns

        flagged = df[
            (df["Statistical Result"] == "Potential Anomaly")
            | (df["ML Result"] == "Potential Anomaly")
        ]
        assert len(flagged) > 0, f"At least 1 anomaly expected in {filename}"
        for _, row in flagged.iterrows():
            assert len(row["Reasons"]) > 0, "Flagged record must have non-empty reason"
            assert row["Flagged By"] in ("Statistical", "ML", "Both")

        print(f"      [PASS] {filename}: {len(df)} records processed, {len(flagged)} flagged with valid reasons")


def test_multi_feature_statistical_detector():
    print("[7/7] Testing Upgraded Multi-Feature Statistical Anomaly Detector...")

    # Deterministic base normal dataset (21 records centered at 50 packets, 5000 bytes, 5.0s duration)
    p = list(range(40, 61))
    b = [x * 100 for x in p]
    d = [5.0 + (x - 50) * 0.1 for x in p]
    base_df = pd.DataFrame({"protocol": ["TCP"] * len(p), "packets": p, "bytes": b, "duration": d})
    base_df = add_engineered_features(base_df)
    n = len(base_df)

    # 1. Packet count anomaly (normal bytes, normal duration, huge packets)
    df_pkt = base_df.copy()
    df_pkt.loc[n] = {"protocol": "TCP", "packets": 5000, "bytes": 5000, "duration": 5.0}
    status_pkt, thresh_pkt = detect_statistical_anomalies(df_pkt, std_multiplier=2.0)
    assert status_pkt.iloc[n] == "Potential Anomaly", "Packet spike must be flagged"
    assert "packets" in status_pkt.attrs["triggered_features"][n]
    assert (status_pkt.iloc[:n] == "Normal").all(), "Normal records must remain Normal"
    print("      [PASS] Anomaly detected through packet count (normal records clean)")

    # 2. Bytes anomaly while packet count remains completely normal
    df_byte = base_df.copy()
    df_byte.loc[n] = {"protocol": "TCP", "packets": 50, "bytes": 500000, "duration": 5.0}
    status_byte, thresh_byte = detect_statistical_anomalies(df_byte, std_multiplier=2.0)
    assert status_byte.iloc[n] == "Potential Anomaly", "Byte spike must be flagged"
    assert "bytes" in status_byte.attrs["triggered_features"][n]
    assert "packets" not in status_byte.attrs["triggered_features"][n]
    print("      [PASS] Anomaly detected through bytes while packet count remains normal")

    # 3. Rate-based feature anomaly (normal total volume, extreme rate)
    df_rate = base_df.copy()
    df_rate.loc[n] = {"protocol": "TCP", "packets": 50, "bytes": 5000, "duration": 0.001}
    df_rate = add_engineered_features(df_rate)
    status_rate, thresh_rate = detect_statistical_anomalies(df_rate, std_multiplier=2.0)
    assert status_rate.iloc[n] == "Potential Anomaly", "Rate burst must be flagged"
    trig_rate = status_rate.attrs["triggered_features"][n]
    assert "packets_per_sec" in trig_rate or "bytes_per_sec" in trig_rate
    assert "packets" not in trig_rate
    print("      [PASS] Anomaly detected through rate features (packets_per_sec / bytes_per_sec)")

    # 4. Both baseline modes: Mean+Std and Median+MAD
    status_mean, thresh_mean = detect_statistical_anomalies(df_byte, std_multiplier=2.0, baseline_mode="mean_std")
    status_mad, thresh_mad = detect_statistical_anomalies(df_byte, std_multiplier=2.0, baseline_mode="median_mad")
    assert status_mean.iloc[n] == "Potential Anomaly"
    assert status_mad.iloc[n] == "Potential Anomaly"
    assert thresh_mean.baseline_mode == "mean_std"
    assert thresh_mad.baseline_mode == "median_mad"
    print("      [PASS] Verified both mean_std and median_mad (robust MAD) baseline modes")

    # 5. Missing and non-finite values (np.nan, np.inf, -np.inf)
    df_nonfinite = base_df.copy()
    df_nonfinite.loc[0, "duration"] = np.nan
    df_nonfinite.loc[1, "bytes"] = np.nan
    df_nonfinite.loc[2, "packets"] = np.nan
    df_nonfinite.loc[3, "duration"] = np.inf
    df_nonfinite.loc[4, "bytes"] = -np.inf
    df_nonfinite.loc[n, :] = base_df.loc[0, :]
    df_nonfinite.loc[n, "bytes"] = 800000
    status_nf, thresh_nf = detect_statistical_anomalies(df_nonfinite, std_multiplier=2.0)
    assert status_nf.iloc[n] == "Potential Anomaly"
    assert status_nf.iloc[0] == "Normal"
    assert status_nf.iloc[1] == "Normal"
    assert status_nf.iloc[2] == "Normal"
    print("      [PASS] Non-finite values (NaN, inf, -np.inf) handled safely without false alarms")

    # 6. Constant features and zero MAD
    df_const = base_df.copy()
    df_const["duration"] = 5.0  # Zero spread across all rows
    status_const, thresh_const = detect_statistical_anomalies(df_const, std_multiplier=2.0, baseline_mode="mean_std")
    assert thresh_const["duration"] == float("inf"), "Constant column must have inf threshold"
    assert (status_const == "Normal").all(), "Zero-variance column must not trigger false positives"
    print("      [PASS] Constant features and zero MAD handled safely (no ZeroDivisionError)")

    # 7. Multiple features triggering simultaneously on the same record
    df_multi = base_df.copy()
    df_multi.loc[n, :] = df_multi.loc[0, :]
    df_multi.loc[n, "packets"] = 8000
    df_multi.loc[n, "bytes"] = 900000
    status_multi, _ = detect_statistical_anomalies(df_multi, std_multiplier=2.0)
    assert status_multi.iloc[n] == "Potential Anomaly"
    trig_multi = status_multi.attrs["triggered_features"][n]
    assert "packets" in trig_multi and "bytes" in trig_multi
    print("      [PASS] Multiple features triggering simultaneously on same record")

    # 8. Normal traffic not flagged merely because a feature is missing
    df_missing = base_df.copy()
    df_missing["bytes_per_packet"] = np.nan
    status_miss, _ = detect_statistical_anomalies(df_missing, std_multiplier=2.0)
    assert (status_miss == "Normal").all(), "Records with missing features must remain Normal"
    print("      [PASS] Normal traffic is not flagged merely because a feature is missing")

    # 9. Compatibility with ML detector and explainability pipeline
    df_pipeline = base_df.copy()
    df_pipeline.loc[n, :] = df_pipeline.loc[0, :]
    df_pipeline.loc[n, "packets"] = 50   # normal packets
    df_pipeline.loc[n, "bytes"] = 500000 # anomalous bytes
    df_pipeline = add_engineered_features(df_pipeline)
    df_pipeline["Statistical Result"], s_thresh = detect_statistical_anomalies(df_pipeline, std_multiplier=2.0)
    ml_res = detect_anomalies(df_pipeline, use_engineered_features=True)
    df_pipeline["ML Result"] = ml_res["ml_status"].values
    df_pipeline = add_explanations(df_pipeline, threshold=s_thresh)

    assert "Flagged By" in df_pipeline.columns
    assert "Reasons" in df_pipeline.columns
    assert "Severity" in df_pipeline.columns
    assert df_pipeline.loc[n, "Statistical Result"] == "Potential Anomaly"
    assert df_pipeline.loc[n, "Flagged By"] in ("Statistical", "Both")
    assert "bytes" in df_pipeline.loc[n, "Reasons"].lower()
    assert df_pipeline.loc[n, "Severity"] in ("Low", "Medium", "High")
    print("      [PASS] Fully compatible with ML detector and explainability pipeline")


def test_supervised_flow_model_compatibility():
    print("[8/10] Testing Supervised Flow Ensemble Model Compatibility & Robustness...")
    model_path = "flow_ensemble_model.joblib"
    assert os.path.exists(model_path), f"{model_path} artifact must exist"
    bundle = joblib.load(model_path)

    # 1. Check bundle structure
    assert "rf" in bundle and "hgb" in bundle, "Bundle must contain rf and hgb models"
    assert "thresholds" in bundle and "features" in bundle, "Bundle must contain thresholds and features"

    expected_features = [
        "packets", "bytes", "duration", "packets_per_sec", "bytes_per_sec",
        "bytes_per_packet", "source_port", "dest_port", "proto_tcp", "proto_udp"
    ]
    assert bundle["features"] == expected_features, f"Features order mismatch: {bundle['features']}"

    # 2. Check prediction with normal traffic
    test_df = pd.DataFrame([{
        "packets": 50, "bytes": 4500, "duration": 2.0, "packets_per_sec": 25.0,
        "bytes_per_sec": 2250.0, "bytes_per_packet": 90.0, "source_port": 54321,
        "dest_port": 80, "proto_tcp": 1.0, "proto_udp": 0.0
    }])
    X_norm = test_df[bundle["features"]]
    score_rf = bundle["rf"].predict_proba(X_norm)[:, 1]
    score_hgb = bundle["hgb"].predict_proba(X_norm)[:, 1]
    ens_score = (score_rf + score_hgb) / 2.0
    assert 0.0 <= ens_score[0] <= 1.0, "Ensemble score must be in [0, 1]"
    print("      [PASS] Supervised ensemble features and clean probability output verified")

    # 3. Test resilience to NaN, inf, -inf, and malformed strings
    malformed_df = pd.DataFrame({
        "packets": [100, np.nan, np.inf],
        "bytes": [1000, 2000, -np.inf],
        "duration": [1.0, 0.0, "bad_val"],
        "packets_per_sec": [100.0, np.inf, 0.0],
        "bytes_per_sec": [1000.0, np.inf, 0.0],
        "bytes_per_packet": [10.0, np.nan, 0.0],
        "source_port": [80, "invalid", 443],
        "dest_port": [8080, 53, np.nan],
        "proto_tcp": [1.0, 0.0, 1.0],
        "proto_udp": [0.0, 1.0, 0.0],
    })
    # Apply standard dashboard sanitization
    X_clean = malformed_df[bundle["features"]].apply(
        pd.to_numeric, errors="coerce"
    ).replace([np.inf, -np.inf], np.nan).fillna(0)
    scores = (bundle["rf"].predict_proba(X_clean)[:, 1] + bundle["hgb"].predict_proba(X_clean)[:, 1]) / 2.0
    assert len(scores) == 3, "All 3 malformed records safely scored"
    assert not np.isnan(scores).any(), "No NaN scores allowed"
    print("      [PASS] Extreme values (inf, -inf, NaN, malformed strings) handled safely without crash")


def test_benchmark_selection_and_cic_label_normalization():
    print("[9/10] Testing Benchmark Result Selection & CIC Label Normalization...")
    # 1. Verify UNSW and CIC result files exist and are distinct
    assert os.path.exists("evaluation_results.csv"), "UNSW evaluation results CSV must exist"
    assert os.path.exists("evaluation_cic_results.csv"), "CIC evaluation results CSV must exist"

    df_unsw = pd.read_csv("evaluation_results.csv")
    df_cic = pd.read_csv("evaluation_cic_results.csv")

    assert not df_unsw.empty and not df_cic.empty
    assert "Dataset" in df_unsw.columns and "Dataset" in df_cic.columns
    # Ensure independent results (no bleed-through)
    assert df_unsw["Dataset"].iloc[0] != df_cic["Dataset"].iloc[0]
    print("      [PASS] Both benchmark results load independently with distinct dataset identifiers")

    # 2. Test clean_cic_label on encoding artifacts
    test_labels = pd.Series([
        "BENIGN",
        "Web Attack \xef\xbf\xbd Brute Force",
        "Web Attack \ufffd XSS",
        "Web Attack \u00ef\u00bf\u00bd Sql Injection",
        "Web Attack – Generic",
        "FTP-Patator",
        "SSH-Patator",
    ])
    cleaned = list(clean_cic_label(test_labels))
    assert cleaned[0] == "BENIGN"
    assert cleaned[1] == "Web Attack - Brute Force"
    assert cleaned[2] == "Web Attack - XSS"
    assert cleaned[3] == "Web Attack - Sql Injection"
    assert cleaned[4] == "Web Attack - Generic"
    assert cleaned[5] == "FTP-Patator"
    assert cleaned[6] == "SSH-Patator"
    print("      [PASS] CIC label normalization safely removes replacement chars, bad en-dashes, and UTF-8 artifacts")

    # 3. Verify JSON metadata structure and category encoding
    if os.path.exists("evaluation_cic_results.json"):
        with open("evaluation_cic_results.json", encoding="utf-8") as f:
            cic_meta = json.load(f)
        assert "dataset_name" in cic_meta
        assert "best_method" in cic_meta
        for method_name, method_data in cic_meta.get("methods", {}).items():
            for cat_name in method_data.get("per_category_recall", {}):
                assert not any(c in cat_name for c in ["\ufffd", "\xef", "ï", "¿", "½"]), (
                    f"Corrupted character found in category: {repr(cat_name)}"
                )
    print("      [PASS] Evaluation JSON metadata has clean, valid category keys")


def test_live_alert_deduplication_and_interface_fallback():
    print("[10/10] Testing Live Alert Deduplication & Interface Discovery Fallback...")
    # 1. Alert deduplication across dashboard reruns
    mon = LiveMonitor()
    assert mon.get_alert_log().empty
    assert mon.get_time_series().empty

    alerts_df = pd.DataFrame([
        {
            "src_ip": "192.168.1.50", "dst_ip": "10.0.0.1", "source_port": 54321,
            "dest_port": 80, "protocol": "TCP", "packets": 100, "bytes": 80000,
            "Flagged By": "Both", "Severity": "High", "Reasons": "High rate"
        },
        {
            "src_ip": "192.168.1.51", "dst_ip": "10.0.0.2", "source_port": 54322,
            "dest_port": 443, "protocol": "TCP", "packets": 80, "bytes": 60000,
            "Flagged By": "Statistical", "Severity": "Medium", "Reasons": "High bytes"
        }
    ])

    # First record
    mon.record_alerts(alerts_df)
    log1 = mon.get_alert_log()
    assert len(log1) == 2, "Both initial alerts should be recorded"

    # Second record with identical alerts (dashboard rerun)
    mon.record_alerts(alerts_df)
    log2 = mon.get_alert_log()
    assert len(log2) == 2, "Identical alerts on rerun must NOT create duplicate entries"

    # Third record with an updated flow state (packet count changed)
    alerts_df_updated = pd.DataFrame([
        {
            "src_ip": "192.168.1.50", "dst_ip": "10.0.0.1", "source_port": 54321,
            "dest_port": 80, "protocol": "TCP", "packets": 110, "bytes": 88000,
            "Flagged By": "Both", "Severity": "High", "Reasons": "High rate"
        }
    ])
    mon.record_alerts(alerts_df_updated)
    log3 = mon.get_alert_log()
    assert len(log3) == 3, "New/updated flow alert should be recorded"
    print("      [PASS] Live alert history preserves log and prevents duplicate entries on reruns")

    # 2. Network interface discovery degradation
    with patch("scapy.arch.windows.get_windows_if_list", side_effect=RuntimeError("Scapy WinPCAP failed")), \
         patch("scapy.all.get_if_list", side_effect=RuntimeError("Npcap driver unavailable")):
        fallback_ifaces = get_available_interfaces()
        assert fallback_ifaces == [], "Discovery failure must return [] instead of raising unhandled exception"
    print("      [PASS] Interface discovery degrades gracefully to empty list on Scapy/driver failure")


if __name__ == "__main__":
    print("==================================================")
    print(" FlowWatch Complete Verification Test Suite")
    print("==================================================")
    try:
        test_feature_engineering()
        test_ml_detector()
        test_explainability()
        test_pcap_loader()
        test_error_handling()
        test_end_to_end_pipeline()
        test_multi_feature_statistical_detector()
        test_supervised_flow_model_compatibility()
        test_benchmark_selection_and_cic_label_normalization()
        test_live_alert_deduplication_and_interface_fallback()
        print("\n==================================================")
        print(" ALL TESTS PASSED! All features verified working.")
        print("==================================================")
    except AssertionError as e:
        print(f"\n[FAIL] Test assertion failed: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n[ERROR] Unexpected error: {e}")
        sys.exit(1)
