import os
import sys
import numpy as np
import pandas as pd

from data_loader import load_network_data
from feature_engineering import add_engineered_features
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
        print("\n==================================================")
        print(" ALL TESTS PASSED! All features verified working.")
        print("==================================================")
    except AssertionError as e:
        print(f"\n[FAIL] Test assertion failed: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n[ERROR] Unexpected error: {e}")
        sys.exit(1)
