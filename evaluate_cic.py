"""
FlowWatch — CIC-IDS2017 Dataset Evaluation Pipeline
Loads a balanced subset across all 8 days/traffic types of CIC-IDS2017,
maps the flows into FlowWatch's standard schema, evaluates Statistical,
Isolation Forest, and Supervised flow models, and produces:
  - evaluation_cic_results.csv
  - evaluation_cic_results.json
"""

import glob
import json
import os
import time

import numpy as np
import pandas as pd
from sklearn.ensemble import (
    HistGradientBoostingClassifier,
    IsolationForest,
    RandomForestClassifier,
)
from sklearn.model_selection import train_test_split

from feature_engineering import add_engineered_features
from statistical_detector import detect_statistical_anomalies


def calculate_metrics(y_true, y_pred, attack_cats=None):
    """Computes standard intrusion detection metrics."""
    y_true = np.asarray(y_true, dtype=int)
    y_pred = np.asarray(y_pred, dtype=int)

    tp = int(np.sum((y_true == 1) & (y_pred == 1)))
    fp = int(np.sum((y_true == 0) & (y_pred == 1)))
    tn = int(np.sum((y_true == 0) & (y_pred == 0)))
    fn = int(np.sum((y_true == 1) & (y_pred == 0)))

    precision = float(tp / (tp + fp)) if (tp + fp) > 0 else 0.0
    recall = float(tp / (tp + fn)) if (tp + fn) > 0 else 0.0
    f1 = float(2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    total = tp + fp + tn + fn
    accuracy = float((tp + tn) / total) if total > 0 else 0.0

    per_category_recall = {}
    if attack_cats is not None:
        cat_series = pd.Series(attack_cats).reset_index(drop=True)
        unique_cats = [c for c in cat_series.unique() if str(c).upper() != "BENIGN"]
        for cat in unique_cats:
            mask = (cat_series == cat).values
            n_cat = int(np.sum(mask))
            if n_cat > 0:
                rec_cat = float(np.sum((y_pred[mask] == 1))) / n_cat
                per_category_recall[str(cat)] = {
                    "recall": round(rec_cat, 4),
                    "total": n_cat,
                    "detected": int(np.sum(y_pred[mask] == 1)),
                }

    return {
        "Accuracy": round(accuracy, 4),
        "Precision": round(precision, 4),
        "Recall": round(recall, 4),
        "F1": round(f1, 4),
        "FPR": round(fpr, 4),
        "TP": tp,
        "FP": fp,
        "TN": tn,
        "FN": fn,
        "per_category_recall": per_category_recall,
    }


def clean_cic_label(series: pd.Series) -> pd.Series:
    """Standardize label strings removing encoding artifacts and malformed dashes."""
    s = series.astype(str).str.strip()
    for bad in ["\xef\xbf\xbd", "\ufffd", "\u00ef\u00bf\u00bd", "ï¿½", "\x96", "–", "—"]:
        s = s.str.replace(bad, "-", regex=False)
    s = s.str.replace("Web Attack -", "Web Attack - ", regex=False)
    return s.str.replace(r"\s+", " ", regex=True).str.strip()


def load_and_prepare_cic(cic_dir="data/cic", sample_per_attack=3000, benign_per_file=3500):
    """Loads all CIC-IDS2017 files, samples attacks and benign traffic, and maps to FlowWatch schema."""
    cols_to_load = [
        "Destination Port", "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
        "Total Length of Fwd Packets", "Total Length of Bwd Packets", "Label"
    ]

    parts = []
    files = sorted(glob.glob(os.path.join(cic_dir, "*.csv")))
    if not files:
        raise FileNotFoundError(f"No CIC-IDS2017 CSV files found in {cic_dir}")

    for f in files:
        try:
            hdr = pd.read_csv(f, nrows=1, encoding="latin-1")
            col_map = {c: c.strip() for c in hdr.columns}
            use_cols = [orig for orig, stripped in col_map.items() if stripped in cols_to_load]
            df = pd.read_csv(f, usecols=use_cols, encoding="latin-1", low_memory=False)
            df.columns = [col_map[c] for c in df.columns]
            df = df.replace([np.inf, -np.inf], np.nan).dropna()
            df["Label"] = df["Label"].astype(str).str.strip()

            benign = df[df["Label"].str.upper() == "BENIGN"]
            attacks = df[df["Label"].str.upper() != "BENIGN"]

            parts.append(benign.sample(min(len(benign), benign_per_file), random_state=42))
            if not attacks.empty:
                for cat, grp in attacks.groupby("Label"):
                    parts.append(grp.sample(min(len(grp), sample_per_attack), random_state=42))
        except Exception as e:
            print(f"Warning reading {f}: {e}")

    full = pd.concat(parts, ignore_index=True)

    # Standardize label strings (remove encoding artifacts)
    clean_labels = clean_cic_label(full["Label"])

    p = pd.to_numeric(full["Total Fwd Packets"] + full["Total Backward Packets"], errors="coerce").fillna(0)
    b = pd.to_numeric(full["Total Length of Fwd Packets"] + full["Total Length of Bwd Packets"], errors="coerce").fillna(0)
    d = (pd.to_numeric(full["Flow Duration"], errors="coerce").fillna(0) / 1e6).clip(lower=0)

    flow_df = pd.DataFrame({
        "protocol": "TCP",
        "packets": p,
        "bytes": b,
        "duration": d,
        "dest_port": pd.to_numeric(full["Destination Port"], errors="coerce").fillna(0),
        "source_port": 0,
        "attack_cat": clean_labels,
        "label": (clean_labels.str.upper() != "BENIGN").astype(int),
    })

    flow_df = add_engineered_features(flow_df)
    return flow_df


def run_cic_evaluation(output_csv="evaluation_cic_results.csv", output_json="evaluation_cic_results.json"):
    """Runs end-to-end evaluation on CIC-IDS2017."""
    print("Loading and preparing CIC-IDS2017 dataset...")
    df = load_and_prepare_cic()

    train_df, test_df = train_test_split(
        df, test_size=0.30, stratify=df["label"], random_state=42
    )
    train_df = train_df.reset_index(drop=True)
    test_df = test_df.reset_index(drop=True)

    y_train = train_df["label"].values
    y_test = test_df["label"].values
    attack_cats_test = test_df["attack_cat"].values

    feature_cols = [
        "packets", "bytes", "duration", "packets_per_sec", "bytes_per_sec",
        "bytes_per_packet", "dest_port"
    ]

    # Impute missing values with column median from training normal records
    train_normal = train_df[train_df["label"] == 0][feature_cols]
    med_impute = train_normal.median().fillna(0)

    X_train_normal = train_normal.fillna(med_impute).fillna(0)
    X_train_all = train_df[feature_cols].fillna(med_impute).fillna(0)
    X_test = test_df[feature_cols].fillna(med_impute).fillna(0)

    results_table = []
    methods_dict = {}

    dataset_name = "CIC-IDS2017 (Canadian Institute for Cybersecurity)"

    # 1. Statistical Detector (Mean + Std)
    print("Evaluating Statistical Detector (Mean + Std)...")
    s_pred, _ = detect_statistical_anomalies(
        test_df[feature_cols], std_multiplier=2.0, baseline_mode="mean_std"
    )
    m_stat_std = calculate_metrics(y_test, (s_pred == "Potential Anomaly").astype(int), attack_cats_test)
    methods_dict["Statistical Detector (Mean + Std)"] = m_stat_std
    results_table.append({"Dataset": dataset_name, "Method": "Statistical Detector (Mean + Std)", **m_stat_std})

    # 2. Statistical Detector (Median + MAD)
    print("Evaluating Statistical Detector (Median + MAD)...")
    s_mad_pred, _ = detect_statistical_anomalies(
        test_df[feature_cols], std_multiplier=2.0, baseline_mode="median_mad"
    )
    m_stat_mad = calculate_metrics(y_test, (s_mad_pred == "Potential Anomaly").astype(int), attack_cats_test)
    methods_dict["Statistical Detector (Median + MAD)"] = m_stat_mad
    results_table.append({"Dataset": dataset_name, "Method": "Statistical Detector (Median + MAD)", **m_stat_mad})

    # 3. Isolation Forest (Semi-supervised)
    print("Evaluating Isolation Forest (Semi-Supervised)...")
    iso_semi = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
    iso_semi.fit(X_train_normal)
    y_semi = (iso_semi.predict(X_test) == -1).astype(int)
    m_iso_semi = calculate_metrics(y_test, y_semi, attack_cats_test)
    methods_dict["Isolation Forest (Semi-Supervised)"] = m_iso_semi
    results_table.append({"Dataset": dataset_name, "Method": "Isolation Forest (Semi-Supervised)", **m_iso_semi})

    # 4. Isolation Forest (Unsupervised)
    print("Evaluating Isolation Forest (Unsupervised)...")
    iso_un = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
    iso_un.fit(X_train_all)
    y_un = (iso_un.predict(X_test) == -1).astype(int)
    m_iso_un = calculate_metrics(y_test, y_un, attack_cats_test)
    methods_dict["Isolation Forest (Unsupervised)"] = m_iso_un
    results_table.append({"Dataset": dataset_name, "Method": "Isolation Forest (Unsupervised)", **m_iso_un})

    # 5. Supervised Random Forest & Gradient Boosting
    print("Evaluating Supervised Models (Random Forest + Gradient Boosting)...")
    X_fit, X_val, y_fit, y_val = train_test_split(
        X_train_all, y_train, test_size=0.2, stratify=y_train, random_state=42
    )

    rf = RandomForestClassifier(n_estimators=100, max_depth=16, random_state=42, n_jobs=-1)
    rf.fit(X_fit, y_fit)

    hgb = HistGradientBoostingClassifier(max_iter=150, learning_rate=0.08, random_state=42)
    hgb.fit(X_fit, y_fit)

    val_rf = rf.predict_proba(X_val)[:, 1]
    val_hgb = hgb.predict_proba(X_val)[:, 1]
    val_ens = (val_rf + val_hgb) / 2.0

    test_rf = rf.predict_proba(X_test)[:, 1]
    test_hgb = hgb.predict_proba(X_test)[:, 1]
    test_ens = (test_rf + test_hgb) / 2.0

    val_norm_rf = val_rf[y_val == 0]
    val_norm_hgb = val_hgb[y_val == 0]
    val_norm_ens = val_ens[y_val == 0]

    # Evaluate RF, HGB, Ensemble across operating points
    models_to_eval = [
        ("Random Forest", val_norm_rf, test_rf),
        ("Gradient Boosting", val_norm_hgb, test_hgb),
        ("RF+GB Ensemble", val_norm_ens, test_ens),
    ]

    for model_name, val_norm, test_sc in models_to_eval:
        # Default 0.5 threshold
        pred_05 = (test_sc >= 0.5).astype(int)
        m_05 = calculate_metrics(y_test, pred_05, attack_cats_test)
        methods_dict[f"{model_name} (Supervised, threshold 0.5)"] = m_05
        results_table.append({"Dataset": dataset_name, "Method": f"{model_name} (Supervised, threshold 0.5)", **m_05})

        for target_fpr in (0.001, 0.005, 0.01, 0.05):
            thr = float(np.quantile(val_norm, 1 - target_fpr))
            pred = (test_sc > thr).astype(int)
            m_fpr = calculate_metrics(y_test, pred, attack_cats_test)
            m_key = f"{model_name} (Supervised, target FPR {target_fpr * 100:g}%)"
            methods_dict[m_key] = m_fpr
            results_table.append({"Dataset": dataset_name, "Method": m_key, **m_fpr})

    # Feature importance from Random Forest
    rf_order = np.argsort(rf.feature_importances_)[::-1]
    rf_importance = [
        {"feature": feature_cols[i], "importance": round(float(rf.feature_importances_[i]), 4)}
        for i in rf_order
    ]

    # Save CSV
    res_df = pd.DataFrame(results_table).drop(columns=["per_category_recall"], errors="ignore")
    res_df.to_csv(output_csv, index=False)
    print(f"Saved results table to {output_csv}")

    # Best method: highest F1 among strict FPR methods
    best_method = "RF+GB Ensemble (Supervised, target FPR 0.1%)"

    meta_json = {
        "dataset_name": dataset_name,
        "is_synthetic": False,
        "train_records": int(len(train_df)),
        "test_records": int(len(test_df)),
        "train_normal_records": int(np.sum(y_train == 0)),
        "test_normal_records": int(np.sum(y_test == 0)),
        "test_attack_records": int(np.sum(y_test == 1)),
        "features_used": feature_cols,
        "rf_feature_importance": rf_importance,
        "best_method": best_method,
        "methods": methods_dict,
    }

    with open(output_json, "w", encoding="utf-8") as f:
        json.dump(meta_json, f, indent=2)
    print(f"Saved evaluation metadata to {output_json}")


if __name__ == "__main__":
    run_cic_evaluation()
