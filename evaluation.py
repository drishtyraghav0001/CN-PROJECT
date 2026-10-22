import os
import json
import joblib
from pathlib import Path
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier, HistGradientBoostingClassifier
from sklearn.metrics import precision_recall_curve
from sklearn.model_selection import train_test_split

from feature_engineering import add_engineered_features
from statistical_detector import detect_statistical_anomalies

# Extra UNSW-NB15 columns used by the extended-feature models (only those present are used).
# stcpb / dtcpb (random TCP sequence numbers) and id (row counter) are excluded on purpose.
EXTRA_NUMERIC = [
    "rate", "sttl", "dttl", "sload", "dload", "sloss", "dloss", "sinpkt", "dinpkt",
    "sjit", "djit", "swin", "dwin", "tcprtt", "synack", "ackdat", "smean", "dmean",
    "trans_depth", "response_body_len", "ct_srv_src", "ct_state_ttl", "ct_dst_ltm",
    "ct_src_dport_ltm", "ct_dst_sport_ltm", "ct_dst_src_ltm", "ct_src_ltm", "ct_srv_dst",
]
EXTRA_CATEGORICAL = ["service", "state"]


# ---------------------------------------------------------------------------
# Data preparation
# ---------------------------------------------------------------------------
def generate_synthetic_labelled_data(output_path="data/labelled_synthetic_sample.csv", n_records=800):
    """
    Generates a synthetic labelled dataset mirroring the UNSW-NB15 schema.
    Used when no external UNSW-NB15 files are placed in data/.
    """
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    np.random.seed(42)

    records = []
    # 70% Normal traffic (label = 0)
    n_normal = int(n_records * 0.70)
    for _ in range(n_normal):
        proto = np.random.choice(["tcp", "udp", "dns", "icmp"], p=[0.6, 0.25, 0.1, 0.05])
        dur = float(np.random.uniform(1.0, 15.0))
        spkts = int(np.random.randint(10, 80))
        dpkts = int(np.random.randint(5, 70))
        sbytes = int(spkts * np.random.randint(200, 700))
        dbytes = int(dpkts * np.random.randint(200, 700))
        records.append({
            "proto": proto,
            "dur": dur,
            "spkts": spkts,
            "dpkts": dpkts,
            "sbytes": sbytes,
            "dbytes": dbytes,
            "attack_cat": "Normal",
            "label": 0,
        })

    # 30% Attack traffic (label = 1) across various attack categories
    attack_types = ["DoS", "Exploits", "Fuzzers", "Reconnaissance", "Generic"]
    n_attack = n_records - n_normal
    for _ in range(n_attack):
        cat = np.random.choice(attack_types)
        proto = np.random.choice(["tcp", "udp", "icmp"], p=[0.7, 0.2, 0.1])
        if cat == "DoS":
            dur = float(np.random.uniform(0.1, 1.5))
            spkts = int(np.random.randint(300, 1500))
            dpkts = int(np.random.randint(0, 50))
            sbytes = int(spkts * np.random.randint(500, 1200))
            dbytes = int(dpkts * 60)
        elif cat == "Reconnaissance":
            dur = float(np.random.uniform(0.01, 2.0))
            spkts = int(np.random.randint(1, 10))
            dpkts = int(np.random.randint(0, 5))
            sbytes = int(spkts * 40)
            dbytes = int(dpkts * 40)
        elif cat == "Exploits":
            dur = float(np.random.uniform(2.0, 8.0))
            spkts = int(np.random.randint(40, 120))
            dpkts = int(np.random.randint(30, 100))
            sbytes = int(spkts * 1400)  # Large payload frames
            dbytes = int(dpkts * 500)
        else:  # Fuzzers / Generic
            dur = float(np.random.uniform(0.5, 5.0))
            spkts = int(np.random.randint(50, 250))
            dpkts = int(np.random.randint(10, 100))
            sbytes = int(spkts * np.random.randint(100, 900))
            dbytes = int(dpkts * np.random.randint(100, 900))

        records.append({
            "proto": proto,
            "dur": dur,
            "spkts": spkts,
            "dpkts": dpkts,
            "sbytes": sbytes,
            "dbytes": dbytes,
            "attack_cat": cat,
            "label": 1,
        })

    df = pd.DataFrame(records)
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    df.to_csv(output_path, index=False)
    print(f"Generated synthetic labelled dataset with {len(df)} records at {output_path}")
    return output_path


def inspect_and_load_unsw(filepath):
    """
    Inspects header of the UNSW-NB15 file, prints columns, and maps them
    into FlowWatch standard schema.

    Expected mapping:
      - label (0 normal / 1 attack) -> ground truth, never used as a feature
      - proto -> protocol
      - dur -> duration
      - spkts + dpkts -> packets
      - sbytes + dbytes -> bytes
      - attack_cat -> kept only for per-category reporting
      - EXTRA_NUMERIC / EXTRA_CATEGORICAL columns are carried along when present
      - source_port does not exist; skipped
    """
    path = Path(filepath)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {filepath}")

    header_preview = pd.read_csv(filepath, nrows=5)
    print(f"\n[Header Inspection for {path.name}]")
    print(f"Raw columns found ({len(header_preview.columns)}): {list(header_preview.columns)}")

    df_raw = pd.read_csv(filepath)
    col_map = {c.strip().lower(): c for c in df_raw.columns}

    # Ground truth label
    if "label" not in col_map:
        raise ValueError("Dataset missing required 'label' column (0 for normal, 1 for attack).")
    labels = pd.to_numeric(df_raw[col_map["label"]], errors="coerce").fillna(0).astype(int)

    # Protocol
    if "proto" in col_map:
        protocol = df_raw[col_map["proto"]].astype(str).str.strip().str.upper()
    elif "protocol" in col_map:
        protocol = df_raw[col_map["protocol"]].astype(str).str.strip().str.upper()
    else:
        protocol = pd.Series(["UNKNOWN"] * len(df_raw))

    # Duration
    if "dur" in col_map:
        duration = pd.to_numeric(df_raw[col_map["dur"]], errors="coerce")
    elif "duration" in col_map:
        duration = pd.to_numeric(df_raw[col_map["duration"]], errors="coerce")
    else:
        duration = pd.Series([np.nan] * len(df_raw))

    # Packets: spkts + dpkts
    if "spkts" in col_map and "dpkts" in col_map:
        spkts = pd.to_numeric(df_raw[col_map["spkts"]], errors="coerce").fillna(0)
        dpkts = pd.to_numeric(df_raw[col_map["dpkts"]], errors="coerce").fillna(0)
        packets = spkts + dpkts
    elif "packets" in col_map:
        packets = pd.to_numeric(df_raw[col_map["packets"]], errors="coerce").fillna(0)
    else:
        raise ValueError("Could not find packets columns (spkts + dpkts, or packets).")

    # Bytes: sbytes + dbytes
    if "sbytes" in col_map and "dbytes" in col_map:
        sbytes = pd.to_numeric(df_raw[col_map["sbytes"]], errors="coerce").fillna(0)
        dbytes = pd.to_numeric(df_raw[col_map["dbytes"]], errors="coerce").fillna(0)
        total_bytes = sbytes + dbytes
    elif "bytes" in col_map:
        total_bytes = pd.to_numeric(df_raw[col_map["bytes"]], errors="coerce").fillna(0)
    else:
        total_bytes = pd.Series([np.nan] * len(df_raw))

    # Attack category (reporting only)
    if "attack_cat" in col_map:
        attack_cat = df_raw[col_map["attack_cat"]].astype(str).str.strip()
    else:
        attack_cat = labels.apply(lambda l: "Attack" if l == 1 else "Normal")

    mapped_df = pd.DataFrame({
        "protocol": protocol,
        "packets": packets,
        "bytes": total_bytes,
        "duration": duration,
        "attack_cat": attack_cat,
        "label": labels,
    })

    # Extra UNSW features (only the ones present in the file)
    for c in EXTRA_NUMERIC:
        if c in col_map:
            mapped_df[c] = pd.to_numeric(df_raw[col_map[c]], errors="coerce").values
    for c in EXTRA_CATEGORICAL:
        if c in col_map:
            mapped_df[c] = df_raw[col_map[c]].astype(str).str.strip().str.lower().values

    print("Mapped schema: ['protocol', 'packets', 'bytes', 'duration'] + ['attack_cat', 'label']")
    print(f"Total rows: {len(mapped_df)} (Normal: {(labels == 0).sum()}, Attack: {(labels == 1).sum()})")
    return mapped_df


def find_or_prepare_dataset(data_dir="data"):
    """
    Locates training/testing CSV files in data/.
    If no usable CSV exists, creates data/labelled_synthetic_sample.csv and prints warning.
    """
    dir_path = Path(data_dir)
    dir_path.mkdir(parents=True, exist_ok=True)

    csv_files = list(dir_path.glob("*.csv"))
    train_file = None
    test_file = None

    for f in csv_files:
        name_lower = f.name.lower()
        if "train" in name_lower:
            train_file = f
        elif "test" in name_lower:
            test_file = f

    is_synthetic = False
    if train_file and test_file:
        print(f"Found dedicated training file: {train_file.name} and testing file: {test_file.name}")
        train_df = inspect_and_load_unsw(train_file)
        test_df = inspect_and_load_unsw(test_file)
        dataset_name = f"UNSW-NB15 ({train_file.name} / {test_file.name})"
    elif csv_files:
        single_file = csv_files[0]
        print(f"Using single CSV file: {single_file.name}")
        df_all = inspect_and_load_unsw(single_file)
        train_df, test_df = train_test_split(
            df_all, test_size=0.30, stratify=df_all["label"], random_state=42
        )
        dataset_name = single_file.name
        if "synthetic" in single_file.name.lower():
            is_synthetic = True
    else:
        synthetic_path = dir_path / "labelled_synthetic_sample.csv"
        generate_synthetic_labelled_data(str(synthetic_path))
        is_synthetic = True
        df_all = inspect_and_load_unsw(synthetic_path)
        train_df, test_df = train_test_split(
            df_all, test_size=0.30, stratify=df_all["label"], random_state=42
        )
        dataset_name = "labelled_synthetic_sample.csv"

    if is_synthetic:
        print("\n" + "=" * 75)
        print("WARNING: Evaluating on SYNTHETIC labelled dataset (labelled_synthetic_sample.csv).")
        print("Results are for testing pipeline correctness, NOT real-world attack evidence.")
        print("=" * 75 + "\n")

    return train_df, test_df, dataset_name, is_synthetic


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------
def calculate_metrics(y_true, y_pred, attack_cats=None):
    """
    Computes confusion matrix and classification metrics:
      TP, FP, TN, FN, Precision, Recall, F1, FPR, Accuracy, and per-category recall.
    """
    y_true = np.array(y_true, dtype=int)
    y_pred = np.array(y_pred, dtype=int)

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
        unique_cats = cat_series[y_true == 1].unique()
        for cat in unique_cats:
            cat_mask = (cat_series == cat) & (y_true == 1)
            cat_total = int(np.sum(cat_mask))
            cat_tp = int(np.sum(cat_mask & (y_pred == 1)))
            cat_recall = float(cat_tp / cat_total) if cat_total > 0 else 0.0
            per_category_recall[str(cat)] = {
                "total": cat_total,
                "detected": cat_tp,
                "recall": round(cat_recall, 4),
            }

    return {
        "TP": tp,
        "FP": fp,
        "TN": tn,
        "FN": fn,
        "Precision": round(precision, 4),
        "Recall": round(recall, 4),
        "F1": round(f1, 4),
        "FPR": round(fpr, 4),
        "Accuracy": round(accuracy, 4),
        "per_category_recall": per_category_recall,
    }


# ---------------------------------------------------------------------------
# Extended features, Isolation Forest, Random Forest, Gradient Boosting
# ---------------------------------------------------------------------------
def prepare_extended_features(train_feat, test_feat, train_labels, top_k=8):
    """
    Signed-log numeric features + one-hot categoricals, fitted on train NORMAL only.
    Returns (X_train_normal, X_test, X_train_all, feature_names).
    """
    base = ["packets", "bytes", "duration", "packets_per_sec", "bytes_per_sec", "bytes_per_packet"]
    num_cols = [c for c in base + EXTRA_NUMERIC if c in train_feat.columns]
    cat_cols = [c for c in ["protocol"] + EXTRA_CATEGORICAL if c in train_feat.columns]
    normal = np.asarray(train_labels) == 0

    def numeric(df):
        x = df[num_cols].apply(pd.to_numeric, errors="coerce")
        return np.sign(x) * np.log1p(x.abs())

    tr_num, te_num = numeric(train_feat), numeric(test_feat)
    med = tr_num[normal].median().fillna(0)
    tr_num = tr_num.fillna(med).fillna(0).values
    te_num = te_num.fillna(med).fillna(0).values

    tops = {c: train_feat.loc[normal, c].value_counts().head(top_k).index.tolist() for c in cat_cols}

    def categorical(df):
        parts = []
        for c in cat_cols:
            cats = tops[c] + ["other"]
            s = df[c].where(df[c].isin(tops[c]), "other")
            parts.append(pd.get_dummies(pd.Categorical(s, categories=cats)).values.astype(float))
        return np.hstack(parts) if parts else np.empty((len(df), 0))

    X_train = np.hstack([tr_num, categorical(train_feat)])
    X_test = np.hstack([te_num, categorical(test_feat)])
    names = num_cols + [f"{c}={v}" for c in cat_cols for v in tops[c] + ["other"]]
    return X_train[normal], X_test, X_train, names


def run_extended_if(X_train_normal, X_test, y_test, attack_cats, random_state=42):
    """
    Isolation Forest fitted on normal traffic. The alert threshold is chosen from a
    held-out slice of TRAIN normal data (target false-positive rate), never from the test set.
    """
    X_fit, X_val = train_test_split(X_train_normal, test_size=0.2, random_state=random_state)
    iso = IsolationForest(n_estimators=200, random_state=random_state, n_jobs=-1).fit(X_fit)
    val_scores = iso.score_samples(X_val)      # lower = more anomalous
    test_scores = iso.score_samples(X_test)
    results = {}
    for target in (0.01, 0.05, 0.10):
        thr = np.quantile(val_scores, target)
        y_pred = (test_scores < thr).astype(int)
        results[target] = calculate_metrics(y_test, y_pred, attack_cats)
    return results


def run_supervised_rf(X_train, y_train, X_test, y_test, attack_cats, feature_names, random_state=42):
    """
    Supervised Random Forest (uses training labels). Alert thresholds are chosen on a
    held-out validation split of the TRAIN set, never on the test set.
    Returns (metrics per setting, top-10 feature importances).
    """
    y_train = np.asarray(y_train)
    X_fit, X_val, y_fit, y_val = train_test_split(
        X_train, y_train, test_size=0.2, stratify=y_train, random_state=random_state
    )
    rf = RandomForestClassifier(
        n_estimators=200, min_samples_leaf=2, class_weight="balanced_subsample",
        n_jobs=-1, random_state=random_state,
    ).fit(X_fit, y_fit)

    test_scores = rf.predict_proba(X_test)[:, 1]
    val_scores = rf.predict_proba(X_val)[:, 1]
    val_normal_scores = val_scores[y_val == 0]

    results = {
        "Random Forest (Supervised, threshold 0.5)": calculate_metrics(
            y_test, (test_scores >= 0.5).astype(int), attack_cats
        )
    }

    # Thresholds chosen to reach a target false-positive rate on validation normals
    for target in (0.001, 0.005, 0.01, 0.05, 0.10):
        thr = np.quantile(val_normal_scores, 1 - target)
        pred = (test_scores > thr).astype(int)
        results[f"Random Forest (Supervised, target FPR {target * 100:g}%)"] = calculate_metrics(
            y_test, pred, attack_cats
        )

    # Thresholds chosen on validation to reach a target precision (highest recall that qualifies)
    prec, _, thr_arr = precision_recall_curve(y_val, val_scores)
    for p in (0.95, 0.98, 0.99):
        ok = np.where(prec[:-1] >= p)[0]
        if len(ok) == 0:
            continue
        pred = (test_scores >= thr_arr[ok[0]]).astype(int)
        results[f"Random Forest (Supervised, target precision {int(p * 100)}%)"] = calculate_metrics(
            y_test, pred, attack_cats
        )

    order = np.argsort(rf.feature_importances_)[::-1][:10]
    importance = [
        {"feature": feature_names[i], "importance": round(float(rf.feature_importances_[i]), 4)}
        for i in order
    ]
    return results, importance


def run_supervised_hgb(X_train, y_train, X_test, y_test, attack_cats, random_state=42):
    """
    Gradient boosting with early stopping (boosting rounds ~ epochs).
    Thresholds are chosen on a held-out slice of TRAIN, never on test.
    Returns (metrics per setting, boosting rounds actually used).
    """
    y_train = np.asarray(y_train)
    X_fit, X_val, y_fit, y_val = train_test_split(
        X_train, y_train, test_size=0.2, stratify=y_train, random_state=random_state
    )
    hgb = HistGradientBoostingClassifier(
        max_iter=500, learning_rate=0.1, early_stopping=True,
        validation_fraction=0.1, n_iter_no_change=20,
        class_weight="balanced", random_state=random_state,
    ).fit(X_fit, y_fit)

    test_scores = hgb.predict_proba(X_test)[:, 1]
    val_normal_scores = hgb.predict_proba(X_val[y_val == 0])[:, 1]

    results = {
        "Gradient Boosting (Supervised, threshold 0.5)": calculate_metrics(
            y_test, (test_scores >= 0.5).astype(int), attack_cats
        )
    }
    for target in (0.001, 0.005, 0.01, 0.05, 0.10):
        thr = np.quantile(val_normal_scores, 1 - target)
        results[f"Gradient Boosting (Supervised, target FPR {target * 100:g}%)"] = calculate_metrics(
            y_test, (test_scores > thr).astype(int), attack_cats
        )
    return results, int(hgb.n_iter_)

def run_supervised_ensemble(X_train, y_train, X_test, y_test, attack_cats, random_state=42):
    """Average of RF and GB probabilities. Thresholds chosen on validation normals only."""
    y_train = np.asarray(y_train)
    X_fit, X_val, y_fit, y_val = train_test_split(
        X_train, y_train, test_size=0.2, stratify=y_train, random_state=random_state
    )
    rf = RandomForestClassifier(
        n_estimators=200, min_samples_leaf=2, class_weight="balanced_subsample",
        n_jobs=-1, random_state=random_state,
    ).fit(X_fit, y_fit)
    hgb = HistGradientBoostingClassifier(
        max_iter=500, learning_rate=0.1, early_stopping=True,
        validation_fraction=0.1, n_iter_no_change=20,
        class_weight="balanced", random_state=random_state,
    ).fit(X_fit, y_fit)

    val = (rf.predict_proba(X_val)[:, 1] + hgb.predict_proba(X_val)[:, 1]) / 2
    test = (rf.predict_proba(X_test)[:, 1] + hgb.predict_proba(X_test)[:, 1]) / 2
    val_normal = val[y_val == 0]

    results = {}
    for target in (0.001, 0.002, 0.005, 0.01):
        thr = np.quantile(val_normal, 1 - target)
        results[f"RF+GB Ensemble (Supervised, target FPR {target * 100:g}%)"] = calculate_metrics(
            y_test, (test > thr).astype(int), attack_cats
        )
    return results

def build_feature_spec(train_feat, train_labels, top_k=8):
    """Preprocessing recipe fitted on train NORMAL records, reusable on new data."""
    base = ["packets", "bytes", "duration", "packets_per_sec", "bytes_per_sec", "bytes_per_packet"]
    num_cols = [c for c in base + EXTRA_NUMERIC if c in train_feat.columns]
    cat_cols = [c for c in ["protocol"] + EXTRA_CATEGORICAL if c in train_feat.columns]
    normal = np.asarray(train_labels) == 0
    x = train_feat[num_cols].apply(pd.to_numeric, errors="coerce")
    med = (np.sign(x) * np.log1p(x.abs()))[normal].median().fillna(0)
    tops = {c: train_feat.loc[normal, c].value_counts().head(top_k).index.tolist() for c in cat_cols}
    return {"num_cols": num_cols, "cat_cols": cat_cols, "med": med, "tops": tops}


def transform_with_spec(df, spec):
    x = df[spec["num_cols"]].apply(pd.to_numeric, errors="coerce")
    num = (np.sign(x) * np.log1p(x.abs())).fillna(spec["med"]).fillna(0).values
    parts = [num]
    for c in spec["cat_cols"]:
        s = df[c].astype(str)
        s = s.where(s.isin(spec["tops"][c]), "other")
        parts.append(pd.get_dummies(pd.Categorical(s, categories=spec["tops"][c] + ["other"])).values.astype(float))
    return np.hstack(parts)


def save_ensemble_model(train_feat, train_labels, path="ensemble_model.joblib", random_state=42):
    """Trains the RF+GB ensemble (same recipe as the evaluation) and saves it for the dashboard."""
    spec = build_feature_spec(train_feat, train_labels)
    X = transform_with_spec(train_feat, spec)
    y = np.asarray(train_labels)
    X_fit, X_val, y_fit, y_val = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=random_state
    )
    rf = RandomForestClassifier(
        n_estimators=200, min_samples_leaf=2, class_weight="balanced_subsample",
        n_jobs=-1, random_state=random_state,
    ).fit(X_fit, y_fit)
    hgb = HistGradientBoostingClassifier(
        max_iter=500, learning_rate=0.1, early_stopping=True,
        validation_fraction=0.1, n_iter_no_change=20,
        class_weight="balanced", random_state=random_state,
    ).fit(X_fit, y_fit)
    val = (rf.predict_proba(X_val)[:, 1] + hgb.predict_proba(X_val)[:, 1]) / 2
    vn = val[y_val == 0]
    thresholds = {
        "High precision (0.2% FPR target)": float(np.quantile(vn, 1 - 0.002)),
        "Balanced (1% FPR target)": float(np.quantile(vn, 1 - 0.01)),
    }
    joblib.dump({"spec": spec, "rf": rf, "hgb": hgb, "thresholds": thresholds}, path, compress=3)
    print(f"Saved ensemble model to {path}")

# ---------------------------------------------------------------------------
# Main evaluation
# ---------------------------------------------------------------------------

def run_evaluation(data_dir="data", max_test_records=100000, random_state=42):
    """
    Full evaluation pipeline (labels are never used as model features):
      statistical detectors, Isolation Forest variants, contamination sweep,
      extended-feature Isolation Forest, supervised Random Forest,
      Gradient Boosting and an RF+GB ensemble. Thresholds are chosen on
      validation data from the training set, never on the test set.
    """
    train_df, test_df, dataset_name, is_synthetic = find_or_prepare_dataset(data_dir)

    # Stratified cap on test records if needed for speed
    if len(test_df) > max_test_records:
        test_df, _ = train_test_split(
            test_df,
            train_size=max_test_records,
            stratify=test_df["label"],
            random_state=random_state
        )
        print(f"Stratified test cap applied: limited to {max_test_records} records.")

    test_df = test_df.reset_index(drop=True)
    train_df = train_df.reset_index(drop=True)

    y_test = test_df["label"].values
    attack_cats_test = test_df["attack_cat"].values

    # Feature engineering (label excluded)
    train_feat = add_engineered_features(train_df.drop(columns=["label", "attack_cat"], errors="ignore"))
    test_feat = add_engineered_features(test_df.drop(columns=["label", "attack_cat"], errors="ignore"))

    num_cols = ["packets", "bytes", "duration", "packets_per_sec", "bytes_per_sec", "bytes_per_packet"]
    feature_cols = [c for c in num_cols if c in train_feat.columns]
    print(f"\nFeatures used for baseline ML models: {feature_cols}")

    # Impute missing values with column median from training normal records
    train_normal_feat = train_feat[train_df["label"] == 0][feature_cols]
    median_impute = train_normal_feat.median().fillna(0)

    X_train_normal = train_normal_feat.fillna(median_impute).fillna(0)
    X_train_all = train_feat[feature_cols].fillna(median_impute).fillna(0)
    X_test = test_feat[feature_cols].fillna(median_impute).fillna(0)

    results_table = []
    methods_dict = {}

    # 1. Isolation Forest (Semi-supervised: fit on Normal only)
    print("\nEvaluating Isolation Forest (Semi-supervised on Normal)...")
    iso_semi = IsolationForest(n_estimators=100, contamination=0.1, random_state=random_state)
    iso_semi.fit(X_train_normal)
    y_pred_semi = (iso_semi.predict(X_test) == -1).astype(int)
    metrics_semi = calculate_metrics(y_test, y_pred_semi, attack_cats_test)
    methods_dict["Isolation Forest (Semi-Supervised)"] = metrics_semi
    results_table.append({"Method": "Isolation Forest (Semi-Supervised)", **metrics_semi})

    # 2. Isolation Forest (Unsupervised: fit on All Train)
    print("Evaluating Isolation Forest (Unsupervised on All Train)...")
    iso_un = IsolationForest(n_estimators=100, contamination=0.1, random_state=random_state)
    iso_un.fit(X_train_all)
    y_pred_un = (iso_un.predict(X_test) == -1).astype(int)
    metrics_un = calculate_metrics(y_test, y_pred_un, attack_cats_test)
    methods_dict["Isolation Forest (Unsupervised)"] = metrics_un
    results_table.append({"Method": "Isolation Forest (Unsupervised)", **metrics_un})

    # 3. Statistical Detector (Mean + Std baseline on Normal)
    print("Evaluating Statistical Detector (Mean + Std)...")
    clean_packets = pd.to_numeric(train_df[train_df["label"] == 0]["packets"], errors="coerce").dropna()
    m_mean = clean_packets.mean()
    m_std = clean_packets.std()
    stat_thresh = m_mean + 2.0 * m_std if m_std > 0 else float("inf")
    y_pred_stat = (test_df["packets"] > stat_thresh).astype(int)
    metrics_stat = calculate_metrics(y_test, y_pred_stat, attack_cats_test)
    methods_dict["Statistical Detector (Mean + Std)"] = metrics_stat
    results_table.append({"Method": "Statistical Detector (Mean + Std)", **metrics_stat})

    # 4. Statistical Detector (Median + MAD robust baseline on Normal)
    print("Evaluating Statistical Detector (Median + MAD)...")
    m_med = clean_packets.median()
    m_mad = 1.4826 * (clean_packets - m_med).abs().median()
    mad_thresh = m_med + 2.0 * m_mad if m_mad > 0 else float("inf")
    y_pred_mad = (test_df["packets"] > mad_thresh).astype(int)
    metrics_mad = calculate_metrics(y_test, y_pred_mad, attack_cats_test)
    methods_dict["Statistical Detector (Median + MAD)"] = metrics_mad
    results_table.append({"Method": "Statistical Detector (Median + MAD)", **metrics_mad})

    # 5. Contamination sweep for Isolation Forest (semi-supervised, baseline features)
    print("\nRunning Contamination Sweep for Isolation Forest...")
    contamination_levels = [0.01, 0.05, 0.1, 0.2]
    sweep_results = []
    for contam in contamination_levels:
        iso_sweep = IsolationForest(n_estimators=100, contamination=contam, random_state=random_state)
        iso_sweep.fit(X_train_normal)
        y_sweep = (iso_sweep.predict(X_test) == -1).astype(int)
        sweep_metrics = calculate_metrics(y_test, y_sweep)
        sweep_results.append({
            "Contamination": contam,
            "Precision": sweep_metrics["Precision"],
            "Recall": sweep_metrics["Recall"],
            "F1": sweep_metrics["F1"],
            "FPR": sweep_metrics["FPR"],
        })
        print(f"  Contamination {contam:.2f} -> Precision: {sweep_metrics['Precision']:.4f}, "
              f"Recall: {sweep_metrics['Recall']:.4f}, F1: {sweep_metrics['F1']:.4f}")

    # 6 - 9. Extended-feature models (only when the extra UNSW columns exist)
    extended_count = 0
    rf_importance = []
    hgb_rounds = 0
    if any(c in train_feat.columns for c in EXTRA_NUMERIC):
        print("\nEvaluating Isolation Forest (Extended features)...")
        X_tr_n, X_te, X_tr_all, feat_names = prepare_extended_features(
            train_feat, test_feat, train_df["label"].values
        )
        extended_count = int(X_te.shape[1])
        print(f"Extended feature matrix: {extended_count} columns")
        for target, m in run_extended_if(X_tr_n, X_te, y_test, attack_cats_test, random_state).items():
            name = f"Isolation Forest (Extended, target FPR {int(target * 100)}%)"
            methods_dict[name] = m
            results_table.append({"Method": name, **m})

        print("\nEvaluating Random Forest (Supervised)...")
        rf_results, rf_importance = run_supervised_rf(
            X_tr_all, train_df["label"].values, X_te, y_test, attack_cats_test, feat_names, random_state
        )
        for name, m in rf_results.items():
            methods_dict[name] = m
            results_table.append({"Method": name, **m})

        print("\nEvaluating Gradient Boosting (Supervised)...")
        hgb_results, hgb_rounds = run_supervised_hgb(
            X_tr_all, train_df["label"].values, X_te, y_test, attack_cats_test, random_state
        )
        print(f"  Early stopping used {hgb_rounds} boosting rounds")
        for name, m in hgb_results.items():
            methods_dict[name] = m
            results_table.append({"Method": name, **m})

        print("\nEvaluating RF + GB Ensemble (Supervised)...")
        ens_results = run_supervised_ensemble(
            X_tr_all, train_df["label"].values, X_te, y_test, attack_cats_test, random_state
        )
        for name, m in ens_results.items():
            methods_dict[name] = m
            results_table.append({"Method": name, **m})
        save_ensemble_model(train_feat, train_df["label"].values)

    # Best method by F1
    best_method = max(results_table, key=lambda x: x["F1"])

    output_payload = {
        "dataset_name": dataset_name,
        "is_synthetic": is_synthetic,
        "train_records": len(train_df),
        "test_records": len(test_df),
        "train_normal_records": int((train_df["label"] == 0).sum()),
        "test_normal_records": int((test_df["label"] == 0).sum()),
        "test_attack_records": int((test_df["label"] == 1).sum()),
        "features_used": feature_cols,
        "extended_feature_count": extended_count,
        "rf_feature_importance": rf_importance,
        "hgb_boosting_rounds": hgb_rounds,
        "methods": methods_dict,
        "contamination_sweep": sweep_results,
        "best_method": best_method["Method"],
        "best_f1": best_method["F1"],
    }

    with open("evaluation_results.json", "w", encoding="utf-8") as f:
        json.dump(output_payload, f, indent=2)

    csv_rows = []
    for r in results_table:
        csv_rows.append({
            "Dataset": dataset_name,
            "Method": r["Method"],
            "Accuracy": r["Accuracy"],
            "Precision": r["Precision"],
            "Recall": r["Recall"],
            "F1": r["F1"],
            "FPR": r["FPR"],
            "TP": r["TP"],
            "FP": r["FP"],
            "TN": r["TN"],
            "FN": r["FN"],
        })
    pd.DataFrame(csv_rows).to_csv("evaluation_results.csv", index=False)

    print("\nSaved evaluation results to evaluation_results.json and evaluation_results.csv")
    return output_payload


if __name__ == "__main__":
    run_evaluation()