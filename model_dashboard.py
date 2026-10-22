import json
import os
import tempfile
import time

import joblib
import numpy as np
import pandas as pd
import plotly.express as px
import streamlit as st

from data_loader import load_network_data
from ml_detector import detect_anomalies
from explainability import add_explanations
from feature_engineering import add_engineered_features
from pcap_loader import load_pcap_data
from statistical_detector import detect_statistical_anomalies
from live_monitor import LiveMonitor
from evaluation import inspect_and_load_unsw, transform_with_spec

st.set_page_config(page_title="FlowWatch", page_icon="🛡️", layout="wide")

st.markdown(
    """
    <style>
    .block-container {padding-top: 2rem;}
    [data-testid="stMetric"] {
        background: rgba(128,128,128,0.08);
        border: 1px solid rgba(128,128,128,0.25);
        padding: 14px 16px;
        border-radius: 12px;
    }
    [data-testid="stMetricLabel"] {opacity: 0.75;}
    </style>
    """,
    unsafe_allow_html=True,
)

st.title("🛡️ FlowWatch")
st.caption("Network traffic monitoring and anomaly detection: statistical vs machine learning")

FLAG = "Potential Anomaly"
COLORS = {"Normal": "#4C78A8", "Statistical": "#F58518", "ML": "#B279A2", "Both": "#E45756"}
ORDER = ["Normal", "Statistical", "ML", "Both"]


@st.cache_resource
def load_ensemble(path="ensemble_model.joblib"):
    return joblib.load(path) if os.path.exists(path) else None


def auto_refresh(seconds):
    time.sleep(seconds)
    st.rerun()


def show(fig, height=330):
    fig.update_layout(margin=dict(l=10, r=10, t=30, b=10), height=height, legend_title_text="")
    st.plotly_chart(fig)


# ---------------- Sidebar: data source mode ----------------
st.sidebar.header("Mode")
mode = st.sidebar.radio("Data source", ["File upload", "Live monitoring"])
live = mode == "Live monitoring"
mon = st.session_state.setdefault("monitor", LiveMonitor())
uploaded_file = None
window, refresh = 120, 5

if live:
    iface_mode = st.sidebar.radio("Network interface", ["Default interface", "Choose interface"])
    iface = ""
    if iface_mode == "Choose interface":
        iface = st.sidebar.text_input("Interface name", placeholder=r"e.g. Wi-Fi or \Device\NPF_{...}")
        if not iface.strip():
            st.sidebar.caption("Enter a name, or switch back to Default interface.")
    window = st.sidebar.slider("Rolling window (seconds)", 30, 600, 120, 10)
    refresh = st.sidebar.slider("Refresh every (seconds)", 2, 30, 5)
    need_name = iface_mode == "Choose interface" and not iface.strip()
    b1, b2 = st.sidebar.columns(2)
    if b1.button("Start", disabled=mon.running or need_name):
        try:
            mon.start(iface.strip())
        except Exception as error:
            st.sidebar.error(str(error))
    if b2.button("Stop", disabled=not mon.running):
        mon.stop()
    st.sidebar.caption("🟢 Monitoring (authorized traffic only)" if mon.running else "⚪ Stopped")
else:
    if mon.running:
        mon.stop()
    uploaded_file = st.file_uploader(
        "Upload network traffic data", type=["csv", "json", "pcap", "pcapng"]
    )

# ---------------- Sidebar: detection settings ----------------
st.sidebar.header("Detection Settings")
std_multiplier = st.sidebar.slider("Std multiplier (threshold)", 1.0, 4.0, 2.0, 0.1)
baseline_mode = st.sidebar.selectbox(
    "Baseline mode",
    ["mean_std", "median_mad"],
    format_func=lambda m: "Mean + Std" if m == "mean_std" else "Median + MAD (robust)",
)
contamination = st.sidebar.slider("ML contamination", 0.01, 0.30, 0.10, 0.01)

# ---------------- Load data ----------------
source_label = "Sample dataset (network_traffic.json)"
if uploaded_file is not None:
    source_label = uploaded_file.name
    try:
        fname = uploaded_file.name.lower()
        if fname.endswith((".pcap", ".pcapng")):
            df, pcap_stats = load_pcap_data(uploaded_file)
            if pcap_stats["cap_hit"]:
                st.warning(f"Processing capped at {pcap_stats['max_packets']} packets.")
            st.info(
                f"**PCAP Summary**: {pcap_stats['total_packets']:,} packets read | "
                f"{pcap_stats['num_flows']} flows extracted | "
                f"Capture time span: {pcap_stats['time_span']:.2f}s"
            )
        elif fname.endswith(".csv"):
            df = pd.read_csv(uploaded_file)
            if {"proto", "spkts", "dpkts"}.issubset(c.strip().lower() for c in df.columns):
                with tempfile.NamedTemporaryFile(suffix=".csv", delete=False, mode="w", newline="") as tmp:
                    df.to_csv(tmp, index=False)
                df = inspect_and_load_unsw(tmp.name)
                os.remove(tmp.name)
                if len(df) > 20000:
                    df = df.sample(20000, random_state=42)
                    st.info("UNSW-format file detected: random sample of 20,000 records analysed for speed.")
                else:
                    st.info("UNSW-format file detected and mapped to the FlowWatch schema.")
        else:
            df = pd.read_json(uploaded_file)

        df.columns = df.columns.str.strip().str.lower()
        if not {"protocol", "packets"}.issubset(df.columns):
            st.error("File must contain Protocol and Packets columns.")
            st.stop()
        df["protocol"] = df["protocol"].astype(str).str.strip()
        df["packets"] = pd.to_numeric(df["packets"], errors="coerce")
        df = df.dropna(subset=["protocol", "packets"])
        df = df[df["protocol"] != ""]
    except Exception as error:
        st.error(f"Could not read the file: {error}")
        st.stop()
elif live:
    source_label = "Live monitoring"
    df, ls = mon.snapshot(window)
    st.info(
        f"**Live monitoring** ({'running' if mon.running else 'stopped'}): "
        f"{ls['total_packets']:,} packets seen | {ls['num_flows']} flows in the last {window}s"
    )
    if len(df) < 10:
        if mon.running:
            st.warning("Collecting traffic... at least 10 flows are needed for analysis.")
            auto_refresh(refresh)
        else:
            st.warning("Press Start to begin monitoring.")
        st.stop()
else:
    df = load_network_data("network_traffic.json")

if df.empty:
    st.warning("No usable records found.")
    st.stop()
if (df["packets"] < 0).any():
    st.error("Packet counts cannot be negative.")
    st.stop()

# Keep ground-truth labels (UNSW files) out of the detectors
truth = None
if "label" in df.columns:
    keep = ["label"] + (["attack_cat"] if "attack_cat" in df.columns else [])
    truth = df[keep].reset_index(drop=True)
    df = df.drop(columns=keep)
df = df.reset_index(drop=True)

# ---------------- Detection pipeline ----------------
df["Statistical Result"], stat_threshold = detect_statistical_anomalies(
    df, std_multiplier=std_multiplier, baseline_mode=baseline_mode
)
df = add_engineered_features(df)

eng_cols = ["packets_per_sec", "bytes_per_sec", "bytes_per_packet"]
has_engineered = any(c in df.columns for c in eng_cols)
use_engineered = False
if has_engineered:
    use_engineered = st.sidebar.checkbox(
        "Use engineered features", value=True,
        help="Include packets/sec, bytes/sec and bytes/packet in Isolation Forest",
    )

ml_without = detect_anomalies(df, use_engineered_features=False, contamination=contamination)
ml_with = (
    detect_anomalies(df, use_engineered_features=True, contamination=contamination)
    if has_engineered else ml_without
)
ml_results = ml_with if use_engineered else ml_without
df["ML Result"] = ml_results["ml_status"].values

df = add_explanations(df, threshold=std_multiplier, baseline_mode=baseline_mode)
df["Flag Status"] = df["Flagged By"].replace({"None": "Normal"})

# Supervised ensemble (only for UNSW-format feature sets)
bundle = load_ensemble()
has_ens = False
if bundle is not None:
    spec = bundle["spec"]
    if all(c in df.columns for c in spec["num_cols"] + spec["cat_cols"]):
        op = st.sidebar.selectbox("Supervised ensemble operating point", list(bundle["thresholds"]))
        X_ens = transform_with_spec(df, spec)
        score = (bundle["rf"].predict_proba(X_ens)[:, 1] + bundle["hgb"].predict_proba(X_ens)[:, 1]) / 2
        df["Ensemble Score"] = score.round(4)
        df["Ensemble Result"] = np.where(score > bundle["thresholds"][op], FLAG, "Normal")
        has_ens = True

# ---------------- Sidebar filters ----------------
st.sidebar.header("Filters")
protocols = sorted(df["protocol"].unique())
sel_protocols = st.sidebar.multiselect("Protocol", protocols, default=protocols)
flag_filter = st.sidebar.selectbox(
    "Flagged by", ["All flagged", "Statistical only", "ML only", "Both"]
)
if has_engineered:
    st.sidebar.caption(
        f"ML flags without engineered: **{int((ml_without['ml_status'] == FLAG).sum())}** | "
        f"with: **{int((ml_with['ml_status'] == FLAG).sum())}**"
    )

is_stat = df["Statistical Result"] == FLAG
is_ml = df["ML Result"] == FLAG
view = df[df["protocol"].isin(sel_protocols)]
flagged_pct = 100 * int((is_stat | is_ml).sum()) / len(df)

# ---------------- Tabs ----------------
tab_ov, tab_tr, tab_inv, tab_cmp, tab_eval, tab_rep = st.tabs(
    ["Overview", "Traffic Analytics", "Anomaly Investigation",
     "Model Comparison", "Evaluation", "Reports"]
)

with tab_ov:
    st.caption(f"Source: **{source_label}** | {len(df):,} records | {flagged_pct:.1f}% flagged by at least one detector")
    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Records Analysed", f"{len(df):,}")
    c2.metric("Flagged (any)", f"{int((is_stat | is_ml).sum()):,}", f"{flagged_pct:.1f}%", delta_color="off")
    c3.metric("Statistical Flags", f"{int(is_stat.sum()):,}")
    c4.metric("ML Flags", f"{int(is_ml.sum()):,}")
    c5.metric("Flagged by Both", f"{int((is_stat & is_ml).sum()):,}")
    st.caption(
        f"Statistical threshold on packets: "
        f"{'none (zero spread)' if stat_threshold == float('inf') else f'{stat_threshold:,.2f}'} "
        f"({baseline_mode}, multiplier {std_multiplier})"
    )

    left, right = st.columns([1, 2])
    with left:
        st.subheader("Traffic Status")
        counts = view["Flag Status"].value_counts().reset_index()
        counts.columns = ["Status", "Records"]
        show(px.pie(counts, names="Status", values="Records", hole=0.55,
                    color="Status", color_discrete_map=COLORS))
    with right:
        st.subheader("Records by Protocol")
        by_proto = view.groupby(["protocol", "Flag Status"]).size().reset_index(name="Records")
        show(px.bar(by_proto, x="protocol", y="Records", color="Flag Status",
                    color_discrete_map=COLORS, category_orders={"Flag Status": ORDER}))

    with st.expander("Show records"):
        st.dataframe(view[["protocol", "packets", "Statistical Result", "ML Result"]], width="stretch")

with tab_tr:
    st.subheader("Packets vs Bytes per Record")
    if "bytes" in view.columns and view["bytes"].notna().any():
        plot = view[(view["packets"] > 0) & (view["bytes"] > 0)]
        flagged_pts = plot[plot["Flag Status"] != "Normal"]
        normal_pts = plot[plot["Flag Status"] == "Normal"]
        plot = pd.concat([flagged_pts, normal_pts.sample(min(len(normal_pts), 3000), random_state=1)])
        fig = px.scatter(plot, x="packets", y="bytes", color="Flag Status",
                         color_discrete_map=COLORS, category_orders={"Flag Status": ORDER},
                         hover_data=[c for c in ["protocol", "duration"] if c in plot.columns],
                         log_x=True, log_y=True, opacity=0.7)
        show(fig, 420)
        st.caption("Log scales. Up to 3,000 normal records are drawn for speed; all flagged records are shown.")
    else:
        show(px.histogram(view, x="packets", color="Flag Status", color_discrete_map=COLORS, nbins=40))

    st.subheader("Total Packets by Protocol")
    show(px.bar(view.groupby("protocol")["packets"].sum().reset_index(),
                x="protocol", y="packets", color_discrete_sequence=[COLORS["Normal"]]))

    if has_engineered:
        cols = st.columns(3)
        for slot, (col, title) in zip(cols, [("packets_per_sec", "Avg packets/sec"),
                                             ("bytes_per_sec", "Avg bytes/sec"),
                                             ("bytes_per_packet", "Avg bytes/packet")]):
            if col in view.columns:
                data = view.groupby("protocol")[col].mean().dropna().reset_index()
                if not data.empty:
                    with slot:
                        st.caption(title)
                        show(px.bar(data, x="protocol", y=col,
                                    color_discrete_sequence=[COLORS["Normal"]]), 260)

with tab_inv:
    st.subheader("Potential Anomalies")
    flagged = view[is_stat.loc[view.index] | is_ml.loc[view.index]]
    fmap = {"Statistical only": "Statistical", "ML only": "ML", "Both": "Both"}
    if flag_filter in fmap:
        flagged = flagged[flagged["Flagged By"] == fmap[flag_filter]]

    if flagged.empty:
        st.success("No potential anomalies for the current settings and filters.")
    else:
        st.warning(f"{len(flagged):,} record(s) flagged for review.")
        sev = flagged["Severity"].value_counts()
        scols = st.columns(len(sev))
        for slot, (name, n) in zip(scols, sev.items()):
            slot.metric(f"Severity: {name}", f"{n:,}")
        show_cols = [c for c in ["protocol", "packets", "bytes", "duration", "source_port", "dest_port",
                                 "src_ip", "dst_ip", "Flagged By", "Severity", "Reasons"]
                     if c in flagged.columns]
        st.dataframe(flagged[show_cols], width="stretch")
        st.download_button("Download flagged records", flagged.to_csv(index=False).encode("utf-8"),
                           "flowwatch_flagged_records.csv", "text/csv")
    st.caption("Flagged records are unusual patterns, not confirmed attacks. "
               "An empty reason means Isolation Forest flagged the record on a feature "
               "combination no single feature explains.")

with tab_cmp:
    st.subheader("Statistical vs Machine Learning")
    cmp_long = pd.DataFrame({
        "Method": ["Statistical", "Statistical", "Machine Learning", "Machine Learning"],
        "Result": ["Normal", "Potential Anomaly", "Normal", "Potential Anomaly"],
        "Records": [int((~is_stat).sum()), int(is_stat.sum()), int((~is_ml).sum()), int(is_ml.sum())],
    })
    left, right = st.columns(2)
    with left:
        show(px.bar(cmp_long, x="Method", y="Records", color="Result", barmode="group",
                    color_discrete_map={"Normal": COLORS["Normal"], "Potential Anomaly": COLORS["Both"]}), 300)
    with right:
        st.table(pd.DataFrame({
            "Agreement": ["Both flag", "Statistical only", "ML only", "Neither"],
            "Records": [int((is_stat & is_ml).sum()), int((is_stat & ~is_ml).sum()),
                        int((~is_stat & is_ml).sum()), int((~is_stat & ~is_ml).sum())],
        }))
    st.caption("The statistical method tests packet count only; Isolation Forest uses every "
               "available numeric feature, so the two can legitimately disagree.")

    if has_ens:
        is_ens = df["Ensemble Result"] == FLAG
        st.subheader("Supervised Ensemble (Random Forest + Gradient Boosting)")
        e1, e2, e3 = st.columns(3)
        e1.metric("Ensemble Flags", int(is_ens.sum()))
        e2.metric("Also flagged by Statistical or ML", int((is_ens & (is_stat | is_ml)).sum()))
        e3.metric("Ensemble only", int((is_ens & ~is_stat & ~is_ml).sum()))
        if truth is not None:
            y = truth["label"].astype(int).values
            rows = []
            for name, mask in [("Statistical", is_stat), ("Isolation Forest", is_ml), ("RF+GB Ensemble", is_ens)]:
                p = mask.values.astype(int)
                tp = int(((p == 1) & (y == 1)).sum())
                fp = int(((p == 1) & (y == 0)).sum())
                fn = int(((p == 0) & (y == 1)).sum())
                rows.append({"Method": name,
                             "Precision": round(tp / (tp + fp), 4) if tp + fp else 0.0,
                             "Recall": round(tp / (tp + fn), 4) if tp + fn else 0.0,
                             "False alarms": fp})
            st.table(pd.DataFrame(rows))
            st.caption("Computed against the file's own ground-truth label column.")
        top = df[is_ens].sort_values("Ensemble Score", ascending=False)
        show_cols = [c for c in ["protocol", "packets", "bytes", "duration", "Ensemble Score",
                                 "Statistical Result", "ML Result"] if c in top.columns]
        st.dataframe(top[show_cols].head(500), width="stretch")

with tab_eval:
    st.subheader("Model Evaluation (labelled data)")
    if os.path.exists("evaluation_results.csv"):
        res = pd.read_csv("evaluation_results.csv")
        meta = {}
        if os.path.exists("evaluation_results.json"):
            with open("evaluation_results.json", encoding="utf-8") as f:
                meta = json.load(f)
        if meta.get("is_synthetic"):
            st.warning("These metrics come from a SYNTHETIC labelled dataset generated by "
                       "evaluation.py. They demonstrate the evaluation method and are not "
                       "evidence of real-world detection performance.")
        if meta:
            st.caption(f"Dataset: {meta.get('dataset_name')} | train {meta.get('train_records'):,} | "
                       f"test {meta.get('test_records'):,} ({meta.get('test_attack_records'):,} attacks)")

        st.dataframe(res.drop(columns=["Dataset"], errors="ignore"), width="stretch")

        st.subheader("Precision vs Recall (all methods)")
        family = res["Method"].str.extract(
            r"^(Isolation Forest|Statistical Detector|Random Forest|Gradient Boosting|RF\+GB Ensemble)"
        )[0].fillna("Other")
        fig = px.scatter(res.assign(Family=family), x="Recall", y="Precision", color="Family",
                         hover_name="Method", hover_data=["F1", "FPR"])
        fig.update_traces(marker=dict(size=11))
        fig.update_xaxes(range=[0, 1.02])
        fig.update_yaxes(range=[0, 1.02])
        show(fig, 400)
        st.caption("Top-right is better. Each dot is one method or operating point.")

        st.subheader("Compare selected methods")
        default = [m for m in ["Statistical Detector (Mean + Std)", "Isolation Forest (Semi-Supervised)",
                               meta.get("best_method")] if m in set(res["Method"])]
        chosen = st.multiselect("Methods", res["Method"].tolist(), default=default)
        if chosen:
            long = res[res["Method"].isin(chosen)].melt(
                id_vars="Method", value_vars=["Precision", "Recall", "F1", "FPR"],
                var_name="Metric", value_name="Value")
            show(px.bar(long, x="Metric", y="Value", color="Method", barmode="group"), 360)

        imp = meta.get("rf_feature_importance")
        if imp:
            st.subheader("Top Random Forest Feature Importances")
            show(px.bar(pd.DataFrame(imp).sort_values("importance"), x="importance", y="feature",
                        orientation="h", color_discrete_sequence=[COLORS["Normal"]]), 340)

        sup_methods = {k: v for k, v in meta.get("methods", {}).items()
                       if k.startswith(("Random Forest", "Gradient Boosting", "RF+GB"))
                       and v.get("per_category_recall")}
        if sup_methods:
            names = list(sup_methods)
            pick = st.selectbox("Per-category recall for", names,
                                index=names.index(meta["best_method"]) if meta.get("best_method") in names else 0)
            cat = pd.DataFrame(sup_methods[pick]["per_category_recall"]).T.astype(float)
            cat = cat.reset_index().rename(columns={"index": "category"})
            show(px.bar(cat, x="category", y="recall", range_y=[0, 1.02],
                        color_discrete_sequence=[COLORS["Normal"]]), 320)
        st.caption("Supervised models only recognise attack types seen in training; Isolation "
                   "Forest can flag novel behaviour. FlowWatch presents both as a hybrid. "
                   "Test false-positive rates can exceed their targets because of the known "
                   "UNSW-NB15 train/test distribution shift.")
    else:
        st.info("evaluation_results.csv not found. Run: py -3.12 evaluation.py")

with tab_rep:
    st.subheader("Export Report")
    st.download_button("Download full comparison report", df.to_csv(index=False).encode("utf-8"),
                       "flowwatch_model_comparison.csv", "text/csv")
    st.info("An anomaly is an unusual pattern, not proof of an attack. "
            "FlowWatch is a prototype for demonstration and learning. "
            "Only monitor traffic you are authorized to capture.")

# ---------------- Live auto-refresh ----------------
if live and mon.running:
    auto_refresh(refresh)