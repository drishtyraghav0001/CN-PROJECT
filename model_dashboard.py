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
from live_monitor import LiveMonitor, get_available_interfaces
from evaluation import inspect_and_load_unsw, transform_with_spec
from evaluate_cic import clean_cic_label
from incident_models import (
    ActionMode,
    ActionStatus,
    ActionType,
    AlertSeverity,
    IncidentStatus,
    VALID_INCIDENT_TRANSITIONS,
)
from incident_store import IncidentStore
from incident_engine import IncidentEngine, extract_alerts_from_dataframe
from response_engine import ResponseEngine

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


@st.cache_resource
def load_flow_ensemble(path="flow_ensemble_model.joblib"):
    return joblib.load(path) if os.path.exists(path) else None


@st.cache_resource
def get_incident_store(db_path: str = "flowwatch.db") -> IncidentStore:
    return IncidentStore(db_path)


@st.cache_resource
def get_response_engine(db_path: str = "flowwatch.db") -> ResponseEngine:
    store = get_incident_store(db_path)
    return ResponseEngine(store)


@st.cache_resource
def get_incident_engine() -> IncidentEngine:
    return IncidentEngine(time_window_seconds=300)


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
    avail_ifaces = get_available_interfaces()
    if avail_ifaces:
        iface_options = ["Default interface"] + [i["label"] for i in avail_ifaces] + ["Manual input"]
        iface_choice = st.sidebar.selectbox("Network interface", iface_options)
        if iface_choice == "Default interface":
            iface = ""
            need_name = False
        elif iface_choice == "Manual input":
            iface = st.sidebar.text_input("Interface name / GUID", placeholder=r"e.g. \Device\NPF_{...}")
            need_name = not bool(iface.strip())
        else:
            matched = next((i["name"] for i in avail_ifaces if i["label"] == iface_choice), iface_choice)
            iface = matched
            need_name = False
    else:
        iface_mode = st.sidebar.radio("Network interface", ["Default interface", "Choose interface"])
        iface = ""
        if iface_mode == "Choose interface":
            iface = st.sidebar.text_input("Interface name", placeholder=r"e.g. Wi-Fi or \Device\NPF_{...}")
        need_name = iface_mode == "Choose interface" and not iface.strip()
    window = st.sidebar.slider("Rolling window (seconds)", 30, 600, 120, 10)
    refresh = st.sidebar.slider("Refresh every (seconds)", 2, 30, 5)
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
bonferroni_adj = st.sidebar.checkbox(
    "Bonferroni adjustment",
    value=True,
    help="Adjust significance threshold across multiple tested features to control false positive rate",
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
            col_map = {c.strip().lower(): c for c in df.columns}
            if {"proto", "spkts", "dpkts"}.issubset(col_map):
                with tempfile.NamedTemporaryFile(suffix=".csv", delete=False, mode="w", newline="") as tmp:
                    df.to_csv(tmp, index=False)
                df = inspect_and_load_unsw(tmp.name)
                os.remove(tmp.name)
                if len(df) > 20000:
                    df = df.sample(20000, random_state=42)
                    st.info("UNSW-format file detected: random sample of 20,000 records analysed for speed.")
                else:
                    st.info("UNSW-format file detected and mapped to the FlowWatch schema.")
            elif {"total fwd packets", "total backward packets"}.issubset(col_map):
                p = (
                    pd.to_numeric(df[col_map["total fwd packets"]], errors="coerce").fillna(0)
                    + pd.to_numeric(df[col_map["total backward packets"]], errors="coerce").fillna(0)
                )
                b = 0
                if "total length of fwd packets" in col_map and "total length of bwd packets" in col_map:
                    b = (
                        pd.to_numeric(df[col_map["total length of fwd packets"]], errors="coerce").fillna(0)
                        + pd.to_numeric(df[col_map["total length of bwd packets"]], errors="coerce").fillna(0)
                    )
                d = 0.0
                if "flow duration" in col_map:
                    d = (pd.to_numeric(df[col_map["flow duration"]], errors="coerce").fillna(0) / 1e6).clip(lower=0)
                dport = (
                    pd.to_numeric(df[col_map["destination port"]], errors="coerce").fillna(0)
                    if "destination port" in col_map else 0
                )
                clean_lbl = clean_cic_label(df[col_map["label"]]) if "label" in col_map else None

                df = pd.DataFrame({
                    "protocol": "TCP",
                    "packets": p,
                    "bytes": b,
                    "duration": d,
                    "dest_port": dport,
                    "source_port": 0,
                })
                if clean_lbl is not None:
                    df["attack_cat"] = clean_lbl
                    df["label"] = (clean_lbl.str.upper() != "BENIGN").astype(int)

                if len(df) > 20000:
                    df = df.sample(20000, random_state=42)
                    st.info("CIC-IDS2017-format file detected: random sample of 20,000 records analysed for speed.")
                else:
                    st.info("CIC-IDS2017-format file detected and mapped to the FlowWatch schema.")
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
df = add_engineered_features(df)
df["Statistical Result"], stat_threshold = detect_statistical_anomalies(
    df, std_multiplier=std_multiplier, baseline_mode=baseline_mode, bonferroni=bonferroni_adj
)

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

df = add_explanations(df, threshold=stat_threshold, baseline_mode=baseline_mode)
df["Flag Status"] = df["Flagged By"].replace({"None": "Normal"})

if live:
    mon.record_alerts(df[df["Flag Status"] != "Normal"])

# Supervised ensemble (extended UNSW model or live/PCAP flow model)
bundle = load_ensemble()
flow_bundle = load_flow_ensemble()
has_ens = False
ens_title = "Supervised Ensemble"

if bundle is not None and all(c in df.columns for c in bundle["spec"]["num_cols"] + bundle["spec"]["cat_cols"]):
    spec = bundle["spec"]
    op = st.sidebar.selectbox("Supervised ensemble operating point", list(bundle["thresholds"]))
    X_ens = transform_with_spec(df, spec)
    score = (bundle["rf"].predict_proba(X_ens)[:, 1] + bundle["hgb"].predict_proba(X_ens)[:, 1]) / 2
    df["Ensemble Score"] = score.round(4)
    df["Ensemble Result"] = np.where(score > bundle["thresholds"][op], FLAG, "Normal")
    has_ens = True
    ens_title = "Supervised Ensemble (UNSW Extended)"
elif flow_bundle is not None and all(c in df.columns for c in ["packets", "bytes", "duration"]):
    op = st.sidebar.selectbox("Supervised flow model operating point", list(flow_bundle["thresholds"]))
    proto = df["protocol"].astype(str).str.lower() if "protocol" in df.columns else pd.Series("tcp", index=df.index)
    sport = pd.to_numeric(df["source_port"], errors="coerce").fillna(0) if "source_port" in df.columns else pd.Series(0, index=df.index)
    dport = pd.to_numeric(df["dest_port"], errors="coerce").fillna(0) if "dest_port" in df.columns else pd.Series(0, index=df.index)

    X_flow = pd.DataFrame({
        "packets": pd.to_numeric(df["packets"], errors="coerce"),
        "bytes": pd.to_numeric(df["bytes"], errors="coerce"),
        "duration": pd.to_numeric(df["duration"], errors="coerce"),
        "packets_per_sec": pd.to_numeric(df["packets_per_sec"], errors="coerce") if "packets_per_sec" in df.columns else 0.0,
        "bytes_per_sec": pd.to_numeric(df["bytes_per_sec"], errors="coerce") if "bytes_per_sec" in df.columns else 0.0,
        "bytes_per_packet": pd.to_numeric(df["bytes_per_packet"], errors="coerce") if "bytes_per_packet" in df.columns else 0.0,
        "source_port": sport,
        "dest_port": dport,
        "proto_tcp": (proto == "tcp").astype(float),
        "proto_udp": (proto == "udp").astype(float),
    }).replace([np.inf, -np.inf], np.nan).fillna(0)

    X_flow = X_flow[flow_bundle["features"]]
    score = (flow_bundle["rf"].predict_proba(X_flow)[:, 1] + flow_bundle["hgb"].predict_proba(X_flow)[:, 1]) / 2
    df["Ensemble Score"] = score.round(4)
    df["Ensemble Result"] = np.where(score > flow_bundle["thresholds"][op], FLAG, "Normal")
    has_ens = True
    ens_title = "Supervised Flow Model (Live/PCAP compatible)"

# ---------------- Sidebar filters ----------------
st.sidebar.header("Filters")
protocols = sorted(df["protocol"].unique())
sel_protocols = st.sidebar.multiselect("Protocol", protocols, default=protocols)
if not sel_protocols:
    st.sidebar.warning("Please select at least one protocol.")
    st.warning("No protocols selected. Please select at least one protocol from the sidebar filter.")
    st.stop()
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

# ---------------- Incident Engine Ingestion ----------------
inc_store = get_incident_store()
inc_engine = get_incident_engine()
resp_engine = get_response_engine()

# Automatically ingest flagged traffic into incidents without duplicate creation
try:
    if "Flag Status" in df.columns and (df["Flag Status"] != "Normal").any():
        stype = "live" if live else ("pcap" if source_label.lower().endswith((".pcap", ".pcapng")) else "file")
        extracted_alerts = extract_alerts_from_dataframe(df, source_type=stype)
        if extracted_alerts:
            inc_engine.process_and_persist(extracted_alerts, inc_store, skip_already_associated=True)
except Exception as ing_err:
    pass

# ---------------- Tabs ----------------
tab_ov, tab_tr, tab_inv, tab_cmp, tab_eval, tab_rep, tab_resp = st.tabs(
    [
        "Overview",
        "Traffic Analytics",
        "Anomaly Investigation",
        "Model Comparison",
        "Evaluation",
        "Reports",
        "Incident Response & Triage",
    ]
)

with tab_ov:
    st.caption(f"Source: **{source_label}** | {len(df):,} records | {flagged_pct:.1f}% flagged by at least one detector")
    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Records Analysed", f"{len(df):,}")
    c2.metric("Flagged (any)", f"{int((is_stat | is_ml).sum()):,}", f"{flagged_pct:.1f}%", delta_color="off")
    c3.metric("Statistical Flags", f"{int(is_stat.sum()):,}")
    c4.metric("ML Flags", f"{int(is_ml.sum()):,}")
    c5.metric("Flagged by Both", f"{int((is_stat & is_ml).sum()):,}")
    if hasattr(stat_threshold, "summary_text"):
        thresh_info = stat_threshold.summary_text()
    elif isinstance(stat_threshold, dict):
        thresh_info = ", ".join(
            f"{k}: {v:,.1f}" if v != float("inf") else f"{k}: none"
            for k, v in stat_threshold.items()
        )
    else:
        thresh_info = f"packets: {stat_threshold:,.2f}"
    st.caption(
        f"Statistical thresholds ({baseline_mode}, base multiplier {std_multiplier}"
        f"{', Bonferroni-adjusted' if getattr(stat_threshold, 'bonferroni', False) else ''}): "
        f"{thresh_info}"
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
        if not plot.empty:
            fig = px.scatter(plot, x="packets", y="bytes", color="Flag Status",
                             color_discrete_map=COLORS, category_orders={"Flag Status": ORDER},
                             hover_data=[c for c in ["protocol", "duration"] if c in plot.columns],
                             log_x=True, log_y=True, opacity=0.7)
            show(fig, 420)
            st.caption("Log scales. Up to 3,000 normal records are drawn for speed; all flagged records are shown.")
        else:
            st.info("No records with positive packet and byte counts to display.")
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

    if live:
        ts_df = mon.get_time_series()
        if not ts_df.empty and len(ts_df) > 1:
            st.divider()
            st.subheader("📈 Live Traffic Temporal Trends")
            tc1, tc2 = st.columns(2)
            with tc1:
                show(px.line(ts_df, x="time", y="packets_per_sec", markers=True,
                             title="Packets/sec over time",
                             color_discrete_sequence=[COLORS["Normal"]]), 280)
            with tc2:
                show(px.line(ts_df, x="time", y="bytes_per_sec", markers=True,
                             title="Bytes/sec over time",
                             color_discrete_sequence=[COLORS["Statistical"]]), 280)

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

    if live:
        st.divider()
        st.subheader("🚨 Live Session Alert History Log")
        alerts_df = mon.get_alert_log()
        if not alerts_df.empty:
            st.info(f"**{len(alerts_df):,} total alert(s)** recorded across this entire monitoring session.")
            st.dataframe(alerts_df, width="stretch")
            st.download_button(
                "Download full session alert history",
                alerts_df.to_csv(index=False).encode("utf-8"),
                "flowwatch_session_alert_log.csv",
                "text/csv",
            )
        else:
            st.caption("No alerts logged in the session history yet.")

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
    st.caption("The statistical detector evaluates continuous flow features (packets, bytes, duration, and rates); "
               "Isolation Forest uses all numeric features including ports to detect multivariate anomalies.")

    if has_ens:
        is_ens = df["Ensemble Result"] == FLAG
        st.subheader(ens_title)
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
    eval_options = []
    if os.path.exists("evaluation_results.csv"):
        eval_options.append("UNSW-NB15")
    if os.path.exists("evaluation_cic_results.csv"):
        eval_options.append("CIC-IDS2017")

    if eval_options:
        chosen_dataset = st.radio("Benchmark Dataset", eval_options, horizontal=True)
        if chosen_dataset == "CIC-IDS2017":
            csv_path = "evaluation_cic_results.csv"
            json_path = "evaluation_cic_results.json"
        else:
            csv_path = "evaluation_results.csv"
            json_path = "evaluation_results.json"

        res = pd.read_csv(csv_path)
        meta = {}
        if os.path.exists(json_path):
            with open(json_path, encoding="utf-8") as f:
                meta = json.load(f)
        if meta.get("is_synthetic"):
            st.warning("These metrics come from a SYNTHETIC labelled dataset generated by "
                       "evaluation.py. They demonstrate the evaluation method and are not "
                       "evidence of real-world detection performance.")
        if meta:
            ds_name = meta.get("dataset_name", chosen_dataset)
            parts = [f"Dataset: {ds_name}"]
            if meta.get("train_records") is not None:
                parts.append(f"train {meta['train_records']:,}")
            if meta.get("test_records") is not None:
                atk_str = f" ({meta.get('test_attack_records'):,} attacks)" if meta.get("test_attack_records") is not None else ""
                parts.append(f"test {meta['test_records']:,}{atk_str}")
            st.caption(" | ".join(parts))

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
        default_candidates = [
            "Statistical Detector (Mean + Std)",
            "Isolation Forest (Semi-Supervised)",
            meta.get("best_method"),
        ]
        default = [m for m in dict.fromkeys(default_candidates) if m and m in set(res["Method"])]
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
            if not cat.empty:
                show(px.bar(cat, x="category", y="recall", range_y=[0, 1.02],
                            color_discrete_sequence=[COLORS["Normal"]]), 320)
        shift_note = (
            "Test false-positive rates can exceed their targets because of the known "
            "UNSW-NB15 train/test distribution shift."
            if chosen_dataset == "UNSW-NB15"
            else "CIC-IDS2017 evaluation demonstrates cross-day generalization across multiple attack profiles."
        )
        st.caption(f"Supervised models only recognise attack types seen in training; Isolation "
                   f"Forest can flag novel behaviour. FlowWatch presents both as a hybrid. "
                   f"{shift_note}")
    else:
        st.info("evaluation_results.csv not found. Run: py -3.12 evaluation.py")

with tab_rep:
    st.subheader("Export Report")
    st.download_button("Download full comparison report", df.to_csv(index=False).encode("utf-8"),
                       "flowwatch_model_comparison.csv", "text/csv")
    st.info("An anomaly is an unusual pattern, not proof of an attack. "
            "FlowWatch is a prototype for demonstration and learning. "
            "Only monitor traffic you are authorized to capture.")

# ---------------- Tab 7: Incident Response & Triage ----------------
with tab_resp:
    st.subheader("🛡️ Incident Response & Simulated Triage")
    st.caption("Review correlated network security incidents, manage approval workflows, execute safe simulated containment playbooks, and inspect audit logs.")

    # --- Section A: Incident Overview & Summary Metrics ---
    all_incidents = inc_store.list_incidents(limit=300)
    total_incs = len(all_incidents)
    active_incs = sum(1 for i in all_incidents if i.status in (IncidentStatus.NEW, IncidentStatus.INVESTIGATING))
    high_risk_incs = sum(1 for i in all_incidents if i.severity in (AlertSeverity.HIGH, AlertSeverity.CRITICAL) or i.risk_score >= 70)
    contained_incs = sum(1 for i in all_incidents if i.status == IncidentStatus.CONTAINED)
    all_actions = inc_store.get_response_actions()
    pending_approvals = sum(1 for a in all_actions if a.status == ActionStatus.PENDING)

    m1, m2, m3, m4, m5 = st.columns(5)
    m1.metric("Total Incidents", f"{total_incs:,}")
    m2.metric("Active Incidents", f"{active_incs:,}")
    m3.metric("High / Critical Risk", f"{high_risk_incs:,}")
    m4.metric("Simulated Containments", f"{contained_incs:,}")
    m5.metric("Pending Approvals", f"{pending_approvals:,}")

    if total_incs == 0:
        st.info("ℹ️ No network incidents currently recorded in the persistent database. Ingest traffic data or start live monitoring with flagged anomalies to trigger incident correlation.")
    else:
        # --- Section B: Incident List and Filters ---
        st.markdown("---")
        st.subheader("Incident Queue")
        f1, f2, f3 = st.columns(3)
        with f1:
            status_opts = ["All"] + [s.value for s in IncidentStatus]
            f_status = st.selectbox("Status Filter", status_opts, key="resp_filter_status")
        with f2:
            sev_opts = ["All"] + [s.value for s in AlertSeverity]
            f_sev = st.selectbox("Severity Filter", sev_opts, key="resp_filter_severity")
        with f3:
            risk_opts = ["All", "Critical (>= 80)", "High (60-79)", "Medium (40-59)", "Low (< 40)"]
            f_risk = st.selectbox("Risk Level Filter", risk_opts, key="resp_filter_risk")

        filtered_incs = all_incidents
        if f_status != "All":
            filtered_incs = [i for i in filtered_incs if i.status.value == f_status]
        if f_sev != "All":
            filtered_incs = [i for i in filtered_incs if i.severity.value == f_sev]
        if f_risk != "All":
            if "Critical" in f_risk:
                filtered_incs = [i for i in filtered_incs if i.risk_score >= 80]
            elif "High" in f_risk:
                filtered_incs = [i for i in filtered_incs if 60 <= i.risk_score < 80]
            elif "Medium" in f_risk:
                filtered_incs = [i for i in filtered_incs if 40 <= i.risk_score < 60]
            elif "Low" in f_risk:
                filtered_incs = [i for i in filtered_incs if i.risk_score < 40]

        if not filtered_incs:
            st.warning("No incidents match the active filter criteria.")
        else:
            inc_rows = []
            for i in filtered_incs:
                inc_rows.append({
                    "Incident ID": i.incident_id[:8] + "...",
                    "Created": i.created_at[:19].replace("T", " ") if i.created_at else "—",
                    "Title": i.title,
                    "Status": i.status.value,
                    "Severity": i.severity.value,
                    "Risk Score": f"{i.risk_score}/100",
                    "Rule": i.correlation_rule,
                    "Primary Entity": i.primary_entity or "—",
                    "Alerts": len(i.alert_ids),
                })
            st.dataframe(pd.DataFrame(inc_rows), width="stretch")

            inc_selection_map = {
                i.incident_id: f"[{i.severity.value}] {i.title} (Risk: {i.risk_score}/100, Status: {i.status.value}) — ID: {i.incident_id[:8]}"
                for i in filtered_incs
            }
            prev_sel = st.session_state.get("selected_incident_id")
            opt_keys = list(inc_selection_map.keys())
            def_idx = opt_keys.index(prev_sel) if prev_sel in opt_keys else 0

            sel_inc_id = st.selectbox(
                "Select an incident to investigate and respond:",
                opt_keys,
                index=def_idx,
                format_func=lambda k: inc_selection_map[k],
                key="resp_selected_inc_id",
            )
            st.session_state["selected_incident_id"] = sel_inc_id

            if sel_inc_id:
                sel_inc = inc_store.get_incident(sel_inc_id)
                if sel_inc:
                    # --- Section C: Incident Detail & Investigation ---
                    st.markdown("---")
                    st.subheader(f"Incident Investigation: {sel_inc.title}")

                    c_det1, c_det2, c_det3, c_det4 = st.columns(4)
                    c_det1.metric("Status", sel_inc.status.value)
                    c_det2.metric("Severity", sel_inc.severity.value)
                    c_det3.metric("Risk Score", f"{sel_inc.risk_score}/100")
                    c_det4.metric("Rule", sel_inc.correlation_rule)

                    st.progress(sel_inc.risk_score / 100.0)

                    with st.expander("📊 Explainable Risk Scoring & Individual Factors", expanded=True):
                        st.caption("Heuristic risk prioritization index (0-100), not an attack probability.")
                        for rf in sel_inc.risk_factors:
                            st.markdown(f"- {rf}")

                    with st.expander("🔍 Observed Network Metadata & Summary", expanded=True):
                        st.write(f"**Primary Entity**: `{sel_inc.primary_entity or 'Network'}` (Type: `{sel_inc.entity_type or 'unspecified'}`)")
                        if sel_inc.summary:
                            st.write(f"**Correlation Rationale**: {sel_inc.summary}")
                        st.write(f"**Created At**: `{sel_inc.created_at}` | **Updated At**: `{sel_inc.updated_at}`")

                    # Associated alerts table
                    with st.expander(f"🚨 Associated Alerts ({len(sel_inc.alert_ids)} alerts)", expanded=False):
                        inc_alerts = inc_store.get_alerts_for_incident(sel_inc.incident_id)
                        if inc_alerts:
                            alert_rows = []
                            for a in inc_alerts:
                                alert_rows.append({
                                    "Alert ID": a.alert_id[:8] + "...",
                                    "Timestamp": a.timestamp[:19].replace("T", " ") if a.timestamp else "—",
                                    "Source IP": a.src_ip or "—",
                                    "Dest IP": a.dst_ip or "—",
                                    "Src Port": str(a.source_port) if a.source_port else "—",
                                    "Dest Port": str(a.dest_port) if a.dest_port else "—",
                                    "Proto": a.protocol,
                                    "Packets": f"{a.packets:,}",
                                    "Bytes": f"{a.bytes:,}" if a.bytes is not None else "—",
                                    "Flagged By": a.flagged_by,
                                    "Severity": a.severity.value,
                                    "Reasons": a.reasons or "—",
                                })
                            st.dataframe(pd.DataFrame(alert_rows), width="stretch")
                        else:
                            st.caption("No alerts directly linked in database.")

                    # --- Section D: Response Playbooks ---
                    st.markdown("---")
                    st.subheader("🛡️ Response Playbooks")
                    playbook_analysis = resp_engine.explain_playbook_availability(sel_inc)

                    pb_col1, pb_col2 = st.columns([2, 1])
                    with pb_col1:
                        st.write("**Confirmed Targets in Evidence**:")
                        ip_text = ", ".join(f"`{ip}`" for ip in playbook_analysis["source_ips"]) if playbook_analysis["source_ips"] else "*None (No source IP)*"
                        port_text = ", ".join(f"`{p}`" for p in playbook_analysis["destination_ports"]) if playbook_analysis["destination_ports"] else "*None (No destination port)*"
                        st.write(f"- Source IPs: {ip_text}")
                        st.write(f"- Destination Ports: {port_text}")

                        if playbook_analysis["unavailable_reasons"]:
                            with st.expander("ℹ️ Playbook Limitations & Unavailable Actions"):
                                for ur in playbook_analysis["unavailable_reasons"]:
                                    st.write(f"- {ur}")

                    with pb_col2:
                        if st.button("Generate Recommended Proposals", key=f"gen_prop_{sel_inc.incident_id}"):
                            new_props = resp_engine.propose_actions(sel_inc.incident_id, auto_save=True, actor="ANALYST")
                            st.success(f"Generated {len(new_props)} response proposal(s).")
                            st.rerun()

                    # Custom proposal creation
                    with st.expander("➕ Propose Custom Action"):
                        with st.form(f"custom_prop_form_{sel_inc.incident_id}"):
                            avail_types = [ActionType(pt) for pt in playbook_analysis["available_playbooks"] if pt in [m.value for m in ActionType]]
                            custom_type = st.selectbox("Action Type", avail_types, format_func=lambda t: t.value)
                            default_target = ""
                            if custom_type in (ActionType.SIMULATE_BLOCK_SOURCE, ActionType.WATCH_SOURCE) and playbook_analysis["source_ips"]:
                                default_target = playbook_analysis["source_ips"][0]
                            elif custom_type in (ActionType.SIMULATE_BLOCK_DESTINATION_PORT, ActionType.SIMULATED_BLOCK_PORT) and playbook_analysis["destination_ports"]:
                                default_target = str(playbook_analysis["destination_ports"][0])
                            elif custom_type == ActionType.MARK_FOR_INVESTIGATION:
                                default_target = sel_inc.incident_id

                            custom_target = st.text_input("Target Entity (IP / Port / ID)", value=default_target)
                            custom_desc = st.text_input("Description (optional)", value=f"Custom {custom_type.value} on {custom_target}")
                            sub_custom = st.form_submit_button("Submit Proposal")
                            if sub_custom:
                                try:
                                    resp_engine.create_proposal(
                                        sel_inc.incident_id,
                                        custom_type,
                                        target_entity=custom_target,
                                        description=custom_desc,
                                        actor="ANALYST",
                                    )
                                    st.success("Custom proposal submitted in PENDING state.")
                                    st.rerun()
                                except Exception as prop_err:
                                    st.error(f"Proposal creation error: {prop_err}")

                    # --- Section E & F: Action Approval, Execution, Verification, and Rollback ---
                    st.markdown("---")
                    st.subheader("📋 Response Action Workflow")
                    inc_actions = inc_store.get_response_actions(incident_id=sel_inc.incident_id)

                    if not inc_actions:
                        st.info("No response actions currently proposed for this incident. Click 'Generate Recommended Proposals' above to begin.")
                    else:
                        for act in inc_actions:
                            with st.container():
                                st.markdown(f"#### `{act.action_type.value}` on `{act.target_entity}`")
                                a_col1, a_col2, a_col3 = st.columns([2, 1, 1])
                                with a_col1:
                                    st.write(f"**Action ID**: `{act.action_id[:8]}...` | **Mode**: `{act.mode.value}`")
                                    st.write(f"**Description**: {act.description}")
                                    if act.execution_log:
                                        st.caption(f"**Log**: {act.execution_log}")
                                with a_col2:
                                    st.write(f"**Status**: `{act.status.value}`")
                                    if act.approver:
                                        st.caption(f"Approved by: `{act.approver}` at {act.approved_at[:19] if act.approved_at else ''}")
                                    if act.rejection_reason:
                                        st.caption(f"Rejection Reason: {act.rejection_reason}")
                                with a_col3:
                                    if act.verification_status:
                                        v_color = "🟢" if act.verification_status == "VERIFIED" else ("🔴" if act.verification_status == "FAILED" else "⚪")
                                        st.write(f"**Verification**: {v_color} `{act.verification_status}`")
                                    if act.executed_at:
                                        st.caption(f"Executed: {act.executed_at[:19].replace('T', ' ')}")

                                # Approval controls for PENDING
                                if act.status == ActionStatus.PENDING:
                                    st.info("✋ **Approval Required**: This action cannot execute until explicitly approved.")
                                    appr_col1, appr_col2 = st.columns(2)
                                    with appr_col1:
                                        appr_note = st.text_input("Approval Comment (optional)", key=f"appr_note_{act.action_id}")
                                        if st.button("✅ Approve Action", key=f"btn_appr_{act.action_id}"):
                                            try:
                                                resp_engine.approve_action(act.action_id, actor="ANALYST", comment=appr_note)
                                                st.success("Action approved. Ready for simulated execution.")
                                                st.rerun()
                                            except Exception as a_err:
                                                st.error(f"Approval error: {a_err}")
                                    with appr_col2:
                                        rej_reason = st.text_input("Rejection Reason", key=f"rej_reason_{act.action_id}")
                                        if st.button("❌ Reject Action", key=f"btn_rej_{act.action_id}"):
                                            try:
                                                resp_engine.reject_action(act.action_id, actor="ANALYST", reason=rej_reason or "Declined by analyst")
                                                st.info("Action rejected.")
                                                st.rerun()
                                            except Exception as r_err:
                                                st.error(f"Rejection error: {r_err}")

                                # Execution controls for APPROVED
                                elif act.status == ActionStatus.APPROVED:
                                    st.warning("⚠️ **Simulated Containment**: This action changes FlowWatch's simulated containment state only. It does not modify your real firewall, operating system, or network traffic.")
                                    if st.button("🚀 Execute Simulated Action", key=f"btn_exec_{act.action_id}"):
                                        try:
                                            ok, msg, _ = resp_engine.execute_action(act.action_id, actor="ANALYST")
                                            if ok:
                                                st.success(f"Simulated execution succeeded: {msg}")
                                            else:
                                                st.error(f"Simulated execution failed: {msg}")
                                            st.rerun()
                                        except Exception as exec_err:
                                            st.error(f"Execution failed: {exec_err}")

                                # Verification & Rollback controls for APPLIED
                                elif act.status == ActionStatus.APPLIED:
                                    st.caption("ℹ️ *Verification confirms the simulated database state table entry only, not real-world network traffic blocking.*")
                                    v_btn_col, rb_btn_col = st.columns(2)
                                    with v_btn_col:
                                        if st.button("🔄 Re-Verify Simulated State", key=f"btn_ver_{act.action_id}"):
                                            v_st, v_dt = resp_engine.verify_action(act.action_id, auto_audit=True)
                                            st.info(f"Verification outcome: {v_st} — {v_dt}")
                                            st.rerun()
                                    with rb_btn_col:
                                        with st.expander("↩️ Rollback Simulated Action"):
                                            rb_reason = st.text_input("Rollback Reason", key=f"rb_note_{act.action_id}", value="Analyst requested state rollback")
                                            if st.button("Confirm Rollback", key=f"btn_rb_{act.action_id}"):
                                                try:
                                                    rb_ok, rb_msg, _ = resp_engine.rollback_action(act.action_id, actor="ANALYST", reason=rb_reason)
                                                    if rb_ok:
                                                        st.success(f"Rollback succeeded: {rb_msg}")
                                                    else:
                                                        st.error(f"Rollback failed: {rb_msg}")
                                                    st.rerun()
                                                except Exception as rb_err:
                                                    st.error(f"Rollback error: {rb_err}")

                                st.markdown("<hr style='margin: 0.5rem 0;'>", unsafe_allow_html=True)

    # --- Section G: Global Simulated State & Audit History ---
    st.markdown("---")
    st.subheader("🌐 Global Simulated Containment State & Audit History")

    sim_tab1, sim_tab2 = st.tabs(["Active Simulated State (Isolated)", "Historical Audit Trail"])

    with sim_tab1:
        st.caption("🔒 All containment states below are isolated to the FlowWatch SQLite simulation table. Real host networking and firewall rules are never modified.")
        sim_col1, sim_col2, sim_col3 = st.columns(3)
        with sim_col1:
            st.markdown("**Blocked Source IPs**")
            b_srcs = resp_engine.get_simulated_blocked_sources()
            if b_srcs:
                for ip in b_srcs:
                    st.markdown(f"- 🔴 `{ip}`")
            else:
                st.caption("*No source IPs currently blocked in simulation.*")

        with sim_col2:
            st.markdown("**Blocked Destination Ports**")
            b_ports = resp_engine.get_simulated_blocked_ports()
            if b_ports:
                for p in b_ports:
                    st.markdown(f"- 🔴 Port `{p}`")
            else:
                st.caption("*No ports currently blocked in simulation.*")

        with sim_col3:
            st.markdown("**Watched Source IPs**")
            w_srcs = resp_engine.get_simulated_watchlist()
            if w_srcs:
                for w in w_srcs:
                    st.markdown(f"- 🟡 `{w}`")
            else:
                st.caption("*Watchlist is currently empty.*")

    with sim_tab2:
        st.caption("Append-only immutable audit events log recording all proposals, approvals, executions, and rollbacks.")
        audit_events = inc_store.get_audit_events(limit=100)
        if audit_events:
            audit_rows = []
            for ev in audit_events:
                audit_rows.append({
                    "Timestamp": ev.timestamp[:19].replace("T", " ") if ev.timestamp else "—",
                    "Actor": ev.actor,
                    "Event Type": ev.event_type,
                    "Incident ID": ev.incident_id[:8] + "..." if ev.incident_id else "—",
                    "Action ID": ev.action_id[:8] + "..." if ev.action_id else "—",
                    "Description": ev.description,
                })
            st.dataframe(pd.DataFrame(audit_rows), width="stretch")
        else:
            st.caption("No audit events recorded yet.")

# ---------------- Live auto-refresh ----------------
if live and mon.running:
    auto_refresh(refresh)