
import streamlit as st
import pandas as pd

from data_loader import load_network_data
from ml_detector import detect_anomalies

st.set_page_config(
    page_title="FlowWatch ML Analysis",
    page_icon="🛡️",
    layout="wide"
)

st.title("FlowWatch | ML Anomaly Analysis")
st.caption("Compare statistical and machine-learning traffic detection")

uploaded_file = st.file_uploader(
    "Upload network traffic data",
    type=["csv", "json"]
)

if uploaded_file is not None:
    try:
        if uploaded_file.name.lower().endswith(".csv"):
            df = pd.read_csv(uploaded_file)
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
else:
    df = load_network_data("network_traffic.json")

if df.empty:
    st.warning("No usable records found.")
    st.stop()

if (df["packets"] < 0).any():
    st.error("Packet counts cannot be negative.")
    st.stop()

# Statistical anomaly detection
mean = df["packets"].mean()
std = df["packets"].std()
threshold = mean + 2 * std if pd.notna(std) else float("inf")

df["Statistical Result"] = df["packets"].apply(
    lambda x: "Potential Anomaly" if x > threshold else "Normal"
)

# Machine-learning anomaly detection
ml_results = detect_anomalies(df)
df["ML Result"] = ml_results["ml_status"].values

# Summary metrics
col1, col2, col3 = st.columns(3)

col1.metric("Records Analysed", len(df))
col2.metric(
    "Statistical Flags",
    int((df["Statistical Result"] == "Potential Anomaly").sum())
)
col3.metric(
    "ML Flags",
    int((df["ML Result"] == "Potential Anomaly").sum())
)

# Main results
st.subheader("Detection Results")

st.dataframe(
    df[["protocol", "packets", "Statistical Result", "ML Result"]],
    width="stretch"
)

# Packet count chart
st.subheader("Packet Count Distribution")
st.bar_chart(df, x="protocol", y="packets")

# Total traffic for each protocol
st.subheader("Protocol-wise Traffic Analysis")

protocol_data = (
    df.groupby("protocol")["packets"]
    .sum()
    .reset_index()
)

st.bar_chart(protocol_data, x="protocol", y="packets")

# Compare detection methods
st.subheader("Anomaly Detection Comparison")

comparison_data = pd.DataFrame({
    "Detection Method": ["Statistical", "Machine Learning"],
    "Normal": [
        int((df["Statistical Result"] == "Normal").sum()),
        int((df["ML Result"] == "Normal").sum())
    ],
    "Potential Anomaly": [
        int((df["Statistical Result"] == "Potential Anomaly").sum()),
        int((df["ML Result"] == "Potential Anomaly").sum())
    ]
})

st.bar_chart(comparison_data.set_index("Detection Method"))

# Show records flagged by either method
st.subheader("Potential Anomalies")

anomalies = df[
    (df["Statistical Result"] == "Potential Anomaly")
    | (df["ML Result"] == "Potential Anomaly")
]

if anomalies.empty:
    st.success("No potential anomalies detected.")
else:
    st.warning(f"{len(anomalies)} record(s) flagged for review.")
    st.dataframe(
        anomalies[["protocol", "packets", "Statistical Result", "ML Result"]],
        width="stretch"
    )

# Download report
st.subheader("Export Report")

st.download_button(
    "Download comparison report",
    data=df.to_csv(index=False).encode("utf-8"),
    file_name="flowwatch_model_comparison.csv",
    mime="text/csv"
)

st.info(
    "An anomaly is an unusual pattern, not proof of an attack. "
    "This demonstration uses a small, manually created dataset."
)
