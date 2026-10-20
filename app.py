
import streamlit as st
import pandas as pd
import plotly.express as px

# =====================================================
# FLOWWATCH - NETWORK TRAFFIC MONITORING DASHBOARD
# =====================================================

st.set_page_config(
    page_title="FlowWatch | Security Center",
    page_icon="🌐",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ---------------- PROFESSIONAL DESIGN ----------------

st.markdown("""
<style>
    .stApp {
        background: linear-gradient(135deg, #f4f8ff, #eef5fc);
        color: #14284b;
    }

    .block-container {
        padding-top: 1.5rem;
        padding-bottom: 2rem;
    }

    [data-testid="stSidebar"] {
        background: linear-gradient(180deg, #0b1930, #102b4d);
        border-right: 1px solid #244568;
    }

    [data-testid="stSidebar"] * {
        color: #edf6ff;
    }

    [data-testid="stSidebar"] hr {
        border-color: #35516f;
    }

    [data-testid="stSidebar"] [data-testid="stRadio"] label {
        background: transparent;
        border-radius: 9px;
        padding: 5px;
    }

    /* HIGH-CONTRAST FILE UPLOADER */
    [data-testid="stSidebar"] [data-testid="stFileUploader"] {
        background: #102642 !important;
        border: 1px solid #2877a9 !important;
        border-radius: 12px !important;
        padding: 10px !important;
    }

    [data-testid="stSidebar"] [data-testid="stFileUploader"] section {
        background: #102642 !important;
        border: 1px dashed #38bdf8 !important;
        border-radius: 9px !important;
    }

    [data-testid="stSidebar"] [data-testid="stFileUploader"] label,
    [data-testid="stSidebar"] [data-testid="stFileUploader"] label *,
    [data-testid="stSidebar"] [data-testid="stFileUploader"] span,
    [data-testid="stSidebar"] [data-testid="stFileUploader"] small,
    [data-testid="stSidebar"] [data-testid="stFileUploader"] p,
    [data-testid="stSidebar"] [data-testid="stFileUploader"] [data-testid="stMarkdownContainer"] {
        color: #f1f7ff !important;
    }

    [data-testid="stSidebar"] [data-testid="stFileUploader"] button {
        background: #38bdf8 !important;
        color: #08233d !important;
        border: none !important;
        border-radius: 8px !important;
        font-weight: 700 !important;
    }

    [data-testid="stSidebar"] [data-testid="stFileUploader"] button * {
        color: #08233d !important;
    }

    [data-testid="stSidebar"] [data-testid="stFileUploader"] button:hover {
        background: #7dd3fc !important;
    }

    /* BRAND */
    .brand {
        font-size: 30px;
        font-weight: 800;
        color: #38bdf8;
        letter-spacing: -1px;
        margin-top: 4px;
    }

    .brand-caption {
        color: #a9c5e2;
        font-size: 12px;
        margin-bottom: 22px;
    }

    /* HERO BANNER */
    .hero {
        background: linear-gradient(110deg, #dff2ff, #c4e7ff 65%, #a9d9ff);
        border: 1px solid #b8ddfb;
        border-radius: 18px;
        padding: 25px 28px;
        margin-bottom: 22px;
        color: #102c57;
    }

    .hero-title {
        font-size: 31px;
        font-weight: 800;
        margin-bottom: 5px;
        color: #102c57;
    }

    .hero-text {
        color: #365b86;
        font-size: 14px;
    }

    .hero-visual {
        font-size: 62px;
        text-align: center;
        padding-top: 2px;
    }

    .section-title {
        font-size: 22px;
        font-weight: 800;
        color: #15345f;
        padding: 5px 0 12px 0;
    }

    /* METRIC CARDS */
    div[data-testid="stMetric"] {
        background: rgba(255, 255, 255, 0.96);
        border: 1px solid #d5e6fa;
        border-radius: 14px;
        padding: 18px 20px;
        box-shadow: 0 4px 15px rgba(25, 75, 130, 0.05);
    }

    div[data-testid="stMetricLabel"] {
        color: #607796;
    }

    div[data-testid="stMetricValue"] {
        color: #102b53;
        font-weight: 800;
    }

    /* CHARTS AND TABLES */
    div[data-testid="stPlotlyChart"],
    div[data-testid="stDataFrame"] {
        background: #ffffff;
        border: 1px solid #dce9f8;
        border-radius: 12px;
        padding: 5px;
    }

    div[data-testid="stDownloadButton"] button {
        background: #0878db;
        color: white;
        border: 0;
        border-radius: 8px;
        font-weight: 650;
    }

    div[data-testid="stDownloadButton"] button:hover {
        background: #075eb0;
        color: white;
    }

    .status-note {
        background: #e3f3ff;
        border: 1px solid #c0e2ff;
        border-radius: 12px;
        padding: 15px;
        color: #204d7d;
        margin: 10px 0 18px 0;
    }

    .footer {
        text-align: center;
        color: #7085a1;
        font-size: 12px;
        padding: 20px 0 4px 0;
    }
</style>
""", unsafe_allow_html=True)


# ---------------- SIDEBAR ----------------

with st.sidebar:
    st.markdown(
        '<div class="brand">🛡️ FlowWatch</div>',
        unsafe_allow_html=True
    )
    st.markdown(
        '<div class="brand-caption">'
        'NETWORK MONITORING & ANALYSIS'
        '</div>',
        unsafe_allow_html=True
    )

    st.divider()

    page = st.radio(
        "NAVIGATION",
        [
            "Overview",
            "Traffic Analysis",
            "Anomaly Detection",
            "Data Explorer"
        ],
        index=0
    )

    st.divider()

    st.markdown("### 📂 Traffic Dataset")
    st.caption("Upload your network traffic CSV")

    uploaded_file = st.file_uploader(
        "Choose a CSV file",
        type=["csv"],
        help="Your CSV should contain a Protocol column. "
             "A Packets column is needed for traffic charts "
             "and packet anomaly detection."
    )

    st.caption("Required: Protocol")
    st.caption("For traffic analysis: Packets")

    st.divider()

    st.markdown("### 🖥️ System Information")
    st.caption("Mode: Local analysis")
    st.caption("Engine: Statistical detection")
    st.caption("Version: 1.0")

    st.divider()

    st.markdown("### 🔐 Network Safety")
    st.caption("Analyze • Detect • Stay Secure")


# ---------------- LOAD DATA ----------------

sample_mode = uploaded_file is None

sample_data = pd.DataFrame({
    "Protocol": [
        "TCP", "UDP", "DNS", "TCP", "UDP",
        "TCP", "DNS", "UDP", "TCP", "TCP"
    ],
    "Packets": [
        100, 110, 95, 105, 100,
        98, 102, 95, 110, 1000
    ]
})

if sample_mode:
    data = sample_data.copy()
else:
    try:
        data = pd.read_csv(uploaded_file)

        if data.empty:
            st.error("The uploaded CSV file is empty.")
            st.stop()

        if "Protocol" not in data.columns:
            st.error(
                "Your CSV must contain a column named Protocol."
            )
            st.stop()

        data["Protocol"] = (
            data["Protocol"]
            .astype(str)
            .str.upper()
            .str.strip()
        )

        supported_protocols = [
            "TCP", "UDP", "DNS", "ICMP", "HTTP", "HTTPS"
        ]

        data = data[
            data["Protocol"].isin(supported_protocols)
        ].copy()

        if data.empty:
            st.warning(
                "No supported network protocols were found."
            )
            st.stop()

    except Exception as e:
        st.error(f"Could not read the uploaded CSV: {e}")
        st.stop()


# ---------------- PREPARE DATA ----------------

has_packets = "Packets" in data.columns

if has_packets:
    data["Packets"] = pd.to_numeric(
        data["Packets"],
        errors="coerce"
    )

    data["Packets"] = data["Packets"].replace(
        [float("inf"), float("-inf")],
        float("nan")
    )

data = data.reset_index(drop=True)

record_count = len(data)
protocol_count = data["Protocol"].nunique()

threshold = None
flagged_records = pd.DataFrame()

data["Anomaly Status"] = "Not Evaluated"

# ---------------- BASIC ANOMALY DETECTION ----------------

if has_packets:
    valid_packets = data["Packets"].dropna()
    data["Anomaly Status"] = "Normal"

    if len(valid_packets) >= 2:
        threshold = (
            valid_packets.mean()
            + 2 * valid_packets.std()
        )

        data.loc[
            data["Packets"] > threshold,
            "Anomaly Status"
        ] = "Potential Anomaly"

    flagged_records = data[
        data["Anomaly Status"] == "Potential Anomaly"
    ].copy()

anomaly_count = len(flagged_records)


# ---------------- MAIN HERO ----------------

hero_left, hero_right = st.columns([4, 1])

with hero_left:
    st.markdown("""
    <div class="hero">
        <div class="hero-title">Network Security Center</div>
        <div class="hero-text">
            Monitor network traffic, explore protocol activity,
            and review potentially unusual records.
        </div>
        <br>
        <b>ANALYZE &nbsp; • &nbsp; DETECT &nbsp; • &nbsp; STAY SECURE</b>
    </div>
    """, unsafe_allow_html=True)

with hero_right:
    st.markdown("""
    <div class="hero">
        <div class="hero-visual">🌐🛡️</div>
    </div>
    """, unsafe_allow_html=True)

if sample_mode:
    st.info(
        "DEMO MODE — Sample data is being displayed. "
        "Upload your own CSV using the sidebar to analyze it."
    )
else:
    st.success(
        f"Dataset loaded successfully: {record_count} records"
    )


# =====================================================
# PAGE 1: OVERVIEW
# =====================================================

if page == "Overview":

    st.markdown(
        '<div class="section-title">📊 Overview</div>',
        unsafe_allow_html=True
    )

    col1, col2, col3 = st.columns(3)

    col1.metric(
        "Records Analyzed",
        f"{record_count:,}"
    )

    col2.metric(
        "Protocols Detected",
        protocol_count
    )

    col3.metric(
        "Potential Anomalies",
        anomaly_count
    )

    st.markdown(
        '<div class="section-title">📈 Traffic Overview</div>',
        unsafe_allow_html=True
    )

    if has_packets:
        chart_data = (
            data.groupby("Protocol", as_index=False)
            .agg(
                Packets=("Packets", "sum"),
                Records=("Protocol", "size")
            )
        )

        left, right = st.columns(2)

        with left:
            fig = px.bar(
                chart_data,
                x="Protocol",
                y="Packets",
                color="Protocol",
                title="Traffic Volume by Protocol",
                color_discrete_sequence=[
                    "#0878db", "#38bdf8", "#f43f5e",
                    "#8b5cf6", "#10b981", "#f59e0b"
                ],
                template="plotly_white"
            )

            fig.update_layout(
                showlegend=False,
                margin=dict(l=15, r=15, t=55, b=15),
                paper_bgcolor="white",
                plot_bgcolor="white"
            )

            st.plotly_chart(
                fig,
                use_container_width=True
            )

        with right:
            positive_data = chart_data[
                chart_data["Packets"] > 0
            ]

            if not positive_data.empty:
                pie_fig = px.pie(
                    positive_data,
                    names="Protocol",
                    values="Packets",
                    hole=0.58,
                    title="Protocol Distribution",
                    color_discrete_sequence=[
                        "#0878db", "#38bdf8", "#f43f5e",
                        "#8b5cf6", "#10b981", "#f59e0b"
                    ]
                )

                pie_fig.update_layout(
                    margin=dict(l=10, r=10, t=55, b=10),
                    paper_bgcolor="white",
                    legend_title_text=""
                )

                st.plotly_chart(
                    pie_fig,
                    use_container_width=True
                )
            else:
                st.info(
                    "No positive packet totals to display."
                )

        st.markdown(
            '<div class="section-title">📋 Protocol Summary</div>',
            unsafe_allow_html=True
        )

        summary = (
            data.groupby("Protocol")
            .agg(
                Records=("Protocol", "size"),
                Total_Packets=("Packets", "sum")
            )
            .reset_index()
        )

        st.dataframe(
            summary,
            use_container_width=True,
            hide_index=True
        )

    else:
        st.warning(
            "Add a Packets column to your CSV to display "
            "traffic charts and packet statistics."
        )

    st.markdown(
        '<div class="section-title">🧾 Recent Traffic Records</div>',
        unsafe_allow_html=True
    )

    st.dataframe(
        data.head(10),
        use_container_width=True,
        hide_index=True
    )

    st.download_button(
        "⬇ Download Analyzed Data",
        data=data.to_csv(index=False),
        file_name="flowwatch_analyzed.csv",
        mime="text/csv"
    )


# =====================================================
# PAGE 2: TRAFFIC ANALYSIS
# =====================================================

elif page == "Traffic Analysis":

    st.markdown(
        '<div class="section-title">📈 Traffic Analysis</div>',
        unsafe_allow_html=True
    )

    if not has_packets:
        st.warning(
            "Upload a CSV containing a numeric Packets column."
        )
    else:
        selected_protocols = st.multiselect(
            "Choose protocols to compare",
            options=sorted(data["Protocol"].unique()),
            default=sorted(data["Protocol"].unique())
        )

        filtered_data = data[
            data["Protocol"].isin(selected_protocols)
        ]

        if filtered_data.empty:
            st.info("Select at least one protocol.")
        else:
            summary = (
                filtered_data.groupby("Protocol", as_index=False)
                .agg(
                    Records=("Protocol", "size"),
                    Total_Packets=("Packets", "sum")
                )
            )

            fig = px.bar(
                summary,
                x="Protocol",
                y="Total_Packets",
                color="Protocol",
                title="Selected Protocol Traffic",
                color_discrete_sequence=[
                    "#0878db", "#38bdf8", "#f43f5e",
                    "#8b5cf6", "#10b981", "#f59e0b"
                ],
                template="plotly_white"
            )

            st.plotly_chart(
                fig,
                use_container_width=True
            )

            st.markdown("#### Protocol Statistics")

            st.dataframe(
                summary,
                use_container_width=True,
                hide_index=True
            )

            st.download_button(
                "⬇ Download Protocol Summary",
                data=summary.to_csv(index=False),
                file_name="flowwatch_protocol_summary.csv",
                mime="text/csv"
            )


# =====================================================
# PAGE 3: ANOMALY DETECTION
# =====================================================

elif page == "Anomaly Detection":

    st.markdown(
        '<div class="section-title">🚨 Anomaly Detection Center</div>',
        unsafe_allow_html=True
    )

    st.markdown("""
    <div class="status-note">
        <b>Detection method: Statistical threshold</b><br>
        This baseline rule flags packet counts above the dataset
        mean plus two standard deviations.
    </div>
    """, unsafe_allow_html=True)

    if not has_packets or threshold is None:
        st.info(
            "At least two valid numeric Packets values are "
            "required for anomaly detection."
        )

    elif flagged_records.empty:
        st.success(
            "No unusually high packet counts were detected "
            "by the current statistical rule."
        )

    else:
        st.warning(
            f"{anomaly_count} potentially unusual record(s) detected."
        )

        st.dataframe(
            flagged_records,
            use_container_width=True,
            hide_index=True
        )

        st.download_button(
            "⬇ Download Anomaly Report",
            data=flagged_records.to_csv(index=False),
            file_name="flowwatch_anomaly_report.csv",
            mime="text/csv"
        )

    st.caption(
        "A flagged record is not proof of a cyberattack. "
        "Results depend on the dataset and detection rule."
    )


# =====================================================
# PAGE 4: DATA EXPLORER
# =====================================================

elif page == "Data Explorer":

    st.markdown(
        '<div class="section-title">🗂️ Data Explorer</div>',
        unsafe_allow_html=True
    )

    selected_protocol = st.selectbox(
        "Filter by protocol",
        ["All"] + sorted(data["Protocol"].unique().tolist())
    )

    if selected_protocol == "All":
        filtered_data = data
    else:
        filtered_data = data[
            data["Protocol"] == selected_protocol
        ]

    st.write(
        f"Showing {len(filtered_data)} of {len(data)} records."
    )

    st.dataframe(
        filtered_data,
        use_container_width=True,
        hide_index=True
    )

    st.download_button(
        "⬇ Download Filtered Records",
        data=filtered_data.to_csv(index=False),
        file_name="flowwatch_filtered_records.csv",
        mime="text/csv"
    )


# ---------------- FOOTER ----------------

st.markdown("---")

st.markdown("""
<div class="footer">
    🛡️ FlowWatch &nbsp; | &nbsp;
    Network Traffic Monitoring & Analysis &nbsp; | &nbsp;
    Student Project
</div>
""", unsafe_allow_html=True)
