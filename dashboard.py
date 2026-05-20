"""
IoT Threat Hunting Dashboard
Project 3 - CV Portfolio
Stack: Streamlit, Plotly, scikit-learn RF, Suricata
"""

import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
import io
import time
from pathlib import Path

# ─── PAGE CONFIG ─────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="IoT Threat Hunting Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─── CUSTOM CSS ──────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Syne:wght@400;700;800&display=swap');

/* Global */
html, body, [class*="css"] {
    font-family: 'Syne', sans-serif;
    background-color: #090e1a;
    color: #c8d6ef;
}

/* Sidebar */
section[data-testid="stSidebar"] {
    background: #0d1424;
    border-right: 1px solid #1e3a5f;
}
section[data-testid="stSidebar"] * {
    color: #8aa8d0 !important;
}

/* Header bar */
.dash-header {
    background: linear-gradient(135deg, #0d1f3c 0%, #091529 100%);
    border: 1px solid #1e3a5f;
    border-radius: 8px;
    padding: 16px 24px;
    margin-bottom: 24px;
    display: flex;
    align-items: center;
    gap: 16px;
}
.dash-header h1 {
    font-family: 'Syne', sans-serif;
    font-weight: 800;
    font-size: 1.6rem;
    color: #4fc3f7;
    margin: 0;
    letter-spacing: -0.5px;
}
.dash-header .subtitle {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.72rem;
    color: #4a6a8a;
    margin-top: 2px;
}

/* Metric cards */
.metric-row {
    display: flex;
    gap: 16px;
    margin-bottom: 24px;
}
.metric-card {
    flex: 1;
    background: #0d1424;
    border: 1px solid #1e3a5f;
    border-radius: 8px;
    padding: 16px 20px;
}
.metric-card .label {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.68rem;
    color: #4a6a8a;
    text-transform: uppercase;
    letter-spacing: 1px;
    margin-bottom: 6px;
}
.metric-card .value {
    font-family: 'Syne', sans-serif;
    font-weight: 800;
    font-size: 1.9rem;
    color: #4fc3f7;
    line-height: 1;
}
.metric-card .sub {
    font-size: 0.7rem;
    color: #3a5a7a;
    margin-top: 4px;
}

/* Threat badges */
.badge {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 4px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.72rem;
    font-weight: 600;
}
.badge-ddos    { background: #1a0d2e; color: #c084fc; border: 1px solid #7c3aed; }
.badge-dos     { background: #1a1a0d; color: #fbbf24; border: 1px solid #d97706; }
.badge-recon   { background: #0d1a1a; color: #34d399; border: 1px solid #059669; }
.badge-brute   { background: #1a0d0d; color: #f87171; border: 1px solid #dc2626; }
.badge-mirai   { background: #1a0a0d; color: #fb7185; border: 1px solid #e11d48; }
.badge-spoof   { background: #0d1020; color: #818cf8; border: 1px solid #4f46e5; }
.badge-benign  { background: #0d1a0d; color: #4ade80; border: 1px solid #16a34a; }

/* Live indicator */
.live-dot {
    width: 8px; height: 8px;
    border-radius: 50%;
    background: #22c55e;
    display: inline-block;
    animation: blink 1.2s ease-in-out infinite;
    margin-right: 6px;
}
@keyframes blink {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.2; }
}

/* Alert note */
.alert-note {
    background: #0d1a2e;
    border-left: 3px solid #2563eb;
    border-radius: 4px;
    padding: 10px 14px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.74rem;
    color: #60a5fa;
    margin-bottom: 16px;
}

/* Tables */
.stDataFrame { border: 1px solid #1e3a5f !important; border-radius: 6px; }

/* Tabs */
.stTabs [data-baseweb="tab-list"] {
    background: #0d1424;
    border-bottom: 1px solid #1e3a5f;
    gap: 0;
}
.stTabs [data-baseweb="tab"] {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.8rem;
    color: #4a6a8a;
    padding: 10px 20px;
}
.stTabs [aria-selected="true"] {
    color: #4fc3f7 !important;
    border-bottom: 2px solid #4fc3f7 !important;
}

/* Upload area */
.uploadedFile { background: #0d1424 !important; border: 1px solid #1e3a5f !important; }

/* Scrollbar */
::-webkit-scrollbar { width: 6px; }
::-webkit-scrollbar-track { background: #090e1a; }
::-webkit-scrollbar-thumb { background: #1e3a5f; border-radius: 3px; }
</style>
""", unsafe_allow_html=True)

# ─── CONSTANTS ───────────────────────────────────────────────────────────────
FEATURE_COLS_V3 = [
    'flow_duration', 'Duration', 'Rate', 'Srate', 'Drate',
    'fin_flag_number', 'syn_flag_number', 'rst_flag_number', 'psh_flag_number',
    'ack_flag_number', 'ece_flag_number', 'cwr_flag_number',
    'ack_count', 'syn_count', 'fin_count', 'urg_count', 'rst_count',
    'HTTP', 'HTTPS', 'DNS', 'Telnet', 'SMTP', 'SSH', 'IRC',
    'TCP', 'UDP', 'DHCP', 'ARP', 'ICMP', 'IPv', 'LLC',
    'Tot sum', 'Min', 'Max', 'AVG', 'Std', 'Tot size',
    'Number', 'Magnitue', 'Radius', 'Covariance', 'Variance', 'Weight'
]

CLASS_COLORS = {
    'DDoS':       '#c084fc',
    'DoS':        '#fbbf24',
    'Recon':      '#34d399',
    'BruteForce': '#f87171',
    'Mirai':      '#fb7185',
    'Spoofing':   '#818cf8',
    'BENIGN':     '#4ade80',
}

CLASS_BADGE = {
    'DDoS':       'badge-ddos',
    'DoS':        'badge-dos',
    'Recon':      'badge-recon',
    'BruteForce': 'badge-brute',
    'Mirai':      'badge-mirai',
    'Spoofing':   'badge-spoof',
    'BENIGN':     'badge-benign',
}

MODEL_PATH = Path("models/rf_model_v3.pkl")


# ─── MODEL LOADER ─────────────────────────────────────────────────────────────
@st.cache_resource(show_spinner=False)
def load_model():
    import pickle
    if not MODEL_PATH.exists():
        return None
    with open(MODEL_PATH, "rb") as f:
        bundle = pickle.load(f)
    return bundle


def predict_df(df: pd.DataFrame, bundle: dict):
    """Predict on a DataFrame. Returns df with prediction cols added."""
    model = bundle["model"]
    le    = bundle["label_encoder"]
    feats = bundle["features"]

    # Align columns
    missing = [c for c in feats if c not in df.columns]
    for c in missing:
        df[c] = 0.0

    X = df[feats].copy().fillna(0).astype(float)
    probs = model.predict_proba(X.values)
    pred_idx = np.argmax(probs, axis=1)
    predictions  = le.inverse_transform(pred_idx)
    confidences  = probs.max(axis=1)
    classes      = le.classes_

    result = df.copy()
    result["prediction"]  = predictions
    result["confidence"]  = confidences.round(4)
    for i, cls in enumerate(classes):
        result[f"score_{cls}"] = probs[:, i].round(4)
    return result, classes


# ─── HEADER ──────────────────────────────────────────────────────────────────
st.markdown("""
<div class="dash-header">
  <div>🛡️</div>
  <div>
    <h1>IoT Threat Hunting Dashboard</h1>
    <div class="subtitle">RF Classifier v3 · 7-class · CICIoT2023 · Blue Team / SOC Portfolio</div>
  </div>
</div>
""", unsafe_allow_html=True)

# ─── SIDEBAR ─────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("### 🔧 Configuration")
    bundle = load_model()
    if bundle:
        st.success("✅ rf_model_v3.pkl loaded")
        st.caption(f"Features: {len(bundle['features'])}  |  Classes: {len(bundle['label_encoder'].classes_)}")
    else:
        st.error("❌ Model not found at `models/rf_model_v3.pkl`")

    st.divider()
    st.markdown("**Classes**")
    for cls, color in CLASS_COLORS.items():
        st.markdown(
            f'<span class="badge {CLASS_BADGE[cls]}">{cls}</span>',
            unsafe_allow_html=True,
        )

    st.divider()
    st.markdown("**Confidence threshold**")
    conf_threshold = st.slider("Flag if below:", 0.50, 0.99, 0.70, 0.01)

    st.divider()
    st.caption("Project 3 — IoT Threat Hunting\nModel: RandomForest · n=300 · depth=30\nAccuracy: 94% · F1(DDoS/DoS/Mirai)=1.00")


# ─── TABS ────────────────────────────────────────────────────────────────────
tab1, tab2, tab3 = st.tabs([
    "📂  CSV Analysis",
    "📊  Analytics",
    "🔴  Live Monitor",
])


# ════════════════════════════════════════════════════════════════════════════
# TAB 1 — CSV ANALYSIS
# ════════════════════════════════════════════════════════════════════════════
with tab1:
    st.markdown("#### Upload CICIoT2023 CSV for batch prediction")
    st.markdown(
        '<div class="alert-note">ℹ️ Upload bất kỳ CSV nào từ CICIoT2023. '
        'Dashboard tự detect 43 features từ FEATURE_COLS_V3. '
        'Cột thiếu → fill 0.0 tự động.</div>',
        unsafe_allow_html=True,
    )

    uploaded = st.file_uploader(
        "Drop CSV here", type=["csv"], label_visibility="collapsed"
    )

    if uploaded and bundle:
        with st.spinner("⚙️ Reading CSV…"):
            try:
                raw_df = pd.read_csv(uploaded, low_memory=False)
            except Exception as e:
                st.error(f"CSV parse error: {e}")
                st.stop()

        st.caption(f"Loaded **{len(raw_df):,}** rows · **{len(raw_df.columns)}** columns")

        # Check label column
        has_label = "label" in raw_df.columns

        with st.spinner("🤖 Running RF predictions…"):
            result_df, classes = predict_df(raw_df.copy(), bundle)

        # ── Summary metrics ──────────────────────────────────────────────
        total     = len(result_df)
        n_threat  = (result_df["prediction"] != "BENIGN").sum()
        n_benign  = total - n_threat
        avg_conf  = result_df["confidence"].mean()
        low_conf  = (result_df["confidence"] < conf_threshold).sum()

        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Total flows", f"{total:,}")
        col2.metric("Threats detected", f"{n_threat:,}", delta=f"{n_threat/total*100:.1f}%", delta_color="inverse")
        col3.metric("Avg confidence", f"{avg_conf:.2%}")
        col4.metric(f"Low conf (<{conf_threshold:.0%})", f"{low_conf:,}")

        st.divider()

        # ── Result table ─────────────────────────────────────────────────
        display_cols = ["prediction", "confidence"]
        score_cols   = [f"score_{c}" for c in classes]
        if has_label:
            display_cols = ["label"] + display_cols
        display_cols += score_cols

        # Trim to available
        display_cols = [c for c in display_cols if c in result_df.columns]

        st.markdown("**Prediction Results** (first 500 rows)")

        def color_prediction(val):
            c = CLASS_COLORS.get(val, "#ffffff")
            return f"color: {c}; font-weight: 600; font-family: 'JetBrains Mono', monospace;"

        def color_confidence(val):
            if val < conf_threshold:
                return "color: #f87171;"
            return "color: #4ade80;"

        styled = (
            result_df[display_cols]
            .head(500)
            .style
            .applymap(color_prediction, subset=["prediction"])
            .applymap(color_confidence, subset=["confidence"])
            .format({c: "{:.3f}" for c in score_cols + ["confidence"]})
        )
        st.dataframe(styled, use_container_width=True, height=380)

        # ── Accuracy vs ground truth ──────────────────────────────────────
        if has_label:
            st.divider()
            st.markdown("**Ground Truth Comparison**")
            correct = (result_df["prediction"] == result_df["label"]).sum()
            acc = correct / total
            st.progress(float(acc), text=f"Accuracy vs label column: {acc:.2%}  ({correct:,}/{total:,} correct)")

        # ── Download ─────────────────────────────────────────────────────
        st.divider()
        csv_out = result_df[display_cols].to_csv(index=False).encode()
        st.download_button(
            "⬇️ Download predictions CSV",
            data=csv_out,
            file_name="iot_predictions.csv",
            mime="text/csv",
        )

    elif uploaded and not bundle:
        st.error("Model not loaded. Check `models/rf_model_v3.pkl`.")
    else:
        # Placeholder state
        st.info("👆 Upload a CSV to start analysis.")
        st.markdown("""
**Expected format:** Any CSV from CICIoT2023 dataset  
**Auto-detected features:** 43 columns from FEATURE_COLS_V3  
**Output classes:** BENIGN · DDoS · DoS · Recon · BruteForce · Mirai · Spoofing
        """)


# ════════════════════════════════════════════════════════════════════════════
# TAB 2 — ANALYTICS
# ════════════════════════════════════════════════════════════════════════════
with tab2:
    # Grab result_df from session state or tab1 context
    # We use st.session_state to share data across tabs
    if "result_df" not in st.session_state and "result_df_tab1" not in dir():
        # Check if uploaded was processed in tab1 this session
        pass

    # Re-use result from tab1 if available (Streamlit re-runs full script)
    try:
        df_anal = result_df  # set in tab1
    except NameError:
        df_anal = None

    if df_anal is None or "prediction" not in df_anal.columns:
        st.info("📂 Run a CSV prediction in **CSV Analysis** tab first.")
    else:
        col_l, col_r = st.columns([1, 1])

        # ── Donut — class distribution ────────────────────────────────────
        with col_l:
            counts = df_anal["prediction"].value_counts().reset_index()
            counts.columns = ["Class", "Count"]
            colors = [CLASS_COLORS.get(c, "#888") for c in counts["Class"]]

            fig_pie = go.Figure(go.Pie(
                labels=counts["Class"],
                values=counts["Count"],
                hole=0.55,
                marker_colors=colors,
                textinfo="label+percent",
                textfont_size=12,
                hovertemplate="%{label}: %{value:,} flows<extra></extra>",
            ))
            fig_pie.update_layout(
                title="Traffic Class Distribution",
                paper_bgcolor="#090e1a",
                plot_bgcolor="#090e1a",
                font_color="#c8d6ef",
                showlegend=False,
                margin=dict(t=40, b=10, l=10, r=10),
                height=320,
            )
            st.plotly_chart(fig_pie, use_container_width=True)

        # ── Bar — class counts ─────────────────────────────────────────────
        with col_r:
            fig_bar = go.Figure(go.Bar(
                x=counts["Class"],
                y=counts["Count"],
                marker_color=colors,
                text=counts["Count"],
                textposition="outside",
                textfont_color="#c8d6ef",
            ))
            fig_bar.update_layout(
                title="Flow Count by Class",
                paper_bgcolor="#090e1a",
                plot_bgcolor="#0d1424",
                font_color="#c8d6ef",
                xaxis=dict(showgrid=False),
                yaxis=dict(gridcolor="#1e3a5f"),
                margin=dict(t=40, b=10, l=10, r=10),
                height=320,
            )
            st.plotly_chart(fig_bar, use_container_width=True)

        # ── Confidence distribution ───────────────────────────────────────
        st.divider()
        fig_hist = px.histogram(
            df_anal,
            x="confidence",
            color="prediction",
            color_discrete_map=CLASS_COLORS,
            nbins=50,
            title="Confidence Distribution by Class",
            labels={"confidence": "Confidence Score", "count": "Flows"},
        )
        fig_hist.update_layout(
            paper_bgcolor="#090e1a",
            plot_bgcolor="#0d1424",
            font_color="#c8d6ef",
            xaxis=dict(gridcolor="#1e3a5f"),
            yaxis=dict(gridcolor="#1e3a5f"),
            margin=dict(t=40, b=10),
            height=280,
            bargap=0.05,
        )
        st.plotly_chart(fig_hist, use_container_width=True)

        # ── Timeline (if timestamp cols exist) ────────────────────────────
        ts_candidates = [c for c in df_anal.columns if "time" in c.lower() or "timestamp" in c.lower()]
        if ts_candidates:
            st.divider()
            ts_col = ts_candidates[0]
            try:
                ts_df = df_anal.copy()
                ts_df[ts_col] = pd.to_datetime(ts_df[ts_col], errors="coerce")
                ts_df = ts_df.dropna(subset=[ts_col])
                ts_df["minute"] = ts_df[ts_col].dt.floor("1min")
                timeline = ts_df.groupby(["minute", "prediction"]).size().reset_index(name="count")
                fig_tl = px.line(
                    timeline, x="minute", y="count", color="prediction",
                    color_discrete_map=CLASS_COLORS,
                    title=f"Timeline (1-min bins) — {ts_col}",
                )
                fig_tl.update_layout(
                    paper_bgcolor="#090e1a", plot_bgcolor="#0d1424",
                    font_color="#c8d6ef",
                    xaxis=dict(gridcolor="#1e3a5f"),
                    yaxis=dict(gridcolor="#1e3a5f"),
                    margin=dict(t=40, b=10), height=280,
                )
                st.plotly_chart(fig_tl, use_container_width=True)
            except Exception:
                pass

        # ── Top Source IPs ─────────────────────────────────────────────────
        ip_candidates = [c for c in df_anal.columns if "src_ip" in c.lower() or "srcip" in c.lower() or "source_ip" in c.lower()]
        if ip_candidates:
            st.divider()
            ip_col = ip_candidates[0]
            top_ips = (
                df_anal[df_anal["prediction"] != "BENIGN"][ip_col]
                .value_counts()
                .head(10)
                .reset_index()
            )
            top_ips.columns = ["IP", "Threat Flows"]
            st.markdown("**Top 10 Source IPs (Threat traffic only)**")
            st.dataframe(top_ips, use_container_width=True, height=250)

        # ── Summary stats ──────────────────────────────────────────────────
        st.divider()
        st.markdown("**Class Breakdown Summary**")
        summary = df_anal.groupby("prediction").agg(
            count=("prediction", "count"),
            avg_conf=("confidence", "mean"),
            min_conf=("confidence", "min"),
            max_conf=("confidence", "max"),
        ).reset_index()
        summary.columns = ["Class", "Flows", "Avg Conf", "Min Conf", "Max Conf"]
        summary["% of Total"] = (summary["Flows"] / len(df_anal) * 100).round(2)
        st.dataframe(
            summary.style.format({"Avg Conf": "{:.3f}", "Min Conf": "{:.3f}", "Max Conf": "{:.3f}", "% of Total": "{:.2f}%"}),
            use_container_width=True,
        )


# ════════════════════════════════════════════════════════════════════════════
# TAB 3 — LIVE MONITOR (Suricata)
# ════════════════════════════════════════════════════════════════════════════
with tab3:
    st.markdown(
        '<div class="alert-note">'
        '<span class="live-dot"></span>'
        'Live mode requires <b>Suricata running in Docker</b> with eve.json at '
        '<code>suricata/logs/eve.json</code>. '
        'Auto-refresh every 10 seconds.'
        '</div>',
        unsafe_allow_html=True,
    )

    eve_path = Path("suricata/logs/eve.json")
    suricata_ok = eve_path.exists()

    col_status, col_refresh = st.columns([3, 1])
    with col_status:
        if suricata_ok:
            st.success(f"✅ eve.json found — {eve_path.stat().st_size // 1024} KB")
        else:
            st.warning("⚠️ eve.json not found. Showing demo mode.")
    with col_refresh:
        auto_refresh = st.checkbox("Auto-refresh (10s)", value=False)

    if suricata_ok and bundle:
        # ── Real mode ────────────────────────────────────────────────────
        try:
            from parser import parse_alerts, parse_flows
            from feature_bridge import predict_batch

            placeholder = st.empty()

            def render_live():
                alerts = parse_alerts(max_lines=1000)
                flows  = parse_flows(max_lines=2000)

                with placeholder.container():
                    c1, c2, c3 = st.columns(3)
                    c1.metric("Alerts (last 1000 lines)", len(alerts))
                    c2.metric("Flows parsed", len(flows))
                    c3.metric("Last updated", time.strftime("%H:%M:%S"))

                    if flows:
                        preds = predict_batch(flows)
                        pred_df = pd.DataFrame(preds)

                        st.markdown("**Flow predictions (latest 200)**")
                        st.dataframe(pred_df.tail(200), use_container_width=True, height=320)

                        # Mini donut
                        if "class" in pred_df.columns:
                            vc = pred_df["class"].value_counts().reset_index()
                            vc.columns = ["Class", "Count"]
                            colors = [CLASS_COLORS.get(c, "#888") for c in vc["Class"]]
                            fig = go.Figure(go.Pie(
                                labels=vc["Class"], values=vc["Count"],
                                hole=0.5, marker_colors=colors,
                                textinfo="label+percent",
                            ))
                            fig.update_layout(
                                paper_bgcolor="#090e1a", font_color="#c8d6ef",
                                showlegend=False, height=260,
                                margin=dict(t=10, b=10, l=10, r=10),
                            )
                            st.plotly_chart(fig, use_container_width=True)

                    if alerts:
                        st.divider()
                        st.markdown("**Recent Alerts**")
                        alert_df = pd.DataFrame(alerts).tail(50)
                        st.dataframe(alert_df, use_container_width=True, height=280)

            render_live()

            if auto_refresh:
                time.sleep(10)
                st.rerun()

        except ImportError as e:
            st.error(f"Import error: {e}. Make sure parser.py and feature_bridge.py are in project root.")

    else:
        # ── Demo mode ────────────────────────────────────────────────────
        st.markdown("#### 📡 Demo Mode — Simulated live traffic")

        np.random.seed(int(time.time()) % 100)
        n = 50
        classes_demo = ["BENIGN", "DDoS", "DoS", "Recon", "BruteForce", "Mirai", "Spoofing"]
        weights      = [0.45, 0.20, 0.12, 0.10, 0.06, 0.04, 0.03]
        demo_preds   = np.random.choice(classes_demo, size=n, p=weights)
        demo_conf    = np.clip(np.random.beta(8, 2, n), 0.5, 0.999)

        demo_df = pd.DataFrame({
            "flow_id":    range(1, n + 1),
            "prediction": demo_preds,
            "confidence": demo_conf.round(4),
            "src_port":   np.random.randint(1024, 65535, n),
            "dst_port":   np.random.choice([80, 443, 22, 53, 23, 8080], n),
        })

        d1, d2, d3 = st.columns(3)
        n_threat_d = (demo_df["prediction"] != "BENIGN").sum()
        d1.metric("Flows (simulated)", n)
        d2.metric("Threats", n_threat_d)
        d3.metric("Avg confidence", f"{demo_conf.mean():.2%}")

        def highlight_threat(row):
            if row["prediction"] != "BENIGN":
                return ["background-color: #0d0d1a"] * len(row)
            return [""] * len(row)

        st.dataframe(
            demo_df.style.apply(highlight_threat, axis=1)
                         .applymap(
                             lambda v: f"color: {CLASS_COLORS.get(v, '#fff')}; font-weight:600;",
                             subset=["prediction"]
                         ),
            use_container_width=True, height=360,
        )

        if auto_refresh:
            time.sleep(10)
            st.rerun()

        st.caption("⚠️ This is simulated data. Start Suricata Docker to enable real live monitoring.")