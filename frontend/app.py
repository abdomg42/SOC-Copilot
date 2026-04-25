from __future__ import annotations

from collections import Counter

import streamlit as st

from components.ui import alerts_to_dataframe, render_hero, render_stat_cards, severity_badge
from core.api_client import APIError
from core.config import load_config
from core.state import get_api_client, init_session_state
from core.theme import apply_theme

st.set_page_config(
    page_title="SOC Copilot Frontend",
    page_icon=":shield:",
    layout="wide",
    initial_sidebar_state="expanded",
)

apply_theme()
init_session_state()
cfg = load_config()
client = get_api_client()

st.sidebar.title("SOC Copilot")
st.sidebar.caption("Incident triage cockpit")
st.sidebar.markdown(f"API base: {cfg.api_base_url}")
st.sidebar.markdown("Use the pages below to investigate alerts and generate reports.")

health_label = "Offline"
agent_label = "N/A"
health_detail = "Backend did not respond"

try:
    health = client.health()
    health_label = health.get("status", "unknown").upper()
    agent_label = health.get("agent", "N/A")
    health_detail = "FastAPI endpoint reachable"
except APIError as exc:
    health_detail = str(exc)

st.sidebar.markdown("### Backend Status")
st.sidebar.markdown(severity_badge("low" if health_label == "OK" else "high"), unsafe_allow_html=True)
st.sidebar.caption(f"{health_label} - {agent_label}")

render_hero(
    "SOC Copilot Mission Console",
    "A multi-page Streamlit cockpit for triage, report generation, and knowledge correlation.",
)

alerts = []
alerts_error = ""
try:
    alerts_payload = client.get_alerts(hours=cfg.default_alert_window_h, severity="Toutes")
    alerts = alerts_payload.get("alerts", [])
    alerts_error = alerts_payload.get("error", "")
except APIError as exc:
    alerts_error = str(exc)

frame = alerts_to_dataframe(alerts)
sev_counts = Counter(frame["severity"].tolist()) if not frame.empty else Counter()

render_stat_cards(
    [
        ("Backend", health_label),
        ("Agent", agent_label),
        ("Alerts Loaded", str(len(alerts))),
        (
            "Critical/High",
            str(int(sev_counts.get("critical", 0) + sev_counts.get("high", 0))),
        ),
    ]
)

if alerts_error:
    st.warning(f"Alerts endpoint warning: {alerts_error}")

col1, col2 = st.columns([1.2, 1])
with col1:
    st.markdown("### Workflow")
    st.markdown("1. Open Alerts Inventory to review recent logs.")
    st.markdown("2. Send suspicious events to Alert Analyzer for structured incident reports.")
    st.markdown("3. Use SOC Chat for ad-hoc questions and investigative iterations.")
    st.markdown("4. Correlate findings with runbooks and ATT&CK/D3FEND mappings.")

    st.page_link("pages/2_Alerts_Inventory.py", label="Open Alerts Inventory")
    st.page_link("pages/1_Alert_Analyzer.py", label="Open Alert Analyzer")
    st.page_link("pages/3_SOC_Chat.py", label="Open SOC Chat")

with col2:
    st.markdown("### Live Signal Snapshot")
    if frame.empty:
        st.info("No alert data available yet. Check API connectivity from the System Health page.")
    else:
        preview = frame[[
            "timestamp",
            "severity",
            "rule_level",
            "rule_description",
            "src_ip",
            "agent_name",
        ]].head(8)
        st.dataframe(preview, use_container_width=True, hide_index=True)

st.divider()
st.caption(health_detail)
