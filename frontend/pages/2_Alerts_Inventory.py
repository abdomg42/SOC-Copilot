from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
import json
from typing import Any, Dict, List

import pandas as pd
import plotly.express as px
import streamlit as st

from components.ui import alert_to_payload, alerts_to_dataframe, render_hero, render_stat_cards
from core.api_client import APIError
from core.config import load_config
from core.state import DRAFT_ALERT_KEY, get_api_client, init_session_state
from core.theme import apply_theme

apply_theme()
init_session_state()
client = get_api_client()
cfg = load_config()

CACHE_KEY = "inventory_alerts_cache"
FILTER_KEY = "inventory_filters"


def _fetch_alerts(hours: int, severity: str) -> Dict[str, Any]:
    try:
        payload = client.get_alerts(hours=hours, severity=severity)
        return {
            "alerts": payload.get("alerts", []),
            "error": payload.get("error", ""),
            "fetched_at": datetime.now(timezone.utc).isoformat(),
        }
    except APIError as exc:
        return {"alerts": [], "error": str(exc), "fetched_at": datetime.now(timezone.utc).isoformat()}


if CACHE_KEY not in st.session_state:
    st.session_state[CACHE_KEY] = {"alerts": [], "error": "", "fetched_at": "N/A"}
if FILTER_KEY not in st.session_state:
    st.session_state[FILTER_KEY] = {
        "hours": cfg.default_alert_window_h,
        "severity": "Toutes",
    }

render_hero(
    "Alerts Inventory",
    "Inspect recent alerts from /alerts, filter by severity, and route selected events to the analyzer.",
)

filter_col1, filter_col2, filter_col3 = st.columns([1, 1, 0.7])
with filter_col1:
    hours = st.slider("Lookback Window (hours)", min_value=1, max_value=72, value=int(st.session_state[FILTER_KEY]["hours"]))
with filter_col2:
    severity_options = ["Toutes", "critical", "high", "medium", "low"]
    stored_severity = st.session_state[FILTER_KEY].get("severity", "Toutes")
    severity_index = severity_options.index(stored_severity) if stored_severity in severity_options else 0
    severity = st.selectbox(
        "Severity Filter",
        options=severity_options,
        index=severity_index,
    )
with filter_col3:
    st.write("")
    refresh = st.button("Refresh Alerts", type="primary", use_container_width=True)

filters_changed = (
    st.session_state[FILTER_KEY]["hours"] != hours
    or st.session_state[FILTER_KEY]["severity"] != severity
)

if refresh or filters_changed or not st.session_state[CACHE_KEY]["alerts"]:
    st.session_state[FILTER_KEY] = {"hours": hours, "severity": severity}
    with st.spinner("Fetching alerts from backend..."):
        st.session_state[CACHE_KEY] = _fetch_alerts(hours, severity)

cache = st.session_state[CACHE_KEY]
alerts: List[Dict[str, Any]] = cache.get("alerts", [])
error = cache.get("error", "")
fetched_at = cache.get("fetched_at", "N/A")

if error:
    st.warning(f"Backend warning: {error}")

frame = alerts_to_dataframe(alerts)
if frame.empty:
    st.info("No alerts found for the selected filters.")
    st.caption(f"Last fetch: {fetched_at}")
    st.stop()

severity_counts = Counter(frame["severity"].tolist())
render_stat_cards(
    [
        ("Fetched Alerts", str(len(frame))),
        ("Critical", str(severity_counts.get("critical", 0))),
        ("High", str(severity_counts.get("high", 0))),
        ("Medium", str(severity_counts.get("medium", 0))),
    ]
)

chart_col1, chart_col2 = st.columns([1, 1])
with chart_col1:
    sev_series = frame["severity"].value_counts().rename_axis("severity").reset_index(name="count")
    fig_severity = px.bar(
        sev_series,
        x="severity",
        y="count",
        title="Severity Distribution",
        color="severity",
        color_discrete_map={
            "critical": "#8f1520",
            "high": "#b33121",
            "medium": "#d58a2f",
            "low": "#2f7b4b",
            "na": "#76706a",
        },
    )
    fig_severity.update_layout(showlegend=False, height=340, margin=dict(l=20, r=20, t=60, b=20))
    st.plotly_chart(fig_severity, use_container_width=True)

with chart_col2:
    top_rules = (
        frame["rule_description"]
        .fillna("N/A")
        .value_counts()
        .head(8)
        .rename_axis("rule_description")
        .reset_index(name="count")
    )
    fig_rules = px.bar(
        top_rules,
        x="count",
        y="rule_description",
        orientation="h",
        title="Top Triggered Rules",
        color="count",
        color_continuous_scale=["#e7d8b9", "#d38b35", "#b33121"],
    )
    fig_rules.update_layout(height=340, margin=dict(l=20, r=20, t=60, b=20), coloraxis_showscale=False)
    st.plotly_chart(fig_rules, use_container_width=True)

st.markdown("### Alert Table")
query = st.text_input("Search rule, IP, MITRE, or agent", value="").strip().lower()

view = frame.copy()
if query:
    mask = (
        view["rule_description"].astype(str).str.lower().str.contains(query, na=False)
        | view["src_ip"].astype(str).str.lower().str.contains(query, na=False)
        | view["mitre_id"].astype(str).str.lower().str.contains(query, na=False)
        | view["agent_name"].astype(str).str.lower().str.contains(query, na=False)
    )
    view = view[mask]

st.dataframe(
    view[[
        "timestamp",
        "severity",
        "rule_level",
        "rule_description",
        "src_ip",
        "agent_name",
        "mitre_id",
    ]],
    use_container_width=True,
    hide_index=True,
    height=380,
)

options = view["row_id"].tolist()
if not options:
    st.info("No row matches the current search.")
    st.stop()

selected_row_id = st.selectbox(
    "Select one alert for deep analysis",
    options=options,
    format_func=lambda rid: (
        f"{view.loc[view['row_id'] == rid, 'timestamp'].iloc[0]} | "
        f"{view.loc[view['row_id'] == rid, 'src_ip'].iloc[0]} | "
        f"{view.loc[view['row_id'] == rid, 'rule_description'].iloc[0]}"
    ),
)

raw_alert = alerts[int(selected_row_id)]
selected_payload = alert_to_payload(raw_alert)

act_col1, act_col2 = st.columns([1, 1])
with act_col1:
    if st.button("Send Selected Alert To Analyzer", type="primary", use_container_width=True):
        st.session_state[DRAFT_ALERT_KEY] = selected_payload
        try:
            st.switch_page("pages/1_Alert_Analyzer.py")
        except Exception:
            st.success("Draft copied to session. Open the Alert Analyzer page manually.")
with act_col2:
    st.download_button(
        label="Download Selected Alert JSON",
        data=json.dumps(selected_payload, indent=2, default=str),
        file_name="selected_alert_payload.json",
        mime="application/json",
        use_container_width=True,
    )

with st.expander("Raw selected alert"):
    st.json(raw_alert)

st.caption(f"Last fetch: {fetched_at}")
