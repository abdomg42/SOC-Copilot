from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
import html
from typing import Any, Dict, List

import pandas as pd
import plotly.express as px
import streamlit as st

from components.ui import alerts_to_dataframe, render_hero, render_stat_cards, severity_badge
from core.api_client import APIError
from core.config import load_config
from core.state import get_api_client, init_session_state
from core.theme import apply_theme

st.set_page_config(
    page_title="SOC Dashboard",
    page_icon=":bar_chart:",
    layout="wide",
    initial_sidebar_state="expanded",
)

apply_theme()
init_session_state()
cfg = load_config()
client = get_api_client()

CACHE_KEY = "dashboard_alerts_cache"
FILTER_KEY = "dashboard_filters"


def _fetch_alerts(hours: int) -> Dict[str, Any]:
    """Fetch alerts with a consistent response shape for caching."""
    timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    try:
        payload = client.get_alerts(hours=hours, severity="Toutes")
        return {
            "alerts": payload.get("alerts", []),
            "error": payload.get("error", ""),
            "fetched_at": timestamp,
        }
    except APIError as exc:
        return {"alerts": [], "error": str(exc), "fetched_at": timestamp}


def _count_resolved(alerts: List[Dict[str, Any]]) -> int:
    """Best-effort resolved count based on common status fields."""
    resolved_markers = {"resolved", "closed", "done", "mitigated", "fixed"}
    keys = ("status", "alert_status", "state", "resolution", "resolved")
    count = 0
    for alert in alerts:
        if not isinstance(alert, dict):
            continue
        value = None
        for key in keys:
            if key in alert:
                value = alert.get(key)
                break
        if value is None:
            continue
        if str(value).strip().lower() in resolved_markers:
            count += 1
    return count


def _build_alert_feed(frame: pd.DataFrame, max_items: int = 8) -> None:
    """Render a compact alert feed with severity badges."""
    if frame.empty:
        st.info("No alerts available for the selected window.")
        return

    view = frame.copy()
    view["timestamp_parsed"] = pd.to_datetime(view["timestamp"], errors="coerce", utc=True)
    view = view.sort_values("timestamp_parsed", ascending=False).head(max_items)

    cards: List[str] = []
    for _, row in view.iterrows():
        timestamp = html.escape(str(row.get("timestamp", "N/A")))
        severity_html = severity_badge(row.get("severity", "na"))
        description = html.escape(str(row.get("rule_description", "N/A")))
        if len(description) > 120:
            description = description[:117] + "..."
        src_ip = html.escape(str(row.get("src_ip", "10.0.2.15")))
        agent = html.escape(str(row.get("agent_name", "N/A")))

        cards.append(
            f"""
<div class="soc-feed-item">
  <div class="soc-feed-meta">{timestamp}</div>
  <div>{severity_html}</div>
  <div>
    <div class="soc-feed-title">{description}</div>
    <div class="soc-feed-meta">{src_ip} | {agent}</div>
  </div>
</div>
            """
        )

    st.markdown("<div class='soc-feed'>" + "".join(cards) + "</div>", unsafe_allow_html=True)


if CACHE_KEY not in st.session_state:
    st.session_state[CACHE_KEY] = {"alerts": [], "error": "", "fetched_at": "N/A"}
if FILTER_KEY not in st.session_state:
    st.session_state[FILTER_KEY] = {"hours": cfg.default_alert_window_h}

# Sidebar controls for the dashboard window and refresh.
st.sidebar.title("SOC Copilot")
st.sidebar.caption("Unified dashboard + chat")
st.sidebar.markdown(f"API base: {cfg.api_base_url}")

hours = st.sidebar.slider(
    "Lookback window (hours)",
    min_value=1,
    max_value=72,
    value=int(st.session_state[FILTER_KEY]["hours"]),
)
refresh = st.sidebar.button("Refresh alerts", type="primary", use_container_width=True)

filters_changed = st.session_state[FILTER_KEY]["hours"] != hours
if refresh or filters_changed or not st.session_state[CACHE_KEY]["alerts"]:
    st.session_state[FILTER_KEY] = {"hours": hours}
    with st.spinner("Fetching alerts from backend..."):
        st.session_state[CACHE_KEY] = _fetch_alerts(hours)

cache = st.session_state[CACHE_KEY]
alerts: List[Dict[str, Any]] = cache.get("alerts", [])
error = cache.get("error", "")
fetched_at = cache.get("fetched_at", "N/A")

render_hero(
    "SOC Dashboard",
    "Live alert telemetry with fast summaries and trend highlights for quick triage.",
)

if error:
    st.warning(f"Backend warning: {error}")

frame = alerts_to_dataframe(alerts)
sev_counts = Counter(frame["severity"].tolist()) if not frame.empty else Counter()
resolved_alerts = _count_resolved(alerts)

# Summary widgets keep the critical counts visible at a glance.
if frame.empty:
    render_stat_cards(
        [
            ("Alerts (window)", "0"),
            ("Alerts today", "0"),
            ("Critical", "0"),
            ("High", "0"),
            ("Resolved", str(resolved_alerts)),
        ]
    )
    st.info("No alerts found for the selected window.")
    st.caption(f"Last fetch: {fetched_at}")
    st.stop()

frame["timestamp_parsed"] = pd.to_datetime(frame["timestamp"], errors="coerce", utc=True)
now_utc = pd.Timestamp.now(tz="UTC")
alerts_today = int((frame["timestamp_parsed"] >= now_utc.normalize()).sum())

render_stat_cards(
    [
        ("Alerts (window)", str(len(frame))),
        ("Alerts today", str(alerts_today)),
        ("Critical", str(sev_counts.get("critical", 0))),
        ("High", str(sev_counts.get("high", 0))),
        ("Resolved", str(resolved_alerts)),
    ]
)

# Main layout: live feed on the left, trend on the right.
feed_col, trend_col = st.columns([1.35, 1])
with feed_col:
    st.markdown("### Recent Alert Feed")
    _build_alert_feed(frame)
with trend_col:
    st.markdown("### Alert Trend")
    trend = frame.dropna(subset=["timestamp_parsed"]).copy()
    if trend.empty:
        st.info("No timestamps available for trend charting.")
    else:
        trend["hour"] = trend["timestamp_parsed"].dt.floor("H")
        per_hour = trend.groupby("hour", as_index=False).size().rename(columns={"size": "count"})
        fig_trend = px.line(
            per_hour,
            x="hour",
            y="count",
            markers=True,
            title="Alerts per hour",
        )
        fig_trend.update_layout(height=320, margin=dict(l=20, r=20, t=60, b=20))
        st.plotly_chart(fig_trend, use_container_width=True)

    # Severity distribution keeps overall risk profile visible.
st.markdown("### Severity Breakdown")
sev_series = frame["severity"].value_counts().rename_axis("severity").reset_index(name="count")
fig_severity = px.bar(
    sev_series,
    x="severity",
    y="count",
    color="severity",
    color_discrete_map={
        "critical": "#8f1520",
        "high": "#b33121",
        "medium": "#d58a2f",
        "low": "#2f7b4b",
        "na": "#76706a",
    },
    title="Severity distribution",
)
fig_severity.update_layout(showlegend=False, height=300, margin=dict(l=20, r=20, t=60, b=20))
st.plotly_chart(fig_severity, use_container_width=True)

st.caption(f"Last fetch: {fetched_at}")
