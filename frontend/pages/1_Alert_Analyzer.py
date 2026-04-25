from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict

import streamlit as st

from components.ui import render_hero, render_report
from core.api_client import APIError
from core.state import DRAFT_ALERT_KEY, get_api_client, get_last_analysis, init_session_state, set_last_analysis
from core.theme import apply_theme

apply_theme()
init_session_state()
client = get_api_client()


def _coerce_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _coerce_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _default_timestamp() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


render_hero(
    "Alert Analyzer",
    "Submit an alert payload to /analyze and receive a structured incident report.",
)

sample_payload = {
    "rule_description": "Possible SSH brute-force activity detected",
    "src_ip": "192.168.56.22",
    "timestamp": _default_timestamp(),
    "rule_level": 12,
    "ml_severity": "high",
    "ml_attack_category": "credential_access",
    "ml_anomaly_score": 0.87,
    "agent_name": "wazuh-agent-linux-01",
    "extra": {"alert_id": "demo-ssh-001", "source": "frontend-sample"},
}

control_col1, control_col2 = st.columns([1, 1])
with control_col1:
    if st.button("Load sample payload"):
        st.session_state[DRAFT_ALERT_KEY] = sample_payload
        st.rerun()
with control_col2:
    if st.button("Clear draft"):
        st.session_state[DRAFT_ALERT_KEY] = {}
        st.rerun()

draft: Dict[str, Any] = st.session_state.get(DRAFT_ALERT_KEY, {})

with st.form("alert_analyzer_form", clear_on_submit=False):
    col1, col2 = st.columns(2)

    with col1:
        rule_description = st.text_area(
            "Rule Description",
            value=str(draft.get("rule_description", "")),
            height=110,
            placeholder="Describe the triggered detection rule...",
        )
        src_ip = st.text_input("Source IP", value=str(draft.get("src_ip", "")), placeholder="10.0.0.5")
        timestamp = st.text_input(
            "Timestamp (ISO-8601)",
            value=str(draft.get("timestamp", _default_timestamp())),
        )
        rule_level = st.slider(
            "Rule Level",
            min_value=0,
            max_value=16,
            value=max(0, min(16, _coerce_int(draft.get("rule_level", 8), 8))),
            step=1,
        )

    with col2:
        severity_options = ["", "critical", "high", "medium", "low"]
        default_severity = str(draft.get("ml_severity", "")).strip().lower()
        severity_index = severity_options.index(default_severity) if default_severity in severity_options else 0
        ml_severity = st.selectbox(
            "ML Severity",
            options=severity_options,
            index=severity_index,
            help="Optional ML enrichment field.",
        )

        ml_attack_category = st.text_input(
            "ML Attack Category",
            value=str(draft.get("ml_attack_category", "")),
            placeholder="lateral_movement",
        )
        ml_anomaly_score = st.number_input(
            "ML Anomaly Score",
            min_value=0.0,
            max_value=1.0,
            value=min(1.0, max(0.0, _coerce_float(draft.get("ml_anomaly_score", 0.0), 0.0))),
            step=0.01,
        )
        agent_name = st.text_input(
            "Agent Name",
            value=str(draft.get("agent_name", "")),
            placeholder="wazuh-agent-linux-01",
        )

    extra_default = draft.get("extra", {}) if isinstance(draft.get("extra"), dict) else {}
    extra_json = st.text_area(
        "Extra (JSON)",
        value=json.dumps(extra_default, indent=2),
        height=140,
    )

    submitted = st.form_submit_button("Run Analyze", type="primary")

if submitted:
    if not rule_description.strip():
        st.error("rule_description is required.")
    elif not src_ip.strip():
        st.error("src_ip is required.")
    elif not timestamp.strip():
        st.error("timestamp is required.")
    else:
        try:
            extra = json.loads(extra_json.strip() or "{}")
            if not isinstance(extra, dict):
                raise ValueError("Extra must be a JSON object.")
        except Exception as exc:
            st.error(f"Invalid extra JSON: {exc}")
        else:
            payload = {
                "rule_description": rule_description.strip(),
                "src_ip": src_ip.strip(),
                "timestamp": timestamp.strip(),
                "rule_level": int(rule_level),
                "ml_severity": ml_severity or None,
                "ml_attack_category": ml_attack_category.strip() or None,
                "ml_anomaly_score": float(ml_anomaly_score),
                "agent_name": agent_name.strip() or None,
                "extra": extra,
            }
            st.session_state[DRAFT_ALERT_KEY] = payload
            try:
                with st.spinner("SOC agent is analyzing the alert..."):
                    result = client.analyze_alert(payload)
                set_last_analysis(result)
                st.success("Analysis completed.")
            except APIError as exc:
                st.error(str(exc))

analysis = get_last_analysis()
if analysis:
    summary_col1, summary_col2, summary_col3 = st.columns(3)
    summary_col1.metric("Alert ID", str(analysis.get("alert_id", "unknown")))
    summary_col2.metric("Duration (s)", str(analysis.get("duration_s", "N/A")))
    summary_col3.metric(
        "Report",
        "Available" if isinstance(analysis.get("report"), dict) else "Raw",
    )

    report = analysis.get("report", {})
    if isinstance(report, dict):
        render_report(report)
    else:
        st.warning("Report was not a JSON object; showing raw output.")
        st.code(str(report), language="text")

    with st.expander("Raw analysis payload"):
        st.json(analysis)

    report_data = analysis.get("report", {})
    report_json = json.dumps(report_data, indent=2) if isinstance(report_data, dict) else str(report_data)
    st.download_button(
        label="Download report.json",
        data=report_json,
        file_name="soc_report.json",
        mime="application/json",
    )
else:
    st.info("No analysis has been run in this session yet.")
