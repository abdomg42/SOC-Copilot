from __future__ import annotations

from datetime import datetime, timezone

import streamlit as st

from components.ui import render_hero, render_stat_cards, severity_badge
from core.api_client import APIError
from core.config import load_config
from core.state import get_api_client, init_session_state
from core.theme import apply_theme

apply_theme()
init_session_state()
cfg = load_config()
client = get_api_client()

render_hero(
    "System Health",
    "Validate backend reachability, endpoint behavior, and runtime configuration for the Streamlit cockpit.",
)

st.markdown("### Runtime Configuration")
render_stat_cards(
    [
        ("API Base URL", cfg.api_base_url),
        ("Request Timeout (s)", str(cfg.request_timeout_s)),
        ("Default Alert Window (h)", str(cfg.default_alert_window_h)),
        ("Max Table Rows", str(cfg.max_table_rows)),
    ]
)

st.markdown("### Endpoint Probes")
probe = st.button("Run Connectivity Checks", type="primary")

if probe:
    checks = []

    try:
        health = client.health()
        checks.append(("GET /health", "OK", str(health)))
    except APIError as exc:
        checks.append(("GET /health", "FAIL", str(exc)))

    try:
        alerts = client.get_alerts(hours=1, severity="Toutes")
        count = len(alerts.get("alerts", []))
        maybe_error = alerts.get("error", "")
        detail = f"alerts={count}" + (f" | warning={maybe_error}" if maybe_error else "")
        checks.append(("GET /alerts", "OK", detail))
    except APIError as exc:
        checks.append(("GET /alerts", "FAIL", str(exc)))

    try:
        chat = client.chat(
            question="Return one sentence about SOC triage best practice.",
            history=[],
        )
        answer = str(chat.get("answer", ""))
        checks.append(("POST /chat", "OK", answer[:180] + ("..." if len(answer) > 180 else "")))
    except APIError as exc:
        checks.append(("POST /chat", "FAIL", str(exc)))

    status_values = [item[1] for item in checks]
    global_status = "OK" if all(v == "OK" for v in status_values) else "DEGRADED"

    col1, col2 = st.columns([1, 4])
    with col1:
        st.markdown(severity_badge("low" if global_status == "OK" else "high"), unsafe_allow_html=True)
    with col2:
        st.write(f"Overall status: {global_status}")

    for endpoint, status, detail in checks:
        if status == "OK":
            st.success(f"{endpoint}: {detail}")
        else:
            st.error(f"{endpoint}: {detail}")

st.markdown("### Analyze Endpoint Smoke Test")
st.caption("Use this optional test to verify /analyze contract and report generation.")

if st.button("Run /analyze Smoke Test"):
    payload = {
        "rule_description": "Smoke test alert from frontend health page",
        "src_ip": "127.0.0.1",
        "timestamp": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "rule_level": 5,
        "ml_severity": "low",
        "ml_attack_category": "test_event",
        "ml_anomaly_score": 0.05,
        "agent_name": "frontend-smoke-test",
        "extra": {"alert_id": "health-smoke-test"},
    }
    with st.spinner("Running analyze smoke test..."):
        try:
            result = client.analyze_alert(payload)
            st.success("Analyze endpoint returned a report.")
            st.json(
                {
                    "alert_id": result.get("alert_id"),
                    "duration_s": result.get("duration_s"),
                    "report_keys": list(result.get("report", {}).keys())
                    if isinstance(result.get("report"), dict)
                    else "non-dict report",
                }
            )
        except APIError as exc:
            st.error(str(exc))

st.markdown("### Environment Variables")
st.code(
    "\n".join(
        [
            "SOC_API_BASE_URL=http://localhost:8000",
            "SOC_API_TIMEOUT=45",
            "SOC_DEFAULT_HOURS=24",
            "SOC_MAX_TABLE_ROWS=1500",
        ]
    ),
    language="bash",
)
