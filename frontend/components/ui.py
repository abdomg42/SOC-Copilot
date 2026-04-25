from __future__ import annotations

from typing import Any, Dict, Iterable, List, Sequence, Tuple

import pandas as pd
import streamlit as st


def render_hero(title: str, subtitle: str) -> None:
    st.markdown(
        f"""
<div class="soc-hero">
  <h1 class="soc-title">{title}</h1>
  <p class="soc-subtitle">{subtitle}</p>
</div>
        """,
        unsafe_allow_html=True,
    )


def render_stat_cards(items: Iterable[Tuple[str, str]]) -> None:
    cards = []
    for label, value in items:
        cards.append(
            f"""
<div class="soc-card">
  <div class="soc-card-label">{label}</div>
  <div class="soc-card-value">{value}</div>
</div>
            """
        )
    html = "<div class='soc-grid'>" + "".join(cards) + "</div>"
    st.markdown(html, unsafe_allow_html=True)


def normalize_severity(severity: Any) -> str:
    value = str(severity or "").strip().lower()
    if value in {"critical", "high", "medium", "low"}:
        return value
    return "na"


def severity_badge(severity: Any) -> str:
    mapped = normalize_severity(severity)
    label = mapped.upper() if mapped != "na" else "N/A"
    return (
        f"<span class='soc-severity soc-severity-{mapped}'>"
        f"{label}"
        f"</span>"
    )


def _to_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, list):
        return ", ".join(str(x) for x in value)
    return str(value)


def render_report(report: Dict[str, Any]) -> None:
    if not report:
        st.info("No report available yet.")
        return

    severity = report.get("severity", "N/A")
    title = report.get("title", "Untitled incident")

    left, right = st.columns([5, 2])
    with left:
        st.subheader(title)
    with right:
        st.markdown(severity_badge(severity), unsafe_allow_html=True)

    explanation = report.get("explanation")
    if explanation:
        st.write(explanation)

    c1, c2, c3 = st.columns(3)
    c1.metric("MITRE Technique", _to_text(report.get("mitre_technique_id", "N/A")))
    c2.metric("Technique Name", _to_text(report.get("mitre_technique_name", "N/A")))
    c3.metric("Tactic", _to_text(report.get("mitre_tactic", "N/A")))

    attack_sequence = report.get("attack_sequence", [])
    if attack_sequence:
        st.markdown("### Attack Sequence")
        for step in attack_sequence:
            st.markdown(f"- {step}")

    iocs = report.get("iocs", [])
    if iocs:
        st.markdown("### Indicators")
        ioc_frame = pd.DataFrame(iocs)
        st.dataframe(ioc_frame, use_container_width=True, hide_index=True)

    remediations = report.get("remediation_steps", [])
    if remediations:
        st.markdown("### Remediation Plan")
        rem_frame = pd.DataFrame(remediations)
        st.dataframe(rem_frame, use_container_width=True, hide_index=True)

    confidence = report.get("confidence")
    if isinstance(confidence, (int, float)):
        bounded = max(0.0, min(float(confidence), 1.0))
        st.progress(bounded, text=f"Confidence: {bounded:.2f}")


def _drill(item: Dict[str, Any], path: str) -> Any:
    current: Any = item
    for part in path.split("."):
        if isinstance(current, dict):
            current = current.get(part)
        else:
            return None
    return current


def pick_value(item: Dict[str, Any], paths: Sequence[str], default: Any = None) -> Any:
    for path in paths:
        value = _drill(item, path)
        if value not in (None, "", []):
            return value
    return default


def level_to_severity(level: Any) -> str:
    try:
        parsed = int(level)
    except (TypeError, ValueError):
        return "low"

    if parsed >= 13:
        return "critical"
    if parsed >= 10:
        return "high"
    if parsed >= 6:
        return "medium"
    return "low"


def alerts_to_dataframe(alerts: Sequence[Dict[str, Any]]) -> pd.DataFrame:
    rows: List[Dict[str, Any]] = []
    for idx, alert in enumerate(alerts):
        src_ip = pick_value(
            alert,
            [
                "src_ip",
                "srcip",
                "data.srcip",
                "eventdata.srcip",
                "event.srcip",
            ],
            default="N/A",
        )
        rule_level = pick_value(alert, ["rule_level", "rule.level"], default=0)
        ml_severity = pick_value(alert, ["ml_severity"], default="")
        severity = ml_severity or level_to_severity(rule_level)

        mitre_id = pick_value(alert, ["rule.mitre.id", "mitre_technique_id"], default="N/A")
        if isinstance(mitre_id, list):
            mitre_id = ", ".join(str(x) for x in mitre_id)

        row = {
            "row_id": idx,
            "timestamp": pick_value(alert, ["timestamp", "@timestamp"], default="N/A"),
            "severity": str(severity).lower(),
            "ml_attack_category": pick_value(alert, ["ml_attack_category"], default="N/A"),
            "rule_level": rule_level,
            "rule_description": pick_value(
                alert, ["rule_description", "rule.description"], default="N/A"
            ),
            "rule_id": pick_value(alert, ["rule.id"], default="N/A"),
            "src_ip": src_ip,
            "agent_name": pick_value(alert, ["agent_name", "agent.name"], default="N/A"),
            "mitre_id": mitre_id,
        }
        rows.append(row)

    if not rows:
        return pd.DataFrame()

    frame = pd.DataFrame(rows)
    frame["severity"] = frame["severity"].fillna("na").str.lower()
    return frame


def alert_to_payload(alert: Dict[str, Any]) -> Dict[str, Any]:
    rule_level = pick_value(alert, ["rule_level", "rule.level"], default=0)
    try:
        normalized_rule_level = int(float(rule_level))
    except (TypeError, ValueError):
        normalized_rule_level = 0

    payload = {
        "rule_description": pick_value(alert, ["rule_description", "rule.description"], default="N/A"),
        "src_ip": pick_value(
            alert,
            ["src_ip", "srcip", "data.srcip", "eventdata.srcip", "event.srcip"],
            default="N/A",
        ),
        "timestamp": pick_value(alert, ["timestamp", "@timestamp"], default=""),
        "rule_level": normalized_rule_level,
        "ml_severity": pick_value(alert, ["ml_severity"], default=None),
        "ml_attack_category": pick_value(alert, ["ml_attack_category"], default=None),
        "ml_anomaly_score": pick_value(alert, ["ml_anomaly_score"], default=None),
        "agent_name": pick_value(alert, ["agent_name", "agent.name"], default=None),
        "extra": {
            "rule_id": pick_value(alert, ["rule.id"], default="N/A"),
            "raw_alert": alert,
        },
    }
    return payload
