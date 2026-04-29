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
            default="10.0.2.15",
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


