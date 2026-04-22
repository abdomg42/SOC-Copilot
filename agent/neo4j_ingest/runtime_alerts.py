import json
import time
from pathlib import Path
from typing import Any

from neo4j import Driver

from .connection import get_driver


def ingest_alert(alert: dict[str, Any], report: dict[str, Any], driver: Driver | None = None) -> None:
    src_ip = alert.get("src_ip", "unknown")
    dst_host = alert.get("agent_name", "unknown")
    user = alert.get("user")
    alert_id = alert.get("alert_id", f"auto-{time.time()}")
    ts = alert.get("timestamp", "")
    severity = report.get("severity", "low")
    tid = report.get("mitre_technique_id", "")
    score = float(alert.get("ml_anomaly_score", 0.5))

    session_driver = driver or get_driver()
    with session_driver.session() as session:
        session.run(
            """
            MERGE (ip:IP {address: $ip})
            ON CREATE SET ip.risk_score = 0.0,
                          ip.attack_count = 0,
                          ip.first_seen = $ts
            ON MATCH SET ip.last_seen = $ts,
                         ip.attack_count = ip.attack_count + 1,
                         ip.risk_score = CASE
                             WHEN ip.risk_score < $score THEN $score
                             ELSE ip.risk_score END
            """,
            ip=src_ip,
            ts=ts,
            score=score,
        )

        session.run(
            """
            MERGE (h:Host {name: $host})
            ON CREATE SET h.first_targeted = $ts, h.attack_count = 0
            ON MATCH SET h.last_targeted = $ts,
                         h.attack_count = coalesce(h.attack_count, 0) + 1
            """,
            host=dst_host,
            ts=ts,
        )

        session.run(
            """
            MERGE (a:Alert {alert_id: $aid})
            SET a.timestamp = $ts,
                a.severity = $sev,
                a.description = $desc,
                a.explanation = $expl
            """,
            aid=alert_id,
            ts=ts,
            sev=severity,
            desc=alert.get("rule_description", ""),
            expl=str(report.get("explanation", ""))[:300],
        )

        session.run(
            """
            MATCH (ip:IP {address: $ip}), (h:Host {name: $host})
            MERGE (ip)-[r:ATTACKED]->(h)
            ON CREATE SET r.count = 1, r.first = $ts
            ON MATCH SET r.count = r.count + 1, r.last = $ts
            """,
            ip=src_ip,
            host=dst_host,
            ts=ts,
        )

        session.run(
            """
            MATCH (ip:IP {address: $ip}), (a:Alert {alert_id: $aid})
            MERGE (ip)-[:TRIGGERED]->(a)
            """,
            ip=src_ip,
            aid=alert_id,
        )

        if tid:
            session.run(
                """
                MATCH (a:Alert {alert_id: $aid})
                MATCH (t:MitreTechnique {tid: $tid})
                MERGE (a)-[:USES]->(t)
                """,
                aid=alert_id,
                tid=tid,
            )

        if user:
            session.run(
                """
                MERGE (u:User {name: $user})
                WITH u
                MATCH (h:Host {name: $host})
                MERGE (u)-[:TARGETED_ON]->(h)
                """,
                user=user,
                host=dst_host,
            )

        session.run(
            """
            MATCH (ip:IP {address: $ip})-[:TRIGGERED]->(prev:Alert)
            WHERE prev.alert_id <> $aid
            WITH prev ORDER BY prev.timestamp DESC LIMIT 1
            MATCH (curr:Alert {alert_id: $aid})
            MERGE (prev)-[:FOLLOWED_BY]->(curr)
            """,
            ip=src_ip,
            aid=alert_id,
        )


def _severity_from_level(level: int) -> str:
    if level >= 10:
        return "critical"
    if level >= 7:
        return "high"
    if level >= 4:
        return "medium"
    return "low"


def _is_windows_alert(raw: dict[str, Any]) -> bool:
    groups = raw.get("rule", {}).get("groups", [])
    location = str(raw.get("location", "")).lower()
    agent_name = str(raw.get("agent", {}).get("name", "")).lower()
    has_windows_payload = bool(raw.get("data", {}).get("win"))

    return (
        has_windows_payload
        or "windows" in groups
        or location == "eventchannel"
        or "windows" in agent_name
    )


def ingest_alerts_file(
    alerts_path: Path,
    only_windows: bool = True,
    driver: Driver | None = None,
) -> None:
    if not alerts_path.exists():
        print(f"[ALERTS] file not found: {alerts_path}")
        return

    ingested = 0
    skipped = 0
    errors = 0
    session_driver = driver or get_driver()

    with open(alerts_path, "r", encoding="utf-8") as file_obj:
        for line_no, line in enumerate(file_obj, start=1):
            line = line.strip()
            if not line:
                continue

            try:
                raw = json.loads(line)
            except json.JSONDecodeError:
                errors += 1
                continue

            if only_windows and not _is_windows_alert(raw):
                skipped += 1
                continue

            level = int(raw.get("rule", {}).get("level", 0) or 0)
            mitre_ids = raw.get("rule", {}).get("mitre", {}).get("id", [])
            mitre_tid = mitre_ids[0] if mitre_ids else ""

            payload = {
                "src_ip": raw.get("agent", {}).get("ip", "unknown"),
                "agent_name": raw.get("agent", {}).get("name", "unknown"),
                "user": raw.get("data", {}).get("srcuser")
                or raw.get("data", {}).get("dstuser")
                or raw.get("data", {}).get("win", {}).get("eventdata", {}).get("user"),
                "alert_id": raw.get("id", f"line-{line_no}"),
                "timestamp": raw.get("timestamp", ""),
                "rule_description": raw.get("rule", {}).get("description", ""),
                "ml_anomaly_score": min(1.0, max(0.1, level / 15.0)),
            }
            report = {
                "severity": _severity_from_level(level),
                "mitre_technique_id": mitre_tid,
                "explanation": raw.get("full_log")
                or raw.get("rule", {}).get("description", ""),
            }

            try:
                ingest_alert(payload, report, driver=session_driver)
                ingested += 1
            except Exception:
                errors += 1

    mode = "windows only" if only_windows else "all alerts"
    print(
        f"[OK] Runtime alerts ingestion ({mode}): "
        f"{ingested} imported | {skipped} skipped | {errors} errors"
    )
