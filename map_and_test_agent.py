import argparse
import ast
import csv
import json
import sys
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional


def clean(value: Optional[str], default: str = "") -> str:
    if value is None:
        return default
    v = str(value).strip()
    if v == "" or v.lower() in {"none", "null"}:
        return default
    return v


def to_int(value: Optional[str], default: int = 0) -> int:
    v = clean(value)
    if not v:
        return default
    try:
        return int(float(v))
    except ValueError:
        return default


def to_float(value: Optional[str], default: float = 0.5) -> float:
    v = clean(value)
    if not v:
        return default
    try:
        return float(v)
    except ValueError:
        return default


def parse_list_field(value: Optional[str]) -> List[str]:
    v = clean(value)
    if not v:
        return []
    try:
        parsed = ast.literal_eval(v)
        if isinstance(parsed, list):
            return [str(x) for x in parsed if str(x).strip()]
    except Exception:
        pass

    # fallback if value is not a valid Python list string
    return [p.strip() for p in v.split(",") if p.strip()]


def map_row_to_alert(row: Dict[str, str]) -> Dict[str, Any]:
    rule_level = to_int(row.get("_source.rule.level"), 3)
    mitre_ids = parse_list_field(row.get("_source.rule.mitre.id"))
    mitre_tactic = parse_list_field(row.get("_source.rule.mitre.tactic"))
    mitre_technique = parse_list_field(row.get("_source.rule.mitre.technique"))

    timestamp = clean(row.get("_source.timestamp")) or clean(row.get("_source.@timestamp"))
    src_ip = clean(row.get("_source.agent.ip"), "unknown")
    agent_name = clean(row.get("_source.agent.name"), "unknown")
    rule_description = clean(row.get("_source.rule.description"), "No description")

    # Optional enrichments
    user = (
        clean(row.get("_source.data.win.eventdata.user"))
        or clean(row.get("_source.data.win.eventdata.targetUserName"))
        or clean(row.get("_source.data.win.eventdata.subjectUserName"))
    )

    groups = parse_list_field(row.get("_source.rule.groups"))
    ml_anomaly_score = max(0.1, min(1.0, rule_level / 15.0))

    return {
        "rule_description": rule_description,
        "src_ip": src_ip,
        "timestamp": timestamp,
        "rule_level": rule_level,
        "ml_severity": "",
        "ml_attack_category": "",
        "ml_anomaly_score": ml_anomaly_score,
        "agent_name": agent_name,
        "extra": {
            "alert_id": clean(row.get("_source.id")) or clean(row.get("_id")) or "csv-row",
            "rule_id": clean(row.get("_source.rule.id")),
            "agent_id": clean(row.get("_source.agent.id")),
            "user": user,
            "mitre_ids": mitre_ids,
            "mitre_tactic": mitre_tactic[0] if mitre_tactic else "",
            "mitre_technique": mitre_technique[0] if mitre_technique else "",
            "groups": groups,
            "full_log": clean(row.get("_source.full_log")),
            "event_id": clean(row.get("_source.data.win.system.eventID")),
            "host": clean(row.get("_source.data.win.system.computer")),
        },
    }


def is_windows_like(row: Dict[str, str]) -> bool:
    groups = [g.lower() for g in parse_list_field(row.get("_source.rule.groups"))]
    location = clean(row.get("_source.location")).lower()
    has_win_payload = any(
        clean(row.get(k))
        for k in [
            "_source.data.win.system.channel",
            "_source.data.win.system.eventID",
            "_source.data.win.eventdata.image",
        ]
    )
    return (
        "windows" in groups
        or "windows_security" in groups
        or location == "eventchannel"
        or has_win_payload
    )


def call_analyze_api(base_url: str, alert_payload: Dict[str, Any]) -> Dict[str, Any]:
    url = base_url.rstrip("/") + "/analyze"
    body = json.dumps(alert_payload).encode("utf-8")
    req = urllib.request.Request(
        url=url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=120) as resp:
        data = resp.read().decode("utf-8")
        return json.loads(data)


def main() -> int:
    parser = argparse.ArgumentParser(description="Map CSV alerts and test SOC agent API")
    parser.add_argument("--csv", default="combined_3000.csv", help="Path to flattened CSV")
    parser.add_argument("--api", default="http://127.0.0.1:8000", help="Agent API base URL")
    parser.add_argument("--limit", type=int, default=5, help="How many alerts to test")
    parser.add_argument("--windows-only", action="store_true", help="Only send windows-like rows")
    parser.add_argument("--dry-run", action="store_true", help="Only print mapped payloads")
    args = parser.parse_args()

    tested = 0
    sent = 0
    failed = 0

    try:
        with open(args.csv, "r", encoding="utf-8", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                if args.windows_only and not is_windows_like(row):
                    continue

                alert = map_row_to_alert(row)
                tested += 1

                if args.dry_run:
                    print(json.dumps(alert, ensure_ascii=False, indent=2))
                else:
                    try:
                        result = call_analyze_api(args.api, alert)
                        sent += 1
                        report = result.get("report", {})
                        print(
                            f"[OK] {tested} alert_id={alert['extra'].get('alert_id')} "
                            f"severity={report.get('severity', 'n/a')} "
                            f"title={report.get('title', 'n/a')}"
                        )
                    except urllib.error.HTTPError as e:
                        failed += 1
                        err_body = e.read().decode("utf-8", errors="ignore")
                        print(f"[HTTP {e.code}] row={tested} error={err_body}")
                    except Exception as e:
                        failed += 1
                        print(f"[ERROR] row={tested} error={e}")

                if tested >= args.limit:
                    break

    except FileNotFoundError:
        print(f"CSV not found: {args.csv}")
        return 1

    print("\n=== Summary ===")
    print(f"Mapped rows: {tested}")
    print(f"Sent OK:     {sent}")
    print(f"Failed:      {failed}")
    return 0


if __name__ == "__main__":
    sys.exit(main())