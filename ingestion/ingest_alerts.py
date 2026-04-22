




def _severity_from_level(level: int) -> str:
    if level >= 10:
        return "critical"
    if level >= 7:
        return "high"
    if level >= 4:
        return "medium"
    return "low"


def _is_windows_alert(raw: dict) -> bool:
    rule_groups = raw.get("rule", {}).get("groups", [])
    location = str(raw.get("location", "")).lower()
    agent_name = str(raw.get("agent", {}).get("name", "")).lower()
    has_windows_payload = bool(raw.get("data", {}).get("win"))

    return (
        has_windows_payload
        or "windows" in rule_groups
        or location == "eventchannel"
        or "windows" in agent_name
    )


def ingest_alerts_file(alerts_path: Path, only_windows: bool = True):
    """
    Lit un fichier NDJSON d'alertes (une alerte JSON par ligne),
    normalise les champs vers le format runtime et appelle ingest_alert.
    """
    if not alerts_path.exists():
        print(f"[ALERTS] Fichier introuvable: {alerts_path}")
        return

    ingested = skipped = errors = 0

    with open(alerts_path, "r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
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

            alert_payload = {
                "src_ip": raw.get("agent", {}).get("ip", "unknown"),
                "agent_name": raw.get("agent", {}).get("name", "unknown"),
                "user": (
                    raw.get("data", {}).get("srcuser")
                    or raw.get("data", {}).get("dstuser")
                    or raw.get("data", {}).get("win", {}).get("eventdata", {}).get("user")
                ),
                "alert_id": raw.get("id", f"line-{line_no}"),
                "timestamp": raw.get("timestamp", ""),
                "rule_description": raw.get("rule", {}).get("description", ""),
                "ml_anomaly_score": min(1.0, max(0.1, level / 15.0)),
            }

            report_payload = {
                "severity": _severity_from_level(level),
                "mitre_technique_id": mitre_tid,
                "explanation": (
                    raw.get("full_log")
                    or raw.get("rule", {}).get("description", "")
                ),
            }

            try:
                ingest_alert(alert_payload, report_payload)
                ingested += 1
            except Exception:
                errors += 1

    mode = "Windows seulement" if only_windows else "Toutes alertes"
    print(
        f"[✓] Ingestion alertes ({mode}) : "
        f"{ingested} importées | {skipped} ignorées | {errors} erreurs"
    )

