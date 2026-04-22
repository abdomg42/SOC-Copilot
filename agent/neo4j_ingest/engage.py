import json
from pathlib import Path

from neo4j import Driver

from .connection import get_driver


def ingest_engage(data_dir: Path, driver: Driver | None = None) -> None:
    mapping_path = data_dir / "attack_mapping.json"
    eac_path = data_dir / "eac.json"

    if not mapping_path.exists():
        print(f"[ENGAGE] missing file: {mapping_path}")
        return

    raw_mapping = json.loads(mapping_path.read_text(encoding="utf-8"))
    if isinstance(raw_mapping, dict):
        for key in ["data", "activities", "mapping"]:
            if key in raw_mapping:
                raw_mapping = raw_mapping[key]
                break

    print(f"[Engage] {len(raw_mapping)} entries in attack_mapping.json")

    eac_details = {}
    if eac_path.exists():
        raw_eac = json.loads(eac_path.read_text(encoding="utf-8"))
        if isinstance(raw_eac, list):
            for item in raw_eac:
                eid = str(item.get("id") or item.get("eac_id") or "").strip()
                if eid:
                    eac_details[eid] = {
                        "desc": str(item.get("description") or "").strip(),
                        "approach": str(item.get("approach") or "").strip(),
                        "goal": str(item.get("goal") or "").strip(),
                    }
        print(f"[Engage] enriched activities from eac.json: {len(eac_details)}")

    activities = {}
    for entry in raw_mapping:
        eac_id = str(entry.get("eac_id", "")).strip()
        eac_name = str(entry.get("eac", "")).strip()
        att_id = str(entry.get("attack_id", "")).strip()
        eav_text = str(entry.get("eav", "")).strip()

        if not eac_id:
            continue

        if eac_id not in activities:
            detail = eac_details.get(eac_id, {})
            activities[eac_id] = {
                "eid": eac_id,
                "name": eac_name,
                "desc": detail.get("desc", ""),
                "approach": detail.get("approach", ""),
                "goal": detail.get("goal", ""),
                "mappings": [],
            }

        if att_id:
            activities[eac_id]["mappings"].append((att_id, eav_text))

    print(f"[Engage] unique activities: {len(activities)}")

    linked = 0
    skipped = 0
    session_driver = driver or get_driver()

    with session_driver.session() as session:
        for info in activities.values():
            session.run(
                """
                MERGE (e:EngageActivity {eid: $eid})
                SET e.name = $name,
                    e.desc = $desc,
                    e.approach = $approach,
                    e.goal = $goal
                """,
                eid=info["eid"],
                name=info["name"],
                desc=info["desc"],
                approach=info["approach"],
                goal=info["goal"],
            )

        for info in activities.values():
            for att_id, eav_text in info["mappings"]:
                rec = session.run(
                    """
                    MATCH (att:MitreTechnique {tid: $tid})
                    MATCH (e:EngageActivity {eid: $eid})
                    MERGE (e)-[r:COUNTERS]->(att)
                    SET r.why = $why
                    RETURN att.tid AS ok
                    """,
                    tid=att_id,
                    eid=info["eid"],
                    why=eav_text[:300],
                ).single()

                if rec and rec.get("ok"):
                    linked += 1
                    continue

                if "." in att_id:
                    parent = att_id.split(".")[0]
                    rec2 = session.run(
                        """
                        MATCH (att:MitreTechnique {tid: $tid})
                        MATCH (e:EngageActivity {eid: $eid})
                        MERGE (e)-[r:COUNTERS]->(att)
                        SET r.why = $why
                        RETURN att.tid AS ok
                        """,
                        tid=parent,
                        eid=info["eid"],
                        why=eav_text[:300],
                    ).single()
                    if rec2 and rec2.get("ok"):
                        linked += 1
                        continue

                skipped += 1

    print(
        f"[OK] Engage: {len(activities)} nodes | "
        f"{linked} COUNTERS | {skipped} skipped"
    )
