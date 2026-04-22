import json
from pathlib import Path

from neo4j import Driver

from .connection import get_driver


def ingest_mitre_json(json_path: Path, driver: Driver | None = None) -> None:
    data = json.loads(json_path.read_text(encoding="utf-8"))
    techniques = [
        obj
        for obj in data.get("objects", [])
        if obj.get("type") == "attack-pattern" and not obj.get("revoked")
    ]

    print(f"[MITRE] importing {len(techniques)} techniques...")

    session_driver = driver or get_driver()
    with session_driver.session() as session:
        for obj in techniques:
            refs = obj.get("external_references", [])
            tid = next(
                (
                    ref.get("external_id")
                    for ref in refs
                    if ref.get("source_name") == "mitre-attack"
                ),
                "",
            )
            if not tid:
                continue

            name = obj.get("name", "")
            description = (obj.get("description") or "")[:500]
            platforms = obj.get("x_mitre_platforms", [])
            phases = obj.get("kill_chain_phases", [])
            tactics = [phase.get("phase_name") for phase in phases if phase.get("phase_name")]

            session.run(
                """
                MERGE (t:MitreTechnique {tid: $tid})
                SET t.name = $name,
                    t.desc = $desc,
                    t.platforms = $platforms,
                    t.tactics = $tactics
                """,
                tid=tid,
                name=name,
                desc=description,
                platforms=platforms,
                tactics=tactics,
            )

            for tactic in tactics:
                session.run(
                    """
                    MERGE (tac:MitreTactic {name: $tactic})
                    WITH tac
                    MATCH (t:MitreTechnique {tid: $tid})
                    MERGE (t)-[:BELONGS_TO]->(tac)
                    """,
                    tactic=tactic,
                    tid=tid,
                )

            if "." in tid:
                parent_id = tid.split(".")[0]
                session.run(
                    """
                    MERGE (parent:MitreTechnique {tid: $pid})
                    WITH parent
                    MATCH (child:MitreTechnique {tid: $cid})
                    MERGE (child)-[:SUB_TECHNIQUE_OF]->(parent)
                    """,
                    pid=parent_id,
                    cid=tid,
                )

    with session_driver.session() as session:
        technique_count = session.run(
            "MATCH (t:MitreTechnique) RETURN count(t) AS c"
        ).single()["c"]
        rel_count = session.run(
            "MATCH ()-[:SUB_TECHNIQUE_OF]->() RETURN count(*) AS c"
        ).single()["c"]

    print(
        f"[OK] MITRE imported: {technique_count} techniques, "
        f"{rel_count} SUB_TECHNIQUE_OF relations"
    )
