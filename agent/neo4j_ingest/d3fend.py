import csv
from pathlib import Path

from neo4j import Driver

from .connection import get_driver


def ingest_d3fend_csv(csv_path: Path, driver: Driver | None = None) -> None:
    count = 0
    session_driver = driver or get_driver()

    with open(csv_path, newline="", encoding="utf-8") as file_obj:
        reader = csv.DictReader(file_obj)
        print(f"[D3FEND CSV] detected columns: {reader.fieldnames}")

        with session_driver.session() as session:
            for row in reader:
                did = row.get("ID", "").strip()
                tactic = row.get("D3FEND Tactic", "").strip()
                technique = row.get("D3FEND Technique", "").strip()
                level0 = row.get("D3FEND Technique Level 0", "").strip()
                level1 = row.get("D3FEND Technique Level 1", "").strip()
                definition = row.get("Definition", "").strip()[:500]

                name = level1 or level0 or technique
                if not did or not name:
                    continue

                session.run(
                    """
                    MERGE (d:D3FEND {id: $id})
                    SET d.name = $name,
                        d.tactic = $tactic,
                        d.technique = $technique,
                        d.level0 = $level0,
                        d.level1 = $level1,
                        d.definition = $definition
                    """,
                    id=did,
                    name=name,
                    tactic=tactic,
                    technique=technique,
                    level0=level0,
                    level1=level1,
                    definition=definition,
                )
                count += 1

    print(f"[OK] D3FEND nodes created: {count}")


def ingest_d3fend_mappings(csv_path: Path, driver: Driver | None = None) -> None:
    linked = 0
    skipped = 0

    with open(csv_path, newline="", encoding="utf-8") as file_obj:
        reader = csv.DictReader(file_obj)
        print(f"[Mappings CSV] detected columns: {reader.fieldnames}")
        rows = list(reader)

    print(f"[Mappings CSV] {len(rows)} rows to process...")

    session_driver = driver or get_driver()
    with session_driver.session() as session:
        for row in rows:
            def_tech_label = row.get("def_tech_label", "").strip()
            off_tech_id = row.get("off_tech_id", "").strip()
            def_tactic = row.get("def_tactic_label", "").strip()
            off_tactic = row.get("off_tactic_label", "").strip()
            off_tech_label = row.get("off_tech_label", "").strip()

            if not def_tech_label or not off_tech_id:
                skipped += 1
                continue

            result = session.run(
                """
                MATCH (m:MitreTechnique {tid: $off_tech_id})
                OPTIONAL MATCH (d1:D3FEND {technique: $def_tech_label})
                OPTIONAL MATCH (d2:D3FEND {name: $def_tech_label})
                WITH m, coalesce(d1, d2) AS d
                WHERE d IS NOT NULL
                MERGE (d)-[r:DEFENDS_AGAINST]->(m)
                SET r.d3fend_tactic = $def_tactic,
                    r.attack_tactic = $off_tactic,
                    r.attack_tech = $off_tech_label
                RETURN d.id AS did, m.tid AS mtid
                """,
                off_tech_id=off_tech_id,
                def_tech_label=def_tech_label,
                def_tactic=def_tactic,
                off_tactic=off_tactic,
                off_tech_label=off_tech_label,
            ).single()

            if result and result.get("mtid"):
                linked += 1
            else:
                skipped += 1

    print(f"[OK] DEFENDS_AGAINST created: {linked} | skipped: {skipped}")


def create_additional_relationships(driver: Driver | None = None) -> None:
    session_driver = driver or get_driver()

    with session_driver.session() as session:
        session.run(
            """
            MATCH (d:D3FEND)
            WHERE d.tactic IS NOT NULL AND d.tactic <> ''
            MERGE (tac:D3fendTactic {name: d.tactic})
            MERGE (d)-[:BELONGS_TO_TACTIC]->(tac)
            """
        )
        n_tactic = session.run(
            "MATCH ()-[:BELONGS_TO_TACTIC]->() RETURN count(*) AS c"
        ).single()["c"]
        print(f"[OK] BELONGS_TO_TACTIC: {n_tactic}")

        session.run(
            """
            MATCH (child:D3FEND)
            WHERE child.level1 IS NOT NULL AND child.level1 <> ''
              AND child.level0 IS NOT NULL AND child.level0 <> ''
              AND child.level1 <> child.level0
            MATCH (parent:D3FEND {level0: child.level0})
            WHERE (parent.level1 IS NULL OR parent.level1 = '')
              AND parent.id <> child.id
            MERGE (parent)-[:HAS_SUBTECHNIQUE]->(child)
            """
        )
        n_sub = session.run(
            "MATCH ()-[:HAS_SUBTECHNIQUE]->() RETURN count(*) AS c"
        ).single()["c"]
        print(f"[OK] HAS_SUBTECHNIQUE: {n_sub}")

        session.run(
            """
            MATCH (e:EngageActivity)-[:COUNTERS]->(att:MitreTechnique)
            MATCH (d:D3FEND)-[:DEFENDS_AGAINST]->(att)
            MERGE (e)-[:SUPPORTS_DEFENSE]->(d)
            """
        )
        n_supports = session.run(
            "MATCH ()-[:SUPPORTS_DEFENSE]->() RETURN count(*) AS c"
        ).single()["c"]
        print(f"[OK] SUPPORTS_DEFENSE: {n_supports}")
