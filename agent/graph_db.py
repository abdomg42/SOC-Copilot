
import csv
from importlib.resources import path
import json
import os
from neo4j import GraphDatabase
from dotenv import load_dotenv
load_dotenv()

_driver = None
def get_driver():
    global _driver
    if _driver is None:
        _driver = GraphDatabase.driver(
            os.getenv('NEO4J_URI'),
            auth=(os.getenv('NEO4J_USER'), os.getenv('NEO4J_PASSWORD'))
        )
    return _driver

def init_schema():
    pass
    # with get_driver().session() as session:
    #     session.run("""
    #     CREATE CONSTRAINT IF NOT EXISTS ON (n:IP) ASSERT n.address IS UNIQUE;
    #     CREATE CONSTRAINT IF NOT EXISTS ON (n:Host) ASSERT n.name IS UNIQUE;
    #     CREATE CONSTRAINT IF NOT EXISTS ON (n:Protocol) ASSERT n.name IS UNIQUE;
    #     CREATE CONSTRAINT IF NOT EXISTS ON (n:Agent) ASSERT n.id IS UNIQUE;
    #     CREATE CONSTRAINT IF NOT EXISTS ON (n:Rule) ASSERT n.id IS UNIQUE;
    #     CREATE CONSTRAINT IF NOT EXISTS ON (n:MITRE) ASSERT n.id IS UNIQUE;
    #     CREATE CONSTRAINT IF NOT EXISTS ON (n:Event) ASSERT n.id IS UNIQUE;
    #     CREATE CONSTRAINT IF NOT EXISTS ON (n:File) ASSERT n.path IS UNIQUE;
    #     """)




def ingest_d3fend_csv(csv_path):
    """Ingest D3FEND techniques from d3fend.csv into Neo4j."""
    with open(csv_path, newline='', encoding='utf-8') as csvfile:
        reader = csv.DictReader(csvfile)
        with get_driver().session() as session:
            for row in reader:
                session.run(
                    """
                    MERGE (d:D3FEND {id: $id})
                    SET d.tactic = $tactic, d.technique = $technique, d.level0 = $level0, d.level1 = $level1, d.definition = $definition
                    """,
                    id=row['ID'],
                    tactic=row['D3FEND Tactic'],
                    technique=row['D3FEND Technique'],
                    level0=row.get('D3FEND Technique Level 0', ''),
                    level1=row.get('D3FEND Technique Level 1', ''),
                    definition=row.get('Definition', '')
                )

def ingest_mitre_json(path):

    data       = json.loads(path.read_text())
    techniques = [o for o in data["objects"]
                  if o.get("type") == "attack-pattern" and not o.get("revoked")]


    with get_driver().session() as s:
        for obj in techniques:
            refs = obj.get("external_references", [])
            tid  = next((e["external_id"] for e in refs if e.get("source_name") == "mitre-attack"), "")
            if not tid:
                continue
            name     = obj.get("name", "")
            desc     = (obj.get("description") or "")[:500]
            platforms= obj.get("x_mitre_platforms", [])
            phases   = obj.get("kill_chain_phases", [])
            tactics  = [p["phase_name"] for p in phases]
            #Create MitreTechnique node
            s.run("""
                MERGE (t:MitreTechnique {tid: $tid})
                SET t.name      = $name,
                    t.desc      = $desc,
                    t.platforms = $platforms,
                    t.tactics   = $tactics
            """, tid=tid, name=name, desc=desc,
                 platforms=platforms, tactics=tactics)

            #Create MitreTactic nodes + BELONGS_TO edges
            for tactic in tactics:
                s.run("""
                    MERGE (tac:MitreTactic {name: $tactic})
                    WITH tac
                    MATCH (t:MitreTechnique {tid: $tid})
                    MERGE (t)-[:BELONGS_TO]->(tac)
                """, tactic=tactic, tid=tid)

            #SUB_TECHNIQUE_OF edge (T1059.007 → T1059)
            if "." in tid:
                parent_id = tid.split(".")[0]
                s.run("""
                    MERGE (parent:MitreTechnique {tid: $pid})
                    WITH parent
                    MATCH (child:MitreTechnique {tid: $cid})
                    MERGE (child)-[:SUB_TECHNIQUE_OF]->(parent)
                """, pid=parent_id, cid=tid)
                

def ingest_d3fend_mappings(csv_path):
    """Ingest mappings from d3fend-full-mappings.csv and create relationships between D3FEND and MITRE nodes."""
    with open(csv_path, newline='', encoding='utf-8') as csvfile:
        reader = csv.DictReader(csvfile)
        with get_driver().session() as session:
            for row in reader:
                def_tech = row['def_tech_label']
                off_tech_id = row['off_tech_id']
                rel_type = row['def_tactic_rel_label']
                # Create relationship if both are present
                if def_tech and off_tech_id:
                    session.run(
                        """
                        MATCH (d:D3FEND {technique: $def_tech})
                        MATCH (m:MITRE {external_id: $off_tech_id})
                        MERGE (d)-[r:MAPPED_TO {relation: $rel_type}]->(m)
                        """,
                        def_tech=def_tech,
                        off_tech_id=off_tech_id,
                        rel_type=rel_type
                    )

if __name__ == "__main__":
    # Chemins par défaut (adapter si besoin)
    d3fend_csv = os.path.join('..', 'data', 'd3fend', 'd3fend.csv')
    mitre_json = os.path.join('..', 'data', 'mitre_attack.json')
    mappings_csv = os.path.join('..', 'data', 'd3fend', 'd3fend-full-mappings.csv')

    print("[+] Initialisation du schéma Neo4j...")
    init_schema()
    print("[+] Ingestion D3FEND...")
    ingest_d3fend_csv(d3fend_csv)
    print("[+] Ingestion MITRE ATT&CK...")
    ingest_mitre_json(mitre_json)
    print("[+] Ingestion des mappings D3FEND <-> MITRE...")
    ingest_d3fend_mappings(mappings_csv)
    print("[✓] Import terminé.")