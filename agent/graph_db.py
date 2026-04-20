import csv
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
    with get_driver().session() as session:
        session.run("""
        CREATE CONSTRAINT IF NOT EXISTS ON (n:IP) ASSERT n.address IS UNIQUE;
        CREATE CONSTRAINT IF NOT EXISTS ON (n:Host) ASSERT n.name IS UNIQUE;
        CREATE CONSTRAINT IF NOT EXISTS ON (n:Protocol) ASSERT n.name IS UNIQUE;
        CREATE CONSTRAINT IF NOT EXISTS ON (n:Agent) ASSERT n.id IS UNIQUE;
        CREATE CONSTRAINT IF NOT EXISTS ON (n:Rule) ASSERT n.id IS UNIQUE;
        CREATE CONSTRAINT IF NOT EXISTS ON (n:MITRE) ASSERT n.id IS UNIQUE;
        CREATE CONSTRAINT IF NOT EXISTS ON (n:Event) ASSERT n.id IS UNIQUE;
        CREATE CONSTRAINT IF NOT EXISTS ON (n:File) ASSERT n.path IS UNIQUE;
        """)

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

def ingest_mitre_json(json_path):
    """Ingest MITRE ATT&CK techniques from mitre_attack.json into Neo4j."""
    with open(json_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    objects = data.get('objects', [])
    with get_driver().session() as session:
        for obj in objects:
            if obj.get('type') == 'attack-pattern':
                # Find external_id
                ext_id = None
                for ref in obj.get('external_references', []):
                    if ref.get('source_name') == 'mitre-attack':
                        ext_id = ref.get('external_id')
                        break
                if ext_id:
                    session.run(
                        """
                        MERGE (m:MITRE {id: $id})
                        SET m.name = $name, m.description = $description, m.external_id = $external_id
                        """,
                        id=obj['id'],
                        name=obj.get('name', ''),
                        description=obj.get('description', ''),
                        external_id=ext_id
                    )

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
from neo4j import GraphDatabase
import json, os 
from pathlib import Path
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

_driver.verify_connectivity()

def init_schema():
    with get_driver().session() as session:
        session.run("""
        CREATE CONSTRAINT IF NOT EXISTS ON (n:IP) ASSERT n.address IS UNIQUE;
        CREATE CONSTRAINT IF NOT EXISTS ON (n:Host) ASSERT n.name IS UNIQUE;
        CREATE CONSTRAINT IF NOT EXISTS ON (n:Protocol) ASSERT n.name IS UNIQUE;
        CREATE CONSTRAINT IF NOT EXISTS ON (n:Agent) ASSERT n.id IS UNIQUE;
        CREATE CONSTRAINT IF NOT EXISTS ON (n:Rule) ASSERT n.id IS UNIQUE;
        CREATE CONSTRAINT IF NOT EXISTS ON (n:MITRE) ASSERT n.id IS UNIQUE;
        CREATE CONSTRAINT IF NOT EXISTS ON (n:Event) ASSERT n.id IS UNIQUE;
        CREATE CONSTRAINT IF NOT EXISTS ON (n:File) ASSERT n.path IS UNIQUE;
        """)


def ingest_mitre_attack(json_path):

    def ingest_alerts(alerts_path):
        """Ingest alerts from alerts.json into Neo4j."""
        import re
        with open(alerts_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        with get_driver().session() as session:
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                try:
                    alert = json.loads(line)
                except Exception:
                    continue
                alert_id = alert.get('id')
                timestamp = alert.get('timestamp')
                full_log = alert.get('full_log')
                location = alert.get('location')
                # Agent
                agent = alert.get('agent', {})
                agent_id = agent.get('id')
                agent_name = agent.get('name')
                # Rule
                rule = alert.get('rule', {})
                rule_id = rule.get('id')
                rule_desc = rule.get('description')
                rule_level = rule.get('level')
                # Create Event/Alert node
                session.run(
                    """
                    MERGE (e:Event {id: $id})
                    SET e.timestamp = $timestamp, e.full_log = $full_log, e.location = $location, e.raw = $raw
                    """,
                    id=alert_id,
                    timestamp=timestamp,
                    full_log=full_log,
                    location=location,
                    raw=json.dumps(alert)
                )
                # Create Agent node and relationship
                if agent_id:
                    session.run(
                        """
                        MERGE (a:Agent {id: $agent_id})
                        SET a.name = $agent_name
                        WITH a
                        MATCH (e:Event {id: $event_id})
                        MERGE (e)-[:GENERATED_BY]->(a)
                        """,
                        agent_id=agent_id,
                        agent_name=agent_name,
                        event_id=alert_id
                    )
                # Create Rule node and relationship
                if rule_id:
                    session.run(
                        """
                        MERGE (r:Rule {id: $rule_id})
                        SET r.description = $rule_desc, r.level = $rule_level
                        WITH r
                        MATCH (e:Event {id: $event_id})
                        MERGE (e)-[:TRIGGERED_RULE]->(r)
                        """,
                        rule_id=rule_id,
                        rule_desc=rule_desc,
                        rule_level=rule_level,
                        event_id=alert_id
                    )
    def ingest_d3fend(json_path):
        """Ingest MITRE D3FEND JSON-LD data into Neo4j."""
        with open(json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        graph = data.get('@graph', [])
        with get_driver().session() as session:
            for obj in graph:
                node_id = obj.get('@id', None)
                node_type = obj.get('@type', None)
                label = obj.get('rdfs:label', None)
                definition = obj.get('d3f:definition', None)
                # Only ingest nodes with an id and label
                if node_id and label:
                    session.run(
                        """
                        MERGE (n:D3FEND {id: $id})
                        SET n.type = $type, n.label = $label, n.definition = $definition, n.raw = $raw
                        """,
                        id=node_id,
                        type=node_type if isinstance(node_type, str) else str(node_type),
                        label=label,
                        definition=definition,
                        raw=json.dumps(obj)
                    )
    """Ingest MITRE ATT&CK JSON data into Neo4j."""
    with open(json_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    objects = data.get('objects', [])
    with get_driver().session() as session:
        for obj in objects:
            node_type = obj.get('type', 'Unknown')
            node_id = obj.get('id', None)
            name = obj.get('name', None)
            description = obj.get('description', None)
            # Only ingest nodes with an id and name
            if node_id and name:
                session.run(
                    """
                    MERGE (n:MITRE {id: $id})
                    SET n.type = $type, n.name = $name, n.description = $description, n.raw = $raw
                    """,
                    id=node_id,
                    type=node_type,
                    name=name,
                    description=description,
                    raw=json.dumps(obj)
                )

