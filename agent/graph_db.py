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