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

