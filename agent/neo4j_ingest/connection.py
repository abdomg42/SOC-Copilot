import os
from typing import Optional

from dotenv import load_dotenv
from neo4j import Driver, GraphDatabase

load_dotenv()

_driver: Optional[Driver] = None


def get_driver() -> Driver:
    global _driver
    if _driver is None:
        _driver = GraphDatabase.driver(
            os.getenv("NEO4J_URI", "bolt://localhost:7687"),
            auth=(
                os.getenv("NEO4J_USER", "neo4j"),
                os.getenv("NEO4J_PASSWORD", "soc2025"),
            ),
        )
    return _driver


def close_driver() -> None:
    global _driver
    if _driver is not None:
        _driver.close()
        _driver = None
