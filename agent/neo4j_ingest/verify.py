from neo4j import Driver

from .connection import get_driver


def verify(driver: Driver | None = None) -> None:
    queries = {
        "MitreTechnique": "MATCH (n:MitreTechnique) RETURN count(n) AS c",
        "MitreTactic": "MATCH (n:MitreTactic) RETURN count(n) AS c",
        "D3FEND": "MATCH (n:D3FEND) RETURN count(n) AS c",
        "D3fendTactic": "MATCH (n:D3fendTactic) RETURN count(n) AS c",
        "EngageActivity": "MATCH (n:EngageActivity) RETURN count(n) AS c",
        "BELONGS_TO": "MATCH ()-[:BELONGS_TO]->() RETURN count(*) AS c",
        "SUB_TECHNIQUE_OF": "MATCH ()-[:SUB_TECHNIQUE_OF]->() RETURN count(*) AS c",
        "DEFENDS_AGAINST": "MATCH ()-[:DEFENDS_AGAINST]->() RETURN count(*) AS c",
        "BELONGS_TO_TACTIC": "MATCH ()-[:BELONGS_TO_TACTIC]->() RETURN count(*) AS c",
        "HAS_SUBTECHNIQUE": "MATCH ()-[:HAS_SUBTECHNIQUE]->() RETURN count(*) AS c",
        "COUNTERS": "MATCH ()-[:COUNTERS]->() RETURN count(*) AS c",
        "SUPPORTS_DEFENSE": "MATCH ()-[:SUPPORTS_DEFENSE]->() RETURN count(*) AS c",
        "Alert": "MATCH (n:Alert) RETURN count(n) AS c",
    }

    session_driver = driver or get_driver()
    print("\n[NEO4J VERIFICATION]")
    print("-" * 45)
    with session_driver.session() as session:
        for label, query in queries.items():
            count = session.run(query).single()["c"]
            print(f"  {label:<20} {count:>8}")
    print("-" * 45)
