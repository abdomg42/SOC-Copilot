from neo4j import Driver

from .connection import get_driver


def init_schema(driver: Driver | None = None) -> None:
    session_driver = driver or get_driver()
    commands = [
        "CREATE CONSTRAINT IF NOT EXISTS FOR (n:MitreTechnique) REQUIRE n.tid IS UNIQUE",
        "CREATE CONSTRAINT IF NOT EXISTS FOR (n:MitreTactic) REQUIRE n.name IS UNIQUE",
        "CREATE CONSTRAINT IF NOT EXISTS FOR (n:D3FEND) REQUIRE n.id IS UNIQUE",
        "CREATE CONSTRAINT IF NOT EXISTS FOR (n:EngageActivity) REQUIRE n.eid IS UNIQUE",
        "CREATE CONSTRAINT IF NOT EXISTS FOR (n:IP) REQUIRE n.address IS UNIQUE",
        "CREATE CONSTRAINT IF NOT EXISTS FOR (n:Host) REQUIRE n.name IS UNIQUE",
        "CREATE CONSTRAINT IF NOT EXISTS FOR (n:User) REQUIRE n.name IS UNIQUE",
        "CREATE CONSTRAINT IF NOT EXISTS FOR (n:Alert) REQUIRE n.alert_id IS UNIQUE",
        "CREATE INDEX IF NOT EXISTS FOR (n:IP) ON (n.risk_score)",
        "CREATE INDEX IF NOT EXISTS FOR (n:Alert) ON (n.timestamp)",
        "CREATE INDEX IF NOT EXISTS FOR (n:Alert) ON (n.severity)",
        "CREATE INDEX IF NOT EXISTS FOR (n:MitreTechnique) ON (n.tid)",
        "CREATE INDEX IF NOT EXISTS FOR (n:D3FEND) ON (n.technique)",
    ]

    with session_driver.session() as session:
        for command in commands:
            session.run(command)

    print("Schema initialized: 8 constraints + 5 indexes")
