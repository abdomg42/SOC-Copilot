from pathlib import Path

from neo4j_ingest import (
    close_driver,
    create_additional_relationships,
    get_driver,
    ingest_alerts_file,
    ingest_d3fend_csv,
    ingest_d3fend_mappings,
    ingest_engage,
    ingest_mitre_json,
    init_schema,
    verify,
)


def run() -> None:
    base_dir = Path(__file__).resolve().parent.parent
    data_dir = base_dir / "data"

    paths = {
        "mitre_json": data_dir / "mitre_attack.json",
        "d3fend_csv": data_dir / "d3fend" / "d3fend.csv",
        "mappings_csv": data_dir / "d3fend" / "d3fend-full-mappings.csv",
        "engage_dir": data_dir / "engage",
        "alerts_file": base_dir / "input" / "alerts.json",
    }

    print("=" * 56)
    print("SOC Copilot - Neo4j Ingestion")
    print("=" * 56)

    driver = get_driver()
    try:
        print("\n[1/7] Initializing schema...")
        init_schema(driver=driver)

        print("\n[2/7] Ingesting MITRE ATT&CK...")
        if paths["mitre_json"].exists():
            ingest_mitre_json(paths["mitre_json"], driver=driver)
        else:
            print(f"  Missing: {paths['mitre_json']}")

        print("\n[3/7] Ingesting D3FEND nodes...")
        if paths["d3fend_csv"].exists():
            ingest_d3fend_csv(paths["d3fend_csv"], driver=driver)
        else:
            print(f"  Missing: {paths['d3fend_csv']}")

        print("\n[4/7] Ingesting D3FEND mappings...")
        if paths["mappings_csv"].exists():
            ingest_d3fend_mappings(paths["mappings_csv"], driver=driver)
        else:
            print(f"  Missing: {paths['mappings_csv']}")

        print("\n[5/7] Ingesting Engage...")
        if paths["engage_dir"].exists():
            ingest_engage(paths["engage_dir"], driver=driver)
        else:
            print(f"  Missing: {paths['engage_dir']}")

        print("\n[6/7] Creating additional relationships...")
        create_additional_relationships(driver=driver)

        print("\n[7/7] Ingesting runtime Windows alerts...")
        ingest_alerts_file(paths["alerts_file"], only_windows=True, driver=driver)

        verify(driver=driver)
        print("\n[OK] Full import completed")
    finally:
        close_driver()


if __name__ == "__main__":
    run()
