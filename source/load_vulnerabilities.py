from __future__ import annotations

import pandas as pd
from neo4j import GraphDatabase
from config import settings

CSV_PATH = "cve_data2.csv"


def clean_text(value):
    if pd.isna(value):
        return None
    text = str(value).strip()
    if not text or text.lower() in {"nan", "none", "null","n/a","na","unknown","unspecified","not applicable","not available","not provided","not reported","not disclosed","not determined","not defined","not identified","not classified","not categorized","not assigned","not specified","not mentioned","not documented","not recorded","not observed","not detected","not found"}:
        return None
    return " ".join(text.split())


def normalize_value(value):
    text = clean_text(value)
    return text.lower() if text else None


def parse_cvss(value):
    if pd.isna(value):
        return None
    try:
        return float(value)
    except Exception:
        return None


def choose_identity_values(raw_value, extracted_value):
    raw_clean = clean_text(raw_value)
    extracted_clean = clean_text(extracted_value)

    if raw_clean:
        preferred = raw_clean
        alternative = extracted_clean if extracted_clean else raw_clean
    else:
        preferred = extracted_clean
        alternative = extracted_clean

    if not preferred:
        return None

    return {
        "key": preferred.lower(),
        "value": preferred,
        "alternative_value": alternative,
        "raw_value": raw_clean,
        "extracted_value": extracted_clean,
    }


def build_software_version_props(software_key: str, version_raw_value):
    version_value = clean_text(version_raw_value)
    if not software_key or not version_value:
        return None

    return {
        "key": f"{software_key}::{version_value.lower()}",
        "value": version_value,
        "software_key": software_key,
    }


def merge_vulnerability(tx, row: dict):
    tx.run(
        """
        MERGE (v:Vulnerability {cve_id: $cve_id})
        SET v.description = $description,
            v.published_date = $published_date,
            v.cvss_score = $cvss_score
        """,
        **row
    )


def merge_vendor(tx, cve_id: str, props: dict):
    tx.run(
        """
        MATCH (v:Vulnerability {cve_id: $cve_id})
        MERGE (n:Vendor {key: $key})
        SET n.value = $value,
            n.alternative_value = $alternative_value,
            n.raw_value = $raw_value,
            n.extracted_value = $extracted_value
        MERGE (v)-[:HAS_VENDOR]->(n)
        """,
        cve_id=cve_id,
        **props
    )


def merge_software(tx, cve_id: str, props: dict):
    tx.run(
        """
        MATCH (v:Vulnerability {cve_id: $cve_id})
        MERGE (n:Software {key: $key})
        SET n.value = $value,
            n.alternative_value = $alternative_value,
            n.raw_value = $raw_value,
            n.extracted_value = $extracted_value
        MERGE (v)-[:AFFECTS_SOFTWARE]->(n)
        """,
        cve_id=cve_id,
        **props
    )


def link_software_to_vendor(tx, software_key: str, vendor_key: str):
    tx.run(
        """
        MATCH (s:Software {key: $software_key})
        MATCH (v:Vendor {key: $vendor_key})
        MERGE (s)-[:BELONGS_TO_VENDOR]->(v)
        """,
        software_key=software_key,
        vendor_key=vendor_key,
    )


def merge_software_version(tx, cve_id: str, props: dict):
    tx.run(
        """
        MATCH (v:Vulnerability {cve_id: $cve_id})
        MATCH (s:Software {key: $software_key})
        MERGE (sv:SoftwareVersion {key: $key})
        SET sv.value = $value,
            sv.software_key = $software_key
        MERGE (v)-[:HAS_VERSION]->(sv)
        MERGE (s)-[:HAS_VERSION]->(sv)
        """,
        cve_id=cve_id,
        **props
    )


def merge_shared_node(tx, cve_id: str, label: str, rel_type: str, value: str):
    query = f"""
    MATCH (v:Vulnerability {{cve_id: $cve_id}})
    MERGE (n:{label} {{value: $value}})
    MERGE (v)-[:{rel_type}]->(n)
    """
    tx.run(query, cve_id=cve_id, value=value)


def main():
    df = pd.read_csv(CSV_PATH)

    # source and system_state are semantic fields now and are loaded in load_semantic_nodes.py.
    # Other structural fields remain as before.
    shared_fields = {
        "operatig_system": ("OperatingSystem", "MENTIONS_OS"),
        "user_interaction": ("UserInteraction", "REQUIRES_USER_INTERACTION"),
        "network_access": ("NetworkAccess", "REQUIRES_NETWORK_ACCESS"),
        "privilege": ("Privilege", "REQUIRES_PRIVILEGE"),
    }

    driver = GraphDatabase.driver(
        settings.uri,
        auth=(settings.user, settings.password)
    )

    try:
        with driver.session(database=settings.database) as session:
            for _, raw in df.iterrows():
                row = raw.to_dict()
                cve_id = clean_text(row.get("cve_id"))
                if not cve_id:
                    continue

                vuln_record = {
                    "cve_id": cve_id,
                    "description": clean_text(row.get("description")),
                    "published_date": clean_text(row.get("published_date")),
                    "cvss_score": parse_cvss(row.get("cvss_score")),
                }
                session.execute_write(merge_vulnerability, vuln_record)

                vendor_props = choose_identity_values(row.get("vendor_raw"), row.get("vendor"))
                if vendor_props:
                    session.execute_write(merge_vendor, cve_id, vendor_props)

                software_props = choose_identity_values(row.get("software_raw"), row.get("software"))
                if software_props:
                    session.execute_write(merge_software, cve_id, software_props)

                if vendor_props and software_props:
                    session.execute_write(
                        link_software_to_vendor,
                        software_props["key"],
                        vendor_props["key"]
                    )

                if software_props:
                    version_props = build_software_version_props(
                        software_props["key"],
                        row.get("software_version")
                    )
                    if version_props:
                        session.execute_write(merge_software_version, cve_id, version_props)

                for field_name, (label, rel_type) in shared_fields.items():
                    value = normalize_value(row.get(field_name))
                    if value:
                        session.execute_write(
                            merge_shared_node,
                            cve_id,
                            label,
                            rel_type,
                            value
                        )

        print("Structural data loaded successfully.")
    finally:
        driver.close()


if __name__ == "__main__":
    main()