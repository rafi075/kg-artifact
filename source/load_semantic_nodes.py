from __future__ import annotations

import json
import pandas as pd
from neo4j import GraphDatabase
from config import settings

CSV_PATH = "cve_data2.csv"
EMBEDDING_JSONL = "semantic_embeddings_exact_merge.jsonl"

# source and system_state are now semantic fields.
SEMANTIC_CONFIG = {
    "source": ("Source", "HAS_SOURCE"),
    "system_state": ("SystemState", "REQUIRES_SYSTEM_STATE"),
    "reason": ("Reason", "HAS_REASON"),
    "attacker_action": ("AttackerAction", "EXPLOITED_BY_ACTION"),
    "consequences": ("Consequence", "CAUSES_CONSEQUENCE"),
    "trigger": ("Trigger", "HAS_TRIGGER"),
    "vulnerability_type": ("VulnerabilityType", "HAS_VULNERABILITY_TYPE"),
}


def clean_text(value):
    if pd.isna(value):
        return None
    text = str(value).strip()
    if not text or text.lower() in {"nan", "none", "null","n/a","na","unknown","unspecified","not applicable","not available","not provided","not reported","not disclosed","not determined","not defined","not identified","not classified","not categorized","not assigned","not specified","not mentioned","not documented","not recorded","not observed","not detected","not found"}:
        return None
    return " ".join(text.split())


def normalize_value_key(value):
    text = clean_text(value)
    return text.lower() if text else None


def load_embedding_map(path: str) -> dict:
    out = {}
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            record = json.loads(line)
            out[(record["field_name"], record["value_key"])] = record
    return out


def merge_semantic_node(tx, label: str, props: dict):
    query = f"""
    MERGE (n:{label} {{value_key: $value_key}})
    SET n.value = $value,
        n.embedding = $embedding,
        n.model_name = $model_name,
        n.task_prefix = $task_prefix
    """
    tx.run(query, **props)


def merge_vuln_to_semantic(tx, cve_id: str, label: str, rel_type: str, value_key: str):
    query = f"""
    MATCH (v:Vulnerability {{cve_id: $cve_id}})
    MATCH (n:{label} {{value_key: $value_key}})
    MERGE (v)-[:{rel_type}]->(n)
    """
    tx.run(query, cve_id=cve_id, value_key=value_key)


def main():
    df = pd.read_csv(CSV_PATH)
    embedding_map = load_embedding_map(EMBEDDING_JSONL)

    driver = GraphDatabase.driver(
        settings.uri,
        auth=(settings.user, settings.password)
    )

    try:
        with driver.session(database=settings.database) as session:
            # First create merged semantic nodes
            created = set()
            for (field_name, value_key), rec in embedding_map.items():
                label, _ = SEMANTIC_CONFIG[field_name]
                if (label, value_key) in created:
                    continue

                session.execute_write(
                    merge_semantic_node,
                    label,
                    {
                        "value_key": rec["value_key"],
                        "value": rec["value"],
                        "embedding": rec["embedding"],
                        "model_name": rec["model_name"],
                        "task_prefix": rec["task_prefix"],
                    }
                )
                created.add((label, value_key))

            # Then connect vulnerabilities to merged semantic nodes
            for _, raw in df.iterrows():
                row = raw.to_dict()
                cve_id = clean_text(row.get("cve_id"))
                if not cve_id:
                    continue

                for field_name, (label, rel_type) in SEMANTIC_CONFIG.items():
                    value_key = normalize_value_key(row.get(field_name))
                    if not value_key:
                        continue

                    if (field_name, value_key) not in embedding_map:
                        continue

                    session.execute_write(
                        merge_vuln_to_semantic,
                        cve_id,
                        label,
                        rel_type,
                        value_key
                    )

        print("Semantic nodes and relationships loaded successfully.")
    finally:
        driver.close()


if __name__ == "__main__":
    main()
