from __future__ import annotations

import json
from pathlib import Path

import pandas as pd
from sentence_transformers import SentenceTransformer

CSV_PATH = "cve_data2.csv"
OUTPUT_JSONL = "semantic_embeddings_exact_merge.jsonl"

MODEL_NAME = "nomic-ai/nomic-embed-text-v1.5"
TASK_PREFIX = "clustering"

# source and system_state are now semantic fields.
SEMANTIC_FIELDS = [
    "source",
    "system_state",
    "reason",
    "attacker_action",
    "consequences",
    "trigger",
    "vulnerability_type",
]


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


def build_model_input(text: str) -> str:
    return f"{TASK_PREFIX}: {text}"


def main():
    df = pd.read_csv(CSV_PATH)
    model = SentenceTransformer(MODEL_NAME)

    unique_records = {}

    for _, raw in df.iterrows():
        row = raw.to_dict()
        for field_name in SEMANTIC_FIELDS:
            value = clean_text(row.get(field_name))
            value_key = normalize_value_key(value)
            if not value_key:
                continue

            key = (field_name, value_key)
            if key not in unique_records:
                unique_records[key] = {
                    "field_name": field_name,
                    "value_key": value_key,
                    "value": value,
                }

    output_rows = []
    for rec in unique_records.values():
        embedding = model.encode(
            build_model_input(rec["value"]),
            normalize_embeddings=True
        ).tolist()

        output_rows.append({
            "field_name": rec["field_name"],
            "value_key": rec["value_key"],
            "value": rec["value"],
            "embedding": embedding,
            "embedding_dim": len(embedding),
            "model_name": MODEL_NAME,
            "task_prefix": TASK_PREFIX,
        })

    Path(OUTPUT_JSONL).parent.mkdir(parents=True, exist_ok=True)

    with open(OUTPUT_JSONL, "w", encoding="utf-8") as f:
        for row in output_rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")

    print(f"Saved {len(output_rows)} unique semantic embeddings to {OUTPUT_JSONL}")


if __name__ == "__main__":
    main()
