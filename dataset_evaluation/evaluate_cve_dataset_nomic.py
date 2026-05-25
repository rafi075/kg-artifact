import re
import math
import json
import argparse
from pathlib import Path
from collections import defaultdict

import numpy as np
import pandas as pd
from sentence_transformers import SentenceTransformer


MODEL_NAME = "nomic-ai/nomic-embed-text-v1.5"
TASK_PREFIX = "clustering"


ALIASES = {
    "cve_id": ["cve_id", "cveid", "cve"],
    "vendor": ["vendor"],
    "software": ["software", "product"],
    "software_version": ["software_version", "version", "software_versions"],
    "source": ["source"],
    "reason": ["reason"],
    "trigger": ["trigger"],
    "attacker_action": ["attacker_action", "attackeraction", "attacker_actions"],
    "consequences": ["consequences", "consequence", "impact", "impacts"],
    "system_state": ["system_state", "systemstate"],
    "user_interaction": ["user_interaction", "userinteraction", "user_action"],
    "operating_system": ["operating_system", "operatig_system", "os"],
    "network_access": ["network_access", "netowrk_access", "network", "network_level"],
    "privilege": ["privilege", "privileges", "authentication_privilege_level"],
    "vulnerability_type": ["vulnerability_type", "vuln_type", "type"],
}


PROPERTIES = [
    "vendor",
    "software",
    "software_version",
    "source",
    "reason",
    "trigger",
    "attacker_action",
    "consequences",
    "system_state",
    "user_interaction",
    "operating_system",
    "network_access",
    "privilege",
    "vulnerability_type",
]


EMPTY_EQUIVALENTS = {
    "",
    "none",
    "null",
    "nan",
    "n/a",
    "na",
    "not applicable",
    "unknown",
    "unspecified",
    "not specified",
    "not provided",
    "not reported",
    "not mentioned",
    "not available",
}


USER_INTERACTION_NO_EQ = {
    "",
    "none",
    "null",
    "nan",
    "n/a",
    "na",
    "no",
    "not required",
    "not needed",
    "no user interaction",
    "no user interaction required",
    "user action not required",
    "user interaction not required",
    "user interaction is not needed for exploitation",
    "user interaction is not required for exploitation",
    "user action is not needed for exploitation",
    "user action is not required for exploitation",
}


def normalize_col(col):
    return re.sub(r"[^a-z0-9]+", "_", str(col).strip().lower()).strip("_")


def find_col(columns, canonical_name):
    col_map = {normalize_col(c): c for c in columns}

    for alias in ALIASES.get(canonical_name, [canonical_name]):
        alias_norm = normalize_col(alias)

        if alias_norm in col_map:
            return col_map[alias_norm]

    return None


def clean_text(value, field=None):

    if pd.isna(value):
        value = ""

    text = str(value).strip()
    normalized = " ".join(text.lower().split())

    if field == "user_interaction":
        if normalized in USER_INTERACTION_NO_EQ:
            return "no"

    if normalized in EMPTY_EQUIVALENTS:
        return ""

    return " ".join(text.split())


def model_input(text):
    return f"{TASK_PREFIX}: {text}"


def cosine_from_normalized_embeddings(a, b):
    return float(np.dot(a, b))


def summarize(records, mode):

    values = []
    case_counts = defaultdict(int)

    tp = 0
    fp = 0
    fn = 0

    for r in records:

        case = r["case"]
        case_counts[case] += 1

        if mode == 1:
            # Only evaluate rows where both annotated and extracted have values.
            # Presence metrics are therefore calculated over both-present rows only.
            if case == "both_present":
                values.append(r["similarity"])
                tp += 1

        elif mode == 2:
            # Both present = TP
            # Both empty = TN-like correct absence, included in similarity average,
            # but not counted as TP/FP/FN for precision/recall.
            if case == "both_present":
                values.append(r["similarity"])
                tp += 1

            elif case == "both_empty":
                values.append(1.0)

            elif case == "only_extracted":
                fp += 1

            elif case == "only_annotated":
                fn += 1

        elif mode == 3:
            # Both present = TP
            # Both empty = correct absence
            # Only extracted = considered correct because annotated is empty
            if case == "both_present":
                values.append(r["similarity"])
                tp += 1

            elif case == "both_empty":
                values.append(1.0)

            elif case == "only_extracted":
                values.append(1.0)
                tp += 1

            elif case == "only_annotated":
                fn += 1

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (
        2 * precision * recall / (precision + recall)
        if (precision + recall) > 0
        else 0.0
    )

    return {
        "count_considered": len(values),
        "avg_sim": round(float(np.mean(values)), 4) if values else "",
        "median_sim": round(float(np.median(values)), 4) if values else "",
        "min_sim": round(float(np.min(values)), 4) if values else "",
        "max_sim": round(float(np.max(values)), 4) if values else "",
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "both_present": case_counts["both_present"],
        "both_empty": case_counts["both_empty"],
        "only_annotated": case_counts["only_annotated"],
        "only_extracted": case_counts["only_extracted"],
        "total_rows": len(records),
    }



def build_canonical_df(df, properties, cve_col):

    out = pd.DataFrame()

    out["cve_id"] = df[cve_col].astype(str).str.strip()

    for prop in properties:

        col = find_col(df.columns, prop)

        if col is not None:
            out[prop] = df[col]
        else:
            out[prop] = ""

    return out


def main():

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--annotated",
        required=True,
        help="Path to annotated CSV"
    )

    parser.add_argument(
        "--extracted",
        required=True,
        help="Path to extracted CSV"
    )

    parser.add_argument(
        "--out_dir",
        default="cve_eval_outputs"
    )

    args = parser.parse_args()

    out_dir = Path(args.out_dir)
    detail_dir = out_dir / "property_details"

    detail_dir.mkdir(parents=True, exist_ok=True)

    ann = pd.read_csv(args.annotated)
    ext = pd.read_csv(args.extracted)

    # remove patch + description
    ann = ann[
        [
            c for c in ann.columns
            if "patch" not in c.lower()
            and normalize_col(c) != "description"
        ]
    ]

    ext = ext[
        [
            c for c in ext.columns
            if "patch" not in c.lower()
            and normalize_col(c) != "description"
        ]
    ]

    ann_cve = find_col(ann.columns, "cve_id")
    ext_cve = find_col(ext.columns, "cve_id")

    if ann_cve is None or ext_cve is None:
        raise ValueError("Could not find CVE ID columns")

    ann_std = build_canonical_df(
        ann,
        PROPERTIES,
        ann_cve
    )

    ext_std = build_canonical_df(
        ext,
        PROPERTIES,
        ext_cve
    )

    # subset extracted to annotated set
    ext_std = ext_std[
        ext_std["cve_id"].isin(set(ann_std["cve_id"]))
    ].copy()

    merged = ann_std.merge(
        ext_std,
        on="cve_id",
        suffixes=("_gt", "_pred"),
        how="inner"
    )

    print(f"Aligned rows: {len(merged)}")

    print("Loading model...")

    model = SentenceTransformer(
        MODEL_NAME,
        trust_remote_code=True
    )

    all_texts = []
    pair_map = {}

    for prop in PROPERTIES:

        for idx, row in merged.iterrows():

            gt = clean_text(
                row[f"{prop}_gt"],
                prop
            )

            pred = clean_text(
                row[f"{prop}_pred"],
                prop
            )

            if gt and pred:

                if gt.lower() != pred.lower():

                    pair_map[(prop, idx)] = len(all_texts)

                    all_texts.append(
                        model_input(gt)
                    )

                    all_texts.append(
                        model_input(pred)
                    )

    print(f"Encoding {len(all_texts)} texts...")

    embeddings = model.encode(
        all_texts,
        normalize_embeddings=True,
        batch_size=32,
        show_progress_bar=True
    ) if all_texts else []

    summaries = {
        1: [],
        2: [],
        3: []
    }

    for prop in PROPERTIES:

        records = []

        for idx, row in merged.iterrows():

            cve_id = row["cve_id"]

            gt = clean_text(
                row[f"{prop}_gt"],
                prop
            )

            pred = clean_text(
                row[f"{prop}_pred"],
                prop
            )

            if gt and pred:

                if gt.lower() == pred.lower():

                    sim = 1.0

                else:

                    emb_idx = pair_map[(prop, idx)]

                    sim = cosine_from_normalized_embeddings(
                        embeddings[emb_idx],
                        embeddings[emb_idx + 1]
                    )

                case = "both_present"

            elif not gt and not pred:

                sim = 1.0
                case = "both_empty"

            elif gt and not pred:

                sim = math.nan
                case = "only_annotated"

            else:

                sim = math.nan
                case = "only_extracted"

            records.append({
                "cve_id": cve_id,
                "property": prop,
                "annotated": gt,
                "predicted": pred,
                "similarity": sim if not math.isnan(sim) else "",
                "case": case,
            })

        detail_df = pd.DataFrame(records)

        detail_df.to_csv(
            detail_dir / f"{prop}_evaluation.csv",
            index=False
        )

        for mode in [1, 2, 3]:

            summaries[mode].append({
                "property": prop,
                **summarize(records, mode)
            })

    pd.DataFrame(summaries[1]).to_csv(
        out_dir / "summary_1_both_present_only.csv",
        index=False
    )

    pd.DataFrame(summaries[2]).to_csv(
        out_dir / "summary_2_both_present_plus_both_empty.csv",
        index=False
    )

    pd.DataFrame(summaries[3]).to_csv(
        out_dir / "summary_3_annotated_empty_as_correct.csv",
        index=False
    )

    metadata = {
        "model": MODEL_NAME,
        "task_prefix": TASK_PREFIX,
        "embedding_normalized": True,
        "similarity": "cosine similarity",
        "aligned_rows": len(merged),
        "properties": PROPERTIES
    }

    with open(
        out_dir / "run_metadata.json",
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            metadata,
            f,
            indent=2
        )

    print(f"\nDone. Outputs saved to: {out_dir}")


if __name__ == "__main__":
    main()