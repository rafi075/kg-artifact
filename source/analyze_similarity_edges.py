from __future__ import annotations

import argparse
import csv
from datetime import datetime

from neo4j import GraphDatabase
from config import settings

FIELD_TO_LABEL = {
    "source": "Source",
    "system_state": "SystemState",
    "reason": "Reason",
    "attacker_action": "AttackerAction",
    "consequences": "Consequence",
    "trigger": "Trigger",
    "vulnerability_type": "VulnerabilityType",
}


def parse_args():
    parser = argparse.ArgumentParser(
        description="Analyze SIMILAR_TO edges for a semantic field"
    )
    parser.add_argument("--field", required=True, choices=list(FIELD_TO_LABEL.keys()))
    parser.add_argument("--top_k", type=int, required=True, help="TopK used (for logging)")
    parser.add_argument("--reciprocal", default=None, help="Optional logging value: True/False")
    parser.add_argument("--output_csv", default=None, help="Optional CSV file to append results")
    return parser.parse_args()


def main():
    args = parse_args()
    label = FIELD_TO_LABEL[args.field]

    driver = GraphDatabase.driver(
        settings.uri,
        auth=(settings.user, settings.password)
    )

    # Count unique unordered pairs, not raw directed relationships.
    # This makes evaluation comparable whether --reciprocal True or False was used.
    query = f"""
    MATCH (a:{label})-[r:SIMILAR_TO]->(b:{label})
    WHERE a <> b AND r.score IS NOT NULL
    WITH
      CASE WHEN elementId(a) < elementId(b) THEN elementId(a) ELSE elementId(b) END AS node1,
      CASE WHEN elementId(a) < elementId(b) THEN elementId(b) ELSE elementId(a) END AS node2,
      toFloat(r.score) AS score
    WITH node1, node2, avg(score) AS score, count(*) AS direction_count
    RETURN
        count(score) AS unique_pairs,
        sum(direction_count) AS directed_edges,
        sum(CASE WHEN direction_count = 2 THEN 1 ELSE 0 END) AS reciprocal_pairs,
        sum(CASE WHEN direction_count = 1 THEN 1 ELSE 0 END) AS one_way_pairs,
        avg(score) AS avg_score,
        min(score) AS min_score,
        max(score) AS max_score,
        percentileCont(score, 0.5) AS p50,
        percentileCont(score, 0.75) AS p75,
        percentileCont(score, 0.9) AS p90,
        percentileCont(score, 0.95) AS p95,
        sum(CASE WHEN score >= 0.7 THEN 1 ELSE 0 END) AS unique_pairs_ge_07,
        sum(CASE WHEN score >= 0.8 THEN 1 ELSE 0 END) AS unique_pairs_ge_08,
        sum(CASE WHEN score >= 0.85 THEN 1 ELSE 0 END) AS unique_pairs_ge_085,
        sum(CASE WHEN score >= 0.9 THEN 1 ELSE 0 END) AS unique_pairs_ge_09
    """

    try:
        with driver.session(database=settings.database) as session:
            result = session.run(query).single()

            if result is None:
                print("No SIMILAR_TO edges found.")
                return

            metrics = dict(result)

            print("\n===== SIMILARITY EDGE ANALYSIS =====")
            print(f"Field: {args.field} ({label})")
            print(f"TopK used: {args.top_k}")
            if args.reciprocal is not None:
                print(f"Reciprocal setting: {args.reciprocal}")
            print("-----------------------------------")
            for k, v in metrics.items():
                print(f"{k:24}: {v}")

            if args.output_csv:
                row = {
                    "timestamp": datetime.now().isoformat(),
                    "field": args.field,
                    "top_k": args.top_k,
                    "reciprocal": args.reciprocal,
                    **metrics
                }

                write_header = False
                try:
                    with open(args.output_csv, "r", encoding="utf-8"):
                        pass
                except FileNotFoundError:
                    write_header = True

                with open(args.output_csv, "a", newline="", encoding="utf-8") as f:
                    writer = csv.DictWriter(f, fieldnames=row.keys())
                    if write_header:
                        writer.writeheader()
                    writer.writerow(row)

                print(f"\nSaved results to {args.output_csv}")

    finally:
        driver.close()


if __name__ == "__main__":
    main()
