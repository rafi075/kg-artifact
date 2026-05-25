from __future__ import annotations

import argparse
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


def str_to_bool(value: str) -> bool:
    if isinstance(value, bool):
        return value
    value = value.strip().lower()
    if value in {"true", "1", "yes", "y"}:
        return True
    if value in {"false", "0", "no", "n"}:
        return False
    raise argparse.ArgumentTypeError("Expected True/False")


def parse_args():
    parser = argparse.ArgumentParser(description="Build top-k SIMILAR_TO edges for a semantic label.")
    parser.add_argument("--field", required=True, choices=list(FIELD_TO_LABEL.keys()))
    parser.add_argument("--top_k", type=int, default=10)
    parser.add_argument("--concurrency", type=int, default=1)
    parser.add_argument(
        "--reciprocal",
        type=str_to_bool,
        default=False,
        help="If True, enforce reciprocal SIMILAR_TO edges with symmetric average score."
    )
    return parser.parse_args()


def main():
    args = parse_args()
    label = FIELD_TO_LABEL[args.field]
    graph_name = f"{args.field}Graph"

    driver = GraphDatabase.driver(
        settings.uri,
        auth=(settings.user, settings.password)
    )

    drop_graph = f"""
    CALL gds.graph.drop('{graph_name}', false)
    YIELD graphName
    """

    # Remove old SIMILAR_TO edges for this label only
    delete_old_edges = f"""
    MATCH (a:{label})-[r:SIMILAR_TO]->(b:{label})
    DELETE r
    """

    project_graph = f"""
    CALL gds.graph.project.cypher(
      '{graph_name}',
      '
      MATCH (n:{label})
      WHERE n.embedding IS NOT NULL
      RETURN id(n) AS id, n.embedding AS embedding
      ',
      '
      MATCH (n1:{label}), (n2:{label})
      WHERE id(n1) < id(n2)
        AND n1.embedding IS NOT NULL
        AND n2.embedding IS NOT NULL
      RETURN id(n1) AS source, id(n2) AS target
      '
    )
    YIELD graphName, nodeCount, relationshipCount, projectMillis
    """

    knn_write = f"""
    CALL gds.knn.write(
      '{graph_name}',
      {{
        nodeProperties: ['embedding'],
        topK: {args.top_k},
        randomSeed: 42,
        concurrency: {args.concurrency},
        sampleRate: 1.0,
        deltaThreshold: 0.0,
        writeRelationshipType: 'SIMILAR_TO',
        writeProperty: 'score'
      }}
    )
    YIELD
      nodesCompared,
      nodePairsConsidered,
      relationshipsWritten,
      similarityDistribution,
      writeMillis
    """

    # If requested, make every unordered semantic pair reciprocal.
    # If both directions already exist with different scores, use their average as symmetric score.
    enforce_reciprocal = f"""
    MATCH (a:{label})-[r:SIMILAR_TO]->(b:{label})
    WHERE a <> b AND r.score IS NOT NULL
    WITH
      CASE WHEN elementId(a) < elementId(b) THEN a ELSE b END AS n1,
      CASE WHEN elementId(a) < elementId(b) THEN b ELSE a END AS n2,
      avg(toFloat(r.score)) AS symmetric_score
    MERGE (n1)-[r12:SIMILAR_TO]->(n2)
    SET r12.score = symmetric_score
    MERGE (n2)-[r21:SIMILAR_TO]->(n1)
    SET r21.score = symmetric_score
    RETURN count(*) AS reciprocal_pairs
    """

    verify = f"""
    MATCH (a:{label})-[r:SIMILAR_TO]->(b:{label})
    WHERE a <> b
    WITH
      CASE WHEN elementId(a) < elementId(b) THEN elementId(a) ELSE elementId(b) END AS node1,
      CASE WHEN elementId(a) < elementId(b) THEN elementId(b) ELSE elementId(a) END AS node2,
      count(*) AS direction_count
    RETURN
      count(*) AS unique_pairs,
      sum(direction_count) AS directed_edges,
      sum(CASE WHEN direction_count = 2 THEN 1 ELSE 0 END) AS reciprocal_pairs,
      sum(CASE WHEN direction_count = 1 THEN 1 ELSE 0 END) AS one_way_pairs
    """

    final_drop = f"""
    CALL gds.graph.drop('{graph_name}', false)
    YIELD graphName
    """

    try:
        with driver.session(database=settings.database) as session:
            try:
                session.run(drop_graph)
            except Exception:
                pass

            session.run(delete_old_edges)
            proj = session.run(project_graph).single()
            print(f"Projected {proj['nodeCount']} {label} nodes")

            knn = session.run(knn_write).single()
            print(f"Wrote {knn['relationshipsWritten']} raw SIMILAR_TO edges for {label}")

            if args.reciprocal:
                rec = session.run(enforce_reciprocal).single()
                print(f"Reciprocal enforcement completed for {rec['reciprocal_pairs']} unique pairs")

            v = session.run(verify).single()
            print(
                f"Verified {label}: unique_pairs={v['unique_pairs']}, "
                f"directed_edges={v['directed_edges']}, "
                f"reciprocal_pairs={v['reciprocal_pairs']}, "
                f"one_way_pairs={v['one_way_pairs']}"
            )

            session.run(final_drop)
            print(f"Dropped in-memory graph: {graph_name}")

    finally:
        driver.close()


if __name__ == "__main__":
    main()
