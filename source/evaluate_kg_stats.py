from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd
from neo4j import GraphDatabase
from config import settings


SEMANTIC_FIELDS = {
    "Reason": "HAS_REASON",
    "AttackerAction": "EXPLOITED_BY_ACTION",
    "Consequence": "CAUSES_CONSEQUENCE",
    "Trigger": "HAS_TRIGGER",
    "SystemState": "REQUIRES_SYSTEM_STATE",
    "Source": "HAS_SOURCE",
    "VulnerabilityType": "HAS_VULNERABILITY_TYPE",
}

STRUCTURAL_FIELDS = {
    "Vendor": "HAS_VENDOR",
    "Software": "AFFECTS_SOFTWARE",
    "SoftwareVersion": "HAS_VERSION",
    "NetworkAccess": "REQUIRES_NETWORK_ACCESS",
    "UserInteraction": "REQUIRES_USER_INTERACTION",
    "Privilege": "REQUIRES_PRIVILEGE",
}


def run_one(session, query: str, **params) -> dict:
    record = session.run(query, **params).single()
    return dict(record) if record else {}


def run_many(session, query: str, **params) -> list[dict]:
    return [dict(r) for r in session.run(query, **params)]


def vulnerability_summary(session) -> dict:
    query = """
    MATCH (v:Vulnerability)
    RETURN
        count(v) AS vulnerability_count,
        min(v.cvss_score) AS min_cvss,
        max(v.cvss_score) AS max_cvss,
        avg(v.cvss_score) AS avg_cvss,
        min(v.published_date) AS earliest_date,
        max(v.published_date) AS latest_date
    """
    return run_one(session, query)


def semantic_node_reuse_distribution(session, label: str, rel: str) -> list[dict]:
    """One row per semantic node. Used for reuse boxplots."""
    query = f"""
    MATCH (n:{label})
    OPTIONAL MATCH (v:Vulnerability)-[:{rel}]->(n)
    WITH n, count(DISTINCT v) AS vulnerability_count
    OPTIONAL MATCH (n)-[:SIMILAR_TO]-(m:{label})
    WHERE n <> m
    WITH n, vulnerability_count, count(DISTINCT m) AS unique_neighbor_degree
    RETURN
        elementId(n) AS node_element_id,
        n.value AS value,
        n.value_key AS value_key,
        vulnerability_count,
        unique_neighbor_degree
    ORDER BY vulnerability_count DESC
    """
    return run_many(session, query)


def semantic_field_summary(session, label: str, rel: str) -> dict:
    query = f"""
    MATCH (n:{label})
    OPTIONAL MATCH (v:Vulnerability)-[:{rel}]->(n)
    WITH n, count(DISTINCT v) AS vuln_count
    OPTIONAL MATCH (n)-[:SIMILAR_TO]-(m:{label})
    WHERE n <> m
    WITH n, vuln_count, count(DISTINCT m) AS unique_neighbor_degree
    WITH
        toFloat(vuln_count) AS vuln_count,
        toFloat(unique_neighbor_degree) AS degree
    RETURN
        count(*) AS node_count,
        avg(vuln_count) AS avg_vulnerabilities_per_node,
        min(vuln_count) AS min_vulnerabilities_per_node,
        max(vuln_count) AS max_vulnerabilities_per_node,
        percentileCont(vuln_count, 0.25) AS p25_vulnerabilities_per_node,
        percentileCont(vuln_count, 0.50) AS p50_vulnerabilities_per_node,
        percentileCont(vuln_count, 0.75) AS p75_vulnerabilities_per_node,
        percentileCont(vuln_count, 0.90) AS p90_vulnerabilities_per_node,
        avg(degree) AS avg_unique_neighbor_degree,
        min(degree) AS min_unique_neighbor_degree,
        max(degree) AS max_unique_neighbor_degree,
        percentileCont(degree, 0.50) AS p50_unique_neighbor_degree,
        percentileCont(degree, 0.90) AS p90_unique_neighbor_degree
    """
    return run_one(session, query)


def structural_field_summary(session, label: str, rel: str) -> dict:
    query = f"""
    MATCH (n:{label})
    OPTIONAL MATCH (v:Vulnerability)-[:{rel}]->(n)
    WITH n, count(DISTINCT v) AS vuln_count
    WITH toFloat(vuln_count) AS vuln_count
    RETURN
        count(*) AS node_count,
        avg(vuln_count) AS avg_vulnerabilities_per_node,
        min(vuln_count) AS min_vulnerabilities_per_node,
        max(vuln_count) AS max_vulnerabilities_per_node,
        percentileCont(vuln_count, 0.50) AS p50_vulnerabilities_per_node,
        percentileCont(vuln_count, 0.90) AS p90_vulnerabilities_per_node
    """
    return run_one(session, query)


def relationship_summary(session) -> list[dict]:
    query = """
    MATCH ()-[r]->()
    RETURN type(r) AS relationship_type, count(r) AS relationship_count
    ORDER BY relationship_count DESC
    """
    return run_many(session, query)


def similarity_pair_scores(session, label: str) -> list[dict]:
    """One row per undirected semantic neighbor pair. Used for score distributions."""
    query = f"""
    MATCH (a:{label})-[r:SIMILAR_TO]->(b:{label})
    WHERE a <> b AND r.score IS NOT NULL
    WITH
      CASE WHEN elementId(a) < elementId(b) THEN elementId(a) ELSE elementId(b) END AS node1,
      CASE WHEN elementId(a) < elementId(b) THEN elementId(b) ELSE elementId(a) END AS node2,
      toFloat(r.score) AS score
    WITH node1, node2, avg(score) AS pair_score, count(*) AS direction_count
    RETURN
      node1,
      node2,
      pair_score,
      direction_count
    ORDER BY pair_score DESC
    """
    return run_many(session, query)


def similarity_edge_summary(session, label: str) -> dict:
    query = f"""
    MATCH (a:{label})-[r:SIMILAR_TO]->(b:{label})
    WHERE a <> b AND r.score IS NOT NULL
    WITH
      CASE WHEN elementId(a) < elementId(b) THEN elementId(a) ELSE elementId(b) END AS node1,
      CASE WHEN elementId(a) < elementId(b) THEN elementId(b) ELSE elementId(a) END AS node2,
      toFloat(r.score) AS score
    WITH node1, node2, avg(score) AS pair_score, count(*) AS direction_count
    WITH pair_score, direction_count
    RETURN
      count(pair_score) AS undirected_pair_count,
      sum(direction_count) AS directed_relationship_count,
      sum(CASE WHEN direction_count = 2 THEN 1 ELSE 0 END) AS reciprocal_pair_count,
      sum(CASE WHEN direction_count = 1 THEN 1 ELSE 0 END) AS one_way_pair_count,
      avg(pair_score) AS avg_score,
      stdev(pair_score) AS std_score,
      min(pair_score) AS min_score,
      max(pair_score) AS max_score,
      percentileCont(pair_score, 0.50) AS p50_score,
      percentileCont(pair_score, 0.75) AS p75_score,
      percentileCont(pair_score, 0.90) AS p90_score,
      percentileCont(pair_score, 0.95) AS p95_score,
      sum(CASE WHEN pair_score >= 0.80 THEN 1 ELSE 0 END) AS pairs_ge_080,
      sum(CASE WHEN pair_score >= 0.85 THEN 1 ELSE 0 END) AS pairs_ge_085,
      sum(CASE WHEN pair_score >= 0.90 THEN 1 ELSE 0 END) AS pairs_ge_090,
      sum(CASE WHEN pair_score >= 0.95 THEN 1 ELSE 0 END) AS pairs_ge_095
    """
    return run_one(session, query)


def similarity_score_histogram(session, label: str) -> list[dict]:
    query = f"""
    MATCH (a:{label})-[r:SIMILAR_TO]->(b:{label})
    WHERE a <> b AND r.score IS NOT NULL
    WITH
      CASE WHEN elementId(a) < elementId(b) THEN elementId(a) ELSE elementId(b) END AS node1,
      CASE WHEN elementId(a) < elementId(b) THEN elementId(b) ELSE elementId(a) END AS node2,
      toFloat(r.score) AS score
    WITH node1, node2, avg(score) AS pair_score
    WITH floor(pair_score * 20) / 20.0 AS score_bin
    RETURN score_bin, count(*) AS undirected_pair_count
    ORDER BY score_bin
    """
    return run_many(session, query)


def component_summary_gds_thresholded(session, label: str, threshold: float) -> dict:
    """Compute WCC statistics on a thresholded same-type SIMILAR_TO subgraph.

    Running WCC on the full KNN graph often produces one giant component.
    Thresholding SIMILAR_TO edges before projection exposes semantic
    fragmentation at different confidence levels.
    """
    th_key = f"{threshold:.3f}".replace(".", "_")
    graph_name = f"eval_{label}_sim_ge_{th_key}"

    drop_query = f"CALL gds.graph.drop('{graph_name}', false) YIELD graphName RETURN graphName"
    try:
        session.run(drop_query).consume()
    except Exception:
        pass

    project_query = f"""
    CALL gds.graph.project.cypher(
      '{graph_name}',
      '
      MATCH (n:{label})
      RETURN id(n) AS id
      ',
      '
      MATCH (a:{label})-[r:SIMILAR_TO]->(b:{label})
      WHERE a <> b
        AND r.score IS NOT NULL
        AND toFloat(r.score) >= $threshold
      RETURN id(a) AS source, id(b) AS target
      ',
      {{
        parameters: {{
          threshold: $threshold
        }}
      }}
    )
    YIELD graphName, nodeCount, relationshipCount, projectMillis
    RETURN graphName, nodeCount, relationshipCount, projectMillis
    """
    project_record = run_one(session, project_query, threshold=threshold)

    wcc_query = f"""
    CALL gds.wcc.stream('{graph_name}')
    YIELD nodeId, componentId
    WITH componentId, count(*) AS component_size
    RETURN
        count(componentId) AS component_count,
        avg(toFloat(component_size)) AS avg_component_size,
        min(component_size) AS min_component_size,
        max(component_size) AS max_component_size,
        percentileCont(toFloat(component_size), 0.50) AS p50_component_size,
        percentileCont(toFloat(component_size), 0.90) AS p90_component_size,
        sum(CASE WHEN component_size = 1 THEN 1 ELSE 0 END) AS singleton_component_count,
        sum(CASE WHEN component_size > 1 THEN 1 ELSE 0 END) AS non_singleton_component_count
    """
    comp_record = run_one(session, wcc_query)

    try:
        session.run(drop_query).consume()
    except Exception:
        pass

    out = {"threshold": threshold}
    out.update(project_record)
    out.update(comp_record)
    return out


def parse_thresholds(value: str) -> list[float]:
    return [float(x.strip()) for x in value.split(',') if x.strip()]


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate statistical summary tables for the vulnerability KG."
    )
    parser.add_argument("--output_dir", default="kg_statistics", help="Output directory for CSV files")
    parser.add_argument("--skip_components", action="store_true", help="Skip GDS WCC component summary")
    parser.add_argument(
        "--component_thresholds",
        default="0.85,0.875,0.90,0.925,0.95",
        help="Comma-separated SIMILAR_TO score thresholds for WCC component summaries",
    )
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    component_thresholds = parse_thresholds(args.component_thresholds)

    driver = GraphDatabase.driver(settings.uri, auth=(settings.user, settings.password))

    semantic_rows = []
    structural_rows = []
    sim_rows = []
    hist_rows = []
    pair_score_rows = []
    reuse_rows = []
    component_rows = []

    try:
        with driver.session(database=settings.database) as session:
            pd.DataFrame([vulnerability_summary(session)]).to_csv(
                output_dir / "vulnerability_summary.csv", index=False
            )

            for label, rel in SEMANTIC_FIELDS.items():
                print(f"[INFO] Evaluating semantic field: {label}")
                row = semantic_field_summary(session, label, rel)
                row["field"] = label
                semantic_rows.append(row)

                sim = similarity_edge_summary(session, label)
                sim["field"] = label
                sim_rows.append(sim)

                for h in similarity_score_histogram(session, label):
                    h["field"] = label
                    hist_rows.append(h)

                for ps in similarity_pair_scores(session, label):
                    ps["field"] = label
                    pair_score_rows.append(ps)

                for rr in semantic_node_reuse_distribution(session, label, rel):
                    rr["field"] = label
                    reuse_rows.append(rr)

                if not args.skip_components:
                    for th in component_thresholds:
                        print(f"[INFO]   WCC components for {label} at threshold >= {th}")
                        comp = component_summary_gds_thresholded(session, label, th)
                        comp["field"] = label
                        component_rows.append(comp)

            for label, rel in STRUCTURAL_FIELDS.items():
                print(f"[INFO] Evaluating structural field: {label}")
                row = structural_field_summary(session, label, rel)
                row["field"] = label
                structural_rows.append(row)

            pd.DataFrame(semantic_rows).to_csv(output_dir / "semantic_field_summary.csv", index=False)
            pd.DataFrame(structural_rows).to_csv(output_dir / "structural_field_summary.csv", index=False)
            pd.DataFrame(sim_rows).to_csv(output_dir / "similarity_edge_summary.csv", index=False)
            pd.DataFrame(hist_rows).to_csv(output_dir / "similarity_score_histogram.csv", index=False)
            pd.DataFrame(pair_score_rows).to_csv(output_dir / "similarity_pair_scores.csv", index=False)
            pd.DataFrame(reuse_rows).to_csv(output_dir / "semantic_node_reuse_distribution.csv", index=False)
            pd.DataFrame(component_rows).to_csv(output_dir / "semantic_component_summary.csv", index=False)
            pd.DataFrame(relationship_summary(session)).to_csv(output_dir / "relationship_summary.csv", index=False)

        print(f"Evaluation summaries written to: {output_dir}")

    finally:
        driver.close()


if __name__ == "__main__":
    main()
