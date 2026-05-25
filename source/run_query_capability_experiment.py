from __future__ import annotations

import csv
import json
import time
from pathlib import Path
from typing import Any, Dict, List

from neo4j import GraphDatabase
from config import settings


OUTPUT_DIR = Path("query_experiment_results")
OUTPUT_DIR.mkdir(exist_ok=True)

TOP_K = 10


QUERIES: List[Dict[str, Any]] = [
    {
        "id": "Q1",
        "class": "Structural filtering",
        "plain_language": (
            "Find high-severity vulnerabilities affecting software from a specific vendor "
            "within a publication date range."
        ),
        "params": {
            "vendor": "microsoft",
            "start_date": "2020-01-01",
            "end_date": "2024-12-31",
            "min_cvss": 7.0,
            "limit": TOP_K,
        },
        "cypher": """
        MATCH (v:Vulnerability)-[:HAS_VENDOR]->(ven:Vendor)
        WHERE toLower(ven.value) CONTAINS toLower($vendor)
          AND v.published_date >= $start_date
          AND v.published_date <= $end_date
          AND v.cvss_score >= $min_cvss
        OPTIONAL MATCH (v)-[:AFFECTS_SOFTWARE]->(s:Software)
        
        RETURN
          v.cve_id AS cve_id,
          v.cvss_score AS cvss,
          v.published_date AS published_date,
          ven.value AS vendor,
          collect(DISTINCT s.value)[0..3] AS software
        ORDER BY cvss DESC, published_date DESC
        LIMIT $limit
        """,
    },

    {
        "id": "Q2",
        "class": "Multi-hop traversal",
        "plain_language": (
            "For a vendor, retrieve vulnerabilities together with required privilege, "
            "network access, and consequences."
        ),
        "params": {
            "vendor": "microsoft",
            "limit": TOP_K,
        },
        "cypher": """
        MATCH (v:Vulnerability)-[:HAS_VENDOR]->(ven:Vendor)
        WHERE toLower(ven.value) CONTAINS toLower($vendor)
        OPTIONAL MATCH (v)-[:REQUIRES_PRIVILEGE]->(p:Privilege)
        OPTIONAL MATCH (v)-[:REQUIRES_NETWORK_ACCESS]->(na:NetworkAccess)
        OPTIONAL MATCH (v)-[:CAUSES_CONSEQUENCE]->(c:Consequence)
        
        RETURN
          v.cve_id AS cve_id,
          v.cvss_score AS cvss,
          ven.value AS vendor,
          collect(DISTINCT p.value)[0..3] AS privilege,
          collect(DISTINCT na.value)[0..3] AS network_access,
          collect(DISTINCT c.value)[0..3] AS consequences
        ORDER BY cvss DESC
        LIMIT $limit
        """,
    },

    {
        "id": "Q3",
        "class": "Semantic neighborhood search",
        "plain_language": (
            "Given an attacker-action keyword, retrieve distinct CVEs whose attacker actions "
            "are semantically close to the matched seed action, while emphasizing non-exact "
            "semantic matches rather than repeated keyword matches."
        ),
        "params": {
            "keyword": "execute arbitrary code",
            "sim_threshold": 0.90,
            "limit": TOP_K,
        },
        "cypher": """
        CALL db.index.fulltext.queryNodes(
          'semantic_attacker_action_ft',
          $keyword
        ) YIELD node AS seed, score AS ft_score

        MATCH (seed)-[sim:SIMILAR_TO]-(aa:AttackerAction)
        MATCH (v:Vulnerability)-[:EXPLOITED_BY_ACTION]->(aa)

        WHERE sim.score >= $sim_threshold
          AND toLower(aa.value) <> toLower(seed.value)
          AND NOT toLower(aa.value) CONTAINS toLower($keyword)

        WITH
          v,
          seed,
          aa,
          sim.score AS similarity,
          ft_score
        ORDER BY similarity DESC, ft_score DESC, v.cvss_score DESC

        WITH
          v,
          collect({
            seed_action: seed.value,
            matched_action: aa.value,
            similarity: similarity,
            keyword_score: ft_score
          })[0] AS best_match

        RETURN
          v.cve_id AS cve_id,
          v.cvss_score AS cvss,
          best_match.seed_action AS seed_action,
          best_match.matched_action AS semantically_matched_action,
          best_match.similarity AS similarity,
          best_match.keyword_score AS keyword_score

        ORDER BY similarity DESC, cvss DESC
        LIMIT $limit
        """,
    },

    {
        
    "id": "Q4",
    "class": "Similar-vulnerability discovery",
    "plain_language": (
        "Find unique vulnerability pairs whose reason, attacker action, and consequence "
        "are semantically similar, and retain only the strongest semantic explanation "
        "for each CVE pair."
    ),
    "params": {
        "sim_threshold": 0.90,
        "limit": 10,
    },
    "cypher": """
    MATCH (v1:Vulnerability)-[:HAS_REASON]->(r1:Reason)
    MATCH (v2:Vulnerability)-[:HAS_REASON]->(r2:Reason)
    MATCH (r1)-[sr:SIMILAR_TO]-(r2)

    WHERE v1.cve_id < v2.cve_id
      AND sr.score >= $sim_threshold

    MATCH (v1)-[:EXPLOITED_BY_ACTION]->(a1:AttackerAction)
    MATCH (v2)-[:EXPLOITED_BY_ACTION]->(a2:AttackerAction)
    MATCH (a1)-[sa:SIMILAR_TO]-(a2)

    WHERE sa.score >= $sim_threshold

    MATCH (v1)-[:CAUSES_CONSEQUENCE]->(c1:Consequence)
    MATCH (v2)-[:CAUSES_CONSEQUENCE]->(c2:Consequence)
    MATCH (c1)-[sc:SIMILAR_TO]-(c2)

    WHERE sc.score >= $sim_threshold

    WITH
      v1.cve_id AS cve_1,
      v2.cve_id AS cve_2,

      r1.value AS reason_1,
      r2.value AS reason_2,
      sr.score AS reason_sim,

      a1.value AS action_1,
      a2.value AS action_2,
      sa.score AS action_sim,

      c1.value AS consequence_1,
      c2.value AS consequence_2,
      sc.score AS consequence_sim,

      (sr.score + sa.score + sc.score) / 3.0 AS avg_similarity

    ORDER BY avg_similarity DESC

    WITH
      cve_1,
      cve_2,
      collect({
        reason_1: reason_1,
        reason_2: reason_2,
        reason_sim: reason_sim,

        action_1: action_1,
        action_2: action_2,
        action_sim: action_sim,

        consequence_1: consequence_1,
        consequence_2: consequence_2,
        consequence_sim: consequence_sim,

        avg_similarity: avg_similarity
      })[0] AS best_match

    RETURN
      cve_1,
      cve_2,

      best_match.reason_1 AS reason_1,
      best_match.reason_2 AS reason_2,
      best_match.reason_sim AS reason_sim,

      best_match.action_1 AS action_1,
      best_match.action_2 AS action_2,
      best_match.action_sim AS action_sim,

      best_match.consequence_1 AS consequence_1,
      best_match.consequence_2 AS consequence_2,
      best_match.consequence_sim AS consequence_sim,

      best_match.avg_similarity AS avg_similarity

    ORDER BY avg_similarity DESC
    LIMIT $limit
    """,

    },

    {
        "id": "Q5",
        "class": "Context-filtered semantic-cluster correlation",
        "plain_language": (
            "Find frequent semantic Reason--Consequence correlations by first building "
            "query-context-filtered temporary WCC clusters for Reason and Consequence nodes, "
            "then ranking observed cluster pairs by distinct CVE support."
        ),
        "params": {
            "vendor": "microsoft",
            "software": None,
            "from_date": "2020-01-01T00:00:00",
            "to_date": "2024-12-31T23:59:59",
            "threshold": 0.92,
            "min_support": 3,
            "limit": TOP_K,
        },
        "requires_graphs": [
            "reasonFilteredCorrelationGraph092",
            "consequenceFilteredCorrelationGraph092",
        ],
        "cypher": """
        CALL {
          CALL gds.wcc.stream('reasonFilteredCorrelationGraph092')
          YIELD nodeId, componentId
          RETURN collect({node_id: nodeId, cluster_id: componentId}) AS reason_clusters
        }

        CALL {
          CALL gds.wcc.stream('consequenceFilteredCorrelationGraph092')
          YIELD nodeId, componentId
          RETURN collect({node_id: nodeId, cluster_id: componentId}) AS consequence_clusters
        }

        MATCH (v:Vulnerability)-[:HAS_REASON]->(r:Reason)
        MATCH (v)-[:CAUSES_CONSEQUENCE]->(c:Consequence)
        WHERE datetime(v.published_date) >= datetime($from_date)
          AND datetime(v.published_date) <= datetime($to_date)

        OPTIONAL MATCH (v)-[:HAS_VENDOR]->(ven:Vendor)
        OPTIONAL MATCH (v)-[:AFFECTS_SOFTWARE]->(s:Software)

        WITH v, r, c, ven, s, reason_clusters, consequence_clusters
        WHERE ($vendor IS NULL
               OR toLower(ven.value) = toLower($vendor)
               OR toLower(ven.alternative_value) = toLower($vendor))
          AND ($software IS NULL
               OR toLower(s.value) = toLower($software)
               OR toLower(s.alternative_value) = toLower($software))

        WITH
          v,
          r,
          c,
          [x IN reason_clusters WHERE x.node_id = id(r)][0].cluster_id AS reason_cluster,
          [x IN consequence_clusters WHERE x.node_id = id(c)][0].cluster_id AS consequence_cluster

        WITH
          reason_cluster,
          consequence_cluster,
          r,
          c,
          collect(DISTINCT v.cve_id) AS pair_cves,
          avg(v.cvss_score) AS pair_avg_cvss,
          max(v.cvss_score) AS pair_max_cvss

        WITH
          reason_cluster,
          consequence_cluster,
          collect({
            reason: r.value,
            consequence: c.value,
            cves: pair_cves,
            freq: size(pair_cves),
            avg_cvss: round(pair_avg_cvss * 100.0) / 100.0,
            max_cvss: pair_max_cvss
          }) AS member_pairs

        UNWIND member_pairs AS mp
        UNWIND mp.cves AS cve_id

        WITH
          reason_cluster,
          consequence_cluster,
          member_pairs,
          collect(DISTINCT cve_id) AS cluster_pair_cves

        WITH
          reason_cluster,
          consequence_cluster,
          size(cluster_pair_cves) AS support,
          cluster_pair_cves,
          member_pairs
        WHERE support >= $min_support

        UNWIND member_pairs AS mp2
        WITH
          reason_cluster,
          consequence_cluster,
          support,
          cluster_pair_cves,
          mp2
        ORDER BY mp2.freq DESC, mp2.avg_cvss DESC

        WITH
          reason_cluster,
          consequence_cluster,
          support,
          cluster_pair_cves,
          collect(mp2)[0] AS representative_pair,
          collect(DISTINCT mp2.reason)[0..4] AS reason_examples,
          collect(DISTINCT mp2.consequence)[0..4] AS consequence_examples

        MATCH (v:Vulnerability)
        WHERE v.cve_id IN cluster_pair_cves

        RETURN
          reason_cluster,
          consequence_cluster,
          representative_pair.reason AS representative_reason,
          representative_pair.consequence AS representative_consequence,
          support,
          round(avg(v.cvss_score) * 100.0) / 100.0 AS avg_cvss,
          max(v.cvss_score) AS max_cvss,
          reason_examples,
          consequence_examples,
          cluster_pair_cves[0..8] AS cve_examples

        ORDER BY support DESC, avg_cvss DESC
        LIMIT $limit
        """,
    },

    {
        "id": "Q6",
        "class": "Cross-vendor semantic transfer",
        "plain_language": (
            "Find vulnerabilities from different vendors that share semantically similar "
            "exploitation mechanisms."
        ),
        "params": {
            "sim_threshold": 0.92,
            "limit": TOP_K,
        },
        "cypher": """
        MATCH (v1:Vulnerability)-[:HAS_VENDOR]->(ven1:Vendor)
        MATCH (v2:Vulnerability)-[:HAS_VENDOR]->(ven2:Vendor)
        WHERE id(v1) < id(v2)
          AND ven1.key <> ven2.key

        MATCH (v1)-[:HAS_REASON]->(r1:Reason)
        MATCH (v2)-[:HAS_REASON]->(r2:Reason)
        MATCH (r1)-[sr:SIMILAR_TO]-(r2)
        WHERE sr.score >= $sim_threshold

        MATCH (v1)-[:EXPLOITED_BY_ACTION]->(a1:AttackerAction)
        MATCH (v2)-[:EXPLOITED_BY_ACTION]->(a2:AttackerAction)
        MATCH (a1)-[sa:SIMILAR_TO]-(a2)
        WHERE sa.score >= $sim_threshold

        WITH
          v1, v2, ven1, ven2,
          avg(sr.score) AS reason_sim,
          avg(sa.score) AS action_sim
        RETURN
          v1.cve_id AS cve_1,
          ven1.value AS vendor_1,
          v2.cve_id AS cve_2,
          ven2.value AS vendor_2,
          reason_sim,
          action_sim,
          (reason_sim + action_sim) / 2.0 AS avg_similarity
        ORDER BY avg_similarity DESC
        LIMIT $limit
        """,
    },

    {
        "id": "Q7",
        "class": "Context-filtered semantic ranking",
        "plain_language": (
            "For Microsoft vulnerabilities published in 2024, create a temporary Reason-only "
            "semantic projection restricted to the filtered CVE set, run WCC over that filtered "
            "projection, and rank reason components by distinct CVE count."
        ),
        "params": {
            "vendor": "microsoft",
            "from_date": "2020-01-01T00:00:00",
            "to_date": "2024-12-31T23:59:59",
            "threshold": 0.92,
            "limit": TOP_K,
        },
        "requires_graphs": ["reasonFilteredGraph092"],
        "cypher": """
        CALL gds.wcc.stream('reasonFilteredGraph092')
        YIELD nodeId, componentId
        WITH componentId, gds.util.asNode(nodeId) AS r

        MATCH (v:Vulnerability)-[:HAS_REASON]->(r)
        MATCH (v)-[:HAS_VENDOR]->(ven:Vendor)
        WHERE datetime(v.published_date) >= datetime($from_date)
          AND datetime(v.published_date) <= datetime($to_date)
          AND (
            toLower(ven.value) = toLower($vendor)
            OR toLower(ven.alternative_value) = toLower($vendor)
          )

        WITH
          componentId,
          r,
          r.value AS reason_text,
          collect(DISTINCT v.cve_id) AS reason_cves,
          avg(v.cvss_score) AS reason_avg_cvss,
          max(v.cvss_score) AS reason_max_cvss

        WITH
          componentId,
          r,
          reason_text,
          size(reason_cves) AS freq,
          reason_cves,
          reason_avg_cvss,
          reason_max_cvss
        ORDER BY componentId, freq DESC, reason_avg_cvss DESC

        WITH
          componentId,
          collect({
            reason: reason_text,
            freq: freq,
            avg_cvss: round(reason_avg_cvss * 100.0) / 100.0,
            max_cvss: reason_max_cvss,
            cves: reason_cves[0..6]
          }) AS ranked,
          count(DISTINCT r) AS reason_node_count

        UNWIND ranked AS item
        UNWIND item.cves AS cve_id

        WITH
          componentId,
          ranked,
          reason_node_count,
          collect(DISTINCT cve_id) AS component_cves

        MATCH (v:Vulnerability)
        WHERE v.cve_id IN component_cves

        RETURN
          componentId AS reason_cluster,
          ranked[0].reason AS representative_reason,
          ranked[0].freq AS representative_reason_vuln_count,
          size(component_cves) AS total_cve_count,
          reason_node_count,
          round(avg(v.cvss_score) * 100.0) / 100.0 AS avg_cvss,
          max(v.cvss_score) AS max_cvss,
          ranked[0..5] AS top_reason_members,
          component_cves[0..8] AS example_cves

        ORDER BY total_cve_count DESC, avg_cvss DESC
        LIMIT $limit
        """,
    },
]


TEMP_GDS_GRAPHS: List[Dict[str, Any]] = [
    {
        "name": "reasonGraph092",
        "label": "Reason",
        "threshold": 0.92,
    },
    {
        "name": "consequenceGraph092",
        "label": "Consequence",
        "threshold": 0.92,
    },
]


def drop_gds_graph_if_exists(session, graph_name: str) -> None:
    """Drop a GDS in-memory graph if it exists; ignore absence."""
    try:
        session.run(
            "CALL gds.graph.drop($graph_name, false) YIELD graphName RETURN graphName",
            graph_name=graph_name,
        ).consume()
    except Exception:
        # Some GDS versions still raise if the graph does not exist.
        pass


def project_thresholded_semantic_graph(
    session,
    graph_name: str,
    label: str,
    threshold: float,
) -> Dict[str, Any]:
    """
    Create a temporary GDS projection over semantic nodes using thresholded
    SIMILAR_TO edges. This does not write cluster IDs or properties to Neo4j.
    """
    drop_gds_graph_if_exists(session, graph_name)

    query = f"""
    CALL gds.graph.project.cypher(
      $graph_name,
      '
      MATCH (n:{label})
      RETURN id(n) AS id
      ',
      '
      MATCH (a:{label})-[r:SIMILAR_TO]-(b:{label})
      WHERE r.score >= {threshold}
        AND id(a) < id(b)
      RETURN id(a) AS source, id(b) AS target
      '
    )
    YIELD graphName, nodeCount, relationshipCount, projectMillis
    RETURN graphName, nodeCount, relationshipCount, projectMillis
    """
    rec = session.run(query, graph_name=graph_name).single()
    return dict(rec) if rec else {}


def project_filtered_reason_graph(
    session,
    graph_name: str,
    vendor: str,
    from_date: str,
    to_date: str,
    threshold: float,
) -> Dict[str, Any]:
    """
    Create a temporary GDS projection over only those Reason nodes connected
    to vulnerabilities satisfying the query-time vendor and date filters.
    This projection is used by Q7 and does not write any properties to Neo4j.
    """
    drop_gds_graph_if_exists(session, graph_name)

    query = """
    CALL gds.graph.project.cypher(
      $graph_name,
      '
      MATCH (v:Vulnerability)-[:HAS_REASON]->(r:Reason)
      WHERE datetime(v.published_date) >= datetime($from_date)
        AND datetime(v.published_date) <= datetime($to_date)

      MATCH (v)-[:HAS_VENDOR]->(ven:Vendor)
      WHERE toLower(ven.value) = toLower($vendor)
         OR toLower(ven.alternative_value) = toLower($vendor)

      RETURN DISTINCT id(r) AS id
      ',
      '
      MATCH (v1:Vulnerability)-[:HAS_REASON]->(r1:Reason)
      WHERE datetime(v1.published_date) >= datetime($from_date)
        AND datetime(v1.published_date) <= datetime($to_date)

      MATCH (v1)-[:HAS_VENDOR]->(ven1:Vendor)
      WHERE toLower(ven1.value) = toLower($vendor)
         OR toLower(ven1.alternative_value) = toLower($vendor)

      WITH DISTINCT r1
      MATCH (r1)-[sim:SIMILAR_TO]-(r2:Reason)
      WHERE r1 <> r2
        AND sim.score >= $threshold

      MATCH (v2:Vulnerability)-[:HAS_REASON]->(r2)
      WHERE datetime(v2.published_date) >= datetime($from_date)
        AND datetime(v2.published_date) <= datetime($to_date)

      MATCH (v2)-[:HAS_VENDOR]->(ven2:Vendor)
      WHERE toLower(ven2.value) = toLower($vendor)
         OR toLower(ven2.alternative_value) = toLower($vendor)

      RETURN DISTINCT id(r1) AS source, id(r2) AS target
      ',
      {
        parameters: {
          vendor: $vendor,
          from_date: $from_date,
          to_date: $to_date,
          threshold: $threshold
        }
      }
    )
    YIELD graphName, nodeCount, relationshipCount, projectMillis
    RETURN graphName, nodeCount, relationshipCount, projectMillis
    """
    rec = session.run(
        query,
        graph_name=graph_name,
        vendor=vendor,
        from_date=from_date,
        to_date=to_date,
        threshold=threshold,
    ).single()
    return dict(rec) if rec else {}



def project_context_filtered_semantic_graph(
    session,
    graph_name: str,
    label: str,
    vuln_rel: str,
    vendor: str | None,
    software: str | None,
    from_date: str,
    to_date: str,
    threshold: float,
) -> Dict[str, Any]:
    """
    Create a temporary GDS projection over semantic nodes of a given label
    connected to vulnerabilities satisfying optional vendor/software and date
    filters. This is used for context-filtered correlation analysis in Q5.
    """
    drop_gds_graph_if_exists(session, graph_name)

    query = f"""
    CALL gds.graph.project.cypher(
      $graph_name,
      '
      MATCH (v:Vulnerability)-[:{vuln_rel}]->(n:{label})
      WHERE datetime(v.published_date) >= datetime($from_date)
        AND datetime(v.published_date) <= datetime($to_date)

      OPTIONAL MATCH (v)-[:HAS_VENDOR]->(ven:Vendor)
      OPTIONAL MATCH (v)-[:AFFECTS_SOFTWARE]->(s:Software)

      WITH v, n, ven, s
      WHERE ($vendor IS NULL
             OR toLower(ven.value) = toLower($vendor)
             OR toLower(ven.alternative_value) = toLower($vendor))
        AND ($software IS NULL
             OR toLower(s.value) = toLower($software)
             OR toLower(s.alternative_value) = toLower($software))

      RETURN DISTINCT id(n) AS id
      ',
      '
      MATCH (v1:Vulnerability)-[:{vuln_rel}]->(n1:{label})
      WHERE datetime(v1.published_date) >= datetime($from_date)
        AND datetime(v1.published_date) <= datetime($to_date)

      OPTIONAL MATCH (v1)-[:HAS_VENDOR]->(ven1:Vendor)
      OPTIONAL MATCH (v1)-[:AFFECTS_SOFTWARE]->(s1:Software)

      WITH DISTINCT n1, ven1, s1
      WHERE ($vendor IS NULL
             OR toLower(ven1.value) = toLower($vendor)
             OR toLower(ven1.alternative_value) = toLower($vendor))
        AND ($software IS NULL
             OR toLower(s1.value) = toLower($software)
             OR toLower(s1.alternative_value) = toLower($software))

      MATCH (n1)-[sim:SIMILAR_TO]-(n2:{label})
      WHERE n1 <> n2
        AND sim.score >= $threshold

      MATCH (v2:Vulnerability)-[:{vuln_rel}]->(n2)
      WHERE datetime(v2.published_date) >= datetime($from_date)
        AND datetime(v2.published_date) <= datetime($to_date)

      OPTIONAL MATCH (v2)-[:HAS_VENDOR]->(ven2:Vendor)
      OPTIONAL MATCH (v2)-[:AFFECTS_SOFTWARE]->(s2:Software)

      WITH DISTINCT n1, n2, ven2, s2
      WHERE ($vendor IS NULL
             OR toLower(ven2.value) = toLower($vendor)
             OR toLower(ven2.alternative_value) = toLower($vendor))
        AND ($software IS NULL
             OR toLower(s2.value) = toLower($software)
             OR toLower(s2.alternative_value) = toLower($software))

      RETURN DISTINCT id(n1) AS source, id(n2) AS target
      ',
      {{
        parameters: {{
          vendor: $vendor,
          software: $software,
          from_date: $from_date,
          to_date: $to_date,
          threshold: $threshold
        }}
      }}
    )
    YIELD graphName, nodeCount, relationshipCount, projectMillis
    RETURN graphName, nodeCount, relationshipCount, projectMillis
    """

    rec = session.run(
        query,
        graph_name=graph_name,
        vendor=vendor,
        software=software,
        from_date=from_date,
        to_date=to_date,
        threshold=threshold,
    ).single()
    return dict(rec) if rec else {}


def create_required_temp_graphs(session) -> List[Dict[str, Any]]:
    """Create all temporary GDS graphs needed by cluster-based queries."""
    projection_results = []
    for cfg in TEMP_GDS_GRAPHS:
        print(
            f"Projecting temporary semantic graph {cfg['name']} "
            f"({cfg['label']}, threshold={cfg['threshold']})"
        )
        result = project_thresholded_semantic_graph(
            session=session,
            graph_name=cfg["name"],
            label=cfg["label"],
            threshold=cfg["threshold"],
        )
        projection_results.append(result)
        print(
            f"  nodes={result.get('nodeCount')} "
            f"edges={result.get('relationshipCount')} "
            f"project_ms={result.get('projectMillis')}"
        )
    return projection_results


def drop_required_temp_graphs(session) -> None:
    """Drop temporary GDS graphs after the experiment."""
    for cfg in TEMP_GDS_GRAPHS:
        drop_gds_graph_if_exists(session, cfg["name"])



def run_query(session, query_info: Dict[str, Any]) -> Dict[str, Any]:
    qid = query_info["id"]
    cypher = query_info["cypher"]
    params = query_info["params"]

    start = time.perf_counter()
    result = session.run(cypher, **params)
    rows = [dict(record) for record in result]
    elapsed_ms = (time.perf_counter() - start) * 1000

    return {
        "id": qid,
        "class": query_info["class"],
        "plain_language": query_info["plain_language"],
        "params": params,
        "runtime_ms": round(elapsed_ms, 3),
        "row_count": len(rows),
        "rows": rows,
    }


def write_json(results: List[Dict[str, Any]]) -> None:
    path = OUTPUT_DIR / "query_capability_results.json"
    with path.open("w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)


def write_summary_csv(results: List[Dict[str, Any]]) -> None:
    path = OUTPUT_DIR / "query_capability_summary.csv"

    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "id",
                "class",
                "plain_language",
                "runtime_ms",
                "row_count",
                "params",
            ],
        )
        writer.writeheader()

        for r in results:
            writer.writerow({
                "id": r["id"],
                "class": r["class"],
                "plain_language": r["plain_language"],
                "runtime_ms": r["runtime_ms"],
                "row_count": r["row_count"],
                "params": json.dumps(r["params"]),
            })


def write_per_query_csv(results: List[Dict[str, Any]]) -> None:
    for r in results:
        rows = r["rows"]
        if not rows:
            continue

        path = OUTPUT_DIR / f"{r['id']}_{r['class'].lower().replace(' ', '_')}.csv"

        fieldnames = sorted({key for row in rows for key in row.keys()})

        with path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()

            for row in rows:
                serialized = {
                    k: json.dumps(v, ensure_ascii=False) if isinstance(v, (list, dict)) else v
                    for k, v in row.items()
                }
                writer.writerow(serialized)


def main() -> None:
    driver = GraphDatabase.driver(
        settings.uri,
        auth=(settings.user, settings.password),
    )

    results: List[Dict[str, Any]] = []

    try:
        with driver.session(database=settings.database) as session:
            try:
                # Temporary GDS projections are used only for Q5/Q7.
                # They are analytical artifacts and are not persisted to Neo4j.
                create_required_temp_graphs(session)

                for query_info in QUERIES:
                    print(f"Running {query_info['id']}: {query_info['class']}")
                    filtered_graph_name = None

                    try:
                        if query_info["id"] == "Q5":
                            # Q5 uses two context-filtered semantic projections:
                            # one for Reason nodes and one for Consequence nodes.
                            # WCC components are then correlated by shared CVE support.
                            params = query_info["params"]
                            q5_graphs = [
                                ("reasonFilteredCorrelationGraph092", "Reason", "HAS_REASON"),
                                ("consequenceFilteredCorrelationGraph092", "Consequence", "CAUSES_CONSEQUENCE"),
                            ]
                            for graph_name, label, rel_type in q5_graphs:
                                print(
                                    f"Projecting filtered {label} graph {graph_name} "
                                    f"(vendor={params['vendor']}, "
                                    f"software={params['software']}, "
                                    f"from={params['from_date']}, "
                                    f"to={params['to_date']}, "
                                    f"threshold={params['threshold']})"
                                )
                                projection = project_context_filtered_semantic_graph(
                                    session=session,
                                    graph_name=graph_name,
                                    label=label,
                                    vuln_rel=rel_type,
                                    vendor=params["vendor"],
                                    software=params["software"],
                                    from_date=params["from_date"],
                                    to_date=params["to_date"],
                                    threshold=params["threshold"],
                                )
                                print(
                                    f"  nodes={projection.get('nodeCount')} "
                                    f"edges={projection.get('relationshipCount')} "
                                    f"project_ms={projection.get('projectMillis')}"
                                )

                        if query_info["id"] == "Q7":
                            # Q7 uses a query-context-specific projection rather than
                            # the global Reason graph. The filtered projection includes
                            # only Reason nodes attached to Microsoft vulnerabilities
                            # published during the requested date range.
                            filtered_graph_name = "reasonFilteredGraph092"
                            params = query_info["params"]
                            print(
                                f"Projecting filtered Reason graph {filtered_graph_name} "
                                f"(vendor={params['vendor']}, "
                                f"from={params['from_date']}, "
                                f"to={params['to_date']}, "
                                f"threshold={params['threshold']})"
                            )
                            projection = project_filtered_reason_graph(
                                session=session,
                                graph_name=filtered_graph_name,
                                vendor=params["vendor"],
                                from_date=params["from_date"],
                                to_date=params["to_date"],
                                threshold=params["threshold"],
                            )
                            print(
                                f"  nodes={projection.get('nodeCount')} "
                                f"edges={projection.get('relationshipCount')} "
                                f"project_ms={projection.get('projectMillis')}"
                            )

                        result = run_query(session, query_info)
                        results.append(result)
                        print(
                            f"  rows={result['row_count']} "
                            f"time={result['runtime_ms']} ms"
                        )
                    except Exception as e:
                        print(f"  ERROR: {e}")
                        results.append({
                            "id": query_info["id"],
                            "class": query_info["class"],
                            "plain_language": query_info["plain_language"],
                            "params": query_info["params"],
                            "runtime_ms": None,
                            "row_count": 0,
                            "rows": [],
                            "error": str(e),
                        })
                    finally:
                        if query_info["id"] == "Q5":
                            drop_gds_graph_if_exists(session, "reasonFilteredCorrelationGraph092")
                            drop_gds_graph_if_exists(session, "consequenceFilteredCorrelationGraph092")
                        if filtered_graph_name:
                            drop_gds_graph_if_exists(session, filtered_graph_name)
            finally:
                drop_required_temp_graphs(session)

    finally:
        driver.close()

    write_json(results)
    write_summary_csv(results)
    write_per_query_csv(results)

    print("\nExperiment complete.")
    print(f"Results written to: {OUTPUT_DIR.resolve()}")


if __name__ == "__main__":
    main()