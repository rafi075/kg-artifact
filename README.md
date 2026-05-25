# CVE++ : A Semantic-Aware KG-based Vulnerability Reasoning Framework  




## 1. Files

Core build files:

- `neo4j_schema.py`: creates constraints, full-text indexes, and vector indexes.
- `load_vulnerabilities.py`: loads vulnerability, vendor, software, version, and remaining structured nodes.
- `create_semantic_embeddings.py`: creates one embedding per unique exact semantic value.
- `load_semantic_nodes.py`: loads semantic nodes and connects CVEs to them.
- `build_similarity_edges.py`: creates KNN-based `SIMILAR_TO` edges per semantic field.
- `analyze_similarity_edges.py`: summarizes semantic neighborhood quality for top-k selection.
- `create_kg_fresh.sh`: runs the full fresh-build pipeline.
- `evaluate_topk_neighborhoods.sh`: sweeps top-k values for paper/evaluation analysis.

## 2. Semantic fields in this artifact

The semantic fields are:

- `source`
- `system_state`
- `reason`
- `attacker_action`
- `consequences`
- `trigger`
- `vulnerability_type`


## 3. Structured fields

The structural fields remain:

- `vendor_raw` / `vendor` -> `Vendor`
- `software_raw` / `software` -> `Software`
- `software_version` -> product-specific `SoftwareVersion`
- `operatig_system` -> `OperatingSystem`
- `user_interaction` -> `UserInteraction`
- `network_access` -> `NetworkAccess`
- `privilege` -> `Privilege`



## 4. Setup

Install dependencies:

```bash
pip install -r requirements.txt
```

Create a `.env` file from `.env.template`:

```bash
cp .env.template .env
```

Edit `.env` with the local Neo4j password and database name.

Place the dataset CSV in the same directory using the filename expected by the scripts:

```text
cve_data2.csv
```

If your dataset has a different name, update `CSV_PATH` in:

- `load_vulnerabilities.py`
- `create_semantic_embeddings.py`
- `load_semantic_nodes.py`

add Graph Data Science (GDS) plugin to the database. GDS plugin can be installed the GDS library directly from the Neo4j UI

## 5. Fresh KG creation

Start a new empty Neo4j database in Neo4j Desktop. Then run:

```bash
bash create_kg_fresh.sh --top_k 10 --reciprocal False
```

To enforce reciprocal `SIMILAR_TO` edges:

```bash
bash create_kg_fresh.sh --top_k 10 --reciprocal True
```



To generate new embeddings jsonl file (if not already exists ). [```semantic_embeddings_exact_merge.jsonl``` is provided]  

```bash
bash create_kg_fresh.sh --do_embeddings
```

## 6. Reciprocal vs non-reciprocal SIMILAR_TO

`build_similarity_edges.py` supports:

```bash
--reciprocal True
```

or

```bash
--reciprocal False
```

Non-reciprocal mode preserves the raw KNN output. Reciprocal mode enforces both directions for every unordered pair, using a symmetric averaged score if both directions exist.

## 7. Top-k neighborhood selection for the paper

To sweep different K values for all semantic fields:

```bash
bash evaluate_topk_neighborhoods.sh --topks "5 10 15 20" --reciprocal False --output_csv topk_selection.csv
```

To evaluate only selected fields:

```bash
bash evaluate_topk_neighborhoods.sh --fields "reason consequences attacker_action" --topks "5 10 15 20" --output_csv topk_selection_subset.csv
```

The output CSV can be used to justify the chosen `top_k` by comparing:

- unique semantic pairs
- directed edge count
- reciprocal pair count
- one-way pair count
- average similarity
- score percentiles
- number of pairs above common thresholds

## 8. Verification queries

Check node counts:

```cypher
MATCH (n) RETURN labels(n)[0] AS label, count(*) AS count ORDER BY count DESC;
```

Check semantic edges:

```cypher
MATCH (a:Reason)-[r:SIMILAR_TO]->(b:Reason)
RETURN a.value, b.value, r.score
ORDER BY r.score DESC
LIMIT 20;
```

Check reciprocal status:

```cypher
MATCH (a:Reason)-[r:SIMILAR_TO]->(b:Reason)
WHERE a <> b
WITH
  CASE WHEN elementId(a) < elementId(b) THEN elementId(a) ELSE elementId(b) END AS node1,
  CASE WHEN elementId(a) < elementId(b) THEN elementId(b) ELSE elementId(a) END AS node2,
  count(*) AS direction_count
RETURN
  count(*) AS unique_pairs,
  sum(direction_count) AS directed_edges,
  sum(CASE WHEN direction_count = 2 THEN 1 ELSE 0 END) AS reciprocal_pairs,
  sum(CASE WHEN direction_count = 1 THEN 1 ELSE 0 END) AS one_way_pairs;
```
