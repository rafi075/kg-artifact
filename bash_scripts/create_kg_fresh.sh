#!/usr/bin/env bash
set -euo pipefail

TOP_K="10"
RECIPROCAL="False"
CONCURRENCY="1"
SKIP_SIMILARITY="false"
CREATE_EMBEDDINGS="false"

usage() {
  echo "Usage: $0 [--top_k 10] [--reciprocal True|False] [--concurrency 1] [--skip_similarity] [--do_embeddings]"
  echo "This script assumes a brand-new empty Neo4j database is already running."
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --top_k)
      TOP_K="$2"; shift 2;;
    --reciprocal)
      RECIPROCAL="$2"; shift 2;;
    --concurrency)
      CONCURRENCY="$2"; shift 2;;
    --skip_similarity)
      SKIP_SIMILARITY="true"; shift;;
    --do_embeddings)
      CREATE_EMBEDDINGS="true"; shift;; 
    *)
      echo "Unknown argument: $1"; usage;;
  esac
done

echo "[INFO] Creating schema in the empty Neo4j database"
python neo4j_schema.py

echo "[INFO] Loading structural nodes and relationships"
python load_vulnerabilities.py

if [[ "$CREATE_EMBEDDINGS" != "false" ]]; then
  echo "[INFO] Creating semantic embeddings"
  python create_semantic_embeddings.py
fi


echo "[INFO] Loading semantic nodes and relationships"
python load_semantic_nodes.py

if [[ "$SKIP_SIMILARITY" != "true" ]]; then
  for FIELD in source system_state reason attacker_action consequences trigger vulnerability_type; do
    echo "[INFO] Building SIMILAR_TO for field=$FIELD top_k=$TOP_K reciprocal=$RECIPROCAL"
    python build_similarity_edges.py --field "$FIELD" --top_k "$TOP_K" --concurrency "$CONCURRENCY" --reciprocal "$RECIPROCAL"
  done
fi

echo "[INFO] Fresh KG creation completed"
