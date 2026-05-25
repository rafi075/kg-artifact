#!/usr/bin/env bash
set -euo pipefail

OUTPUT_CSV="topk_neighborhood_selection.csv"
RECIPROCAL="False"
CONCURRENCY="1"
FIELDS=("source" "system_state" "reason" "attacker_action" "consequences" "trigger" "vulnerability_type")
TOPKS=("5" "10" "15" "20")

usage() {
  echo "Usage: $0 [--output_csv file.csv] [--reciprocal True|False] [--concurrency 1] [--fields \"reason consequences\"] [--topks \"5 10 15 20\"]"
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output_csv)
      OUTPUT_CSV="$2"; shift 2;;
    --reciprocal)
      RECIPROCAL="$2"; shift 2;;
    --concurrency)
      CONCURRENCY="$2"; shift 2;;
    --fields)
      read -r -a FIELDS <<< "$2"; shift 2;;
    --topks)
      read -r -a TOPKS <<< "$2"; shift 2;;
    *)
      echo "Unknown argument: $1"; usage;;
  esac
done

rm -f "$OUTPUT_CSV"

for FIELD in "${FIELDS[@]}"; do
  for K in "${TOPKS[@]}"; do
    echo "[INFO] Evaluating field=$FIELD top_k=$K reciprocal=$RECIPROCAL"
    python build_similarity_edges.py --field "$FIELD" --top_k "$K" --concurrency "$CONCURRENCY" --reciprocal "$RECIPROCAL"
    python analyze_similarity_edges.py --field "$FIELD" --top_k "$K" --reciprocal "$RECIPROCAL" --output_csv "$OUTPUT_CSV"
  done
done

echo "[INFO] Top-k neighborhood selection results saved to $OUTPUT_CSV"
