#!/usr/bin/env bash
set -euo pipefail

# Default top-k values used for semantic neighborhood construction.
# More context-sensitive fields use a smaller neighborhood.
DEFAULT_TOP_K="15"
CONTEXT_TOP_K="10"
RECIPROCAL="False"
CONCURRENCY="1"

usage() {
  echo "Usage: $0 [--default_top_k <k>] [--context_top_k <k>] [--reciprocal True|False] [--concurrency <n>]"
  echo ""
  echo "Defaults:"
  echo "  --default_top_k 15     used for reason, attacker_action, consequences, trigger, vulnerability_type"
  echo "  --context_top_k 10     used for source, system_state"
  echo "  --reciprocal False"
  echo "  --concurrency 1"
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --default_top_k)
      DEFAULT_TOP_K="$2"; shift 2;;
    --context_top_k)
      CONTEXT_TOP_K="$2"; shift 2;;
    --top_k)
      # Backward-compatible option: sets the default top-k for non-context fields.
      DEFAULT_TOP_K="$2"; shift 2;;
    --reciprocal)
      RECIPROCAL="$2"; shift 2;;
    --concurrency)
      CONCURRENCY="$2"; shift 2;;
    --help|-h)
      usage;;
    *)
      echo "Unknown argument: $1"
      usage;;
  esac
done

for FIELD in source system_state reason attacker_action consequences trigger vulnerability_type; do
  if [[ "$FIELD" == "source" || "$FIELD" == "system_state" ]]; then
    FIELD_TOP_K="$CONTEXT_TOP_K"
  else
    FIELD_TOP_K="$DEFAULT_TOP_K"
  fi

  echo "[INFO] Building SIMILAR_TO for field=$FIELD top_k=$FIELD_TOP_K reciprocal=$RECIPROCAL"
  python build_similarity_edges.py \
    --field "$FIELD" \
    --top_k "$FIELD_TOP_K" \
    --concurrency "$CONCURRENCY" \
    --reciprocal "$RECIPROCAL"
done
