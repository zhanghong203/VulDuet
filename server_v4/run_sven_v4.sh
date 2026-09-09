#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PYTHON_BIN="${PYTHON_BIN:-$ROOT/.venv/bin/python}"
export PYTHONUNBUFFERED=1
export TOKENIZERS_PARALLELISM=false
export RULE_RAG_EMBEDDING_DEVICE="${RULE_RAG_EMBEDDING_DEVICE:-cuda:0}"

mkdir -p output/result/sven logs

exec "$PYTHON_BIN" -u -m src.main_sven_dual_path_v4 \
  --dataset data/test/sven/sven_cpp_pairs_official_423.jsonl \
  --profile deepseek_v3_2 \
  --workers "${SAMPLE_WORKERS:-3}" \
  --reasoning-workers "${REASONING_WORKERS:-5}" \
  --rule-top-k 5 \
  --knowledge-retrieval-top-k 5 \
  --knowledge-reasoning-top-k 3 \
  --minimum-scenario-match 0.2 \
  --minimum-confidence 0.5 \
  --request-timeout "${REQUEST_TIMEOUT:-120}" \
  "$@"
