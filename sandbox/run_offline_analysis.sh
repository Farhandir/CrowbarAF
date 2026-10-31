#!/usr/bin/env bash
# Run inside the offline analysis VM.
# Produces a deterministic state.json with NO LLM call, NO API key, NO DB write.
set -euo pipefail
umask 077

if [[ $# -lt 1 ]]; then
  echo "usage: $0 <sample> [state.json]" >&2
  exit 2
fi

sample="$1"
out="${2:-state_$(date +%Y%m%d-%H%M%S).json}"

if [[ ! -f "$sample" ]]; then
  echo "sample not found: $sample" >&2
  exit 2
fi

repo_dir="$(cd "$(dirname "$0")/.." && pwd)"
export CROWBAR_SKIP_LLM=1
export CROWBAR_SKIP_DB=1
unset CROWBAR_LLM_API_KEY 2>/dev/null || true

echo "[sandbox] deterministic analysis: $sample" >&2
echo "[sandbox] output: $out" >&2
exec "${PYTHON:-python3}" "$repo_dir/main.py" "$sample" --no-llm --no-db --out "$out"
