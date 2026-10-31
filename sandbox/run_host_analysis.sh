#!/usr/bin/env bash
# Run on the host (or a separate LLM VM), never inside the malware-analysis VM.
# The API key must come from the environment; this script never accepts it.
set -euo pipefail
umask 077

if [[ $# -lt 1 ]]; then
  echo "usage: $0 <state.json> [state.llm.json]" >&2
  exit 2
fi

state="$1"
out="${2:-${state%.json}.llm.json}"
repo_dir="$(cd "$(dirname "$0")/.." && pwd)"

# Do not inherit the analysis-VM skip flags.
unset CROWBAR_SKIP_LLM 2>/dev/null || true
unset CROWBAR_SKIP_DB 2>/dev/null || true

echo "[host] LLM stage: $state -> $out" >&2
exec "${PYTHON:-python3}" "$repo_dir/host_analyze.py" --state "$state" --out "$out"
