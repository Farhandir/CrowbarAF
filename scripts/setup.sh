#!/usr/bin/env bash
# One-command Python setup for CrowbarAF.
#
#   ./scripts/setup.sh                 # venv + core requirements
#   ./scripts/setup.sh --with-tools    # + capa/FLOSS/YARA/py-tlsh (pip tools)
#
# Ghidra, JDK, readelf and UPX are system tools and cannot be installed by pip;
# scripts/check_tools.py prints what is missing (see docs/SETUP.md).
set -euo pipefail

cd "$(dirname "$0")/.."
PYTHON="${PYTHON:-python3}"
WITH_TOOLS=0
if [[ "${1:-}" == "--with-tools" || "${1:-}" == "--tools" ]]; then
  WITH_TOOLS=1
fi

if ! command -v "$PYTHON" >/dev/null 2>&1; then
  echo "Python not found: $PYTHON" >&2
  exit 2
fi

if [[ ! -d .venv ]]; then
  echo "[setup] creating .venv with $PYTHON"
  "$PYTHON" -m venv .venv
fi

# shellcheck disable=SC1091
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

if [[ "$WITH_TOOLS" == "1" ]]; then
  echo "[setup] installing optional pip analysis tools"
  if ! python -m pip install -r requirements-tools.txt; then
    echo "[setup] optional tools failed to install; core analysis still works" >&2
    echo "[setup] py-tlsh needs a C compiler; install build-essential or skip it" >&2
  fi
fi

echo
python scripts/check_tools.py || true

cat <<'EOF'

[setup] done.

Activate the environment:
  source .venv/bin/activate

Next:
  python main.py <sample> --no-llm --no-db --out state.json
  # or read the split-mode guide:
  # docs/HANDOFF-VM-SMOKE.md

API keys are never needed for the offline VM stage.
EOF
