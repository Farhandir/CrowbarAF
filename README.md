# CrowbarAF

Autonomous **static malware analysis** pipeline (LangGraph) with a
**context-efficient, evidence-grounded** LLM layer.

## Pipeline
```
DIE + YARA triage
   -> unpack (UPX / PyInstaller / .NET)
   -> static features (capa, FLOSS, imports, entropy, import combos)
   -> Ghidra decompile (prioritized)
   -> LLM analysis (budgeted, bottom-up)
   -> tool-first report + SQLite + FastAPI UI
```

## Highlights
- **Deterministic first:** capa/FLOSS/imports/entropy produce the evidence; the LLM
  explains it, it is not the authority.
- **Context-efficient:** priority selection, per-function budgets, soft budgets for
  low-priority functions, optional priority threshold, bottom-up summaries
  (call-graph SCC order).
- **Evidence-grounded:** every AI claim is classified as
  `verified_claim` / `verified_observation` / `file_level` / `unverified`.
- **Honest uncertainty:** with no evidence the verdict is `unknown`, never `clean`.
- **Model-agnostic:** Ollama, vLLM or any OpenAI-compatible endpoint.
- **Traceable:** every run writes a JSON trace (functions selected/skipped, token
  usage, claims and their verification status).
- **Reports:** Markdown / HTML / JSON; SQLite storage; FastAPI UI.

## Quick start
```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
pip install -r requirements-tools.txt      # optional: capa, floss, yara-python, ...

cp .env.example .env && set -a && . ./.env && set +a

python main.py <sample>                    # CLI: analysis + state JSON
python main.py --serve                     # UI/API at http://127.0.0.1:8000
python report.py <state.json> --format md --out reports/
```

External tools (diec, upx, pycdc, capa rules) are optional; missing tools degrade
gracefully. Full instructions: **[`docs/SETUP.md`](docs/SETUP.md)**.

## Docs
- [`docs/SETUP.md`](docs/SETUP.md) — installation, tools, environment
- [`docs/LLM-LAYER.md`](docs/LLM-LAYER.md) — LLM layer design and usage
- [`docs/PIPELINE-HANDOFF.md`](docs/PIPELINE-HANDOFF.md) — data contract and pipeline TODOs
- [`docs/TOOL-ADDITIONS.md`](docs/TOOL-ADDITIONS.md) — how to add analysis tools
- [`results/archive/README.md`](results/archive/README.md) — experiment setup, records and metrics

## Status
End-to-end pipeline verified on harmless samples (DIE → YARA → FLOSS → Ghidra →
LLM → DB). The context-reduction layer is tested; LLM detection precision with a
9B local model is limited, so results should be read as *assistance*, not a verdict.
