#!/usr/bin/env python3
"""Host-side LLM stage for the split VM/host analysis.

The offline analysis VM runs:

    python main.py sample.bin --no-llm --no-db --out state.json

This script runs on the host (or a separate LLM VM) where the API key lives.
It reads the deterministic state, runs the LLM layer, recomputes the verdict
with policy C, builds the report, and writes a new state JSON.

The API key is read from the environment by ``llm_layer.factory.from_env``
(``CROWBAR_LLM_API_KEY`` for cloud providers). It is never accepted on the
command line, never written to the state, and never needed inside the analysis
VM.

Examples:
    # local model on the host (no cloud key)
    CROWBAR_LLM_PROVIDER=ollama CROWBAR_LLM_MODEL=qwen2.5-coder:7b \
        python host_analyze.py --state state.json --out state_llm.json

    # OpenAI-compatible provider; key only in the host environment
    CROWBAR_LLM_PROVIDER=openai CROWBAR_LLM_API_KEY=... \
        python host_analyze.py --state state.json --out state_llm.json \
        --model deepseek-v4.1-flash --max-workers 8

    # also persist to SQLite so the FastAPI UI (main.py --serve) shows it
    python host_analyze.py --state state.json --db            # crowbaraf.db
    python host_analyze.py --state state.json --db other.db
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

import db
from llm_layer.nodes import run_reverser, run_supervisor
from state import AgentState

DEFAULT_MAX_STATE_MB = int(os.getenv("CROWBAR_HOST_MAX_STATE_MB", "500"))
STATE_PERMISSIONS = 0o600


def load_state(path: str | Path) -> AgentState:
    """Read and validate a deterministic state JSON.

    The file comes from the analysis VM, so it is treated as untrusted input:
    size is bounded and parsing is strictly Pydantic validation.
    """
    p = Path(path).expanduser()
    if not p.is_file():
        raise ValueError(f"state file not found: {p}")
    size = p.stat().st_size
    if size > DEFAULT_MAX_STATE_MB * 1024 * 1024:
        raise ValueError(
            f"state file too large: {size} bytes "
            f"(limit {DEFAULT_MAX_STATE_MB} MB)"
        )
    try:
        text = p.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"cannot read state file: {exc}") from exc
    try:
        return AgentState.model_validate_json(text)
    except Exception as exc:  # noqa: BLE001 - report a clean CLI error
        raise ValueError(f"invalid state JSON: {type(exc).__name__}: {exc}") from exc


def analyze_state(
    state: AgentState,
    *,
    client=None,
    budget_tokens: int = 6000,
    report: bool = True,
) -> AgentState:
    """Run the LLM stage on a deterministic state and return the merged state.

    ``client`` is injectable for tests; production uses ``from_env`` inside
    ``run_reverser``. No database write (see ``persist_state``) and no sample
    execution happens here.
    """
    out = run_reverser(state, client=client, budget_tokens=budget_tokens)
    merged = state.model_copy(update=out)
    if report:
        merged = merged.model_copy(update=run_supervisor(merged))
    return merged


def write_state(state: AgentState, path: str | Path) -> Path:
    """Write the state atomically with owner-only permissions."""
    p = Path(path).expanduser()
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_name(f".{p.name}.tmp.{os.getpid()}")
    text = state.model_dump_json(indent=2)
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        try:
            os.chmod(tmp, STATE_PERMISSIONS)
        except OSError:
            pass
        os.replace(tmp, p)
    finally:
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass
    return p


def persist_state(state: AgentState, db_path: str | None = None) -> dict:
    """Host'ta biten analizi SQLite'a yazar (UI/``report.py --db`` görsün diye).

    Sample, bulgular, fonksiyonlar (``llm_summary`` dahil), çağrı kenarları ve
    ``llm_claims`` (rapor + ``verdict``) ``db.save_analysis`` ile kalıcı olur.
    ``sample.sha256`` boşsa ``ValueError`` fırlatır. Sadece **host** tarafında
    çağrılır; analiz VM'i ``--no-db`` ile hiç veritabanına dokunmaz.
    """
    return db.save_analysis(state, db_path)


def _apply_cli_env(args: argparse.Namespace) -> None:
    """Map non-secret CLI options to the env vars read by llm_layer."""
    if args.model:
        os.environ["CROWBAR_LLM_MODEL"] = args.model
    if args.provider:
        os.environ["CROWBAR_LLM_PROVIDER"] = args.provider
    if args.base_url:
        os.environ["CROWBAR_LLM_BASE_URL"] = args.base_url
    if args.num_ctx is not None:
        os.environ["CROWBAR_LLM_NUM_CTX"] = str(args.num_ctx)
    if args.num_predict is not None:
        os.environ["CROWBAR_LLM_NUM_PREDICT"] = str(args.num_predict)
    if args.max_workers is not None:
        os.environ["CROWBAR_LLM_MAX_WORKERS"] = str(args.max_workers)
    if args.min_priority is not None:
        os.environ["CROWBAR_LLM_MIN_PRIORITY"] = str(args.min_priority)
    if args.trace_dir:
        os.environ["CROWBAR_LLM_TRACE_DIR"] = args.trace_dir
    if args.cache:
        os.environ["CROWBAR_LLM_CACHE"] = args.cache


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Host-side LLM stage for CrowbarAF split analysis"
    )
    parser.add_argument("--state", required=True, help="state.json from the offline VM")
    parser.add_argument("--out", help="merged state JSON (default: stdout)")
    parser.add_argument("--model", help="model name (CROWBAR_LLM_MODEL)")
    parser.add_argument("--provider", help="ollama | openai | vllm (CROWBAR_LLM_PROVIDER)")
    parser.add_argument("--base-url", help="provider base URL (CROWBAR_LLM_BASE_URL)")
    parser.add_argument("--num-ctx", type=int, help="context window (CROWBAR_LLM_NUM_CTX)")
    parser.add_argument("--num-predict", type=int, help="max output tokens (CROWBAR_LLM_NUM_PREDICT)")
    parser.add_argument("--budget-tokens", type=int, default=6000, help="per-function context budget")
    parser.add_argument("--max-workers", type=int, help="parallel per-SCC-level calls")
    parser.add_argument("--min-priority", type=int, help="skip functions below this priority")
    parser.add_argument("--trace-dir", help="directory for LLM trace JSON")
    parser.add_argument("--cache", help="summary cache JSON path")
    parser.add_argument("--no-report", action="store_true", help="skip the deterministic report")
    parser.add_argument(
        "--db", nargs="?", const=db.DEFAULT_DB_PATH, default=None, metavar="PATH",
        help=f"persist the result to SQLite so the UI/report.py --db can show it "
             f"(PATH optional; default {db.DEFAULT_DB_PATH}). Omit to skip the DB.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    _apply_cli_env(args)

    if os.getenv("CROWBAR_SKIP_LLM", "").strip().lower() in ("1", "true", "yes", "on"):
        print(
            "host_analyze: CROWBAR_SKIP_LLM is set; unset it on the host "
            "(this side must run the LLM stage).",
            file=sys.stderr,
        )
        return 2

    try:
        state = load_state(args.state)
        merged = analyze_state(
            state,
            budget_tokens=args.budget_tokens,
            report=not args.no_report,
        )
        if args.out:
            path = write_state(merged, args.out)
            print(f"host_analyze: wrote {path}", file=sys.stderr)
        else:
            print(merged.model_dump_json(indent=2))
        if args.db:
            saved = persist_state(merged, args.db)
            print(
                f"host_analyze: saved to {saved['db_path']} "
                f"(sha256={saved['sha256'][:12]}, functions={saved['functions']}, "
                f"findings={saved['findings']}, verdict="
                f"{(merged.verdict or {}).get('verdict', '-')})",
                file=sys.stderr,
            )
    except Exception as exc:  # noqa: BLE001 - clean CLI failure, no traceback/key
        print(f"host_analyze: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
