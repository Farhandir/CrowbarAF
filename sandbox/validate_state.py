#!/usr/bin/env python3
"""Validate a CrowbarAF ``state.json`` before it crosses the VM/host boundary.

Checks, in order (all failures are collected; exit code 1 if any fails):

  1. size        file <= 50 MB (``--max-mb``)            -- stops here if exceeded
  2. schema      valid JSON object with ``sample``, ``route_flag``, ``file_path``
  3. permissions POSIX only: no bit outside ``0o600`` (no group/world access)
  4. summaries   every decompiled function has a string ``llm_summary``;
                 empty ones are rejected (an unfinished analysis)
  5. key leak    no ``sk-...`` style API key and not the value of
                 ``CROWBAR_LLM_API_KEY`` anywhere in the state (keys and values,
                 nested). The matched text is never printed.

Exit codes: 0 = valid, 1 = invalid / could not be validated.

Note on ``--allow-empty-summaries``: the *offline VM* produces a deterministic
state with ``--no-llm``, so its ``llm_summary`` fields are empty **by design**.
Use the flag for that stage; run without it on the host after the LLM stage.
The type check (string) and every other check still apply with the flag.

Usage:
    python sandbox/validate_state.py /out/true.state.json
    python sandbox/validate_state.py --allow-empty-summaries /out/*.state.json
"""
from __future__ import annotations

import argparse
import json
import os
import re
import stat
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator, Mapping

MAX_STATE_MB = 50
REQUIRED_KEYS = ("sample", "route_flag", "file_path")
ALLOWED_PERMISSION_BITS = 0o600
API_KEY_ENV = "CROWBAR_LLM_API_KEY"
# ``sk-`` must start a token ("disk-", "task-", "risk-" do not match) and be
# followed by enough key-like characters (OpenAI/DeepSeek style keys are long).
SK_KEY_RE = re.compile(r"(?<![A-Za-z0-9_])sk-[A-Za-z0-9_\-]{16,}")
MIN_ENV_KEY_LEN = 8  # a 1-2 char "key" would match everything; ignore it
MAX_LEAKS_REPORTED = 10


@dataclass
class ValidationResult:
    path: str
    errors: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)   # checks not applicable (e.g. POSIX perms on Windows)
    functions: int = 0
    findings: int = 0

    @property
    def ok(self) -> bool:
        return not self.errors

    def __bool__(self) -> bool:
        return self.ok


# --------------------------------------------------------------------------- #
# Individual checks (each returns a list of error strings)
# --------------------------------------------------------------------------- #
def check_size(path: Path, max_mb: float = MAX_STATE_MB) -> list[str]:
    size = path.stat().st_size
    if size > max_mb * 1024 * 1024:
        return [f"size: {size / 1024 / 1024:.1f} MB exceeds the {max_mb:g} MB limit"]
    return []


def check_schema(state: Any) -> list[str]:
    if not isinstance(state, dict):
        return [f"schema: top-level JSON must be an object, got {type(state).__name__}"]
    errors = [f"schema: missing required key '{k}'" for k in REQUIRED_KEYS if k not in state]
    if "sample" in state and not isinstance(state["sample"], dict):
        errors.append("schema: 'sample' must be an object")
    if "file_path" in state and not isinstance(state["file_path"], str):
        errors.append("schema: 'file_path' must be a string")
    for key in ("source_code", "findings"):
        if key in state and not isinstance(state[key], list):
            errors.append(f"schema: '{key}' must be a list")
    return errors


def _is_windows() -> bool:
    return os.name == "nt"


def check_permissions(path: Path) -> list[str] | None:
    """POSIX only. Returns ``None`` (skipped) on Windows, else a list of errors."""
    if _is_windows():
        return None
    mode = stat.S_IMODE(path.stat().st_mode)
    extra = mode & ~ALLOWED_PERMISSION_BITS
    if extra:
        return [f"permissions: mode {mode:04o} is too open "
                f"(group/world or extra bits {extra:04o}); expected at most 0600 "
                f"-- fix with: chmod 600 <file>"]
    return []


def check_llm_summaries(state: dict, allow_empty: bool = False) -> list[str]:
    functions = state.get("source_code")
    if not isinstance(functions, list):
        return []  # absence/type is a schema matter
    errors: list[str] = []
    empty: list[str] = []
    for i, fn in enumerate(functions):
        label = fn.get("offset") if isinstance(fn, dict) and fn.get("offset") else f"#{i}"
        if not isinstance(fn, dict):
            errors.append(f"llm_summary: source_code[{i}] is not an object")
            continue
        summary = fn.get("llm_summary")
        if not isinstance(summary, str):
            errors.append(f"llm_summary: function {label} has a non-string llm_summary "
                          f"({type(summary).__name__})")
        elif not summary.strip():
            empty.append(str(label))
    if empty and not allow_empty:
        shown = ", ".join(empty[:5]) + (f", ... (+{len(empty) - 5})" if len(empty) > 5 else "")
        errors.append(f"llm_summary: {len(empty)}/{len(functions)} function(s) have an empty "
                      f"llm_summary (unfinished analysis?): {shown}")
    return errors


def _iter_strings(obj: Any) -> Iterator[tuple[str, str]]:
    """Yield ``(json_path, string)`` for every dict key and string value, iteratively."""
    stack: list[tuple[str, Any]] = [("$", obj)]
    while stack:
        where, cur = stack.pop()
        if isinstance(cur, str):
            yield where, cur
        elif isinstance(cur, dict):
            for k, v in cur.items():
                if isinstance(k, str):
                    yield f"{where}.<key>", k  # a secret used as a dict key must not slip through
                stack.append((f"{where}.{k}", v))
        elif isinstance(cur, (list, tuple)):
            for i, v in enumerate(cur):
                stack.append((f"{where}[{i}]", v))


def check_key_leak(state: Any, env: Mapping[str, str] | None = None) -> list[str]:
    """Reject ``sk-...`` keys and the configured ``CROWBAR_LLM_API_KEY`` value.

    The secret itself is never included in the messages.
    """
    env = os.environ if env is None else env
    env_key = (env.get(API_KEY_ENV) or "").strip()
    if len(env_key) < MIN_ENV_KEY_LEN:
        env_key = ""

    hits: list[str] = []
    for where, text in _iter_strings(state):
        if SK_KEY_RE.search(text):
            hits.append(f"{where}: looks like an API key (sk-...)")
        elif env_key and env_key in text:
            hits.append(f"{where}: contains the value of {API_KEY_ENV}")
        if len(hits) > MAX_LEAKS_REPORTED:
            break
    errors = [f"key leak: {h}" for h in hits[:MAX_LEAKS_REPORTED]]
    if len(hits) > MAX_LEAKS_REPORTED:
        errors.append("key leak: more occurrences omitted")
    return errors


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #
def validate_state(
    path: str | Path,
    *,
    max_mb: float = MAX_STATE_MB,
    allow_empty_summaries: bool = False,
    env: Mapping[str, str] | None = None,
) -> ValidationResult:
    """Run all checks on ``path`` and return a ``ValidationResult`` (truthy when valid)."""
    p = Path(path).expanduser()
    result = ValidationResult(path=str(p))

    if not p.is_file():
        result.errors.append(f"file: not found or not a regular file: {p}")
        return result

    # 1) size -- before reading anything
    result.errors += check_size(p, max_mb)
    if result.errors:
        return result

    try:
        state = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError) as exc:
        result.errors.append(f"file: cannot read: {type(exc).__name__}")
        return result
    except json.JSONDecodeError as exc:
        result.errors.append(f"schema: invalid JSON ({exc.msg} at line {exc.lineno})")
        return result

    # 2) schema
    schema_errors = check_schema(state)
    result.errors += schema_errors

    # 3) permissions
    perm = check_permissions(p)
    if perm is None:
        result.skipped.append("permissions (POSIX only; skipped on Windows)")
    else:
        result.errors += perm

    if isinstance(state, dict):
        result.functions = len(state["source_code"]) if isinstance(state.get("source_code"), list) else 0
        result.findings = len(state["findings"]) if isinstance(state.get("findings"), list) else 0
        # 4) llm_summary
        if not schema_errors:
            result.errors += check_llm_summaries(state, allow_empty_summaries)

    # 5) key leak -- always scanned, even when other checks failed
    result.errors += check_key_leak(state, env)
    return result


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate a CrowbarAF state.json (size, schema, permissions, "
                    "llm_summary, API key leak). Exit 0 = valid, 1 = invalid."
    )
    parser.add_argument("state", nargs="+", help="state JSON file(s)")
    parser.add_argument("--max-mb", type=float, default=MAX_STATE_MB,
                        help=f"maximum file size in MB (default {MAX_STATE_MB})")
    parser.add_argument("--allow-empty-summaries", action="store_true",
                        help="accept empty llm_summary (deterministic --no-llm state from the offline VM)")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    failed = 0
    for path in args.state:
        res = validate_state(path, max_mb=args.max_mb,
                             allow_empty_summaries=args.allow_empty_summaries)
        if res.ok:
            note = f"; skipped: {', '.join(res.skipped)}" if res.skipped else ""
            print(f"OK    {res.path}  ({res.functions} functions, {res.findings} findings{note})")
        else:
            failed += 1
            print(f"FAIL  {res.path}")
            for err in res.errors:
                print(f"      - {err}", file=sys.stderr)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
