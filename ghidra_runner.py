"""Ghidra analyzeHeadless orchestrator (Python 3.12).

Runs the ``export_functions.py`` script (PyGhidra / Python 3) with analyzeHeadless.
The script scores all functions in the file, decompiles the highest-scoring ones,
and returns the result as a list of ``DecompiledFunction``.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
from typing import Any

from pydantic import BaseModel, ValidationError

from import_combos import combo_api_map
from state import DecompiledFunction

logger = logging.getLogger(__name__)

GHIDRA_TIMEOUT_SECONDS = int(os.environ.get("CROWBAR_GHIDRA_TIMEOUT", "600"))
GHIDRA_PROJECT_NAME = "TempGhidraProject"
SCRIPT_NAME = "export_functions.py"
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


def _find_analyze_headless() -> str | None:
    """Searches PATH and GHIDRA_INSTALL_DIR for the analyzeHeadless(.bat) executable."""
    exe = "analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless"

    found = shutil.which(exe)
    if found:
        return found

    install_dir = os.environ.get("GHIDRA_INSTALL_DIR")
    if install_dir:
        candidate = os.path.join(install_dir, "support", exe)
        if os.path.isfile(candidate):
            return candidate
    return None


def _finding_to_dict(finding: BaseModel | dict[str, Any]) -> dict[str, Any]:
    return finding.model_dump() if isinstance(finding, BaseModel) else dict(finding)


def _install_dir_from(analyze_headless: str) -> str | None:
    """Finds the Ghidra installation directory from the analyzeHeadless path (or env)."""
    env = os.environ.get("GHIDRA_INSTALL_DIR")
    if env:
        return env
    support = os.path.dirname(os.path.abspath(analyze_headless))
    cand = os.path.dirname(support)
    return cand if os.path.isdir(os.path.join(cand, "Ghidra")) else None


def _pyghidra_launcher(install_dir: str | None) -> str | None:
    """Returns the PyGhidra headless launcher (if present).

    export_functions.py is PyGhidra (Python 3), so it does not work with plain analyzeHeadless;
    the launcher starts AnalyzeHeadless with PyGhidra via -H.
    """
    if not install_dir:
        return None
    path = os.path.join(install_dir, "Ghidra", "Features", "PyGhidra",
                        "support", "pyghidra_launcher.py")
    return path if os.path.isfile(path) else None


def run_ghidra(
    file_path: str,
    hints: list[dict[str, Any]],
    findings: list[BaseModel | dict[str, Any]] | None = None,
    decoded_hints: list[dict[str, Any]] | None = None,
) -> list[DecompiledFunction]:
    """Analyzes the target file with Ghidra; decompiles priority functions.

    ``hints``: capa address hints (``[{"offset", "rule"}]``).
    ``findings``: ``state.findings``; the script uses it to reflect ``import_combo`` findings
    in function priority.
    ``decoded_hints``: FLOSS ``decoded_at``/``function`` metadata; used to bind decoded-only
    strings to functions.

    Ghidra is run even if ``hints`` and ``findings`` are empty; the script scans all
    functions and performs its own prioritization. It does not crash on error, timeout or
    when Ghidra is not found; it returns ``[]``.
    """
    # Managed manually instead of using a TemporaryDirectory context manager: cleanup is
    # guaranteed in finally, and locked files on Windows do not cause a crash.
    temp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
    try:
        analyze_headless = _find_analyze_headless()
        if analyze_headless is None:
            logger.error(
                "[run_ghidra] analyzeHeadless not found (check PATH or GHIDRA_INSTALL_DIR)"
            )
            return []

        temp_dir = temp.name
        input_json_path = os.path.join(temp_dir, "ghidra_input.json")
        out_json_path = os.path.join(temp_dir, "out.json")

        payload = {
            "hints": hints,
            "findings": [_finding_to_dict(f) for f in findings or []],
            # FLOSS decoded/tight string -> function metadata (Ghidra xref)
            "decoded_hints": decoded_hints or [],
            # import_combo finding -> API names (so the script does not have to know the rules)
            "combo_apis": combo_api_map(),
        }
        with open(input_json_path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=True)

        analyze_args = [
            temp_dir,
            GHIDRA_PROJECT_NAME,
            "-import",
            file_path,
            # Required because the script is not in Ghidra's default script directories
            "-scriptPath",
            SCRIPT_DIR,
            "-postScript",
            SCRIPT_NAME,
            input_json_path,
            out_json_path,
            "-deleteProject",
        ]
        install_dir = _install_dir_from(analyze_headless)
        launcher = _pyghidra_launcher(install_dir)
        if launcher:
            # export_functions.py is PyGhidra (Python 3): start AnalyzeHeadless with PyGhidra
            cmd = [sys.executable, launcher, str(install_dir), "-H", "--console", *analyze_args]
        else:
            logger.warning(
                "[run_ghidra] PyGhidra launcher not found; trying plain analyzeHeadless "
                "(the PyGhidra script may not work)"
            )
            cmd = [analyze_headless, *analyze_args]

        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=GHIDRA_TIMEOUT_SECONDS,
            check=False,
        )
        if proc.returncode != 0:
            tail = (proc.stderr.strip() or proc.stdout.strip() or "no output")[-500:]
            logger.error(
                "[run_ghidra] analyzeHeadless exited with code %s: %s", proc.returncode, tail
            )
            return []

        if not os.path.isfile(out_json_path):
            logger.error("[run_ghidra] Ghidra did not produce an output file (out.json)")
            return []

        with open(out_json_path, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
        if not isinstance(raw, list):
            logger.error("[run_ghidra] out.json has an unexpected structure (not a list)")
            return []

        functions: list[DecompiledFunction] = []
        for item in raw:
            try:
                functions.append(DecompiledFunction(**item))
            except (ValidationError, TypeError) as exc:
                logger.warning("[run_ghidra] skipped invalid function record: %s", exc)
        return functions

    except subprocess.TimeoutExpired:
        logger.error("[run_ghidra] Ghidra did not finish within %d seconds (timeout)", GHIDRA_TIMEOUT_SECONDS)
    except FileNotFoundError as exc:
        logger.error("[run_ghidra] analyzeHeadless or the target file was not found: %s", exc)
    except json.JSONDecodeError as exc:
        logger.error("[run_ghidra] could not parse out.json: %s", exc)
    except Exception as exc:  # noqa: BLE001 - the workflow must never crash
        logger.error("[run_ghidra] unexpected error: %s: %s", type(exc).__name__, exc)
    finally:
        temp.cleanup()  # the temp folder + ghidra_input.json/out.json are always deleted

    return []
