"""Unpack helpers: Python (.pyc), .NET and UPX extraction via external tools."""

from __future__ import annotations

import logging
import os
import re
import subprocess
import tempfile

logger = logging.getLogger(__name__)

UPX_TIMEOUT_SECONDS = int(os.environ.get("CROWBAR_UPX_TIMEOUT", "60"))
UNPACKED_SUFFIX = ".unpacked"
CLEAN_SUFFIX = ".clean"  # de4dot output
PYTHON_TOOL_TIMEOUT_SECONDS = 60  # pyinstxtractor, pycdc/decompyle3
DOTNET_TOOL_TIMEOUT_SECONDS = 60  # de4dot
DOTNET_DECOMPILE_TIMEOUT_SECONDS = 120  # ilspycmd (large assemblies take longer)


def _run_tool(cmd: list[str], timeout: int, cwd: str | None = None) -> subprocess.CompletedProcess[str] | None:
    """Runs an external tool. Returns the result only if ``returncode == 0``; otherwise ``None``.

    If the tool is missing, times out or exits with a non-zero code, the error is logged;
    it never raises.
    """
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            cwd=cwd,
            check=False,
        )
    except subprocess.TimeoutExpired:
        logger.warning("[unpack] %s did not finish within %d seconds (timeout)", cmd[0], timeout)
        return None
    except FileNotFoundError as exc:
        logger.warning("[unpack] %s not found: %s", cmd[0], exc)
        return None
    except Exception as exc:  # noqa: BLE001 - the workflow must never crash
        logger.warning("[unpack] %s could not be run: %s: %s", cmd[0], type(exc).__name__, exc)
        return None

    if proc.returncode != 0:
        tail = (proc.stderr.strip() or proc.stdout.strip() or "no output")[-300:]
        logger.warning("[unpack] %s exited with code %s: %s", cmd[0], proc.returncode, tail)
        return None
    return proc


def _find_main_pyc(extracted_dir: str, exe_stem: str, extractor_stdout: str) -> str | None:
    """Finds the application's main ``.pyc`` file in the pyinstxtractor output folder.

    Order: (1) one matching the exe name, (2) the one pyinstxtractor reports as the
    "Possible entry point", (3) the largest application .pyc. PyInstaller's own
    ``pyi*`` helper scripts are always excluded.
    """
    try:
        names = sorted(
            n
            for n in os.listdir(extracted_dir)
            if n.lower().endswith(".pyc")
            and not n.lower().startswith("pyi")
            and os.path.isfile(os.path.join(extracted_dir, n))
        )
    except OSError:
        return None

    for name in names:
        if os.path.splitext(name)[0].lower() == exe_stem.lower():
            return os.path.join(extracted_dir, name)
    for match in re.finditer(r"Possible entry point:\s*(\S+\.pyc)", extractor_stdout):
        if match.group(1) in names:
            return os.path.join(extracted_dir, match.group(1))
    if names:
        return os.path.join(extracted_dir, max(names, key=lambda n: os.path.getsize(os.path.join(extracted_dir, n))))
    return None


def _decompile_pyc(pyc_path: str) -> str:
    """Converts a .pyc to Python source with ``pycdc``, falling back to ``decompyle3``; else ``""``."""
    for tool in ("pycdc", "decompyle3"):
        proc = _run_tool([tool, pyc_path], PYTHON_TOOL_TIMEOUT_SECONDS)
        if proc is not None and proc.stdout.strip():
            return proc.stdout
    return ""


def _extract_python_source(file_path: str) -> str:
    """Extracts the main script's Python source from a PyInstaller exe; ``""`` on failure."""
    temp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
    try:
        abs_path = os.path.abspath(file_path)
        # pyinstxtractor writes its output into the working directory: keep it away from the original file
        proc = _run_tool(["pyinstxtractor", abs_path], PYTHON_TOOL_TIMEOUT_SECONDS, cwd=temp.name)
        if proc is None:
            return ""

        base = os.path.basename(abs_path)
        extracted_dir = os.path.join(temp.name, base + "_extracted")
        if not os.path.isdir(extracted_dir):
            logger.warning("[unpack_python_node] pyinstxtractor output folder not found: %s", extracted_dir)
            return ""

        pyc_path = _find_main_pyc(extracted_dir, os.path.splitext(base)[0], proc.stdout)
        if pyc_path is None:
            logger.warning("[unpack_python_node] main .pyc file not found")
            return ""
        return _decompile_pyc(pyc_path)
    except Exception as exc:  # noqa: BLE001 - the workflow must never crash
        logger.warning("[unpack_python_node] unexpected error: %s: %s", type(exc).__name__, exc)
        return ""
    finally:
        temp.cleanup()


def _extract_dotnet_source(file_path: str) -> str:
    """Cleans with de4dot and produces C# source with ilspycmd; ``""`` on failure."""
    clean_path = file_path + CLEAN_SUFFIX
    try:
        if os.path.exists(clean_path):
            os.remove(clean_path)  # leftover output from a previous run

        # de4dot is best effort: if it is missing, fails or writes nothing, decompile the original
        # assembly. Obfuscated C# is still far better input than Ghidra disassembling MSIL as x86.
        target = file_path
        if _run_tool(["de4dot", file_path, "-o", clean_path], DOTNET_TOOL_TIMEOUT_SECONDS) is None:
            logger.warning("[unpack_dotnet_node] de4dot unavailable/failed; decompiling original assembly")
        elif not os.path.isfile(clean_path):
            logger.warning("[unpack_dotnet_node] de4dot did not produce an output file; using original")
        else:
            target = clean_path

        # Note: ``-p`` (project mode) requires ``-o <folder>``; stdout mode emits a single C# file.
        proc = _run_tool(["ilspycmd", target], DOTNET_DECOMPILE_TIMEOUT_SECONDS)
        return proc.stdout if proc is not None and proc.stdout.strip() else ""
    except Exception as exc:  # noqa: BLE001 - the workflow must never crash
        logger.warning("[unpack_dotnet_node] unexpected error: %s: %s", type(exc).__name__, exc)
        return ""
    finally:
        # Do not leave artifacts next to the original sample (not needed since file_path is unchanged)
        try:
            if os.path.exists(clean_path):
                os.remove(clean_path)
        except OSError:
            pass


def _run_upx_unpack(src: str, dst: str) -> bool:
    """Runs ``upx -d -o <dst> <src>``; returns ``True`` on success. Never raises on error."""
    try:
        # UPX refuses to overwrite an existing output file; clean up leftovers from a previous run
        if os.path.exists(dst):
            os.remove(dst)

        proc = subprocess.run(
            ["upx", "-d", "-o", dst, src],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=UPX_TIMEOUT_SECONDS,
            check=False,
        )
        if proc.returncode == 0 and os.path.isfile(dst):
            return True
        stderr = (proc.stderr.strip() or proc.stdout.strip() or "no output")[-300:]
        msg = f"upx exited with code {proc.returncode} (or the output file is missing): {stderr}"
    except subprocess.TimeoutExpired:
        msg = f"upx did not finish within {UPX_TIMEOUT_SECONDS} seconds (timeout)"
    except FileNotFoundError as exc:
        msg = f"upx not found: {exc}"
    except Exception as exc:  # noqa: BLE001 - the workflow must never crash
        msg = f"unexpected error while running upx: {type(exc).__name__}: {exc}"

    logger.warning("[unpack_native_node] %s; continuing with the original file", msg)
    # Do not leave a partial output behind
    try:
        if os.path.exists(dst):
            os.remove(dst)
    except OSError:
        pass
    return False
