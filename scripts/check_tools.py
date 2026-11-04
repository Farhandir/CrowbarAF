#!/usr/bin/env python3
"""Check Python packages and external analysis tools used by CrowbarAF.

No network and no API key are needed. Required Python packages make the script
exit non-zero; optional tools only warn unless ``--strict`` is used.

    python scripts/check_tools.py
    python scripts/check_tools.py --strict   # CI / smoke-test gate
"""
from __future__ import annotations

import argparse
import importlib.util
import os
import shutil
import sys
from pathlib import Path

# (module name, label, required?)
PYTHON_PACKAGES = (
    ("fastapi", "FastAPI UI/API", True),
    ("uvicorn", "Uvicorn server", True),
    ("pydantic", "Pydantic state models", True),
    ("langgraph", "LangGraph pipeline", True),
    ("langchain_ollama", "Ollama client", True),
    ("pefile", "PE parsing", True),
    ("multipart", "FastAPI multipart upload", True),
    ("httpx", "FastAPI TestClient", False),
    ("pytest", "tests", False),
    ("yara", "YARA Python bindings", False),
    ("tlsh", "TLSH fuzzy hash", False),
    ("pyghidra", "Ghidra Python bridge", False),
)

# (binary, label, required for full analysis?)
BINARIES = (
    ("analyzeHeadless", "Ghidra headless", True),
    ("capa", "capa", False),
    ("floss", "FLOSS", False),
    ("upx", "UPX unpacker", False),
    ("readelf", "binutils readelf (ELF imports/entropy)", True),
    ("java", "Java runtime (Ghidra)", True),
    ("yara", "YARA CLI (optional; yara-python is enough)", False),
    ("diec", "Detect It Easy", False),
    ("pycdc", "PyInstaller .pyc decompiler", False),
    ("pyinstxtractor", "PyInstaller extractor", False),
)


def _has_module(name: str) -> bool:
    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, ValueError):
        return False


def _which_with_ghidra(binary: str) -> str | None:
    found = shutil.which(binary)
    if found:
        return found
    if binary == "analyzeHeadless":
        ghidra = os.environ.get("GHIDRA_INSTALL_DIR", "").strip()
        if ghidra:
            candidate = Path(ghidra) / "support" / "analyzeHeadless"
            if candidate.is_file():
                return str(candidate)
    return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check CrowbarAF dependencies")
    parser.add_argument("--strict", action="store_true",
                        help="fail if any optional tool is missing (smoke-test gate)")
    args = parser.parse_args(argv)

    missing_required: list[str] = []
    missing_optional: list[str] = []

    print("Python packages")
    for module, label, required in PYTHON_PACKAGES:
        ok = _has_module(module)
        status = "OK" if ok else ("MISSING (required)" if required else "missing (optional)")
        print(f"  [{status:20}] {module:20} {label}")
        if not ok:
            (missing_required if required else missing_optional).append(module)

    print("\nExternal tools")
    for binary, label, required in BINARIES:
        found = _which_with_ghidra(binary)
        status = "OK" if found else ("MISSING (required)" if required else "missing (optional)")
        print(f"  [{status:20}] {binary:18} {label}" + (f" -> {found}" if found else ""))
        if not found:
            (missing_required if required else missing_optional).append(binary)

    ghidra = os.environ.get("GHIDRA_INSTALL_DIR", "").strip()
    print("\nEnvironment")
    print(f"  GHIDRA_INSTALL_DIR: {ghidra or '(not set)'}")
    print(f"  CROWBAR_TOOL_PROFILE: {os.environ.get('CROWBAR_TOOL_PROFILE', 'deep (default)')}")

    if missing_required:
        print("\nRequired missing: " + ", ".join(missing_required), file=sys.stderr)
        print("  pip install -r requirements.txt", file=sys.stderr)
        print("  Ghidra/JDK/readelf/UPX installation: docs/SETUP.md", file=sys.stderr)
    if missing_optional:
        print("\nOptional missing: " + ", ".join(missing_optional))
        print("  pip install -r requirements-tools.txt (analysis tools)")
        print("  Ghidra PyGhidra wheel: docs/SETUP.md §2")

    if missing_required or (args.strict and missing_optional):
        return 1
    print("\nRequired Python packages and core tools are present.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
