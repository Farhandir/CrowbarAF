"""Suspicious import combination rules (shared by nodes.py and ghidra_runner.py)."""

from __future__ import annotations

# Rule name -> required API groups (at least one alternative must be present per group; lowercase)
IMPORT_COMBO_RULES: dict[str, list[tuple[str, ...]]] = {
    "Process Injection Combo": [
        ("virtualalloc", "virtualallocex"),
        ("writeprocessmemory",),
        ("createremotethread", "createremotethreadex"),
    ],
    # --- ELF / Linux (readelf --dyn-syms UND symbols; matching is lowercase) ---
    # Note: legitimate tools such as strace/gdb also import this combination; it is not conclusive evidence on its own.
    "Linux Process Injection": [
        ("ptrace",),
        ("waitpid", "wait4"),
        ("execve", "execv", "execvp", "execvpe", "fexecve"),
    ],
    # Note: dlsym+mmap+mprotect is also common in legitimate software that loads JIT/plugins (low confidence).
    "Linux Evasion": [
        ("mprotect",),
        ("mmap", "mmap64"),
        ("dlsym",),
    ],
}


def combo_api_map() -> dict[str, list[str]]:
    """Rule name -> all API names in the combo (lowercase, flat list).

    The Ghidra script uses this map to match the ``import_combo`` finding against
    the APIs called by functions.
    """
    return {rule: [api for group in groups for api in group] for rule, groups in IMPORT_COMBO_RULES.items()}
