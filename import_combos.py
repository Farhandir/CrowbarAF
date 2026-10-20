"""Şüpheli import kombinasyonu kuralları (nodes.py ve ghidra_runner.py ortak kullanır)."""

from __future__ import annotations

# Kural adı -> gerekli API grupları (her grup için en az bir alternatif bulunmalı; küçük harf)
IMPORT_COMBO_RULES: dict[str, list[tuple[str, ...]]] = {
    "Process Injection Combo": [
        ("virtualalloc", "virtualallocex"),
        ("writeprocessmemory",),
        ("createremotethread", "createremotethreadex"),
    ],
}


def combo_api_map() -> dict[str, list[str]]:
    """Kural adı -> kombonun içerdiği tüm API isimleri (küçük harf, düz liste).

    Ghidra betiği, ``import_combo`` bulgusunu fonksiyonların çağırdığı API'lerle
    eşleştirmek için bu haritayı kullanır.
    """
    return {rule: [api for group in groups for api in group] for rule, groups in IMPORT_COMBO_RULES.items()}
