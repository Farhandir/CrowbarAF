"""Token tahmini ve butce yardimcilari.

Gercek tokenizer modelden modele degisir; burada muhafazakar bir tahmin
(karakter/4) kullaniyoruz. Gercek degeri Ollama/OpenAI yanitindaki
prompt_tokens ile kalibre edebiliriz.
"""
from __future__ import annotations

CHARS_PER_TOKEN = 4


def estimate_tokens(text: str) -> int:
    if not text:
        return 0
    return max(1, (len(text) + CHARS_PER_TOKEN - 1) // CHARS_PER_TOKEN)


def truncate_to_tokens(text: str, max_tokens: int, marker: str = "\n/* ... kisaltildi ... */\n") -> str:
    """Basi ve sonu koruyarak kirpar (sinyal genelde iki ucta olur)."""
    if max_tokens <= 0:
        return ""
    max_chars = max_tokens * CHARS_PER_TOKEN
    if len(text) <= max_chars:
        return text
    keep = max(0, max_chars - len(marker))
    head = (keep * 2) // 3
    tail = keep - head
    return text[:head] + marker + (text[-tail:] if tail else "")
