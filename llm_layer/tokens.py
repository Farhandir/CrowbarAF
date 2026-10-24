"""Token tahmini ve butce yardimcilari.

Gercek tokenizer modelden modele degisir. Burada:
  * varsayilan: karakter/4 tahmini
  * `TokenCounter.calibrate`: Ollama/OpenAI yanitindaki gercek prompt token
    sayisiyla orani gunceller (EMA). Boylece butce olcumu modele gore kalibre olur.
"""
from __future__ import annotations

CHARS_PER_TOKEN = 4.0


class TokenCounter:
    def __init__(self, chars_per_token: float = CHARS_PER_TOKEN) -> None:
        self.chars_per_token = float(chars_per_token)
        self.samples = 0

    def estimate(self, text: str) -> int:
        if not text:
            return 0
        return max(1, int(len(text) / self.chars_per_token + 0.999))

    def calibrate(self, text: str, actual_tokens: int) -> None:
        """Gercek token sayisiyla orani gunceller (usul usul, EMA)."""
        if not text or not actual_tokens:
            return
        ratio = len(text) / float(actual_tokens)
        if ratio <= 0:
            return
        self.samples += 1
        if self.samples == 1:
            self.chars_per_token = ratio
        else:
            self.chars_per_token = 0.7 * self.chars_per_token + 0.3 * ratio

    def to_dict(self) -> dict:
        return {"chars_per_token": round(self.chars_per_token, 4), "samples": self.samples}


DEFAULT_COUNTER = TokenCounter()


def estimate_tokens(text: str) -> int:
    return DEFAULT_COUNTER.estimate(text)


def truncate_to_tokens(text: str, max_tokens: int, marker: str = "\n/* ... kisaltildi ... */\n") -> str:
    """Basi ve sonu koruyarak kirpar (sinyal genelde iki ucta olur)."""
    if max_tokens <= 0:
        return ""
    max_chars = int(max_tokens * DEFAULT_COUNTER.chars_per_token)
    if len(text) <= max_chars:
        return text
    keep = max(0, max_chars - len(marker))
    head = (keep * 2) // 3
    tail = keep - head
    return text[:head] + marker + (text[-tail:] if tail else "")
