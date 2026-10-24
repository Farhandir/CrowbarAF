"""Fonksiyon ozeti onbellegi (memoization).

Ayni fonksiyon (normalize edilmis kod + isim) tekrar analiz edilirse LLM cagrisi
yapilmaz. Anahtar: sha256(kod + isim); adres kasitli olarak disarida (adresler
analizden analize degisebilir).
"""
from __future__ import annotations

import hashlib
import json
import os

from .types import Claim, FunctionSummary, FunctionInfo


class SummaryCache:
    def __init__(self, path: str | None = None) -> None:
        self.path = path
        self.data: dict[str, dict] = {}
        if path and os.path.isfile(path):
            try:
                with open(path, encoding="utf-8") as fh:
                    self.data = json.load(fh)
            except Exception:  # noqa: BLE001 - bozuk onbellek akisi cokertmesin
                self.data = {}

    @staticmethod
    def key(fn: FunctionInfo) -> str:
        h = hashlib.sha256()
        h.update((fn.name or "").encode("utf-8"))
        h.update(b"\x00")
        h.update((fn.c_code or "").encode("utf-8"))
        return h.hexdigest()

    def get(self, fn: FunctionInfo) -> FunctionSummary | None:
        rec = self.data.get(self.key(fn))
        if not rec:
            return None
        return FunctionSummary(
            offset=fn.offset,
            summary=rec.get("summary", ""),
            suspicious=rec.get("suspicious"),
            confidence=rec.get("confidence", "dusuk"),
            behaviors=list(rec.get("behaviors", [])),
            claims=[Claim(text=c.get("text", ""), evidence=c.get("evidence", ""), status=c.get("status", "unverified"))
                    for c in rec.get("claims", [])],
            suggested_name=rec.get("suggested_name", ""),
        )

    def put(self, fn: FunctionInfo, s: FunctionSummary) -> None:
        self.data[self.key(fn)] = {
            "summary": s.summary, "suspicious": s.suspicious, "confidence": s.confidence,
            "behaviors": s.behaviors, "suggested_name": s.suggested_name,
            "claims": [{"text": c.text, "evidence": c.evidence, "status": c.status} for c in s.claims],
        }

    def save(self) -> None:
        if not self.path:
            return
        os.makedirs(os.path.dirname(os.path.abspath(self.path)), exist_ok=True)
        with open(self.path, "w", encoding="utf-8") as fh:
            json.dump(self.data, fh, ensure_ascii=False)
