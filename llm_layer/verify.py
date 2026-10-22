"""Kanit dogrulayici: LLM iddialarini **fonksiyon-yerel** koda/bulgulara baglar.

Ilke (precision-first): "✅ dogrulandi" asla yanlis olmamali. Emin degilse
"unverified" (⚠️) denir.

Dort kanit sinifi:
  verified_observation  : iddianin kaniti, BU fonksiyonun kodundan birebir alinti
  verified_claim        : kanit, BU fonksiyona YEREL bir deterministik bulguyla ortusuyor
                          (bulgu adresi fonksiyonla esliyor VEYA bulgu degeri
                           fonksiyonun kodunda geciyor)
  file_level            : kanit DOSYADA var ama bu fonksiyona atfedilemiyor
                          (fonksiyon atfi belirsiz)
  unverified            : hicbir dayanak yok -> sari uyari ("emin degilim")
"""
from __future__ import annotations

import re

from .types import Claim, Finding


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", (s or "").strip().lower())


def verify_claim(claim: Claim, code: str, findings: list[Finding],
                 function_offset: str | None = None) -> str:
    ev = _norm(claim.evidence)
    code_n = _norm(code)

    # 1) kanit, bu fonksiyonun kodundan birebir alinti mi?
    if len(ev) >= 4 and ev in code_n:
        return "verified_observation"

    if not ev:
        return "unverified"

    # 2) kanit bir bulguyla ortusuyor mu? Yerel ise verified_claim, degilse file_level.
    global_match = False
    for f in findings:
        val = _norm(f.value)
        if not val or not (val in ev or ev in val):
            continue
        addr_local = (
            bool(function_offset) and bool(f.address)
            and _norm(str(f.address)) == _norm(str(function_offset))
        )
        token_local = val in code_n  # bulgunun degeri bu fonksiyonun kodunda geciyor
        if addr_local or token_local:
            return "verified_claim"
        global_match = True  # dosyada var ama bu fonksiyona baglanamadi

    return "file_level" if global_match else "unverified"


def verify_claims(claims: list[Claim], code: str, findings: list[Finding],
                   function_offset: str | None = None) -> list[Claim]:
    for c in claims:
        c.status = verify_claim(c, code, findings, function_offset)
    return claims
