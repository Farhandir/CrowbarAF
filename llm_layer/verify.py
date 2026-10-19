"""Kanit dogrulayici: LLM iddialarini koda/bulgulara baglar.

Uc kanit sinifi:
  verified_claim        : iddia, deterministik bir bulguyla ortusuyor
  verified_observation  : iddianin kaniti koddan birebir alinti
  unverified            : hicbiri -> sari uyari (uydurma olabilir)
"""
from __future__ import annotations

import re

from .types import Claim, Finding


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", (s or "").strip().lower())


def verify_claim(claim: Claim, code: str, findings: list[Finding]) -> str:
    ev = _norm(claim.evidence)
    code_n = _norm(code)

    # 1) kodda birebir alinti mi?
    if len(ev) >= 4 and ev in code_n:
        return "verified_observation"

    # 2) deterministik bir bulguyla ortusuyor mu?
    if ev:
        for f in findings:
            val = _norm(f.value)
            if val and (val in ev or ev in val):
                return "verified_claim"
    return "unverified"


def verify_claims(claims: list[Claim], code: str, findings: list[Finding]) -> list[Claim]:
    for c in claims:
        c.status = verify_claim(c, code, findings)
    return claims
