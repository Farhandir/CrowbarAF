"""Evidence verifier: binds LLM claims to **function-local** code/findings.

Principle (precision-first): "verified" must never be wrong. If unsure,
say "unverified".

Four evidence classes:
  verified_observation  : the claim's evidence is a verbatim quote from THIS function's code
  verified_claim        : the evidence overlaps with a deterministic finding LOCAL to THIS
                          function (the finding address matches the function OR the
                          finding value appears in the function's code)
  file_level            : the evidence exists in the FILE but cannot be attributed to this
                          function (function attribution unclear)
  unverified            : no basis at all -> yellow warning ("not sure")
"""
from __future__ import annotations

import re

from .context import looks_like_instruction
from .types import Claim, Finding


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", (s or "").strip().lower())


def verify_claim(claim: Claim, code: str, findings: list[Finding],
                 function_offset: str | None = None) -> str:
    ev = _norm(claim.evidence)
    code_n = _norm(code)

    # 1) is the evidence a verbatim quote from this function's code?
    if len(ev) >= 4 and ev in code_n:
        return "verified_observation"

    if not ev:
        return "unverified"

    # Instruction-like text is sample data, never a verified claim.
    if looks_like_instruction(claim.text) or looks_like_instruction(claim.evidence):
        return "unverified"

    # 2) does the evidence overlap a finding? If local -> verified_claim, else file_level.
    global_match = False
    for f in findings:
        val = _norm(f.value)
        if not val or not (val in ev or ev in val):
            continue
        addr_local = (
            bool(function_offset) and bool(f.address)
            and _norm(str(f.address)) == _norm(str(function_offset))
        )
        token_local = val in code_n  # the finding value appears in this function's code
        if addr_local or token_local:
            return "verified_claim"
        global_match = True  # present in the file but could not be linked to this function

    return "file_level" if global_match else "unverified"


def verify_claims(claims: list[Claim], code: str, findings: list[Finding],
                   function_offset: str | None = None) -> list[Claim]:
    for c in claims:
        c.status = verify_claim(c, code, findings, function_offset)
    return claims
