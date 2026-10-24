"""LLM katmaninin veri sozlesmesi (pipeline <-> LLM).

Bu tipler, CrowbarAF pipeline'inin urettigi `functions` ve `findings`
yapisinin LLM katmanindaki karsiligidir.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Finding:
    """Deterministik bir arac bulgusu (capa, floss, import, ioc...)."""
    source: str                 # capa | floss | import | ioc | yara | entropy
    kind: str                   # capability | string | import_combo | ioc | ...
    value: str
    address: str | None = None
    confidence: float = 1.0


@dataclass
class FunctionInfo:
    """Ghidra'dan gelen fonksiyon (LLM'in asil girdisi)."""
    offset: str
    name: str = ""
    c_code: str = ""
    priority: int = 0
    size: int = 0
    is_library: bool = False
    callees: list[str] = field(default_factory=list)
    xrefs: list[str] = field(default_factory=list)
    decompile_warnings: list[str] = field(default_factory=list)


@dataclass
class Claim:
    """LLM'in bir iddiasi + kaniti."""
    text: str
    evidence: str = ""
    # verified_claim | verified_observation | unverified
    status: str = "unverified"


@dataclass
class FunctionSummary:
    """Bir fonksiyon icin sabit semali ozet (yukari tasinan 'not')."""
    offset: str
    summary: str = ""
    suspicious: bool | None = None
    confidence: str = "low"            # low | medium | high
    behaviors: list[str] = field(default_factory=list)
    claims: list[Claim] = field(default_factory=list)
    suggested_name: str = ""

    def note(self) -> str:
        """Ust fonksiyona tasinacak kisa not (sabit ve dar)."""
        flag = "SUSPICIOUS" if self.suspicious else "benign"
        return f"[{self.name_or_offset()}] {flag}: {self.summary}"[:300]

    def name_or_offset(self) -> str:
        return self.suggested_name or self.offset
