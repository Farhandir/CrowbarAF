"""Data contract of the LLM layer (pipeline <-> LLM).

These types are the LLM-layer counterparts of the `functions` and `findings`
structures produced by the CrowbarAF pipeline.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Finding:
    """A deterministic tool finding (capa, floss, import, ioc...)."""
    source: str                 # capa | floss | import | ioc | yara | entropy
    kind: str                   # capability | string | import_combo | ioc | ...
    value: str
    address: str | None = None
    confidence: float = 1.0
    finding_id: str = ""        # nodes.finding_id (md5[:8]); if empty the verdict produces its own id
    verified: bool = True       # False: text IoC was not found in the binary (not reliable as evidence)


@dataclass
class FunctionInfo:
    """Function from Ghidra (the LLM's main input)."""
    offset: str
    name: str = ""
    c_code: str = ""
    priority: int = 0
    size: int = 0
    is_library: bool = False
    callees: list[str] = field(default_factory=list)
    xrefs: list[str] = field(default_factory=list)
    decompile_warnings: list[str] = field(default_factory=list)
    # Ghidra string xref mapping: IoC values this function uses via string references
    iocs: list[str] = field(default_factory=list)


@dataclass
class Claim:
    """An LLM claim + its evidence."""
    text: str
    evidence: str = ""
    # verified_claim | verified_observation | unverified
    status: str = "unverified"


@dataclass
class FunctionSummary:
    """Fixed-schema summary for one function (a 'note' carried upward)."""
    offset: str
    summary: str = ""
    suspicious: bool | None = None
    confidence: str = "low"            # low | medium | high
    behaviors: list[str] = field(default_factory=list)
    claims: list[Claim] = field(default_factory=list)
    suggested_name: str = ""
    fail_closed: bool = False  # LLM said benign, but a critical finding overrode it

    def note(self) -> str:
        """Short note to carry up to the parent function (fixed and narrow)."""
        flag = "SUSPICIOUS" if self.suspicious else "benign"
        return f"[{self.name_or_offset()}] {flag}: {self.summary}"[:300]

    def name_or_offset(self) -> str:
        return self.suggested_name or self.offset
