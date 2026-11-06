"""Common state (State) definition carried between LangGraph nodes."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

RouteFlag = Literal["python", "dotnet", "native", "fast_track"]


class DecompiledFunction(BaseModel):
    """Function-level decompile output from Ghidra and its LLM analysis."""

    offset: str = Field(
        ...,
        description='Entry Point address of the function (not the hint address), e.g. "0x1000".',
    )
    size: int = Field(
        default=0,
        description="Size of the function in bytes.",
    )
    is_library: bool = Field(
        default=False,
        description="Ghidra thunk/library function flag.",
    )
    callees: list[str] = Field(
        default_factory=list,
        description='Entry Point addresses of functions called by this function, e.g. ["0x1000"].',
    )
    xrefs: list[str] = Field(
        default_factory=list,
        description="Addresses referencing this function (call sites).",
    )
    decompile_warnings: list[str] = Field(
        default_factory=list,
        description="Warnings that reduce decompile confidence.",
    )
    name: str = Field(
        default="FUN_1000",
        description="Function name/symbol.",
    )
    priority: int = Field(
        default=0,
        description="Ghidra priority score. Functions with a capa match get +5 points.",
    )
    c_code: str = Field(
        default="",
        description="Pseudo-C code produced by Ghidra analyzeHeadless.",
    )
    capa_hits: list[str] = Field(
        default_factory=list,
        description="Names of Capa rules matching in this specific function.",
    )
    iocs: list[str] = Field(
        default_factory=list,
        description="IoC values used by this function via string references (Ghidra string->function mapping).",
    )
    llm_summary: str = Field(
        default="",
        description="Analysis summary produced by the Reverser Agent for this function.",
    )


class SampleInfo(BaseModel):
    """Identity of the analyzed sample and the pre-scan (entry_node) summary."""

    sha256: str = Field(default="", description="SHA-256 digest of the file (hex).")
    file_type: str = Field(default="unknown", description="PE | ELF | Mach-O | ...")
    route: str = Field(
        default="native",
        description="python | dotnet | native | fast_track (same value as route_flag).",
    )
    packer: str = Field(default="unknown", description='UPX | none | ... ("unknown": detection failed).')
    arch: str = Field(default="unknown", description="x86 | x86-64 | arm64 | ...")


class Finding(BaseModel):
    """A deterministic tool finding (evidence source for the LLM layer)."""

    source: str = Field(
        ...,
        description='Source that produced the finding: "yara", "floss", "capa", "pefile_entropy", "import_combo"...',
    )
    kind: str = Field(
        ...,
        description='Finding type: "rule", "ip", "url", "high_entropy", "behavior"...',
    )
    value: str = Field(
        ...,
        description="Matched rule name, IP address, API combo, etc.",
    )
    address: str = Field(
        default="",
        description='Memory address if any (e.g. "0x401000"); empty otherwise.',
    )
    confidence: float = Field(
        default=1.0,
        ge=0.0,
        le=1.0,
        description="Confidence between 0 and 1; 1.0 for deterministic tools.",
    )
    finding_id: str = Field(
        default="",
        description="Deterministic ID of the finding: md5(source_kind_value_address)[:8] "
                    "(set by static_feature_node).",
    )
    verified: bool = Field(
        default=True,
        description="Does the finding really exist in the binary? False if a statically extracted text IoC "
                    "(ip/url/domain/email) cannot be found in the file bytes (UTF-8/UTF-16LE); "
                    "types that cannot be checked stay True.",
    )


class AgentState(BaseModel):
    """State object flowing through the entire analysis pipeline.

    Nodes return a ``dict`` containing only the fields they want to update,
    not the whole object (LangGraph merges them).
    """

    # Input
    file_path: str

    # entry_node output: sha256, file type, architecture, packer, route
    sample: SampleInfo = Field(default_factory=SampleInfo)

    # YARA rule matches, e.g. {"rule": "...", "tags": [...], "meta": {...}}
    yara_results: list[dict[str, Any]] = Field(default_factory=list)

    # FLOSS outputs (static / stack / tight / decoded strings)
    extracted_strings: list[str] = Field(default_factory=list)

    # capa outputs: MITRE ATT&CK tactics and function offsets
    capabilities: dict[str, Any] = Field(default_factory=dict)

    # All deterministic findings (yara, capa, floss, entropy, import combo).
    # The LLM layer reads evidence directly from here.
    findings: list[Finding] = Field(default_factory=list)

    # Capa -> Ghidra target addresses,
    # e.g. [{"offset": "0x1000", "rule": "encrypt data using AES"}]
    ghidra_hints: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Target addresses the Capa node passes to Ghidra for decompilation.",
    )

    floss_hints: list[dict[str, Any]] = Field(
        default_factory=list,
        description="FLOSS decoded/tight string -> function/address metadata (for Ghidra xref).",
    )

    # Decompiled functions (Ghidra; function-level Pseudo-C + LLM summary)
    source_code: list[DecompiledFunction] = Field(
        default_factory=list,
        description="Function-level decompile outputs.",
    )

    # Intermediate outputs produced by the AI agents
    iocs: dict[str, list[str]] = Field(default_factory=dict)  # ai_extractor_agent
    intent_analysis: str = ""  # ai_reverser_agent
    verdict: dict[str, Any] = Field(
        default_factory=dict,
        description="Deterministic file-level verdict (malicious/needs_review/unknown/no_evidence).",
    )

    # Final synthesis report (JSON / Markdown)
    analysis_report: str = ""

    # Routing flag; set by entry_node
    route_flag: RouteFlag | None = None
