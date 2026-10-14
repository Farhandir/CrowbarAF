"""LangGraph düğümleri arasında taşınan ortak durum (State) tanımı."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

RouteFlag = Literal["python", "dotnet", "native", "fast_track"]


class DecompiledFunction(BaseModel):
    """Ghidra'dan çıkan fonksiyon bazlı decompile çıktısı ve LLM analizi."""

    offset: str = Field(
        ...,
        description='Fonksiyonun bellek/dosya adresi, örn: "0x1000".',
    )
    name: str = Field(
        default="FUN_1000",
        description="Fonksiyon adı/sembolü.",
    )
    priority: int = Field(
        default=0,
        description="Ghidra öncelik puanı. Capa eşleşmesi olan fonksiyonlar +5 puan alır.",
    )
    c_code: str = Field(
        default="",
        description="Ghidra analyzeHeadless tarafından çıkarılan Pseudo-C kodu.",
    )
    capa_hits: list[str] = Field(
        default_factory=list,
        description="Bu spesifik fonksiyonda eşleşen Capa kural isimleri.",
    )
    llm_summary: str = Field(
        default="",
        description="Reverser Agent'ın bu fonksiyon için ürettiği analiz özeti.",
    )


class AgentState(BaseModel):
    """Tüm analiz hattı boyunca akan durum nesnesi.

    Düğümler bu nesnenin tamamını değil, sadece güncellemek istedikleri
    alanları içeren bir ``dict`` döndürür (LangGraph bunları birleştirir).
    """

    # Girdi
    file_path: str

    # DIE çıktısı: dil, derleyici, mimari, paketleyici...
    file_metadata: dict[str, Any] = Field(default_factory=dict)

    # YARA kural eşleşmeleri, ör. {"rule": "...", "tags": [...], "meta": {...}}
    yara_results: list[dict[str, Any]] = Field(default_factory=list)

    # FLOSS çıktıları (static / stack / tight / decoded stringler)
    extracted_strings: list[str] = Field(default_factory=list)

    # capa çıktıları: MITRE ATT&CK taktikleri ve fonksiyon offset'leri
    capabilities: dict[str, Any] = Field(default_factory=dict)

    # Capa -> Ghidra hedef adresleri,
    # ör. [{"offset": "0x1000", "rule": "encrypt data using AES"}]
    ghidra_hints: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Capa düğümünün Ghidra'ya decompile için aktardığı hedef adresler.",
    )

    # Decompile edilmiş fonksiyonlar (Ghidra; fonksiyon bazlı Pseudo-C + LLM özeti)
    source_code: list[DecompiledFunction] = Field(
        default_factory=list,
        description="Fonksiyon bazlı decompile çıktıları.",
    )

    # AI ajanlarının ürettiği ara çıktılar
    iocs: dict[str, list[str]] = Field(default_factory=dict)  # ai_extractor_agent
    intent_analysis: str = ""  # ai_reverser_agent

    # Nihai sentez raporu (JSON / Markdown)
    analysis_report: str = ""

    # Yönlendirme bayrağı; entry_node tarafından belirlenir
    route_flag: RouteFlag | None = None
