"""LangGraph düğümleri arasında taşınan ortak durum (State) tanımı."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

RouteFlag = Literal["python", "dotnet", "native", "fast_track"]


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

    # Decompile edilmiş kod: {"<kaynak>/<fonksiyon veya dosya>": "<kod>"}
    # Kaynaklar: ghidra, ilspy, pycdc
    source_code: dict[str, str] = Field(default_factory=dict)

    # AI ajanlarının ürettiği ara çıktılar
    iocs: dict[str, list[str]] = Field(default_factory=dict)  # ai_extractor_agent
    intent_analysis: str = ""  # ai_reverser_agent

    # Nihai sentez raporu (JSON / Markdown)
    analysis_report: str = ""

    # Yönlendirme bayrağı; entry_node tarafından belirlenir
    route_flag: RouteFlag | None = None
