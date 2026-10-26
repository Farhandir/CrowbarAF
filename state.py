"""LangGraph düğümleri arasında taşınan ortak durum (State) tanımı."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

RouteFlag = Literal["python", "dotnet", "native", "fast_track"]


class DecompiledFunction(BaseModel):
    """Ghidra'dan çıkan fonksiyon bazlı decompile çıktısı ve LLM analizi."""

    offset: str = Field(
        ...,
        description='Fonksiyonun Entry Point adresi (hint adresi değil), örn: "0x1000".',
    )
    size: int = Field(
        default=0,
        description="Fonksiyonun bayt cinsinden boyutu.",
    )
    is_library: bool = Field(
        default=False,
        description="Ghidra thunk/kütüphane fonksiyonu bayrağı.",
    )
    callees: list[str] = Field(
        default_factory=list,
        description='Bu fonksiyonun çağırdığı fonksiyonların Entry Point adresleri, örn: ["0x1000"].',
    )
    xrefs: list[str] = Field(
        default_factory=list,
        description="Bu fonksiyona referans veren adresler (çağrı yerleri).",
    )
    decompile_warnings: list[str] = Field(
        default_factory=list,
        description="Decompile güvenini düşüren uyarılar.",
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
    iocs: list[str] = Field(
        default_factory=list,
        description="Bu fonksiyonun string referansıyla kullandığı IoC değerleri (Ghidra string->fonksiyon eşlemesi).",
    )
    llm_summary: str = Field(
        default="",
        description="Reverser Agent'ın bu fonksiyon için ürettiği analiz özeti.",
    )


class SampleInfo(BaseModel):
    """Analiz edilen örneğin kimliği ve ön tarama (entry_node) özeti."""

    sha256: str = Field(default="", description="Dosyanın SHA-256 özeti (hex).")
    file_type: str = Field(default="unknown", description="PE | ELF | Mach-O | ...")
    route: str = Field(
        default="native",
        description="python | dotnet | native | fast_track (route_flag ile aynı değer).",
    )
    packer: str = Field(default="unknown", description='UPX | none | ... ("unknown": tespit yapılamadı).')
    arch: str = Field(default="unknown", description="x86 | x86-64 | arm64 | ...")


class Finding(BaseModel):
    """Deterministik bir araç bulgusu (LLM katmanının kanıt kaynağı)."""

    source: str = Field(
        ...,
        description='Bulguyu üreten kaynak: "yara", "floss", "capa", "pefile_entropy", "import_combo"...',
    )
    kind: str = Field(
        ...,
        description='Bulgu türü: "rule", "ip", "url", "high_entropy", "behavior"...',
    )
    value: str = Field(
        ...,
        description="Eşleşen kural adı, IP adresi, API kombosu vb.",
    )
    address: str = Field(
        default="",
        description='Varsa bellek adresi (örn. "0x401000"); yoksa boş.',
    )
    confidence: float = Field(
        default=1.0,
        ge=0.0,
        le=1.0,
        description="0-1 arası güven; deterministik araçlar için 1.0.",
    )


class AgentState(BaseModel):
    """Tüm analiz hattı boyunca akan durum nesnesi.

    Düğümler bu nesnenin tamamını değil, sadece güncellemek istedikleri
    alanları içeren bir ``dict`` döndürür (LangGraph bunları birleştirir).
    """

    # Girdi
    file_path: str

    # entry_node çıktısı: sha256, dosya türü, mimari, paketleyici, rota
    sample: SampleInfo = Field(default_factory=SampleInfo)

    # YARA kural eşleşmeleri, ör. {"rule": "...", "tags": [...], "meta": {...}}
    yara_results: list[dict[str, Any]] = Field(default_factory=list)

    # FLOSS çıktıları (static / stack / tight / decoded stringler)
    extracted_strings: list[str] = Field(default_factory=list)

    # capa çıktıları: MITRE ATT&CK taktikleri ve fonksiyon offset'leri
    capabilities: dict[str, Any] = Field(default_factory=dict)

    # Tüm deterministik bulgular (yara, capa, floss, entropy, import combo).
    # LLM katmanı kanıtı doğrudan buradan okur.
    findings: list[Finding] = Field(default_factory=list)

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
    verdict: dict[str, Any] = Field(
        default_factory=dict,
        description="Deterministic file-level verdict (malicious/needs_review/unknown/no_evidence).",
    )

    # Nihai sentez raporu (JSON / Markdown)
    analysis_report: str = ""

    # Yönlendirme bayrağı; entry_node tarafından belirlenir
    route_flag: RouteFlag | None = None
