"""SQLite kalıcılık katmanı: samples, findings, functions, calls, llm_claims.

Yardımcılar duck-typing ile çalışır (``SampleInfo``/``Finding``/``DecompiledFunction``
alanlarını okur); böylece bu modül ``state.py``'ye bağımlı değildir.

Yeniden analiz: aynı ``sha256`` için ``insert_*`` çağrıları o örneğin eski
satırlarını silip yenilerini yazar (çift kayıt oluşmaz).
"""

from __future__ import annotations

import json
import os
import sqlite3
from contextlib import closing
from typing import Any, Iterable

from utils import defang_finding, defang_iocs

# Varsayılan: çalışma dizininde "crowbaraf.db"; CROWBAR_DB_PATH ile değiştirilebilir.
DEFAULT_DB_PATH = os.environ.get("CROWBAR_DB_PATH", "crowbaraf.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS samples (
    sha256    TEXT PRIMARY KEY,
    file_type TEXT,
    route     TEXT,
    packer    TEXT,
    arch      TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    sha256     TEXT,
    source     TEXT,
    kind       TEXT,
    value      TEXT,
    address    TEXT,
    confidence REAL,
    finding_id TEXT,
    verified   BOOLEAN DEFAULT 1
);

CREATE TABLE IF NOT EXISTS functions (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    sha256             TEXT,
    offset             TEXT,
    name               TEXT,
    priority           INTEGER,
    c_code             TEXT,
    decompile_warnings TEXT,
    llm_summary        TEXT,
    size               INTEGER,
    is_library         BOOLEAN,
    capa_hits          TEXT,
    xrefs              TEXT,
    iocs               TEXT
);

CREATE TABLE IF NOT EXISTS calls (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    sha256        TEXT,
    caller_offset TEXT,
    callee_offset TEXT
);

CREATE TABLE IF NOT EXISTS llm_claims (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    sha256            TEXT,
    supervisor_report TEXT,
    verdict           TEXT
);

CREATE INDEX IF NOT EXISTS idx_findings_sha256   ON findings(sha256);
CREATE INDEX IF NOT EXISTS idx_functions_sha256  ON functions(sha256);
CREATE INDEX IF NOT EXISTS idx_calls_sha256      ON calls(sha256);
CREATE INDEX IF NOT EXISTS idx_llm_claims_sha256 ON llm_claims(sha256);
"""

# Eski veritabanlarını yükseltmek için: functions tablosuna sonradan eklenen sütunlar
FUNCTION_EXTRA_COLUMNS = (
    ("llm_summary", "TEXT"),
    ("size", "INTEGER"),
    ("is_library", "BOOLEAN"),
    ("capa_hits", "TEXT"),
    ("xrefs", "TEXT"),
    ("iocs", "TEXT"),
)

# llm_claims'e sonradan eklenen sütunlar (verdict: dosya düzeyi karar, JSON metni)
LLM_CLAIMS_EXTRA_COLUMNS = (("verdict", "TEXT"),)

# findings'e sonradan eklenen sütunlar: finding_id (kimlik), verified (binary'de var mı?).
# Eski satırlar DEFAULT 1 ile "doğrulanmış" sayılır (geriye uyumluluk).
FINDINGS_EXTRA_COLUMNS = (("finding_id", "TEXT"), ("verified", "BOOLEAN DEFAULT 1"))

# tablo -> sonradan eklenen sütunlar (eski veritabanı migrasyonu)
_MIGRATIONS = (
    ("functions", FUNCTION_EXTRA_COLUMNS),
    ("llm_claims", LLM_CLAIMS_EXTRA_COLUMNS),
    ("findings", FINDINGS_EXTRA_COLUMNS),
)


def _path(db_path: str | None) -> str:
    return db_path or DEFAULT_DB_PATH


def init_db(db_path: str | None = None) -> str:
    """Tabloları (yoksa) oluşturur ve kullanılan veritabanı yolunu döndürür.

    ``db_path`` verilmezse ``crowbaraf.db`` (veya ``CROWBAR_DB_PATH``) kullanılır.
    Şema değişikliğinden önce oluşturulmuş veritabanlarında eksik ``functions``
    sütunları ``ALTER TABLE`` ile eklenir.
    """
    path = _path(db_path)
    with closing(sqlite3.connect(path)) as conn, conn:
        conn.executescript(SCHEMA)
        # CREATE TABLE IF NOT EXISTS mevcut tabloya sütun eklemez: eski şemayı yükselt
        for table, columns in _MIGRATIONS:
            existing = {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
            for column, sql_type in columns:
                if column not in existing:
                    conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {sql_type}")
    return path


# --------------------------------------------------------------------------- #
# Yazma yardımcıları
# --------------------------------------------------------------------------- #
def insert_sample(sample: Any, db_path: str | None = None) -> None:
    """``samples`` tablosuna örneği yazar (aynı sha256 varsa günceller)."""
    with closing(sqlite3.connect(_path(db_path))) as conn, conn:
        conn.execute(
            "INSERT OR REPLACE INTO samples (sha256, file_type, route, packer, arch) VALUES (?, ?, ?, ?, ?)",
            (sample.sha256, sample.file_type, sample.route, sample.packer, sample.arch),
        )


def insert_findings(sha256: str, findings: Iterable[Any], db_path: str | None = None) -> int:
    """Örneğin bulgularını yazar (öncekileri siler). Yazılan satır sayısını döndürür."""
    rows = [
        (sha256, f.source, f.kind, f.value, f.address, f.confidence,
         getattr(f, "finding_id", "") or "", int(bool(getattr(f, "verified", True))))
        for f in findings
    ]
    with closing(sqlite3.connect(_path(db_path))) as conn, conn:
        conn.execute("DELETE FROM findings WHERE sha256 = ?", (sha256,))
        conn.executemany(
            "INSERT INTO findings (sha256, source, kind, value, address, confidence, finding_id, verified) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            rows,
        )
    return len(rows)


def insert_functions_and_calls(
    sha256: str, functions: Iterable[Any], db_path: str | None = None
) -> tuple[int, int]:
    """Fonksiyonları ``functions``, ``callees`` ilişkilerini ``calls`` tablosuna yazar.

    Önceki kayıtlar silinir. ``decompile_warnings``, ``capa_hits`` ve ``xrefs``
    JSON metni (``json.dumps``) olarak saklanır; ``is_library`` 0/1 yazılır.
    Aynı fonksiyondan aynı hedefe tekrarlayan çağrılar tek satıra indirilir.
    Dönüş: ``(yazılan_fonksiyon_sayısı, yazılan_çağrı_sayısı)``.
    """
    function_rows: list[tuple[Any, ...]] = []
    call_rows: list[tuple[str, str, str]] = []
    for fn in functions:
        function_rows.append(
            (
                sha256,
                fn.offset,
                fn.name,
                fn.priority,
                fn.c_code,
                json.dumps(list(fn.decompile_warnings), ensure_ascii=False),
                fn.llm_summary,
                fn.size,
                int(bool(fn.is_library)),
                json.dumps(list(fn.capa_hits), ensure_ascii=False),
                json.dumps(list(fn.xrefs), ensure_ascii=False),
                json.dumps(list(fn.iocs), ensure_ascii=False),
            )
        )
        for callee in dict.fromkeys(fn.callees):
            call_rows.append((sha256, fn.offset, callee))

    with closing(sqlite3.connect(_path(db_path))) as conn, conn:
        conn.execute("DELETE FROM functions WHERE sha256 = ?", (sha256,))
        conn.execute("DELETE FROM calls WHERE sha256 = ?", (sha256,))
        conn.executemany(
            "INSERT INTO functions (sha256, offset, name, priority, c_code, decompile_warnings, "
            "llm_summary, size, is_library, capa_hits, xrefs, iocs) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            function_rows,
        )
        conn.executemany(
            "INSERT INTO calls (sha256, caller_offset, callee_offset) VALUES (?, ?, ?)",
            call_rows,
        )
    return len(function_rows), len(call_rows)


def insert_llm_claims(
    sha256: str,
    report: str,
    db_path: str | None = None,
    verdict: dict[str, Any] | str | None = None,
) -> None:
    """Supervisor raporunu ve dosya kararını (``verdict``) ``llm_claims`` tablosuna yazar.

    Önceki kayıt silinir. ``verdict`` bir ``dict`` ise ``json.dumps`` ile JSON metnine çevrilir;
    ``None``/boş ise sütun ``NULL`` kalır. (Geriye uyumluluk: ``verdict`` isteğe bağlıdır.)
    """
    verdict_json = None
    if verdict:
        verdict_json = verdict if isinstance(verdict, str) else json.dumps(verdict, ensure_ascii=False)
    with closing(sqlite3.connect(_path(db_path))) as conn, conn:
        conn.execute("DELETE FROM llm_claims WHERE sha256 = ?", (sha256,))
        conn.execute(
            "INSERT INTO llm_claims (sha256, supervisor_report, verdict) VALUES (?, ?, ?)",
            (sha256, report, verdict_json),
        )


def save_analysis(state: Any, db_path: str | None = None) -> dict[str, Any]:
    """Bir ``AgentState``'in tüm sonuçlarını tek çağrıda kalıcı hale getirir.

    ``db_writer_node`` (tam hat) ve ``host_analyze.py --db`` (split mod) ortak kullanır:
    ``init_db`` -> ``insert_sample`` -> ``insert_findings`` -> ``insert_functions_and_calls``
    (``llm_summary`` dahil) -> ``insert_llm_claims`` (rapor ve/veya ``verdict`` varsa).

    ``state.sample.sha256`` boşsa ``ValueError`` fırlatır (anahtarsız satır yazılmaz).
    Hataları yutmaz; çağıran karar verir. Dönüş: yazılan satır sayıları + ``db_path``.
    """
    sha256 = state.sample.sha256
    if not sha256:
        raise ValueError("sample.sha256 boş; veritabanına yazılamaz")
    path = init_db(db_path)
    insert_sample(state.sample, path)
    n_findings = insert_findings(sha256, state.findings, path)
    n_functions, n_calls = insert_functions_and_calls(sha256, state.source_code, path)
    claims = bool(state.analysis_report or state.verdict)
    if claims:
        insert_llm_claims(sha256, state.analysis_report, path, verdict=state.verdict)
    return {"sha256": sha256, "db_path": path, "findings": n_findings,
            "functions": n_functions, "calls": n_calls, "llm_claims": claims}


# --------------------------------------------------------------------------- #
# Okuma yardımcıları (API/UI için)
# --------------------------------------------------------------------------- #
def _loads(text: str | None, default: Any) -> Any:
    try:
        return json.loads(text) if text else default
    except (TypeError, ValueError):
        return default


def _loads_dict(text: str | None) -> dict[str, Any]:
    """JSON metnini ``dict``'e çevirir; boş, bozuk veya dict olmayan değerde ``{}``."""
    value = _loads(text, {})
    return value if isinstance(value, dict) else {}


def _connect_ro(db_path: str | None) -> sqlite3.Connection:
    path = init_db(db_path)  # tablolar/sütunlar garanti olsun (boş veritabanında da çalışır)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn


def get_all_samples(db_path: str | None = None) -> list[dict[str, Any]]:
    """Analiz edilmiş tüm örnekler (en son yazılan önce) + bulgu/fonksiyon sayıları."""
    with closing(_connect_ro(db_path)) as conn:
        rows = conn.execute(
            """
            SELECT s.sha256, s.file_type, s.route, s.packer, s.arch,
                   (SELECT COUNT(*) FROM findings  f WHERE f.sha256 = s.sha256) AS findings_count,
                   (SELECT COUNT(*) FROM functions u WHERE u.sha256 = s.sha256) AS functions_count,
                   EXISTS(SELECT 1 FROM llm_claims c WHERE c.sha256 = s.sha256)  AS has_report,
                   (SELECT c.verdict FROM llm_claims c WHERE c.sha256 = s.sha256
                    ORDER BY c.id DESC LIMIT 1) AS verdict_json
            FROM samples s
            ORDER BY s.rowid DESC
            """
        ).fetchall()
    out = []
    for r in rows:
        item = dict(r)
        item["verdict"] = _loads_dict(item.pop("verdict_json"))
        item["has_report"] = bool(item["has_report"])
        out.append(item)
    return out


def get_sample_details(sha256: str, db_path: str | None = None) -> dict[str, Any] | None:
    """Bir örneğin bulguları, fonksiyonları (callees ile) ve supervisor raporu; yoksa ``None``."""
    with closing(_connect_ro(db_path)) as conn:
        sample = conn.execute(
            "SELECT sha256, file_type, route, packer, arch FROM samples WHERE sha256 = ?", (sha256,)
        ).fetchone()
        if sample is None:
            return None

        # Analist güvenliği: ağ IoC'leri (url/ip/domain/email) defang edilmiş döner;
        # veritabanında ham değer kalır (bkz. utils.defang_ioc).
        findings = []
        for r in conn.execute(
            "SELECT source, kind, value, address, confidence, finding_id, verified "
            "FROM findings WHERE sha256 = ? ORDER BY id",
            (sha256,),
        ):
            item = dict(r)
            item["finding_id"] = item["finding_id"] or ""
            # NULL (eski satır / migrasyon öncesi) = doğrulanmış; yalnızca açık 0 "False"
            item["verified"] = item["verified"] is None or bool(item["verified"])
            findings.append(defang_finding(item))

        callees: dict[str, list[str]] = {}
        for r in conn.execute(
            "SELECT caller_offset, callee_offset FROM calls WHERE sha256 = ? ORDER BY id", (sha256,)
        ):
            callees.setdefault(r["caller_offset"], []).append(r["callee_offset"])

        functions = [
            {
                "offset": r["offset"],
                "name": r["name"],
                "priority": r["priority"],
                "size": r["size"] or 0,
                "is_library": bool(r["is_library"]),
                "c_code": r["c_code"] or "",
                "llm_summary": r["llm_summary"] or "",
                "capa_hits": _loads(r["capa_hits"], []),
                "xrefs": _loads(r["xrefs"], []),
                "iocs": defang_iocs(_loads(r["iocs"], [])),
                "decompile_warnings": _loads(r["decompile_warnings"], []),
                "callees": callees.get(r["offset"], []),
            }
            for r in conn.execute(
                "SELECT * FROM functions WHERE sha256 = ? ORDER BY priority DESC, id", (sha256,)
            )
        ]

        report_row = conn.execute(
            "SELECT supervisor_report, verdict FROM llm_claims WHERE sha256 = ? ORDER BY id DESC LIMIT 1",
            (sha256,),
        ).fetchone()

    return {
        "sample": dict(sample),
        "findings": findings,
        "functions": functions,
        "supervisor_report": (report_row["supervisor_report"] or "") if report_row else "",
        "verdict": _loads_dict(report_row["verdict"]) if report_row else {},
    }
