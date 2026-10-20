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
    confidence REAL
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
    xrefs              TEXT
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
    supervisor_report TEXT
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
        existing = {row[1] for row in conn.execute("PRAGMA table_info(functions)")}
        for column, sql_type in FUNCTION_EXTRA_COLUMNS:
            if column not in existing:
                conn.execute(f"ALTER TABLE functions ADD COLUMN {column} {sql_type}")
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
    rows = [(sha256, f.source, f.kind, f.value, f.address, f.confidence) for f in findings]
    with closing(sqlite3.connect(_path(db_path))) as conn, conn:
        conn.execute("DELETE FROM findings WHERE sha256 = ?", (sha256,))
        conn.executemany(
            "INSERT INTO findings (sha256, source, kind, value, address, confidence) VALUES (?, ?, ?, ?, ?, ?)",
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
            )
        )
        for callee in dict.fromkeys(fn.callees):
            call_rows.append((sha256, fn.offset, callee))

    with closing(sqlite3.connect(_path(db_path))) as conn, conn:
        conn.execute("DELETE FROM functions WHERE sha256 = ?", (sha256,))
        conn.execute("DELETE FROM calls WHERE sha256 = ?", (sha256,))
        conn.executemany(
            "INSERT INTO functions (sha256, offset, name, priority, c_code, decompile_warnings, "
            "llm_summary, size, is_library, capa_hits, xrefs) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            function_rows,
        )
        conn.executemany(
            "INSERT INTO calls (sha256, caller_offset, callee_offset) VALUES (?, ?, ?)",
            call_rows,
        )
    return len(function_rows), len(call_rows)


def insert_llm_claims(sha256: str, report: str, db_path: str | None = None) -> None:
    """Supervisor raporunu ``llm_claims`` tablosuna yazar (örneğin önceki raporunun yerine)."""
    with closing(sqlite3.connect(_path(db_path))) as conn, conn:
        conn.execute("DELETE FROM llm_claims WHERE sha256 = ?", (sha256,))
        conn.execute(
            "INSERT INTO llm_claims (sha256, supervisor_report) VALUES (?, ?)",
            (sha256, report),
        )


# --------------------------------------------------------------------------- #
# Okuma yardımcıları (API/UI için)
# --------------------------------------------------------------------------- #
def _loads(text: str | None, default: Any) -> Any:
    try:
        return json.loads(text) if text else default
    except (TypeError, ValueError):
        return default


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
                   EXISTS(SELECT 1 FROM llm_claims c WHERE c.sha256 = s.sha256)  AS has_report
            FROM samples s
            ORDER BY s.rowid DESC
            """
        ).fetchall()
    return [{**dict(r), "has_report": bool(r["has_report"])} for r in rows]


def get_sample_details(sha256: str, db_path: str | None = None) -> dict[str, Any] | None:
    """Bir örneğin bulguları, fonksiyonları (callees ile) ve supervisor raporu; yoksa ``None``."""
    with closing(_connect_ro(db_path)) as conn:
        sample = conn.execute(
            "SELECT sha256, file_type, route, packer, arch FROM samples WHERE sha256 = ?", (sha256,)
        ).fetchone()
        if sample is None:
            return None

        findings = [
            dict(r)
            for r in conn.execute(
                "SELECT source, kind, value, address, confidence FROM findings WHERE sha256 = ? ORDER BY id",
                (sha256,),
            )
        ]

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
                "decompile_warnings": _loads(r["decompile_warnings"], []),
                "callees": callees.get(r["offset"], []),
            }
            for r in conn.execute(
                "SELECT * FROM functions WHERE sha256 = ? ORDER BY priority DESC, id", (sha256,)
            )
        ]

        report_row = conn.execute(
            "SELECT supervisor_report FROM llm_claims WHERE sha256 = ? ORDER BY id DESC LIMIT 1", (sha256,)
        ).fetchone()

    return {
        "sample": dict(sample),
        "findings": findings,
        "functions": functions,
        "supervisor_report": report_row["supervisor_report"] if report_row else "",
    }
