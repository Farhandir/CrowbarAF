"""SQLite persistence layer: samples, findings, functions, calls, llm_claims.

The helpers work via duck typing (they read ``SampleInfo``/``Finding``/``DecompiledFunction``
fields), so this module does not depend on ``state.py``.

Re-analysis: for the same ``sha256``, the ``insert_*`` calls delete that sample's old
rows and write the new ones (no duplicate records).
"""

from __future__ import annotations

import json
import os
import sqlite3
from contextlib import closing
from typing import Any, Iterable

from utils import defang_finding, defang_iocs

# Default: "crowbaraf.db" in the working directory; can be changed with CROWBAR_DB_PATH.
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

# For upgrading older databases: columns added later to the functions table
FUNCTION_EXTRA_COLUMNS = (
    ("llm_summary", "TEXT"),
    ("size", "INTEGER"),
    ("is_library", "BOOLEAN"),
    ("capa_hits", "TEXT"),
    ("xrefs", "TEXT"),
    ("iocs", "TEXT"),
)

# Columns added later to llm_claims (verdict: file-level decision, JSON text)
LLM_CLAIMS_EXTRA_COLUMNS = (("verdict", "TEXT"),)

# Columns added later to findings: finding_id (identity), verified (does it exist in the binary?).
# Older rows are treated as "verified" via DEFAULT 1 (backward compatibility).
FINDINGS_EXTRA_COLUMNS = (("finding_id", "TEXT"), ("verified", "BOOLEAN DEFAULT 1"))

# table -> columns added later (old database migration)
_MIGRATIONS = (
    ("functions", FUNCTION_EXTRA_COLUMNS),
    ("llm_claims", LLM_CLAIMS_EXTRA_COLUMNS),
    ("findings", FINDINGS_EXTRA_COLUMNS),
)


def _path(db_path: str | None) -> str:
    return db_path or DEFAULT_DB_PATH


def init_db(db_path: str | None = None) -> str:
    """Creates the tables (if missing) and returns the database path in use.

    If ``db_path`` is not given, ``crowbaraf.db`` (or ``CROWBAR_DB_PATH``) is used.
    On databases created before a schema change, missing ``functions`` columns
    are added with ``ALTER TABLE``.
    """
    path = _path(db_path)
    with closing(sqlite3.connect(path)) as conn, conn:
        conn.executescript(SCHEMA)
        # CREATE TABLE IF NOT EXISTS does not add columns to an existing table: upgrade the old schema
        for table, columns in _MIGRATIONS:
            existing = {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
            for column, sql_type in columns:
                if column not in existing:
                    conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {sql_type}")
    return path


# --------------------------------------------------------------------------- #
# Write helpers
# --------------------------------------------------------------------------- #
def insert_sample(sample: Any, db_path: str | None = None) -> None:
    """Writes the sample to the ``samples`` table (updates if the same sha256 exists)."""
    with closing(sqlite3.connect(_path(db_path))) as conn, conn:
        conn.execute(
            "INSERT OR REPLACE INTO samples (sha256, file_type, route, packer, arch) VALUES (?, ?, ?, ?, ?)",
            (sample.sha256, sample.file_type, sample.route, sample.packer, sample.arch),
        )


def insert_findings(sha256: str, findings: Iterable[Any], db_path: str | None = None) -> int:
    """Writes the sample's findings (deletes previous ones). Returns the number of rows written."""
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
    """Writes functions to ``functions`` and callee relations to ``calls``.

    Previous records are deleted. ``decompile_warnings``, ``capa_hits`` and ``xrefs``
    are stored as JSON text (``json.dumps``); ``is_library`` is written as 0/1.
    Repeated calls from the same function to the same target are collapsed into one row.
    Returns: ``(number_of_functions_written, number_of_calls_written)``.
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
    """Writes the supervisor report and the file-level decision (``verdict``) to the ``llm_claims`` table.

    Previous records are deleted. If ``verdict`` is a ``dict``, it is converted to JSON text with
    ``json.dumps``; if ``None``/empty, the column stays ``NULL``. (Backward compatibility: ``verdict`` is optional.)
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
    """Persists all results of an ``AgentState`` in a single call.

    Shared by ``db_writer_node`` (full pipeline) and ``host_analyze.py --db`` (split mode):
    ``init_db`` -> ``insert_sample`` -> ``insert_findings`` -> ``insert_functions_and_calls``
    (including ``llm_summary``) -> ``insert_llm_claims`` (if a report and/or ``verdict`` exists).

    If ``state.sample.sha256`` is empty, it raises ``ValueError`` (no row is written without a key).
    It does not swallow errors; the caller decides. Returns: written row counts + ``db_path``.
    """
    sha256 = state.sample.sha256
    if not sha256:
        raise ValueError("sample.sha256 is empty; cannot write to the database")
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
# Read helpers (for API/UI)
# --------------------------------------------------------------------------- #
def _loads(text: str | None, default: Any) -> Any:
    try:
        return json.loads(text) if text else default
    except (TypeError, ValueError):
        return default


def _loads_dict(text: str | None) -> dict[str, Any]:
    """Converts JSON text to a ``dict``; ``{}`` for empty, broken or non-dict values."""
    value = _loads(text, {})
    return value if isinstance(value, dict) else {}


def _connect_ro(db_path: str | None) -> sqlite3.Connection:
    path = init_db(db_path)  # ensure tables/columns exist (also works on an empty database)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn


def get_all_samples(db_path: str | None = None) -> list[dict[str, Any]]:
    """All analyzed samples (most recently written first) + finding/function counts."""
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
    """A sample's findings, functions (with callees) and supervisor report; ``None`` if missing."""
    with closing(_connect_ro(db_path)) as conn:
        sample = conn.execute(
            "SELECT sha256, file_type, route, packer, arch FROM samples WHERE sha256 = ?", (sha256,)
        ).fetchone()
        if sample is None:
            return None

        # Analyst safety: network IoCs (url/ip/domain/email) are returned defanged;
        # the raw value stays in the database (see utils.defang_ioc).
        findings = []
        for r in conn.execute(
            "SELECT source, kind, value, address, confidence, finding_id, verified "
            "FROM findings WHERE sha256 = ? ORDER BY id",
            (sha256,),
        ):
            item = dict(r)
            item["finding_id"] = item["finding_id"] or ""
            # NULL (old row / pre-migration) = verified; only an explicit 0 means "False"
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
