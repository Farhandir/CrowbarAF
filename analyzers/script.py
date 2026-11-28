"""Static analysis of script-type samples (JS/VBS/PS1/HTA/WSF/BAT/LNK); nothing is executed."""

from __future__ import annotations

import logging
import os
import re
from collections.abc import Iterable
from typing import Any
from urllib.parse import urlsplit

from analyzers.capa_floss import _IPV4_RE, _URL_RE
from analyzers.script_deobf import DeobfResult, deobfuscate
from state import Finding

logger = logging.getLogger(__name__)

SCRIPT_TYPES = ("js", "vbs", "ps1", "hta", "wsf", "bat", "lnk")
SNIFF_BYTES = 64 * 1024
MAX_SCRIPT_BYTES = 10 * 1024 * 1024
SCRIPT_SOURCE = "script"

_MAX_IOC_VALUES = 200
_MAX_REPLACEMENT_RATIO = 0.05

# Windows shell link header magic (bytes 0:4) and the LNK CLSID (bytes 4:20).
_LNK_MAGIC = b"\x4c\x00\x00\x00"
_LNK_CLSID = b"\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46"

# Non-script containers: never treated as scripts, whatever the extension or DIE hint says.
_NON_SCRIPT_MAGICS: tuple[bytes, ...] = (
    b"MZ",  # PE
    b"\x7fELF",  # ELF
    b"%PDF",  # PDF
    b"PK\x03\x04",  # ZIP (also docx/xlsx/jar)
    b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",  # OLE/Office
    b"\xfe\xed\xfa\xce",  # Mach-O 32-bit big-endian
    b"\xfe\xed\xfa\xcf",  # Mach-O 64-bit big-endian
    b"\xce\xfa\xed\xfe",  # Mach-O 32-bit little-endian
    b"\xcf\xfa\xed\xfe",  # Mach-O 64-bit little-endian
    b"\xca\xfe\xba\xbe",  # Mach-O universal / Java class
    b"Rar!",  # RAR
    b"7z\xbc\xaf\x27\x1c",  # 7-Zip
    b"\x1f\x8b",  # gzip
)

_EXTENSION_TYPES: dict[str, str] = {
    ".js": "js",
    ".jse": "js",
    ".vbs": "vbs",
    ".vbe": "vbs",
    ".ps1": "ps1",
    ".psm1": "ps1",
    ".hta": "hta",
    ".wsf": "wsf",
    ".wsc": "wsf",
    ".bat": "bat",
    ".cmd": "bat",
}

_DIE_HINTS: tuple[tuple[str, str], ...] = (
    ("javascript", "js"),
    ("jscript", "js"),
    ("vbscript", "vbs"),
    ("powershell", "ps1"),
    ("html application", "hta"),
    ("hta", "hta"),
    ("batch", "bat"),
)
_DIE_HINT_RES: tuple[tuple[re.Pattern[str], str], ...] = tuple(
    (re.compile(rf"\b{re.escape(marker)}\b"), script_type) for marker, script_type in _DIE_HINTS
)

_HTML_SCRIPT_LANG_RE = re.compile(r"""language\s*=\s*["']?(?:vbscript|jscript|javascript)""")
_CREATEOBJECT_RE = re.compile(r"\bcreateobject\s*\(")

_PS_MARKERS = ("param(", "$env:", "invoke-expression", "iex ", "new-object ", "-encodedcommand", "[system.")
_JS_MARKERS = ("var ", "function", "new activexobject", "wscript.", "eval(", "=>", "let ", "const ")
_VBS_MARKERS = ("dim ", "sub ", "end sub", "wscript.")

# Only these TLDs may turn a dotted token into a domain (keeps COM ProgIDs/file names out).
_DOMAIN_TLDS = frozenset({
    "com", "net", "org", "info", "biz", "io", "ru", "cn", "top", "xyz", "online", "site", "club",
    "live", "me", "co", "uk", "de", "br", "in", "tk", "pw", "cc", "su", "ws", "link", "shop",
    "app", "dev",
})
_DOMAIN_IGNORE = frozenset({"schemas.microsoft.com", "www.w3.org"})
_DOMAIN_CANDIDATE_RE = re.compile(
    r"(?<![a-z0-9_-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}(?![a-z0-9-])",
    re.IGNORECASE,
)

# Minified/obfuscated JS property access yields short dotted tokens ("e.app", "t.io", "ab.co")
# that look like bare domains. The label left of the TLD needs >= 3 chars, or >= 2 chars when
# the domain has 3+ labels ("cdn.ab.co" is kept, "ab.co" is dropped).
_MIN_BARE_TLD_LABEL_LEN = 3
_MIN_MULTI_LABEL_TLD_LABEL_LEN = 2
_MIN_MULTI_LABEL_DOMAIN_LABELS = 3

_URL_TRAILING_CHARS = ");,'\""
_IGNORED_IPS = frozenset({"0.0.0.0", "255.255.255.255"})


# --------------------------------------------------------------------------- #
# Byte reading / decoding
# --------------------------------------------------------------------------- #
def _read_prefix(file_path: str, limit: int) -> bytes:
    """Reads at most ``limit`` bytes from the file."""
    with open(file_path, "rb") as fh:
        return fh.read(limit)


def _decode_script_bytes(data: bytes) -> str:
    """Decodes script bytes by BOM (UTF-8/UTF-16) or a UTF-16LE-without-BOM heuristic."""
    try:
        if data.startswith(b"\xef\xbb\xbf"):
            return data.decode("utf-8-sig", errors="replace")
        if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
            return data.decode("utf-16", errors="replace")
        if len(data) >= 2 and all(byte == 0 for byte in data[1:512:2]):
            return data.decode("utf-16-le", errors="replace")
        return data.decode("utf-8", errors="replace")
    except UnicodeError:  # defensive: decoding must never raise
        return data.decode("utf-8", errors="replace")


def _looks_like_text(text: str) -> bool:
    """Rejects decoded binary garbage (embedded NULs or too many replacement chars)."""
    if not text or "\x00" in text:
        return False
    return text.count("\ufffd") / len(text) <= _MAX_REPLACEMENT_RATIO


def read_script_text(file_path: str, max_bytes: int = MAX_SCRIPT_BYTES) -> str:
    """Reads a script as text (BOM-aware); returns ``""`` on read errors."""
    try:
        data = _read_prefix(file_path, max_bytes)
    except OSError as exc:
        logger.warning("[script] could not read %s: %s", file_path, exc)
        return ""
    return _decode_script_bytes(data)


# --------------------------------------------------------------------------- #
# Type detection
# --------------------------------------------------------------------------- #
def _die_script_hint(die_info: dict[str, Any] | None) -> str | None:
    """Maps a DIE summary to a script type using word-boundary hint patterns."""
    if not isinstance(die_info, dict):
        return None
    haystack = " ".join(
        str(die_info.get(key, "")) for key in ("file_type", "language", "detected", "compiler")
    ).lower()
    for pattern, script_type in _DIE_HINT_RES:
        if pattern.search(haystack):
            return script_type
    return None


def _sniff_script_type(text: str) -> str | None:
    """Infers a script type from content markers (text is lowercased here)."""
    lowered = text.lower()

    if "<hta:application" in lowered:
        return "hta"
    if ("<job" in lowered or "<package" in lowered) and "<script" in lowered:
        return "wsf"
    if "<html" in lowered and "<script" in lowered and _HTML_SCRIPT_LANG_RE.search(lowered):
        return "hta"
    if _CREATEOBJECT_RE.search(lowered) and any(marker in lowered for marker in _VBS_MARKERS):
        return "vbs"
    if sum(marker in lowered for marker in _PS_MARKERS) >= 2:
        return "ps1"
    if lowered.lstrip("\ufeff \t\r\n").startswith("@echo off"):
        return "bat"
    if sum(marker in lowered for marker in _JS_MARKERS) >= 2:
        return "js"
    return None


def detect_script_type(file_path: str, die_info: dict[str, Any] | None = None) -> str | None:
    """Returns the detected script type, or ``None`` (binary, unknown or unreadable)."""
    try:
        head = _read_prefix(file_path, SNIFF_BYTES)
    except OSError as exc:
        logger.debug("[script] could not read %s for type detection: %s", file_path, exc)
        return None

    # Binary/container guard: PE, PDF, archives etc. must stay on the native route even if named .js.
    if head.startswith(_NON_SCRIPT_MAGICS):
        return None

    if head[:4] == _LNK_MAGIC and head[4:20] == _LNK_CLSID:
        return "lnk"

    hint = _die_script_hint(die_info)
    if hint:
        return hint

    # A binary blob renamed to .ps1/.bat must not skip the binary tools. The extension only
    # needs NUL-free text (a legacy code page script may decode with replacement chars);
    # content sniffing needs clean text.
    # A .lnk file only counts as LNK when the header magic also matched above.
    text = _decode_script_bytes(head)
    if "\x00" in text:
        return None

    extension = os.path.splitext(file_path)[1].lower()
    if extension in _EXTENSION_TYPES:
        return _EXTENSION_TYPES[extension]
    if not _looks_like_text(text):
        return None
    return _sniff_script_type(text)


# --------------------------------------------------------------------------- #
# Dangerous API combos
# --------------------------------------------------------------------------- #
# Each rule maps to groups; every group needs at least one alternative present (case-insensitive substring).
# Legitimate admin/installer scripts can match these patterns, so combo confidence stays below 1.
SCRIPT_COMBO_RULES: dict[str, list[tuple[str, ...]]] = {
    # Network download -> write to disk -> execute (generic dropper chain).
    "Download-Write-Execute": [
        ("msxml2.xmlhttp", "msxml2.serverxmlhttp", "winhttp.winhttprequest", "microsoft.xmlhttp"),
        ("adodb.stream",),
        ("wscript.shell", "shell.application"),
        (".run(", ".exec(", "shellexecute"),
    ],
    # PowerShell download cradle piped into an execution primitive.
    "Download-Execute (PowerShell)": [
        ("downloadstring", "downloadfile", "invoke-webrequest", "iwr ", "net.webclient", "start-bitstransfer"),
        ("invoke-expression", "iex", "start-process", "& ("),
    ],
    # A PowerShell process launched with encoded/base64 content (common stager pattern).
    "Encoded PowerShell Launch": [
        ("powershell",),
        ("-enc", "frombase64string"),
    ],
    # Script host spawned with a built-in LOLBin/command shell.
    "Script Host Spawn": [
        ("wscript.shell", "shell.application"),
        (".run(", ".exec(", "shellexecute"),
        ("cmd /c", "cmd.exe", "powershell", "mshta", "rundll32", "regsvr32", "certutil", "bitsadmin"),
    ],
    # Registry Run key written for persistence (admin provisioning scripts can match).
    "Persistence via Registry Run": [
        ("regwrite", "set-itemproperty", "new-itemproperty", "reg add"),
        ("\\currentversion\\run",),
    ],
    # Dropped copy in a Startup folder for persistence (installers can match).
    "Persistence via Startup Folder": [
        ("startup",),
        ("copyfile", "copy-item", "savetofile", ".copy("),
    ],
    # certutil used as a downloader/decoder (often benign admin activity).
    "LOLBin Download (certutil)": [
        ("certutil",),
        ("-urlcache", "-decode"),
    ],
    # bitsadmin used as a transfer client (often benign admin activity).
    "LOLBin Download (bitsadmin)": [
        ("bitsadmin",),
        ("/transfer",),
    ],
}

# Alternatives that need regex matching instead of raw substring matching: word boundaries
# (e.g. "iex" vs "index") and the PowerShell encoded-command flag prefixes.
_ALTERNATIVE_RES: dict[str, re.Pattern[str]] = {
    "iex": re.compile(r"\biex\b"),
    # PowerShell accepts any unambiguous prefix of -EncodedCommand (-e, -ec, ... -encodedcommand);
    # a raw "-enc" substring would wrongly match benign "-Encoding utf8".
    "-enc": re.compile(
        r"(?<![\w-])-e(?:c|n|nc|nco|ncod|ncode|ncoded|ncodedc|ncodedco|ncodedcom|"
        r"ncodedcomm|ncodedcomma|ncodedcomman|ncodedcommand)?\s"
    ),
}


def _alternative_present(lowered: str, alternative: str) -> bool:
    """Checks one combo alternative (regex-based where an entry exists, substring otherwise)."""
    pattern = _ALTERNATIVE_RES.get(alternative)
    if pattern is not None:
        return pattern.search(lowered) is not None
    return alternative in lowered


def match_script_combos(text: str) -> list[str]:
    """Returns the sorted names of combo rules whose groups are all satisfied."""
    if not text:
        return []
    lowered = text.lower()
    matched = [
        rule
        for rule, groups in SCRIPT_COMBO_RULES.items()
        if all(any(_alternative_present(lowered, alt) for alt in group) for group in groups)
    ]
    return sorted(matched)


# --------------------------------------------------------------------------- #
# IoC extraction
# --------------------------------------------------------------------------- #
def _dedupe_capped(values: Iterable[str], cap: int = _MAX_IOC_VALUES) -> list[str]:
    """Deduplicates while preserving order, capped at ``cap`` items."""
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        if not value or value in seen:
            continue
        seen.add(value)
        out.append(value)
        if len(out) >= cap:
            break
    return out


def _ip_is_ignored(ip: str) -> bool:
    """Drops unspecified, loopback and broadcast addresses."""
    return ip in _IGNORED_IPS or ip.startswith("127.")


def _url_hostnames(urls: Iterable[str]) -> set[str]:
    """Collects the exact lowercased hostnames of already-extracted URLs."""
    hostnames: set[str] = set()
    for url in urls:
        try:
            hostname = urlsplit(url).hostname
        except ValueError:  # malformed URL (e.g. bad IPv6 bracket)
            continue
        if hostname:
            hostnames.add(hostname.lower())
    return hostnames


def _bare_domain_is_plausible(domain: str) -> bool:
    """Rejects bare domain candidates produced by minified/obfuscated JS property access.

    The label directly left of the TLD must be at least 3 characters long, unless the
    domain has 3 or more labels, where a 2-character label is also accepted.
    """
    labels = domain.split(".")
    tld_label = labels[-2]
    if len(tld_label) >= _MIN_BARE_TLD_LABEL_LEN:
        return True
    return (
        len(labels) >= _MIN_MULTI_LABEL_DOMAIN_LABELS
        and len(tld_label) >= _MIN_MULTI_LABEL_TLD_LABEL_LEN
    )


def extract_script_iocs(text: str) -> dict[str, list[str]]:
    """Extracts URLs, IPv4 addresses and allowlisted bare domains from script text."""
    if not isinstance(text, str) or not text:
        return {"url": [], "ip": [], "domain": []}

    urls = _dedupe_capped(url.rstrip(_URL_TRAILING_CHARS) for url in _URL_RE.findall(text))
    ips = _dedupe_capped(ip for ip in _IPV4_RE.findall(text) if not _ip_is_ignored(ip))

    lowered = text.lower()
    url_hostnames = _url_hostnames(urls)
    domains: list[str] = []
    for match in _DOMAIN_CANDIDATE_RE.finditer(lowered):
        domain = match.group(0)
        if domain.rsplit(".", 1)[-1] not in _DOMAIN_TLDS:
            continue
        if domain in _DOMAIN_IGNORE or domain in url_hostnames:
            continue
        if not _bare_domain_is_plausible(domain):
            continue
        domains.append(domain)

    return {"url": urls, "ip": ips, "domain": _dedupe_capped(domains)}


# --------------------------------------------------------------------------- #
# Findings
# --------------------------------------------------------------------------- #
def _finding(kind: str, value: str, confidence: float) -> Finding:
    """Builds a script finding without a precomputed deterministic ID."""
    return Finding(
        source=SCRIPT_SOURCE,
        kind=kind,
        value=value,
        address="",  # script findings are global: "address" is a function offset
        confidence=confidence,
        finding_id="",
        verified=True,
    )


def script_findings(text: str, script_type: str) -> list[Finding]:
    """Converts script text into findings (combos, URLs, IPs, domains, in that order)."""
    iocs = extract_script_iocs(text)
    findings = [_finding("combo", name, 0.8) for name in match_script_combos(text)]
    findings.extend(_finding("url", value, 0.7) for value in iocs["url"])
    findings.extend(_finding("ip", value, 0.7) for value in iocs["ip"])
    findings.extend(_finding("domain", value, 0.5) for value in iocs["domain"])
    logger.debug(
        "[script] %s: %d combo(s), %d url(s), %d ip(s), %d domain(s)",
        script_type,
        sum(f.kind == "combo" for f in findings),
        len(iocs["url"]),
        len(iocs["ip"]),
        len(iocs["domain"]),
    )
    return findings


_DEOBF_DISABLED_VALUES = frozenset({"0", "false", "no", "off"})
_DEOBF_IOC_FINDINGS: tuple[tuple[str, str, float], ...] = (
    ("url", "deobf_url", 0.7),
    ("ip", "deobf_ip", 0.7),
    ("domain", "deobf_domain", 0.5),
)
_EMBEDDED_BINARY_KINDS = {"pe": "embedded_pe", "zip": "embedded_zip"}
DEOBF_COMBO_KIND = "deobf_combo"
ENCRYPTED_PAYLOAD_KIND = "encrypted_payload"
# Opaque blobs below this size are usually icons/resources, not a hidden stage.
MIN_ENCRYPTED_PAYLOAD_BYTES = 64 * 1024
# Below the verdict's medium-authority floor: an encrypted blob explains an "unknown",
# it is never evidence of maliciousness on its own.
_ENCRYPTED_PAYLOAD_CONFIDENCE = 0.3


def _deobf_enabled() -> bool:
    """Reads the kill switch at call time (default: enabled)."""
    return os.environ.get("CROWBAR_SCRIPT_DEOBF", "1").strip().lower() not in _DEOBF_DISABLED_VALUES


def _deobf_findings(result: DeobfResult, raw_findings: Iterable[Finding]) -> list[Finding]:
    """Converts deobfuscation artefacts into findings, avoiding raw duplicates."""
    raw_list = list(raw_findings)
    seen_combos = {finding.value for finding in raw_list if finding.kind == "combo"}
    seen_iocs: dict[str, set[str]] = {
        raw_kind: {finding.value for finding in raw_list if finding.kind == raw_kind}
        for raw_kind, _kind, _confidence in _DEOBF_IOC_FINDINGS
    }

    findings: list[Finding] = []
    for layer in result.layers:
        for rule in match_script_combos(layer.text):
            if rule in seen_combos:
                continue
            seen_combos.add(rule)
            logger.debug("[script] deobf combo %s via %s", rule, layer.transform)
            findings.append(_finding(DEOBF_COMBO_KIND, rule, 0.8))
        iocs = extract_script_iocs(layer.text)
        for raw_kind, kind, confidence in _DEOBF_IOC_FINDINGS:
            for value in iocs[raw_kind]:
                if value in seen_iocs[raw_kind]:
                    continue
                seen_iocs[raw_kind].add(value)
                findings.append(_finding(kind, value, confidence))

    for binary in result.binaries:
        kind = _EMBEDDED_BINARY_KINDS.get(binary.kind)
        if kind is None:
            continue
        findings.append(
            _finding(kind, f"sha256={binary.sha256} size={binary.size} via={binary.transform}", 0.9)
        )

    for blob in result.opaque:
        if blob.size < MIN_ENCRYPTED_PAYLOAD_BYTES:
            continue
        findings.append(
            _finding(
                ENCRYPTED_PAYLOAD_KIND,
                f"sha256={blob.sha256} size={blob.size} via={blob.transform}",
                _ENCRYPTED_PAYLOAD_CONFIDENCE,
            )
        )
    return findings


def analyze_script_file(file_path: str, script_type: str) -> list[Finding]:
    """Analyzes a script file; returns ``[]`` for LNK or on any error."""
    if script_type == "lnk":
        logger.info("[script] lnk parsing not yet supported: %s", file_path)
        return []
    try:
        text = read_script_text(file_path)
        findings = script_findings(text, script_type)
        if _deobf_enabled():
            result = deobfuscate(text)
            for note in result.notes:
                logger.info("[script] deobf note for %s: %s", file_path, note)
            findings.extend(_deobf_findings(result, findings))
        return findings
    except Exception as exc:  # noqa: BLE001 - standalone analysis must never crash the caller
        logger.warning("[script] analysis failed for %s: %s", file_path, exc)
        return []
