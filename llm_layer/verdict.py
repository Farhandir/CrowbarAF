"""Deterministic file-level verdict and fail-closed policy.

Four states (never "clean"):
  malicious     : suspicious function(s) or a high-authority (YARA) finding
  needs_review  : medium-authority evidence (capa/import combo/IoC), a C2-like
                  URL/IP token, or a conflict
  unknown       : coverage too low, packed, tool failure, no functions
  no_evidence   : covered surface analyzed, no malicious evidence found

C2-like detection is token based: a finding is only critical when it contains a
URL/IP that is not a known schema/signature host or a version-like dotted number.
The LLM-only high-confidence tier (Policy C v2) additionally requires a large
enough analyzed surface, several suspicious functions, and at least three
canonical behavior classes. Free-text behavior strings do not count as classes.

Integrity: a critical finding with ``verified=False`` (a statically extracted text IoC
that is not present in the file bytes) is never evidence for "malicious"; it only
escalates the verdict to needs_review (and still overrides a benign LLM verdict).
"""
from __future__ import annotations

import hashlib
import ipaddress
import os
import re
from urllib.parse import urlsplit

from .types import Finding, FunctionInfo, FunctionSummary

MALICIOUS = "malicious"
NEEDS_REVIEW = "needs_review"
UNKNOWN = "unknown"
NO_EVIDENCE = "no_evidence"

# URL schemes that can carry a C2 endpoint. Trailing punctuation is stripped.
_URL_TOKEN_RE = re.compile(r"\b(?:https?|ftp|tcp)://[^\s'\"<>]+", re.IGNORECASE)
# Strict dotted-quad: four 0-255 octets that are not part of a longer dotted or
# numeric sequence (so "1.2.3.4.5" and "311.2.3.4" are not addresses).
_IPV4_RE = re.compile(
    r"(?<![\d.])(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)"
    r"(?:\.(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)){3}(?![\d]|\.\d)"
)
_VERSION_CONTEXT_RE = re.compile(
    r"(?:version|ver|fileversion|productversion|assemblyversion)\s*[=:]?\s*[\"']?$",
    re.IGNORECASE,
)
_VERSION_V_CONTEXT_RE = re.compile(r"\bv$", re.IGNORECASE)
_DER_TAIL_RE = re.compile(r"(?<=[a-z])0[0-9a-z]{0,2}$")

# XML namespaces / signature infrastructure that regularly appears in PE
# manifests and version resources; a URL on one of these hosts is not C2.
BENIGN_URL_HOSTS = (
    "schemas.microsoft.com", "schemas.xmlsoap.org", "schemas.openxmlformats.org",
    "w3.org", "nsis.sf.net", "ns.adobe.com", "purl.org", "crl.microsoft.com",
    "digicert.com", "verisign.com", "symcb.com", "symcd.com", "globalsign.com",
    "globalsign.net", "sectigo.com", "usertrust.com", "comodoca.com",
)

_BENIGN_CLAIM = ("benign", "clean", "not malicious", "no malicious", "signed",
                 "harmless", "no threat", "0/70", "safe")

# YARA is the only source that can stand alone as "malicious".
HIGH_AUTHORITY = {"yara"}
# Dual-use / supporting signals: they can require review, not a malicious verdict.
MEDIUM_AUTHORITY = {"capa", "import_combo", "ioc", "script"}
# Sources whose URL/IPv4 values are checked for C2-like tokens.
C2_SOURCES = ("floss", "ioc", "script")
# Static script analysis: only a dangerous API chain is a behavior signal of its own;
# script url/ip findings feed the C2 check, so one string never counts twice.
# A dangerous chain found after static deobfuscation and an embedded PE are behavior signals too.
SCRIPT_SIGNAL_KINDS = {"combo", "deobf_combo", "embedded_pe"}
# Encrypted blob the script carries: explains an "unknown", never counts as evidence.
ENCRYPTED_PAYLOAD_KIND = "encrypted_payload"
SCRIPT_UNSUPPORTED_REASON = "script format: static script analysis not yet supported"
CONFIDENCE_FLOOR = 0.7
LLM_MIN_SUSPICIOUS = int(os.getenv("CROWBAR_LLM_MIN_SUSPICIOUS", "3"))
LLM_MIN_BEHAVIORS = int(os.getenv("CROWBAR_LLM_MIN_BEHAVIORS", "3"))
LLM_MIN_COVERAGE = float(os.getenv("CROWBAR_LLM_MIN_COVERAGE", "0.6"))
# A handful of functions is too small a surface for an LLM-only malicious call.
LLM_MIN_ANALYZED = int(os.getenv("CROWBAR_LLM_MIN_ANALYZED", "20"))

# LLM summaries are one signal; multiple distinct behavior classes are required
# before a single-source LLM verdict may be promoted to malicious. Only these
# canonical labels count (not free-text behavior strings).
BEHAVIOR_KEYWORDS = {
    "persistence": ("persist", "cron", "systemd", "rc.local", "watchdog", "init"),
    "execution": ("exec", "system(", "shell", "spawn", "fork", "subprocess"),
    "network": ("socket", "connect", "c2", "http", "dns", "bot", "network"),
    "process": ("kill", "process", "pid", "locker", "watchdog"),
    "file": ("file", "unlink", "delete", "hidden", "copy", "drop"),
    "memory": ("mmap", "memory", "inject", "virtualalloc", "protect"),
}


def finding_id(f: Finding) -> str:
    if f.finding_id:  # nodes.compute_finding_id: same identity as DB/state
        return f.finding_id
    raw = f"{f.source}|{f.kind}|{f.value}|{f.address}"
    return "f_" + hashlib.sha1(raw.encode("utf-8", "replace")).hexdigest()[:12]


def _ip_token_is_benign(token: str, before: str) -> bool:
    """True for infrastructure/version-like addresses, not routable C2 endpoints."""
    try:
        ip = ipaddress.ip_address(token)
    except ValueError:
        return False
    if not isinstance(ip, ipaddress.IPv4Address):
        return False
    if (ip.is_multicast or ip.is_loopback or ip.is_unspecified
            or ip.is_reserved or ip.is_link_local):
        return True
    octets = token.split(".")
    # Last octet 0/255: network/broadcast, and what 4-part versions look like.
    if octets[-1] in ("0", "255"):
        return True
    # All single-digit octets ("7.4.1.3", "1.1.2.1"): versions/OIDs. This also drops public
    # resolvers such as 1.1.1.1 / 8.8.8.8, which are not C2 endpoints either.
    if all(len(o) == 1 for o in octets):
        return True
    # Version context: "FileVersion 6.1.7601.17514", "v2.4.1.3".
    if _VERSION_CONTEXT_RE.search(before) or _VERSION_V_CONTEXT_RE.search(before):
        return True
    return False


def _url_token_is_benign(token: str) -> bool:
    try:
        host = (urlsplit(token).hostname or "").lower()
    except ValueError:
        return False  # malformed: keep fail-closed
    if not host:
        return False
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if isinstance(ip, ipaddress.IPv4Address):
        return _ip_token_is_benign(host, "")
    if ip is not None:
        return False  # IPv6 literal: keep fail-closed
    # No dot: not a resolvable public host ("http://Mozilla/5.0", "https://H"); typically Go
    # string-table fragments glued to a scheme.
    if "." not in host:
        return True
    # Certificate (DER) data glues the next ASN.1 byte to the URL: "ocsp.digicert.com0A".
    # Only used for the allowlist check.
    candidates = {host, _DER_TAIL_RE.sub("", host)}
    return any(h == benign or h.endswith("." + benign)
               for h in candidates for benign in BENIGN_URL_HOSTS)


def c2_like_tokens(value: str) -> list[str]:
    """Non-benign URL/IPv4 tokens in ``value``, deduplicated and in source order.

    Manifest namespaces, schema/signature URLs and version-like dotted numbers
    are excluded so they do not become critical "c2" findings.
    """
    text = value or ""
    found: list[tuple[int, str]] = []
    url_spans: list[tuple[int, int]] = []
    for match in _URL_TOKEN_RE.finditer(text):
        token = match.group(0).rstrip(".,;)]}")
        if not token:
            continue
        url_spans.append((match.start(), match.end()))
        if _url_token_is_benign(token):
            continue
        found.append((match.start(), token))
    for match in _IPV4_RE.finditer(text):
        # An IP that is part of a URL was already handled (or excluded) above.
        if any(start <= match.start() < end for start, end in url_spans):
            continue
        token = match.group(0)
        if _ip_token_is_benign(token, text[:match.start()]):
            continue
        found.append((match.start(), token))

    found.sort(key=lambda item: item[0])
    out: list[str] = []
    seen: set[str] = set()
    for _, token in found:
        if token not in seen:
            seen.add(token)
            out.append(token)
    return out


def is_critical_finding(f: Finding) -> bool:
    """Findings that force must-include / fail-closed (YARA, high IOC, C2-like)."""
    src = (f.source or "").lower()
    if src == "yara":
        return True
    if src == "ioc" and (f.confidence or 0) >= CONFIDENCE_FLOOR:
        return True
    # C2-like tokens are critical even from FLOSS; benign schema/version strings are not.
    if src in C2_SOURCES and c2_like_tokens(f.value or ""):
        return True
    return False


def is_high_authority(f: Finding) -> bool:
    return (f.source or "").lower() in HIGH_AUTHORITY


def is_medium_authority(f: Finding) -> bool:
    src = (f.source or "").lower()
    return src in MEDIUM_AUTHORITY and (f.confidence or 0) >= CONFIDENCE_FLOOR


def _claims_benign(value: str) -> bool:
    low = (value or "").lower()
    return any(m in low for m in _BENIGN_CLAIM)


def _unique_findings(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple] = set()
    out: list[Finding] = []
    for f in findings:
        key = ((f.source or "").lower(), (f.kind or "").lower(),
               re.sub(r"\s+", " ", (f.value or "").strip().lower()))
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


# Short/ambiguous keywords that must match as a whole word ("init" != "initialize").
_EXACT_KEYWORDS = frozenset({"init", "pid", "bot", "c2", "dns", "file", "copy", "drop"})


def _keyword_matches(word: str, text: str) -> bool:
    """Prefix match at a word start ("persist" -> "persistence", not "profile" -> "file");
    whole-word match for ``_EXACT_KEYWORDS``; plain substring for non-alphanumeric keywords."""
    if word.isalnum():
        tail = r"\b" if word in _EXACT_KEYWORDS else ""
        return re.search(r"\b" + re.escape(word) + tail, text) is not None
    return word in text


def linked_critical_ids(findings: list[Finding], functions: list[FunctionInfo]) -> frozenset[str]:
    """Ids of address-less critical findings that can be tied to at least one function.

    A finding is tied to a function by ``context.finding_matches_function`` (its value appears
    in the function's code or in the function's IoC list: Ghidra string xrefs, .NET ldstr).
    """
    from .context import finding_matches_function  # local import: context imports verdict

    ids = set()
    for f in findings:
        if f.address or not is_critical_finding(f):
            continue
        if any(finding_matches_function(f, fn) for fn in functions):
            ids.add(finding_id(f))
    return frozenset(ids)


def _relevant_to(f: Finding, fn: FunctionInfo, linked: frozenset[str] | None) -> bool:
    if f.address:
        return f.address == fn.offset
    # S13: an address-less finding that is tied to some functions applies only to them;
    # one that cannot be tied to any function stays global (fail-closed for all).
    # Revisit if a sample hides its use of an IoC (e.g. through a decoded pointer).
    if linked is None or finding_id(f) not in linked:
        return True
    from .context import finding_matches_function

    return finding_matches_function(f, fn)


def apply_fail_closed(summary: FunctionSummary, fn: FunctionInfo,
                      findings: list[Finding],
                      linked: frozenset[str] | None = None) -> FunctionSummary:
    """If the LLM says benign but a critical finding is relevant, return unknown.

    ``linked`` (from ``linked_critical_ids``) localizes address-less critical findings to the
    functions they are tied to; ``None`` keeps the old rule (every address-less finding is global).
    """
    if summary.suspicious is not False:
        return summary
    relevant = [f for f in findings if _relevant_to(f, fn, linked)]
    critical = [f for f in relevant if is_critical_finding(f)]
    if not critical:
        return summary
    # An unverified (not found in the binary) critical finding also invalidates a "clean" decision
    # (fail-closed: unknown), but cannot produce malicious in the file verdict (compute_verdict).
    summary.suspicious = None
    summary.fail_closed = True
    note = ("fail-closed: critical finding present" if any(f.verified for f in critical)
            else "fail-closed: unverified critical finding present")
    if note not in summary.behaviors:
        summary.behaviors = (list(summary.behaviors) + [note])[:4]
    return summary


def compute_verdict(
    functions: list[FunctionInfo],
    findings: list[Finding],
    summaries: dict[str, FunctionSummary] | None = None,
    packed: bool = False,
    tool_failures: list[str] | None = None,
    analysis_failures: list[str] | None = None,
    min_coverage: float = 0.8,
    require_two_signals: bool = True,
) -> dict:
    """Compute the file-level verdict with explicit coverage and reasons."""
    summaries = summaries or {}
    tool_failures = [x for x in (tool_failures or []) if x]
    analysis_failures = [x for x in (analysis_failures or []) if x]
    # Coverage is over the whole analyzed surface, not only decompiled functions.
    # Empty c_code records are call-graph stubs; they still count as skipped
    # functions so a 100/170 run cannot be reported as 100% coverage.
    total_functions = [f for f in functions if not f.is_library]
    decompiled = [f for f in total_functions if (f.c_code or "").strip()]
    # A failed call (rate limit, bad JSON) or a function the model omitted is not
    # analyzed: it must not count toward coverage.
    failed = [f for f in decompiled
              if f.offset in summaries and getattr(summaries[f.offset], "analysis_failed", False)]
    failed_offsets = {f.offset for f in failed}
    analyzed = [f for f in decompiled if f.offset in summaries and f.offset not in failed_offsets]
    total = len(total_functions)
    coverage = round(len(analyzed) / total, 3) if total else 0.0

    susp = [f for f in analyzed if summaries[f.offset].suspicious is True]
    unknown_fns = [f for f in analyzed if summaries[f.offset].suspicious is None]
    fail_closed = [f for f in analyzed if summaries[f.offset].fail_closed]

    all_critical = [f for f in findings if is_critical_finding(f)]
    # Integrity: a critical finding whose text IoC is NOT present in the file bytes
    # (verified=False) is not evidence. It can never support "malicious" (alone or as a
    # corroborating signal); it only escalates to needs_review.
    critical = _unique_findings([f for f in all_critical if f.verified])
    unverified = _unique_findings([f for f in all_critical if not f.verified])
    high = [f for f in critical if is_high_authority(f)]
    low = [f for f in critical if not is_high_authority(f)]
    medium = [f for f in _unique_findings([f for f in findings if is_medium_authority(f)])
              if not is_critical_finding(f)]

    # Independent evidence classes. A malicious verdict needs at least one
    # strong signal (LLM-suspicious function, YARA, or C2-like string) plus a
    # second independent class. A single strong signal is escalated to review.
    signals: set[str] = set()
    if susp:
        signals.add("llm")
    if high:
        signals.add("yara")
    if low:
        signals.add("c2")
    if any((f.source or "").lower() == "capa" for f in medium):
        signals.add("capa")
    if any((f.source or "").lower() == "import_combo" for f in medium):
        signals.add("import_combo")
    if any((f.source or "").lower() == "ioc" for f in medium):
        signals.add("ioc")
    if any((f.source or "").lower() == "script"
           and (f.kind or "").lower() in SCRIPT_SIGNAL_KINDS for f in medium):
        signals.add("script")
    strong = signals & {"llm", "yara", "c2"}
    two_signal = len(signals) >= 2 and bool(strong)
    # The script combo and a script URL come from the same analyzer (one pass over the
    # same text), so together they are not two independent signals: cap at review.
    script_only = ("script" in signals and signals <= {"script", "c2"}
                   and all((f.source or "").lower() == "script" for f in low))
    if script_only:
        two_signal = False

    # LLM-only high-confidence tier (Policy C v2): several suspicious functions,
    # at least three canonical behavior classes, enough coverage and a large
    # enough analyzed surface. Free-text behavior strings are not classes.
    # This is still one source; it is deliberately gated, not a replacement for C.
    behavior_classes: set[str] = set()
    for fn in susp:
        summary = summaries[fn.offset]
        text = " ".join(
            [summary.summary or ""] + [str(b) for b in (summary.behaviors or [])]
        ).lower()
        for label, words in BEHAVIOR_KEYWORDS.items():
            if any(_keyword_matches(word, text) for word in words):
                behavior_classes.add(label)
    llm_high = (require_two_signals and bool(susp)
                and len(susp) >= LLM_MIN_SUSPICIOUS
                and len(behavior_classes) >= LLM_MIN_BEHAVIORS
                and coverage >= LLM_MIN_COVERAGE
                and len(analyzed) >= LLM_MIN_ANALYZED)
    llm_small_surface = (not llm_high and bool(susp)
                         and strong == {"llm"}
                         and len(susp) >= LLM_MIN_SUSPICIOUS
                         and len(behavior_classes) >= LLM_MIN_BEHAVIORS
                         and coverage >= LLM_MIN_COVERAGE
                         and len(analyzed) < LLM_MIN_ANALYZED)

    conflicts = []
    if high or susp:
        conflicts = [
            {"finding": {"id": finding_id(f), "source": f.source, "value": (f.value or "")[:160]}}
            for f in findings if _claims_benign(f.value)
        ]

    reasons: list[str] = []
    unknown_reasons: list[str] = []
    next_actions: list[str] = []

    if require_two_signals and (two_signal or llm_high):
        verdict = MALICIOUS
        if two_signal:
            reasons.append("corroborated signals: " + ", ".join(sorted(signals)))
        else:
            reasons.append(f"LLM high-confidence: {len(susp)} suspicious function(s), "
                           f"{len(behavior_classes)} behavior class(es)")
    elif require_two_signals and strong:
        verdict = NEEDS_REVIEW
        if script_only:
            reasons.append("script findings only (combo + C2-like URL from one analyzer); "
                           "an independent source is required for malicious")
        reasons.append("single strong signal (" + ", ".join(sorted(strong))
                       + "); corroboration required")
        if llm_small_surface:
            reasons.append(
                f"LLM-only signal on small surface ({len(analyzed)} analyzed function(s) "
                f"< {LLM_MIN_ANALYZED}); manual review"
            )
    elif not require_two_signals and susp:
        verdict = MALICIOUS
        reasons.append(f"{len(susp)} suspicious function(s)")
    elif not require_two_signals and high:
        verdict = MALICIOUS
        reasons.append(f"{len(high)} high-authority (YARA) finding(s)")
    elif conflicts:
        verdict = NEEDS_REVIEW
        reasons.append(f"{len(conflicts)} benign claim(s) conflict with evidence")
    elif unverified:
        verdict = NEEDS_REVIEW
        reasons.append(f"{len(unverified)} unverified critical finding(s) (string not found in the "
                       "file bytes); cannot support a malicious verdict")
    elif medium:
        verdict = NEEDS_REVIEW
        reasons.append(f"{len(medium)} medium-authority finding(s) (capa/import/IoC/script)")
    elif low:
        verdict = NEEDS_REVIEW
        reasons.append(f"{len(low)} C2-like string(s) without corroborating code evidence")
    elif analyzed and len(unknown_fns) == len(analyzed):
        verdict = UNKNOWN
        unknown_reasons.append("all analyzed functions returned unknown")
    elif total == 0:
        verdict = UNKNOWN
        unknown_reasons.append("no analyzable functions")
    elif packed:
        verdict = UNKNOWN
        unknown_reasons.append("packed sample; analysis surface incomplete")
    elif tool_failures:
        verdict = UNKNOWN
        unknown_reasons.append(f"{len(tool_failures)} tool failure(s)")
    elif analysis_failures:
        verdict = UNKNOWN
        unknown_reasons.append(f"{len(analysis_failures)} analysis failure(s)")
    elif coverage < min_coverage:
        verdict = UNKNOWN
        unknown_reasons.append(f"coverage {coverage:.0%} < {min_coverage:.0%}")
    else:
        verdict = NO_EVIDENCE
        reasons.append("covered surface analyzed; no malicious evidence found")

    if unverified and verdict != NEEDS_REVIEW:
        reasons.append(f"{len(unverified)} unverified critical finding(s) ignored as evidence")
    if fail_closed:
        reasons.append(f"{len(fail_closed)} function(s) fail-closed over a benign LLM verdict")
    if unknown_fns:
        unknown_reasons.append(f"{len(unknown_fns)} function(s) returned unknown")
    encrypted = [f for f in _unique_findings(findings)
                 if (f.source or "").lower() == "script"
                 and (f.kind or "").lower() == ENCRYPTED_PAYLOAD_KIND]
    if encrypted:
        note = (f"{len(encrypted)} encrypted payload(s) in the script could not be decoded "
                "statically (not counted as evidence)")
        (unknown_reasons if verdict == UNKNOWN else reasons).append(note)
        next_actions.append("recover the payload key from the script or analyze the payload "
                            "dynamically in a sandbox")

    if verdict == UNKNOWN:
        if packed:
            next_actions.append("unpack the sample and re-run static analysis")
        if total and coverage < min_coverage:
            next_actions.append("analyze the skipped functions (raise budget or priority)")
        if tool_failures or analysis_failures:
            next_actions.append("inspect/re-run failed tools or functions")
        if not total:
            next_actions.append("run Ghidra decompilation first")
        if not any("dynamic" in a for a in next_actions):
            next_actions.append("run dynamic analysis")

    return {
        "verdict": verdict,
        "reasons": reasons,
        "unknown_reasons": unknown_reasons,
        "next_actions": next_actions,
        "coverage": {
            "total": total,
            "decompiled": len(decompiled),
            "analyzed": len(analyzed),
            "failed": len(failed),
            "skipped": total - len(analyzed),
            "ratio": coverage,
            "min_required": min_coverage,
        },
        "counts": {
            "suspicious_functions": len(susp),
            "unknown_functions": len(unknown_fns),
            "failed_functions": len(failed),
            "fail_closed": len(fail_closed),
            "critical_findings": len(critical),
            "unverified_critical": len(unverified),
            "high_authority": len(high),
            "medium_findings": len(medium),
            "c2_like": len(low),
            "conflicts": len(conflicts),
            "signals": sorted(signals),
            "two_signal": two_signal,
            "single_strong_signal": bool(strong) and not two_signal,
            "llm_high_confidence": llm_high,
            "behavior_classes": len(behavior_classes),
            "total_functions": total,
            "decompiled_functions": len(decompiled),
            "skipped_functions": total - len(analyzed),
        },
        "critical_findings": [
            {"id": finding_id(f), "source": f.source, "kind": f.kind,
             "value": (f.value or "")[:160], "address": f.address,
             "tier": "high" if is_high_authority(f) else "c2_like"}
            for f in critical[:20]
        ],
        "unverified_findings": [
            {"id": finding_id(f), "source": f.source, "kind": f.kind,
             "value": (f.value or "")[:160], "address": f.address, "tier": "unverified"}
            for f in unverified[:20]
        ],
        "medium_findings": [
            {"id": finding_id(f), "source": f.source, "kind": f.kind,
             "value": (f.value or "")[:160], "address": f.address, "tier": "medium"}
            for f in medium[:20]
        ],
        "conflicts": conflicts[:20],
        "tool_failures": tool_failures[:20],
        "analysis_failures": analysis_failures[:20],
    }
