"""Deterministic file-level verdict and fail-closed policy.

Four states (never "clean"):
  malicious     : suspicious function(s) or a high-authority (YARA) finding
  needs_review  : medium-authority evidence (capa/import combo/IoC), C2-like
                  string, or a conflict
  unknown       : coverage too low, packed, tool failure, no functions
  no_evidence   : covered surface analyzed, no malicious evidence found

Integrity: a critical finding with ``verified=False`` (a statically extracted text IoC
that is not present in the file bytes) is never evidence for "malicious"; it only
escalates the verdict to needs_review (and still overrides a benign LLM verdict).
"""
from __future__ import annotations

import hashlib
import os
import re

from .types import Finding, FunctionInfo, FunctionSummary

MALICIOUS = "malicious"
NEEDS_REVIEW = "needs_review"
UNKNOWN = "unknown"
NO_EVIDENCE = "no_evidence"

_URL_RE = re.compile(r"https?://|(?:\d{1,3}\.){3}\d{1,3}")
_BENIGN_CLAIM = ("benign", "clean", "not malicious", "no malicious", "signed",
                 "harmless", "no threat", "0/70", "safe")

# YARA is the only source that can stand alone as "malicious".
HIGH_AUTHORITY = {"yara"}
# Dual-use / supporting signals: they can require review, not a malicious verdict.
MEDIUM_AUTHORITY = {"capa", "import_combo", "ioc"}
CONFIDENCE_FLOOR = 0.7
LLM_MIN_SUSPICIOUS = int(os.getenv("CROWBAR_LLM_MIN_SUSPICIOUS", "3"))
LLM_MIN_BEHAVIORS = int(os.getenv("CROWBAR_LLM_MIN_BEHAVIORS", "2"))
LLM_MIN_COVERAGE = float(os.getenv("CROWBAR_LLM_MIN_COVERAGE", "0.6"))

# LLM summaries are one signal; multiple distinct behavior classes are required
# before a single-source LLM verdict may be promoted to malicious.
BEHAVIOR_KEYWORDS = {
    "persistence": ("persist", "cron", "systemd", "rc.local", "watchdog", "init"),
    "execution": ("exec", "system(", "shell", "spawn", "fork", "subprocess"),
    "network": ("socket", "connect", "c2", "http", "dns", "bot", "network"),
    "process": ("kill", "process", "pid", "locker", "watchdog"),
    "file": ("file", "unlink", "delete", "hidden", "copy", "drop"),
    "memory": ("mmap", "memory", "inject", "virtualalloc", "protect"),
}


def finding_id(f: Finding) -> str:
    if f.finding_id:  # nodes.compute_finding_id: DB/state ile aynı kimlik
        return f.finding_id
    raw = f"{f.source}|{f.kind}|{f.value}|{f.address}"
    return "f_" + hashlib.sha1(raw.encode("utf-8", "replace")).hexdigest()[:12]


def is_critical_finding(f: Finding) -> bool:
    """Findings that force must-include / fail-closed (YARA, high IOC, C2-like)."""
    src = (f.source or "").lower()
    if src == "yara":
        return True
    if src == "ioc" and (f.confidence or 0) >= CONFIDENCE_FLOOR:
        return True
    # C2-like strings are critical even from FLOSS: a URL/IP in a finding value.
    if src in ("floss", "ioc") and _URL_RE.search(f.value or ""):
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


def apply_fail_closed(summary: FunctionSummary, fn: FunctionInfo,
                      findings: list[Finding]) -> FunctionSummary:
    """If the LLM says benign but a critical finding is relevant, return unknown."""
    if summary.suspicious is not False:
        return summary
    relevant = [f for f in findings if not f.address or f.address == fn.offset]
    critical = [f for f in relevant if is_critical_finding(f)]
    if not critical:
        return summary
    # Doğrulanmamış (binary'de bulunamayan) kritik bulgu da "temiz" kararını geçersiz kılar
    # (fail-closed: unknown), ama dosya kararında malicious üretemez (compute_verdict).
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
    analyzed = [f for f in decompiled if f.offset in summaries]
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
    strong = signals & {"llm", "yara", "c2"}
    two_signal = len(signals) >= 2 and bool(strong)

    # LLM-only high-confidence tier: several suspicious functions and multiple
    # distinct behavior classes, with enough coverage. This is still one source;
    # it is deliberately gated and configurable, not a replacement for C.
    behavior_classes: set[str] = set()
    for fn in susp:
        summary = summaries[fn.offset]
        for behavior in (summary.behaviors or []):
            norm = re.sub(r"\s+", " ", str(behavior).strip().lower())
            if norm:
                behavior_classes.add(norm)
        text = (summary.summary or "").lower()
        for label, words in BEHAVIOR_KEYWORDS.items():
            if any(word in text for word in words):
                behavior_classes.add(label)
    llm_high = (require_two_signals and bool(susp)
                and len(susp) >= LLM_MIN_SUSPICIOUS
                and len(behavior_classes) >= LLM_MIN_BEHAVIORS
                and coverage >= LLM_MIN_COVERAGE)

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
        reasons.append("single strong signal (" + ", ".join(sorted(strong))
                       + "); corroboration required")
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
        reasons.append(f"{len(medium)} medium-authority finding(s) (capa/import/IoC)")
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
            "skipped": total - len(analyzed),
            "ratio": coverage,
            "min_required": min_coverage,
        },
        "counts": {
            "suspicious_functions": len(susp),
            "unknown_functions": len(unknown_fns),
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
