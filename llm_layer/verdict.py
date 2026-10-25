"""Deterministic file-level verdict and fail-closed policy.

Four states (never "clean"):
  malicious     : suspicious function(s) or high-authority critical finding
  needs_review  : conflict, or only a low-authority C2-like string
  unknown       : coverage too low, packed, tool failure, no functions
  no_evidence   : covered surface analyzed, no malicious evidence found
"""
from __future__ import annotations

import hashlib
import re

from .types import Finding, FunctionInfo, FunctionSummary

MALICIOUS = "malicious"
NEEDS_REVIEW = "needs_review"
UNKNOWN = "unknown"
NO_EVIDENCE = "no_evidence"

_URL_RE = re.compile(r"https?://|(?:\d{1,3}\.){3}\d{1,3}")
_BENIGN_CLAIM = ("benign", "clean", "not malicious", "no malicious", "signed",
                 "harmless", "no threat", "0/70", "safe")

HIGH_AUTHORITY = {"yara", "capa", "ioc"}
CONFIDENCE_FLOOR = 0.7


def finding_id(f: Finding) -> str:
    raw = f"{f.source}|{f.kind}|{f.value}|{f.address}"
    return "f_" + hashlib.sha1(raw.encode("utf-8", "replace")).hexdigest()[:12]


def is_critical_finding(f: Finding) -> bool:
    """A finding that can stand on its own against a benign LLM verdict."""
    src = (f.source or "").lower()
    if src == "yara":
        return True
    if src in HIGH_AUTHORITY and (f.confidence or 0) >= CONFIDENCE_FLOOR:
        return True
    if src in ("import", "import_combo") and f.kind == "import_combo" \
            and (f.confidence or 0) >= CONFIDENCE_FLOOR:
        return True
    # C2-like strings are critical even from FLOSS: a URL/IP in a finding value.
    if src in ("floss", "ioc") and _URL_RE.search(f.value or ""):
        return True
    return False


def is_high_authority(f: Finding) -> bool:
    src = (f.source or "").lower()
    if src == "yara":
        return True
    if src in HIGH_AUTHORITY and (f.confidence or 0) >= CONFIDENCE_FLOOR:
        return True
    if src in ("import", "import_combo") and f.kind == "import_combo" \
            and (f.confidence or 0) >= CONFIDENCE_FLOOR:
        return True
    return False


def _claims_benign(value: str) -> bool:
    low = (value or "").lower()
    return any(m in low for m in _BENIGN_CLAIM)


def apply_fail_closed(summary: FunctionSummary, fn: FunctionInfo,
                      findings: list[Finding]) -> FunctionSummary:
    """If the LLM says benign but a critical finding is relevant, return unknown."""
    if summary.suspicious is not False:
        return summary
    relevant = [f for f in findings if f.address is None or f.address == fn.offset]
    if not any(is_critical_finding(f) for f in relevant):
        return summary
    summary.suspicious = None
    summary.fail_closed = True
    note = "fail-closed: critical finding present"
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
) -> dict:
    """Compute the file-level verdict with explicit coverage and reasons."""
    summaries = summaries or {}
    tool_failures = [x for x in (tool_failures or []) if x]
    analysis_failures = [x for x in (analysis_failures or []) if x]
    analyzable = [f for f in functions if (f.c_code or "").strip() and not f.is_library]
    analyzed = [f for f in analyzable if f.offset in summaries]
    total = len(analyzable)
    coverage = round(len(analyzed) / total, 3) if total else 0.0

    susp = [f for f in analyzed if summaries[f.offset].suspicious is True]
    unknown_fns = [f for f in analyzed if summaries[f.offset].suspicious is None]
    fail_closed = [f for f in analyzed if summaries[f.offset].fail_closed]

    critical = [f for f in findings if is_critical_finding(f)]
    high = [f for f in critical if is_high_authority(f)]
    low = [f for f in critical if not is_high_authority(f)]
    conflicts = []
    if high or susp:
        conflicts = [
            {"finding": {"id": finding_id(f), "source": f.source, "value": (f.value or "")[:160]}}
            for f in findings if _claims_benign(f.value)
        ]

    reasons: list[str] = []
    unknown_reasons: list[str] = []
    next_actions: list[str] = []

    if susp:
        verdict = MALICIOUS
        reasons.append(f"{len(susp)} suspicious function(s)")
    elif high:
        verdict = MALICIOUS
        reasons.append(f"{len(high)} high-authority critical finding(s)")
    elif conflicts:
        verdict = NEEDS_REVIEW
        reasons.append(f"{len(conflicts)} benign claim(s) conflict with critical evidence")
    elif low:
        verdict = NEEDS_REVIEW
        reasons.append(f"{len(low)} C2-like string(s) without corroborating code evidence")
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
            "high_authority": len(high),
            "c2_like": len(low),
            "conflicts": len(conflicts),
        },
        "critical_findings": [
            {"id": finding_id(f), "source": f.source, "kind": f.kind,
             "value": (f.value or "")[:160], "address": f.address,
             "tier": "high" if is_high_authority(f) else "c2_like"}
            for f in critical[:20]
        ],
        "conflicts": conflicts[:20],
        "tool_failures": tool_failures[:20],
        "analysis_failures": analysis_failures[:20],
    }
