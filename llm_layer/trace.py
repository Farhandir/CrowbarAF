"""LLM analiz izi (trace): ne incelendi, ne atlandi, kac token, hangi iddia.

Amac: LLM katmaninin "kara kutu" olmaktan cikmasi. Her kosu JSON olarak
kaydedilir; insan-okunur raporu `experiments/trace_report.py` basar.
"""
from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field


@dataclass
class Tracer:
    model: str = ""
    provider: str = ""
    budget_tokens: int = 0
    skip_library: bool = True
    started: str = field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%S"))
    finished: str | None = None
    functions: list[dict] = field(default_factory=list)
    events: list[dict] = field(default_factory=list)
    totals: dict = field(default_factory=dict)
    _t0: float = field(default_factory=time.monotonic, repr=False)

    # --- kayit ---
    def event(self, kind: str, **data) -> None:
        self.events.append({"elapsed_s": round(time.monotonic() - self._t0, 3),
                            "kind": kind, **data})

    def skipped(self, fn, reason: str) -> None:
        self.functions.append({
            "offset": fn.offset, "name": fn.name, "priority": fn.priority,
            "status": "skipped", "skip_reason": reason,
        })
        self.event("skip", offset=fn.offset, reason=reason)

    def analyzed(self, fn, ctx_stats: dict, res, summary, duration_s: float,
                 children: list[str], n_findings: int, cached: bool = False) -> None:
        claims = [{"text": c.text, "evidence": c.evidence, "status": c.status}
                  for c in summary.claims]
        prompt = getattr(res, "prompt_tokens", None)
        completion = getattr(res, "completion_tokens", None)
        self.functions.append({
            "offset": fn.offset, "name": fn.name, "priority": fn.priority,
            "status": "analyzed",
            "cached": cached,
            "context_tokens": ctx_stats.get("estimated_tokens"),
            "chars_per_token": ctx_stats.get("chars_per_token"),
            "code_truncated": ctx_stats.get("code_truncated"),
            "children_included": children,
            "findings_included": n_findings,
            "prompt_tokens": prompt,
            "completion_tokens": completion,
            "duration_s": round(duration_s, 2),
            "json_ok": ctx_stats.get("json_ok"),
            "summary": summary.summary,
            "suspicious": summary.suspicious,
            "confidence": summary.confidence,
            "claims": claims,
        })
        self.event("analyze", offset=fn.offset, tokens=prompt, cached=cached)

    def finalize(self, result) -> None:
        self.finished = time.strftime("%Y-%m-%dT%H:%M:%S")
        analyzed = [f for f in self.functions if f["status"] == "analyzed"]
        skipped = [f for f in self.functions if f["status"] == "skipped"]
        total = len(self.functions)
        verified = sum(1 for f in analyzed for c in f.get("claims", [])
                       if c["status"].startswith("verified"))
        unverified = sum(1 for f in analyzed for c in f.get("claims", [])
                         if c["status"] == "unverified")
        full_code_tokens = sum(
            (f.get("context_tokens") or 0) for f in analyzed)
        self.totals = {
            "functions_total": total,
            "functions_analyzed": len(analyzed),
            "functions_skipped": len(skipped),
            "skipped_library": sum(1 for f in skipped if f["skip_reason"] == "library"),
            "skipped_budget": sum(1 for f in skipped if f["skip_reason"] == "budget"),
            "skipped_priority": sum(1 for f in skipped if f["skip_reason"] == "priority"),
            "coverage": round(len(analyzed) / total, 3) if total else 0.0,
            "calls": result.calls,
            "cache_hits": getattr(result, "cache_hits", 0),
            "prompt_tokens": result.total_prompt_tokens,
            "completion_tokens": result.total_completion_tokens,
            "tokens_total": result.token_total(),
            "verified_claims": verified,
            "unverified_claims": unverified,
            "failures": len(result.failures),
            "context_tokens_sum": full_code_tokens,
        }
        self.event("finalize", **self.totals)

    # --- cikti ---
    def to_dict(self) -> dict:
        return {
            "run": {
                "model": self.model, "provider": self.provider,
                "budget_tokens": self.budget_tokens,
                "skip_library": self.skip_library,
                "started": self.started, "finished": self.finished,
            },
            "totals": self.totals,
            "functions": self.functions,
            "events": self.events,
        }

    def save(self, path: str) -> str:
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(self.to_dict(), fh, ensure_ascii=False, indent=2)
        return path
