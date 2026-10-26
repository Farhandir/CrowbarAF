"""One-shot LLM connectivity smoke test.

Reads the client from environment variables and prints the response, token
usage and (for OpenCode Go) the billing source. It never prints the API key.

Usage:
    python -m llm_layer.smoke
"""
from __future__ import annotations

import sys
import time

from .factory import from_env


def main() -> None:
    c = from_env()
    print(f"provider={c.provider} model={c.model} base_url={c.base_url}")
    print(f"user_agent={c.user_agent} session_id={c.session_id or '-'}")

    t = time.time()
    try:
        r = c.chat(
            [{"role": "user", "content": "Reply with the single word: OK"}],
            json_mode=False, temperature=0,
        )
    except Exception as exc:  # noqa: BLE001
        print(f"FAILED: {type(exc).__name__}: {str(exc)[:500]}")
        sys.exit(1)

    print(f"content={r.content[:200]!r}")
    print(f"tokens prompt={r.prompt_tokens} completion={r.completion_tokens} "
          f"time={time.time() - t:.1f}s")

    raw = r.raw or {}
    usage = raw.get("usage", {}) or {}
    oc = usage.get("opencode", {}) or {}
    if oc:
        print(f"billing_source={oc.get('billing_source')} "
              f"allowance={oc.get('allowance')} cost={usage.get('cost')}")
    elif usage:
        print(f"usage={usage}")

    # Structured-output check (some endpoints reject response_format).
    try:
        r2 = c.chat(
            [{"role": "user", "content": 'Return exactly {"ok": true}'}],
            json_mode=True, temperature=0,
        )
        mode = "prompt-only fallback" if c.json_mode_supported is False else "response_format"
        print(f"json_mode=ok ({mode}) content={r2.content[:120]!r}")
    except Exception as exc:  # noqa: BLE001
        print(f"json_mode=FAILED: {type(exc).__name__}: {str(exc)[:300]}")


if __name__ == "__main__":
    main()
