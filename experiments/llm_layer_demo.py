#!/usr/bin/env python3
"""LLM katmani demosu — dis veri gerektirmez.

Kullanim:
    python experiments/llm_layer_demo.py
    CROWBAR_LLM_MODEL=qwen8:latest python experiments/llm_layer_demo.py

Gercek Ghidra ciktisi (ExportC JSON: [{offset,name,c_code}, ...]) vermek icin:
    python experiments/llm_layer_demo.py /path/functions.json
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from llm_layer import Finding, FunctionInfo, LLMClient, analyze  # noqa: E402
from llm_layer.factory import from_env  # noqa: E402

BUILTIN = [
    {
        "offset": "0x401000",
        "name": "decode",
        "c_code": "void decode(char *buf,int n,unsigned char key){"
                  " for(int i=0;i<n;i++){ buf[i]=(char)(buf[i]^key); } }",
        "callees": [],
    },
    {
        "offset": "0x4010a0",
        "name": "wrapper",
        "c_code": "int wrapper(char *s,int n){ decode(s,n,0x5a);"
                  " return checksum((unsigned char*)s,n); }",
        "callees": ["0x401000"],
    },
]


def load(path: str | None) -> list[FunctionInfo]:
    if not path:
        items = BUILTIN
    else:
        with open(path, encoding="utf-8") as fh:
            items = json.load(fh)
    return [FunctionInfo(
        offset=it.get("offset", ""),
        name=it.get("name", ""),
        c_code=it.get("c_code", ""),
        priority=it.get("priority", 0),
        callees=list(it.get("callees", []) or []),
        is_library=bool(it.get("is_library", False)),
    ) for it in items]


def main() -> None:
    client = from_env()
    fns = load(sys.argv[1] if len(sys.argv) > 1 else None)
    findings = [Finding(source="capa", kind="capability", value="string decoding",
                        address=fns[0].offset)] if fns else []
    res = analyze(fns, findings, client, budget_tokens=4000)

    print(f"model={client.model} provider={client.provider} "
          f"calls={res.calls} token={res.token_total()}")
    for off, s in res.summaries.items():
        print(f"\n--- {s.name_or_offset()} @ {off} ---")
        print(f"summary: {s.summary}")
        print(f"suspicious={s.suspicious} confidence={s.confidence}")
        for c in s.claims:
            print(f"  [{c.status}] {c.text[:80]}")
    if res.failures:
        print("\nHATALAR:", *res.failures, sep="\n  ")


if __name__ == "__main__":
    main()
