<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/crowbaraf-banner-dark.png">
    <img src="docs/assets/crowbaraf-banner-light.png" alt="CrowbarAF" width="480">
  </picture>
</p>

<p align="center">
  <b>Pry the sample open. Keep the evidence. Never fake certainty.</b><br>
  Deterministic-first static malware analysis with a context-efficient,
  fail-closed LLM layer.
</p>

<p align="center">
  LangGraph · Ghidra · capa · FLOSS · YARA · SQLite ·
  Ollama / vLLM / OpenCode Go
</p>

---

## Why

Static malware analysis produces a lot of evidence and very little certainty.
CrowbarAF runs the deterministic tools first, then gives an LLM **only the
evidence it needs** — with provenance, token budgets, and a verdict that fails
closed instead of guessing.

The design goal is not "an AI that decides". It is:

> **Deterministic tools observe. The LLM explains. The evidence decides.**

---

## Architecture

```mermaid
flowchart LR
    S["Sample"] --> T["DIE + YARA triage"]
    T --> U{"Packed?"}
    U -->|"UPX / PyInstaller / .NET"| V["Unpacked sample"]
    U -->|"native"| V
    V --> F1["capa"]
    V --> F2["FLOSS"]
    V --> F3["imports / imphash"]
    V --> F4["entropy"]
    V --> F5["PE metadata"]
    F1 --> G["Ghidra<br/>priority + IoC xref"]
    F2 --> G
    F3 --> G
    F4 --> G
    F5 --> G
    G --> L["LLM layer<br/>budgeted + evidence-grounded"]
    L --> R["Verdict + report<br/>MD / HTML / JSON"]
    R --> D[(SQLite)]
    D --> UI["FastAPI UI"]
```

| Stage | What happens |
|---|---|
| **Triage** | DIE identifies type/packer/arch; YARA matches rules. |
| **Unpack** | UPX, PyInstaller and .NET are handled before static analysis. |
| **Static features** | capa capabilities, FLOSS strings/IoCs, imports/imphash, section entropy, PE metadata. |
| **Ghidra** | Functions are scored and decompiled; string xrefs map IoCs to functions. |
| **LLM layer** | Per-function summaries under a token budget, with verified claims. |
| **Verdict** | Four deterministic states — never `clean`. |
| **Output** | Markdown/HTML/JSON report, SQLite, FastAPI UI. |


### What happens to a sample

1. **Triage** — DIE identifies the format/packer; YARA checks known rules.
2. **Unpack** — UPX, PyInstaller and .NET are unpacked before analysis.
3. **Collect evidence** — capa, FLOSS, imports/imphash, entropy, PE metadata.
4. **Decompile + map** — Ghidra scores functions, decompiles the important ones,
   and links string IoCs to functions by xref.
5. **Analyze under budget** — the LLM gets local findings plus a global digest;
   critical findings are always included.
6. **Verify** — claims are checked against code/findings; instruction-like tool
   text is quarantined.
7. **Decide** — fail-closed verdict (`malicious` / `needs_review` / `unknown` /
   `no_evidence`).
8. **Persist** — trace, SQLite, Markdown/HTML/JSON and the FastAPI UI.

---

## The LLM layer

```mermaid
flowchart TD
    A["Functions + findings"] --> B["Priority selection"]
    B --> C["Must-include<br/>critical findings + xrefs"]
    B --> D["Local findings<br/>address-matched"]
    B --> E["Global digest<br/>ranked + budgeted"]
    C --> F["Per-function prompt<br/>DATA: JSON"]
    D --> F
    E --> F
    F --> G["LLM summary<br/>strict JSON"]
    G --> H["Claim verifier<br/>verified / file-level / unverified"]
    H --> I{"Fail-closed"}
    I -->|"benign + critical finding"| J["unknown"]
    I -->|"benign, no critical"| K["benign function"]
    I -->|"suspicious"| L["malicious"]
    J --> V["File verdict"]
    K --> V
    L --> V
    V --> O["malicious / needs_review / unknown / no_evidence"]
```

- **Context-efficient:** priority selection, per-function budgets, soft budgets
  for low-priority functions, optional priority threshold, bottom-up summaries
  in call-graph SCC order.
- **Decision recall first:** critical findings (YARA, high-confidence
  capa/IoC, C2-like URLs) are **must-include** — they bypass priority and the
  budget. A priority-0 payload is still caught when the evidence points at it.
- **Evidence as data:** findings are rendered as `DATA: {...}` JSON. Instruction-
  like strings are quarantined; the original stays in the trace.
- **Claims are graded:** every AI claim is `verified_claim`,
  `verified_observation`, `file_level` or `unverified`.
- **Fail-closed:** a benign LLM verdict cannot override a critical finding; the
  function becomes `unknown`, not `clean`.

Deep dive: [`docs/EVIDENCE-CHANNEL.md`](docs/EVIDENCE-CHANNEL.md).

---

## Evidence and verdicts

| Verdict | Meaning |
|---|---|
| `malicious` | Suspicious function(s) or a YARA hit. |
| `needs_review` | Medium-authority evidence (capa/import/IoC), a C2-like string, or a conflict. |
| `unknown` | Coverage too low, packed sample, tool/analysis failure. |
| `no_evidence` | Covered surface analyzed; no malicious evidence found. |

**There is no `clean`.** Absence of evidence is reported as a scoped
`no_evidence` or `unknown`, with coverage and reasons attached.

---

## Deterministic tools

| Tool | Contribution |
|---|---|
| **DIE** | File type, architecture, packer/protector. |
| **YARA** | Rule matches (high-authority evidence). |
| **capa** | Capabilities, ATT&CK/MBC, function hints. |
| **FLOSS** | Decoded/stack/static strings; IP/URL/registry/file IoCs. |
| **readelf / pefile** | Imports, imphash, section entropy. |
| **PE metadata** | Authenticode presence, version info, manifest execution level. |
| **Ghidra** | Decompilation, priority scoring, string→function IoC xrefs. |

Missing external tools degrade gracefully; the run continues with what is
available and the verdict reflects the coverage.

---

## Ecosystem: attack, defense, memory

```mermaid
flowchart LR
    GL["Gaslighter<br/>attacks + measurement"] -->|"attacks"| CA["CrowbarAF<br/>defense + verdict"]
    CA -->|"traces / verdicts"| AR[(results archive)]
    GL -->|"raw results"| AR
    AR -->|"same config"| API["API / frontier A/B"]
```

- **CrowbarAF** (this repo) — the defense: analysis, context budgeting,
  evidence verification, fail-closed verdicts.
- **Gaslighter** — the attack: obfuscation, prompt injection, decoys, packing,
  paraphrase/encoded instructions, and the measurement harness.
- **`results/archive/`** — comparable records: same dataset + config, raw
  outputs, and the honest limits of each run.

---

## Measured, not promised

Synthetic, harmless samples. Numbers are real; scale is not production malware.

| Finding | Result |
|---|---|
| Threshold + must-include | **13.5× / 64.9×** fewer tokens on flood/overflow **with the payload found** |
| Tool-output injection | **blocked 3/3** after data fencing + quarantine + fail-closed |
| Paraphrase / base64 / ROT13 / split | quarantine evaded, **verdict held** (fail-closed) |
| Packing (UPX) | tools blind, 8.6× cost; `upx -d` restores the payload |
| Semantic evidence attacks | no flip on fake reputation/conflict |
| S1 scale ladder (DeepSeek) | naive 543k tokens at 1,000 fn and **HTTP 400 at 2,000**; threshold **904–929 tokens**, payload held |
| S2/S3 real SQLite (A policy) | benign **needs_review** (no malicious FP); injected **malicious**, payload caught; threshold 2.8× cheaper, 3–4× slower after 8 workers |
| S4 packed/encoded | UPX is unpacked and the payload held; an encoded decoded-only payload is **missed by threshold** (390 tokens), caught by soft (20k, 74.6 s) |

Full records, metrics and caveats:
[`results/archive/README.md`](results/archive/README.md).

---

## Quick start

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
pip install -r requirements-tools.txt      # optional: capa, floss, yara-python, ...

cp .env.example .env
# edit .env (local Ollama or an API provider)
set -a; . ./.env; set +a

python main.py <sample>                    # analysis + state JSON
python main.py --serve                     # UI/API at http://127.0.0.1:8000
python report.py <state.json> --format md --out reports/
```

### Using OpenCode Go (OpenAI-compatible)

```bash
export CROWBAR_LLM_PROVIDER="openai"
export CROWBAR_LLM_BASE_URL="https://opencode.ai/inference/go/openai"
export CROWBAR_LLM_MODEL="deepseek-v4.1-flash"
export CROWBAR_LLM_API_KEY="..."           # never commit
export CROWBAR_LLM_USER_AGENT="crowbaraf/0.1"
export CROWBAR_LLM_SESSION_ID="crowbaraf-run-1"
```

`LLMClient` sends the Go-required user agent/session headers and falls back to
prompt-only JSON if `response_format` is rejected.

### Scale knobs

For large samples, raise the decompile cap and tool timeouts instead of guessing:

```bash
export CROWBAR_MAX_DECOMPILE=100          # Ghidra top-N (default 100)
export CROWBAR_LLM_MAX_WORKERS=8           # per-level LLM parallelism
export CROWBAR_FALLBACK_DECOMPILE=20
export CROWBAR_GHIDRA_TIMEOUT=1200        # seconds
export CROWBAR_CAPA_TIMEOUT=600
export CROWBAR_FLOSS_TIMEOUT=600
export CROWBAR_READELF_TIMEOUT=60
```

Full setup: [`docs/SETUP.md`](docs/SETUP.md).

---

## Project layout

```text
CrowbarAF/
├── main.py / graph.py / nodes.py    # LangGraph pipeline
├── llm_layer/                       # context, prompts, verifier, verdict
├── export_functions.py              # Ghidra: priority + IoC xref
├── db.py / report.py                # SQLite + MD/HTML/JSON
├── docs/                            # setup, LLM layer, evidence channel
├── tests/                           # pipeline + LLM-layer tests
├── results/archive/                 # comparable experiment records
└── docs/assets/                     # logo
```

---

## Docs

- [`docs/SETUP.md`](docs/SETUP.md) — installation, tools, environment
- [`docs/LLM-LAYER.md`](docs/LLM-LAYER.md) — LLM layer design and usage
- [`docs/EVIDENCE-CHANNEL.md`](docs/EVIDENCE-CHANNEL.md) — evidence hardening,
  fail-closed verdicts, injection/recall notes
- [`docs/PIPELINE-HANDOFF.md`](docs/PIPELINE-HANDOFF.md) — data contract and TODOs
- [`docs/TOOL-ADDITIONS.md`](docs/TOOL-ADDITIONS.md) — how to add analysis tools
- [`results/archive/README.md`](results/archive/README.md) — experiment setup,
  records, metrics and pitfalls

---

## Status and limits

- End-to-end verified on harmless ELF/PE samples: triage → unpack → static
  features → Ghidra → LLM → SQLite/UI.
- Local 9B precision is limited; the LLM is an assistant, not a verdict
  authority. Frontier comparison is ongoing.
- Test scale is still small; real malware has thousands of functions and
  stronger packers/obfuscation.
- Unknown is not clean: every negative is scoped by coverage and reasons.
