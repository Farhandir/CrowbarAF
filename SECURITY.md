# Security Policy

## Reporting a vulnerability

Please **do not** open a public issue for security problems.

Use GitHub's private vulnerability reporting for this repository:

- Repository → **Security** → **Report a vulnerability**

Include:

- affected version/commit,
- reproduction steps or a minimal sample,
- impact assessment,
- whether the issue involves the LLM layer, a parser, the UI/API, or sample handling.

Do not attach real malware or API keys to a report. If a sample is required,
share a hash and a safe transfer method first.

## Scope

- CrowbarAF code, prompts, context selection, verdict policy.
- UI/API and SQLite persistence.
- Sandbox/split-mode scripts and state validation.
- Supply-chain/dependency issues.

## Out of scope

- Malware samples themselves.
- Third-party tools (Ghidra, capa, FLOSS, YARA, UPX) — report upstream.
- Findings caused by running real malware outside the documented isolation model.
