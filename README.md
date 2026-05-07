# Web3 AI Bounty Tools

Reusable skills, prompts, scripts, and templates for Web3/AI bug bounty research.

## What this is

A public toolkit for Web3 and AI-agent security researchers focused on:

- PoC-first vulnerability validation
- Foundry PoC scaffolding
- evidence-gated bug bounty workflows
- report-readiness checks
- duplicate/N/A risk reduction
- reusable AI skills for codebase review, hypothesis generation, PoC writing, and report drafting

## What this is not

- not an autonomous bug hunter
- not a replacement for professional auditors
- not a guarantee of bounty rewards
- not a place for real private target data
- not a repo for secrets, logs, cookies, RPC URLs, or unsanitized reports

## Core workflow

Lead → Hypothesis → Code Review → PoC → Evidence Gate → Report Gate → Submit / Kill / Archive

## Repository layout

- `skills/` — reusable AI-agent skills for Web3/AI bug bounty workflows.
- `prompts/` — reusable prompt snippets, Opencode command prompts, and agent definitions.
- `framework/` — reusable scripts, helpers, and workflow logic. Imported Web3 scripts currently live under `skills/web3-ai-bounty/scripts/` to preserve skill-relative paths.
- `templates/` — reusable finding folders, status files, report templates, and PoC templates.
- `docs/` — short workflow, safety, evidence, report-readiness, and sanitization notes.
- `examples/` — toy/synthetic examples only. Do not add real private bounty target data.
- `benchmarks/` — sanitized benchmark definitions or summaries only. Do not add private corpora or raw target data.
- `targets/` — placeholder area for sanitized target notes only. Do not commit real private target data.
- `generated/` — generated artifacts are ignored by default. Commit only safe README/placeholders.
- `scratch/` — local temporary workspace ignored by default. Do not commit scratch work.
- `archives/` — sanitized old experiments or summaries only. Do not commit secrets, raw logs, or private reports.

## Skills

Planned reusable skills:

- `web3-bounty-xray`
- `poc-first-validator`
- `foundry-poc-writer`
- `evidence-gate-reviewer`
- `report-readiness-checker`
- `duplicate-na-risk-checker`
- `ai-agent-web3-threat-modeler`

Imported Opencode skills are also included under `skills/`, including `web3-ai-bounty`, `web3-audit`, `bug-bounty`, `triage-validation`, and related workflow skills.

## Usage

Example agent prompts:

```text
Use the poc-first-validator skill to review this finding and decide whether it is report-ready or should be killed.
```

```text
Use the foundry-poc-writer skill to turn this hypothesis into an exploit test and a control test.
```

```text
Use the duplicate-na-risk-checker skill to identify why this report may get duplicate or N/A.
```

## Safety

Only use this toolkit for authorized security research, bug bounty programs, private labs, CTFs, and owned code.

Never commit:

- private keys
- seed phrases
- wallet files
- `.env` files
- RPC URLs
- API tokens
- session cookies
- private platform messages
- real user data
- unsanitized target reports
- raw exploit logs

## License

License placeholder: MIT is recommended unless a different license is chosen.
