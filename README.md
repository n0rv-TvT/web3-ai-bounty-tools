# Web3 AI Bounty Tools

> PoC-first Web3/AI bug bounty skills, prompts, scripts, and evidence-gated workflows.

Reusable skills, prompts, scripts, templates, and toy examples for authorized Web3 and AI-agent security research.

**Supported AI workflows:** Claude Code, OpenCode, Codex-style agents, Cursor, GitHub Copilot, Windsurf, and other coding-agent environments that can load markdown skills/prompts.

---

## What this is

This repository is a public Web3/AI bug bounty toolkit focused on:

- PoC-first vulnerability validation
- Foundry PoC planning and scaffolding
- evidence-gated bug bounty workflows
- execution safety gating before PoC/RPC/tool runs
- report-readiness checks
- duplicate and N/A risk reduction
- reusable AI skills for codebase review, hypothesis generation, PoC writing, and report drafting
- AI-agent/Web3 threat modeling for signing, transaction submission, tool use, memory, and data leakage boundaries

Core workflow:

```text
Lead → Hypothesis → Code Review → PoC → Evidence Gate → Report Gate → Submit / Kill / Archive
```

The goal is not to produce more speculative findings. The goal is to **prove strong findings and kill weak ones early**.

---

## What this is not

- not an autonomous bug hunter
- not a replacement for professional auditors
- not a guarantee of bounty rewards
- not a repo for real private target data
- not a repo for secrets, logs, cookies, RPC URLs, or unsanitized reports
- not a place to store exploit output from live systems

Use this only for authorized security research, bug bounty programs, private labs, CTFs, and owned code.

---

## Install / use prompts

Clone the repo:

```bash
git clone https://github.com/n0rv-TvT/web3-ai-bounty-tools.git
cd web3-ai-bounty-tools
```

Example agent prompts:

For Opencode, first verify or install the active runtime assets:

```bash
bash scripts/install-opencode-assets.sh --dry-run
bash scripts/install-opencode-assets.sh --verify
bash scripts/install-opencode-assets.sh --install
```

The installer is dry-run by default and backs up overwritten files under `~/.config/opencode/backups/web3-ai-bounty-tools/` during `--install`.

```text
Install https://github.com/n0rv-TvT/web3-ai-bounty-tools and use the poc-first-validator skill to decide whether this finding is report-ready or should be killed.
```

```text
Use the foundry-poc-writer skill to turn this hypothesis into an exploit test and a control test.
```

```text
Use the duplicate-na-risk-checker skill to identify why this report may get duplicate or N/A.
```

```text
Use the web3-ai-bounty skill to run a PoC-first bug bounty workflow on this authorized Solidity repo.
```

---

## Start here

| File | Purpose |
|---|---|
| [`skills/web3-ai-bounty/SKILL.md`](skills/web3-ai-bounty/SKILL.md) | Full Web3/AI bug bounty workflow |
| [`skills/poc-first-validator/SKILL.md`](skills/poc-first-validator/SKILL.md) | Decide prove/kill/report-ready |
| [`skills/foundry-poc-writer/SKILL.md`](skills/foundry-poc-writer/SKILL.md) | Convert hypotheses into Foundry PoC plans |
| [`skills/evidence-gate-reviewer/SKILL.md`](skills/evidence-gate-reviewer/SKILL.md) | Check evidence before report drafting |
| [`skills/report-readiness-checker/SKILL.md`](skills/report-readiness-checker/SKILL.md) | Run the 7-question report gate |
| [`docs/workflow.md`](docs/workflow.md) | Short workflow overview |
| [`docs/safety.md`](docs/safety.md) | Safety rules |
| [`examples/toy-vulnerable-vault/`](examples/toy-vulnerable-vault/) | Synthetic PoC-first example |

---

## Skills

### Core PoC-first bounty skills

| Skill | Description |
|---|---|
| [`web3-bounty-xray`](skills/web3-bounty-xray/) | Map contracts, roles, entry points, asset flows, and attack surfaces |
| [`poc-first-validator`](skills/poc-first-validator/) | Decide whether a lead should be proven, killed, downgraded, or report-ready |
| [`foundry-poc-writer`](skills/foundry-poc-writer/) | Turn hypotheses into exploit/control test plans |
| [`evidence-gate-reviewer`](skills/evidence-gate-reviewer/) | Review code refs, PoC output, impact, and duplicate checks |
| [`report-readiness-checker`](skills/report-readiness-checker/) | Apply the 7-question report-readiness gate |
| [`duplicate-na-risk-checker`](skills/duplicate-na-risk-checker/) | Identify duplicate, known-risk, intended-behavior, and likely N/A issues |
| [`ai-agent-web3-threat-modeler`](skills/ai-agent-web3-threat-modeler/) | Map AI-agent read/tool/signing boundaries and harmful capability chains |

### Imported Opencode workflow skills

| Skill | Description |
|---|---|
| [`web3-ai-bounty`](skills/web3-ai-bounty/) | Full PoC-first Web3/AI bounty methodology, scripts, schemas, examples, and evals |
| [`web3-audit`](skills/web3-audit/) | Smart contract audit bug-class reference |
| [`bug-bounty`](skills/bug-bounty/) | General Web2/Web3 bounty workflow reference |
| [`triage-validation`](skills/triage-validation/) | Finding validation and rejection gate reference |
| [`report-writing`](skills/report-writing/) | Impact-first report writing guidance |
| [`security-arsenal`](skills/security-arsenal/) | Payload and bypass reference material |
| [`web2-recon`](skills/web2-recon/) | Web2 recon workflow reference |
| [`web2-vuln-classes`](skills/web2-vuln-classes/) | Web2 vulnerability-class reference |
| [`bb-methodology`](skills/bb-methodology/) | General bounty methodology reference |

---

## Useful scripts

Reusable Web3 scripts live under [`skills/web3-ai-bounty/scripts/`](skills/web3-ai-bounty/scripts/).

Start with:

| Script | Purpose |
|---|---|
| `safety_guard.py` | Safety self-tests and execution guard checks |
| `execution_safety_gate.py` | Classify command, file, RPC, network, and PoC execution safety |
| `web3_result_lint.py` | Validate `web3_result` blocks from saved Opencode command output |
| `poc_execution_gate.py` | Gate local PoC execution and block unsafe runs |
| `evidence_package_validator.py` | Validate evidence packages before report drafting |
| `report_linter.py` | Catch weak or unsafe report wording |
| `readiness_policy.py` | Keep report-readiness and post-hoc evidence rules explicit |
| `no_overfit_guard.py` | Guard against benchmark leakage and overfit claims |
| `foundry_poc_generator.py` | Generate Foundry PoC scaffolds/plans |
| `lead_db.py` | Track leads and finding state |
| `scanner_normalize.py` | Normalize scanner output into leads |
| `code_indexer.py` | Build a source-code index for audit workflows |

See [`docs/script-index.md`](docs/script-index.md) for more.

---

## Repository layout

- `skills/` — reusable AI-agent skills for Web3/AI bounty workflows.
- `prompts/` — Opencode command prompts, agent definitions, and reusable prompt snippets.
- `framework/` — notes for reusable framework-level helpers. Imported Web3 scripts currently live under `skills/web3-ai-bounty/scripts/` to preserve skill-relative paths.
- `templates/` — reusable finding folders, status files, report templates, and PoC templates.
- `docs/` — workflow, safety, evidence, report-readiness, script index, and sanitization docs.
- `examples/` — toy/synthetic examples only. Do not add real private bounty target data.
- `benchmarks/` — sanitized benchmark definitions or summaries only. Do not add private corpora or raw target data.
- `targets/` — placeholder area for sanitized target notes only. Do not commit real private target data.
- `generated/` — generated artifacts are ignored by default. Commit only safe README/placeholders.
- `scratch/` — local temporary workspace ignored by default. Do not commit scratch work.
- `archives/` — sanitized old experiments or summaries only. Do not commit secrets, raw logs, or private reports.

---

## Safety

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

When in doubt, commit a short sanitized summary instead of the raw artifact.

---

## Contributing · Security · License

- Contributions: see [`CONTRIBUTING.md`](CONTRIBUTING.md)
- Security policy: see [`SECURITY.md`](SECURITY.md)
- License: MIT, see [`LICENSE`](LICENSE)

Suggested repo description:

```text
PoC-first Web3/AI bug bounty skills, prompts, scripts, and evidence-gated workflows.
```
