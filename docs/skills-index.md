# Skills Index

This repo contains two kinds of skills:

1. **Core PoC-first bounty skills** — small focused skills for validating leads, writing PoCs, checking evidence, and deciding report readiness.
2. **Imported Opencode workflow skills** — larger reusable workflow references and script-backed skills.

## Core PoC-first bounty skills

| Skill | Use when | Output |
|---|---|---|
| [`web3-bounty-xray`](../skills/web3-bounty-xray/) | Starting or resuming an authorized Web3 target | attack-surface map and top hypotheses |
| [`poc-first-validator`](../skills/poc-first-validator/) | Deciding whether a lead deserves more time | prove/kill/duplicate/N/A/report-ready decision |
| [`foundry-poc-writer`](../skills/foundry-poc-writer/) | Turning a hypothesis into a Foundry test plan | exploit test, control test, assertions, kill conditions |
| [`evidence-gate-reviewer`](../skills/evidence-gate-reviewer/) | Checking whether a PoC/finding has enough proof | pass/fail/incomplete evidence gate |
| [`report-readiness-checker`](../skills/report-readiness-checker/) | Before drafting or submitting a report | 7-question gate and final recommendation |
| [`duplicate-na-risk-checker`](../skills/duplicate-na-risk-checker/) | Before spending more time on a weak/familiar finding | duplicate/N/A/known-risk/intended-behavior decision |
| [`ai-agent-web3-threat-modeler`](../skills/ai-agent-web3-threat-modeler/) | Reviewing AI wallets, agents, transaction builders, or tool-using AI systems | harmful capability-chain threat model |

## Imported Opencode workflow skills

| Skill | Purpose |
|---|---|
| [`web3-ai-bounty`](../skills/web3-ai-bounty/) | Full Web3/AI bounty workflow, scripts, schemas, templates, examples, and evals |
| [`web3-audit`](../skills/web3-audit/) | Smart contract audit bug-class reference |
| [`bug-bounty`](../skills/bug-bounty/) | General bug bounty workflow reference |
| [`triage-validation`](../skills/triage-validation/) | Strict validation, rejection, and report gate reference |
| [`report-writing`](../skills/report-writing/) | Impact-first bounty report drafting |
| [`security-arsenal`](../skills/security-arsenal/) | Payloads, bypasses, and rejection reference material |
| [`web2-recon`](../skills/web2-recon/) | Web2 recon workflow reference |
| [`web2-vuln-classes`](../skills/web2-vuln-classes/) | Web2 vulnerability-class reference |
| [`bb-methodology`](../skills/bb-methodology/) | General bounty methodology and hunting loop |

## Recommended combinations

### New Web3 target

```text
web3-bounty-xray → web3-ai-bounty → poc-first-validator → foundry-poc-writer
```

### Finding validation

```text
poc-first-validator → evidence-gate-reviewer → duplicate-na-risk-checker → report-readiness-checker
```

### AI-agent/Web3 review

```text
ai-agent-web3-threat-modeler → poc-first-validator → evidence-gate-reviewer
```

## Safety baseline

Skills should treat scanner output and model-generated ideas as leads, not findings. A finding needs source confirmation, reachability, concrete impact, and a working PoC before report drafting.
