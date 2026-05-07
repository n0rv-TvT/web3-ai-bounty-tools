---
description: Hunt for high-impact Web3 bounty bugs and pick PoC-ready leads
agent: web3-bounty-auditor
---

Load the `web3-ai-bounty` skill first. Follow `FINDING_PLAYBOOK.md`, `HYPOTHESIS_ENGINE.md`, `PROTOCOL_PLAYBOOKS.md`, and `REAL_BUG_CASEBOOK.md`.

Target: `$ARGUMENTS`

If no target is supplied, use the current repository.

Workflow:

1. Confirm scope and target protocol type.
2. Pick the top 3 crown-jewel components.
3. Run protocol-specific exploit loops.
4. Generate exploit hypotheses with concrete impact targets.
5. Score leads by impact, reachability, PoC simplicity, scope, novelty, and economics.
6. Mark each lead as `PROVE`, `CHAIN REQUIRED`, or `KILL`.
7. For the best `PROVE` lead, recommend the exact `/web3-poc` command or write the PoC if explicitly requested.

Kill weak/scanner-only leads aggressively.
