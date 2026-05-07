---
description: Run multi-lens Web3 audit swarm and deduplicate leads
agent: web3-bounty-auditor
---

Load the `web3-ai-bounty` skill first and follow `PARALLEL_AUDIT_ORCHESTRATOR.md`.

Target:

`$ARGUMENTS`

Run the target through these audit lenses:

1. Vector scan.
2. Math precision.
3. Access control.
4. Economic security.
5. Execution trace.
6. Invariants.
7. Periphery.
8. First principles.

Deduplicate by `Contract | function | bug-class`, merge only true duplicates, and validate proof-backed leads.

Return ranked `PROVE`, `CHAIN REQUIRED`, and `KILL` items. Do not draft a report.
