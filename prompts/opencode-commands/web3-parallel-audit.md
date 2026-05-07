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

Use the smallest useful mode:

- targeted files if `$ARGUMENTS` names files/contracts
- subsystem mode if a protocol area is implied
- full repo only after x-ray/surface mapping

For each lens output, require structured `FINDING` or `LEAD` blocks. No proof means `LEAD`, not `FINDING`.

Deduplicate by `Contract | function | bug-class`, merge only true duplicates, and validate proof-backed leads.

Before ranking, run the refutation-first gates from `PARALLEL_AUDIT_ORCHESTRATOR.md`:

1. Refutation.
2. Reachability.
3. Trigger.
4. Impact.

Then run the 7-question bounty gate only for survivors.

Return this parseable block first:

```yaml
web3_result:
  schema_version: web3-ai-bounty/v1
  command: web3-parallel-audit
  severity_mode: critical-bounty|medium-bounty|audit-review|learning
  status: PROVE|CHAIN_REQUIRED|NEEDS_CONTEXT|NEEDS_SCOPE_CONFIRMATION|DUPLICATE|NA_RISK|KILL|AUDIT_NOTE|LOW_INFO
  target: "<program/repo/contract>"
  summary: "<one sentence>"
  ranked_items:
    - id: "<lead id>"
      lens: vector-scan|math-precision|access-control|economic-security|execution-trace|invariants|periphery|first-principles
      status: PROVE|CHAIN_REQUIRED|NEEDS_CONTEXT|NEEDS_SCOPE_CONFIRMATION|DUPLICATE|NA_RISK|KILL|AUDIT_NOTE|LOW_INFO
      source_pointer: "<file:contract:function>"
      impact_claim: "<accepted impact or why weak>"
      evidence_missing: []
      next_action: "<exact command or stop reason>"
  evidence_missing: []
  next_action: "<exact command or stop reason>"
```

Do not draft a report.
