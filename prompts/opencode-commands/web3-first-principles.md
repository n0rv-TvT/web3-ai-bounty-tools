---
description: Run Web3 first-principles assumption-breaking audit lens
agent: web3-bounty-auditor
---

Load the `web3-ai-bounty` skill first. Run only the first-principles lens on `$ARGUMENTS`.

Ignore named bug classes. For every state-changing function, extract assumptions, violate them with attacker-controlled inputs/order/timing, and trace whether corrupted state creates concrete impact.

Return exploit sentences and proof targets. Kill assumptions that do not monetize or match accepted impact.

Return this parseable block first:

```yaml
web3_result:
  schema_version: web3-ai-bounty/v1
  command: web3-first-principles
  severity_mode: critical-bounty|medium-bounty|audit-review|learning
  status: PROVE|CHAIN_REQUIRED|NEEDS_CONTEXT|NEEDS_SCOPE_CONFIRMATION|NA_RISK|KILL|AUDIT_NOTE|LOW_INFO
  target: "<program/repo/contract>"
  summary: "<one sentence>"
  assumption_breaks:
    - id: "<lead id>"
      status: PROVE|CHAIN_REQUIRED|NEEDS_CONTEXT|NEEDS_SCOPE_CONFIRMATION|NA_RISK|KILL|AUDIT_NOTE|LOW_INFO
      source_pointer: "<file:contract:function>"
      assumption: "<assumption>"
      violation: "<attacker-controlled counterexample>"
      exploit_sentence: "Because <actor> can ..."
      proof_target: "<assertion target>"
      evidence_missing: []
      next_action: "<exact command or stop reason>"
  evidence_missing: []
  next_action: "<exact command or stop reason>"
```
