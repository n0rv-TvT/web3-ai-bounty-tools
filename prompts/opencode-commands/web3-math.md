---
description: Run Web3 math precision audit lens
agent: web3-bounty-auditor
---

Load the `web3-ai-bounty` skill first. Run only the math precision lens on `$ARGUMENTS`.

Focus on rounding direction, decimal normalization, division-before-multiplication, downcasts, overflow intermediates, ERC4626 preview/execute mismatch, and zero-rounding.

Return canonical-status leads with concrete arithmetic. No numbers means no finding.

Return this parseable block first:

```yaml
web3_result:
  schema_version: web3-ai-bounty/v1
  command: web3-math
  severity_mode: critical-bounty|medium-bounty|audit-review|learning
  status: PROVE|CHAIN_REQUIRED|NEEDS_CONTEXT|NA_RISK|KILL|AUDIT_NOTE|LOW_INFO
  target: "<program/repo/contract>"
  summary: "<one sentence>"
  math_leads:
    - id: "<lead id>"
      status: PROVE|CHAIN_REQUIRED|NEEDS_CONTEXT|NA_RISK|KILL|AUDIT_NOTE|LOW_INFO
      source_pointer: "<file:contract:function>"
      concrete_numbers: "<inputs/outputs/rounding delta>"
      impact_claim: "<accepted impact or why weak>"
      evidence_missing: []
      next_action: "<exact command or stop reason>"
  evidence_missing: []
  next_action: "<exact command or stop reason>"
```
