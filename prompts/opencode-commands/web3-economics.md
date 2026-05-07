---
description: Run Web3 economic security audit lens
agent: web3-bounty-auditor
---

Load the `web3-ai-bounty` skill first. Run only the economic security lens on `$ARGUMENTS`.

Focus on oracle assumptions, token misbehavior, flash-loanable sequences, capacity starvation, external dependency failure, liquidation economics, and value extraction.

Every lead must name who profits, who loses, how much, and what PoC would prove it.

Return this parseable block first:

```yaml
web3_result:
  schema_version: web3-ai-bounty/v1
  command: web3-economics
  severity_mode: critical-bounty|medium-bounty|audit-review|learning
  status: PROVE|CHAIN_REQUIRED|NEEDS_CONTEXT|NEEDS_SCOPE_CONFIRMATION|NA_RISK|KILL|AUDIT_NOTE|LOW_INFO
  target: "<program/repo/contract>"
  summary: "<one sentence>"
  economic_leads:
    - id: "<lead id>"
      status: PROVE|CHAIN_REQUIRED|NEEDS_CONTEXT|NEEDS_SCOPE_CONFIRMATION|NA_RISK|KILL|AUDIT_NOTE|LOW_INFO
      source_pointer: "<file:contract:function>"
      attacker_profit: "<amount or unknown>"
      victim_or_protocol_loss: "<amount or unknown>"
      economic_path: "<oracle/token/liquidation/flash/capacity sequence>"
      assertion_target: "<exact proof target>"
      evidence_missing: []
      next_action: "<exact command or stop reason>"
  evidence_missing: []
  next_action: "<exact command or stop reason>"
```
