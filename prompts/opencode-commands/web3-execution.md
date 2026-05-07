---
description: Run Web3 execution trace audit lens
agent: web3-bounty-auditor
---

Load the `web3-ai-bounty` skill first. Run only the execution trace lens on `$ARGUMENTS`.

Trace entry point to final state. Focus on parameter divergence, stale reads, partial updates, special sentinel paths, cross-transaction interleaving, approval residuals, callbacks, and queue/message lifecycle bugs.

Return minimal call sequences and concrete state changes.

Return this parseable block first:

```yaml
web3_result:
  schema_version: web3-ai-bounty/v1
  command: web3-execution
  severity_mode: critical-bounty|medium-bounty|audit-review|learning
  status: PROVE|CHAIN_REQUIRED|NEEDS_CONTEXT|NEEDS_SCOPE_CONFIRMATION|NA_RISK|KILL|AUDIT_NOTE|LOW_INFO
  target: "<program/repo/contract>"
  summary: "<one sentence>"
  execution_traces:
    - id: "<trace id>"
      status: PROVE|CHAIN_REQUIRED|NEEDS_CONTEXT|NEEDS_SCOPE_CONFIRMATION|NA_RISK|KILL|AUDIT_NOTE|LOW_INFO
      entrypoint: "<file:contract:function>"
      call_sequence: []
      state_changes: []
      invariant_break: "<invariant or none>"
      assertion_target: "<exact proof target>"
      evidence_missing: []
      next_action: "<exact command or stop reason>"
  evidence_missing: []
  next_action: "<exact command or stop reason>"
```
