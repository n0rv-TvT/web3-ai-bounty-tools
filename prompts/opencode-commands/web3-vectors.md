---
description: Classify known Web3 attack vectors against a target
agent: web3-bounty-auditor
---

Load the `web3-ai-bounty` skill first and follow `ATTACK_VECTOR_TRIAGE.md` using the local `ATTACK_VECTOR_DB.md`.

Target:

`$ARGUMENTS`

Classify relevant attack vectors exactly once as:

- `SKIP`: construct absent.
- `DROP`: construct present but guard blocks all paths.
- `INVESTIGATE`: construct present and guard missing/partial/unclear.
- `PROVE`: full reachable exploit path visible.
- `KILL`: investigated but no concrete impact/reachability/scope.

Start with a classification block and then detail only `INVESTIGATE`, `PROVE`, and notable `KILL` reasoning.

Return this parseable block first:

```yaml
web3_result:
  schema_version: web3-ai-bounty/v1
  command: web3-vectors
  severity_mode: critical-bounty|medium-bounty|audit-review|learning
  status: LEAD|PROVE|CHAIN_REQUIRED|NEEDS_CONTEXT|NEEDS_SCOPE_CONFIRMATION|NA_RISK|KILL|AUDIT_NOTE|LOW_INFO
  target: "<program/repo/contract>"
  summary: "<one sentence>"
  vector_classifications:
    - vector_id: "<id>"
      vector_name: "<name>"
      classification: SKIP|DROP|INVESTIGATE|PROVE|KILL
      status: LEAD|PROVE|CHAIN_REQUIRED|NEEDS_CONTEXT|NEEDS_SCOPE_CONFIRMATION|NA_RISK|KILL|AUDIT_NOTE|LOW_INFO
      source_pointer: "<file:contract:function or null>"
      reason: "<reason>"
      next_action: "<exact command or stop reason>"
  evidence_missing: []
  next_action: "<exact command or stop reason>"
```
