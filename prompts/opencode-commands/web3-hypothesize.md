---
description: Generate and score Web3 exploit hypotheses
agent: web3-bounty-auditor
---

Load the `web3-ai-bounty` skill first and follow `HYPOTHESIS_ENGINE.md`.

Target or component:

`$ARGUMENTS`

For each crown-jewel component, produce exploit sentences:

`Because <actor> can <capability> in <function> while <state/assumption> is <stale/missing/desynced>, attacker can <steps> causing <impact>.`

Then score each lead and return:

- `PROVE` leads with PoC assertion targets.
- `CHAIN_REQUIRED` leads with missing chain piece.
- `KILL` leads with reason.

Return this parseable block first:

```yaml
web3_result:
  schema_version: web3-ai-bounty/v1
  command: web3-hypothesize
  severity_mode: critical-bounty|medium-bounty|audit-review|learning
  status: PROVE|CHAIN_REQUIRED|NEEDS_CONTEXT|NEEDS_SCOPE_CONFIRMATION|NA_RISK|KILL|AUDIT_NOTE|LOW_INFO
  target: "<program/repo/contract/component>"
  summary: "<one sentence>"
  hypotheses:
    - id: "<hypothesis id>"
      status: PROVE|CHAIN_REQUIRED|NEEDS_CONTEXT|NEEDS_SCOPE_CONFIRMATION|NA_RISK|KILL|AUDIT_NOTE|LOW_INFO
      exploit_sentence: "Because <actor> can <capability>..."
      source_pointer: "<file:contract:function>"
      assertion_target: "<profit/loss/freeze/bad debt/privilege/data>"
      missing_chain_piece: "<if CHAIN_REQUIRED>"
      kill_condition: "<what refutes it>"
      evidence_missing: []
      next_action: "<exact command or stop reason>"
  evidence_missing: []
  next_action: "<exact command or stop reason>"
```

Do not write reports. Do not call a lead a finding without a PoC.
