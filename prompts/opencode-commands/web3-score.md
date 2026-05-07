---
description: Score whether a Web3 bug bounty target is worth deep audit effort
agent: web3-bounty-auditor
---

Load the `web3-ai-bounty` skill first. Score this Web3 target using `SCOPE_TARGET_BRIEF.md` data when available, plus TVL, bounty cap, audit status, recency, upgradeability, source availability, and protocol familiarity:

`$ARGUMENTS`

Return this parseable block first:

```yaml
web3_result:
  schema_version: web3-ai-bounty/v1
  command: web3-score
  severity_mode: critical-bounty|medium-bounty|audit-review|learning
  status: PROVE|NEEDS_CONTEXT|NEEDS_SCOPE_CONFIRMATION|NA_RISK|KILL|AUDIT_NOTE
  target: "<program/repo/contract>"
  summary: "<one sentence>"
  scope_artifact: "target-scope.json|audit-notes/target-scope.json|not_written"
  score_out_of_10: 0
  decision: skip|narrow-pass|full-workflow|needs-context
  max_realistic_payout_estimate: "<amount or unknown>"
  priority_bug_classes: []
  evidence_missing: []
  next_action: "<exact command or stop reason>"
```

If the user provides incomplete data, infer cautiously from local docs and ask at most one concise follow-up only if necessary.
