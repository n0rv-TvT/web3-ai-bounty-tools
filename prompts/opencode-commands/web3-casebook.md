---
description: Compare a Web3 lead to paid-bug shapes and weak variants
agent: web3-bounty-auditor
---

Load the `web3-ai-bounty` skill first and follow `REAL_BUG_CASEBOOK.md`.

Lead:

`$ARGUMENTS`

Compare the lead to known paid-bug shapes and rejected weak variants.

Return:

1. Closest paid-bug shape.
2. Matching root cause.
3. Missing proof.
4. Likely N/A/rejection risks.
5. Verdict: canonical status such as `PROVE`, `CHAIN_REQUIRED`, `NA_RISK`, or `KILL`.

Return this parseable block first:

```yaml
web3_result:
  schema_version: web3-ai-bounty/v1
  command: web3-casebook
  severity_mode: critical-bounty|medium-bounty|audit-review|learning
  status: PROVE|CHAIN_REQUIRED|NEEDS_CONTEXT|NEEDS_SCOPE_CONFIRMATION|DUPLICATE|NA_RISK|KILL|AUDIT_NOTE|LOW_INFO
  target: "<program/repo/lead>"
  summary: "<one sentence>"
  closest_paid_shape: "<casebook pattern>"
  matching_root_cause: "<root cause or none>"
  missing_proof: []
  rejection_risks: []
  next_action: "<exact command or stop reason>"
```
