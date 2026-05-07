---
description: Mine public audit reports for target-specific Web3 hypotheses
agent: web3-bounty-auditor
---

Load the `web3-ai-bounty` skill first and follow `AUDIT_REPORT_MINING.md`.

Target/protocol type:

`$ARGUMENTS`

Mine public audit reports for similar protocol-type findings. Extract root causes, accepted impacts, fixes, weak variants, and convert them into current-target hypotheses.

Return mined patterns as:

```text
Mined Pattern MP-01:
Source reports:
Current target match:
Files/functions to inspect:
Exploit sentence:
Expected impact:
Status: LEAD | PROVE | CHAIN_REQUIRED | NEEDS_CONTEXT | NEEDS_SCOPE_CONFIRMATION | NA_RISK | KILL
Next check:
```

Return this parseable block first:

```yaml
web3_result:
  schema_version: web3-ai-bounty/v1
  command: web3-mine-reports
  severity_mode: critical-bounty|medium-bounty|audit-review|learning
  status: LEAD|PROVE|CHAIN_REQUIRED|NEEDS_CONTEXT|NEEDS_SCOPE_CONFIRMATION|NA_RISK|KILL
  target: "<program/repo/protocol type>"
  summary: "<one sentence>"
  mined_patterns:
    - id: "MP-01"
      status: LEAD|PROVE|CHAIN_REQUIRED|NEEDS_CONTEXT|NEEDS_SCOPE_CONFIRMATION|NA_RISK|KILL
      source_reports: []
      current_target_match: "<source pointer or gap>"
      exploit_sentence: "<target-specific hypothesis>"
      expected_impact: "<accepted impact or why weak>"
      evidence_missing: []
      next_action: "<exact command or stop reason>"
  evidence_missing: []
  next_action: "<exact command or stop reason>"
```

Do not claim the target is vulnerable unless current code and PoC prove it.
