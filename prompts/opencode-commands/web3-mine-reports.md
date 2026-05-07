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
Status: LEAD | PROVE | CHAIN REQUIRED | KILL
Next check:
```

Do not claim the target is vulnerable unless current code and PoC prove it.
