---
description: Run strict validation gate on a suspected bug bounty finding
agent: validator
---

Load `triage-validation` first.

Finding details: `$ARGUMENTS`

Apply the 7-question gate and 4 pre-submission gates. Require:

- Exact affected asset and endpoint.
- Program scope confirmation.
- Raw HTTP request and response.
- Real impact evidence, not just a 200 response or scanner result.
- Duplicate/known issue check.

Return PASS, KILL Q#, DOWNGRADE, or CHAIN REQUIRED with the shortest useful
explanation.
