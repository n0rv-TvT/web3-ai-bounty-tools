---
description: Draft a concise impact-first bug bounty report after validation passes
agent: report-writer
---

Load `report-writing` first.

Validated finding: `$ARGUMENTS`

Only continue if the finding passed `/bb-validate`. If validation evidence is
missing, stop and ask for the missing proof.

Draft a submission-ready report with:

1. Impact-first title.
2. Summary.
3. Vulnerability details.
4. Raw HTTP reproduction steps.
5. Evidence and impact.
6. CVSS 3.1 score/vector.
7. Remediation.

Never use "could potentially", "may allow", or scanner-only wording.
