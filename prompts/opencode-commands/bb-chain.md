---
description: Build an A-to-B exploit chain from a low or medium bug signal
agent: bug-bounty-hunter
---

Load `bug-bounty`, `web2-vuln-classes`, and `security-arsenal` first.

Signal/finding: `$ARGUMENTS`

Map possible chains:

1. Confirm bug A with exact request/response.
2. Find sibling endpoints in the same feature/controller.
3. Test read/write/delete or old API versions where safe and in scope.
4. Convert low findings only if they reach concrete harm:
   - Open redirect + OAuth code theft = ATO.
   - SSRF callback + internal/cloud data = real SSRF.
   - XSS + token/CSRF/action impact = account/data impact.
   - IDOR read + write/delete/export = higher impact.
5. If no concrete chain exists, kill the finding.

Return the best chain candidate and missing proof.
