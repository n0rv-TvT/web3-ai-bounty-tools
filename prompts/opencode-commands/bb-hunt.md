---
description: Start a focused validation-first bug bounty hunt on a target feature
agent: bug-bounty-hunter
---

Load `bb-methodology`, `bug-bounty`, and the relevant vulnerability-class skill.

Target/focus: `$ARGUMENTS`

Run a disciplined hunt:

1. Define: target feature and crown jewel.
2. Select: one or two vuln classes only.
3. Confirm scope and exclusions.
4. Load existing workspace/recon if present.
5. Map sibling endpoints and trust boundaries.
6. Test with owned accounts only for authenticated flows.
7. Record leads, dead ends, and anomalies in the target workspace.
8. For every signal, try A-to-B chaining before validation.

Do not write a report from this command. Use `/bb-validate` first.
