---
description: Verify a bug bounty asset against program scope before testing
agent: bug-bounty-hunter
---

Load `bb-methodology` and `bug-bounty` first.

Asset/program text: `$ARGUMENTS`

Perform a scope-first review:

1. Extract exact in-scope assets, wildcard rules, and path exclusions.
2. Extract out-of-scope vuln classes and testing prohibitions.
3. Identify third-party or ambiguous assets that require confirmation.
4. State whether the asset is IN SCOPE, OUT OF SCOPE, or UNCLEAR.
5. If unclear, stop and ask for program text or explicit authorization.

Do not run active probes until the scope decision is clear.
