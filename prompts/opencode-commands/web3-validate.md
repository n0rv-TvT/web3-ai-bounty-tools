---
description: Validate a Web3 finding before report writing
agent: web3-bounty-auditor
---

Load the `web3-ai-bounty` skill first. Validate this suspected finding without drafting a report yet:

`$ARGUMENTS`

Run the strict 7-question gate:

1. Is the exact affected contract/function in scope?
2. Is the vulnerable code reachable in the current version or deployed bytecode?
3. Can an attacker exploit it now with normal privileges?
4. Does the victim take no unusual action beyond normal protocol use?
5. Is there concrete impact: stolen funds, frozen funds, bad debt, unauthorized privileged action, sensitive data leak, account takeover, or unsafe signing/tool execution?
6. Is there a working PoC with assertions proving the impact?
7. Did you check docs, prior audits, disclosed reports, changelog, GitHub issues/PRs, and hacktivity for duplicates or intended behavior?

Return exactly one verdict: `REPORT`, `CHAIN REQUIRED`, or `KILL`.

Do not write a final report unless the user then calls `/web3-report`.
