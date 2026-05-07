---
description: Validate and draft a Web3 bug bounty report
agent: web3-bounty-auditor
---

Load the `web3-ai-bounty` skill first. Validate and draft a report for:

`$ARGUMENTS`

Before writing the report, answer the validation gate:

1. Is the target in scope?
2. Is the vulnerable code reachable in the current version or deployed bytecode?
3. Can an attacker exploit it now with normal privileges?
4. Does the victim take no unusual action beyond normal protocol use?
5. Is the impact concrete: stolen funds, frozen funds, bad debt, unauthorized privileged action, sensitive data leak, or account takeover?
6. Is there a working PoC with assertions?
7. Did you check audits, disclosed reports, changelog, and docs for duplicates or intended behavior?

If any answer is no, do not write a final report. Explain what is missing.

If all answers are yes, draft:

- Title.
- Summary.
- Affected contracts, functions, addresses, and commit hash when available.
- Root cause.
- Steps to reproduce with exact command.
- Impact.
- Remediation.
