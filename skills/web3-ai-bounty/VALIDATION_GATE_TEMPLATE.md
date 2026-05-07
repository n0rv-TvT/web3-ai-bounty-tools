# Web3 Finding Validation Gate

Do not draft a report unless every answer is YES.

## 7-Question Gate

1. Is the exact affected contract/function in scope? YES / NO
2. Is the vulnerable code reachable in the current version or deployed bytecode? YES / NO
3. Can an attacker exploit it now with normal privileges? YES / NO
4. Does the victim take no unusual action beyond normal protocol use? YES / NO
5. Is there concrete impact: stolen funds, frozen funds, bad debt, unauthorized privileged action, sensitive data leak, account takeover, or unsafe signing/tool execution? YES / NO
6. Is there a working PoC with assertions proving impact? YES / NO
7. Did you check docs, prior audits, disclosed reports, changelog, GitHub issues/PRs, and hacktivity for duplicate or intended behavior? YES / NO

Decision: REPORT / CHAIN REQUIRED / KILL

## Technical Validity

- PoC command:
- PoC result:
- Verified contract addresses:
- Proxy / implementation checked:
- Derived domains/nonces/storage slots documented:

## Intended Behavior / Recovery

- Docs checked:
- Audit reports checked:
- Admin/operator recovery path exists? If yes, does it make issue N/A?
- Queue/retry/pause mechanism checked:

## Impact Accuracy

- Attacker gain:
- Victim/protocol loss:
- Frozen amount/duration:
- Bad debt amount:
- Unauthorized role/action:
- Sensitive data leaked:
- Program impact category matched verbatim:
- Exclusion risk:
