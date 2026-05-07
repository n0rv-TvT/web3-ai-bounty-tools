# Impact-First Web3 Bug Bounty Report

## Title

`[Bug class] in [contract/function] allows [actor] to [impact]`

## Summary

The PoC demonstrates `<concrete impact>` in `<contract/function>`. The root cause is `<one sentence: missing check / bad ordering / stale state / bad invariant / unsafe trust boundary>`.

## Affected Components

- Program:
- Chain:
- Contract(s):
- Function(s):
- Proxy address:
- Implementation address:
- Commit / deployment block:
- Scope category:

## Root Cause

`<exact root cause in one clear sentence>`

## Proof of Concept

- PoC path:
- Command:

```bash
forge test --match-test test_exploit -vvvv
```

### Reproduction Steps

1. Setup:
2. Baseline:
3. Attack:
4. Proof:
5. Control test:

## Impact

- Attacker gain:
- Victim/protocol loss:
- Funds frozen and duration:
- Bad debt:
- Unauthorized privileged action:
- Sensitive data exposed:
- Why this matches the program impact category:

## Why This Is Not Intended / Duplicate

- Docs reviewed:
- Prior audits reviewed:
- GitHub issues/PRs reviewed:
- Hacktivity/similar reports reviewed:
- Recovery paths checked:

## Remediation

- Fix 1:
- Fix 2:

## Notes

Avoid speculative wording. If the PoC does not prove an impact, do not include that impact.
