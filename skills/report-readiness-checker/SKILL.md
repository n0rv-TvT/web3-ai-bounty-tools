---
name: report-readiness-checker
description: Apply the 7-question bug bounty report-readiness gate before submission.
---

# report-readiness-checker

## Description

Apply a strict bug bounty report-readiness gate to decide whether to submit, hold, downgrade, or kill a finding.

## When to use

- Immediately before writing or submitting a report.
- After PoC and evidence review pass.
- When the impact or scope match is uncertain.

## Inputs expected

- Scope summary.
- Finding summary.
- PoC result.
- Impact proof.
- Duplicate/intended-behavior check.
- Draft report if available.

## Output format

```text
Report readiness: READY | HOLD | KILL | DUPLICATE | N/A-RISK
7-question gate:
1. In scope:
2. Reachable:
3. Normal attacker:
4. Normal victim/action:
5. Concrete impact:
6. Working PoC:
7. Duplicate/intended checked:
Final recommendation:
```

## Safety rules

- All seven gate answers must be yes for report-ready.
- Do not rely on speculation or "could potentially" language.
- Do not submit if exclusions apply.
- Keep reports sanitized in this repo.

## Example prompt

```text
Use the report-readiness-checker skill to run the 7-question gate on this finding and decide submit, hold, or kill.
```
