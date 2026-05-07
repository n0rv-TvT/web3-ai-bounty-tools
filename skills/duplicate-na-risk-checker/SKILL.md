---
name: duplicate-na-risk-checker
description: Identify duplicate, known-risk, intended-behavior, exclusion, and likely N/A reasons before submission.
---

# duplicate-na-risk-checker

## Description

Identify duplicate, known-risk, intended-behavior, and likely N/A reasons before spending more time on a report.

## When to use

- Before report drafting.
- When a finding feels weak or familiar.
- After a PoC passes but impact is unclear.
- When platform exclusions may apply.

## Inputs expected

- Finding summary and bug class.
- Affected contract/function.
- Impact claim.
- Links or notes from docs, issues, prior audits, and public reports.
- Program exclusions if available.

## Output format

```yaml
duplicate_risk_result:
  schema_version: duplicate-na-risk/v1
  status: PROVE|DUPLICATE|NA_RISK|KILL|NEEDS_CONTEXT
  review_decision: CLEAR|DUPLICATE|KNOWN_RISK|INTENDED_BEHAVIOR|EXCLUDED|NA_RISK|NEEDS_CONTEXT
  evidence: []
  likely_rejection_reason: "<reason or none>"
  what_would_make_it_stronger: "<missing proof or scope confirmation>"
  do_not_revisit_reason: "<if blocked>"
```

## Safety rules

- Do not fetch or store private platform data in this public repo.
- Do not treat a variant as new unless root cause or impact is materially different.
- Do not submit issues that are excluded or only best-practice gaps.

## Example prompt

```text
Use the duplicate-na-risk-checker skill to identify why this report may get duplicate or N/A.
```
