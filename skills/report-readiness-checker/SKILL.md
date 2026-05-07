---
name: report-readiness-checker
description: Apply the 7-question bug bounty report-readiness gate before submission.
---

# report-readiness-checker

## Description

Apply a strict bug bounty report-readiness gate to decide whether a Web3/AI finding is `REPORT_READY`, blocked for more evidence, duplicate/N/A-risk, or killed.

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

```yaml
report_readiness_result:
  schema_version: report-readiness/v1
  status: REPORT_READY|REPORT_BLOCKED|PROVE|CHAIN_REQUIRED|NEEDS_CONTEXT|NEEDS_SCOPE_CONFIRMATION|DUPLICATE|NA_RISK|KILL
  seven_question_gate:
    in_scope: true|false
    reachable: true|false
    normal_attacker: true|false
    normal_victim_action: true|false
    concrete_impact: true|false
    working_poc: true|false
    duplicate_intended_checked: true|false
  evidence_missing: []
  final_recommendation: "<submit, block, continue, or stop>"
```

## Safety rules

- All seven gate answers must be yes for report-ready.
- Use canonical Web3 statuses only. Do not output generic readiness words or hyphenated legacy status variants.
- Do not rely on speculation or "could potentially" language.
- Do not submit if exclusions apply.
- Keep reports sanitized in this repo.

## Example prompt

```text
Use the report-readiness-checker skill to run the 7-question gate on this finding and decide submit, hold, or kill.
```
