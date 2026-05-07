# evidence-gate-reviewer

## Description

Review whether a finding's evidence package is complete, reproducible, and safe enough to support a bug bounty report.

## When to use

- After a PoC passes.
- Before report drafting.
- When consolidating notes from code review, PoC output, impact analysis, and duplicate checks.

## Inputs expected

- Finding folder or evidence summary.
- PoC command and output.
- Code references.
- Impact analysis.
- Scope and duplicate/intended-behavior checks.

## Output format

```text
Gate result: PASS | FAIL | INCOMPLETE
Missing evidence:
Weak claims:
Safety issues:
Required fixes before report:
```

## Safety rules

- Do not accept raw logs with secrets as evidence.
- Do not accept PoCs without assertions.
- Do not accept private platform messages unless sanitized.
- Do not upgrade weak impact claims.

## Example prompt

```text
Use the evidence-gate-reviewer skill to check whether this finding folder has enough evidence for report drafting.
```
