---
name: poc-first-validator
description: Validate Web3/AI bug bounty leads through a PoC-first evidence ladder and decide prove, kill, duplicate, N/A-risk, or report-ready.
---

# poc-first-validator

## Description

Validate whether a Web3/AI bug bounty lead deserves more time by forcing it through a PoC-first evidence ladder.

## When to use

- After a hypothesis is drafted.
- Before writing a report.
- When deciding whether to continue, kill, downgrade, or build a PoC.

## Inputs expected

- Finding summary.
- Affected files/functions.
- Hypothesis and attacker capability.
- PoC status or test output if available.
- Impact claim and duplicate/intended-behavior notes.

## Output format

```text
Decision: PROVE | KILL | DUPLICATE | N/A-RISK | REPORT-READY
Reason:
Evidence present:
Evidence missing:
Next action:
Do-not-revisit reason, if killed:
```

## Safety rules

- Do not call a lead report-ready without a working PoC and concrete impact.
- Do not report scanner-only or theoretical issues.
- Do not use live transactions or real funds.
- Do not include unsanitized private target data.

## Example prompt

```text
Use the poc-first-validator skill to review this finding and decide whether it is report-ready or should be killed.
```
