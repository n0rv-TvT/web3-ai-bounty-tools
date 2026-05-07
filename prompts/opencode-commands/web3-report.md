---
description: Draft a Web3 bug bounty report only after evidence and report-readiness gates pass
agent: web3-bounty-auditor
---

Load the `web3-ai-bounty` skill first. Validate evidence and draft a copy-paste bounty report for this finding. If scope is missing or stale, block and run `/web3-scope` first. If duplicate/intended-behavior status is missing, stale, or not `CLEAR`, block and run `/web3-dupe-check` first:

`$ARGUMENTS`

## Blocking rule

Do not write a final report unless the evidence gate passes. Block report drafting if any required item is incomplete:

- exact file/contract/function
- vulnerable code path
- attacker capability
- affected asset
- exploit sequence
- concrete PoC assertion
- kill condition
- exploit test and control test where possible
- scope confirmation
- scope artifact or equivalent target brief
- duplicate/intended-behavior check
- `/web3-dupe-check` result with `review_decision: CLEAR`
- severity mode and severity rationale

If blocked, return `REPORT_BLOCKED` and list missing evidence.

## Validation gate

Before writing the report, answer:

1. Is the target in scope?
2. Is the vulnerable code reachable in the current version or deployed bytecode?
3. Can an attacker exploit it now with normal privileges?
4. Does the victim take no unusual action beyond normal protocol use?
5. Is the impact concrete and accepted for the selected mode/program?
6. Is there a working PoC with assertions?
7. Did you check audits, disclosed reports, changelog, docs, GitHub issues/PRs, and known limitations for duplicates or intended behavior?

Question 7 requires a root-cause fingerprint and a clear duplicate/intended-behavior result. If unresolved, return `REPORT_BLOCKED` and set `next_action` to `/web3-dupe-check <finding id/context>`.

Question 1 requires scope evidence showing the affected contract/function, chain/address or source commit, affected asset, claimed impact, and test method are in scope. If unresolved, return `REPORT_BLOCKED` and set `next_action` to `/web3-scope <target/context>`.

If any answer is no, do not write a final report. Explain what is missing and return `REPORT_BLOCKED`.

## Report output

Return this parseable block first:

```yaml
web3_result:
  schema_version: web3-ai-bounty/v1
  command: web3-report
  severity_mode: critical-bounty|medium-bounty|audit-review|learning
  status: REPORT_READY|REPORT_BLOCKED
  target: "<program/repo/contract>"
  summary: "<one sentence>"
  finding_id: "<id>"
  source_pointer: "<file:contract:function>"
  scope:
    artifact: "target-scope.json|audit-notes/target-scope.json|not_written"
    confidence: confirmed|partial|unknown
    affected_component_in_scope: true|false
    affected_asset_in_scope: true|false
    claimed_impact_accepted: true|false
    exclusions_apply: true|false
    testing_method_allowed: true|false
  evidence_gate:
    exact_source: true|false
    vulnerable_code_path: true|false
    attacker_capability: true|false
    affected_asset: true|false
    exploit_sequence: true|false
    concrete_poc_assertion: true|false
    kill_condition: true|false
    scope_confirmation: true|false
    duplicate_intended_checked: true|false
    dupe_check_clear: true|false
    severity_rationale: true|false
  dupe_check:
    review_decision: CLEAR|DUPLICATE|INTENDED_BEHAVIOR|KNOWN_RISK|EXCLUDED|NA_RISK|NEEDS_CONTEXT
    duplicate_of: "<report/audit/issue/lead id or null>"
    unresolved_reason: "<if not CLEAR>"
  evidence_missing: []
  report_sections_included: []
  next_action: "<submit/review command or unblock step>"
```

If all gates pass, draft after the schema block:

- Title.
- Summary.
- Affected contracts, functions, addresses, and commit hash when available.
- Root cause.
- Steps to reproduce with exact command.
- PoC explanation with exploit assertion and control test.
- Impact.
- Severity rationale.
- Limitations and assumptions.
- Remediation.

Use copy-paste bounty report formatting. Avoid “could potentially” unless describing limitations, not impact.
