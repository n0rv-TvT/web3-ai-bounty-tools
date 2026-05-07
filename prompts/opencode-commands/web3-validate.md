---
description: Validate a Web3 finding with refutation-first and 7-question gates
agent: web3-bounty-auditor
---

Load the `web3-ai-bounty` skill first. Validate this suspected finding without drafting a report. If scope is missing or stale, run `/web3-scope` or follow `SCOPE_TARGET_BRIEF.md`. If duplicate/intended-behavior status is missing or stale, run `/web3-dupe-check` or follow `DUPLICATE_INTENDED_BEHAVIOR_CHECK.md` before returning `REPORT_READY`:

`$ARGUMENTS`

## Refutation-first gate

Answer before any positive verdict:

1. Why might this be false?
2. What modifier/access control could block it?
3. What invariant, branch, revert, or existing test would kill it?
4. What source evidence is missing?
5. What would make it N/A, duplicate, intended behavior, excluded, or low impact for the selected severity mode?

If the lead fails refutation, return `KILL`, `DUPLICATE`, `NA_RISK`, or `NEEDS_CONTEXT` with the exact reason.

## PoC-first evidence checklist

Confirm:

- exact file/contract/function
- scope artifact or equivalent target brief
- vulnerable code path
- attacker capability
- affected asset
- exploit sequence
- concrete assertion
- kill condition
- exploit test and control test where possible
- duplicate/intended-behavior check
- `/web3-dupe-check` result or equivalent fingerprint review

No PoC assertion means no report-ready finding.

## Strict 7-question gate

1. Is the exact affected contract/function in scope?
2. Is the vulnerable code reachable in the current version or deployed bytecode?
3. Can an attacker exploit it now with normal privileges?
4. Does the victim take no unusual action beyond normal protocol use?
5. Is there concrete impact: stolen funds, frozen funds, bad debt, unauthorized privileged action, sensitive data leak, account takeover, unsafe signing/tool execution, or accepted in-scope DoS/freeze?
6. Is there a working PoC with assertions proving the impact?
7. Did you check docs, prior audits, disclosed reports, changelog, GitHub issues/PRs, and hacktivity for duplicates or intended behavior?

Question 7 requires a root-cause fingerprint and a clear duplicate/intended-behavior result. If unresolved, return `NEEDS_CONTEXT`, `DUPLICATE`, or `NA_RISK`, not `REPORT_READY`.

Question 1 requires a scope artifact or equivalent evidence showing the affected contract/function, chain/address or source commit, affected asset, claimed impact, and test method are in scope. If unresolved, return `NEEDS_SCOPE_CONFIRMATION`.

Return this parseable block first with exactly one canonical status:

```yaml
web3_result:
  schema_version: web3-ai-bounty/v1
  command: web3-validate
  severity_mode: critical-bounty|medium-bounty|audit-review|learning
  status: REPORT_READY|PROVE|CHAIN_REQUIRED|NEEDS_CONTEXT|NEEDS_SCOPE_CONFIRMATION|DUPLICATE|NA_RISK|KILL
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
  refutation:
    why_false: "<strongest reason it may be false>"
    blocking_control: "<modifier/access control/invariant/test or none>"
    missing_evidence: []
    duplicate_or_na_risk: "<risk or none>"
  seven_question_gate:
    in_scope: true|false
    reachable: true|false
    normal_attacker: true|false
    normal_victim: true|false
    concrete_impact: true|false
    working_poc_assertions: true|false
    duplicate_intended_checked: true|false
  dupe_check:
    review_decision: CLEAR|DUPLICATE|INTENDED_BEHAVIOR|KNOWN_RISK|EXCLUDED|NA_RISK|NEEDS_CONTEXT
    duplicate_of: "<report/audit/issue/lead id or null>"
    unresolved_reason: "<if not CLEAR>"
  evidence_missing: []
  verdict_reason: "<one sentence>"
  next_action: "<exact command or stop reason>"
```

Do not return vague statuses like “maybe vulnerable”. Do not write a final report unless the user then calls `/web3-report`.
