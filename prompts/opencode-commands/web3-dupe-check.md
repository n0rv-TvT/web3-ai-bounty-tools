---
description: Check Web3 finding duplicate, intended-behavior, known-risk, and N/A risk before reporting
agent: web3-bounty-auditor
---

Load the `web3-ai-bounty` skill first and follow `DUPLICATE_INTENDED_BEHAVIOR_CHECK.md`.

Finding or lead:

`$ARGUMENTS`

## Purpose

Decide whether a suspected finding is clear to continue, duplicate, intended behavior, known risk, excluded, or likely N/A before report drafting.

Do not draft a report. Do not use private platform data unless the user explicitly provides it or authorizes its use. Do not store secrets, cookies, private reports, or triager messages in repo files.

## Required inputs

Confirm these before deciding:

- finding id or short title
- selected severity mode
- bug class
- exact file/contract/function
- vulnerable code path
- attacker capability
- affected asset
- exploit sequence
- assertion target
- scope and exclusion text or notes
- docs/audits/issues/changelog sources checked

If the finding fingerprint or scope/exclusion text is missing, return `NEEDS_CONTEXT`.

## Check order

1. Build root-cause fingerprint: missing check, bad ordering, stale state, bad invariant, unsafe trust boundary, bad hook delta, replay gap, or accounting desync.
2. Compare against local docs/specs/NatSpec for intended behavior.
3. Compare against audits, changelog, issues, PRs, known limitations, and lead memory.
4. Run the variant delta test: same root cause, sink, invariant, and patch shape means likely duplicate even if function names differ.
5. Check program exclusions and selected severity mode.
6. Return one canonical status and an exact do-not-revisit reason when blocked.

## Output

Return this parseable block first:

```yaml
web3_result:
  schema_version: web3-ai-bounty/v1
  command: web3-dupe-check
  severity_mode: critical-bounty|medium-bounty|audit-review|learning
  status: PROVE|DUPLICATE|NA_RISK|KILL|NEEDS_CONTEXT
  target: "<program/repo/contract>"
  summary: "<one sentence>"
  finding_id: "<id>"
  source_pointer: "<file:contract:function>"
  review_decision: CLEAR|DUPLICATE|INTENDED_BEHAVIOR|KNOWN_RISK|EXCLUDED|NA_RISK|NEEDS_CONTEXT
  fingerprints:
    root_cause: "<root cause>"
    sink: "<fund/accounting/oracle/signature/hook/tool sink>"
    impacted_invariant: "<invariant>"
    impact_shape: "<theft/freeze/bad debt/privilege/data/unsafe signing>"
    patch_shape: "<likely fix>"
  sources_checked: []
  duplicate_of: "<report/audit/issue/lead id or null>"
  intended_behavior_evidence: []
  exclusion_evidence: []
  variant_delta:
    same_root_cause_as_prior: true|false|unknown
    same_affected_function: true|false|unknown
    same_sink_or_invariant: true|false|unknown
    same_patch_shape: true|false|unknown
    different_attacker_capability: true|false|unknown
    different_affected_asset: true|false|unknown
    different_accepted_impact: true|false|unknown
    why_not_duplicate: "<one sentence or null>"
  do_not_revisit_reason: "<if DUPLICATE/NA_RISK/KILL>"
  evidence_missing: []
  next_action: "<exact command or stop reason>"
```

Only `review_decision: CLEAR` lets `/web3-validate` or `/web3-report` continue. `CLEAR` is not report readiness; PoC assertions and the seven-question gate are still required.
