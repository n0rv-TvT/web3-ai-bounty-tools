---
description: Hunt for Web3 bounty leads with severity modes, refutation gates, and PoC-first ranking
agent: web3-bounty-auditor
---

Load the `web3-ai-bounty` skill first. Follow `SCOPE_TARGET_BRIEF.md`, `FINDING_PLAYBOOK.md`, `HYPOTHESIS_ENGINE.md`, `PROTOCOL_PLAYBOOKS.md`, and `REAL_BUG_CASEBOOK.md`. For AMM, StableSwap, concentrated-liquidity, or Uniswap v4 hook targets, also apply `AMM_STABLESWAP_HOOK_CHECKLIST.md` before killing boundary-driven Medium/audit-review leads.

Target: `$ARGUMENTS`

If no target is supplied, use the current repository.

## Mode selection

Select or ask for one severity mode before triage:

- `critical-bounty`: only realistic direct loss, permanent/accepted freeze, insolvency, governance takeover, severe privilege abuse, account takeover, sensitive data exposure, or unsafe signing/tool execution.
- `medium-bounty`: allow conditional but realistic issues with concrete impact and source path.
- `audit-review`: broader review mode; Low/Info observations allowed but must be separated from bounty findings.
- `learning`: explanation-heavy mode; educational notes allowed but not findings.

## Workflow

1. Confirm or create the `/web3-scope` target brief: scope artifact, target protocol type, selected severity mode, accepted impact categories, exclusions, and testing permissions.
2. Build or reuse target resume state:
   ```text
   schema_version
   severity_mode
   target_index
   current_best_leads
   active_hypotheses
   poc_written
   poc_passing
   killed
   duplicate
   na_risk
   status_counts
   scope_artifact
   scope_confidence
   next_action
   ```
3. Pick the top 3 crown-jewel components.
4. Run protocol-specific exploit loops and generate hypotheses, not findings.
5. For each hypothesis, answer the refutation-first gate:
   - Why might this be false?
   - What modifier/access control could block it?
   - What invariant or test would kill it?
   - What source evidence is missing?
   - What would make it N/A, duplicate, intended behavior, or low impact?
6. Score surviving leads by impact, reachability, PoC simplicity, scope, novelty, and economics.
7. Mark each item with one canonical status: `PROVE`, `CHAIN_REQUIRED`, `NEEDS_CONTEXT`, `NEEDS_SCOPE_CONFIRMATION`, `DUPLICATE`, `NA_RISK`, `AUDIT_NOTE`, `LOW_INFO`, or `KILL`.
8. For the best `PROVE` lead, recommend the exact `/web3-poc` command. Do not build multiple PoCs at once unless the user asks.

## Early kill reasons

- access control blocks exploit
- function unreachable
- impact not realistic
- only scanner output
- no affected asset
- no attacker path
- intended behavior
- duplicate root cause
- requires privileged malicious admin outside scope
- no PoC assertion target
- only theoretical worst case

## Output

Return this parseable block first:

```yaml
web3_result:
  schema_version: web3-ai-bounty/v1
  command: web3-hunt
  severity_mode: critical-bounty|medium-bounty|audit-review|learning
  status: PROVE|CHAIN_REQUIRED|NEEDS_CONTEXT|NEEDS_SCOPE_CONFIRMATION|DUPLICATE|NA_RISK|AUDIT_NOTE|LOW_INFO|KILL
  target: "<program/repo/contract>"
  summary: "<one sentence>"
  target_summary: "<scope/protocol/crown jewels>"
  scope_artifact: "target-scope.json|audit-notes/target-scope.json|not_written"
  scope_confidence: confirmed|partial|unknown
  target_resume_state:
    target_index: "<id or path>"
    current_best_leads: []
    active_hypotheses: []
    poc_written: false
    poc_passing: false
    killed: []
    duplicate: []
    na_risk: []
    status_counts: {}
    scope_artifact: "<path or not_written>"
    scope_confidence: confirmed|partial|unknown
    next_action: "<exact command or stop reason>"
  current_best_leads:
    - id: "<lead id>"
      status: PROVE|CHAIN_REQUIRED|NEEDS_CONTEXT|NEEDS_SCOPE_CONFIRMATION|DUPLICATE|NA_RISK|AUDIT_NOTE|LOW_INFO|KILL
      source_pointer: "<file:contract:function>"
      impact_claim: "<accepted impact or why weak>"
      evidence_missing: []
      kill_condition: "<what would refute it>"
      next_action: "<exact next command>"
  active_hypotheses: []
  killed: []
  duplicate: []
  na_risk: []
  best_prove_candidate:
    id: "<lead id or null>"
    reason: "<why this one PoC first>"
    command: "/web3-poc <lead id/context>"
  next_action: "<exact next command or stop reason>"
```

Do not draft a report. Do not claim a finding is report-ready without PoC assertions and validation.
