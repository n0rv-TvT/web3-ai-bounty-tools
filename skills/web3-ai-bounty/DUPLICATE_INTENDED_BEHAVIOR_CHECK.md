# Duplicate, Known-Issue, Intended-Behavior, and N/A-Risk Check

Use this before report drafting and whenever a Web3 finding feels familiar, weak, excluded, or dependent on program interpretation. The goal is to prevent duplicate and N/A submissions without storing private platform data in this repository.

Validate a saved duplicate-check result with:

```bash
python3 <skill-dir>/scripts/schema_validator.py dupe_check dupe-check.json
```

## Safety And Data Hygiene

- Do not paste private triager messages, platform-only duplicate IDs, cookies, tokens, private reports, or undisclosed third-party data into public repo files.
- Prefer local repo docs, changelogs, audit PDFs already present in the target, public GitHub issues/PRs, public reports, and user-provided scope text.
- If web search or private platform review is needed, return `NEEDS_CONTEXT` and ask the user for authorized evidence or permission.
- Do not treat a renamed variant as new unless the root cause, affected component, exploit path, or accepted impact is materially different.

## Required Inputs

```yaml
dupe_check_input:
  finding_id: "<id>"
  severity_mode: critical-bounty|medium-bounty|audit-review|learning
  bug_class: "<class>"
  source_pointer: "<file:contract:function>"
  vulnerable_code_path: "<exact path>"
  exploit_sequence: []
  assertion_target: "<profit/loss/freeze/bad debt/privilege/data>"
  affected_asset: "<asset/state/users>"
  program_scope_summary: "<accepted impacts/exclusions>"
  docs_audits_issues_checked: []
```

If any of `bug_class`, `source_pointer`, `vulnerable_code_path`, `assertion_target`, or scope/exclusion text is missing, return `NEEDS_CONTEXT`.

## Fingerprint The Finding

Create these fingerprints before deciding duplicate risk:

```yaml
fingerprints:
  root_cause: "<missing check/bad ordering/stale state/bad invariant/etc>"
  sink: "<fund movement/accounting write/oracle read/signature verify/hook delta/etc>"
  attacker_entrypoint: "<public/external function or tool boundary>"
  impacted_invariant: "<asset conservation/authorization/replay/oracle/accounting/etc>"
  impact_shape: "<theft/freeze/bad debt/privilege/data/unsafe signing>"
  patch_shape: "<likely fix>"
```

A lead is likely duplicate if root cause + sink + impacted invariant + patch shape match a prior issue, even if the function name differs.

## Evidence Sources To Check

Check what is available locally or explicitly provided:

1. Program scope and exclusions.
2. README, docs, whitepaper, specs, NatSpec.
3. `audits/`, `security/`, `docs/audits/`, contest reports, public PDFs.
4. Changelog, releases, migration notes.
5. GitHub issues, PRs, commit messages, fix branches.
6. Known limitations, accepted risks, admin/recovery docs.
7. Public hacktivity or disclosed reports, if provided or already collected.
8. Lead memory / audit-leads history for same root cause.

Do not block a lead just because a generic bug class appears in an audit. Block or downgrade only when the same root cause, code path, or intended behavior is evidenced.

## Decision Rules

### `PROVE` / clear to continue

Use when:

- No matching known issue or intended behavior evidence was found in available sources.
- Scope/exclusion text accepts the claimed impact.
- The variant has materially different root cause, affected asset, exploit path, or impact.
- Missing duplicate checks are low risk and can be completed before report drafting.

### `DUPLICATE`

Use when:

- Same root cause and patch shape are already reported, audited, disclosed, or fixed.
- GitHub PR/commit clearly addresses the same vulnerable path.
- Public report/audit names the same function or invariant and the target version includes that known issue.
- Lead memory shows the same issue was already killed or submitted.

Required output: `duplicate_of`, source evidence, and do-not-revisit reason.

### `NA_RISK`

Use when:

- Program excludes the impact class, e.g. DoS-only, griefing-only, non-standard token behavior, centralization, known limitation, MEV-only, dust-only.
- Docs define the behavior as intended or recoverable under program assumptions.
- Impact is below selected severity mode even if technically real.
- The lead depends on privileged malicious admin/operator actions outside scope.

Required output: exact exclusion/known-risk text or missing text that must be confirmed.

### `KILL`

Use when:

- Source/docs prove the behavior is intended and safe.
- Existing tests or docs show the claimed effect is impossible.
- The affected component, chain, deployment, or impact is clearly out of scope.

### `NEEDS_CONTEXT`

Use when:

- Scope/exclusion text is missing.
- Audit/report/changelog evidence cannot be checked locally.
- The finding fingerprint is too vague to compare.
- User must confirm whether private platform duplicate info can be used.

## Variant Delta Test

Before calling a lead unique, answer:

```yaml
variant_delta:
  same_root_cause_as_prior: true|false|unknown
  same_affected_function: true|false|unknown
  same_sink_or_invariant: true|false|unknown
  same_patch_shape: true|false|unknown
  different_attacker_capability: true|false|unknown
  different_affected_asset: true|false|unknown
  different_accepted_impact: true|false|unknown
  why_not_duplicate: "<one sentence>"
```

If only function names differ but root cause/sink/patch are the same, choose `DUPLICATE` or `NA_RISK`.

## Required Output Schema

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
    sink: "<sink>"
    impacted_invariant: "<invariant>"
    impact_shape: "<impact>"
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

Only a `review_decision: CLEAR` allows report drafting to continue. `CLEAR` does not mean `REPORT_READY`; it only removes the duplicate/intended-behavior blocker.
