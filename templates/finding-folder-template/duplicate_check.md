# Duplicate / Intended-Behavior Check

```yaml
web3_result:
  schema_version: web3-ai-bounty/v1
  command: web3-dupe-check
  severity_mode: critical-bounty|medium-bounty|audit-review|learning
  status: PROVE|DUPLICATE|NA_RISK|KILL|NEEDS_CONTEXT
  target: ""
  summary: ""
  finding_id: ""
  source_pointer: ""
  review_decision: CLEAR|DUPLICATE|INTENDED_BEHAVIOR|KNOWN_RISK|EXCLUDED|NA_RISK|NEEDS_CONTEXT
  fingerprints:
    root_cause: ""
    sink: ""
    impacted_invariant: ""
    impact_shape: ""
    patch_shape: ""
  sources_checked: []
  duplicate_of: null
  intended_behavior_evidence: []
  exclusion_evidence: []
  variant_delta:
    same_root_cause_as_prior: unknown
    same_affected_function: unknown
    same_sink_or_invariant: unknown
    same_patch_shape: unknown
    different_attacker_capability: unknown
    different_affected_asset: unknown
    different_accepted_impact: unknown
    why_not_duplicate: null
  do_not_revisit_reason: ""
  evidence_missing: []
  next_action: ""
```

## Notes

- Only `review_decision: CLEAR` removes the duplicate/intended-behavior blocker.
- `CLEAR` is not report readiness; PoC assertions and the seven-question gate are still required.
- Do not paste private platform duplicate IDs, triager comments, cookies, secrets, or undisclosed third-party data into public repo files.
