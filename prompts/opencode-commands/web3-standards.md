---
description: Map Web3 lead/finding to security standards and remediation guidance
agent: web3-bounty-auditor
---

Load the `web3-ai-bounty` skill first and follow `STANDARDS_MAPPING.md`.

Lead/finding:

`$ARGUMENTS`

Return:

1. Relevant SWC, OWASP Smart Contract Top 10, EthTrust, SCSVS, and OpenZeppelin mappings.
2. Why the mapping applies.
3. Why the mapping alone does not prove impact.
4. Concrete impact proof still required.
5. Remediation aligned with best practices.

Do not assign severity solely from a standards tag.

Return this parseable block first:

```yaml
web3_result:
  schema_version: web3-ai-bounty/v1
  command: web3-standards
  severity_mode: critical-bounty|medium-bounty|audit-review|learning
  status: LEAD|PROVE|CHAIN_REQUIRED|NEEDS_CONTEXT|NA_RISK|KILL|AUDIT_NOTE|LOW_INFO
  target: "<lead/finding>"
  summary: "<one sentence>"
  mappings: []
  why_applies: "<reason>"
  impact_proof_required: "<proof still required>"
  remediation_guidance: "<guidance>"
  evidence_missing: []
  next_action: "<exact command or stop reason>"
```
