---
description: Normalize Web3 scanner outputs into triageable leads
agent: web3-bounty-auditor
---

Load the `web3-ai-bounty` skill first and follow `SCANNER_NORMALIZATION.md`.

Scanner output path / args:

`$ARGUMENTS`

Use the local helper when possible:

```bash
python3 <skill-dir>/scripts/scanner_normalize.py <scanner-output.json> \
  --tool auto \
  --code-index x-ray/code-index.json \
  --json normalized-scanner-report.json \
  --leads-json normalized-scanner-leads.json
```

Import into Lead DB when requested:

```bash
python3 <skill-dir>/scripts/lead_db.py import-scanner audit-leads.json normalized-scanner-report.json
```

Return normalized rows with:

- tool
- bug class
- severity/confidence
- file/line/function
- message
- status: always `LEAD` until manually proven
- proof needed
- dedupe key / group key
- score and triage verdict
- suppressed `KILL` noise with reason

Do not report scanner output as a finding.

Return this parseable block first:

```yaml
web3_result:
  schema_version: web3-ai-bounty/v1
  command: web3-ingest-scanners
  severity_mode: critical-bounty|medium-bounty|audit-review|learning
  status: LEAD|NEEDS_CONTEXT|KILL|AUDIT_NOTE
  target: "<program/repo/scanner output>"
  summary: "<one sentence>"
  normalized_report: "normalized-scanner-report.json|not_written"
  normalized_leads: "normalized-scanner-leads.json|not_written"
  imported_to_lead_db: true|false
  rows:
    - id: "<row id>"
      status: LEAD|CHAIN_REQUIRED|KILL
      tool: "<scanner>"
      source_pointer: "<file:line:function>"
      bug_class: "<class>"
      proof_needed: "<manual proof needed>"
      dedupe_key: "<key>"
  suppressed: []
  evidence_missing: []
  next_action: "<exact command or stop reason>"
```
