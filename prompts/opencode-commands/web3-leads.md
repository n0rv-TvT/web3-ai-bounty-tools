---
description: Manage the Web3 audit Lead Database
agent: web3-bounty-auditor
---

Load the `web3-ai-bounty` skill first and follow `LEAD_DATABASE_ENGINE.md`.

Lead database request:

`$ARGUMENTS`

Use the production JSON lead database at `audit-leads.json` in the target repo root unless the user supplies another path.

Supported operations:

1. Initialize a database for the current target:
   ```bash
   python3 <skill-dir>/scripts/lead_db.py init audit-leads.json --target "<target>" --protocol <type> --repo .
   ```
2. Add manual/x-ray/hypothesis leads as `LEAD` or `INTAKE`; never mark scanner output report-ready.
3. Import normalized scanner rows:
   ```bash
   python3 <skill-dir>/scripts/lead_db.py import-scanner audit-leads.json normalized-scanner-report.json
   ```
   Use `--include-killed` only if you want suppressed scanner noise recorded as `KILL` rows.
4. List, show, summarize, and validate:
   ```bash
   python3 <skill-dir>/scripts/lead_db.py list audit-leads.json
   python3 <skill-dir>/scripts/lead_db.py metrics audit-leads.json
   python3 <skill-dir>/scripts/lead_db.py validate audit-leads.json
   ```
5. Update status only with evidence-backed reasons. `KILL` requires a kill reason; `CHAIN_REQUIRED` requires a missing chain condition; `REPORT_READY` requires PoC `PASS` plus all seven validation questions true.

Return a concise summary of database path, operation performed, lead IDs changed, validation result, and next proof step.

Do not store secrets, private keys, seed phrases, RPC keys, or private user data in the lead database.
