---
description: Build a Foundry PoC for a suspected Web3 finding
agent: web3-bounty-auditor
---

Load the `web3-ai-bounty` skill first. Build a minimal Foundry PoC for this suspected finding:

`$ARGUMENTS`

Requirements:

1. Inspect the relevant contracts, tests, fixtures, deployment scripts, and interfaces before editing.
2. If the finding is in Lead DB or has on-chain/code-index artifacts, generate a scaffold first when useful:
   ```bash
   python3 <skill-dir>/scripts/foundry_poc_generator.py --project-root . --lead-db audit-leads.json --lead-id <lead-id> --onchain onchain.json --code-index x-ray/code-index.json --out test/<LeadId>Exploit.t.sol
   ```
3. Add the smallest useful test or harness that proves the exploit. Generated scaffolds intentionally fail until completed.
4. Use attacker and victim actors with clear initial state.
5. Assert concrete impact: profit, stolen funds, frozen funds, bad debt, unauthorized privileged action, or data exposure.
6. Run the narrowest useful `forge test --match-test ... -vvvv` command.
7. If the finding fails, explain why it is not exploitable and stop instead of forcing a PoC.

Do not mark Lead DB PoC status as `PASS` until the exploit test passes and asserts concrete impact.

Do not modify production contract code unless explicitly asked to patch.
