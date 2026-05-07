---
description: Generate a Foundry fork/local PoC scaffold from Web3 audit artifacts
agent: web3-bounty-auditor
---

Load the `web3-ai-bounty` skill first and follow `FOUNDRY_POC_GENERATOR.md`, `POC_PATTERN_LIBRARY.md`, and `ADVERSARIAL_TEST_HARNESS.md`.

PoC generation request:

`$ARGUMENTS`

Preferred helper:

```bash
python3 <skill-dir>/scripts/foundry_poc_generator.py \
  --project-root . \
  --lead-db audit-leads.json \
  --lead-id <lead-id> \
  --onchain onchain.json \
  --code-index x-ray/code-index.json \
  --out test/<LeadId>Exploit.t.sol \
  --metadata test/<LeadId>Exploit.plan.json
```

If no Lead DB exists, use manual flags:

```bash
python3 <skill-dir>/scripts/foundry_poc_generator.py \
  --project-root . \
  --bug-class <bug-class> \
  --target-address <address> \
  --chain-id <id> \
  --rpc-env <CHAIN_RPC_ENV> \
  --out test/Exploit.t.sol
```

Return:

1. Generated Solidity path and metadata path.
2. Selected PoC pattern and harnesses.
3. Exact narrow `forge test` command.
4. TODOs that must be filled before PoC can count as proof.
5. Lead DB `add-poc` command for `PLANNED` now and `PASS` only after assertions pass.

Do not modify production contracts. Do not mark PoC `PASS` from a scaffold alone. Generated exploit tests intentionally fail until completed.
