---
description: Build a Solidity code/storage/callgraph index for Web3 audit triage
agent: web3-bounty-auditor
---

Load the `web3-ai-bounty` skill first and follow `CODE_INDEX_ENGINE.md`.

Target / args:

`$ARGUMENTS`

If no target is supplied, use the current repository and write `x-ray/code-index.json`.

Run the local helper when possible:

```bash
python3 <skill-dir>/scripts/code_indexer.py <project-root> --out x-ray/code-index.json
```

If the repo uses `contracts/` instead of `src/`, pass `--src-dir contracts`. Use `--include-tests` only when explicitly auditing tests, mocks, scripts, or deployment logic.

Return:

- index path
- contract/function/storage counts
- public/external value-moving functions
- top risk signals as `LEAD` candidates only
- suggested next Lead DB import/artifact command
- top manual questions for sibling guards, multiple writers, external-call ordering, signatures, oracle inputs, and proxy initialization

Do not report index signals as vulnerabilities without manual source confirmation and a working PoC.
