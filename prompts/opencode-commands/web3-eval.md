---
description: Test the Web3 hunter against bundled vulnerable mini-protocol fixtures
agent: web3-bounty-auditor
---

Load the `web3-ai-bounty` skill first.

Eval target:

`$ARGUMENTS`

If no specific fixture is supplied, list the available fixtures under `evals/` and recommend one.

For the selected fixture:

1. Identify the expected bug shape.
2. Run `/web3-xray`-style entry point and invariant reasoning manually or with helper scripts.
3. Generate exploit hypotheses.
4. Pick the correct PoC pattern.
5. Explain the expected Foundry test path and assertion.
6. If the fixture is copied into a Foundry project, run the narrow `forge test --match-test ... -vvvv` command.

Use this command to benchmark whether the hunter finds known bug shapes before trying real bounty targets.
