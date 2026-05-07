---
description: Generate and score Web3 exploit hypotheses
agent: web3-bounty-auditor
---

Load the `web3-ai-bounty` skill first and follow `HYPOTHESIS_ENGINE.md`.

Target or component:

`$ARGUMENTS`

For each crown-jewel component, produce exploit sentences:

`Because <actor> can <capability> in <function> while <state/assumption> is <stale/missing/desynced>, attacker can <steps> causing <impact>.`

Then score each lead and return:

- `PROVE` leads with PoC assertion targets.
- `CHAIN REQUIRED` leads with missing chain piece.
- `KILL` leads with reason.

Do not write reports. Do not call a lead a finding without a PoC.
