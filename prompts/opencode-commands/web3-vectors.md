---
description: Classify known Web3 attack vectors against a target
agent: web3-bounty-auditor
---

Load the `web3-ai-bounty` skill first and follow `ATTACK_VECTOR_TRIAGE.md` using the local `ATTACK_VECTOR_DB.md`.

Target:

`$ARGUMENTS`

Classify relevant attack vectors exactly once as:

- `SKIP`: construct absent.
- `DROP`: construct present but guard blocks all paths.
- `INVESTIGATE`: construct present and guard missing/partial/unclear.
- `PROVE`: full reachable exploit path visible.
- `KILL`: investigated but no concrete impact/reachability/scope.

Start with a classification block and then detail only `INVESTIGATE`, `PROVE`, and notable `KILL` reasoning.
