---
description: Score whether a Web3 bug bounty target is worth deep audit effort
agent: web3-bounty-auditor
---

Load the `web3-ai-bounty` skill first. Score this Web3 target using TVL, bounty cap, audit status, recency, upgradeability, source availability, and protocol familiarity:

`$ARGUMENTS`

Return:

1. Score out of 10.
2. Decision: skip, narrow pass, or full workflow.
3. Maximum realistic payout estimate.
4. Highest-value bug classes to prioritize.
5. What information is missing from the score.

If the user provides incomplete data, infer cautiously from local docs and ask at most one concise follow-up only if necessary.
