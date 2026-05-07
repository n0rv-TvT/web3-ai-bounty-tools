---
description: Threat model a Web3 AI agent, wallet, bot, or transaction assistant
agent: web3-bounty-auditor
---

Load the `web3-ai-bounty` skill first. Threat model the Web3 AI system described here:

`$ARGUMENTS`

Map:

1. What the AI can read.
2. What tools the AI can call.
3. Whether it can sign, simulate, submit, approve, swap, bridge, cancel, or change settings.
4. What untrusted content reaches the model.
5. Where user confirmation is enforced.
6. Where secrets, wallet metadata, API keys, prompts, or cross-user context may leak.

Return concrete test cases only. Prioritize chains that prove unauthorized transaction/tool execution, sensitive data exposure, account takeover, or fund loss.
