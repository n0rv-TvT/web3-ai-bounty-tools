---
description: Run Web3 access control audit lens
agent: web3-bounty-auditor
---

Load the `web3-ai-bounty` skill first. Run only the access-control lens on `$ARGUMENTS`.

Map every sensitive state writer and compare guards across siblings. Focus on missing modifiers, inline sender checks, role escalation, initialization, upgrades, confused deputy calls, delegatecall, and proxy authority.

Return concrete unauthorized actions only. Do not report admin-does-admin-things.
