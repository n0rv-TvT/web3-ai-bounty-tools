---
description: Run the validation-first Web3 AI bug bounty workflow
agent: web3-bounty-auditor
---

Load the `web3-ai-bounty` skill first, then run the full workflow against `$ARGUMENTS`.

If `$ARGUMENTS` is empty, use the current repository as the target.

Deliver the result in this order:

1. Scope and target score.
2. Contract and AI/tool attack surface map.
3. Commands run and key outputs summarized.
4. Top hypotheses ranked by impact and exploitability.
5. Findings killed and why.
6. Validated findings with PoC paths and exact reproduction commands.
7. Report-ready summaries only for findings that pass validation.

Rules:

- Do not stop at scanner output.
- Do not draft reports for unvalidated issues.
- Add Foundry PoCs when a finding looks exploitable.
- Prefer small, focused tests over broad rewrites.
- Never use real keys, real user funds, or broadcast transactions without explicit authorization.
