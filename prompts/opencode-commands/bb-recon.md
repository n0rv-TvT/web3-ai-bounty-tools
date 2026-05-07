---
description: Run safe, scoped Web2 recon and produce a ranked attack surface
agent: recon-agent
---

Load `web2-recon` first.

Target: `$ARGUMENTS`

Before running commands, confirm the exact in-scope asset list. If the user has
not provided scope, ask for it and stop.

Use the local recon engine only after scope is confirmed:

```bash
bash <path-to-tools>/recon_engine.sh "$ARGUMENTS" --quick
```

For sensitive or narrow VDP targets, prefer `--quick`, passive sources, and low
rates. Do not fuzz, brute force, DoS, or bypass WAFs.

Deliver:

1. Commands run and traffic rate.
2. Output directory.
3. Live hosts and tech stack.
4. API/document/upload/auth surfaces.
5. Top 5 manual tests ranked by business impact.
