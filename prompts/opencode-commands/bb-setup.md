---
description: Initialize OpenCode bug bounty skills, target workspace, and safe hunt checklist
agent: bug-bounty-hunter
---

Load `bb-methodology` and `bug-bounty` first.

Target or program: `$ARGUMENTS`

If `$ARGUMENTS` is empty, ask for the target domain/program handle before doing
anything else.

Run the local workspace initializer without making network requests:

```bash
python3 <path-to-tools>/bb_workspace.py --target "$ARGUMENTS"
```

Then summarize:

1. Workspace path and files created.
2. What scope data still needs manual confirmation.
3. Traffic tagging values to add to Burp/Caido.
4. Two-account setup requirements.
5. Recommended first session definition: target feature, impact goal, and 1-2
   vuln classes.

Do not run recon or active testing from this command. Setup only.
