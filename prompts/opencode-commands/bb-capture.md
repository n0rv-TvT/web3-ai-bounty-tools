---
description: Capture browser requests/responses without Caido using Playwright HAR recording
agent: bug-bounty-hunter
---

Load `bb-methodology` and `bug-bounty` first.

Target or URL: `$ARGUMENTS`

Use this when Caido/Burp integration is inconvenient. This launches a headed
Chromium browser, lets the researcher browse manually with owned test accounts,
and saves request/response traffic to a HAR file in the target workspace.

Safety rules:

- Confirm scope first.
- Use only owned test accounts.
- Do not test excluded auth/session flows, DoS, brute force, or spam.
- Stop if real customer PII appears.
- Treat HAR and storage-state files as secrets.

Run capture:

```bash
python3 <path-to-tools>/playwright_har_capture.py --target "$ARGUMENTS" --header "X-Bug-Bounty: HackerOne-<username>" --user-agent "OpenCode-BugBounty/1.0 H1:<username>"
```

After the browser closes, map the HAR:

```bash
python3 <path-to-tools>/har_mapper.py --har /path/to/capture.har
```

Then summarize IDOR, mass-assignment, document/upload/export, and auth-flow
avoidance candidates. Do not run active replay/testing unless the user provides
two owned accounts and confirms scope.
