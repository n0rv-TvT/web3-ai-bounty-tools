# Web3 Lead Memory Template

Purpose: keep a local audit memory of proven and killed lead patterns so the hunter gets faster over time.

Use this as a project-local file, for example `audit-notes/LEAD_MEMORY.md`. Do not store secrets, private client data, or undisclosed vulnerabilities unless the workspace is private and authorized.

## Entry Template

```text
Date:
Target / protocol type:
Lead ID:
Pattern:
Files/functions:
Initial status: LEAD | PROVE | CHAIN REQUIRED
Final status: REPORT | KILL | CHAIN REQUIRED

Exploit sentence:

What evidence existed:
What proof was missing:
PoC command / result:

Why proven or killed:
Scope / exclusion issue:
Duplicate / intended behavior check:

How to check faster next time:
Related attack-vector IDs:
Related paid-bug shape:
```

## Fast Lessons Format

```text
Lesson: <short pattern>
Signal that mattered:
Signal that was noise:
Fast check:
```

## Rules

- Killed leads are valuable; record why they died.
- Never record real private keys, seeds, RPC tokens, or user data.
- Do not copy confidential report details into a shared memory file.
- Keep entries short enough to be searchable.
