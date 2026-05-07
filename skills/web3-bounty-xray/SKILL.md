---
name: web3-bounty-xray
description: Produce a concise attack-surface x-ray for authorized Web3 targets before hypothesis generation and PoC work.
---

# web3-bounty-xray

## Description

Map a Web3 target's attack surface before deep bug hunting. Produces a concise, sanitized x-ray of contracts, roles, entry points, asset flows, invariants, and high-value bug classes.

## When to use

- Starting a new authorized target.
- Resuming a target after time away.
- Before generating exploit hypotheses.
- When you need to understand what assets move and who can move them.

## Inputs expected

- Scope summary or repository path.
- In-scope contracts/components.
- Known exclusions and accepted impact categories.
- Optional docs, architecture notes, tests, and deployment information.

## Output format

```text
## Target summary
## In-scope components
## Roles and permissions
## Entry points
## Asset/value flows
## Trust boundaries
## High-value attack surfaces
## Top hypotheses to investigate
## Kill/skip notes
```

## Safety rules

- Use only authorized targets and local/read-only analysis.
- Do not include secrets, private keys, RPC URLs, cookies, or raw platform messages.
- Mark uncertain claims as uncertain.
- Treat scanner output as leads, not findings.

## Example prompt

```text
Use the web3-bounty-xray skill to map this Solidity repo's entry points, roles, asset flows, and top bug bounty attack surfaces.
```
