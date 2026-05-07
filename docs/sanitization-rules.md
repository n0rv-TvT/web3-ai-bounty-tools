# Sanitization Rules

This repo is private, but it is still not a secret store. Commit only sanitized material that helps resume research later.

## Never commit

- `.env` files
- private keys
- seed phrases
- wallet files
- RPC URLs
- API tokens
- session cookies
- raw platform messages with sensitive info
- private target data
- huge generated artifacts
- Foundry build folders
- unsanitized logs
- real user data
- auth/session JSON
- screenshots containing tokens, cookies, or private program content

## Commit only

- clean summaries
- final decisions
- reusable prompts
- framework scripts
- sanitized reports
- sanitized platform response summaries
- evidence summaries
- PoC templates
- status files
- runbooks

## Report and platform response rule

Commit `report.md` and `platform_response.md` only if sanitized. If they contain private program details, cookies, real user data, RPC URLs, tokens, or sensitive target information, commit only `report_summary.md` or `platform_response_summary.md` instead.

## Before commit checklist

1. Search for secrets and tokens.
2. Remove raw logs unless reduced to useful excerpts.
3. Replace private program details with a summary when needed.
4. Keep final decisions and lessons learned.
5. Prefer small evidence summaries over large raw artifacts.
