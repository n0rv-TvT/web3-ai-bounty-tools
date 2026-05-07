# Opencode Import Notes

Imported sanitized reusable material from local Opencode skills.

Included:

- skill `SKILL.md` files
- reusable workflow/reference markdown
- reusable scripts
- schemas
- toy examples and eval fixtures
- sanitized Opencode command prompts
- sanitized Opencode agent definitions

Excluded:

- benchmark corpora and scoring outputs
- raw target sources
- generated PoCs/results
- caches and build artifacts
- logs, secrets, cookies, RPC URLs, and private target data
- local Opencode config such as `mcp.json`, `opencode.json`, packages, and `node_modules/`

Keep future imports public-safe and reusable.

## Installing into active Opencode

Imported repo files are not automatically active. Use the repo-level installer:

```bash
bash scripts/install-opencode-assets.sh --dry-run
bash scripts/install-opencode-assets.sh --verify
bash scripts/install-opencode-assets.sh --install
```

The installer is intentionally dry-run by default and backs up overwritten active config files during `--install`.

Verification also checks that every active `web3-*.md` command has a `web3_result` schema block.
