# Install and Use

Clone the repo:

```bash
git clone https://github.com/n0rv-TvT/web3-ai-bounty-tools.git
cd web3-ai-bounty-tools
```

Use the markdown skills/prompts with your coding agent of choice.

## Opencode active-runtime install

The repository copy is not automatically active in Opencode. To inspect what would be installed into your active Opencode config, run the safe dry-run first:

```bash
bash scripts/install-opencode-assets.sh --dry-run
```

Verify the currently active Opencode config without changing files:

```bash
bash scripts/install-opencode-assets.sh --verify
```

Install the repo assets into `~/.config/opencode` only when you are ready:

```bash
bash scripts/install-opencode-assets.sh --install
```

By default the installer backs up overwritten files under:

```text
~/.config/opencode/backups/web3-ai-bounty-tools/<timestamp>/
```

Use a custom destination for testing:

```bash
bash scripts/install-opencode-assets.sh --install --dest /tmp/opencode-test
```

The installer copies:

```text
skills/*                    -> DEST/skills/
prompts/opencode-commands/* -> DEST/commands/
prompts/opencode-agents/*   -> DEST/agents/
```

and verifies the active Web3 workflow contains `web3_result` schemas across `/web3-*` commands, `/web3-scope`, `/web3-dupe-check`, `/web3-exec-gate`, canonical statuses, schema validators, and scope/duplicate/execution checks.

Example prompts:

```text
Install https://github.com/n0rv-TvT/web3-ai-bounty-tools and use the web3-ai-bounty skill on this authorized repo.
```

```text
Use the poc-first-validator skill to decide whether this lead should be proven, killed, or report-ready.
```

```text
Use the foundry-poc-writer skill to create a minimal exploit/control test plan.
```

## Local script usage

Most reusable scripts are under:

```text
skills/web3-ai-bounty/scripts/
```

Examples:

```bash
python3 skills/web3-ai-bounty/scripts/safety_guard.py --self-test
python3 skills/web3-ai-bounty/scripts/execution_safety_gate.py --self-test
python3 skills/web3-ai-bounty/scripts/readiness_policy.py --self-test
python3 skills/web3-ai-bounty/scripts/report_linter.py --help
```

Some scripts expect local artifacts or schemas from the same skill directory. Read the script help and use toy examples before using them on real authorized targets.
