#!/usr/bin/env bash
# Safely install or verify this repo's Opencode skills, commands, and agents.
# Default mode is dry-run. Use --install to write into ~/.config/opencode.

set -euo pipefail

MODE="dry-run"
DEST="${OPENCODE_CONFIG_HOME:-${HOME}/.config/opencode}"
BACKUP=1
VERIFY_HASHES=0
WEB3_ONLY=0
MANIFEST_PATH=""

usage() {
  cat <<'EOF'
Usage: bash scripts/install-opencode-assets.sh [--dry-run|--install|--verify] [--dest PATH] [--no-backup] [--web3-only] [--verify-hashes] [--manifest PATH]

Modes:
  --dry-run   Show what would be copied. This is the default.
  --install   Copy repo assets into the Opencode config directory, then verify.
  --verify    Verify the active Opencode config only; do not copy.

Options:
  --dest PATH   Opencode config directory. Default: $OPENCODE_CONFIG_HOME or ~/.config/opencode
  --no-backup   Do not back up overwritten destination files/directories during --install.
  --web3-only   Install/verify only Web3 workflow assets from install-manifest.json.
  --verify-hashes Compare source assets against active destination files.
  --manifest PATH Asset manifest used by --web3-only. Default: repo install-manifest.json.
  -h, --help    Show this help.

Copied assets:
  skills/*                    -> DEST/skills/
  prompts/opencode-commands/* -> DEST/commands/
  prompts/opencode-agents/*   -> DEST/agents/

Verification checks for the current Web3 workflow markers:
  - canonical status vocabulary in web3-ai-bounty skill
  - SCOPE_TARGET_BRIEF and duplicate-check references
  - web3_result schemas in active web3 command prompts
  - /web3-scope and /web3-dupe-check commands installed
  - optional source/destination hash equality with --verify-hashes
EOF
}

log() { printf '[opencode-install] %s\n' "$*"; }
fail() { printf '[opencode-install] ERROR: %s\n' "$*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) MODE="dry-run" ;;
    --install) MODE="install" ;;
    --verify) MODE="verify" ;;
    --dest) shift; [[ $# -gt 0 ]] || fail "--dest requires a path"; DEST="$1" ;;
    --no-backup) BACKUP=0 ;;
    --web3-only) WEB3_ONLY=1 ;;
    --verify-hashes) VERIFY_HASHES=1 ;;
    --manifest) shift; [[ $# -gt 0 ]] || fail "--manifest requires a path"; MANIFEST_PATH="$1" ;;
    -h|--help) usage; exit 0 ;;
    *) fail "unknown argument: $1" ;;
  esac
  shift
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

SRC_SKILLS="${REPO_ROOT}/skills"
SRC_COMMANDS="${REPO_ROOT}/prompts/opencode-commands"
SRC_AGENTS="${REPO_ROOT}/prompts/opencode-agents"
MANIFEST="${MANIFEST_PATH:-${REPO_ROOT}/install-manifest.json}"

[[ -d "$SRC_SKILLS" ]] || fail "missing source skills directory: $SRC_SKILLS"
[[ -d "$SRC_COMMANDS" ]] || fail "missing source commands directory: $SRC_COMMANDS"
[[ -d "$SRC_AGENTS" ]] || fail "missing source agents directory: $SRC_AGENTS"

timestamp() { date -u +%Y%m%dT%H%M%SZ; }

backup_item() {
  local dest_item="$1"
  local rel="$2"
  [[ "$MODE" == "install" ]] || return 0
  [[ "$BACKUP" -eq 1 ]] || return 0
  [[ -e "$dest_item" ]] || return 0
  local backup_root="${DEST}/backups/web3-ai-bounty-tools/$(timestamp)"
  local backup_path="${backup_root}/${rel}"
  mkdir -p "$(dirname "$backup_path")"
  cp -a "$dest_item" "$backup_path"
  log "backed up ${rel} -> ${backup_path}"
}

copy_tree_entries() {
  local src_dir="$1"
  local dest_dir="$2"
  local rel_prefix="$3"
  if [[ "$MODE" == "install" ]]; then
    mkdir -p "$dest_dir"
  fi
  shopt -s nullglob
  local item base dest_item rel
  for item in "$src_dir"/*; do
    base="$(basename "$item")"
    dest_item="${dest_dir}/${base}"
    rel="${rel_prefix}/${base}"
    if [[ "$MODE" == "dry-run" ]]; then
      log "would copy ${rel} -> ${dest_item}"
    else
      backup_item "$dest_item" "$rel"
      rm -rf "$dest_item"
      cp -a "$item" "$dest_item"
      log "copied ${rel} -> ${dest_item}"
    fi
  done
}

copy_path() {
  local src_item="$1"
  local dest_item="$2"
  local rel="$3"
  if [[ "$MODE" == "dry-run" ]]; then
    log "would copy ${rel} -> ${dest_item}"
  else
    mkdir -p "$(dirname "$dest_item")"
    backup_item "$dest_item" "$rel"
    rm -rf "$dest_item"
    cp -a "$src_item" "$dest_item"
    log "copied ${rel} -> ${dest_item}"
  fi
}

manifest_entries() {
  local group="$1"
  [[ -f "$MANIFEST" ]] || fail "missing manifest: $MANIFEST"
  python3 - "$MANIFEST" "$REPO_ROOT" "$group" <<'PY'
import glob
import json
import sys
from pathlib import Path

manifest = Path(sys.argv[1])
root = Path(sys.argv[2])
group = sys.argv[3]
data = json.loads(manifest.read_text())
assets = data.get("groups", {}).get(group)
if assets is None:
    raise SystemExit(f"manifest group not found: {group}")
for asset in assets:
    src_pattern = root / asset["src"]
    matches = sorted(Path(p) for p in glob.glob(str(src_pattern)))
    if not matches:
        raise SystemExit(f"manifest source matched nothing: {asset['src']}")
    for src in matches:
        dest = asset["dest"]
        if dest.endswith("/"):
            dest = dest + src.name
        print(f"{src}\t{dest}")
PY
}

copy_manifest_group() {
  local group="$1"
  local src_item rel dest_item
  while IFS=$'\t' read -r src_item rel; do
    [[ -n "$src_item" ]] || continue
    dest_item="${DEST}/${rel}"
    copy_path "$src_item" "$dest_item" "$rel"
  done < <(manifest_entries "$group")
}

contains() {
  local file="$1"
  local needle="$2"
  [[ -f "$file" ]] && grep -Fq "$needle" "$file"
}

verify_active() {
  local failures=0
  local skill="${DEST}/skills/web3-ai-bounty/SKILL.md"
  local hunt="${DEST}/commands/web3-hunt.md"
  local validate="${DEST}/commands/web3-validate.md"
  local report="${DEST}/commands/web3-report.md"
  local scope_cmd="${DEST}/commands/web3-scope.md"
  local dupe_cmd="${DEST}/commands/web3-dupe-check.md"
  local exec_gate_cmd="${DEST}/commands/web3-exec-gate.md"
  local agent="${DEST}/agents/web3-bounty-auditor.md"
  local schema_validator="${DEST}/skills/web3-ai-bounty/scripts/schema_validator.py"
  local execution_safety_gate="${DEST}/skills/web3-ai-bounty/scripts/execution_safety_gate.py"
  local web3_result_lint="${DEST}/skills/web3-ai-bounty/scripts/web3_result_lint.py"
  local web3_result_schema="${DEST}/skills/web3-ai-bounty/schemas/web3_result.schema.json"
  local web3_hunt_schema="${DEST}/skills/web3-ai-bounty/schemas/web3_hunt_result.schema.json"
  local web3_poc_schema="${DEST}/skills/web3-ai-bounty/schemas/web3_poc_result.schema.json"
  local web3_validate_schema="${DEST}/skills/web3-ai-bounty/schemas/web3_validate_result.schema.json"
  local web3_report_schema="${DEST}/skills/web3-ai-bounty/schemas/web3_report_result.schema.json"
  local target_scope_schema="${DEST}/skills/web3-ai-bounty/schemas/target_scope.schema.json"
  local dupe_check_schema="${DEST}/skills/web3-ai-bounty/schemas/dupe_check.schema.json"
  local execution_safety_schema="${DEST}/skills/web3-ai-bounty/schemas/execution_safety.schema.json"

  check_file() {
    local path="$1"
    local label="$2"
    if [[ -f "$path" ]]; then
      log "verify ok: ${label} exists"
    else
      log "verify fail: ${label} missing at ${path}"
      failures=$((failures + 1))
    fi
  }

  check_contains() {
    local path="$1"
    local needle="$2"
    local label="$3"
    if contains "$path" "$needle"; then
      log "verify ok: ${label}"
    else
      log "verify fail: ${label}"
      failures=$((failures + 1))
    fi
  }

  check_file "$skill" "web3-ai-bounty skill"
  check_file "$hunt" "web3-hunt command"
  check_file "$validate" "web3-validate command"
  check_file "$report" "web3-report command"
  check_file "$scope_cmd" "web3-scope command"
  check_file "$dupe_cmd" "web3-dupe-check command"
  check_file "$exec_gate_cmd" "web3-exec-gate command"
  check_file "$agent" "web3-bounty-auditor agent"
  check_file "$schema_validator" "schema validator script"
  check_file "$execution_safety_gate" "execution safety gate script"
  check_file "$web3_result_lint" "web3_result linter script"
  check_file "$web3_result_schema" "web3_result schema"
  check_file "$web3_hunt_schema" "web3_hunt_result schema"
  check_file "$web3_poc_schema" "web3_poc_result schema"
  check_file "$web3_validate_schema" "web3_validate_result schema"
  check_file "$web3_report_schema" "web3_report_result schema"
  check_file "$target_scope_schema" "target_scope schema"
  check_file "$dupe_check_schema" "dupe_check schema"
  check_file "$execution_safety_schema" "execution_safety schema"

  check_contains "$skill" "Canonical Status Vocabulary" "canonical status vocabulary is active"
  check_contains "$skill" "SCOPE_TARGET_BRIEF.md" "scope target brief is referenced"
  check_contains "$skill" "DUPLICATE_INTENDED_BEHAVIOR_CHECK.md" "duplicate/intended behavior check is referenced"
  check_contains "$hunt" "web3_result:" "web3-hunt has parseable schema"
  check_contains "$hunt" "SCOPE_TARGET_BRIEF.md" "web3-hunt requires scope brief"
  check_contains "$validate" "REPORT_READY" "web3-validate uses REPORT_READY"
  check_contains "$validate" "dupe_check:" "web3-validate includes dupe_check block"
  check_contains "$report" "REPORT_BLOCKED" "web3-report blocks incomplete evidence"
  check_contains "$scope_cmd" "web3-target-scope/v1" "web3-scope embeds target scope schema"
  check_contains "$dupe_cmd" "review_decision:" "web3-dupe-check includes review decision"
  check_contains "$exec_gate_cmd" "web3-execution-safety/v1" "web3-exec-gate embeds execution safety schema"
  check_contains "$agent" "web3_result" "agent mentions web3_result schema discipline"
  check_contains "$agent" "web3-exec-gate" "agent mentions execution gate discipline"
  check_contains "$schema_validator" "web3_result.schema.json" "schema validator knows web3_result schema"
  check_contains "$schema_validator" "web3_hunt_result.schema.json" "schema validator knows web3_hunt_result schema"
  check_contains "$web3_result_lint" "COMMAND_SCHEMA" "web3_result linter knows command-specific schemas"
  check_contains "$schema_validator" "target_scope.schema.json" "schema validator knows target_scope schema"
  check_contains "$schema_validator" "dupe_check.schema.json" "schema validator knows dupe_check schema"
  check_contains "$schema_validator" "execution_safety.schema.json" "schema validator knows execution_safety schema"

  local cmd_file cmd_base
  shopt -s nullglob
  for cmd_file in "${DEST}/commands"/web3-*.md; do
    cmd_base="$(basename "$cmd_file")"
    if contains "$cmd_file" "web3_result:"; then
      log "verify ok: ${cmd_base} has web3_result schema block"
    else
      log "verify fail: ${cmd_base} missing web3_result schema block"
      failures=$((failures + 1))
    fi
  done

  if [[ "$failures" -eq 0 ]]; then
    log "verification passed for ${DEST}"
  else
    log "verification failed with ${failures} issue(s) for ${DEST}"
    return 1
  fi
}

hash_compare_path() {
  local src="$1"
  local dest="$2"
  local rel="$3"
  python3 - "$src" "$dest" "$rel" <<'PY'
import hashlib
import sys
from pathlib import Path

src = Path(sys.argv[1])
dest = Path(sys.argv[2])
rel_label = sys.argv[3]
errors = []

def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

if not src.exists():
    errors.append(f"source missing: {src}")
elif src.is_file():
    if not dest.is_file():
        errors.append(f"destination missing file: {dest}")
    elif sha256(src) != sha256(dest):
        errors.append(f"hash mismatch: {rel_label}")
elif src.is_dir():
    if not dest.is_dir():
        errors.append(f"destination missing directory: {dest}")
    else:
        for source_file in sorted(p for p in src.rglob("*") if p.is_file()):
            rel = source_file.relative_to(src)
            dest_file = dest / rel
            if not dest_file.is_file():
                errors.append(f"destination missing file: {rel_label}/{rel}")
            elif sha256(source_file) != sha256(dest_file):
                errors.append(f"hash mismatch: {rel_label}/{rel}")
else:
    errors.append(f"unsupported source type: {src}")

for error in errors:
    print(error)
raise SystemExit(1 if errors else 0)
PY
}

verify_hashes_active() {
  local failures=0
  local src_item rel dest_item base
  log "hash verification enabled"
  if [[ "$WEB3_ONLY" -eq 1 ]]; then
    while IFS=$'\t' read -r src_item rel; do
      [[ -n "$src_item" ]] || continue
      dest_item="${DEST}/${rel}"
      if hash_compare_path "$src_item" "$dest_item" "$rel"; then
        log "verify ok: ${rel} hash match"
      else
        log "verify fail: ${rel} hash mismatch"
        failures=$((failures + 1))
      fi
    done < <(manifest_entries "web3")
  else
    shopt -s nullglob
    for src_item in "$SRC_SKILLS"/*; do
      base="$(basename "$src_item")"
      rel="skills/${base}"
      if hash_compare_path "$src_item" "${DEST}/${rel}" "$rel"; then log "verify ok: ${rel} hash match"; else log "verify fail: ${rel} hash mismatch"; failures=$((failures + 1)); fi
    done
    for src_item in "$SRC_COMMANDS"/*; do
      base="$(basename "$src_item")"
      rel="commands/${base}"
      if hash_compare_path "$src_item" "${DEST}/${rel}" "$rel"; then log "verify ok: ${rel} hash match"; else log "verify fail: ${rel} hash mismatch"; failures=$((failures + 1)); fi
    done
    for src_item in "$SRC_AGENTS"/*; do
      base="$(basename "$src_item")"
      rel="agents/${base}"
      if hash_compare_path "$src_item" "${DEST}/${rel}" "$rel"; then log "verify ok: ${rel} hash match"; else log "verify fail: ${rel} hash mismatch"; failures=$((failures + 1)); fi
    done
  fi
  if [[ "$failures" -eq 0 ]]; then
    log "hash verification passed"
  else
    log "hash verification failed with ${failures} issue(s)"
    return 1
  fi
}

log "repo root: ${REPO_ROOT}"
log "destination: ${DEST}"
log "mode: ${MODE}"
[[ "$WEB3_ONLY" -eq 0 ]] || log "asset group: web3-only via ${MANIFEST}"

case "$MODE" in
  dry-run)
    if [[ "$WEB3_ONLY" -eq 1 ]]; then
      copy_manifest_group "web3"
    else
      copy_tree_entries "$SRC_SKILLS" "${DEST}/skills" "skills"
      copy_tree_entries "$SRC_COMMANDS" "${DEST}/commands" "commands"
      copy_tree_entries "$SRC_AGENTS" "${DEST}/agents" "agents"
    fi
    log "dry-run complete; rerun with --install to apply"
    ;;
  install)
    if [[ "$WEB3_ONLY" -eq 1 ]]; then
      copy_manifest_group "web3"
    else
      copy_tree_entries "$SRC_SKILLS" "${DEST}/skills" "skills"
      copy_tree_entries "$SRC_COMMANDS" "${DEST}/commands" "commands"
      copy_tree_entries "$SRC_AGENTS" "${DEST}/agents" "agents"
    fi
    verify_active
    [[ "$VERIFY_HASHES" -eq 0 ]] || verify_hashes_active
    ;;
  verify)
    verify_active
    [[ "$VERIFY_HASHES" -eq 0 ]] || verify_hashes_active
    ;;
  *)
    fail "invalid mode: ${MODE}"
    ;;
esac
