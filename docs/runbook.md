# Private Research Runbook

Core workflow:

Lead → Hypothesis → Code Review → PoC → Execution Gate → Evidence Package → Report Gate → Submit / Kill / Archive

## New target

1. Create `targets/<target-name>/`.
2. Add `scope.md`, `notes.md`, and `target_status.md`.
3. Add the target to `targets/index.md`.
4. Store reusable target prompts or notes under the target folder, not in `framework/`.

## New finding

1. Copy `templates/finding-folder-template/` into the matching target findings status folder.
2. Copy `templates/status.json` into the finding folder.
3. Fill `summary.md`, `hypothesis.md`, and `status.json` first.
4. Move the finding between status folders as evidence improves or fails.

## PoC work

1. Keep reusable templates in `templates/`.
2. Keep generated or temporary PoCs in `generated/` or target `pocs/generated/`.
3. Save only final useful test output in `test_output.txt`.
4. Do not commit Foundry `out/`, `cache/`, or `broadcast/`.

## End of session

1. Update `status.json` for active findings.
2. Update `targets/index.md`.
3. Add `do_not_revisit_reason` for killed/duplicate/na-risk loops.
4. Sanitize reports and platform responses before committing.
5. Do not commit raw logs, secrets, or `PRIVATE_NOTES.md`.
