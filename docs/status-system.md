# Finding Status System

Use lowercase status names only. Every finding should have one current status in `status.json` and live in the matching folder under `targets/<target>/findings/` when practical.

## `idea`

Raw bug idea or observation.

Evidence needed:
- short summary
- suspected contract/function or component
- possible impact class

Move forward when the idea has enough detail for source review. Stop if it is clearly out of scope, impossible, or has no concrete impact.

## `needs-code-review`

The idea needs manual source confirmation.

Evidence needed:
- hypothesis
- files/functions to inspect
- expected vulnerable condition
- expected kill condition

Move forward when code confirms the path may exist. Kill when source code clearly blocks the idea.

## `needs-poc`

Manual review found a plausible reachable path and the next step is a PoC.

Evidence needed:
- code references
- attacker capability
- exploit sequence
- concrete assertion target

Move forward when a local test plan is clear. Stop if the exploit requires unrealistic assumptions or privileged compromise.

## `poc-written`

A PoC exists but is not yet passing or not yet trusted.

Evidence needed:
- PoC file/path
- command
- current failure or incomplete assertion
- next debugging step

Move forward when the PoC passes with meaningful assertions. Kill if the test proves the protocol blocks the exploit or the bug is only in the harness.

## `poc-passing`

The PoC passes locally and demonstrates the intended invariant break or impact.

Evidence needed:
- final command
- final test output
- exploit assertions
- control test when practical

Move forward to duplicate/scope/impact checks. Do not report yet unless the full validation gate passes.

## `killed`

The idea is invalid, blocked, intended, out of scope, or lacks impact.

Evidence needed:
- clear kill reason
- code refs or test output supporting the kill
- `do_not_revisit_reason` when useful

Stop unless new code, scope, or evidence materially changes the result.

## `duplicate`

The same root cause and impact are already known, reported, fixed, or disclosed.

Evidence needed:
- duplicate source/link/notes
- why it is the same issue
- whether any variant remains worth testing

Stop unless there is a materially different root cause, path, asset, or impact.

## `na-risk`

The issue may be technically true but likely rejected as low impact, intended behavior, griefing-only, admin-trust, MEV-only, dust-only, or otherwise weak.

Evidence needed:
- N/A-risk reason
- missing impact proof
- what would be needed to strengthen it

Stop unless stronger impact or a valid chain is found.

## `report-ready`

The finding has passed the report gate and is ready to submit.

Evidence needed:
- passing PoC
- impact proof
- scope confirmation
- duplicate/intended-behavior check
- draft report
- final validation decision

Move to `submitted` after submission. If new duplicate/scope weakness appears, move to `duplicate`, `na-risk`, or `killed`.

## `submitted`

The report was submitted to a platform or program.

Evidence needed:
- sanitized submitted report or summary
- submission date
- platform/program
- current triage status

Move to `accepted`, `rejected`, or `duplicate` when the platform responds.

## `accepted`

The platform accepted or validated the finding.

Evidence needed:
- sanitized acceptance summary
- severity/result
- payout if you choose to track it
- lessons learned

Archive after documenting the reusable lesson.

## `rejected`

The platform rejected, marked N/A, closed, or otherwise declined the finding.

Evidence needed:
- sanitized rejection summary
- reason
- whether appeal is worthwhile
- lesson learned

Archive unless there is a strong evidence-based appeal.

## `archived`

Closed, inactive, old, or preserved for history.

Evidence needed:
- final decision
- current status before archive
- reason it is not active

Do not revisit until the `do_not_revisit_until` date or a material code/scope change.
