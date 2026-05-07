# Evidence Ladder

Use this ladder to avoid turning weak leads into bad reports.

1. **Lead** — a signal, pattern, scanner note, or hypothesis.
2. **Source confirmation** — affected code path manually checked.
3. **Reachability** — normal attacker or realistic actor can reach the path.
4. **Invariant break** — clear violated assumption or state transition.
5. **PoC** — local exploit test proves the behavior with assertions.
6. **Control** — honest/control path proves the test is not just harness noise when practical.
7. **Impact** — stolen funds, frozen funds, bad debt, unauthorized privileged action, sensitive data leak, account takeover, or unsafe signing/tool execution.
8. **Duplicate/intended-behavior check** — docs, prior reports, issues, and known risks checked.
9. **Report gate** — final submit/kill/archive decision.

If a lead cannot climb the ladder, mark it `killed`, `duplicate`, or `na-risk` with a reason.
