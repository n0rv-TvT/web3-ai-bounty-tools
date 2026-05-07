# Report Readiness

A finding is report-ready only when all seven questions are answered yes:

1. Is the target and affected component in scope?
2. Is the vulnerable code reachable in the reviewed version?
3. Can a normal attacker exploit it?
4. Does the victim take only normal protocol actions?
5. Is there concrete impact?
6. Is there a working PoC with assertions?
7. Were duplicate and intended-behavior checks completed?

If any answer is no, mark the finding as `killed`, `duplicate`, `na-risk`, or `needs-poc` instead of report-ready.

Avoid report wording like "could potentially" unless the claim is explicitly framed as a limitation and not the core impact.
