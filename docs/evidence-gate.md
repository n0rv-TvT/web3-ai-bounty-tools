# Evidence Gate

The evidence gate decides whether a lead has enough proof to support report drafting.

Minimum evidence:

- affected contract/function
- source references
- attacker capability
- exploit sequence
- concrete impact claim
- local PoC with assertions
- useful test output
- duplicate/intended-behavior notes
- known limitations

Fail the gate when:

- the PoC is scaffold-only
- assertions do not prove impact
- exploit requires unrealistic privileges
- impact is only theoretical
- output contains unsanitized secrets or private data
- duplicate or exclusion risk is unresolved
