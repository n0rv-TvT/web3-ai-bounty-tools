# Hypothesis

Because the toy vault credits shares using a user-provided amount before confirming the actual received amount, an attacker using a fee-on-transfer token can receive more shares than backed assets, causing an accounting mismatch.

Kill condition: if the vault uses actual balance delta accounting or rejects fee-on-transfer behavior, the hypothesis is killed.
