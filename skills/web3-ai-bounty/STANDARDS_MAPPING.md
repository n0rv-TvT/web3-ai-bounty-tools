# Smart Contract Security Standards Mapping

Purpose: map findings and leads to recognized standards without treating standards compliance as a bounty finding by itself.

Primary references:

- SWC Registry (useful but dated)
- OWASP Smart Contract Top 10
- EEA EthTrust Security Levels
- SCSVS / Smart Contract Security Verification Standard
- OpenZeppelin security guidelines and Contracts docs
- ConsenSys Smart Contract Best Practices
- Secureum, Code4rena, Sherlock, Cantina common bug classes

## Standards Rule

Standards tags improve explanation and remediation. They do not prove impact.

Report-ready still requires:

```text
in-scope + reachable + normal attacker + concrete impact + passing PoC + duplicate/intended-behavior check
```

## Mapping Table

| Local class | SWC | OWASP SC Top 10 alignment | EthTrust/SCSVS/OZ alignment | Impact proof required |
|---|---|---|---|---|
| reentrancy | SWC-107 | Reentrancy / Unsafe external calls | CEI, reentrancy guards, external-call safety | double withdraw/claim/borrow, stale-rate extraction |
| integer overflow/underflow | SWC-101 | Arithmetic errors | checked arithmetic, bounds | value mis-accounting or revert/freeze |
| rounding/precision loss | - | Logic/accounting errors | correct fixed-point math | attacker profit, victim loss, bad debt |
| access control missing | SWC-105/SWC-106 | Access control failures | least privilege, role checks | unauthorized state/fund movement |
| tx.origin auth | SWC-115 | Access control failures | msg.sender auth | phishing/call-chain privilege bypass |
| unchecked external call | SWC-104 | Unsafe external calls | return-value validation | false success causes fund/accounting impact |
| unprotected selfdestruct/delegatecall | SWC-106/SWC-112 | Unsafe low-level/delegatecall | restricted delegatecall | takeover/fund theft/storage corruption |
| timestamp/block dependence | SWC-116 | Oracle/time manipulation | temporal assumptions | measurable value extraction or bypass |
| weak randomness | SWC-120 | Weak randomness | VRF/commit-reveal | attacker biases outcome for profit |
| signature replay | SWC-121-ish | Cryptographic/auth failures | EIP-712 domain/nonces/deadlines | same signature used twice/wrong context |
| oracle stale/manipulated | - | Oracle manipulation | freshness/confidence/TWAP | bad debt, unfair liquidation, theft |
| ERC4626 inflation | - | Business logic/accounting | virtual shares/assets, previews | victim shares/assets stolen |
| proxy initialization | SWC-118-ish | Access control/upgradeability | disable initializers, storage layout | ownership/upgrade/admin takeover |
| storage collision | SWC-124-ish | Upgradeability failures | append-only layout, ERC1967 | corrupted privileged/accounting state |
| bridge replay/double finalize | - | Cross-chain/message validation | message domain/state machine | mint/release > lock/burn or accepted freeze |
| fee-on-transfer/rebasing accounting | - | Token integration failure | balanceBefore/after | accounting exceeds real balance |
| DoS via external receiver | SWC-113 | Denial of service | pull payments/failure isolation | accepted freeze duration/no recovery |
| front-running/slippage | SWC-114 | MEV/transaction ordering | slippage/deadline/minOut | accepted impact, not excluded MEV-only |
| arbitrary call target | - | Access control/tool misuse | allowlists/policy | attacker drains approval/funds or privileged action |
| AI unsafe signing/tool call | - | AI/tool boundary security | explicit confirmation/policy | unauthorized tx/tool/data leak |

## OpenZeppelin-Aligned Checks

- Use `SafeERC20` for non-standard ERC20s.
- Use `ReentrancyGuard` or CEI where external calls touch value state.
- Use `AccessControl`/`Ownable2Step` intentionally with clear role ownership.
- Disable implementation initializers with `_disableInitializers()`.
- Use `UUPSUpgradeable._authorizeUpgrade` with strict role/timelock.
- Use EIP-712 domains with chainId, verifyingContract, nonce, deadline, action-specific typehash.
- Use ERC4626 virtual offsets or minimum liquidity where donation inflation matters.
- Preserve upgradeable storage layout.

## Standard-To-Report Language

Good:

```text
This maps to SWC-107-style reentrancy, but the reportable impact is the PoC showing the attacker withdraws 10 ETH more than their entitlement.
```

Bad:

```text
This violates SWC-107, therefore it is high severity.
```
