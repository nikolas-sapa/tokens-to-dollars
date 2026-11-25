# Expected Findings (ground truth) — drill vault-target

An auditor running the `hunt` skill against this fixture should find **every**
item in section 1 and must **not** flag anything in section 2. IDs are stable
(`B1`–`B6` bugs, `T1`–`T4` traps) so drill results can be diffed and scored by
`../score.py`. Difficulty escalates roughly in order: B1/B2 easy, B3 medium,
B4/B5/B6 hard.

## 1. Must find

| ID | Sev | Name | Location |
|----|-----|------|----------|
| B1 | High | First-depositor inflation attack — no virtual offset, `totalAssets`-priced shares | `src/Vault.sol:55` (`convertToShares`) |
| B2 | Critical | Unguarded UUPS `_authorizeUpgrade` — anyone can upgrade the proxy | `src/Vault.sol:106` |
| B3 | High | Merkle airdrop double-claim — `claimed` checked, never written, no leaf bitmap | `src/MerkleAirdrop.sol:33` |
| B4 | High | Stale-NAV pricing with instant settlement — delayed oracle consumed without age check, no cooldown | `src/RedemptionQueue.sol:50` |
| B5 | Medium | Reinitializer version mismatch — `reinitializer(2)` on a proxy already at version 2, latent upgrade brick | `src/Vault.sol:44` |
| B6 | High | Redemption-queue freeze-escrow sink — frozen user can neither settle nor cancel, shares permanently locked | `src/RedemptionQueue.sol:63` |

### Evidence bars — what a correct report must demonstrate

**B1 — first-depositor inflation.** Share price is `assets * supply /
totalAssets()` with `totalAssets()` reading the raw token balance, no virtual
shares/assets offset, no minimum initial liquidity, and a 1:1 price at zero
supply. The bar: attacker deposits 1 wei first, then donates a large amount
directly to the vault via `transfer` (inflating `totalAssets` without minting
shares); a victim depositing just below the donation amount receives **0 or
near-0 shares** due to the inflated ratio, and the attacker redeems their half
of the victim's contribution. Merely noting "rounding" is NOT the bar — see
T1: the rounding direction is correct, the missing offset is the bug.

**B2 — unguarded upgrade.** `_authorizeUpgrade` has an empty body — no
`onlyOwner`, no role check. Anyone can call `upgradeToAndCall` through the
proxy, point it at a malicious implementation, and drain every asset. The bar:
name the upgrade path's missing access control specifically. (Note the
contrast with T3: had the function been `onlyOwner`, the timelock wiring would
make it a non-finding.)

**B3 — merkle double-claim.** `claim` requires `!claimed[msg.sender]` but no
write to `claimed` (or any leaf-index bitmap) ever happens — the state looks
protected and isn't. The bar: the same proof can be replayed until the
distributor balance is drained; root rotation does not fix it because nothing
is recorded per leaf or per account. The evidence is the *absence* of a state
write — count the writes in `claim`.

**B4 — stale NAV, instant settlement.** `settle` destructures
`(uint256 nav, )` — the oracle timestamp is deliberately discarded — and pays
out `shares * nav / 1e18` immediately, permissionlessly, in the same
transaction as `requestRedemption` if the caller wants. The bar has three
required parts: (1) the NAV feed is a daily-cadence desk feed (`HEARTBEAT =
24 hours`) that lags the real portfolio value; (2) settlement consumes it with
no staleness/age validation; (3) there is no cooldown or enforced delay
between request and settlement, so the stale price is instantly arbitrageable.
The attacker buys/holds shares, watches real portfolio value move (or the
publication cadence), and settles at a NAV that no longer reflects reality —
the difference is paid by the queue's buffer and socialized across remaining
holders. Flagging "the oracle can be stale" without the instant-settlement
arbitrage path does not meet the bar; flagging updater centralization is not
the bug at all (see secure-patterns: updater-asserted NAV is a stated trust
assumption).

**B5 — reinitializer version mismatch.** `initializeV1_1` already consumed
version 2 — `script/Deploy.sol` executed it, so the live proxy's
`initializedVersion()` is 2. `initializeV2` is gated `reinitializer(2)`, which
requires the recorded version to be **strictly below** 2. The bar: the v2
migration can never execute — the upgrade either bricks outright or runs with
uninitialized/stale queue and compliance wiring. Latent: everything looks fine
until the v2 upgrade is attempted. The evidence chain must cite both the
`reinitializer(2)` version collision and the deployment fact that the proxy
is already at version 2.

**B6 — freeze-escrow sink.** Shares are escrowed into the queue at
`requestRedemption` time. If compliance freezes the user while the request is
open (a freeze can land at any time — sanctions, court order), then: `settle`
reverts on the frozen check, `cancel` reverts on the frozen check — and even
without that check, `vault.transfer` back to the user would revert because the
token-level freeze hook blocks transfers to frozen accounts. There is no admin
release path either. The bar: the escrowed shares are permanently locked with
zero exit paths — freezing should block *cash-out*, but the escape hatch
(cancel/escrow release) must remain open or the escrow becomes a sink. Both
layers (queue check AND token hook) must be named; fixing only the queue check
does not fix the bug.

## 2. Must NOT flag (false-positive traps)

| ID | Item | Location | Why it's secure |
|----|------|----------|-----------------|
| T1 | Withdraw rounding rounds up (ceil), deposit rounds down | `src/Vault.sol:68` | Spec-correct ERC-4626 direction — rounding favors the vault, the user always pays the dust. B1 exists *despite* correct rounding, not because of it |
| T2 | `pauser` is an EOA | `src/Vault.sol:92` | Fast incident reaction is the entire point of a pause role; a centralization note at most — "compromised keys / governance decisions" is OOS on most programs |
| T3 | Owner functions (`setQueue`, `transferOwnership`, upgrades) carry no timelock modifier — looks asymmetric | `script/Deploy.sol:37` | Not asymmetric: ownership was transferred to the 48h `Timelock` at deployment, so *every* owner path inherits the same delay. Consistent — there is no second path that evades it. Always trace the owner before filing |
| T4 | Private keys in `test/TestKeys.sol` | `test/TestKeys.sol:7` | These are the publicly documented anvil/hardhat default account keys (`0xac0974…` is hardhat account #0) — publishable-by-design test fixtures with no possible mainnet value. A leaked-secret finding here is a false positive |

## 3. Machine-readable scoring data

`../score.py` parses the fenced block below. Key grammar per line:
`,` separates alternative clauses (OR), `+` joins required keyword groups
(AND), `/` separates synonyms within a group (OR). Matching is
case-insensitive substring against the findings file's positive space.

```scoring
bug|B1|high|src/Vault.sol|55|inflat/donation/first depositor/first-depositor/no virtual offset/virtual shares/virtual offset|Look at share pricing when totalSupply is small — what happens to the second depositor after a direct transfer() donation to the vault? (src/Vault.sol:55)
bug|B2|critical|src/Vault.sol|106|authorizeupgrade/anyone can upgrade/unprotected upgrade/unguarded upgrade/unauthorized upgrade/permissionless upgrade/upgrade access control|Who can call upgradeToAndCall? Trace _authorizeUpgrade — what guard does it have? (src/Vault.sol:106)
bug|B3|high|src/MerkleAirdrop.sol|33|double-claim/double claim/claim twice/claimed twice/never written/never set/never updated/missing bitmap/no bitmap/without a bitmap/re-claim/repeat claim|claim() checks claimed[msg.sender] — where is it ever written? Count the state writes. (src/MerkleAirdrop.sol:33)
bug|B4|high|src/RedemptionQueue.sol|50|stale/delayed/lagging+nav/oracle,instant settlement,no cooldown/without cooldown/without a cooldown/no enforced delay/no settlement delay|settle() reads latestNav() — what happens to the timestamp? Compare the 24h heartbeat against the instant, permissionless settlement path. (src/RedemptionQueue.sol:50)
bug|B5|medium|src/Vault.sol|44|reinitializer/version mismatch/upgrade brick/bricked upgrade|initializedVersion() on the live proxy is already 2 — Deploy.sol ran initializeV1_1. What does reinitializer(2) require? (src/Vault.sol:44)
bug|B6|high|src/RedemptionQueue.sol|63|frozen/freeze+cancel/stuck/locked/trapped/permanent/no exit,permanently locked/permanent lock+share/escrow|A user escrows shares, then compliance freezes them mid-flight. Enumerate every exit path for the escrowed shares. (src/RedemptionQueue.sol:63)
trap|T1|src/Vault.sol|68|incorrect rounding/wrong rounding/rounding flaw/rounding vulnerability/improper rounding/rounding against the vault/favors the user/favours the user|Rounding favors the vault — spec-correct ERC-4626 direction, user pays the dust. Not a finding.
trap|T2|src/Vault.sol|92|pauser+eoa/centraliz/single key/externally owned/unilateral|EOA pauser — fast reaction is the point; centralization note at most.
trap|T3|script/Deploy.sol|37|missing timelock/no timelock/without timelock/timelock bypass/bypass the timelock/bypasses the timelock/not timelocked/instant admin/owner can instantly|Owner IS the timelock — every owner path inherits the same 48h delay. Consistent, not asymmetric.
trap|T4|test/TestKeys.sol|7|leaked private key/exposed private key/hardcoded private key/hard-coded private key/committed private key/private key leak/plaintext private key/private key committed/compromised private key|Publicly documented anvil/hardhat test keys — publishable by design, zero mainnet value.
```

## 4. Optional / informational (nice to find, not scored)

- `initialize` sets `owner` to the deployer before the timelock handover — a brief window at deployment, inherent to the pattern.
- Single-step `transferOwnership` — minor hardening note, common in production codebases.
- The queue's asset buffer is assumed to be pre-funded by the operator — a stated trust assumption, not a bug.
- No events on `setQueue` — informational hygiene.

## How this fixture is used

See `../RUN.md`. Short version: the agent audits `vault-target/` cold without
reading this file, writes findings as markdown, and `../score.py` compares
them against the scoring block above — precision, recall, trap-discipline.
