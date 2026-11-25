# Drill Vault — RWA yield vault protocol (fixture)

This is a **static code fixture**, not a runnable project. It exists so the
`hunt` skill can be drilled: an auditor should produce findings for this
codebase cold, and those findings are then scored against
[`expected-findings.md`](./expected-findings.md) — which auditors must NOT
read before or during the audit (see `../RUN.md`).

No foundry/npm install needed. Plain `.sol` reading material; nothing here is
deployed and all keys and addresses are fake.

## Protocol overview

RWA-style yield vault. Users deposit `dUSD` (the underlying) and receive
`vRWA` vault shares. Small exits use the instant `withdraw` path; large exits
route through a two-step redemption queue settled at the portfolio NAV
published daily by the operations desk. The vault is UUPS-upgradeable and
carries a compliance freeze layer for regulated transfer restrictions. Early
LPs receive shares through a merkle-distributed airdrop.

```
src/
  Vault.sol            ERC-4626-shaped share vault, UUPS-upgradeable
  RedemptionQueue.sol  two-step NAV-settled redemption facility
  NavOracle.sol        daily portfolio NAV feed (operations desk)
  MerkleAirdrop.sol    merkle-proof share distributor
  Compliance.sol       freeze registry for regulated transfers
  Timelock.sol         48h governance timelock
  ERC20.sol            minimal token + TestAsset underlying
  Initializable.sol    storage-version tracker
  UUPS.sol             ERC-1967 proxy + upgrade logic
script/
  Deploy.sol           reference deployment wiring (documents live state)
test/
  TestKeys.sol         local fork-test actors
```
