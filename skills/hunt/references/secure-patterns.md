# Secure Patterns — What NOT to Flag (contracts/DeFi + web)

False positives destroy credibility and cost triage standing (see the
precision gates in the reporter skill). Before filing any finding, check
this list. If the code matches a secure pattern here in spirit, it is
not a finding — it belongs in the ruled-out table. Inspired by
momenbuilds/hunt-agent-skill's references/07-secure-patterns.md.

## ERC-4626 / vaults

| Do not flag | Why it's fine |
|---|---|
| Virtual shares/assets offset (OpenZeppelin ERC4626 `_decimalsOffset`) | Canonical first-depositor-inflation defense |
| Share math priced off an external NAV/oracle rather than `totalAssets` balance | Donation/skew attacks don't apply — the price doesn't move when tokens are transferred in |
| Rounding in favor of the vault (`_convertToShares` floor / `_convertToAssets` ceil) | Spec-correct direction; attacker loses dust, never gains |
| Two-step redemption with 1:1 snapshot keyed to `msg.sender` | Request theft/sandwich impossible by construction |
| Claim bitmap indexed by leaf-position in merkle distributors | Double-claim impossible regardless of root rotation |

## Access control / upgrades

| Do not flag | Why it's fine |
|---|---|
| `onlyRole(UPGRADER_ROLE)` on UUPS `_authorizeUpgrade` where the role sits on a timelock | Upgrade hijack requires the timelock — check `hasRole` on-chain before ever filing |
| `reinitializer` guarded by any role or by correct sequential versioning | Unguarded is the bug; guarded is the pattern |
| Safe multisig admin without timelock on mint/upgrade | Centralization NOTE at most — most programs list "compromised keys / governance decisions" as OOS; file only the asymmetry (e.g. a timelock gates one path but a second path achieves the same end) |
| EOA operational roles (pauser, oracle updater) when fast reaction is the point | Document as centralization note, not a finding |

## Oracle / pricing

| Do not flag | Why it's fine |
|---|---|
| Staleness threshold + revert on stale | Working-as-designed UNLESS user paths have no degraded mode AND the outage locks funds — the lock is the finding, not the staleness check |
| Bounded rate deltas upstream (min/max/delta in the engine) | Only a finding if the CONSUMED value isn't re-validated downstream |
| Updater-asserted aggregate TVL | A trust assumption to state in the report intro, not a bug |

## Token / bridging

| Do not flag | Why it's fine |
|---|---|
| Transfer restrictions (allowFrom/allowTo) that check on every transfer | Working as designed; only gaps (unchecked paths) are findings |
| Pause flags that gate user paths but not admin rescue | Deliberate design in most vaults |
| Nonce/deadline-less permit when the token is a standard OZ ERC20Permit | Inherits the standard's nonce/replay safety |

## Web / frontend (bounty-relevant subset)

| Do not flag | Why it's fine |
|---|---|
| Spender address as a build-time constant in a dapp frontend | Drainer-resistant by construction |
| `claimTo`/recipient bound at tx-build time on-chain | No signing-confusion surface |
| Publishable keys in client bundles (Stripe pk_, Supabase anon, Maps browser key) | Designed to be public |
| `dangerouslySetInnerHTML` behind DOMPurify with an allowlist | Sanitized correctly |
| React interpolation of user input | Auto-escaped |
| Missing security headers on a static site with no sessions | Informational at most — Across-class triage will throw it back |

## Process

| Do not flag | Why it's fine |
|---|---|
| "The team could do X malicious thing" with no asymmetry or unintended consequence | Governance trust assumptions are explicitly OOS on most programs |
| Anything already in the repo's audit reports or a disclosed-report corpus hit | Known = ineligible everywhere; run dedupe first |
| Documented behavior contradicting a stale comment | Report the comment bug as info at most, inside a stronger report |
