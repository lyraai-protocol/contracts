# Lyra contracts

The on-chain half of [Lyra AI](https://lyraai.space) — a Sui-native, policy-bound,
non-custodial AI finance agent. The AI is advisory; **fund controls are enforced
here, in deterministic Move**, not by the model. A fully compromised off-chain
agent still cannot exceed the limits an owner set on-chain.

## Modules

| Module          | Responsibility                                                                 |
| --------------- | ------------------------------------------------------------------------------ |
| `constants`     | Package version + the `@0x0` "no specific protocol" sentinel (accessor funcs). |
| `allowlist`     | Reusable membership + idempotent mutation over the coin/protocol/recipient lists (empty = any). |
| `receipt`       | The immutable `ActionReceipt` audit artifact — only the policy gate can mint one (`public(package)`). |
| `policy`        | `AgentPolicy` + `PolicyOwnerCap`: the deterministic gate (`enforce_spend`), the rolling-window blast-radius bound, owner admin, allowlist setters (coin / protocol / recipient), version guard. |
| `vault`         | `Vault<T>`: the non-custodial, per-asset treasury. Every agent draw is policy-gated through one of three bounded exits; the owner escape hatch is never version-trapped. |

## The gate

`policy::enforce_spend` aborts unless the object is at the current package version,
the sender is the delegated agent, the policy is live (not revoked / not expired),
the amount is within the per-tx cap **and** the remaining lifetime budget **and** the
rolling per-window budget, and the coin type and protocol are in scope. On success it
accrues the spend (lifetime + window) and mints an `ActionReceipt`. There is exactly
one internal path that removes funds from a vault (`spend_internal`); it is **not**
public — every caller reaches it through a bounded exit below.

## Spend paths (no unchecked exit)

The agent can move treasury funds only through these, each with an on-chain bound a
compromised or prompt-injected agent cannot exceed:

| Exit | Use | Bound |
| --- | --- | --- |
| `vault_transfer<T>` | plain sends | enforces the policy's **recipient allowlist** on-chain — the agent can only pay owner-approved payees. |
| `vault_borrow<T>` → `vault_settle<U>` | swaps / round-trips | a `FlashSpend` **hot potato**: the drawn coin must be settled back into a vault under the same policy in the SAME PTB — **zero standing exposure**, the output can't be pocketed. |
| `vault_spend_capped<T>` | staking / lending, whose output is not a returnable coin | the **only** path with standing exposure — deliberately capped by the **rolling window** (a compromised agent misdirects at most one window's budget) and restricted to a **named** protocol. |

## Blast-radius bound

Beyond the lifetime budget, each `AgentPolicy` carries a rolling window
(`window_ms` / `window_budget_mist`). `enforce_spend` resets the window when it
elapses and caps spend within it — so a single PTB (or a burst) can drain at most one
window's budget, giving the owner time to `revoke`. `window_ms == 0` disables it.

## Version guard

Each `AgentPolicy` and `Vault` records the package `version` it was created at. The
**agent spend path** asserts the object is current, so a package upgrade can pause a
stale object until the owner calls `migrate`. **Owner controls — `revoke`, the
allowlist setters, and `owner_withdraw` — are never version-gated**, so an upgrade can
pause the agent but can never trap owner authority or funds.

## Develop

```bash
sui move build      # compile
sui move test       # run the unit + integration suite (tests/)
```

## Deployment

Live on **Sui mainnet**: `0xcd6943c0c4397f9d56c908f6e6952056bf469aa062afc7be9af358aba8fe15c5`
(full record — `published-at`, `original-id`, `upgrade-capability` — in `Published.toml`).

This is a **fresh publish**, not an upgrade: the model-B rework changed struct layouts
and public signatures (breaking), which Sui's on-chain compatibility check rejects for
an upgrade. The previous package (`0x1925bced…`) had an unchecked `vault_spend` exit and
is **deprecated**; funds in any old vault remain owner-recoverable via `owner_withdraw`.

CI (`.github/workflows/ci.yml`) builds and tests the package (44 tests) on every push and PR.
