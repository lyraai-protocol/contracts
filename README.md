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
| `policy`        | `AgentPolicy` + `PolicyOwnerCap`: the deterministic gate (`enforce_spend`), owner admin, allowlist setters, version guard. |
| `vault`         | `Vault<T>`: the non-custodial treasury. Agent draws are policy-gated; the owner escape hatch is never version-trapped. |

## The gate

`policy::enforce_spend` aborts unless the object is at the current package version,
the sender is the delegated agent, the policy is live (not revoked / not expired),
the amount is within the per-tx cap and remaining budget, and the coin type and
protocol are in scope. On success it accrues the spend and mints an `ActionReceipt`.
`vault::vault_spend` composes this with a balance-checked draw from the treasury, so
the spend and its on-chain proof are atomic.

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

The current mainnet publication is recorded in `Published.toml` (`published-at`,
`original-id`, `upgrade-capability`). CI (`.github/workflows/ci.yml`) builds and tests
the package on every push and PR.
