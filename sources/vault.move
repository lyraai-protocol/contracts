/// Lyra — non-custodial treasury vault.
///
/// The upgrade that makes Lyra production-grade. User funds live in an on-chain
/// `Vault`, NOT in the agent's EOA. The delegated agent can only draw funds via
/// `vault_spend`, which re-runs the full `lyra::policy` gate on-chain (agent
/// identity, budget, per-tx cap, coin/protocol allowlists, expiry, revoke,
/// version). So a compromised agent key — or even a leaked server signing key —
/// is bounded by the policy and revocable by the owner, who can also pull the
/// whole treasury back at any time with `owner_withdraw`. The platform never has
/// unbounded access to user funds; the agent is a delegate, not a custodian.
///
/// Version guard: the agent spend path asserts the vault is at the running
/// package version, but `deposit` and `owner_withdraw` never do — so an upgrade
/// can pause agent spending without ever trapping the owner's funds.
module lyra::vault;

use lyra::constants;
use lyra::policy::{Self, AgentPolicy, PolicyOwnerCap};
use lyra::receipt::ActionReceipt;
use sui::balance::{Self, Balance};
use sui::clock::Clock;
use sui::coin::{Self, Coin};
use sui::event;

// === Errors ===

const EWrongVault: u64 = 0;
const EInsufficientVault: u64 = 1;
const ENotVaultOwner: u64 = 2;
/// The vault's recorded version is behind the running package: the owner must
/// `migrate` it before the agent can spend again.
const EWrongVersion: u64 = 3;
/// `migrate` was called on a vault that is already at the current version.
const ENotUpgrade: u64 = 4;

// === Structs ===

/// A treasury vault holding funds of coin type `T`, bound to one `AgentPolicy`.
public struct Vault<phantom T> has key {
    id: UID,
    /// Package version this vault is valid for; see `lyra::constants::version`.
    version: u16,
    /// The policy that governs spends from this vault.
    policy_id: ID,
    /// Who opened it (should be the policy owner). The owner cap is the real gate.
    owner: address,
    balance: Balance<T>,
}

// === Events ===

public struct VaultOpened has copy, drop { vault_id: ID, policy_id: ID, owner: address }

public struct VaultDeposited has copy, drop { vault_id: ID, amount: u64, balance: u64 }

public struct VaultSpent has copy, drop { vault_id: ID, policy_id: ID, amount: u64, balance: u64 }

public struct VaultWithdrawn has copy, drop { vault_id: ID, amount: u64, by: address }

public struct VaultMigrated has copy, drop { vault_id: ID, from_version: u16, to_version: u16 }

// === Open / fund ===

/// Construct a vault bound to `policy` (composable). Caller becomes the owner.
public fun new<T>(policy: &AgentPolicy, ctx: &mut TxContext): Vault<T> {
    let vault = Vault<T> {
        id: object::new(ctx),
        version: constants::version(),
        policy_id: object::id(policy),
        owner: ctx.sender(),
        balance: balance::zero<T>(),
    };
    event::emit(VaultOpened {
        vault_id: object::id(&vault),
        policy_id: object::id(policy),
        owner: ctx.sender(),
    });
    vault
}

/// Open + share a treasury vault of coin type `T`, bound to `policy`.
entry fun open<T>(policy: &AgentPolicy, ctx: &mut TxContext) {
    transfer::share_object(new<T>(policy, ctx));
}

/// One-signature onboarding. The owner (caller) creates an `AgentPolicy`
/// delegating to `agent`, opens a vault of coin `T`, deposits `funds`, and
/// receives the `PolicyOwnerCap` — all atomically. The policy + vault are shared;
/// the cap goes to the owner. After this, the delegated agent can `vault_spend`
/// within the policy, and the owner can `owner_withdraw` / revoke any time.
entry fun provision<T>(
    agent: address,
    budget_mist: u64,
    max_per_tx_mist: u64,
    max_slippage_bps: u64,
    allowed_coins: vector<vector<u8>>,
    allowed_protocols: vector<address>,
    expiry_ms: u64,
    funds: Coin<T>,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    let (policy, cap) = policy::new_policy(
        agent,
        budget_mist,
        max_per_tx_mist,
        max_slippage_bps,
        allowed_coins,
        allowed_protocols,
        expiry_ms,
        clock,
        ctx,
    );
    let mut vault = new<T>(&policy, ctx);
    deposit(&mut vault, funds);
    transfer::public_transfer(cap, ctx.sender());
    policy::share_policy(policy);
    transfer::share_object(vault);
}

/// Deposit funds into the vault. Anyone may fund it (typically the owner). Not
/// version-gated: topping up a vault is always safe.
public fun deposit<T>(vault: &mut Vault<T>, coin: Coin<T>) {
    let amount = coin.value();
    balance::join(&mut vault.balance, coin.into_balance());
    event::emit(VaultDeposited {
        vault_id: object::id(vault),
        amount,
        balance: vault.balance.value(),
    });
}

/// Entry wrapper: deposit a whole coin object.
entry fun deposit_entry<T>(vault: &mut Vault<T>, coin: Coin<T>) {
    deposit(vault, coin);
}

// === Spend (agent, policy-enforced) ===

/// The policy-enforced spend. The delegated agent draws `amount_mist` of `T` from
/// the vault, gated by the full on-chain policy via `policy::enforce_spend`
/// (aborts unless the SENDER is the agent and the action is within budget, per-tx
/// cap, coin/protocol allowlists, expiry, version, and the policy is not revoked).
/// Returns the `Coin<T>` for the agent to use in the SAME PTB (transfer / swap /
/// supply) plus the audit `ActionReceipt`.
public fun vault_spend<T>(
    vault: &mut Vault<T>,
    policy: &mut AgentPolicy,
    amount_mist: u64,
    protocol: address,
    kind: vector<u8>,
    memo: vector<u8>,
    clock: &Clock,
    ctx: &mut TxContext,
): (Coin<T>, ActionReceipt) {
    assert!(vault.version == constants::version(), EWrongVersion);
    assert!(vault.policy_id == object::id(policy), EWrongVault);
    assert!(vault.balance.value() >= amount_mist, EInsufficientVault);
    let receipt = policy::enforce_spend<T>(policy, amount_mist, protocol, kind, memo, clock, ctx);
    let coin = coin::take(&mut vault.balance, amount_mist, ctx);
    event::emit(VaultSpent {
        vault_id: object::id(vault),
        policy_id: object::id(policy),
        amount: amount_mist,
        balance: vault.balance.value(),
    });
    (coin, receipt)
}

/// Recipient-checked transfer from the vault. Enforces the policy's optional
/// recipient allowlist ON-CHAIN, then draws `amount_mist` via the full policy gate
/// (`vault_spend`) and sends it to `recipient`; the receipt goes to the owner.
/// This is the hardened path for agent transfers — with a recipient allowlist set,
/// a prompt-injected or compromised agent can still only pay the owner's approved
/// payees, even within budget.
public fun vault_transfer<T>(
    vault: &mut Vault<T>,
    policy: &mut AgentPolicy,
    amount_mist: u64,
    recipient: address,
    memo: vector<u8>,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    policy::assert_recipient_allowed(policy, recipient);
    let no_protocol = constants::no_protocol();
    let (coin, receipt) = vault_spend<T>(
        vault,
        policy,
        amount_mist,
        no_protocol,
        b"transfer",
        memo,
        clock,
        ctx,
    );
    transfer::public_transfer(coin, recipient);
    transfer::public_transfer(receipt, policy::owner(policy));
}

// === Withdraw (owner escape hatch) ===

/// Owner pulls funds back out. Cap-gated: only the holder of the matching
/// `PolicyOwnerCap` may withdraw. Never version-gated — the treasury is always
/// fully recoverable by the owner, regardless of the agent OR a pending migration.
public fun owner_withdraw<T>(
    vault: &mut Vault<T>,
    cap: &PolicyOwnerCap,
    amount: u64,
    ctx: &mut TxContext,
): Coin<T> {
    assert!(policy::owner_cap_policy_id(cap) == vault.policy_id, ENotVaultOwner);
    assert!(vault.balance.value() >= amount, EInsufficientVault);
    let coin = coin::take(&mut vault.balance, amount, ctx);
    event::emit(VaultWithdrawn { vault_id: object::id(vault), amount, by: ctx.sender() });
    coin
}

/// Entry wrapper: owner withdraws `amount` to `to`.
entry fun owner_withdraw_to<T>(
    vault: &mut Vault<T>,
    cap: &PolicyOwnerCap,
    amount: u64,
    to: address,
    ctx: &mut TxContext,
) {
    transfer::public_transfer(owner_withdraw<T>(vault, cap, amount, ctx), to);
}

// === Migrate (owner cap) ===

/// Bring a stale vault up to the running package version so the agent can spend
/// from it again after an upgrade. Owner-gated and forward-only.
public fun migrate<T>(vault: &mut Vault<T>, cap: &PolicyOwnerCap) {
    assert!(policy::owner_cap_policy_id(cap) == vault.policy_id, ENotVaultOwner);
    let from = vault.version;
    assert!(from < constants::version(), ENotUpgrade);
    vault.version = constants::version();
    event::emit(VaultMigrated {
        vault_id: object::id(vault),
        from_version: from,
        to_version: vault.version,
    });
}

// === Getters ===

public fun value<T>(vault: &Vault<T>): u64 { vault.balance.value() }

public fun version<T>(vault: &Vault<T>): u16 { vault.version }

public fun policy_id<T>(vault: &Vault<T>): ID { vault.policy_id }

public fun owner<T>(vault: &Vault<T>): address { vault.owner }

// === Test-only fixtures ===

#[test_only]
/// Force a vault's recorded version (to exercise the version guard / migrate).
public fun set_version_for_testing<T>(vault: &mut Vault<T>, v: u16) {
    vault.version = v;
}
