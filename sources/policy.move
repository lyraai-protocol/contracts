/// Lyra — deterministic on-chain agent policy.
///
/// Lyra's thesis: the AI is advisory; fund controls are enforced in deterministic
/// on-chain code, NOT by the model. An `AgentPolicy` is a shared object created by
/// an owner that bounds what a delegated agent address may do: a lifetime budget
/// and per-tx cap (in MIST), an allowed coin-type list, an allowed protocol-package
/// list, an optional transfer-recipient list, an expiry, and a revoke switch.
///
/// The agent calls `enforce_spend` inside the SAME programmable transaction block
/// that moves the funds. The call aborts if the action is out of policy, and
/// otherwise records the spend and mints a `receipt::ActionReceipt` for the audit
/// trail. Because the limits live on-chain, even a fully compromised off-chain
/// agent cannot exceed them — that is why Lyra runs on Sui.
///
/// Module map:
/// - `lyra::constants` — version + the `@0x0` no-protocol sentinel.
/// - `lyra::allowlist` — shared membership/mutation rules for the three lists.
/// - `lyra::receipt`   — the `ActionReceipt` audit artifact (minted here).
/// - `lyra::vault`     — the non-custodial treasury that draws via this gate.
module lyra::policy;

use lyra::allowlist;
use lyra::constants;
use lyra::receipt::{Self, ActionReceipt};
use std::type_name;
use sui::clock::Clock;
use sui::event;

// === Errors ===

const ENotAgent: u64 = 0;
const ERevoked: u64 = 1;
const EExpired: u64 = 2;
const EOverPerTxCap: u64 = 3;
const EOverBudget: u64 = 4;
const ECoinNotAllowed: u64 = 5;
const EProtocolNotAllowed: u64 = 6;
const EWrongPolicy: u64 = 7;
const EZeroAmount: u64 = 8;
const ERecipientNotAllowed: u64 = 9;
/// The policy's recorded version is behind the running package: the owner must
/// `migrate` it before the agent can spend again.
const EWrongVersion: u64 = 10;
/// `migrate` was called on a policy that is already at the current version.
const ENotUpgrade: u64 = 11;
/// The spend would exceed the rolling per-window budget (blast-radius bound).
const EOverWindow: u64 = 12;

// === Structs ===

/// Bounds a delegated agent's authority. Shared, so the agent (who is not the
/// owner) can mutate spend accounting while acting within the same PTB.
public struct AgentPolicy has key {
    id: UID,
    /// Package version this policy is valid for; see `lyra::constants::version`.
    version: u16,
    /// Creator/controller. Only the holder of the matching `PolicyOwnerCap` may
    /// revoke, top up, migrate, or rotate the policy.
    owner: address,
    /// The single address authorized to spend under this policy.
    agent: address,
    /// Lifetime spend ceiling in MIST.
    budget_mist: u64,
    /// MIST spent so far (monotonically increasing, never exceeds budget).
    spent_mist: u64,
    /// Hard cap for a single action, in MIST.
    max_per_tx_mist: u64,
    /// Rolling spend window — the real blast-radius bound. `window_ms == 0`
    /// disables it (only the lifetime budget applies). Otherwise at most
    /// `window_budget_mist` may be spent per `window_ms`; the window resets once it
    /// elapses. This stops a single PTB (or a short burst) from looping spends to
    /// drain the whole lifetime budget at once.
    window_ms: u64,
    window_budget_mist: u64,
    window_spent_mist: u64,
    window_start_ms: u64,
    /// Reference slippage cap (bps). Enforced off-chain against live quotes;
    /// stored here so the bound is auditable on-chain.
    max_slippage_bps: u64,
    /// Allowed coin types as fully-qualified ascii bytes, e.g.
    /// b"0000...0002::sui::SUI". Empty = any coin type allowed.
    allowed_coins: vector<vector<u8>>,
    /// Allowed protocol package ids. Empty = any protocol allowed.
    allowed_protocols: vector<address>,
    /// Allowed transfer recipients. Empty = any recipient allowed (opt-in
    /// hardening): with a non-empty list the agent may only pay these addresses,
    /// even within budget.
    allowed_recipients: vector<address>,
    /// Expiry in epoch ms; 0 = never expires.
    expiry_ms: u64,
    /// When true every `enforce_spend` call aborts.
    revoked: bool,
    /// Creation time in epoch ms.
    created_ms: u64,
}

/// Capability proving control of one specific `AgentPolicy`. Held by the owner.
public struct PolicyOwnerCap has key, store {
    id: UID,
    policy_id: ID,
}

// === Events ===

public struct PolicyCreated has copy, drop {
    policy_id: ID,
    owner: address,
    agent: address,
    budget_mist: u64,
    max_per_tx_mist: u64,
    expiry_ms: u64,
}

public struct PolicyRevoked has copy, drop { policy_id: ID, by: address }

public struct BudgetToppedUp has copy, drop { policy_id: ID, added_mist: u64, budget_mist: u64 }

public struct AgentRotated has copy, drop { policy_id: ID, old_agent: address, new_agent: address }

public struct PolicyMigrated has copy, drop { policy_id: ID, from_version: u16, to_version: u16 }

public struct RecipientsSet has copy, drop { policy_id: ID, count: u64 }

public struct ProtocolAllowlistChanged has copy, drop { policy_id: ID, count: u64 }

public struct CoinAllowlistChanged has copy, drop { policy_id: ID, count: u64 }

// === Create ===

/// Composable constructor: build an `AgentPolicy` + its `PolicyOwnerCap` and
/// return them (caller becomes `owner`). Lets `lyra::vault::provision` create a
/// policy + vault in a single PTB. `create_policy` is the entry wrapper.
public fun new_policy(
    agent: address,
    budget_mist: u64,
    max_per_tx_mist: u64,
    window_ms: u64,
    window_budget_mist: u64,
    max_slippage_bps: u64,
    allowed_coins: vector<vector<u8>>,
    allowed_protocols: vector<address>,
    expiry_ms: u64,
    clock: &Clock,
    ctx: &mut TxContext,
): (AgentPolicy, PolicyOwnerCap) {
    let owner = ctx.sender();
    let now = clock.timestamp_ms();
    let policy = AgentPolicy {
        id: object::new(ctx),
        version: constants::version(),
        owner,
        agent,
        budget_mist,
        spent_mist: 0,
        max_per_tx_mist,
        window_ms,
        window_budget_mist,
        window_spent_mist: 0,
        window_start_ms: now,
        max_slippage_bps,
        allowed_coins,
        allowed_protocols,
        allowed_recipients: vector[],
        expiry_ms,
        revoked: false,
        created_ms: now,
    };
    let policy_id = object::id(&policy);
    let cap = PolicyOwnerCap { id: object::new(ctx), policy_id };
    event::emit(PolicyCreated {
        policy_id,
        owner,
        agent,
        budget_mist,
        max_per_tx_mist,
        expiry_ms,
    });
    (policy, cap)
}

/// Share a freshly-built `AgentPolicy` (key-only, so only this module may share
/// it). Lets `lyra::vault::provision` compose `new_policy` then publish it.
public fun share_policy(policy: AgentPolicy) {
    transfer::share_object(policy);
}

/// Create a shared `AgentPolicy` and transfer its `PolicyOwnerCap` to the caller.
/// The caller becomes `owner`; `agent` is the delegated spender.
entry fun create_policy(
    agent: address,
    budget_mist: u64,
    max_per_tx_mist: u64,
    window_ms: u64,
    window_budget_mist: u64,
    max_slippage_bps: u64,
    allowed_coins: vector<vector<u8>>,
    allowed_protocols: vector<address>,
    expiry_ms: u64,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    let (policy, cap) = new_policy(
        agent,
        budget_mist,
        max_per_tx_mist,
        window_ms,
        window_budget_mist,
        max_slippage_bps,
        allowed_coins,
        allowed_protocols,
        expiry_ms,
        clock,
        ctx,
    );
    transfer::public_transfer(cap, ctx.sender());
    transfer::share_object(policy);
}

// === Enforce ===

/// Deterministic gate. Aborts unless the policy is at the current package version,
/// the SENDER is the policy's agent, the policy is live (not revoked, not expired),
/// `amount_mist` is within the per-tx cap and remaining budget, and the coin type
/// `T` and `protocol` are in scope. On success it increments `spent_mist` and
/// returns an `ActionReceipt` for the caller to keep or share. Compose this in the
/// SAME PTB as the fund movement so the spend and its proof are atomic.
public fun enforce_spend<T>(
    policy: &mut AgentPolicy,
    amount_mist: u64,
    protocol: address,
    kind: vector<u8>,
    memo: vector<u8>,
    clock: &Clock,
    ctx: &mut TxContext,
): ActionReceipt {
    assert_current_version(policy);
    assert!(ctx.sender() == policy.agent, ENotAgent);
    assert!(!policy.revoked, ERevoked);
    assert!(amount_mist > 0, EZeroAmount);

    let now = clock.timestamp_ms();
    assert!(policy.expiry_ms == 0 || now <= policy.expiry_ms, EExpired);
    assert!(amount_mist <= policy.max_per_tx_mist, EOverPerTxCap);
    assert!(policy.spent_mist + amount_mist <= policy.budget_mist, EOverBudget);

    // Rolling-window blast-radius bound: reset the window if it has elapsed, then
    // cap the spend within it. This is what stops a single PTB from looping spends
    // up to the full lifetime budget. `window_ms == 0` disables the window.
    if (policy.window_ms > 0) {
        if (now >= policy.window_start_ms + policy.window_ms) {
            policy.window_start_ms = now;
            policy.window_spent_mist = 0;
        };
        assert!(
            policy.window_spent_mist + amount_mist <= policy.window_budget_mist,
            EOverWindow,
        );
        policy.window_spent_mist = policy.window_spent_mist + amount_mist;
    };

    let coin_type = type_name::with_defining_ids<T>().into_string().into_bytes();
    assert!(coin_allowed(policy, &coin_type), ECoinNotAllowed);
    assert!(protocol_allowed(policy, protocol), EProtocolNotAllowed);

    policy.spent_mist = policy.spent_mist + amount_mist;

    receipt::issue(
        object::id(policy),
        policy.agent,
        kind,
        coin_type,
        protocol,
        amount_mist,
        policy.spent_mist,
        memo,
        now,
        ctx,
    )
}

/// Standalone AUDIT receipt write — records that an action happened, WITHOUT
/// charging the budget. `enforce_spend` (which does charge) is the only path that
/// moves the spend accounting; a bare log entry must never consume budget, or the
/// agent could exhaust it (griefing) with actions that move no vault funds. Still
/// agent- and version-gated so only the delegated agent can write these.
entry fun record_action<T>(
    policy: &AgentPolicy,
    amount_mist: u64,
    protocol: address,
    kind: vector<u8>,
    memo: vector<u8>,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    assert_current_version(policy);
    assert!(ctx.sender() == policy.agent, ENotAgent);
    assert!(!policy.revoked, ERevoked);
    let coin_type = type_name::with_defining_ids<T>().into_string().into_bytes();
    let receipt = receipt::issue(
        object::id(policy),
        policy.agent,
        kind,
        coin_type,
        protocol,
        amount_mist,
        policy.spent_mist, // unchanged — audit-only, does not consume budget
        memo,
        clock.timestamp_ms(),
        ctx,
    );
    transfer::public_transfer(receipt, policy.owner);
}

/// Pure, read-only preview used by tests and off-chain dry-runs: true when an
/// action of `amount_mist` in coin `T` via `protocol` would pass right now.
public fun would_allow<T>(
    policy: &AgentPolicy,
    amount_mist: u64,
    protocol: address,
    clock: &Clock,
): bool {
    policy.version == constants::version()
        && !policy.revoked
        && amount_mist > 0
        && (policy.expiry_ms == 0 || clock.timestamp_ms() <= policy.expiry_ms)
        && amount_mist <= policy.max_per_tx_mist
        && policy.spent_mist + amount_mist <= policy.budget_mist
        && coin_allowed(policy, &type_name::with_defining_ids<T>().into_string().into_bytes())
        && protocol_allowed(policy, protocol)
}

// === Admin (owner cap) ===
//
// Owner controls are never version-gated: an upgrade may pause the agent's spend
// path (see `assert_current_version`), but the owner can always revoke, top up,
// rotate, re-scope, and — via the vault — withdraw, so an upgrade can never trap
// owner authority or funds.

/// Permanently disable the policy. Every subsequent `enforce_spend` aborts.
public fun revoke(policy: &mut AgentPolicy, cap: &PolicyOwnerCap, ctx: &TxContext) {
    assert_owner(policy, cap);
    policy.revoked = true;
    event::emit(PolicyRevoked { policy_id: object::id(policy), by: ctx.sender() });
}

/// Raise the lifetime budget ceiling.
public fun top_up(policy: &mut AgentPolicy, cap: &PolicyOwnerCap, added_mist: u64) {
    assert_owner(policy, cap);
    policy.budget_mist = policy.budget_mist + added_mist;
    event::emit(BudgetToppedUp {
        policy_id: object::id(policy),
        added_mist,
        budget_mist: policy.budget_mist,
    });
}

/// Rotate the delegated agent address (e.g. after a key rotation).
public fun rotate_agent(policy: &mut AgentPolicy, cap: &PolicyOwnerCap, new_agent: address) {
    assert_owner(policy, cap);
    let old_agent = policy.agent;
    policy.agent = new_agent;
    event::emit(AgentRotated { policy_id: object::id(policy), old_agent, new_agent });
}

/// Bring a stale policy up to the running package version so the agent can spend
/// again after an upgrade. Owner-gated and forward-only.
public fun migrate(policy: &mut AgentPolicy, cap: &PolicyOwnerCap) {
    assert_owner(policy, cap);
    let from = policy.version;
    assert!(from < constants::version(), ENotUpgrade);
    policy.version = constants::version();
    event::emit(PolicyMigrated {
        policy_id: object::id(policy),
        from_version: from,
        to_version: policy.version,
    });
}

// === Recipient allowlist (owner cap) ===

/// Owner sets the transfer-recipient allowlist. An empty vector means ANY
/// recipient is permitted — so this is opt-in hardening. With a non-empty list,
/// the agent may only transfer to those addresses, even within budget; this bounds
/// a prompt-injected or compromised agent to known payees.
public fun set_allowed_recipients(
    policy: &mut AgentPolicy,
    cap: &PolicyOwnerCap,
    recipients: vector<address>,
) {
    assert_owner(policy, cap);
    policy.allowed_recipients = recipients;
    event::emit(RecipientsSet {
        policy_id: object::id(policy),
        count: policy.allowed_recipients.length(),
    });
}

/// True when `recipient` is permitted: an empty allowlist means any recipient;
/// otherwise the recipient must be listed.
public fun recipient_allowed(policy: &AgentPolicy, recipient: address): bool {
    allowlist::allows_addr(&policy.allowed_recipients, recipient)
}

/// Abort unless `recipient` is allowed. Used by `lyra::vault::vault_transfer`.
public fun assert_recipient_allowed(policy: &AgentPolicy, recipient: address) {
    assert!(recipient_allowed(policy, recipient), ERecipientNotAllowed);
}

// === Coin + protocol allowlists (owner cap) ===
//
// The coin + protocol allowlists are seeded at creation, but the Sui ecosystem
// keeps growing — new protocols and coin types appear constantly. These owner-cap
// setters extend (or trim) the allowlists with a single tx, so a new protocol or
// asset can be authorized WITHOUT redeploying or re-provisioning. All are
// cap-gated, so only the owner — never the agent — can widen what the agent may
// touch.

/// Authorize a protocol package/registry id (idempotent). After this the agent may
/// act on `protocol` within the existing budget/cap. No-op if already present.
public fun add_allowed_protocol(policy: &mut AgentPolicy, cap: &PolicyOwnerCap, protocol: address) {
    assert_owner(policy, cap);
    if (allowlist::insert_addr(&mut policy.allowed_protocols, protocol)) {
        emit_protocol_changed(policy);
    };
}

/// De-authorize a protocol (no-op if absent).
public fun remove_allowed_protocol(
    policy: &mut AgentPolicy,
    cap: &PolicyOwnerCap,
    protocol: address,
) {
    assert_owner(policy, cap);
    if (allowlist::remove_addr(&mut policy.allowed_protocols, protocol)) {
        emit_protocol_changed(policy);
    };
}

/// Replace the entire protocol allowlist. An empty vector means ANY protocol is
/// permitted (the allowlist is opt-in hardening, same semantics as at creation).
public fun set_allowed_protocols(
    policy: &mut AgentPolicy,
    cap: &PolicyOwnerCap,
    protocols: vector<address>,
) {
    assert_owner(policy, cap);
    policy.allowed_protocols = protocols;
    emit_protocol_changed(policy);
}

/// Authorize a coin type — the fully-qualified type name as ascii bytes, e.g.
/// `b"0x2::sui::SUI"` (idempotent, no-op if already present). Matches the encoding
/// `enforce_spend` derives from `type_name::with_defining_ids<T>()`.
public fun add_allowed_coin(policy: &mut AgentPolicy, cap: &PolicyOwnerCap, coin_type: vector<u8>) {
    assert_owner(policy, cap);
    if (allowlist::insert_bytes(&mut policy.allowed_coins, coin_type)) {
        emit_coin_changed(policy);
    };
}

/// De-authorize a coin type (no-op if absent).
public fun remove_allowed_coin(
    policy: &mut AgentPolicy,
    cap: &PolicyOwnerCap,
    coin_type: vector<u8>,
) {
    assert_owner(policy, cap);
    if (allowlist::remove_bytes(&mut policy.allowed_coins, &coin_type)) {
        emit_coin_changed(policy);
    };
}

/// Replace the entire coin allowlist. An empty vector means ANY coin is permitted.
public fun set_allowed_coins(
    policy: &mut AgentPolicy,
    cap: &PolicyOwnerCap,
    coins: vector<vector<u8>>,
) {
    assert_owner(policy, cap);
    policy.allowed_coins = coins;
    emit_coin_changed(policy);
}

// === Getters ===

/// Object id of the policy a `PolicyOwnerCap` controls. Lets sibling modules
/// (e.g. `lyra::vault`) verify a caller holds the owner cap for a given policy
/// without exposing the cap's internals.
public fun owner_cap_policy_id(cap: &PolicyOwnerCap): ID { cap.policy_id }

public fun version(policy: &AgentPolicy): u16 { policy.version }

public fun owner(policy: &AgentPolicy): address { policy.owner }

public fun agent(policy: &AgentPolicy): address { policy.agent }

public fun budget_mist(policy: &AgentPolicy): u64 { policy.budget_mist }

public fun spent_mist(policy: &AgentPolicy): u64 { policy.spent_mist }

public fun remaining_mist(policy: &AgentPolicy): u64 { policy.budget_mist - policy.spent_mist }

public fun max_per_tx_mist(policy: &AgentPolicy): u64 { policy.max_per_tx_mist }

public fun window_ms(policy: &AgentPolicy): u64 { policy.window_ms }

public fun window_budget_mist(policy: &AgentPolicy): u64 { policy.window_budget_mist }

public fun window_spent_mist(policy: &AgentPolicy): u64 { policy.window_spent_mist }

public fun max_slippage_bps(policy: &AgentPolicy): u64 { policy.max_slippage_bps }

public fun expiry_ms(policy: &AgentPolicy): u64 { policy.expiry_ms }

public fun is_revoked(policy: &AgentPolicy): bool { policy.revoked }

public fun is_expired(policy: &AgentPolicy, clock: &Clock): bool {
    policy.expiry_ms != 0 && clock.timestamp_ms() > policy.expiry_ms
}

public fun allowed_coins(policy: &AgentPolicy): vector<vector<u8>> { policy.allowed_coins }

public fun allowed_protocols(policy: &AgentPolicy): vector<address> { policy.allowed_protocols }

public fun allowed_recipients(policy: &AgentPolicy): vector<address> { policy.allowed_recipients }

// === Private helpers ===

/// The policy must be at the running package version for the agent to spend.
fun assert_current_version(policy: &AgentPolicy) {
    assert!(policy.version == constants::version(), EWrongVersion);
}

/// Every owner control funnels through here: the cap must match this policy.
fun assert_owner(policy: &AgentPolicy, cap: &PolicyOwnerCap) {
    assert!(cap.policy_id == object::id(policy), EWrongPolicy);
}

fun coin_allowed(policy: &AgentPolicy, coin_type: &vector<u8>): bool {
    allowlist::allows_bytes(&policy.allowed_coins, coin_type)
}

fun protocol_allowed(policy: &AgentPolicy, protocol: address): bool {
    // The no-protocol sentinel (transfers/swaps) is ALWAYS allowed — those actions
    // are bounded by budget / per-tx cap / coin / recipient / slippage instead, so
    // a protocol allowlist restricts only named yield protocols and never blocks a
    // plain transfer or swap. Otherwise: empty allowlist = any, else must be listed.
    protocol == constants::no_protocol()
        || allowlist::allows_addr(&policy.allowed_protocols, protocol)
}

fun emit_protocol_changed(policy: &AgentPolicy) {
    event::emit(ProtocolAllowlistChanged {
        policy_id: object::id(policy),
        count: policy.allowed_protocols.length(),
    });
}

fun emit_coin_changed(policy: &AgentPolicy) {
    event::emit(CoinAllowlistChanged {
        policy_id: object::id(policy),
        count: policy.allowed_coins.length(),
    });
}

// === Test-only fixtures ===
//
// Unit + integration tests live in `tests/`. These `#[test_only]` builders let
// those modules construct a policy + cap directly (owner = the tx sender) and
// drive the real public admin functions with the returned cap.

#[test_only]
public fun new_policy_for_testing(
    agent: address,
    budget_mist: u64,
    max_per_tx_mist: u64,
    expiry_ms: u64,
    allowed_coins: vector<vector<u8>>,
    allowed_protocols: vector<address>,
    ctx: &mut TxContext,
): (AgentPolicy, PolicyOwnerCap) {
    let policy = AgentPolicy {
        id: object::new(ctx),
        version: constants::version(),
        owner: ctx.sender(),
        agent,
        budget_mist,
        spent_mist: 0,
        max_per_tx_mist,
        window_ms: 0,
        window_budget_mist: 0,
        window_spent_mist: 0,
        window_start_ms: 0,
        max_slippage_bps: 100,
        allowed_coins,
        allowed_protocols,
        allowed_recipients: vector[],
        expiry_ms,
        revoked: false,
        created_ms: 0,
    };
    let cap = PolicyOwnerCap { id: object::new(ctx), policy_id: object::id(&policy) };
    (policy, cap)
}

#[test_only]
/// Like `new_policy_for_testing` but with the rolling window armed, so tests can
/// exercise the per-window blast-radius bound. `window_start_ms` seeds at 0.
public fun new_windowed_policy_for_testing(
    agent: address,
    budget_mist: u64,
    max_per_tx_mist: u64,
    window_ms: u64,
    window_budget_mist: u64,
    ctx: &mut TxContext,
): (AgentPolicy, PolicyOwnerCap) {
    let policy = AgentPolicy {
        id: object::new(ctx),
        version: constants::version(),
        owner: ctx.sender(),
        agent,
        budget_mist,
        spent_mist: 0,
        max_per_tx_mist,
        window_ms,
        window_budget_mist,
        window_spent_mist: 0,
        window_start_ms: 0,
        max_slippage_bps: 100,
        allowed_coins: vector[],
        allowed_protocols: vector[],
        allowed_recipients: vector[],
        expiry_ms: 0,
        revoked: false,
        created_ms: 0,
    };
    let cap = PolicyOwnerCap { id: object::new(ctx), policy_id: object::id(&policy) };
    (policy, cap)
}

#[test_only]
/// A `PolicyOwnerCap` bound to a bogus policy id — for tests that a foreign cap is
/// rejected by the owner check.
public fun foreign_cap_for_testing(ctx: &mut TxContext): PolicyOwnerCap {
    PolicyOwnerCap { id: object::new(ctx), policy_id: object::id_from_address(@0xF00D) }
}

#[test_only]
/// Force a policy's recorded version (to exercise the version guard / migrate).
public fun set_version_for_testing(policy: &mut AgentPolicy, v: u16) {
    policy.version = v;
}
