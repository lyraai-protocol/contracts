/// Lyra — the audit artifact.
///
/// Every policy-checked action mints an immutable `ActionReceipt`, owned by the
/// policy owner. It is the on-chain half of Lyra's audit trail: the off-chain
/// receipt (stored on Walrus) references this object id and the transaction
/// digest, so a spend and its proof are inseparable.
///
/// Only the policy gate may mint one — `issue` is `public(package)`, so nothing
/// outside this package can forge a receipt. `lyra::policy::enforce_spend` is the
/// sole caller.
module lyra::receipt;

use std::string::String;
use sui::event;

// === Structs ===

/// Immutable proof of one policy-checked action.
public struct ActionReceipt has key, store {
    id: UID,
    policy_id: ID,
    agent: address,
    /// Short action kind, e.g. b"transfer", b"swap", b"supply".
    kind: String,
    /// Coin type touched (ascii bytes of the fully-qualified type).
    coin_type: vector<u8>,
    /// Protocol package id touched (`lyra::constants::no_protocol()` for a native
    /// / no-protocol action).
    protocol: address,
    amount_mist: u64,
    /// Lifetime spend total AFTER this action.
    spent_after_mist: u64,
    /// Free-form note.
    memo: String,
    timestamp_ms: u64,
}

// === Events ===

public struct ActionRecorded has copy, drop {
    policy_id: ID,
    receipt_id: ID,
    agent: address,
    kind: String,
    amount_mist: u64,
    spent_after_mist: u64,
    timestamp_ms: u64,
}

// === Mint (package-only) ===

/// Mint a receipt for one action and emit `ActionRecorded`. `public(package)` so
/// only the policy gate can create one — receipts cannot be forged from outside.
public(package) fun issue(
    policy_id: ID,
    agent: address,
    kind: vector<u8>,
    coin_type: vector<u8>,
    protocol: address,
    amount_mist: u64,
    spent_after_mist: u64,
    memo: vector<u8>,
    timestamp_ms: u64,
    ctx: &mut TxContext,
): ActionReceipt {
    let receipt = ActionReceipt {
        id: object::new(ctx),
        policy_id,
        agent,
        kind: kind.to_string(),
        coin_type,
        protocol,
        amount_mist,
        spent_after_mist,
        memo: memo.to_string(),
        timestamp_ms,
    };
    event::emit(ActionRecorded {
        policy_id,
        receipt_id: object::id(&receipt),
        agent,
        kind: receipt.kind,
        amount_mist,
        spent_after_mist,
        timestamp_ms,
    });
    receipt
}

// === Getters ===

public fun policy_id(r: &ActionReceipt): ID { r.policy_id }

public fun agent(r: &ActionReceipt): address { r.agent }

public fun kind(r: &ActionReceipt): String { r.kind }

public fun coin_type(r: &ActionReceipt): vector<u8> { r.coin_type }

public fun protocol(r: &ActionReceipt): address { r.protocol }

public fun amount_mist(r: &ActionReceipt): u64 { r.amount_mist }

public fun spent_after_mist(r: &ActionReceipt): u64 { r.spent_after_mist }

public fun memo(r: &ActionReceipt): String { r.memo }

public fun timestamp_ms(r: &ActionReceipt): u64 { r.timestamp_ms }
