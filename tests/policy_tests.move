#[test_only]
module lyra::policy_tests;

use lyra::policy::{Self, AgentPolicy, PolicyOwnerCap};
use std::unit_test::destroy;
use sui::clock;
use sui::sui::SUI;
use std::type_name;

// tx_context::dummy() sender — set as the policy agent so `enforce_spend` passes
// the on-chain agent check by default.
const AGENT: address = @0x0;

fun sui_type(): vector<u8> { type_name::with_defining_ids<SUI>().into_string().into_bytes() }

/// Build a policy + cap with the dummy-ctx sender as agent.
fun mk(
    budget: u64,
    per_tx: u64,
    expiry: u64,
    coins: vector<vector<u8>>,
    protocols: vector<address>,
    ctx: &mut TxContext,
): (AgentPolicy, PolicyOwnerCap) {
    policy::new_policy_for_testing(AGENT, budget, per_tx, expiry, coins, protocols, ctx)
}

#[test]
fun spends_within_limits_and_accrues() {
    let mut ctx = tx_context::dummy();
    let clk = clock::create_for_testing(&mut ctx);
    let (mut policy, cap) = mk(1000, 600, 0, vector[], vector[], &mut ctx);

    let r1 = policy.enforce_spend<SUI>(400, @0x0, b"transfer", b"first", &clk, &mut ctx);
    assert!(policy.spent_mist() == 400);
    assert!(r1.amount_mist() == 400);
    assert!(policy.remaining_mist() == 600);

    let r2 = policy.enforce_spend<SUI>(600, @0x0, b"transfer", b"second", &clk, &mut ctx);
    assert!(policy.spent_mist() == 1000);
    assert!(r2.spent_after_mist() == 1000);
    assert!(policy.remaining_mist() == 0);

    destroy(r1);
    destroy(r2);
    destroy(policy);
    destroy(cap);
    clock::destroy_for_testing(clk);
}

#[test, expected_failure(abort_code = lyra::policy::EOverPerTxCap)]
fun blocks_over_per_tx_cap() {
    let mut ctx = tx_context::dummy();
    let clk = clock::create_for_testing(&mut ctx);
    let (mut policy, cap) = mk(10_000, 500, 0, vector[], vector[], &mut ctx);
    let r = policy.enforce_spend<SUI>(501, @0x0, b"transfer", b"", &clk, &mut ctx);
    destroy(r);
    destroy(policy);
    destroy(cap);
    clock::destroy_for_testing(clk);
}

#[test, expected_failure(abort_code = lyra::policy::EOverBudget)]
fun blocks_over_budget() {
    let mut ctx = tx_context::dummy();
    let clk = clock::create_for_testing(&mut ctx);
    let (mut policy, cap) = mk(1000, 1000, 0, vector[], vector[], &mut ctx);
    let r1 = policy.enforce_spend<SUI>(700, @0x0, b"transfer", b"", &clk, &mut ctx);
    destroy(r1);
    // 700 + 400 = 1100 > 1000 budget — this call aborts.
    let r2 = policy.enforce_spend<SUI>(400, @0x0, b"transfer", b"", &clk, &mut ctx);
    destroy(r2);
    destroy(policy);
    destroy(cap);
    clock::destroy_for_testing(clk);
}

#[test, expected_failure(abort_code = lyra::policy::EOverWindow)]
/// Two spends inside one rolling window that together exceed the window budget:
/// the second aborts, even though each is within the per-tx cap AND the lifetime
/// budget. This is the blast-radius bound a single PTB can't loop around.
fun window_caps_burst() {
    let mut ctx = tx_context::dummy();
    let clk = clock::create_for_testing(&mut ctx);
    // lifetime budget 10_000, per-tx 500, window 1000ms / 600 per window.
    let (mut policy, cap) =
        policy::new_windowed_policy_for_testing(AGENT, 10_000, 500, 1000, 600, &mut ctx);
    let r1 = policy.enforce_spend<SUI>(400, @0x0, b"swap", b"", &clk, &mut ctx);
    destroy(r1);
    // 400 + 300 = 700 > 600 window budget, same window (clock unchanged) → aborts.
    let r2 = policy.enforce_spend<SUI>(300, @0x0, b"swap", b"", &clk, &mut ctx);
    destroy(r2);
    destroy(policy);
    destroy(cap);
    clock::destroy_for_testing(clk);
}

#[test]
/// Once the window elapses the allowance resets, so a spend that would have
/// exceeded the previous window succeeds after time passes; the lifetime budget
/// keeps accumulating across windows.
fun window_resets_after_elapse() {
    let mut ctx = tx_context::dummy();
    let mut clk = clock::create_for_testing(&mut ctx);
    let (mut policy, cap) =
        policy::new_windowed_policy_for_testing(AGENT, 10_000, 500, 1000, 600, &mut ctx);
    let r1 = policy.enforce_spend<SUI>(400, @0x0, b"swap", b"", &clk, &mut ctx);
    assert!(policy.window_spent_mist() == 400);
    destroy(r1);
    // Advance past the window; the next spend resets the window allowance.
    clock::increment_for_testing(&mut clk, 1001);
    let r2 = policy.enforce_spend<SUI>(500, @0x0, b"swap", b"", &clk, &mut ctx);
    assert!(policy.window_spent_mist() == 500); // reset, then charged
    assert!(policy.spent_mist() == 900); // lifetime keeps accumulating
    destroy(r2);
    destroy(policy);
    destroy(cap);
    clock::destroy_for_testing(clk);
}

#[test, expected_failure(abort_code = lyra::policy::ERevoked)]
fun blocks_when_revoked() {
    let mut ctx = tx_context::dummy();
    let clk = clock::create_for_testing(&mut ctx);
    let (mut policy, cap) = mk(1000, 1000, 0, vector[], vector[], &mut ctx);
    policy.revoke(&cap, &ctx);
    let r = policy.enforce_spend<SUI>(100, @0x0, b"transfer", b"", &clk, &mut ctx);
    destroy(r);
    destroy(policy);
    destroy(cap);
    clock::destroy_for_testing(clk);
}

#[test, expected_failure(abort_code = lyra::policy::EExpired)]
fun blocks_when_expired() {
    let mut ctx = tx_context::dummy();
    let mut clk = clock::create_for_testing(&mut ctx);
    clk.set_for_testing(5_000);
    let (mut policy, cap) = mk(1000, 1000, 1_000, vector[], vector[], &mut ctx); // expiry 1s, now 5s
    let r = policy.enforce_spend<SUI>(100, @0x0, b"transfer", b"", &clk, &mut ctx);
    destroy(r);
    destroy(policy);
    destroy(cap);
    clock::destroy_for_testing(clk);
}

#[test, expected_failure(abort_code = lyra::policy::ENotAgent)]
fun blocks_wrong_agent() {
    let mut ctx = tx_context::dummy();
    let clk = clock::create_for_testing(&mut ctx);
    let (mut policy, cap) = mk(1000, 1000, 0, vector[], vector[], &mut ctx);
    policy.rotate_agent(&cap, @0xBEEF); // ctx sender is @0x0, so the agent check fails
    let r = policy.enforce_spend<SUI>(100, @0x0, b"transfer", b"", &clk, &mut ctx);
    destroy(r);
    destroy(policy);
    destroy(cap);
    clock::destroy_for_testing(clk);
}

#[test, expected_failure(abort_code = lyra::policy::ECoinNotAllowed)]
fun blocks_coin_not_in_allowlist() {
    let mut ctx = tx_context::dummy();
    let clk = clock::create_for_testing(&mut ctx);
    // Allowlist a bogus coin type, so SUI is rejected.
    let (mut policy, cap) = mk(1000, 1000, 0, vector[b"0x0::nope::NOPE"], vector[], &mut ctx);
    let r = policy.enforce_spend<SUI>(100, @0x0, b"transfer", b"", &clk, &mut ctx);
    destroy(r);
    destroy(policy);
    destroy(cap);
    clock::destroy_for_testing(clk);
}

#[test]
fun allows_coin_in_allowlist() {
    let mut ctx = tx_context::dummy();
    let clk = clock::create_for_testing(&mut ctx);
    let (mut policy, cap) = mk(1000, 1000, 0, vector[sui_type()], vector[], &mut ctx);
    let r = policy.enforce_spend<SUI>(100, @0x0, b"transfer", b"", &clk, &mut ctx);
    destroy(r);
    destroy(policy);
    destroy(cap);
    clock::destroy_for_testing(clk);
}

#[test, expected_failure(abort_code = lyra::policy::EProtocolNotAllowed)]
fun blocks_protocol_not_in_allowlist() {
    let mut ctx = tx_context::dummy();
    let clk = clock::create_for_testing(&mut ctx);
    let (mut policy, cap) = mk(1000, 1000, 0, vector[], vector[@0xDEE9], &mut ctx);
    // Action touches @0xBAD, not the single allowed protocol.
    let r = policy.enforce_spend<SUI>(100, @0xBAD, b"swap", b"", &clk, &mut ctx);
    destroy(r);
    destroy(policy);
    destroy(cap);
    clock::destroy_for_testing(clk);
}

#[test, expected_failure(abort_code = lyra::policy::EZeroAmount)]
fun blocks_zero_amount() {
    let mut ctx = tx_context::dummy();
    let clk = clock::create_for_testing(&mut ctx);
    let (mut policy, cap) = mk(1000, 1000, 0, vector[], vector[], &mut ctx);
    let r = policy.enforce_spend<SUI>(0, @0x0, b"transfer", b"", &clk, &mut ctx);
    destroy(r);
    destroy(policy);
    destroy(cap);
    clock::destroy_for_testing(clk);
}

#[test]
fun would_allow_tracks_state() {
    let mut ctx = tx_context::dummy();
    let clk = clock::create_for_testing(&mut ctx);
    let (mut policy, cap) = mk(1000, 600, 0, vector[], vector[], &mut ctx);
    assert!(policy.would_allow<SUI>(600, @0x0, &clk));
    assert!(!policy.would_allow<SUI>(601, @0x0, &clk)); // over per-tx cap
    let r = policy.enforce_spend<SUI>(600, @0x0, b"transfer", b"", &clk, &mut ctx);
    destroy(r);
    assert!(!policy.would_allow<SUI>(600, @0x0, &clk)); // only 400 budget left
    assert!(policy.would_allow<SUI>(400, @0x0, &clk));
    destroy(policy);
    destroy(cap);
    clock::destroy_for_testing(clk);
}

#[test]
fun top_up_raises_budget() {
    let mut ctx = tx_context::dummy();
    let (mut policy, cap) = mk(500, 500, 0, vector[], vector[], &mut ctx);
    policy.top_up(&cap, 1_000);
    assert!(policy.budget_mist() == 1_500);
    destroy(cap);
    destroy(policy);
}

#[test]
fun set_max_per_tx_lifts_the_cap() {
    let mut ctx = tx_context::dummy();
    let clk = clock::create_for_testing(&mut ctx);
    let (mut policy, cap) = mk(10_000, 500, 0, vector[], vector[], &mut ctx);
    // 800 would exceed the initial 500 per-tx cap; raise the cap, then it goes through.
    policy.set_max_per_tx(&cap, 9_000);
    assert!(policy.max_per_tx_mist() == 9_000);
    let r = policy.enforce_spend<SUI>(800, @0x0, b"transfer", b"", &clk, &mut ctx);
    assert!(policy.spent_mist() == 800);
    destroy(r);
    destroy(cap);
    destroy(policy);
    clock::destroy_for_testing(clk);
}

#[test]
fun set_budget_and_window_budget_update() {
    let mut ctx = tx_context::dummy();
    let (mut policy, cap) = mk(500, 500, 0, vector[], vector[], &mut ctx);
    policy.set_budget(&cap, 20_000);
    assert!(policy.budget_mist() == 20_000);
    policy.set_window_budget(&cap, 5_000);
    assert!(policy.window_budget_mist() == 5_000);
    destroy(cap);
    destroy(policy);
}

#[test, expected_failure(abort_code = lyra::policy::EBudgetBelowSpent)]
fun set_budget_below_spent_aborts() {
    let mut ctx = tx_context::dummy();
    let clk = clock::create_for_testing(&mut ctx);
    let (mut policy, cap) = mk(10_000, 5_000, 0, vector[], vector[], &mut ctx);
    let r = policy.enforce_spend<SUI>(4_000, @0x0, b"transfer", b"", &clk, &mut ctx);
    // 4_000 already spent; setting the budget below that must abort.
    policy.set_budget(&cap, 3_000);
    destroy(r);
    destroy(cap);
    destroy(policy);
    clock::destroy_for_testing(clk);
}

#[test, expected_failure(abort_code = lyra::policy::EWrongPolicy)]
fun set_max_per_tx_rejects_foreign_cap() {
    let mut ctx = tx_context::dummy();
    let (mut policy, cap) = mk(500, 500, 0, vector[], vector[], &mut ctx);
    let foreign = policy::foreign_cap_for_testing(&mut ctx);
    policy.set_max_per_tx(&foreign, 9_000);
    destroy(cap);
    destroy(foreign);
    destroy(policy);
}

#[test, expected_failure(abort_code = lyra::policy::EWrongPolicy)]
fun rejects_foreign_owner_cap() {
    let mut ctx = tx_context::dummy();
    let (mut policy, cap) = mk(500, 500, 0, vector[], vector[], &mut ctx);
    // A cap minted for a different policy id must not control this one.
    let foreign = policy::foreign_cap_for_testing(&mut ctx);
    policy.top_up(&foreign, 1);
    destroy(cap);
    destroy(foreign);
    destroy(policy);
}

#[test]
fun add_remove_protocol_updates_allowlist() {
    let mut ctx = tx_context::dummy();
    let clk = clock::create_for_testing(&mut ctx);
    // Start with a single allowed protocol; a second one is initially rejected.
    let (mut policy, cap) = mk(10_000, 10_000, 0, vector[], vector[@0xDEE9], &mut ctx);

    assert!(!policy.would_allow<SUI>(100, @0xBEEF, &clk)); // not yet allowed

    policy.add_allowed_protocol(&cap, @0xBEEF);
    policy.add_allowed_protocol(&cap, @0xBEEF); // idempotent
    assert!(policy.allowed_protocols().length() == 2);
    assert!(policy.would_allow<SUI>(100, @0xBEEF, &clk)); // now allowed
    // And a real spend on the freshly-authorized protocol goes through.
    let r = policy.enforce_spend<SUI>(100, @0xBEEF, b"supply", b"", &clk, &mut ctx);
    destroy(r);

    policy.remove_allowed_protocol(&cap, @0xBEEF);
    assert!(policy.allowed_protocols().length() == 1);
    assert!(!policy.would_allow<SUI>(100, @0xBEEF, &clk)); // revoked again

    destroy(cap);
    destroy(policy);
    clock::destroy_for_testing(clk);
}

#[test]
fun set_protocols_replaces_allowlist() {
    let mut ctx = tx_context::dummy();
    let clk = clock::create_for_testing(&mut ctx);
    let (mut policy, cap) = mk(10_000, 10_000, 0, vector[], vector[@0xDEE9], &mut ctx);

    policy.set_allowed_protocols(&cap, vector[@0xAAA, @0xBBB]);
    assert!(policy.allowed_protocols().length() == 2);
    assert!(policy.would_allow<SUI>(100, @0xAAA, &clk));
    assert!(!policy.would_allow<SUI>(100, @0xDEE9, &clk)); // old entry gone

    // Empty vector re-opens to ANY protocol.
    policy.set_allowed_protocols(&cap, vector[]);
    assert!(policy.would_allow<SUI>(100, @0xDEE9, &clk));

    destroy(cap);
    destroy(policy);
    clock::destroy_for_testing(clk);
}

#[test]
fun zero_protocol_always_allowed_under_allowlist() {
    let mut ctx = tx_context::dummy();
    let clk = clock::create_for_testing(&mut ctx);
    // Restrict to a single named yield protocol.
    let (mut policy, cap) = mk(10_000, 10_000, 0, vector[], vector[@0xDEE9], &mut ctx);
    // A named protocol not in the list is blocked...
    assert!(!policy.would_allow<SUI>(100, @0xBEEF, &clk));
    // ...but @0x0 (the transfer/swap tag) is ALWAYS allowed, even under the
    // allowlist — so restricting protocols never blocks a plain transfer or swap.
    assert!(policy.would_allow<SUI>(100, @0x0, &clk));
    let r = policy.enforce_spend<SUI>(100, @0x0, b"transfer", b"", &clk, &mut ctx);
    destroy(r);
    destroy(policy);
    destroy(cap);
    clock::destroy_for_testing(clk);
}

#[test]
fun add_remove_coin_updates_allowlist() {
    let mut ctx = tx_context::dummy();
    let clk = clock::create_for_testing(&mut ctx);
    // Allowlist a bogus coin so SUI starts rejected.
    let (mut policy, cap) = mk(10_000, 10_000, 0, vector[b"0x0::nope::NOPE"], vector[], &mut ctx);

    assert!(!policy.would_allow<SUI>(100, @0x0, &clk)); // SUI not allowed yet

    policy.add_allowed_coin(&cap, sui_type());
    policy.add_allowed_coin(&cap, sui_type()); // idempotent
    assert!(policy.allowed_coins().length() == 2);
    assert!(policy.would_allow<SUI>(100, @0x0, &clk)); // SUI now allowed

    policy.remove_allowed_coin(&cap, sui_type());
    assert!(policy.allowed_coins().length() == 1);
    assert!(!policy.would_allow<SUI>(100, @0x0, &clk)); // rejected again

    // Clearing the coin allowlist re-opens to ANY coin.
    policy.set_allowed_coins(&cap, vector[]);
    assert!(policy.would_allow<SUI>(100, @0x0, &clk));

    destroy(cap);
    destroy(policy);
    clock::destroy_for_testing(clk);
}

#[test, expected_failure(abort_code = lyra::policy::EWrongPolicy)]
fun add_protocol_rejects_foreign_cap() {
    let mut ctx = tx_context::dummy();
    let (mut policy, cap) = mk(500, 500, 0, vector[], vector[], &mut ctx);
    // Only the matching owner cap may widen the allowlist — not the agent, not a
    // cap for another policy.
    let foreign = policy::foreign_cap_for_testing(&mut ctx);
    policy.add_allowed_protocol(&foreign, @0xBEEF);
    destroy(cap);
    destroy(foreign);
    destroy(policy);
}

// === Version guard ===

#[test, expected_failure(abort_code = lyra::policy::EWrongVersion)]
fun blocks_spend_on_stale_version() {
    let mut ctx = tx_context::dummy();
    let clk = clock::create_for_testing(&mut ctx);
    let (mut policy, cap) = mk(1000, 1000, 0, vector[], vector[], &mut ctx);
    policy::set_version_for_testing(&mut policy, 0); // pretend an upgrade moved past this policy
    let r = policy.enforce_spend<SUI>(100, @0x0, b"transfer", b"", &clk, &mut ctx);
    destroy(r);
    destroy(policy);
    destroy(cap);
    clock::destroy_for_testing(clk);
}

#[test]
fun migrate_restores_spend_after_upgrade() {
    let mut ctx = tx_context::dummy();
    let clk = clock::create_for_testing(&mut ctx);
    let (mut policy, cap) = mk(1000, 1000, 0, vector[], vector[], &mut ctx);
    policy::set_version_for_testing(&mut policy, 0); // stale
    assert!(!policy.would_allow<SUI>(100, @0x0, &clk)); // version mismatch blocks
    policy.migrate(&cap); // owner brings it current
    assert!(policy.would_allow<SUI>(100, @0x0, &clk));
    let r = policy.enforce_spend<SUI>(100, @0x0, b"transfer", b"", &clk, &mut ctx);
    destroy(r);
    destroy(policy);
    destroy(cap);
    clock::destroy_for_testing(clk);
}

#[test, expected_failure(abort_code = lyra::policy::ENotUpgrade)]
fun migrate_rejects_already_current() {
    let mut ctx = tx_context::dummy();
    let (mut policy, cap) = mk(1000, 1000, 0, vector[], vector[], &mut ctx);
    policy.migrate(&cap); // already at current version → aborts
    destroy(policy);
    destroy(cap);
}
