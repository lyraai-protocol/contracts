#[test_only]
module lyra::vault_tests;

use lyra::policy;
use lyra::vault;
use std::unit_test::destroy;
use sui::clock;
use sui::coin;
use sui::sui::SUI;

// tx_context::dummy() sender — set as the policy agent so vault_spend passes the
// on-chain agent check by default.
const AGENT: address = @0x0;

#[test]
/// The agent draws funds from the vault under policy; balance + spend accounting move.
fun agent_spends_from_vault_within_policy() {
    let mut ctx = tx_context::dummy();
    let clk = clock::create_for_testing(&mut ctx);
    let (mut policy, cap) =
        policy::new_policy_for_testing(AGENT, 1000, 600, 0, vector[], vector[], &mut ctx);
    let mut v = vault::new<SUI>(&policy, &mut ctx);

    vault::deposit(&mut v, coin::mint_for_testing<SUI>(1000, &mut ctx));
    assert!(vault::value(&v) == 1000);

    let (c, r) =
        vault::vault_spend<SUI>(&mut v, &mut policy, 400, @0x0, b"transfer", b"", &clk, &mut ctx);
    assert!(c.value() == 400);
    assert!(vault::value(&v) == 600);
    assert!(policy.spent_mist() == 400);

    destroy(c);
    destroy(r);
    destroy(v);
    destroy(policy);
    destroy(cap);
    clock::destroy_for_testing(clk);
}

#[test, expected_failure]
/// A spend over the per-tx cap aborts inside the policy gate — even with funds present.
fun blocks_spend_over_per_tx_cap() {
    let mut ctx = tx_context::dummy();
    let clk = clock::create_for_testing(&mut ctx);
    let (mut policy, cap) =
        policy::new_policy_for_testing(AGENT, 10_000, 500, 0, vector[], vector[], &mut ctx);
    let mut v = vault::new<SUI>(&policy, &mut ctx);
    vault::deposit(&mut v, coin::mint_for_testing<SUI>(10_000, &mut ctx));
    let (c, r) =
        vault::vault_spend<SUI>(&mut v, &mut policy, 501, @0x0, b"transfer", b"", &clk, &mut ctx);
    destroy(c);
    destroy(r);
    destroy(v);
    destroy(policy);
    destroy(cap);
    clock::destroy_for_testing(clk);
}

#[test, expected_failure]
/// In-policy but the vault lacks the funds → aborts (EInsufficientVault).
fun blocks_spend_exceeding_vault_balance() {
    let mut ctx = tx_context::dummy();
    let clk = clock::create_for_testing(&mut ctx);
    let (mut policy, cap) =
        policy::new_policy_for_testing(AGENT, 10_000, 10_000, 0, vector[], vector[], &mut ctx);
    let mut v = vault::new<SUI>(&policy, &mut ctx);
    vault::deposit(&mut v, coin::mint_for_testing<SUI>(100, &mut ctx));
    let (c, r) =
        vault::vault_spend<SUI>(&mut v, &mut policy, 500, @0x0, b"transfer", b"", &clk, &mut ctx);
    destroy(c);
    destroy(r);
    destroy(v);
    destroy(policy);
    destroy(cap);
    clock::destroy_for_testing(clk);
}

#[test]
/// The owner can always pull the whole treasury back with the cap.
fun owner_withdraws_treasury_back() {
    let mut ctx = tx_context::dummy();
    let (policy, cap) =
        policy::new_policy_for_testing(AGENT, 1000, 1000, 0, vector[], vector[], &mut ctx);
    let mut v = vault::new<SUI>(&policy, &mut ctx);
    vault::deposit(&mut v, coin::mint_for_testing<SUI>(1000, &mut ctx));

    let c = vault::owner_withdraw<SUI>(&mut v, &cap, 1000, &mut ctx);
    assert!(c.value() == 1000);
    assert!(vault::value(&v) == 0);

    destroy(c);
    destroy(v);
    destroy(policy);
    destroy(cap);
}

#[test]
/// With a recipient allowlist set, the agent can transfer to a listed payee.
fun recipient_allowlist_permits_listed_payee() {
    let mut ctx = tx_context::dummy();
    let clk = clock::create_for_testing(&mut ctx);
    let (mut policy, cap) =
        policy::new_policy_for_testing(AGENT, 1000, 1000, 0, vector[], vector[], &mut ctx);
    policy::set_allowed_recipients(&mut policy, &cap, vector[@0xBEEF]);
    let mut v = vault::new<SUI>(&policy, &mut ctx);
    vault::deposit(&mut v, coin::mint_for_testing<SUI>(1000, &mut ctx));

    vault::vault_transfer<SUI>(&mut v, &mut policy, 100, @0xBEEF, b"", &clk, &mut ctx);
    assert!(vault::value(&v) == 900);

    destroy(v);
    destroy(policy);
    destroy(cap);
    clock::destroy_for_testing(clk);
}

#[test, expected_failure]
/// A transfer to an UNLISTED recipient aborts, even within budget (the key
/// prompt-injection mitigation).
fun recipient_allowlist_blocks_unlisted_payee() {
    let mut ctx = tx_context::dummy();
    let clk = clock::create_for_testing(&mut ctx);
    let (mut policy, cap) =
        policy::new_policy_for_testing(AGENT, 1000, 1000, 0, vector[], vector[], &mut ctx);
    policy::set_allowed_recipients(&mut policy, &cap, vector[@0xBEEF]);
    let mut v = vault::new<SUI>(&policy, &mut ctx);
    vault::deposit(&mut v, coin::mint_for_testing<SUI>(1000, &mut ctx));

    vault::vault_transfer<SUI>(&mut v, &mut policy, 100, @0xBAD, b"", &clk, &mut ctx);

    destroy(v);
    destroy(policy);
    destroy(cap);
    clock::destroy_for_testing(clk);
}

#[test]
/// No allowlist (or an empty one) leaves transfers open to any recipient.
fun recipient_open_by_default() {
    let mut ctx = tx_context::dummy();
    let (policy, cap) =
        policy::new_policy_for_testing(AGENT, 1000, 1000, 0, vector[], vector[], &mut ctx);
    assert!(policy::recipient_allowed(&policy, @0xBAD));
    assert!(policy::recipient_allowed(&policy, @0xBEEF));
    destroy(policy);
    destroy(cap);
}

#[test, expected_failure]
/// A cap from a different policy must not control this vault (ENotVaultOwner).
fun foreign_cap_cannot_withdraw() {
    let mut ctx = tx_context::dummy();
    let (policy, cap) =
        policy::new_policy_for_testing(AGENT, 1000, 1000, 0, vector[], vector[], &mut ctx);
    let mut v = vault::new<SUI>(&policy, &mut ctx);
    vault::deposit(&mut v, coin::mint_for_testing<SUI>(1000, &mut ctx));

    let (policy2, cap2) =
        policy::new_policy_for_testing(AGENT, 1, 1, 0, vector[], vector[], &mut ctx);
    let c = vault::owner_withdraw<SUI>(&mut v, &cap2, 1, &mut ctx);

    destroy(c);
    destroy(v);
    destroy(policy);
    destroy(cap);
    destroy(policy2);
    destroy(cap2);
}

// === Version guard ===

#[test, expected_failure(abort_code = lyra::vault::EWrongVersion)]
/// After an upgrade, a stale vault blocks the agent's spend path until migrated.
fun stale_vault_blocks_agent_spend() {
    let mut ctx = tx_context::dummy();
    let clk = clock::create_for_testing(&mut ctx);
    let (mut policy, cap) =
        policy::new_policy_for_testing(AGENT, 1000, 1000, 0, vector[], vector[], &mut ctx);
    let mut v = vault::new<SUI>(&policy, &mut ctx);
    vault::deposit(&mut v, coin::mint_for_testing<SUI>(1000, &mut ctx));
    vault::set_version_for_testing(&mut v, 0); // pretend an upgrade moved past this vault

    let (c, r) =
        vault::vault_spend<SUI>(&mut v, &mut policy, 100, @0x0, b"transfer", b"", &clk, &mut ctx);
    destroy(c);
    destroy(r);
    destroy(v);
    destroy(policy);
    destroy(cap);
    clock::destroy_for_testing(clk);
}

#[test]
/// The owner escape hatch is NEVER version-gated: even a stale vault can be fully
/// drained by the owner, so an upgrade can never trap user funds.
fun owner_withdraw_works_on_stale_vault() {
    let mut ctx = tx_context::dummy();
    let (policy, cap) =
        policy::new_policy_for_testing(AGENT, 1000, 1000, 0, vector[], vector[], &mut ctx);
    let mut v = vault::new<SUI>(&policy, &mut ctx);
    vault::deposit(&mut v, coin::mint_for_testing<SUI>(1000, &mut ctx));
    vault::set_version_for_testing(&mut v, 0); // stale

    let c = vault::owner_withdraw<SUI>(&mut v, &cap, 1000, &mut ctx);
    assert!(c.value() == 1000);
    assert!(vault::value(&v) == 0);

    destroy(c);
    destroy(v);
    destroy(policy);
    destroy(cap);
}

#[test]
/// Migrating a stale vault restores the agent's spend path.
fun migrate_restores_agent_spend() {
    let mut ctx = tx_context::dummy();
    let clk = clock::create_for_testing(&mut ctx);
    let (mut policy, cap) =
        policy::new_policy_for_testing(AGENT, 1000, 1000, 0, vector[], vector[], &mut ctx);
    let mut v = vault::new<SUI>(&policy, &mut ctx);
    vault::deposit(&mut v, coin::mint_for_testing<SUI>(1000, &mut ctx));
    vault::set_version_for_testing(&mut v, 0); // stale
    vault::migrate<SUI>(&mut v, &cap); // owner brings it current

    let (c, r) =
        vault::vault_spend<SUI>(&mut v, &mut policy, 100, @0x0, b"transfer", b"", &clk, &mut ctx);
    assert!(c.value() == 100);
    assert!(vault::value(&v) == 900);

    destroy(c);
    destroy(r);
    destroy(v);
    destroy(policy);
    destroy(cap);
    clock::destroy_for_testing(clk);
}
