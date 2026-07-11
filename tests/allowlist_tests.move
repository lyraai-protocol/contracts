#[test_only]
module lyra::allowlist_tests;

use lyra::allowlist;

#[test]
fun empty_list_allows_any() {
    let addrs: vector<address> = vector[];
    assert!(allowlist::allows_addr(&addrs, @0xBEEF));
    let bytes: vector<vector<u8>> = vector[];
    assert!(allowlist::allows_bytes(&bytes, &b"0x2::sui::SUI"));
}

#[test]
fun nonempty_list_gates_membership() {
    let addrs = vector[@0xAAA, @0xBBB];
    assert!(allowlist::allows_addr(&addrs, @0xAAA));
    assert!(!allowlist::allows_addr(&addrs, @0xCCC));

    let bytes = vector[b"0x2::sui::SUI"];
    assert!(allowlist::allows_bytes(&bytes, &b"0x2::sui::SUI"));
    assert!(!allowlist::allows_bytes(&bytes, &b"0x2::usdc::USDC"));
}

#[test]
fun insert_addr_is_idempotent() {
    let mut list: vector<address> = vector[];
    assert!(allowlist::insert_addr(&mut list, @0xAAA)); // changed
    assert!(!allowlist::insert_addr(&mut list, @0xAAA)); // no-op, unchanged
    assert!(list.length() == 1);
}

#[test]
fun remove_addr_reports_change() {
    let mut list = vector[@0xAAA, @0xBBB];
    assert!(allowlist::remove_addr(&mut list, @0xAAA)); // changed
    assert!(!allowlist::remove_addr(&mut list, @0xAAA)); // already gone
    assert!(list.length() == 1);
    assert!(list.contains(&@0xBBB));
}

#[test]
fun insert_remove_bytes_roundtrip() {
    let mut list: vector<vector<u8>> = vector[];
    assert!(allowlist::insert_bytes(&mut list, b"0x2::sui::SUI"));
    assert!(!allowlist::insert_bytes(&mut list, b"0x2::sui::SUI")); // idempotent
    assert!(allowlist::allows_bytes(&list, &b"0x2::sui::SUI"));
    assert!(allowlist::remove_bytes(&mut list, &b"0x2::sui::SUI"));
    assert!(list.is_empty());
    assert!(!allowlist::remove_bytes(&mut list, &b"0x2::sui::SUI")); // already gone
}
