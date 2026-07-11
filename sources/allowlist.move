/// Lyra — reusable allowlist primitives.
///
/// `AgentPolicy` keeps three allowlists — coin types (ascii bytes), protocol
/// package ids (addresses), and transfer recipients (addresses) — that all share
/// the same semantics: an EMPTY list means "any is allowed" (opt-in hardening),
/// and mutation is idempotent. Factoring that shared logic here keeps `policy`
/// focused on the gate and gives the membership rules one tested home.
///
/// The `insert_*` / `remove_*` helpers return whether they changed the list so
/// callers can emit an event only on a real change.
module lyra::allowlist;

// === Membership ===

/// True when `x` is in scope: an empty list allows any address, otherwise `x`
/// must be listed.
public fun allows_addr(list: &vector<address>, x: address): bool {
    list.is_empty() || list.contains(&x)
}

/// True when `x` is in scope: an empty list allows any value, otherwise `x` must
/// be listed. Used for coin-type allowlists (fully-qualified type ascii bytes).
public fun allows_bytes(list: &vector<vector<u8>>, x: &vector<u8>): bool {
    list.is_empty() || list.contains(x)
}

// === Mutation (idempotent) ===

/// Add `x` if absent. Returns true when the list changed.
public fun insert_addr(list: &mut vector<address>, x: address): bool {
    if (list.contains(&x)) return false;
    list.push_back(x);
    true
}

/// Remove `x` if present (order is irrelevant, so swap-remove). Returns true when
/// the list changed.
public fun remove_addr(list: &mut vector<address>, x: address): bool {
    let (found, i) = list.index_of(&x);
    if (found) {
        list.swap_remove(i);
        true
    } else {
        false
    }
}

/// Add `x` if absent. Returns true when the list changed.
public fun insert_bytes(list: &mut vector<vector<u8>>, x: vector<u8>): bool {
    if (list.contains(&x)) return false;
    list.push_back(x);
    true
}

/// Remove `x` if present. Returns true when the list changed.
public fun remove_bytes(list: &mut vector<vector<u8>>, x: &vector<u8>): bool {
    let (found, i) = list.index_of(x);
    if (found) {
        list.swap_remove(i);
        true
    } else {
        false
    }
}
