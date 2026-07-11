/// Lyra — package-wide constants.
///
/// Centralizes values that must stay consistent across every module and survive
/// upgrades. Move constants are module-private, so — like DeepBook's `constants`
/// module — they are surfaced through thin accessor functions the rest of the
/// package (and off-chain clients, via a dev-inspect call) can read.
module lyra::constants;

/// On-chain package version. Bumped on every published upgrade. Each shared
/// object (`AgentPolicy`, `Vault`) records the version it was created/migrated
/// at; the agent spend path asserts the object is at THIS version, so an upgrade
/// can pause stale objects until the owner migrates them. Owner controls
/// (revoke, withdraw, migrate) are never version-gated, so an upgrade can never
/// trap owner authority or funds.
const VERSION: u16 = 1;

/// Reserved "no specific protocol" tag. Plain transfers and swaps carry this in
/// place of a protocol package id: they are bounded by budget / per-tx cap /
/// coin allowlist / recipient allowlist / slippage instead of a protocol
/// allowlist, so the sentinel is ALWAYS in scope and a protocol allowlist never
/// blocks a transfer or swap.
const NO_PROTOCOL: address = @0x0;

/// Current on-chain package version. See `VERSION`.
public fun version(): u16 { VERSION }

/// The `@0x0` "no specific protocol" sentinel. See `NO_PROTOCOL`.
public fun no_protocol(): address { NO_PROTOCOL }
