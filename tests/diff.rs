//! Integration test for the pure diff over stored-shape snapshots.
//!
//! This exercises the public crate path a little; most unit coverage lives in
//! the module `#[cfg(test)]` blocks. Kept deliberately small.

// The binary crate is named `gurgl`; integration tests can't import its private
// modules, so this test reconstructs the minimal JSON and checks the CLI-visible
// behavior via the bundled example snapshots instead.

use std::process::Command;

/// `gurgl --config examples/gurgl.toml diff example-mcp` should surface the new
/// unknown host introduced in the example 1.3.0 snapshot.
///
/// Ignored by default because it shells out to the built binary; run with:
///   cargo test -- --ignored
#[test]
#[ignore]
fn example_diff_surfaces_new_unknown_host() {
    let output = Command::new(env!("CARGO_BIN_EXE_gurgl"))
        .args(["--config", "examples/gurgl.toml", "diff", "example-mcp"])
        .output()
        .expect("run gurgl");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("beacon.example-analytics.io") || stdout.contains("UNKNOWN"),
        "diff output should flag the new host; got:\n{stdout}"
    );
}
