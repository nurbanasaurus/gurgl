//! Capture proxy backend (mitmdump).
//!
//! gurgl spawns `mitmdump` with the bundled addon (assets/mitm_flows.py), which
//! appends one JSON line per request recording the destination host and time.
//! gurgl reads that file back to build the per-trial host set. Hosts + time
//! only - never bodies.
//!
//! A pure-Rust MITM backend (`hudsucker`) that removes the mitmproxy dependency
//! is a roadmap item; this module isolates that behind `build_argv`/`parse_flows`.

use std::path::Path;

use anyhow::{Context, Result};

/// The mitmproxy addon, embedded so gurgl is a single binary + one script it
/// writes to a temp path at runtime.
pub const FLOWS_ADDON: &str = include_str!("../assets/mitm_flows.py");

/// Build the argv to launch the capture proxy.
///
/// `confdir` isolates mitmproxy's state (its CA lives at
/// `<confdir>/mitmproxy-ca-cert.pem`) so gurgl doesn't depend on the user's
/// `~/.mitmproxy` and can generate/trust a stable CA.
pub fn build_argv(mitmdump: &str, addon_path: &str, confdir: &str, port: u16) -> Vec<String> {
    vec![
        mitmdump.to_string(),
        "-q".into(), // quiet; the addon does our logging
        "--listen-host".into(),
        "127.0.0.1".into(),
        "--listen-port".into(),
        port.to_string(),
        "--set".into(),
        format!("confdir={confdir}"),
        "-s".into(),
        addon_path.to_string(),
    ]
}

/// Build the argv for the FORCED-capture proxy: mitmdump in transparent mode.
///
/// Unlike the env-proxy `build_argv`, this expects traffic arriving via an
/// nftables REDIRECT (the client never speaks the proxy protocol), so it runs
/// `--mode transparent` and does NOT pin `--listen-host` to loopback - the
/// redirect rewrites the destination, and mitmdump reads the original via
/// `SO_ORIGINAL_DST`. The addon records the TLS SNI (see mitm_flows.py), so
/// `--showhost` (which would trust the Host header) is deliberately omitted.
/// Runs inside the capture network namespace; the caller wraps it with `nsenter`.
pub fn build_transparent_argv(
    mitmdump: &str,
    addon_path: &str,
    confdir: &str,
    port: u16,
) -> Vec<String> {
    vec![
        mitmdump.to_string(),
        "-q".into(),
        "--mode".into(),
        "transparent".into(),
        "--listen-port".into(),
        port.to_string(),
        "--set".into(),
        format!("confdir={confdir}"),
        "-s".into(),
        addon_path.to_string(),
    ]
}

/// One request observed by the proxy: destination host + wall-clock time.
#[derive(Debug, Clone, PartialEq)]
pub struct RawFlow {
    pub host: String,
    pub time: f64,
}

/// A host observed in a single trial, tagged with the flight-plan phase it was
/// seen in (assigned by gurgl from the timestamp).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowHost {
    pub host: String,
    pub phase: Option<String>,
}

/// Parse the addon's JSONL output into raw (host, time) records. Malformed
/// lines are skipped, not fatal. Hosts are lowercased; order is preserved.
pub fn parse_flows(path: &Path) -> Result<Vec<RawFlow>> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e).with_context(|| format!("reading flows {}", path.display())),
    };

    let mut flows = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(val) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        let Some(host) = val.get("host").and_then(|h| h.as_str()) else {
            continue;
        };
        // Normalize a host that is attacker-influenced (the observed server
        // chooses what it connects to). See normalize_host for the ordering
        // rationale; an empty / just-dots / all-control authority is dropped.
        let Some(host) = normalize_host(host) else {
            continue;
        };
        let time = val.get("time").and_then(|t| t.as_f64()).unwrap_or(0.0);
        flows.push(RawFlow { host, time });
    }
    Ok(flows)
}

/// Normalize an observed or externally-loaded host name. ORDER MATTERS: strip
/// control characters FIRST - a hostname carrying an ANSI escape must never reach
/// the terminal or store, and a trailing control byte must not shield the FQDN
/// root dot or stray whitespace from the trims. Then lowercase, then trim
/// whitespace and the trailing root dot TOGETHER so "api.example.com.",
/// "api.example.com " and "api.example.com" all collapse to one host (not two
/// split across trials below the reproduction gate). Returns None for an empty /
/// just-dots / all-control authority. Shared by the flow parser and the
/// shared-capture loader so a hostile shared file gets the exact same, tested
/// sanitization and the two paths cannot diverge.
pub fn normalize_host(raw: &str) -> Option<String> {
    let cleaned: String = raw
        .chars()
        .filter(|c| !c.is_control())
        .collect::<String>()
        .to_ascii_lowercase();
    let host = cleaned
        .trim()
        .trim_end_matches(|c: char| c == '.' || c.is_whitespace());
    (!host.is_empty()).then(|| host.to_string())
}

/// Strip control bytes from an untrusted DISPLAY string (a version, flight-plan
/// fingerprint, or note loaded from a shared file) so an embedded ANSI escape
/// can't corrupt the terminal when shown. Not a host name - no dot/whitespace
/// trimming, no lowercasing.
pub fn strip_control(raw: &str) -> String {
    raw.chars().filter(|c| !c.is_control()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn build_argv_sets_port_addon_and_confdir() {
        let argv = build_argv("mitmdump", "/tmp/addon.py", "/tmp/conf", 8080);
        assert_eq!(argv[0], "mitmdump");
        assert!(argv
            .windows(2)
            .any(|w| w[0] == "--listen-port" && w[1] == "8080"));
        assert!(argv
            .windows(2)
            .any(|w| w[0] == "-s" && w[1] == "/tmp/addon.py"));
        assert!(argv.iter().any(|a| a == "confdir=/tmp/conf"));
    }

    #[test]
    fn transparent_argv_uses_transparent_mode_and_addon() {
        let argv = build_transparent_argv("mitmdump", "/tmp/addon.py", "/tmp/conf", 9090);
        assert_eq!(argv[0], "mitmdump");
        assert!(argv
            .windows(2)
            .any(|w| w[0] == "--mode" && w[1] == "transparent"));
        assert!(argv
            .windows(2)
            .any(|w| w[0] == "--listen-port" && w[1] == "9090"));
        assert!(argv
            .windows(2)
            .any(|w| w[0] == "-s" && w[1] == "/tmp/addon.py"));
        assert!(argv.iter().any(|a| a == "confdir=/tmp/conf"));
        // A transparent proxy must NOT be pinned to a regular-proxy listen host,
        // and --showhost (which trusts the Host header) must stay off.
        assert!(!argv.iter().any(|a| a == "--showhost"));
    }

    #[test]
    fn parse_flows_reads_host_and_time() {
        let mut f = tempfile();
        let l1 = r#"{"host":"API.Example.com","time":1000.5}"#;
        let l2 = r#"{"host":"beacon.unknown.example","time":1002.0}"#;
        writeln!(f.0, "{l1}").unwrap();
        writeln!(f.0, "garbage not json").unwrap();
        writeln!(f.0, "{l2}").unwrap();
        f.0.flush().unwrap();

        let flows = parse_flows(&f.1).unwrap();
        assert_eq!(flows.len(), 2);
        assert_eq!(flows[0].host, "api.example.com");
        assert_eq!(flows[0].time, 1000.5);
        assert_eq!(flows[1].host, "beacon.unknown.example");
    }

    #[test]
    fn parse_flows_strips_control_characters() {
        // A host carrying an ANSI escape (JSON \u001b decodes to a raw ESC
        // byte) must not reach the terminal or store intact - it is stripped.
        let mut f = tempfile();
        let line = r#"{"host":"\u001bevil.example","time":1.0}"#;
        writeln!(f.0, "{line}").unwrap();
        f.0.flush().unwrap();
        let flows = parse_flows(&f.1).unwrap();
        assert_eq!(flows.len(), 1);
        assert!(!flows[0].host.contains('\u{1b}'));
        assert_eq!(flows[0].host, "evil.example");
    }

    #[test]
    fn parse_flows_normalizes_trailing_dot() {
        // A resolver / client that emits the FQDN root dot must not split the
        // host from its dotless form across trials.
        let mut f = tempfile();
        writeln!(f.0, r#"{{"host":"API.Example.com.","time":1.0}}"#).unwrap();
        writeln!(f.0, r#"{{"host":"api.example.com","time":2.0}}"#).unwrap();
        f.0.flush().unwrap();
        let flows = parse_flows(&f.1).unwrap();
        assert_eq!(flows.len(), 2);
        assert_eq!(flows[0].host, "api.example.com");
        assert_eq!(flows[1].host, "api.example.com");
    }

    #[test]
    fn parse_flows_control_byte_does_not_shield_trailing_dot() {
        // A trailing control byte must not shield the FQDN root dot from
        // normalization: "evil.example." + DEL and "evil.example." must collapse
        // to the SAME host (not split below the reproduction gate), and a
        // just-dots-plus-control authority is dropped, not recorded as a phantom
        // host. Regression: the trims once ran BEFORE the control-char filter, so
        // a trailing DEL/ESC left a stranded dot no later stage re-trimmed.
        // A raw DEL byte (U+007F): a control char that is NOT whitespace and NOT
        // '.', so before the fix it shielded the trailing dot from the trims.
        let del = '\u{7f}';
        let l1 = format!(r#"{{"host":"evil.example.{del}","time":1.0}}"#);
        let l2 = r#"{"host":"evil.example.","time":2.0}"#.to_string();
        let l3 = format!(r#"{{"host":"..{del}","time":3.0}}"#);
        let mut f = tempfile();
        writeln!(f.0, "{l1}").unwrap();
        writeln!(f.0, "{l2}").unwrap();
        writeln!(f.0, "{l3}").unwrap();
        f.0.flush().unwrap();
        let flows = parse_flows(&f.1).unwrap();
        // The just-dots+control host is dropped; the two real ones normalize equal.
        assert_eq!(flows.len(), 2);
        assert_eq!(flows[0].host, "evil.example");
        assert_eq!(flows[1].host, "evil.example");
    }

    // Tiny temp-file helper to avoid a dev-dependency.
    fn tempfile() -> (std::fs::File, std::path::PathBuf) {
        let mut path = std::env::temp_dir();
        use std::sync::atomic::{AtomicU32, Ordering};
        static N: AtomicU32 = AtomicU32::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        path.push(format!("gurgl-test-{}-{}.jsonl", std::process::id(), n));
        let f = std::fs::File::create(&path).unwrap();
        (f, path)
    }
}
