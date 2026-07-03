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
        let host = host.trim().to_ascii_lowercase();
        if host.is_empty() {
            continue;
        }
        let time = val.get("time").and_then(|t| t.as_f64()).unwrap_or(0.0);
        flows.push(RawFlow { host, time });
    }
    Ok(flows)
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
