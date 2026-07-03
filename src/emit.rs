//! Emit enforceable allowlists from an observed snapshot.
//!
//! gurgl does not enforce anything itself. It generates least-privilege domain
//! allowlists you feed to a real enforcement engine you already run
//! (Anthropic sandbox-runtime, OpenSnitch, a squid proxy, ...).
//!
//! Every emitted allowlist carries the same caveat: absence of a host means
//! gurgl did not *observe* it under the flight plan, NOT that the tool will
//! never contact it. Treat the output as a starting point to review, never as a
//! certified-complete list.

use std::str::FromStr;

use crate::model::{Host, Snapshot};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// Newline domain list for Anthropic sandbox-runtime `allowedDomains`.
    SandboxRuntime,
    /// OpenSnitch JSON allow-rule.
    OpenSnitch,
    /// squid `acl dstdomain` + `http_access` lines.
    Squid,
}

impl FromStr for Format {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "sandbox-runtime" | "sandbox" | "srt" => Ok(Format::SandboxRuntime),
            "opensnitch" => Ok(Format::OpenSnitch),
            "squid" => Ok(Format::Squid),
            other => Err(format!(
                "unknown format '{other}' (expected: sandbox-runtime | opensnitch | squid)"
            )),
        }
    }
}

/// Hosts eligible for an allowlist: only those that reproduced in every trial.
fn allowlisted(snapshot: &Snapshot) -> Vec<&Host> {
    let mut hosts: Vec<&Host> = snapshot.stable_hosts().collect();
    hosts.sort_by(|a, b| a.name.cmp(&b.name));
    hosts
}

const CAVEAT: &str =
    "absence of a host means gurgl did not observe it under this flight plan — NOT that the tool will never contact it. Review before enforcing.";

pub fn allowlist(snapshot: &Snapshot, format: Format) -> String {
    let hosts = allowlisted(snapshot);
    match format {
        Format::SandboxRuntime => sandbox_runtime(snapshot, &hosts),
        Format::OpenSnitch => opensnitch(snapshot, &hosts),
        Format::Squid => squid(snapshot, &hosts),
    }
}

fn sandbox_runtime(snapshot: &Snapshot, hosts: &[&Host]) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "# gurgl allowlist for {}@{} (flight plan: {}, trials: {})\n",
        snapshot.server, snapshot.version, snapshot.flightplan, snapshot.trials
    ));
    out.push_str(&format!("# {CAVEAT}\n"));
    for h in hosts {
        out.push_str(&format!("{}\n", h.name));
    }
    out
}

fn opensnitch(snapshot: &Snapshot, hosts: &[&Host]) -> String {
    // A single "allow, from these domains" rule. OpenSnitch matches one operand;
    // we use a regexp over the observed domains. Emitted for review, not blind use.
    let domains = hosts
        .iter()
        .map(|h| regex_escape(&h.name))
        .collect::<Vec<_>>()
        .join("|");
    let rule = serde_json::json!({
        "created": "",
        "updated": "",
        "name": format!("gurgl-allow-{}-{}", snapshot.server, snapshot.version),
        "description": format!(
            "Allowlist observed by gurgl for {}@{}. {}",
            snapshot.server, snapshot.version, CAVEAT
        ),
        "enabled": false,
        "precedence": true,
        "action": "allow",
        "duration": "always",
        "operator": {
            "type": "regexp",
            "operand": "dest.host",
            "sensitive": false,
            "data": format!("^({domains})$")
        }
    });
    serde_json::to_string_pretty(&rule).unwrap_or_else(|_| "{}".to_string())
}

fn squid(snapshot: &Snapshot, hosts: &[&Host]) -> String {
    let acl = format!(
        "gurgl_{}_{}",
        sanitize(&snapshot.server),
        sanitize(&snapshot.version)
    );
    let mut out = String::new();
    out.push_str(&format!(
        "# gurgl allowlist for {}@{} (flight plan: {}, trials: {})\n",
        snapshot.server, snapshot.version, snapshot.flightplan, snapshot.trials
    ));
    out.push_str(&format!("# {CAVEAT}\n"));
    for h in hosts {
        out.push_str(&format!("acl {acl} dstdomain {}\n", h.name));
    }
    out.push_str(&format!("http_access allow {acl}\n"));
    out
}

fn regex_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if ".^$|()[]{}*+?\\".contains(c) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect()
}
