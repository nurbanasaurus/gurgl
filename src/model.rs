//! Core data model for gurgl.
//!
//! Everything gurgl records is a set of DNS *host names* an MCP server was
//! observed contacting, aggregated over N repeated trials. We record names, not
//! IPs, and never payloads. Read docs/THREAT-MODEL.md for what this can and
//! (importantly) cannot tell you.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

/// Coarse classification of an observed host. `Unknown` is the interesting one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HostClass {
    /// The server's declared first-party API/backend (from its config entry).
    FirstParty,
    /// A known telemetry/analytics endpoint.
    Telemetry,
    /// A package registry / update host (npm, PyPI, crates.io, GitHub, ...).
    Registry,
    /// Not matched by any rule. Worth a human look.
    Unknown,
}

impl std::fmt::Display for HostClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            HostClass::FirstParty => "first-party",
            HostClass::Telemetry => "telemetry",
            HostClass::Registry => "registry",
            HostClass::Unknown => "unknown",
        };
        // Use pad() (not write_str) so format width/alignment like `{:<11}`
        // applies when the class is formatted directly.
        f.pad(s)
    }
}

/// How consistently a host showed up across the trials of a single capture.
///
/// This is the reproduction gate. Server-side feature gates / A-B cohorts mean
/// the same version can contact different edge hosts on different runs, so a
/// host seen in only *some* trials is NOT reportable as a fact about the tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Reproducibility {
    /// Appeared in every trial. Reportable.
    Stable,
    /// Appeared in some but not all trials. Likely cohort/feature-gated noise;
    /// never publish as a bare fact, never emit as a drift accusation.
    Intermittent,
}

/// One observed egress destination for a server@version, aggregated over trials.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Host {
    pub name: String,
    pub class: HostClass,
    pub reproducibility: Reproducibility,
    /// In how many of the run's trials this host appeared.
    pub seen_in_trials: u32,
    /// Lifecycle phases in which it was seen (e.g. "startup", "tool-call").
    #[serde(default)]
    pub phases: Vec<String>,
}

/// A full capture of one server@version under one flight plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snapshot {
    pub server: String,
    pub version: String,
    /// Unix seconds. Set by the capturer; not used for any trust claim.
    pub captured_at: u64,
    /// N - the number of trials aggregated into this snapshot.
    pub trials: u32,
    /// Name of the flight plan used (bind the observation to the method).
    pub flightplan: String,
    /// Version of gurgl that produced this snapshot.
    pub gurgl_version: String,
    pub hosts: Vec<Host>,
}

impl Snapshot {
    pub fn host_names(&self) -> BTreeSet<String> {
        self.hosts.iter().map(|h| h.name.clone()).collect()
    }

    /// Only the hosts that reproduced in every trial.
    pub fn stable_hosts(&self) -> impl Iterator<Item = &Host> {
        self.hosts
            .iter()
            .filter(|h| h.reproducibility == Reproducibility::Stable)
    }
}

/// Classify a host name. Explicit first-party matches win, then telemetry, then
/// registry; anything unrecognised is `Unknown` (deliberately, so it surfaces).
pub fn classify(name: &str, first_party: &[String]) -> HostClass {
    let name = name.trim().to_ascii_lowercase();

    if first_party.iter().any(|p| host_matches(&name, p)) {
        return HostClass::FirstParty;
    }
    if TELEMETRY.iter().any(|p| host_matches(&name, p)) {
        return HostClass::Telemetry;
    }
    if REGISTRY.iter().any(|p| host_matches(&name, p)) {
        return HostClass::Registry;
    }
    HostClass::Unknown
}

/// `name` equals `pat` or is a subdomain of `pat`. Substring-only patterns
/// (those containing no dot at the boundary, like "analytics.") also match as a
/// contained label prefix - kept intentionally simple and auditable.
fn host_matches(name: &str, pat: &str) -> bool {
    let pat = pat.to_ascii_lowercase();
    if name == pat || name.ends_with(&format!(".{pat}")) {
        return true;
    }
    // Allow coarse label patterns like "telemetry." / "analytics." to match a
    // leading label anywhere in the name.
    if pat.ends_with('.') && (name.starts_with(&pat) || name.contains(&format!(".{pat}"))) {
        return true;
    }
    false
}

const TELEMETRY: &[&str] = &[
    "statsig.com",
    "featuregates.org",
    "segment.io",
    "segment.com",
    "sentry.io",
    "ingest.sentry.io",
    "amplitude.com",
    "datadoghq.com",
    "posthog.com",
    "mixpanel.com",
    "bugsnag.com",
    "google-analytics.com",
    "analytics.",
    "telemetry.",
];

const REGISTRY: &[&str] = &[
    "registry.npmjs.org",
    "npmjs.org",
    "npmjs.com",
    "pypi.org",
    "pythonhosted.org",
    "crates.io",
    "static.crates.io",
    "github.com",
    "githubusercontent.com",
    "codeload.github.com",
    "sum.golang.org",
    "proxy.golang.org",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_known_buckets() {
        let fp = vec!["api.example-vendor.com".to_string()];
        assert_eq!(
            classify("api.example-vendor.com", &fp),
            HostClass::FirstParty
        );
        assert_eq!(
            classify("us.api.example-vendor.com", &fp),
            HostClass::FirstParty
        );
        assert_eq!(classify("featuregates.org", &fp), HostClass::Telemetry);
        assert_eq!(
            classify("o12345.ingest.sentry.io", &fp),
            HostClass::Telemetry
        );
        assert_eq!(classify("registry.npmjs.org", &fp), HostClass::Registry);
        assert_eq!(
            classify("beacon.weird-host.example", &fp),
            HostClass::Unknown
        );
    }
}
