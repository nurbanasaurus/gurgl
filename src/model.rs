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
    /// A known telemetry/analytics endpoint (matched a specific vendor domain).
    Telemetry,
    /// Merely NAMES itself telemetry/analytics (a leading `telemetry.` /
    /// `analytics.` label) but matched no known vendor. Anyone can pick a
    /// hostname, so this must never look as vetted as a vendor match -
    /// scrutinize it like `Unknown`.
    TelemetryNamed,
    /// A package registry / update host (npm, PyPI, crates.io, GitHub, ...).
    Registry,
    /// Not matched by any rule. Worth a human look.
    Unknown,
}

impl HostClass {
    /// Classes that deserve human scrutiny when stable: unrecognized hosts, and
    /// hosts whose only "classification" is what they call themselves.
    pub fn needs_scrutiny(self) -> bool {
        matches!(self, HostClass::Unknown | HostClass::TelemetryNamed)
    }
}

impl std::fmt::Display for HostClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            HostClass::FirstParty => "first-party",
            HostClass::Telemetry => "telemetry",
            HostClass::TelemetryNamed => "telemetry?",
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
    /// Appeared in every trial of a battery of two or more. Reportable.
    Stable,
    /// Appeared in some but not all trials. Likely cohort/feature-gated noise;
    /// never publish as a bare fact, never emit as a drift accusation.
    Intermittent,
    /// Seen in a single observation (a `watch --for`/`--until-closed` hold, or a
    /// battery of fewer than two completed trials), so the reproduction gate
    /// could not be applied at all: not cohort noise, but not confirmed
    /// reproducible either. Treated like Intermittent by every findings, drift,
    /// and allowlist path (only `Stable` earns those) - run a battery of two or
    /// more trials to promote it. Reporting a single sighting as a fact is
    /// exactly the over-claim the gate exists to prevent.
    Observed,
}

/// How a capture forced the child's traffic through the proxy. This is a
/// statement about the capture *mechanism*, never a completeness or safety claim.
///
/// `Forced` routes *all* of the child's TCP egress through the proxy (network
/// namespace + transparent redirect), closing the gap where a client that
/// ignores proxy env vars or opens raw sockets escapes capture. `EnvProxy` - the
/// default and, for now, the only implemented mode - only wires proxy env vars,
/// so a client that does not honor them can look quiet while talking. Neither
/// mode sees inside a trusted channel or anything server-side
/// (docs/THREAT-MODEL.md): `Forced` is a stronger mechanism, not "complete",
/// "safe", or "verified".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum CaptureMode {
    /// The child was wired with proxy env vars; only clients that honor the proxy
    /// are captured. The honest floor for any capture whose mechanism is unknown
    /// (e.g. an old snapshot predating this field), so it is the default - an
    /// unlabeled capture must never be read as `Forced`.
    #[default]
    EnvProxy,
    /// All of the child's TCP egress was routed through the proxy regardless of
    /// whether it honored proxy env vars. Still presence-only.
    Forced,
}

impl std::fmt::Display for CaptureMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // pad() so a format width applies when this is printed directly.
        f.pad(match self {
            CaptureMode::EnvProxy => "env-proxy",
            CaptureMode::Forced => "forced",
        })
    }
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
    /// How the capture forced egress through the proxy (`env-proxy` or `forced`).
    /// `#[serde(default)]` so snapshots captured before this field existed load as
    /// `env-proxy`, never `forced` - defaulting an unlabeled capture to `forced`
    /// would be a false coverage claim.
    #[serde(default)]
    pub capture_mode: CaptureMode,
    /// The server's self-reported `serverInfo.version`, kept for display even when
    /// it was NOT used as the storage key (it is attacker-chosen, so a package
    /// that reports 9.9.9 while installing as 1.2.0 is visibly discrepant). `None`
    /// when the server reported nothing or on a snapshot predating this field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reported_version: Option<String>,
    /// Where `version` came from: `config`, `installed-package`, `server-reported`,
    /// or `unknown`. `None` on a snapshot predating this field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version_source: Option<String>,
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

/// Classify a host name. Explicit first-party matches win, then known telemetry
/// vendors, then registries; a host that merely NAMES itself telemetry (a
/// `telemetry.`/`analytics.` label, no vendor match) is `TelemetryNamed`, not
/// `Telemetry` - a hostname is chosen by whoever registers it, so the calming
/// class is reserved for domains on the vendor list. Anything unrecognised is
/// `Unknown` (deliberately, so it surfaces).
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
    if TELEMETRY_LABELS.iter().any(|p| host_matches(&name, p)) {
        return HostClass::TelemetryNamed;
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
];

/// Coarse self-naming patterns. Matching one of these WITHOUT matching the
/// vendor list above yields `TelemetryNamed`, never the vetted `Telemetry`
/// class: `telemetry.attacker.example` must not look reassuring.
const TELEMETRY_LABELS: &[&str] = &["analytics.", "telemetry."];

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

    #[test]
    fn self_named_telemetry_is_not_vetted() {
        // A hostname is chosen by whoever registers it: a `telemetry.` label
        // with no vendor match must NOT get the calming vendor class.
        assert_eq!(
            classify("telemetry.attacker.example", &[]),
            HostClass::TelemetryNamed
        );
        assert_eq!(
            classify("app.analytics.evil.example", &[]),
            HostClass::TelemetryNamed
        );
        assert!(HostClass::TelemetryNamed.needs_scrutiny());
        assert!(HostClass::Unknown.needs_scrutiny());
        assert!(!HostClass::Telemetry.needs_scrutiny());
        // A real vendor still classifies as vetted telemetry.
        assert_eq!(classify("o1.ingest.sentry.io", &[]), HostClass::Telemetry);
        // Declared first-party still wins over the label pattern.
        let fp = vec!["telemetry.myvendor.com".to_string()];
        assert_eq!(
            classify("telemetry.myvendor.com", &fp),
            HostClass::FirstParty
        );
    }

    #[test]
    fn capture_mode_defaults_to_env_proxy_and_renders_kebab() {
        // The default is the honest floor: an unlabeled capture is never `forced`.
        assert_eq!(CaptureMode::default(), CaptureMode::EnvProxy);
        assert_eq!(CaptureMode::EnvProxy.to_string(), "env-proxy");
        assert_eq!(CaptureMode::Forced.to_string(), "forced");
        // Serde tag is kebab-case (the wire form other tools will read).
        assert_eq!(
            serde_json::to_string(&CaptureMode::Forced).unwrap(),
            "\"forced\""
        );
        assert_eq!(
            serde_json::from_str::<CaptureMode>("\"env-proxy\"").unwrap(),
            CaptureMode::EnvProxy
        );
    }
}
