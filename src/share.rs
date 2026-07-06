//! Shared egress captures: export a scrubbed, shareable capture of a server's
//! observed egress, and load someone else's to diff against.
//!
//! This is deliberately NOT a "baseline" and NOT a verdict. A shared capture is
//! one observer's presence-only host inventory under their own flight plan: a
//! FLOOR of hosts they reproduced, never a ceiling, never an allowlist, never a
//! statement that a tool is safe. Matching one proves nothing - a malicious
//! server exfiltrating over a host it already contacts produces an identical host
//! set, which gurgl cannot see (docs/THREAT-MODEL.md).
//!
//! CONSUMING a shared capture is treated as loading HOSTILE input: the file is
//! size-capped, every string is control-stripped, host names go through the same
//! tested normalization as live flows, and the reproduction gate is re-applied
//! LOCALLY - a shared file is never trusted to have been gated, sanitized, or
//! honestly authored by whoever sent it.
//!
//! No network, ever (non-negotiable #5): `--against` takes a LOCAL path only.
//! There is deliberately no default/well-known baseline URL, no "check for a
//! newer community capture", no registry endpoint - and there must never be one.

use std::path::Path;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::model::{classify, CaptureMode, Host, HostClass, Reproducibility, Snapshot};
use crate::proxy::{normalize_host, strip_control};

pub const SHARE_SCHEMA: &str = "gurgl.shared-capture/1";

/// Size cap for any file read while consuming a shared capture. Real captures are
/// tiny; the cap stops a hostile multi-GB file from OOMing the loader.
const CAP: u64 = 8 * 1024 * 1024;

/// A shareable capture. Carries only what the proxy logged - host names, trial
/// counts, phases, and the flight-plan fingerprint - NOT gurgl's per-host `class`
/// inference. A class is a characterization of a third party; publishing it
/// pre-draws the reader's conclusion and is the exact factual-sounding
/// characterization the Enigma v. Malwarebytes precedent treats as actionable
/// (docs/PUBLISHING.md). The consumer recomputes class locally, against their own
/// first_party list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedCapture {
    pub schema: String,
    /// The rules that MUST travel with any artifact that names a third party, so
    /// they reach whoever receives or reposts the file - not just its author's
    /// terminal.
    pub guardrails: Vec<String>,
    pub server: String,
    pub version: String,
    /// Date (YYYY-MM-DD), coarsened from the capture time: a shared file needs a
    /// receipt date, not a second-precise probe timestamp that correlates the
    /// exporter's activity.
    pub captured_date: String,
    pub trials: u32,
    pub flightplan: String,
    pub gurgl_version: String,
    pub hosts: Vec<SharedHost>,
}

/// One host in a shared capture: name + reproduction evidence + the phases it was
/// seen in. No class (see SharedCapture), no reproducibility field (everything
/// here is Stable by construction - export drops the rest).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedHost {
    pub name: String,
    pub seen_in_trials: u32,
    #[serde(default)]
    pub phases: Vec<String>,
}

/// A shared capture loaded and made safe to compare: sanitized, stable-only,
/// reclassified against the consumer's first_party.
#[derive(Debug)]
pub struct Loaded {
    pub snapshot: Snapshot,
    /// Human label of where it came from (shown to the user).
    pub source: String,
}

/// The guardrails baked into every exported file so the publishing rules travel
/// with the artifact (docs/PUBLISHING.md), not just to the exporter's stderr.
fn guardrails() -> Vec<String> {
    vec![
        "This is a presence-only egress capture, NOT a safety verdict. It lists \
         host names one observer saw a tool contact under one flight plan."
            .to_string(),
        "It is a FLOOR of hosts that reproduced, never a ceiling or an allowlist. \
         Absence of a host is non-coverage, not proof a tool won't contact it."
            .to_string(),
        "Matching this capture is NOT a clean bill of health: a tool exfiltrating \
         over a host it already contacts produces an identical host set, which \
         gurgl cannot see (docs/THREAT-MODEL.md)."
            .to_string(),
        "Host classes are omitted on purpose: what a host IS is the reader's \
         conclusion to draw from the raw names, not the publisher's to assert."
            .to_string(),
        "A host reached via a tool-call ARGUMENT may be the exporter's, not the \
         tool's - do not attribute it to the named server."
            .to_string(),
        "A low trial count is a weak reproduction claim, not cohort-pinned proof.".to_string(),
        "Before publishing anything that names a third party: form an entity and \
         carry insurance, coordinate disclosure with the author, never punch \
         down. See docs/PUBLISHING.md."
            .to_string(),
    ]
}

/// Build a scrubbed shareable capture from a local snapshot. STABLE hosts only
/// (the reproduction gate is mandatory for anything shared - PUBLISHING.md #4),
/// `class` dropped, capture time coarsened to a date, guardrails baked in.
pub fn export(snap: &Snapshot, as_name: Option<&str>) -> SharedCapture {
    let mut hosts: Vec<SharedHost> = snap
        .hosts
        .iter()
        .filter(|h| h.reproducibility == Reproducibility::Stable)
        .map(|h| SharedHost {
            name: h.name.clone(),
            seen_in_trials: h.seen_in_trials,
            phases: h.phases.clone(),
        })
        .collect();
    hosts.sort_by(|a, b| a.name.cmp(&b.name));
    SharedCapture {
        schema: SHARE_SCHEMA.to_string(),
        guardrails: guardrails(),
        server: as_name.unwrap_or(&snap.server).to_string(),
        version: snap.version.clone(),
        captured_date: date_from_epoch(snap.captured_at),
        trials: snap.trials,
        flightplan: snap.flightplan.clone(),
        gurgl_version: snap.gurgl_version.clone(),
        hosts,
    }
}

/// Load someone else's capture of `server` to diff against, from a local PATH:
/// a shared-capture file, a raw gurgl snapshot file, or a gurgl store directory.
/// Treats the input as hostile - caps size, control-strips every string, and
/// re-applies the reproduction gate locally. `first_party` is the CONSUMER's
/// list, used to recompute host classes (never the producer's).
pub fn load_against(path: &Path, server: &str, first_party: &[String]) -> Result<Loaded> {
    // No network, ever (#5): a URL-shaped argument is not a path we resolve.
    // Refuse it explicitly rather than letting it fail as a missing file, so
    // nobody mistakes gurgl for something that fetches captures.
    let p = path.to_string_lossy();
    if p.contains("://") {
        bail!(
            "gurgl never fetches shared captures over the network (local-first). \
             Download the file yourself and pass the local path."
        );
    }
    let meta = std::fs::metadata(path).with_context(|| {
        format!(
            "no such path: {} - pass a local shared-capture file or a gurgl store dir",
            path.display()
        )
    })?;

    let (raw, source) = if meta.is_dir() {
        load_from_store_dir(path, server)?
    } else {
        load_from_file(path)?
    };

    Ok(Loaded {
        snapshot: sanitize_and_regate(raw, first_party),
        source,
    })
}

/// Read a file, refusing symlinks / non-regular files and anything over the cap.
/// HARD-ERRORS on any failure - never degrades to an empty result, because an
/// empty "other" side would make diff() mark every local host as a difference and
/// fabricate a finding (inventory, not invented facts).
fn read_capped(path: &Path, reject_symlink: bool) -> Result<String> {
    let meta =
        std::fs::symlink_metadata(path).with_context(|| format!("reading {}", path.display()))?;
    if reject_symlink && meta.file_type().is_symlink() {
        bail!(
            "{} is a symlink - refusing to follow it in an untrusted shared capture",
            path.display()
        );
    }
    // Follow to the target's metadata for the regular-file + size checks (a
    // char device / fifo is not a regular file; a symlink to a huge file is
    // caught by the size cap).
    let meta = std::fs::metadata(path).with_context(|| format!("reading {}", path.display()))?;
    if !meta.is_file() {
        bail!("{} is not a regular file", path.display());
    }
    if meta.len() > CAP {
        bail!(
            "{} is {} bytes, over the {} MiB cap for a shared capture",
            path.display(),
            meta.len(),
            CAP / 1024 / 1024
        );
    }
    std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))
}

/// Load an untrusted single FILE: a shared-capture bundle (schema-gated) or a raw
/// gurgl snapshot (no schema field). An unknown schema is refused, never guessed.
fn load_from_file(path: &Path) -> Result<(Snapshot, String)> {
    // The top-level file the user named may itself be a symlink they chose - that
    // is fine; only files we DISCOVER inside a store dir are symlink-refused.
    let text = read_capped(path, false)?;
    let value: serde_json::Value = serde_json::from_str(&text)
        .with_context(|| format!("{} is not valid JSON", path.display()))?;
    match value.get("schema").and_then(|s| s.as_str()) {
        Some(SHARE_SCHEMA) => {
            let sc: SharedCapture = serde_json::from_value(value)
                .with_context(|| format!("{} is not a valid {}", path.display(), SHARE_SCHEMA))?;
            // sc.server/sc.version are untrusted and reach the terminal via this
            // label - control-strip them here (sanitize_and_regate only cleans the
            // Snapshot copy, never this separately-built string).
            let source = format!(
                "{} [shared capture: {} @ {}]",
                path.display(),
                strip_control(&sc.server),
                strip_control(&sc.version)
            );
            Ok((shared_to_snapshot(sc), source))
        }
        Some(other) => bail!(
            "{}: unknown schema '{}' - expected {} or a raw gurgl snapshot",
            path.display(),
            other,
            SHARE_SCHEMA
        ),
        None => {
            let snap: Snapshot = serde_json::from_value(value).with_context(|| {
                format!(
                    "{} is neither a shared capture nor a gurgl snapshot",
                    path.display()
                )
            })?;
            let source = format!(
                "{} [raw snapshot: {} @ {}]",
                path.display(),
                strip_control(&snap.server),
                strip_control(&snap.version)
            );
            Ok((snap, source))
        }
    }
}

/// Load the latest capture of `server` from another gurgl STORE directory. Reuses
/// Store (so `server` goes through its traversal-safe key, and Store::load's size
/// cap bounds every file the ordering scan reads - a hostile store with a giant
/// snapshot can't OOM us). The re-read below is capped + symlink-rejecting too.
fn load_from_store_dir(dir: &Path, server: &str) -> Result<(Snapshot, String)> {
    let store = crate::store::Store::new(dir);
    // latest() applies the store's safe_key to `server`, so it errors on a
    // traversal attempt before we build any path; its scan reads each candidate
    // through the (now capped) Store::load, skipping oversized/unreadable files.
    let version = store
        .latest(server)?
        .with_context(|| format!("no captures for '{server}' in store {}", dir.display()))?;
    let file = dir.join(server).join(format!("{version}.json"));
    let text = read_capped(&file, true)?;
    let snap: Snapshot = serde_json::from_str(&text)
        .with_context(|| format!("{} is not a valid snapshot", file.display()))?;
    // `version` is a filesystem-derived name from a possibly-hostile store, so
    // control-strip it (and `server`) before it reaches the terminal.
    let source = format!(
        "{}/{}@{} (store)",
        dir.display(),
        strip_control(server),
        strip_control(&version)
    );
    Ok((snap, source))
}

/// Convert a loaded shared-capture bundle to a Snapshot for comparison. Hosts are
/// marked Stable (they are, by export contract) and Unknown (reclassified later);
/// captured_at is 0 (the bundle carries only a date, never used for compare).
fn shared_to_snapshot(sc: SharedCapture) -> Snapshot {
    Snapshot {
        server: sc.server,
        version: sc.version,
        captured_at: 0,
        trials: sc.trials,
        flightplan: sc.flightplan,
        gurgl_version: sc.gurgl_version,
        // A shared capture asserts no capture mode (the export format does not
        // carry one), so default to the honest floor - never claim `forced` for
        // someone else's untrusted file.
        capture_mode: CaptureMode::EnvProxy,
        // The export format carries no version provenance, and it would be
        // attacker-influenced anyway - do not fabricate it for a peer's file.
        reported_version: None,
        version_source: None,
        hosts: sc
            .hosts
            .into_iter()
            .map(|h| Host {
                name: h.name,
                class: HostClass::Unknown,
                reproducibility: Reproducibility::Stable,
                seen_in_trials: h.seen_in_trials,
                phases: h.phases,
            })
            .collect(),
    }
}

/// Make an untrusted loaded snapshot safe to compare and display: control-strip
/// every string, RE-APPLY the reproduction gate (drop anything not Stable - the
/// file is never trusted to have been gated), normalize + reclassify each host
/// with the CONSUMER's first_party, and drop any host whose name is empty after
/// normalization. Dedups names that normalization collapses together.
fn sanitize_and_regate(snap: Snapshot, first_party: &[String]) -> Snapshot {
    let mut hosts: Vec<Host> = Vec::new();
    for h in snap.hosts {
        if h.reproducibility != Reproducibility::Stable {
            continue; // re-gate locally: only stable hosts are comparable facts
        }
        let Some(name) = normalize_host(&h.name) else {
            continue;
        };
        let class = classify(&name, first_party);
        let phases: Vec<String> = h.phases.iter().map(|p| strip_control(p)).collect();
        hosts.push(Host {
            name,
            class,
            reproducibility: Reproducibility::Stable,
            seen_in_trials: h.seen_in_trials,
            phases,
        });
    }
    hosts.sort_by(|a, b| a.name.cmp(&b.name));
    hosts.dedup_by(|a, b| a.name == b.name);
    Snapshot {
        server: strip_control(&snap.server),
        version: strip_control(&snap.version),
        captured_at: snap.captured_at,
        trials: snap.trials,
        flightplan: strip_control(&snap.flightplan),
        gurgl_version: strip_control(&snap.gurgl_version),
        // Carry the mode through untouched: it is gurgl's own method provenance,
        // not a third-party characterization (unlike `class`, which is dropped).
        // For a shared-capture source it is already the EnvProxy floor.
        capture_mode: snap.capture_mode,
        // Drop version provenance from untrusted input: reported_version is
        // attacker-influenced and version_source describes the peer's derivation,
        // neither of which a consumer should trust or act on.
        reported_version: None,
        version_source: None,
        hosts,
    }
}

/// YYYY-MM-DD (UTC) for a unix-seconds timestamp. Civil-from-days (Hinnant),
/// valid for the unix era; no date dependency.
pub fn date_from_epoch(secs: u64) -> String {
    let z = (secs / 86_400) as i64 + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(name: &str, repro: Reproducibility) -> Host {
        Host {
            name: name.to_string(),
            class: HostClass::Unknown,
            reproducibility: repro,
            seen_in_trials: 2,
            phases: vec!["startup".to_string()],
        }
    }

    fn snap(hosts: Vec<Host>) -> Snapshot {
        Snapshot {
            server: "probe".to_string(),
            version: "1.0.0".to_string(),
            captured_at: 1_700_000_000,
            trials: 2,
            flightplan: "default-abc".to_string(),
            gurgl_version: "0.1.0".to_string(),
            capture_mode: CaptureMode::EnvProxy,
            reported_version: None,
            version_source: None,
            hosts,
        }
    }

    #[test]
    fn export_is_stable_only_and_classless() {
        let s = snap(vec![
            host("stable.example", Reproducibility::Stable),
            host("flaky.example", Reproducibility::Intermittent),
            host("once.example", Reproducibility::Observed),
        ]);
        let sc = export(&s, None);
        // Only the stable host survives; class is not a field anyone can read.
        assert_eq!(sc.hosts.len(), 1);
        assert_eq!(sc.hosts[0].name, "stable.example");
        assert_eq!(sc.schema, SHARE_SCHEMA);
        assert!(!sc.guardrails.is_empty());
        // Time is coarsened to a date, not a second-precise timestamp.
        assert_eq!(sc.captured_date, "2023-11-14");
    }

    #[test]
    fn export_can_rename_the_server_label() {
        let sc = export(
            &snap(vec![host("a.example", Reproducibility::Stable)]),
            Some("canonical-name"),
        );
        assert_eq!(sc.server, "canonical-name");
    }

    #[test]
    fn load_against_refuses_a_url_without_touching_the_network() {
        let err = load_against(
            Path::new("https://evil.example/baseline.json"),
            "probe",
            &[],
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("never fetches"), "got: {err}");
    }

    #[test]
    fn sanitize_regates_and_reclassifies_and_strips_control_bytes() {
        // A raw snapshot as if hand-shared: an intermittent host (must be dropped),
        // a host with a trailing control byte + dot (must normalize), and a host
        // that should reclassify against OUR first_party.
        let del = '\u{7f}';
        let raw = Snapshot {
            server: format!("pr{del}obe"),
            version: "9.9".to_string(),
            captured_at: 0,
            trials: 2,
            flightplan: "fp".to_string(),
            gurgl_version: "x".to_string(),
            capture_mode: CaptureMode::EnvProxy,
            reported_version: None,
            version_source: None,
            hosts: vec![
                host("registry.npmjs.org", Reproducibility::Stable),
                host("flaky.example", Reproducibility::Intermittent),
                Host {
                    name: format!("api.mine.example.{del}"),
                    class: HostClass::Unknown,
                    reproducibility: Reproducibility::Stable,
                    seen_in_trials: 2,
                    phases: vec![format!("start{del}up")],
                },
            ],
        };
        let out = sanitize_and_regate(raw, &["api.mine.example".to_string()]);
        // Intermittent dropped by the re-gate; two stable hosts remain.
        assert_eq!(out.hosts.len(), 2);
        // Control byte gone from every string.
        assert_eq!(out.server, "probe");
        assert!(!out.hosts[0].phases.iter().any(|p| p.contains(del)));
        // The npm host reclassifies as Registry; our first_party host as FirstParty.
        let npm = out
            .hosts
            .iter()
            .find(|h| h.name == "registry.npmjs.org")
            .unwrap();
        assert_eq!(npm.class, HostClass::Registry);
        let mine = out
            .hosts
            .iter()
            .find(|h| h.name == "api.mine.example")
            .unwrap();
        assert_eq!(mine.class, HostClass::FirstParty);
    }

    #[test]
    fn export_then_load_round_trips_stable_hosts() {
        let dir = std::env::temp_dir().join(format!("gurgl-share-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("bundle.json");
        let s = snap(vec![
            host("a.example", Reproducibility::Stable),
            host("b.example", Reproducibility::Stable),
            host("flaky.example", Reproducibility::Intermittent),
        ]);
        let sc = export(&s, None);
        std::fs::write(&file, serde_json::to_string(&sc).unwrap()).unwrap();

        let loaded = load_against(&file, "probe", &[]).unwrap();
        let names: Vec<&str> = loaded
            .snapshot
            .hosts
            .iter()
            .map(|h| h.name.as_str())
            .collect();
        assert_eq!(names, vec!["a.example", "b.example"]); // stable only, sorted
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_source_label_strips_control_bytes() {
        // A hostile bundle puts an ANSI escape in server/version to forge a fake
        // "PASS" line via the `source:` label. The loaded source must be clean.
        let dir = std::env::temp_dir().join(format!("gurgl-share-src-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("evil.json");
        let esc = '\u{1b}';
        let mut sc = export(
            &snap(vec![host("a.example", Reproducibility::Stable)]),
            None,
        );
        sc.server = format!("{esc}[2K forged PASS");
        sc.version = format!("v{esc}[0m");
        std::fs::write(&file, serde_json::to_string(&sc).unwrap()).unwrap();

        let loaded = load_against(&file, "probe", &[]).unwrap();
        assert!(
            !loaded.source.contains(esc),
            "source leaked a control byte: {:?}",
            loaded.source
        );
        // And the sanitized snapshot's server/version are clean too.
        assert!(!loaded.snapshot.server.contains(esc));
        assert!(!loaded.snapshot.version.contains(esc));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_rejects_unknown_schema() {
        let dir = std::env::temp_dir().join(format!("gurgl-share-schema-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("weird.json");
        std::fs::write(&file, r#"{"schema":"gurgl.something/9","hosts":[]}"#).unwrap();
        let err = load_against(&file, "probe", &[]).unwrap_err().to_string();
        assert!(err.contains("unknown schema"), "got: {err}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
