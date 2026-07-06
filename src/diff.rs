//! Pure version-over-version egress diffing.
//!
//! Given two snapshots of the same server, report which host names appeared and
//! disappeared. This is the load-bearing signal: "did this update start talking
//! to somewhere new?" We carry each delta's reproducibility so the caller can
//! separate stable changes (report) from intermittent ones (cohort noise).

use std::collections::BTreeSet;

use serde::Serialize;

use crate::model::{HostClass, Reproducibility, Snapshot};

/// A same-version overwrite whose STABLE host set changed - the signature of a
/// re-released ("rug-pulled") package. `added`/`removed` are stable host names
/// that appeared / disappeared under an unchanged version label.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StableConflict {
    pub added: Vec<String>,
    pub removed: Vec<String>,
}

/// Detect a rug-pull: `new` is about to overwrite `prev` (the stored capture of
/// the SAME server@version) but their stable host sets differ. `Some` only when
/// BOTH captures ran a real battery (`trials >= 2`, so the reproduction gate
/// applied) under the SAME flight-plan fingerprint - otherwise a difference is
/// method change or single-run noise, not a rug pull. Only `Stable` hosts count
/// (constraint #3: intermittent/observed deltas never trigger it). `None` = safe
/// to overwrite. Pure.
pub fn same_label_conflict(prev: &Snapshot, new: &Snapshot) -> Option<StableConflict> {
    if prev.trials < 2 || new.trials < 2 {
        return None;
    }
    if prev.flightplan != new.flightplan {
        return None;
    }
    let prev_stable: BTreeSet<&str> = prev.stable_hosts().map(|h| h.name.as_str()).collect();
    let new_stable: BTreeSet<&str> = new.stable_hosts().map(|h| h.name.as_str()).collect();
    if prev_stable == new_stable {
        return None;
    }
    Some(StableConflict {
        added: new_stable
            .difference(&prev_stable)
            .map(|s| s.to_string())
            .collect(),
        removed: prev_stable
            .difference(&new_stable)
            .map(|s| s.to_string())
            .collect(),
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HostDelta {
    pub name: String,
    pub class: HostClass,
    pub reproducibility: Reproducibility,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SnapshotDiff {
    pub server: String,
    pub from_version: String,
    pub to_version: String,
    pub added: Vec<HostDelta>,
    pub removed: Vec<HostDelta>,
    pub unchanged: usize,
}

impl SnapshotDiff {
    /// New hosts that reproduced in every trial of the newer capture. These are
    /// the only additions worth alerting on; intermittent additions are treated
    /// as likely feature-gate/cohort noise, never as a finding.
    pub fn stable_added(&self) -> Vec<&HostDelta> {
        self.added
            .iter()
            .filter(|d| d.reproducibility == Reproducibility::Stable)
            .collect()
    }

    /// Stable additions that deserve scrutiny - the sharpest signal. Covers
    /// `Unknown` and `TelemetryNamed` (a host that merely names itself
    /// telemetry is not vetted; see model::classify).
    pub fn stable_unknown_added(&self) -> Vec<&HostDelta> {
        self.stable_added()
            .into_iter()
            .filter(|d| d.class.needs_scrutiny())
            .collect()
    }
}

pub fn diff(from: &Snapshot, to: &Snapshot) -> SnapshotDiff {
    let from_names = from.host_names();
    let to_names = to.host_names();

    let mut added = Vec::new();
    for h in &to.hosts {
        if !from_names.contains(&h.name) {
            added.push(HostDelta {
                name: h.name.clone(),
                class: h.class,
                reproducibility: h.reproducibility,
            });
        }
    }

    let mut removed = Vec::new();
    for h in &from.hosts {
        if !to_names.contains(&h.name) {
            removed.push(HostDelta {
                name: h.name.clone(),
                class: h.class,
                reproducibility: h.reproducibility,
            });
        }
    }

    let unchanged = to
        .hosts
        .iter()
        .filter(|h| from_names.contains(&h.name))
        .count();

    added.sort_by(|a, b| a.name.cmp(&b.name));
    removed.sort_by(|a, b| a.name.cmp(&b.name));

    SnapshotDiff {
        server: to.server.clone(),
        from_version: from.version.clone(),
        to_version: to.version.clone(),
        added,
        removed,
        unchanged,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{CaptureMode, Host};

    fn host(name: &str, repro: Reproducibility) -> Host {
        Host {
            name: name.into(),
            class: HostClass::Unknown,
            reproducibility: repro,
            seen_in_trials: 2,
            phases: vec![],
        }
    }

    fn snap(fingerprint: &str, trials: u32, hosts: Vec<Host>) -> Snapshot {
        Snapshot {
            server: "s".into(),
            version: "1.0.0".into(),
            captured_at: 0,
            trials,
            flightplan: fingerprint.into(),
            gurgl_version: "0".into(),
            capture_mode: CaptureMode::EnvProxy,
            reported_version: None,
            version_source: None,
            hosts,
        }
    }

    #[test]
    fn conflict_only_on_stable_set_change_under_same_method() {
        let a = snap("fp", 2, vec![host("keep.example", Reproducibility::Stable)]);

        // Stable host added under the same label -> conflict.
        let b = snap(
            "fp",
            2,
            vec![
                host("keep.example", Reproducibility::Stable),
                host("new.example", Reproducibility::Stable),
            ],
        );
        let c = same_label_conflict(&a, &b).expect("stable set changed");
        assert_eq!(c.added, vec!["new.example".to_string()]);
        assert!(c.removed.is_empty());

        // Stable host removed -> conflict (either direction).
        let c2 = same_label_conflict(&b, &a).expect("stable set changed");
        assert_eq!(c2.removed, vec!["new.example".to_string()]);

        // Identical stable sets -> no conflict.
        assert!(same_label_conflict(&a, &a).is_none());
    }

    #[test]
    fn conflict_ignores_intermittent_and_ungated_and_method_change() {
        let base = snap("fp", 2, vec![host("keep.example", Reproducibility::Stable)]);

        // Only an intermittent host differs -> not a conflict (constraint #3).
        let interm = snap(
            "fp",
            2,
            vec![
                host("keep.example", Reproducibility::Stable),
                host("flaky.example", Reproducibility::Intermittent),
            ],
        );
        assert!(same_label_conflict(&base, &interm).is_none());

        // Either side did not run a battery (trials < 2) -> no conflict.
        let single = snap("fp", 1, vec![host("new.example", Reproducibility::Stable)]);
        assert!(same_label_conflict(&base, &single).is_none());
        assert!(same_label_conflict(&single, &base).is_none());

        // Different flight-plan fingerprint -> method changed, not a rug pull.
        let other_method = snap(
            "fp-other",
            2,
            vec![host("new.example", Reproducibility::Stable)],
        );
        assert!(same_label_conflict(&base, &other_method).is_none());
    }
}
