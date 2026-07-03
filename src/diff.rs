//! Pure version-over-version egress diffing.
//!
//! Given two snapshots of the same server, report which host names appeared and
//! disappeared. This is the load-bearing signal: "did this update start talking
//! to somewhere new?" We carry each delta's reproducibility so the caller can
//! separate stable changes (report) from intermittent ones (cohort noise).

use crate::model::{HostClass, Reproducibility, Snapshot};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostDelta {
    pub name: String,
    pub class: HostClass,
    pub reproducibility: Reproducibility,
}

#[derive(Debug, Clone, PartialEq, Eq)]
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

    /// Stable additions that we could not classify - the sharpest signal.
    pub fn stable_unknown_added(&self) -> Vec<&HostDelta> {
        self.stable_added()
            .into_iter()
            .filter(|d| d.class == HostClass::Unknown)
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
