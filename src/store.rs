//! On-disk snapshot storage.
//!
//! One JSON file per capture: `<root>/<server>/<version>.json`. Plain files, no
//! database - snapshots are meant to be human-readable receipts you can diff,
//! commit, and inspect. Nothing here phones home.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::model::Snapshot;

pub struct Store {
    root: PathBuf,
}

impl Store {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Store { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Whether a snapshot is already stored for this server@version. `save`
    /// overwrites silently by design (re-capturing the same version refreshes
    /// it); callers use this to warn when that would destroy a baseline.
    pub fn exists(&self, server: &str, version: &str) -> bool {
        self.root
            .join(server)
            .join(format!("{version}.json"))
            .is_file()
    }

    pub fn save(&self, snap: &Snapshot) -> Result<PathBuf> {
        let dir = self.root.join(&snap.server);
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("creating snapshot dir {}", dir.display()))?;
        let path = dir.join(format!("{}.json", snap.version));
        let json = serde_json::to_string_pretty(snap).context("serializing snapshot")?;
        std::fs::write(&path, json).with_context(|| format!("writing {}", path.display()))?;
        Ok(path)
    }

    pub fn load(&self, server: &str, version: &str) -> Result<Snapshot> {
        let path = self.root.join(server).join(format!("{version}.json"));
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("reading snapshot {}", path.display()))?;
        let snap: Snapshot =
            serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        Ok(snap)
    }

    pub fn servers(&self) -> Result<Vec<String>> {
        let mut out = Vec::new();
        if !self.root.exists() {
            return Ok(out);
        }
        for entry in std::fs::read_dir(&self.root)
            .with_context(|| format!("reading store {}", self.root.display()))?
        {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                if let Some(name) = entry.file_name().to_str() {
                    out.push(name.to_string());
                }
            }
        }
        out.sort();
        Ok(out)
    }

    /// Versions of a server, sorted oldest-first by capture time.
    pub fn versions(&self, server: &str) -> Result<Vec<String>> {
        let dir = self.root.join(server);
        let mut items: Vec<(u64, String)> = Vec::new();
        if !dir.exists() {
            return Ok(Vec::new());
        }
        for entry in
            std::fs::read_dir(&dir).with_context(|| format!("reading {}", dir.display()))?
        {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let version = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or_default()
                .to_string();
            // Read captured_at to order; fall back to 0 if unreadable.
            let captured_at = self
                .load(server, &version)
                .map(|s| s.captured_at)
                .unwrap_or(0);
            items.push((captured_at, version));
        }
        items.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
        Ok(items.into_iter().map(|(_, v)| v).collect())
    }

    /// The two most recent versions (previous, latest), if at least two exist.
    pub fn latest_two(&self, server: &str) -> Result<Option<(String, String)>> {
        let versions = self.versions(server)?;
        if versions.len() < 2 {
            return Ok(None);
        }
        let latest = versions[versions.len() - 1].clone();
        let previous = versions[versions.len() - 2].clone();
        Ok(Some((previous, latest)))
    }

    pub fn latest(&self, server: &str) -> Result<Option<String>> {
        Ok(self.versions(server)?.pop())
    }
}
