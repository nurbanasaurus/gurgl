//! On-disk snapshot storage.
//!
//! One JSON file per capture: `<root>/<server>/<version>.json`. Plain files, no
//! database - snapshots are meant to be human-readable receipts you can diff,
//! commit, and inspect. Nothing here phones home.
//!
//! Two human-review sidecars live next to a server's snapshots:
//! - `acks.toml` - hosts the user has reviewed (`gurgl ack`), so diff can report
//!   them quietly instead of re-alerting. An ack records a decision and its
//!   context; it is never an endorsement of the host.
//! - `baseline` - the version the user accepted as reviewed (`gurgl accept`),
//!   so diff/audit runs compare against what a human actually looked at.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::model::Snapshot;

/// Reject a server or version string that is not a single, safe path component.
///
/// Server names and versions flow in from config files and client configs that
/// may be attacker-influenced (a malicious `.mcp.json` picked up by
/// `discover --import`). They are joined directly into store paths, so a value
/// like `../../.ssh/authorized_keys` or an absolute path would let a capture
/// read or write OUTSIDE the store. Everything that turns one into a path goes
/// through here first; a bad key is a hard error, never a silent traversal.
fn safe_key(kind: &str, value: &str) -> Result<()> {
    let unsafe_key = value.is_empty()
        || value == "."
        || value == ".."
        || value.contains('/')
        || value.contains('\\')
        || value.bytes().any(|b| b == 0)
        || value.chars().any(|c| c.is_control())
        || Path::new(value).is_absolute()
        || Path::new(value).components().count() != 1;
    if unsafe_key {
        bail!(
            "unsafe {kind} '{}': must be a single path component - no separators, '..', \
             control characters, or absolute paths (it names a directory/file under the store)",
            value.escape_debug()
        );
    }
    Ok(())
}

/// Write `contents` to `path` atomically: write a sibling temp file, then rename
/// over the target (atomic on the same filesystem, on Linux and macOS). A crash,
/// a SIGKILL (the second-Ctrl-C force-quit path is exactly this), or an ENOSPC
/// mid-write then leaves the previous good file intact rather than a truncated
/// half-written snapshot/sidecar. Plain `fs::write` truncates in place first.
pub(crate) fn write_atomic(path: &Path, contents: &[u8]) -> Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("gurgl");
    let tmp = dir.join(format!(
        ".{name}.tmp.{}.{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    if let Err(e) = std::fs::write(&tmp, contents) {
        // Don't leave a partial temp behind when the write itself fails (e.g.
        // ENOSPC): only the rename path cleaned up before, so repeated near-full-
        // disk saves would litter the store with orphaned .tmp fragments.
        let _ = std::fs::remove_file(&tmp);
        return Err(e).with_context(|| format!("writing {}", tmp.display()));
    }
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e).with_context(|| format!("renaming into {}", path.display()));
    }
    Ok(())
}

/// One acknowledged host: the user reviewed it and recorded why. Wording is
/// deliberate - "acknowledged", never "approved" or "safe".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ack {
    pub host: String,
    /// The user's reason, verbatim.
    #[serde(default)]
    pub note: Option<String>,
    /// YYYY-MM-DD the ack was recorded.
    pub date: String,
    /// The server version that was latest when the user reviewed it.
    #[serde(default)]
    pub reviewed_at_version: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct AckFile {
    #[serde(default)]
    acks: Vec<Ack>,
}

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
        // An unsafe key has no valid snapshot by definition; never let it probe
        // an arbitrary filesystem path via is_file().
        if safe_key("server", server).is_err() || safe_key("version", version).is_err() {
            return false;
        }
        self.root
            .join(server)
            .join(format!("{version}.json"))
            .is_file()
    }

    pub fn save(&self, snap: &Snapshot) -> Result<PathBuf> {
        safe_key("server", &snap.server)?;
        safe_key("version", &snap.version)?;
        let dir = self.root.join(&snap.server);
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("creating snapshot dir {}", dir.display()))?;
        let path = dir.join(format!("{}.json", snap.version));
        let json = serde_json::to_string_pretty(snap).context("serializing snapshot")?;
        write_atomic(&path, json.as_bytes())?;
        Ok(path)
    }

    pub fn load(&self, server: &str, version: &str) -> Result<Snapshot> {
        safe_key("server", server)?;
        safe_key("version", version)?;
        let path = self.root.join(server).join(format!("{version}.json"));
        // Cap the read. A snapshot is host names + counts (tiny); the cap bounds
        // memory when loading from an UNTRUSTED store (`diff --against <dir>`,
        // whose ordering scan calls this for every file), where a hostile
        // multi-GB snapshot would otherwise OOM. `versions()` treats the error as
        // an unreadable snapshot and skips it, so a legit store is unaffected.
        const MAX_SNAPSHOT: u64 = 8 * 1024 * 1024;
        if std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0) > MAX_SNAPSHOT {
            bail!(
                "snapshot {} exceeds the {} MiB cap",
                path.display(),
                MAX_SNAPSHOT / 1024 / 1024
            );
        }
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
        safe_key("server", server)?;
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
            // Order by captured_at. A corrupt/unreadable snapshot must NOT
            // silently become captured_at 0 (sorted oldest) and thereby shift
            // which version `latest()` returns: surface it on stderr and exclude
            // it from ordering entirely (it can't be shown or diffed anyway).
            match self.load(server, &version) {
                Ok(s) => items.push((s.captured_at, version)),
                Err(e) => {
                    eprintln!(
                        "warning: skipping unreadable snapshot {}: {e:#}",
                        path.display()
                    );
                }
            }
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

    // ---- acknowledgements (acks.toml sidecar) --------------------------------

    fn acks_path(&self, server: &str) -> PathBuf {
        self.root.join(server).join("acks.toml")
    }

    /// The user's acknowledged hosts for this server (empty if none recorded).
    pub fn acks(&self, server: &str) -> Result<Vec<Ack>> {
        safe_key("server", server)?;
        let path = self.acks_path(server);
        if !path.is_file() {
            return Ok(Vec::new());
        }
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        let file: AckFile =
            toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        Ok(file.acks)
    }

    /// Add or update an ack (by host name). Returns whether it replaced one.
    pub fn add_ack(&self, server: &str, ack: Ack) -> Result<bool> {
        let mut acks = self.acks(server)?;
        let replaced = if let Some(existing) = acks.iter_mut().find(|a| a.host == ack.host) {
            *existing = ack;
            true
        } else {
            acks.push(ack);
            false
        };
        self.write_acks(server, &acks)?;
        Ok(replaced)
    }

    /// Remove an ack by host name. Returns whether one existed.
    pub fn remove_ack(&self, server: &str, host: &str) -> Result<bool> {
        let mut acks = self.acks(server)?;
        let before = acks.len();
        acks.retain(|a| a.host != host);
        let removed = acks.len() != before;
        if removed {
            self.write_acks(server, &acks)?;
        }
        Ok(removed)
    }

    fn write_acks(&self, server: &str, acks: &[Ack]) -> Result<()> {
        let path = self.acks_path(server);
        std::fs::create_dir_all(path.parent().unwrap())
            .with_context(|| format!("creating {}", path.parent().unwrap().display()))?;
        let file = AckFile {
            acks: acks.to_vec(),
        };
        let text = format!(
            "# Hosts you have reviewed for this server (`gurgl ack`). An ack means\n\
             # \"a human looked at this and recorded why\" - it is not an endorsement.\n\
             # diff reports acknowledged hosts quietly instead of re-alerting.\n\n{}",
            toml::to_string_pretty(&file).context("serializing acks")?
        );
        write_atomic(&path, text.as_bytes())
    }

    // ---- reviewed baseline (baseline sidecar) --------------------------------

    fn baseline_path(&self, server: &str) -> PathBuf {
        self.root.join(server).join("baseline")
    }

    /// The version the user accepted as reviewed baseline, if any. A version
    /// read back from the sidecar is validated before any caller joins it into a
    /// snapshot path (a hand-edited baseline file is untrusted input too).
    pub fn baseline(&self, server: &str) -> Option<String> {
        if safe_key("server", server).is_err() {
            return None;
        }
        let v = std::fs::read_to_string(self.baseline_path(server)).ok()?;
        let v = v.trim().to_string();
        if v.is_empty() || safe_key("version", &v).is_err() {
            return None;
        }
        Some(v)
    }

    /// Set (or with `None`, clear) the reviewed-baseline pointer.
    pub fn set_baseline(&self, server: &str, version: Option<&str>) -> Result<()> {
        safe_key("server", server)?;
        if let Some(v) = version {
            safe_key("version", v)?;
        }
        let path = self.baseline_path(server);
        match version {
            Some(v) => write_atomic(&path, format!("{v}\n").as_bytes()),
            None => {
                if path.exists() {
                    std::fs::remove_file(&path)
                        .with_context(|| format!("removing {}", path.display()))?;
                }
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Unique per test name: tests run in parallel within one process, so a
    /// pid-keyed dir would be shared and the cleanup of one races the other.
    fn temp_store(tag: &str) -> (Store, PathBuf) {
        let dir =
            std::env::temp_dir().join(format!("gurgl-store-test-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        (Store::new(dir.clone()), dir)
    }

    #[test]
    fn acks_round_trip_update_and_remove() {
        let (store, dir) = temp_store("acks");
        assert!(store.acks("srv").unwrap().is_empty());

        let ack = Ack {
            host: "cdn.example.net".into(),
            note: Some("CDN used by the pdf renderer".into()),
            date: "2026-07-04".into(),
            reviewed_at_version: Some("1.3.0".into()),
        };
        assert!(!store.add_ack("srv", ack.clone()).unwrap()); // new
        assert_eq!(store.acks("srv").unwrap(), vec![ack.clone()]);

        // Re-acking the same host replaces, not duplicates.
        let updated = Ack {
            note: Some("still expected".into()),
            ..ack
        };
        assert!(store.add_ack("srv", updated.clone()).unwrap());
        assert_eq!(store.acks("srv").unwrap(), vec![updated]);

        assert!(store.remove_ack("srv", "cdn.example.net").unwrap());
        assert!(!store.remove_ack("srv", "cdn.example.net").unwrap());
        assert!(store.acks("srv").unwrap().is_empty());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn rejects_path_traversal_keys() {
        let (store, dir) = temp_store("traversal");
        let evil = Snapshot {
            server: "../../../../tmp/gurgl-pwn".into(),
            version: "1.0".into(),
            captured_at: 0,
            trials: 1,
            flightplan: "fp".into(),
            gurgl_version: "0".into(),
            hosts: vec![],
        };
        assert!(
            store.save(&evil).is_err(),
            "traversal server must be refused"
        );
        assert!(store.load("..", "1.0").is_err());
        assert!(store.load("srv", "../secret").is_err());
        assert!(store.versions("a/b").is_err());
        assert!(!store.exists("../x", "1.0"));
        // A safe key still works.
        let ok = Snapshot {
            server: "srv".into(),
            ..evil
        };
        assert!(store.save(&ok).is_ok());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn baseline_set_get_clear() {
        let (store, dir) = temp_store("baseline");
        assert_eq!(store.baseline("srv"), None);
        store.set_baseline("srv", Some("1.2.0")).unwrap();
        assert_eq!(store.baseline("srv"), Some("1.2.0".into()));
        store.set_baseline("srv", None).unwrap();
        assert_eq!(store.baseline("srv"), None);
        let _ = std::fs::remove_dir_all(dir);
    }
}
