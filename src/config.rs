//! gurgl configuration (`gurgl.toml`).

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SandboxKind {
    /// Rootless, no daemon (Linux). Requires `bwrap` on PATH.
    Bubblewrap,
    /// Requires `podman` (Linux natively; macOS via a VM).
    Podman,
    /// macOS-native Seatbelt sandbox. Requires `sandbox-exec`.
    SandboxExec,
}

impl Default for SandboxKind {
    /// OS-aware: Seatbelt on macOS, bubblewrap elsewhere.
    fn default() -> Self {
        #[cfg(target_os = "macos")]
        {
            SandboxKind::SandboxExec
        }
        #[cfg(not(target_os = "macos"))]
        {
            SandboxKind::Bubblewrap
        }
    }
}

/// One MCP server gurgl watches.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerSpec {
    /// Logical name used for storage and on the CLI, e.g. "filesystem-mcp".
    pub name: String,
    /// Launch command, run *inside* the sandbox (e.g. "npx").
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
    /// Optional explicit version label. If absent, gurgl derives one at capture.
    #[serde(default)]
    pub version: Option<String>,
    /// Declared first-party domains for this server, used to classify egress.
    #[serde(default)]
    pub first_party: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    /// Where snapshots are stored. `~` is expanded. Default: `~/.gurgl/snapshots`.
    #[serde(default)]
    pub store: Option<String>,
    #[serde(default)]
    pub sandbox: SandboxKind,
    /// Path/name of the mitmdump binary (proxy backend).
    #[serde(default = "default_mitmdump")]
    pub mitmdump: String,
    /// Path to the default flight plan.
    #[serde(default = "default_flightplan")]
    pub flightplan: String,
    /// Trials per capture (the reproduction gate). Higher = less cohort noise.
    #[serde(default = "default_trials")]
    pub trials: u32,
    #[serde(default)]
    pub servers: Vec<ServerSpec>,

    /// Directory of the loaded config file. Used to resolve relative `store` and
    /// `flightplan` paths against the config's location rather than the current
    /// working directory. Not part of the file format.
    #[serde(skip)]
    base_dir: Option<PathBuf>,
}

fn default_mitmdump() -> String {
    "mitmdump".to_string()
}
fn default_flightplan() -> String {
    "flightplans/default.toml".to_string()
}
fn default_trials() -> u32 {
    5
}

impl Default for Config {
    fn default() -> Self {
        Config {
            store: None,
            sandbox: SandboxKind::default(),
            mitmdump: default_mitmdump(),
            flightplan: default_flightplan(),
            trials: default_trials(),
            servers: Vec::new(),
            base_dir: None,
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Config> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading config {}", path.display()))?;
        let mut cfg: Config =
            toml::from_str(&text).with_context(|| format!("parsing config {}", path.display()))?;
        cfg.base_dir = path.parent().map(|p| p.to_path_buf());
        Ok(cfg)
    }

    /// Resolve a possibly-relative path from the config against the config
    /// file's directory (so a config works regardless of the current dir).
    /// `~` is expanded; absolute paths pass through unchanged.
    fn resolve(&self, p: &str) -> PathBuf {
        let expanded = expand_tilde(p);
        if expanded.is_absolute() {
            return expanded;
        }
        match &self.base_dir {
            Some(base) => base.join(expanded),
            None => expanded,
        }
    }

    /// The flight plan path, resolved relative to the config file.
    pub fn flightplan_path(&self) -> PathBuf {
        self.resolve(&self.flightplan)
    }

    pub fn server(&self, name: &str) -> Option<&ServerSpec> {
        self.servers.iter().find(|s| s.name == name)
    }

    /// Resolve the store directory: explicit `store` (with `~` expanded) or the
    /// default `~/.gurgl/snapshots`.
    pub fn store_dir(&self) -> Result<PathBuf> {
        if let Some(s) = &self.store {
            return Ok(self.resolve(s));
        }
        Ok(gurgl_home().join("snapshots"))
    }

    /// The `gurgl.toml` written by `gurgl init`.
    pub fn template() -> &'static str {
        TEMPLATE
    }
}

fn expand_tilde(s: &str) -> PathBuf {
    if let Some(rest) = s.strip_prefix("~/") {
        if let Some(home) = dirs::home_dir() {
            return home.join(rest);
        }
    }
    PathBuf::from(s)
}

/// gurgl's self-contained home directory: `$GURGL_HOME` if set, else `~/.gurgl`.
///
/// Everything gurgl needs lives under here - the binary (`bin/`), `gurgl.toml`,
/// `flightplans/`, the snapshot store (`snapshots/`), and the lab CA
/// (`mitmproxy/`). One directory you can inspect, back up, or `rm -rf`.
pub fn gurgl_home() -> PathBuf {
    if let Some(h) = std::env::var_os("GURGL_HOME") {
        return PathBuf::from(h);
    }
    match dirs::home_dir() {
        Some(home) => home.join(".gurgl"),
        None => PathBuf::from(".gurgl"),
    }
}

/// The default config path, `~/.gurgl/gurgl.toml`, used when neither `--config`
/// nor a `./gurgl.toml` in the current directory is present.
pub fn default_config_path() -> PathBuf {
    gurgl_home().join("gurgl.toml")
}

/// The default flight plan, embedded so `gurgl init` can lay down a fully
/// self-contained `~/.gurgl` without needing the source tree present.
pub const DEFAULT_FLIGHTPLAN: &str = include_str!("../flightplans/default.toml");

const TEMPLATE: &str = r#"# gurgl configuration.
# Local-first egress hygiene for the MCP servers you run.

# Where captures are stored. Relative paths resolve against this file's
# directory; the default is ~/.gurgl/snapshots.
# store = "snapshots"

# Sandbox backend. The default is OS-aware: "bubblewrap" on Linux,
# "sandbox-exec" (Seatbelt) on macOS. Override here if you want "podman".
# sandbox = "bubblewrap"

# Proxy backend binary.
mitmdump = "mitmdump"

# Default flight plan (the scripted battery gurgl drives against each server).
flightplan = "flightplans/default.toml"

# Trials per capture. Repeated runs let gurgl separate stable egress from
# server-side cohort/feature-gate noise (the reproduction gate).
trials = 5

# --- the servers you want to watch ---------------------------------------

[[servers]]
name = "filesystem-mcp"
command = "npx"
args = ["-y", "@modelcontextprotocol/server-filesystem", "/tmp/gurgl-scratch"]
# first_party = ["example-vendor.com"]   # domains you expect it to talk to

# [[servers]]
# name = "some-other-mcp"
# command = "npx"
# args = ["-y", "some-other-mcp"]
"#;
