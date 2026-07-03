//! Command-line surface.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "gurgl",
    version,
    about = "Local-first egress hygiene for MCP servers",
    long_about = "gurgl captures what MCP servers contact on the network, diffs it \
across versions, and emits allowlists. It is an egress inventory tool, not a \
verifier: it reports hosts it observed under a flight plan, never a clean bill \
of health. See docs/THREAT-MODEL.md."
)]
pub struct Cli {
    /// Path to gurgl.toml (default: ./gurgl.toml if present).
    #[arg(long, short = 'c', global = true)]
    pub config: Option<PathBuf>,

    /// Override the snapshot store directory.
    #[arg(long, global = true)]
    pub store: Option<PathBuf>,

    /// Plain output for `watch` (no live dashboard). Auto-on when stderr isn't a
    /// terminal, so pipes and scripts already get plain output.
    #[arg(long, global = true)]
    pub plain: bool,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Write a starter gurgl.toml and create the store directory.
    Init,

    /// List captured servers and their versions.
    List,

    /// Show the hosts observed for a server (default: latest version).
    Show {
        server: String,
        version: Option<String>,
    },

    /// Diff egress between two versions of a server (default: latest two).
    Diff {
        server: String,
        #[arg(long)]
        from: Option<String>,
        #[arg(long)]
        to: Option<String>,
    },

    /// Emit an allowlist from a snapshot for an enforcement engine.
    Allow {
        server: String,
        version: Option<String>,
        /// Output format: sandbox-runtime | opensnitch | squid.
        #[arg(long, default_value = "sandbox-runtime")]
        format: String,
    },

    /// Capture egress for a server (omit the name to capture all of them).
    Watch {
        /// Server name from gurgl.toml. Omit to capture every configured server.
        server: Option<String>,
        /// Capture every configured server (the default when no name is given).
        #[arg(long)]
        all: bool,
    },

    /// Find MCP servers configured on this machine (Claude, Cursor, Windsurf, ...).
    Discover {
        /// Append the discovered stdio servers to gurgl.toml so `watch` can run them.
        #[arg(long)]
        import: bool,
    },
}
