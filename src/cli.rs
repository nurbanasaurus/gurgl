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

    /// Machine-readable JSON on stdout for list/show/diff/discover. Each object
    /// carries a `schema` field; the human caveats travel as a `note` field.
    #[arg(long, global = true)]
    pub json: bool,

    /// Update gurgl from the public repo and reinstall (same as `gurgl update`).
    #[arg(short = 'u', long = "update", global = true)]
    pub update: bool,

    #[command(subcommand)]
    pub command: Option<Commands>,
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
        /// Compare from the accepted baseline (see `gurgl accept`) to the latest
        /// capture, instead of the latest two.
        #[arg(long, conflicts_with_all = ["from", "to"])]
        baseline: bool,
        /// Exit 1 when new stable hosts were observed (for CI/cron gates).
        /// `unknown` (default) triggers only on hosts needing scrutiny
        /// (unknown / telemetry?); `any` triggers on any new stable host.
        /// Exit codes: 0 = no drift at this threshold, 1 = drift, 2 = error.
        #[arg(long, value_name = "LEVEL", num_args = 0..=1,
              default_missing_value = "unknown", value_parser = ["unknown", "any"])]
        check: Option<String>,
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
        /// Watch for a fixed time, then stop and save (e.g. 30s, 5m, 1h). Runs
        /// one long observation instead of the repeated-trial battery.
        #[arg(long = "for", value_name = "DURATION", conflicts_with = "until_closed")]
        duration: Option<String>,
        /// Keep watching until you stop it with Ctrl-C, then save. One long
        /// observation.
        #[arg(long = "until-closed")]
        until_closed: bool,
        /// After each capture, diff it against the accepted baseline (or the
        /// previous version) and print a drift summary. Exit 1 if any server
        /// showed new stable hosts needing scrutiny - the one-shot cron audit.
        #[arg(long = "diff")]
        diff: bool,
    },

    /// Find MCP servers configured on this machine (Claude, Cursor, Windsurf, ...).
    Discover {
        /// Append the discovered stdio servers to gurgl.toml so `watch` can run them.
        #[arg(long)]
        import: bool,
    },

    /// Update gurgl from the public repo and reinstall. Runs only when you ask;
    /// gurgl never checks for or fetches updates on its own.
    Update,

    /// Walk through an annotated example diff using bundled snapshots. Needs no
    /// mitmproxy, sandbox, or Node - a 30-second tour of what gurgl shows you.
    Demo,

    /// Record that you reviewed a host, so diff reports it quietly instead of
    /// re-alerting. Acknowledged, not endorsed: gurgl never calls a host safe.
    Ack {
        server: String,
        /// The host name to acknowledge (omit with --list).
        host: Option<String>,
        /// Why you consider this host expected (stored with the ack).
        #[arg(long)]
        note: Option<String>,
        /// List this server's acknowledged hosts.
        #[arg(long, conflicts_with = "remove")]
        list: bool,
        /// Remove the acknowledgement for HOST instead of adding one.
        #[arg(long)]
        remove: bool,
    },

    /// Mark a reviewed capture as this server's baseline; `diff --baseline` and
    /// `watch --diff` then compare against it instead of the latest two.
    Accept {
        server: String,
        /// Version to accept (default: the latest capture).
        version: Option<String>,
        /// Clear the baseline pointer instead of setting one.
        #[arg(long)]
        clear: bool,
    },
}
