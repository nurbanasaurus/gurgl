//! gurgl - local-first egress hygiene for MCP servers.
//!
//! Capture what an MCP server contacts on the network, diff it across versions,
//! and emit allowlists you can enforce elsewhere. gurgl reports what it
//! *observed*; it never certifies a tool as safe. See docs/THREAT-MODEL.md.

mod cli;
mod config;
mod diff;
mod discover;
mod emit;
mod flightplan;
mod mcp;
mod model;
mod observe;
mod proxy;
mod report;
mod sandbox;
mod store;

use std::io::IsTerminal;
use std::path::PathBuf;
use std::str::FromStr;

use anyhow::{bail, Context, Result};
use clap::Parser;

use crate::cli::{Cli, Commands};
use crate::config::Config;
use crate::flightplan::FlightPlan;
use crate::model::Reproducibility;
use crate::store::Store;

fn main() -> Result<()> {
    let cli = Cli::parse();
    let cfg = load_config(&cli)?;
    let store = build_store(&cli, &cfg)?;

    match &cli.command {
        Commands::Init => cmd_init(&store),
        Commands::List => cmd_list(&store),
        Commands::Show { server, version } => cmd_show(&store, server, version.as_deref()),
        Commands::Diff { server, from, to } => {
            cmd_diff(&store, server, from.as_deref(), to.as_deref())
        }
        Commands::Allow {
            server,
            version,
            format,
        } => cmd_allow(&store, server, version.as_deref(), format),
        Commands::Watch { server, all } => {
            cmd_watch(&cfg, &store, server.as_deref(), *all, cli.plain)
        }
        Commands::Discover { import } => cmd_discover(*import),
    }
}

fn load_config(cli: &Cli) -> Result<Config> {
    // Precedence: explicit --config, then a project-local ./gurgl.toml, then the
    // home install at ~/.gurgl/gurgl.toml, then built-in defaults.
    let path = cli.config.clone().or_else(|| {
        let local = PathBuf::from("gurgl.toml");
        if local.is_file() {
            return Some(local);
        }
        let home = config::default_config_path();
        home.is_file().then_some(home)
    });
    match path {
        Some(p) => Config::load(&p),
        None => Ok(Config::default()),
    }
}

fn build_store(cli: &Cli, cfg: &Config) -> Result<Store> {
    let root = match &cli.store {
        Some(s) => s.clone(),
        None => cfg.store_dir()?,
    };
    Ok(Store::new(root))
}

fn cmd_init(store: &Store) -> Result<()> {
    // Lay down a self-contained ~/.gurgl: config, the default flight plan, and
    // the snapshot store. Everything gurgl needs lives under one directory.
    let home = config::gurgl_home();
    std::fs::create_dir_all(&home)
        .with_context(|| format!("creating gurgl home {}", home.display()))?;

    let cfg_path = config::default_config_path();
    if cfg_path.exists() {
        println!(
            "{} already exists - leaving it untouched.",
            cfg_path.display()
        );
    } else {
        std::fs::write(&cfg_path, Config::template())
            .with_context(|| format!("writing {}", cfg_path.display()))?;
        println!("wrote {}", cfg_path.display());
    }

    let fp_path = home.join("flightplans").join("default.toml");
    if !fp_path.exists() {
        std::fs::create_dir_all(fp_path.parent().unwrap())
            .with_context(|| format!("creating {}", fp_path.parent().unwrap().display()))?;
        std::fs::write(&fp_path, config::DEFAULT_FLIGHTPLAN)
            .with_context(|| format!("writing {}", fp_path.display()))?;
        println!("wrote {}", fp_path.display());
    }

    std::fs::create_dir_all(store.root())
        .with_context(|| format!("creating store {}", store.root().display()))?;
    println!("store ready at {}", store.root().display());
    println!(
        "\nnext: edit {} to list the MCP servers you run, then `gurgl watch --all`.",
        cfg_path.display()
    );
    Ok(())
}

fn cmd_list(store: &Store) -> Result<()> {
    let servers = store.servers()?;
    if servers.is_empty() {
        println!("no captures yet in {}", store.root().display());
        return Ok(());
    }
    for server in servers {
        let versions = store.versions(&server)?;
        println!("{server}");
        for v in versions {
            println!("  {v}");
        }
    }
    Ok(())
}

fn cmd_show(store: &Store, server: &str, version: Option<&str>) -> Result<()> {
    let version = resolve_version(store, server, version)?;
    let snap = store.load(server, &version)?;
    println!(
        "{}@{}  ({} trials, flight plan {})",
        snap.server, snap.version, snap.trials, snap.flightplan
    );
    println!("{:<40} {:<12} {:<12} SEEN", "HOST", "CLASS", "REPRO");
    for h in &snap.hosts {
        println!(
            "{:<40} {:<12} {:<12} {}/{}",
            h.name,
            h.class.to_string(),
            repro_str(h.reproducibility),
            h.seen_in_trials,
            snap.trials
        );
    }
    Ok(())
}

fn cmd_diff(store: &Store, server: &str, from: Option<&str>, to: Option<&str>) -> Result<()> {
    let (from_v, to_v) = match (from, to) {
        (Some(f), Some(t)) => (f.to_string(), t.to_string()),
        _ => match store.latest_two(server)? {
            Some(pair) => pair,
            None => bail!(
                "need at least two captured versions of '{server}' to diff (or pass --from/--to)"
            ),
        },
    };

    let from_snap = store.load(server, &from_v)?;
    let to_snap = store.load(server, &to_v)?;
    let d = diff::diff(&from_snap, &to_snap);

    println!("{}: {} -> {}", d.server, d.from_version, d.to_version);
    println!("  unchanged hosts: {}", d.unchanged);

    if d.added.is_empty() {
        println!("  no new hosts observed under this flight plan");
    } else {
        println!("  new hosts:");
        for delta in &d.added {
            let flag = if delta.reproducibility == Reproducibility::Stable {
                "" // stable: a real change
            } else {
                "  (intermittent - likely cohort noise, not a finding)"
            };
            println!("    + {:<40} [{}]{}", delta.name, delta.class, flag);
        }
        let unknown = d.stable_unknown_added();
        if !unknown.is_empty() {
            println!(
                "\n  ⚠ {} new stable UNKNOWN host(s) - worth a look:",
                unknown.len()
            );
            for u in unknown {
                println!("    {}", u.name);
            }
        }
    }

    if !d.removed.is_empty() {
        println!("  hosts no longer observed:");
        for delta in &d.removed {
            println!("    - {:<40} [{}]", delta.name, delta.class);
        }
    }

    println!(
        "\nnote: presence only. Absence of a host is non-coverage under this flight plan, not proof the tool won't contact it."
    );
    Ok(())
}

fn cmd_allow(store: &Store, server: &str, version: Option<&str>, format: &str) -> Result<()> {
    let version = resolve_version(store, server, version)?;
    let snap = store.load(server, &version)?;
    let fmt = emit::Format::from_str(format).map_err(|e| anyhow::anyhow!(e))?;
    print!("{}", emit::allowlist(&snap, fmt));
    Ok(())
}

fn cmd_watch(
    cfg: &Config,
    store: &Store,
    server: Option<&str>,
    _all: bool,
    plain: bool,
) -> Result<()> {
    // A named server watches just that one; bare `gurgl watch` (like `--all`)
    // watches every server configured in gurgl.toml.
    let targets: Vec<&config::ServerSpec> = match server {
        Some(name) => match cfg.server(name) {
            Some(s) => vec![s],
            None => bail!("server '{name}' is not configured in gurgl.toml"),
        },
        None => cfg.servers.iter().collect(),
    };

    if targets.is_empty() {
        bail!(
            "no MCP servers configured. Run `gurgl init` to create {}, then add \
             (or uncomment) a [[servers]] entry and retry.",
            config::default_config_path().display()
        );
    }

    let plan_path = cfg.flightplan_path();
    let plan = FlightPlan::load(&plan_path)
        .with_context(|| format!("loading flight plan {}", plan_path.display()))?;

    // Live dashboard when attached to a terminal; plain lines when piped or with
    // --plain, so logs and scripts are unaffected.
    let mode = if plain || !std::io::stderr().is_terminal() {
        report::Mode::Plain
    } else {
        report::Mode::Dashboard
    };

    for spec in targets {
        let snap = observe::capture(cfg, spec, &plan, mode)?;
        let path = store.save(&snap)?;
        println!(
            "saved {}@{} -> {}",
            snap.server,
            snap.version,
            path.display()
        );
    }
    Ok(())
}

fn cmd_discover(import: bool) -> Result<()> {
    let found = discover::discover();
    if found.is_empty() {
        println!(
            "no MCP servers found. gurgl looked in the standard client configs\n\
             (Claude Desktop, Claude Code's ~/.claude.json, Cursor, Windsurf, Cline).\n\
             If yours live elsewhere, add servers by hand to {}.",
            config::default_config_path().display()
        );
        return Ok(());
    }

    println!(
        "found {} MCP server(s) configured on this machine:\n",
        found.len()
    );
    println!("{:<22} {:<7} {:<34} SOURCE", "NAME", "KIND", "COMMAND");
    for d in &found {
        let kind = if d.is_stdio() { "stdio" } else { "remote" };
        let detail = if d.is_stdio() {
            let mut c = d.command.clone().unwrap_or_default();
            if !d.args.is_empty() {
                c.push(' ');
                c.push_str(&d.args.join(" "));
            }
            c
        } else {
            d.url.clone().unwrap_or_default()
        };
        let mark = if d.has_env { " [env]" } else { "" };
        println!(
            "{:<22} {:<7} {:<34} {}{}",
            truncate(&d.name, 22),
            kind,
            truncate(&detail, 34),
            d.source,
            mark
        );
    }

    let remote = found.iter().filter(|d| !d.is_stdio()).count();
    if remote > 0 {
        println!(
            "\nnote: {remote} remote (url) server(s) are listed for inventory but gurgl cannot\n\
             capture them: it watches local stdio subprocesses, not remote HTTP/SSE endpoints."
        );
    }
    if found.iter().any(|d| d.has_env) {
        println!(
            "note: [env] servers set environment variables (often API keys) in their client\n\
             config. gurgl does not copy those, so such a server may need them present in\n\
             gurgl's own environment to launch."
        );
    }

    let stdio: Vec<&discover::Discovered> = found.iter().filter(|d| d.is_stdio()).collect();
    if !import {
        println!(
            "\nto watch these, add the stdio ones to {} (or re-run with --import),\n\
             then `gurgl watch`.",
            config::default_config_path().display()
        );
        return Ok(());
    }
    if stdio.is_empty() {
        println!("\nnothing to import: no local stdio servers found.");
        return Ok(());
    }
    import_servers(&stdio)
}

/// Append discovered stdio servers to gurgl.toml, skipping any already present.
fn import_servers(stdio: &[&discover::Discovered]) -> Result<()> {
    let path = config::default_config_path();
    if !path.exists() {
        let home = config::gurgl_home();
        std::fs::create_dir_all(&home)
            .with_context(|| format!("creating gurgl home {}", home.display()))?;
        std::fs::write(&path, Config::template())
            .with_context(|| format!("writing {}", path.display()))?;
        println!("\ncreated {}", path.display());
    }

    let mut names: std::collections::HashSet<String> = Config::load(&path)
        .map(|c| c.servers.into_iter().map(|s| s.name).collect())
        .unwrap_or_default();

    let mut text =
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    let mut added = 0;
    for d in stdio {
        if !names.insert(d.name.clone()) {
            continue; // already configured, or a duplicate across client configs
        }
        if !text.ends_with('\n') {
            text.push('\n');
        }
        text.push_str(&discover::to_toml_block(d));
        added += 1;
    }

    if added == 0 {
        println!(
            "\nall discovered stdio servers are already in {}.",
            path.display()
        );
        return Ok(());
    }
    std::fs::write(&path, &text).with_context(|| format!("writing {}", path.display()))?;
    println!("\nimported {added} server(s) into {}.", path.display());
    println!("run `gurgl watch` to capture them all, or `gurgl watch <name>` for one.");
    Ok(())
}

/// Truncate to `max` display chars with a trailing ellipsis, char-boundary safe.
fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let keep = max.saturating_sub(3);
    let head: String = s.chars().take(keep).collect();
    format!("{head}...")
}

fn resolve_version(store: &Store, server: &str, version: Option<&str>) -> Result<String> {
    match version {
        Some(v) => Ok(v.to_string()),
        None => store
            .latest(server)?
            .with_context(|| format!("no captures for '{server}'")),
    }
}

fn repro_str(r: Reproducibility) -> &'static str {
    match r {
        Reproducibility::Stable => "stable",
        Reproducibility::Intermittent => "intermittent",
    }
}
