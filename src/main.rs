//! gurgl — local-first egress hygiene for MCP servers.
//!
//! Capture what an MCP server contacts on the network, diff it across versions,
//! and emit allowlists you can enforce elsewhere. gurgl reports what it
//! *observed*; it never certifies a tool as safe. See docs/THREAT-MODEL.md.

mod cli;
mod config;
mod diff;
mod emit;
mod flightplan;
mod mcp;
mod model;
mod observe;
mod proxy;
mod sandbox;
mod store;

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
        Commands::Watch { server, all } => cmd_watch(&cfg, &store, server.as_deref(), *all),
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
            "{} already exists — leaving it untouched.",
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
                "  (intermittent — likely cohort noise, not a finding)"
            };
            println!("    + {:<40} [{}]{}", delta.name, delta.class, flag);
        }
        let unknown = d.stable_unknown_added();
        if !unknown.is_empty() {
            println!(
                "\n  ⚠ {} new stable UNKNOWN host(s) — worth a look:",
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

fn cmd_watch(cfg: &Config, store: &Store, server: Option<&str>, all: bool) -> Result<()> {
    let targets: Vec<&config::ServerSpec> = if all {
        cfg.servers.iter().collect()
    } else if let Some(name) = server {
        match cfg.server(name) {
            Some(s) => vec![s],
            None => bail!("server '{name}' is not configured in gurgl.toml"),
        }
    } else {
        bail!("specify a server name or pass --all");
    };

    if targets.is_empty() {
        bail!("no servers configured in gurgl.toml (add a [[servers]] entry, then retry)");
    }

    let plan_path = cfg.flightplan_path();
    let plan = FlightPlan::load(&plan_path)
        .with_context(|| format!("loading flight plan {}", plan_path.display()))?;

    for spec in targets {
        eprintln!("capturing {} ({} trials)...", spec.name, cfg.trials);
        let snap = observe::capture(cfg, spec, &plan)?;
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
