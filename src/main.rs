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

/// Exit-code contract (grep convention, so scripts can gate on drift):
///   0 = success / no drift at the requested threshold
///   1 = drift detected (`diff --check`, `watch --diff`)
///   2 = error
fn main() {
    match run() {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("Error: {e:#}");
            std::process::exit(2);
        }
    }
}

fn run() -> Result<i32> {
    let cli = Cli::parse();

    // `-u`/`--update` and `gurgl update` are the same explicit, user-invoked
    // update. Handle it before touching config/store (neither is needed) and
    // before anything else, so it works from a bare `gurgl -u`.
    if cli.update || matches!(cli.command, Some(Commands::Update)) {
        return cmd_update().map(|_| 0);
    }

    let cfg = load_config(&cli)?;
    let store = build_store(&cli, &cfg)?;

    match &cli.command {
        // Bare `gurgl`: a git-status-style orientation beats generic help. It
        // shows where this machine stands and the one next command that helps.
        None => cmd_orient(&cfg, &store).map(|_| 0),
        Some(Commands::Update) => unreachable!("handled above"),
        Some(Commands::Init) => cmd_init(&store).map(|_| 0),
        Some(Commands::List) => cmd_list(&store, cli.json).map(|_| 0),
        Some(Commands::Show { server, version }) => {
            cmd_show(&store, server, version.as_deref(), cli.json).map(|_| 0)
        }
        Some(Commands::Diff {
            server,
            from,
            to,
            baseline,
            check,
        }) => cmd_diff(
            &store,
            server,
            from.as_deref(),
            to.as_deref(),
            *baseline,
            check.as_deref(),
            cli.json,
        ),
        Some(Commands::Allow {
            server,
            version,
            format,
        }) => cmd_allow(&store, server, version.as_deref(), format).map(|_| 0),
        Some(Commands::Watch {
            server,
            all,
            duration,
            until_closed,
            diff,
        }) => cmd_watch(
            &cfg,
            &store,
            server.as_deref(),
            *all,
            cli.plain,
            duration.as_deref(),
            *until_closed,
            *diff,
        ),
        Some(Commands::Discover { import }) => cmd_discover(*import, cli.json).map(|_| 0),
        Some(Commands::Demo) => cmd_demo().map(|_| 0),
        Some(Commands::Ack {
            server,
            host,
            note,
            list,
            remove,
        }) => cmd_ack(
            &store,
            server,
            host.as_deref(),
            note.as_deref(),
            *list,
            *remove,
        )
        .map(|_| 0),
        Some(Commands::Accept {
            server,
            version,
            clear,
        }) => cmd_accept(&store, server, version.as_deref(), *clear).map(|_| 0),
    }
}

/// The bundled example snapshots, embedded so `gurgl demo` works from any
/// install with zero dependencies (no repo checkout, no capture backend).
const DEMO_FROM: &str = include_str!("../examples/snapshots/example-mcp/1.2.0.json");
const DEMO_TO: &str = include_str!("../examples/snapshots/example-mcp/1.3.0.json");

/// Bare `gurgl`: where this machine stands and the single next command that
/// makes progress. States it never asserts: nothing here is a safety judgment.
fn cmd_orient(cfg: &Config, store: &Store) -> Result<()> {
    println!("gurgl - local-first egress hygiene for MCP servers\n");

    // Config: same discovery order load_config used.
    let local = PathBuf::from("gurgl.toml");
    let home_cfg = config::default_config_path();
    let cfg_path = if local.is_file() {
        Some(local)
    } else if home_cfg.is_file() {
        Some(home_cfg)
    } else {
        None
    };
    match &cfg_path {
        Some(p) => println!("  config     {}", p.display()),
        None => println!("  config     none yet"),
    }

    // Servers configured vs discoverable on this machine.
    let names: Vec<&str> = cfg.servers.iter().map(|s| s.name.as_str()).collect();
    if names.is_empty() {
        println!("  servers    none configured");
    } else {
        println!(
            "  servers    {} configured: {}",
            names.len(),
            names.join(", ")
        );
    }
    let unimported = discover::discover()
        .into_iter()
        .filter(|d| d.is_stdio() && cfg.server(&d.name).is_none() && !references_client_runtime(d))
        .count();
    if unimported > 0 {
        println!("             {unimported} more MCP server(s) found on this machine (not yet in gurgl.toml)");
    }

    // Captures: per configured server, history depth and staleness.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut uncaptured: Vec<&str> = Vec::new();
    let mut diffable: Vec<&str> = Vec::new();
    for spec in &cfg.servers {
        let versions = store.versions(&spec.name)?;
        match versions.last() {
            None => {
                println!("  {:<10} no captures yet", spec.name);
                uncaptured.push(&spec.name);
            }
            Some(latest) => {
                let age = store
                    .load(&spec.name, latest)
                    .map(|s| now.saturating_sub(s.captured_at) / 86_400)
                    .unwrap_or(0);
                let when = match age {
                    0 => "today".to_string(),
                    1 => "1 day ago".to_string(),
                    n => format!("{n} days ago"),
                };
                let extra = if versions.len() >= 2 {
                    diffable.push(&spec.name);
                    format!("{} versions (diffable)", versions.len())
                } else {
                    "1 version".to_string()
                };
                println!("  {:<10} latest @{latest}, {when}, {extra}", spec.name);
            }
        }
    }

    // One suggested next command, by state.
    let next = if cfg_path.is_none() {
        "gurgl init                # create ~/.gurgl (config, flight plan, store)".to_string()
    } else if names.is_empty() && unimported > 0 {
        "gurgl discover --import   # add the MCP servers found on this machine".to_string()
    } else if names.is_empty() {
        format!(
            "edit {} to add a [[servers]] entry, then `gurgl watch --all`",
            config::default_config_path().display()
        )
    } else if !uncaptured.is_empty() {
        "gurgl watch --all         # capture a baseline for every server".to_string()
    } else if let Some(name) = diffable.first() {
        format!("gurgl diff {name}         # compare the two most recent captures")
    } else {
        "after your next update: gurgl watch --all && gurgl diff <server>".to_string()
    };
    println!("\n  next:  {next}");
    println!("\n  new to gurgl? `gurgl demo` is a 30-second tour. `gurgl --help` lists commands.");
    Ok(())
}

fn cmd_demo() -> Result<()> {
    let from: model::Snapshot = serde_json::from_str(DEMO_FROM).context("parsing demo snapshot")?;
    let to: model::Snapshot = serde_json::from_str(DEMO_TO).context("parsing demo snapshot")?;

    println!(
        "This is a tour on bundled data - nothing is captured or executed.\n\
         \n\
         Suppose you ran `gurgl watch example-mcp` twice: once on v{}, and again\n\
         after updating to v{}. Each watch runs the server {} times through the\n\
         same scripted session and records every host it contacts:\n",
        from.version, to.version, from.trials
    );

    println!("  example-mcp@{}  (the old baseline)", from.version);
    for h in &from.hosts {
        println!("    {:<34} [{}]", h.name, h.class);
    }
    println!(
        "\n  Two hosts, both explainable: the npm registry (it launches via npx)\n\
         and the vendor's own API. That is the baseline you reviewed.\n"
    );

    let d = diff::diff(&from, &to);
    println!("Now the update lands. `gurgl diff example-mcp` compares the two:\n");
    println!(
        "  example-mcp: {} -> {}   unchanged hosts: {}",
        d.from_version, d.to_version, d.unchanged
    );
    for delta in &d.added {
        println!("    + {:<34} [{}]", delta.name, delta.class);
    }

    println!(
        "\nHow to read those three new hosts - they are NOT equal:\n\
         \n\
         + o1234.ingest.sentry.io [telemetry]\n\
           Matched a known vendor (Sentry crash reporting). Common in npm\n\
           packages; now you know this update added it and can decide if you\n\
           accept it. (A host merely NAMED telemetry.* with no vendor match\n\
           would show as [telemetry?] and deserve the same scrutiny as unknown.)\n\
         \n\
         + beacon.unknown-cdn.example [unknown], seen in 5/5 trials\n\
           THE signal. Stable (every single run) and matching no known rule:\n\
           this update reliably contacts somewhere new that nobody can explain\n\
           yet. This is what gurgl exists to surface - the postmark-mcp pattern.\n\
         \n\
         + edge-42.rollout-cohort.example [unknown], seen in 2/5 trials\n\
           Deliberately NOT flagged. It did not reproduce across trials, which\n\
           usually means server-side A/B or feature-gate noise, not a change in\n\
           the tool. Reporting it as a finding would be an accusation the data\n\
           cannot support - that restraint is the reproduction gate.\n\
         \n\
         Note what gurgl does NOT say: it never says \"safe\" or \"malicious\".\n\
         It shows you what was observed under a fixed session, so the judgment\n\
         (and the allowlist you enforce) is yours, based on evidence.\n\
         \n\
         On your real machine, the same loop is:\n\
           gurgl discover --import   # find the MCP servers you already have\n\
           gurgl watch --all         # capture a baseline for each\n\
           ... update something ...\n\
           gurgl watch --all && gurgl diff <server>"
    );
    Ok(())
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

fn cmd_list(store: &Store, json: bool) -> Result<()> {
    let servers = store.servers()?;
    if json {
        let mut entries = Vec::new();
        for server in &servers {
            entries.push(serde_json::json!({
                "name": server,
                "versions": store.versions(server)?,
                "baseline": store.baseline(server),
            }));
        }
        let out = serde_json::json!({ "schema": "gurgl.list/1", "servers": entries });
        println!("{}", serde_json::to_string_pretty(&out)?);
        return Ok(());
    }
    if servers.is_empty() {
        println!("no captures yet in {}", store.root().display());
        return Ok(());
    }
    for server in servers {
        let versions = store.versions(&server)?;
        let baseline = store.baseline(&server);
        println!("{server}");
        for v in versions {
            let mark = if baseline.as_deref() == Some(v.as_str()) {
                "  (baseline)"
            } else {
                ""
            };
            println!("  {v}{mark}");
        }
    }
    Ok(())
}

fn cmd_show(store: &Store, server: &str, version: Option<&str>, json: bool) -> Result<()> {
    let version = resolve_version(store, server, version)?;
    let snap = store.load(server, &version)?;
    if json {
        let out = serde_json::json!({
            "schema": "gurgl.show/1",
            "snapshot": snap,
            "note": "presence only: hosts observed under this flight plan. Absence is non-coverage, not proof.",
        });
        println!("{}", serde_json::to_string_pretty(&out)?);
        return Ok(());
    }
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

    // A snapshot should explain itself: legend for the classes actually present,
    // what stable/intermittent mean, the coverage caveat, and what to do next.
    let classes: std::collections::BTreeSet<_> =
        snap.hosts.iter().map(|h| h.class.to_string()).collect();
    if !snap.hosts.is_empty() {
        println!();
        for c in &classes {
            println!("  {:<12} {}", c, class_legend(c));
        }
        println!(
            "  {:<12} SEEN n/{}: appeared in n of the {} trials. stable = every trial; \
             intermittent = some\n  {:<12} trials only (usually server-side cohort noise, \
             not a change in the tool).",
            "repro", snap.trials, snap.trials, ""
        );
    }
    println!(
        "\nnote: presence only - hosts observed under this flight plan. Absence of a host \
         is non-coverage,\nnot proof the tool won't contact it."
    );
    let scrutiny = snap
        .hosts
        .iter()
        .filter(|h| h.class.needs_scrutiny() && h.reproducibility == model::Reproducibility::Stable)
        .count();
    if scrutiny > 0 {
        println!(
            "\n{scrutiny} stable host(s) matched no known rule - worth a look. Next: search \
             the package source for\nthe hostname; if it is expected, add it to \
             `first_party` in gurgl.toml so it classifies as yours."
        );
    } else if store.versions(server)?.len() < 2 {
        println!(
            "\nnext: after this server updates, run `gurgl watch {server}` again, then \
             `gurgl diff {server}` -\nnew hosts appearing on an update are the signal."
        );
    }
    Ok(())
}

/// One plain-language line per host class, for the `show` legend.
fn class_legend(class: &str) -> &'static str {
    match class {
        "first-party" => "domains you declared for this server in gurgl.toml",
        "telemetry" => "a known analytics/crash-reporting vendor",
        "telemetry?" => {
            "NAMES itself telemetry but matches no known vendor - scrutinize like unknown"
        }
        "registry" => "package registry / code host (expected for npx- or uvx-launched servers)",
        "unknown" => "matched no rule - the class to scrutinize when stable",
        _ => "",
    }
}

/// The drift decision for `--check` and `watch --diff`, kept pure and testable:
/// which new stable hosts trip the gate at each level, after acks are honored.
fn drift_hosts<'a>(d: &'a diff::SnapshotDiff, level: &str, acked: &[String]) -> Vec<&'a str> {
    d.stable_added()
        .into_iter()
        .filter(|h| level == "any" || h.class.needs_scrutiny())
        .filter(|h| !acked.iter().any(|a| a == &h.name))
        .map(|h| h.name.as_str())
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn cmd_diff(
    store: &Store,
    server: &str,
    from: Option<&str>,
    to: Option<&str>,
    baseline: bool,
    check: Option<&str>,
    json: bool,
) -> Result<i32> {
    let (from_v, to_v) = if baseline {
        // Compare what a human reviewed (gurgl accept) against the latest.
        let base = store.baseline(server).with_context(|| {
            format!("no baseline accepted for '{server}' - run `gurgl accept {server}` first")
        })?;
        let latest = store
            .latest(server)?
            .with_context(|| format!("no captures for '{server}'"))?;
        (base, latest)
    } else {
        match (from, to) {
            (Some(f), Some(t)) => (f.to_string(), t.to_string()),
            _ => match store.latest_two(server)? {
                Some(pair) => pair,
                None => bail!(
                    "need at least two captured versions of '{server}' to diff (or pass --from/--to)"
                ),
            },
        }
    };

    let from_snap = store.load(server, &from_v)?;
    let to_snap = store.load(server, &to_v)?;
    let d = diff::diff(&from_snap, &to_snap);
    let acks = store.acks(server)?;
    let acked_names: Vec<String> = acks.iter().map(|a| a.host.clone()).collect();

    // Scrutiny-worthy additions, split by whether the user already reviewed them.
    let scrutiny = d.stable_unknown_added();
    let (acked_new, unacked): (Vec<&diff::HostDelta>, Vec<&diff::HostDelta>) = scrutiny
        .into_iter()
        .partition(|h| acked_names.iter().any(|a| a == &h.name));

    if json {
        // Stable, versioned schema; the epistemic caveat travels in `note`.
        let out = serde_json::json!({
            "schema": "gurgl.diff/1",
            "server": d.server,
            "from_version": d.from_version,
            "to_version": d.to_version,
            "baseline_used": baseline,
            "unchanged": d.unchanged,
            "added": d.added,
            "removed": d.removed,
            "stable_added": d.stable_added().iter().map(|h| &h.name).collect::<Vec<_>>(),
            "needs_scrutiny": unacked.iter().map(|h| &h.name).collect::<Vec<_>>(),
            "acknowledged_present": acked_new.iter().map(|h| &h.name).collect::<Vec<_>>(),
            "from_flightplan": from_snap.flightplan,
            "to_flightplan": to_snap.flightplan,
            "to_trials": to_snap.trials,
            "note": "presence only: hosts observed under this flight plan. Absence is non-coverage, not proof.",
        });
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else {
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
            if !unacked.is_empty() {
                println!(
                    "\n  ⚠ {} new stable host(s) matched no known rule - review before trusting this update:",
                    unacked.len()
                );
                for u in &unacked {
                    println!("    {}  [{}]", u.name, u.class);
                }
                // Tell the user what to actually DO, not just that it happened.
                println!(
                    "\n  next steps:\n    \
                     1. confirm:  gurgl watch {}   (does it reproduce in a fresh capture?)\n    \
                     2. inspect:  search the package source for the hostname (e.g. grep it in\n                 \
                     the npm tarball or repo) to see what contacts it and why\n    \
                     3. decide:   expected -> `gurgl ack {} <host> --note \"...\"` or add it to\n                 \
                     `first_party`; not expected -> stay on {} and investigate",
                    d.server, d.server, d.from_version
                );
            }
            if !acked_new.is_empty() {
                // Quiet by design: the user reviewed these (an ack is a recorded
                // decision, not an endorsement).
                println!(
                    "\n  {} new host(s) you previously acknowledged (gurgl ack {} --list): {}",
                    acked_new.len(),
                    d.server,
                    acked_new
                        .iter()
                        .map(|h| h.name.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                );
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
    }

    // --check: exit 1 on drift at the requested threshold (acks honored).
    if let Some(level) = check {
        if !drift_hosts(&d, level, &acked_names).is_empty() {
            return Ok(1);
        }
    }
    Ok(0)
}

fn cmd_allow(store: &Store, server: &str, version: Option<&str>, format: &str) -> Result<()> {
    let version = resolve_version(store, server, version)?;
    let snap = store.load(server, &version)?;
    let fmt = emit::Format::from_str(format).map_err(|e| anyhow::anyhow!(e))?;
    print!("{}", emit::allowlist(&snap, fmt));
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn cmd_watch(
    cfg: &Config,
    store: &Store,
    server: Option<&str>,
    _all: bool,
    plain: bool,
    duration: Option<&str>,
    until_closed: bool,
    audit: bool,
) -> Result<i32> {
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

    // How long to watch: the repeated-trial battery (default), a fixed hold, or
    // until Ctrl-C.
    let monitor = if until_closed {
        observe::Monitor::Hold(None)
    } else if let Some(s) = duration {
        observe::Monitor::Hold(Some(parse_hold(s)?))
    } else {
        observe::Monitor::Battery
    };
    // Make Ctrl-C (and the dashboard's `q`) a clean stop that still saves what
    // completed, in every watch mode. A second Ctrl-C force-quits.
    observe::arm_interrupt();

    // Live dashboard when attached to a terminal; plain lines when piped or with
    // --plain, so logs and scripts are unaffected.
    let mode = if plain || !std::io::stderr().is_terminal() {
        report::Mode::Plain
    } else {
        report::Mode::Dashboard
    };

    // Capture each target independently: one un-runnable server (missing runtime,
    // a plugin that needs its client's env) must not abort the whole batch. The
    // flight plan is per-server: a server's own `flightplan` wins over the default.
    let multi = targets.len() > 1;
    let mut captured = 0usize;
    let mut skipped: Vec<String> = Vec::new();
    // --diff: per-server drift lines, printed after the batch summary.
    let mut drift_lines: Vec<String> = Vec::new();
    let mut drifted = false;
    for spec in targets {
        if observe::stop_requested() {
            println!("stopped by user; skipping remaining servers");
            break;
        }
        let plan_path = cfg.flightplan_path_for(spec);
        // For --diff: what we will compare the fresh capture against - the
        // accepted baseline if set, else whatever is latest BEFORE this save.
        let compare_to = if audit {
            store
                .baseline(&spec.name)
                .or(store.latest(&spec.name).unwrap_or(None))
        } else {
            None
        };
        match FlightPlan::load(&plan_path)
            .with_context(|| format!("loading flight plan {}", plan_path.display()))
            .and_then(|plan| observe::capture(cfg, spec, &plan, mode, monitor))
            .and_then(|snap| {
                let overwrote = store.exists(&snap.server, &snap.version);
                let path = store.save(&snap)?;
                Ok((path, snap, overwrote))
            }) {
            Ok((path, snap, overwrote)) => {
                println!(
                    "saved {}@{} -> {}",
                    snap.server,
                    snap.version,
                    path.display()
                );
                // Same-version captures overwrite. That is fine for refreshing a
                // baseline, but silent destruction of history breaks `diff`,
                // especially for servers stuck on the "unknown" label.
                if overwrote {
                    println!(
                        "note: this replaced the previous capture of {}@{} (same version \
                         label), so there is nothing new for `gurgl diff` to compare.",
                        snap.server, snap.version
                    );
                    if snap.version == "unknown" {
                        println!(
                            "      this server reports no version; pin one in gurgl.toml \
                             (version = \"...\") so each capture keeps its own history."
                        );
                    }
                }
                captured += 1;

                // The audit line for this server, against baseline/previous.
                if audit {
                    match compare_to {
                        Some(prev) if prev != snap.version => {
                            let prev_snap = store.load(&snap.server, &prev)?;
                            let d = diff::diff(&prev_snap, &snap);
                            let acked: Vec<String> = store
                                .acks(&snap.server)?
                                .into_iter()
                                .map(|a| a.host)
                                .collect();
                            let scrutiny = drift_hosts(&d, "unknown", &acked);
                            let stable_new = d.stable_added().len();
                            if scrutiny.is_empty() {
                                drift_lines.push(format!(
                                    "  {:<16} {} -> {}: {} new stable host(s), none needing scrutiny",
                                    snap.server, prev, snap.version, stable_new
                                ));
                            } else {
                                drifted = true;
                                drift_lines.push(format!(
                                    "  {:<16} {} -> {}: {} new stable host(s) NEED SCRUTINY: {} \
                                     (gurgl diff {})",
                                    snap.server,
                                    prev,
                                    snap.version,
                                    scrutiny.len(),
                                    scrutiny.join(", "),
                                    snap.server
                                ));
                            }
                        }
                        Some(_) => drift_lines.push(format!(
                            "  {:<16} same version label - nothing to compare",
                            snap.server
                        )),
                        None => drift_lines.push(format!(
                            "  {:<16} first capture - baseline recorded, nothing to compare yet",
                            snap.server
                        )),
                    }
                }
            }
            Err(e) => {
                // A deliberate stop is not a per-server failure; the loop's next
                // iteration (or the captured==0 path) reports it neutrally.
                if observe::stop_requested() {
                    continue;
                }
                eprintln!("skipped {}: {:#}", spec.name, e);
                skipped.push(spec.name.clone());
            }
        }
    }

    if multi {
        print!("\n{captured} captured");
        if !skipped.is_empty() {
            print!(", {} skipped: {}", skipped.len(), skipped.join(", "));
        }
        println!();
    }
    if captured == 0 {
        // A deliberate quit before anything completed is not an error.
        if observe::stop_requested() {
            println!("stopped by user; nothing captured");
            return Ok(0);
        }
        bail!("no servers were captured (see the messages above)");
    }

    if audit && !drift_lines.is_empty() {
        println!("\ndrift (vs accepted baseline, else previous version; acks honored):");
        for line in &drift_lines {
            println!("{line}");
        }
        if drifted {
            println!(
                "\nnew stable hosts needing scrutiny were observed - exit 1. Review with \
                 `gurgl diff <server>`."
            );
            return Ok(1);
        }
        println!("\nno drift needing scrutiny - exit 0.");
    }
    Ok(0)
}

/// Record, list, or remove host acknowledgements. Wording is deliberate
/// throughout: an ack is "you reviewed this and said why", never approval.
fn cmd_ack(
    store: &Store,
    server: &str,
    host: Option<&str>,
    note: Option<&str>,
    list: bool,
    remove: bool,
) -> Result<()> {
    if list {
        let acks = store.acks(server)?;
        if acks.is_empty() {
            println!("no acknowledged hosts for {server}.");
            return Ok(());
        }
        println!("acknowledged hosts for {server} (reviewed, not endorsed):");
        for a in acks {
            let at = a
                .reviewed_at_version
                .map(|v| format!(" @{v}"))
                .unwrap_or_default();
            let note = a.note.map(|n| format!("  - {n}")).unwrap_or_default();
            println!("  {:<40} {}{}{}", a.host, a.date, at, note);
        }
        return Ok(());
    }

    let host = host.context("specify a host to ack (or use --list)")?;
    if remove {
        if store.remove_ack(server, host)? {
            println!("removed the acknowledgement for {host}; diff will alert on it again.");
        } else {
            println!("no acknowledgement recorded for {host}.");
        }
        return Ok(());
    }

    let ack = store::Ack {
        host: host.to_string(),
        note: note.map(String::from),
        date: today(),
        reviewed_at_version: store.latest(server)?,
    };
    let replaced = store.add_ack(server, ack)?;
    println!(
        "{} {host} for {server}. diff now reports it quietly instead of alerting;\n\
         undo with `gurgl ack {server} {host} --remove`. An ack records your review -\n\
         gurgl still cannot see what is SENT to this host (payloads are out of scope).",
        if replaced {
            "updated the acknowledgement of"
        } else {
            "acknowledged"
        }
    );
    Ok(())
}

/// Set or clear the reviewed-baseline pointer used by `diff --baseline` and
/// `watch --diff`.
fn cmd_accept(store: &Store, server: &str, version: Option<&str>, clear: bool) -> Result<()> {
    if clear {
        store.set_baseline(server, None)?;
        println!("cleared the baseline for {server}; diff defaults to the latest two versions.");
        return Ok(());
    }
    let version = match version {
        Some(v) => {
            if !store.exists(server, v) {
                bail!("no capture stored for {server}@{v} (see `gurgl list`)");
            }
            v.to_string()
        }
        None => store
            .latest(server)?
            .with_context(|| format!("no captures for '{server}' - run `gurgl watch {server}`"))?,
    };
    store.set_baseline(server, Some(&version))?;
    println!(
        "accepted {server}@{version} as the reviewed baseline. `gurgl diff {server} --baseline`\n\
         and `gurgl watch --diff` now compare against it. This records that you reviewed this\n\
         capture - it is not a statement that the server is safe."
    );
    Ok(())
}

/// Today as YYYY-MM-DD (UTC), from the system clock - no date dependency.
/// Civil-from-days algorithm (Howard Hinnant's); valid for the unix era.
fn today() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
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

/// Parse a `--for` duration like `30s`, `5m`, `1h` (a bare number is seconds).
fn parse_hold(s: &str) -> Result<std::time::Duration> {
    let s = s.trim();
    let (num, mult) = if let Some(v) = s.strip_suffix('s') {
        (v, 1)
    } else if let Some(v) = s.strip_suffix('m') {
        (v, 60)
    } else if let Some(v) = s.strip_suffix('h') {
        (v, 3600)
    } else {
        (s, 1)
    };
    let n: u64 = num
        .trim()
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid --for duration '{s}': use e.g. 30s, 5m, 1h"))?;
    if n == 0 {
        bail!("--for duration must be greater than zero");
    }
    Ok(std::time::Duration::from_secs(n * mult))
}

fn cmd_discover(import: bool, json: bool) -> Result<()> {
    let found = discover::discover();
    if json {
        // Inventory as data; --import still requires the human-readable mode.
        let out = serde_json::json!({ "schema": "gurgl.discover/1", "servers": found });
        println!("{}", serde_json::to_string_pretty(&out)?);
        if import {
            bail!("--import is interactive-output only; run it without --json");
        }
        return Ok(());
    }
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
    println!(
        "{:<20} {:<10} {:<6} {:<30} SOURCE",
        "NAME", "STATUS", "KIND", "COMMAND"
    );
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
            "{:<20} {:<10} {:<6} {:<30} {}{}",
            truncate(&d.name, 20),
            d.status,
            kind,
            truncate(&detail, 30),
            d.source,
            mark
        );
    }

    let enabled = found
        .iter()
        .filter(|d| d.status == discover::Status::Enabled)
        .count();
    let bundled = found
        .iter()
        .filter(|d| d.status == discover::Status::Bundled)
        .count();
    println!(
        "\nstatus: {enabled} enabled, {bundled} bundled (plugin, not enabled), {} configured (present, \
         not confirmed on).",
        found.len() - enabled - bundled
    );
    println!(
        "note: 'enabled' is read from each client's own config; 'bundled' plugins ship with a\n\
         marketplace but are not turned on; 'configured' means present but gurgl found no enable\n\
         record for it."
    );

    let remote = found.iter().filter(|d| !d.is_stdio()).count();
    if remote > 0 {
        println!(
            "note: {remote} remote (url) server(s) are listed for inventory but gurgl cannot\n\
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

    if !import {
        println!(
            "\nto watch these, add the stdio ones to {} (or re-run with --import),\n\
             then `gurgl watch`.",
            config::default_config_path().display()
        );
        return Ok(());
    }

    // Only import servers gurgl can actually launch. Skip those that reference a
    // client runtime variable (e.g. ${CLAUDE_PLUGIN_ROOT}): only their client
    // expands it, so gurgl - which runs the command directly - cannot start them.
    let (runnable, client_only): (Vec<&discover::Discovered>, Vec<&discover::Discovered>) = found
        .iter()
        .filter(|d| d.is_stdio())
        .partition(|d| !references_client_runtime(d));

    if !client_only.is_empty() {
        println!(
            "\nnot importing {} server(s) that only run inside their client (they reference a\n\
             runtime variable like ${{CLAUDE_PLUGIN_ROOT}} gurgl cannot expand): {}",
            client_only.len(),
            client_only
                .iter()
                .map(|d| d.name.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    if runnable.is_empty() {
        println!("\nnothing to import: no directly-runnable stdio servers found.");
        return Ok(());
    }
    import_servers(&runnable)
}

/// Whether a server's launch references a client-provided runtime variable (e.g.
/// `${CLAUDE_PLUGIN_ROOT}`) that only its client expands - gurgl cannot run it.
fn references_client_runtime(d: &discover::Discovered) -> bool {
    let has_var = |s: &str| s.contains("${");
    d.command.as_deref().map(has_var).unwrap_or(false) || d.args.iter().any(|a| has_var(a))
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

/// Update gurgl from the public repository and reinstall. This runs ONLY when
/// the user invokes it (`gurgl update` / `gurgl -u`); gurgl never checks for,
/// pings about, or downloads updates on its own (constraint #5: no phone-home,
/// no auto-update). The only network access is the explicit git fetch below.
///
/// It keeps a managed checkout at `~/.gurgl/src` and reinstalls from it, so it
/// works the same whether gurgl was git-cloned or rsync-deployed (a machine set
/// up via `make deploy` has no .git of its own to pull).
fn cmd_update() -> Result<()> {
    use std::process::Command;
    const REPO: &str = "https://github.com/nurbanasaurus/gurgl.git";

    let home = config::gurgl_home();
    let src = home.join("src");

    if src.join(".git").is_dir() {
        println!(">> updating gurgl source in {} ...", src.display());
        run_cmd(
            Command::new("git")
                .arg("-C")
                .arg(&src)
                .args(["pull", "--ff-only"]),
        )?;
    } else {
        std::fs::create_dir_all(&home).with_context(|| format!("creating {}", home.display()))?;
        if src.exists() {
            std::fs::remove_dir_all(&src).with_context(|| format!("clearing {}", src.display()))?;
        }
        println!(">> fetching gurgl from {REPO} ...");
        run_cmd(Command::new("git").arg("clone").arg(REPO).arg(&src))?;
    }

    println!(">> building + installing the update ...");
    run_cmd(
        Command::new("bash")
            .arg(src.join("install.sh"))
            .arg("--no-modify-path")
            .current_dir(&src),
    )?;

    println!("\ngurgl is up to date. Check `gurgl --version`.");
    Ok(())
}

/// Run a subprocess inheriting stdio, with clear errors when the tool is missing
/// or the command fails.
fn run_cmd(cmd: &mut std::process::Command) -> Result<()> {
    let program = cmd.get_program().to_string_lossy().to_string();
    let status = cmd.status().map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            anyhow::anyhow!("`{program}` is required but was not found on PATH")
        } else {
            anyhow::Error::from(e).context(format!("running `{program}`"))
        }
    })?;
    if !status.success() {
        bail!(
            "`{program}` failed with exit {}",
            status.code().unwrap_or(-1)
        );
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Host, HostClass, Snapshot};

    fn snap(version: &str, hosts: Vec<Host>) -> Snapshot {
        Snapshot {
            server: "s".into(),
            version: version.into(),
            captured_at: 0,
            trials: 5,
            flightplan: "fp".into(),
            gurgl_version: "0".into(),
            hosts,
        }
    }

    fn host(name: &str, class: HostClass, repro: Reproducibility) -> Host {
        Host {
            name: name.into(),
            class,
            reproducibility: repro,
            seen_in_trials: if repro == Reproducibility::Stable {
                5
            } else {
                2
            },
            phases: vec![],
        }
    }

    #[test]
    fn drift_gate_levels_and_acks() {
        let from = snap("1.0", vec![]);
        let to = snap(
            "1.1",
            vec![
                host(
                    "api.vendor.example",
                    HostClass::FirstParty,
                    Reproducibility::Stable,
                ),
                host(
                    "beacon.evil.example",
                    HostClass::Unknown,
                    Reproducibility::Stable,
                ),
                host(
                    "telemetry.odd.example",
                    HostClass::TelemetryNamed,
                    Reproducibility::Stable,
                ),
                host(
                    "flaky.example",
                    HostClass::Unknown,
                    Reproducibility::Intermittent,
                ),
            ],
        );
        let d = diff::diff(&from, &to);

        // Default level: only stable scrutiny classes trip the gate; the
        // intermittent unknown never does (the reproduction gate holds).
        let hits = drift_hosts(&d, "unknown", &[]);
        assert_eq!(hits, vec!["beacon.evil.example", "telemetry.odd.example"]);

        // `any`: every stable addition trips it, including first-party.
        assert_eq!(drift_hosts(&d, "any", &[]).len(), 3);

        // Acks silence exactly the reviewed host, at both levels.
        let acked = vec!["beacon.evil.example".to_string()];
        assert_eq!(
            drift_hosts(&d, "unknown", &acked),
            vec!["telemetry.odd.example"]
        );
        assert_eq!(drift_hosts(&d, "any", &acked).len(), 2);
    }

    #[test]
    fn today_is_iso_date_shaped() {
        let t = today();
        assert_eq!(t.len(), 10);
        assert_eq!(t.as_bytes()[4], b'-');
        assert_eq!(t.as_bytes()[7], b'-');
        assert!(t.starts_with("20"));
    }
}
