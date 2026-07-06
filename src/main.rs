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
mod pkgver;
mod proxy;
mod report;
mod sandbox;
mod share;
mod store;

use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use anyhow::{bail, Context, Result};
use clap::Parser;

use crate::cli::{Cli, Commands};
use crate::config::Config;
use crate::flightplan::FlightPlan;
use crate::model::{CaptureMode, Reproducibility};
use crate::store::Store;

/// Exit-code contract (grep convention, so scripts can gate on drift):
///   0 = success / no drift at the requested threshold
///   1 = drift detected (`diff --check`, `watch --diff`)
///   2 = error
fn main() {
    // If a panic happens while the live dashboard owns the terminal, restore the
    // terminal FIRST so the panic message lands on a normal screen instead of
    // being erased by the alternate-screen teardown during unwinding.
    // emergency_restore is idempotent and no-ops when the dashboard is inactive.
    let prev_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        report::emergency_restore();
        prev_hook(info);
    }));

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
    // The config path actually resolved (honors --config), so orient/doctor
    // report and gate on the same file load_config read - not a re-derivation
    // that ignores --config.
    let cfg_source = config_source(&cli);

    match &cli.command {
        // Bare `gurgl`: a git-status-style orientation beats generic help. It
        // shows where this machine stands and the one next command that helps.
        None => cmd_orient(&cfg, &store, cfg_source.as_deref()).map(|_| 0),
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
            against,
            check,
        }) => match against {
            // --against compares the local capture to someone else's SHARED
            // capture: exploratory, never a pass/fail (see cmd_diff_against).
            Some(path) => {
                let first_party = cfg
                    .server(server)
                    .map(|s| s.first_party.clone())
                    .unwrap_or_default();
                cmd_diff_against(&store, server, path, &first_party, cli.json)
            }
            None => cmd_diff(
                &store,
                server,
                from.as_deref(),
                to.as_deref(),
                *baseline,
                check.as_deref(),
                cli.json,
            ),
        },
        Some(Commands::Export {
            server,
            version,
            output,
            as_name,
            force,
        }) => cmd_export(
            &store,
            server,
            version.as_deref(),
            output.as_deref(),
            as_name.as_deref(),
            *force,
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
        Some(Commands::Discover { import }) => {
            cmd_discover(*import, cli.json, &import_target(&cli)).map(|_| 0)
        }
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
        Some(Commands::Doctor) => cmd_doctor(&cfg, &store, cfg_source.as_deref()),
        Some(Commands::Explain { server, host }) => {
            cmd_explain(&store, server, host.as_deref()).map(|_| 0)
        }
    }
}

/// The bundled example snapshots, embedded so `gurgl demo` works from any
/// install with zero dependencies (no repo checkout, no capture backend).
const DEMO_FROM: &str = include_str!("../examples/snapshots/example-mcp/1.2.0.json");
const DEMO_TO: &str = include_str!("../examples/snapshots/example-mcp/1.3.0.json");

/// Bare `gurgl`: where this machine stands and the single next command that
/// makes progress. States it never asserts: nothing here is a safety judgment.
fn cmd_orient(cfg: &Config, store: &Store, cfg_path: Option<&Path>) -> Result<()> {
    println!("gurgl - local-first egress hygiene for MCP servers\n");

    // Config: the path load_config actually resolved (honors --config).
    match cfg_path {
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

/// The config file `load_config` will read, by precedence: explicit --config,
/// then a project-local ./gurgl.toml, then ~/.gurgl/gurgl.toml. `None` means no
/// file was found and built-in defaults are used. Shared so `doctor`/`orient`
/// report the SAME path that is actually loaded, honoring --config.
fn config_source(cli: &Cli) -> Option<PathBuf> {
    cli.config.clone().or_else(|| {
        let local = PathBuf::from("gurgl.toml");
        if local.is_file() {
            return Some(local);
        }
        let home = config::default_config_path();
        home.is_file().then_some(home)
    })
}

fn load_config(cli: &Cli) -> Result<Config> {
    match config_source(cli) {
        Some(p) => Config::load(&p),
        None => Ok(Config::default()),
    }
}

/// Where `discover --import` writes: the same precedence as `config_source`, but
/// falling back to the default path to CREATE when nothing exists yet, and
/// honoring an explicit --config even if that file does not exist.
fn import_target(cli: &Cli) -> PathBuf {
    config_source(cli).unwrap_or_else(config::default_config_path)
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
        "{}@{}  ({} trials, flight plan {}, capture {})",
        snap.server, snap.version, snap.trials, snap.flightplan, snap.capture_mode
    );
    // Show where the version label came from, and flag a self-reported version
    // that disagrees with what was actually installed (a neutral observation, not
    // an accusation - the installed value is the trustworthy storage key).
    if let Some(src) = &snap.version_source {
        if src != "server-reported" {
            match &snap.reported_version {
                Some(rep) if rep != &snap.version => println!(
                    "  version source: {src} (server self-reports {rep}; stored under {})",
                    snap.version
                ),
                _ => println!("  version source: {src}"),
            }
        }
    }
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
        if snap.trials < 2 {
            // One observation: the reproduction gate never ran, so nothing here
            // is "stable". Say so rather than implying a battery happened.
            println!(
                "  {:<12} this was a single observation ({} trial), so hosts are `observed`,\n  \
                 {:<12} not `stable`: reproducibility is untested. Run `gurgl watch {}` a few\n  \
                 {:<12} times for a battery that can confirm which hosts reproduce.",
                "repro", snap.trials, "", server, ""
            );
        } else {
            println!(
                "  {:<12} SEEN n/{}: appeared in n of the {} trials. stable = every trial; \
                 intermittent = some\n  {:<12} trials only (usually server-side cohort noise, \
                 not a change in the tool).",
                "repro", snap.trials, snap.trials, ""
            );
        }
    }
    println!("\n{}", capture_mode_note(snap.capture_mode));
    println!(
        "note: presence only - hosts observed under this flight plan. Absence of a host \
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

/// One-line explanation of what a capture mode did and did not cover. A mechanism
/// statement only - never "safe"/"complete"/"verified" (constraint #1/#2).
fn capture_mode_note(mode: CaptureMode) -> &'static str {
    match mode {
        CaptureMode::EnvProxy => {
            "capture mode env-proxy: only egress from clients that honor proxy env vars was seen; \
             a client that ignores them or opens raw sockets is not captured here, so it can look \
             quiet while talking."
        }
        CaptureMode::Forced => {
            "capture mode forced: all of the child's TCP egress was routed through the proxy \
             (still presence-only; server-side and trusted-channel activity remain invisible)."
        }
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
            // A lone --from diffs that version against the latest capture (a
            // natural "what changed since f"). A lone --to is ambiguous (from
            // what?), so ask for both rather than silently diffing the latest two
            // and answering a different question than the one asked.
            (Some(f), None) => {
                let latest = store
                    .latest(server)?
                    .with_context(|| format!("no captures for '{server}'"))?;
                (f.to_string(), latest)
            }
            (None, Some(_)) => bail!(
                "--to needs --from; pass both versions, or give --from <v> alone to diff it \
                 against the latest"
            ),
            (None, None) => match store.latest_two(server)? {
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
            "flightplan_mismatch": from_snap.flightplan != to_snap.flightplan,
            "from_capture_mode": from_snap.capture_mode,
            "to_capture_mode": to_snap.capture_mode,
            "capture_mode_mismatch": from_snap.capture_mode != to_snap.capture_mode,
            "to_trials": to_snap.trials,
            "note": "presence only: hosts observed under this flight plan. Absence is non-coverage, not proof.",
        });
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else {
        println!("{}: {} -> {}", d.server, d.from_version, d.to_version);
        println!("  unchanged hosts: {}", d.unchanged);
        if from_snap.flightplan != to_snap.flightplan {
            // The flight-plan fingerprint binds an observation to its method. If
            // the two captures used different plans, added/removed hosts may
            // reflect the changed method, not the tool - say so plainly.
            println!(
                "  ! flight plans differ ({} -> {}): new or missing hosts may reflect the changed \
                 method, not the tool. Re-capture both under one plan to compare cleanly.",
                from_snap.flightplan, to_snap.flightplan
            );
        }
        if from_snap.capture_mode != to_snap.capture_mode {
            // The capture mode is also part of the method. A weaker->stronger mode
            // change (env-proxy -> forced) can surface hosts that were always
            // contacted but previously escaped capture; those are NOT new egress.
            // Flag it like a flight-plan mismatch so a mode change is never misread
            // as drift.
            println!(
                "  ! capture modes differ ({} -> {}): a stronger mode sees egress the weaker one \
                 missed, so \"new\" hosts may have been contacted all along, not newly added. \
                 Re-capture both under one mode to compare cleanly.",
                from_snap.capture_mode, to_snap.capture_mode
            );
        }

        if d.added.is_empty() {
            println!("  no new hosts observed under this flight plan");
        } else {
            println!("  new hosts:");
            for delta in &d.added {
                let flag = match delta.reproducibility {
                    Reproducibility::Stable => "", // stable: a real change
                    Reproducibility::Observed => {
                        "  (single observation - reproducibility untested, not a finding)"
                    }
                    Reproducibility::Intermittent => {
                        "  (intermittent - likely cohort noise, not a finding)"
                    }
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

/// `gurgl export`: write a scrubbed, shareable capture (stable hosts only, no
/// verdict, guardrails baked in). JSON to stdout, or to a file with -o. The
/// bundle carries the publishing rules IN-BAND; we ALSO surface them plus the
/// exact host list on stderr so the exporter sees them at export time.
fn cmd_export(
    store: &Store,
    server: &str,
    version: Option<&str>,
    out: Option<&Path>,
    as_name: Option<&str>,
    force: bool,
) -> Result<i32> {
    let v = match version {
        Some(v) => v.to_string(),
        None => store.latest(server)?.with_context(|| {
            format!("no captures for '{server}' - run `gurgl watch {server}` first")
        })?,
    };
    let snap = store.load(server, &v)?;
    let bundle = share::export(&snap, as_name);
    let text = serde_json::to_string_pretty(&bundle)?;

    // Everything human goes to STDERR so stdout stays a clean bundle when piped
    // (`gurgl export foo > bundle.json`), matching `allow`.
    if bundle.hosts.is_empty() {
        eprintln!(
            "note: {}@{} has no STABLE hosts to share - only reproduced (stable) hosts are \
             exportable. Capture a battery of >=2 trials so the reproduction gate can apply.",
            bundle.server, bundle.version
        );
    }
    eprintln!(
        "shared capture of {} @ {} - {} stable host(s):",
        bundle.server,
        bundle.version,
        bundle.hosts.len()
    );
    for h in &bundle.hosts {
        eprintln!("    {}", h.name);
    }
    eprintln!(
        "\nreview before you share (this file names a third party):\n  \
         - server label written: '{}'{} - it may identify you; rename with --as-name.\n  \
         - a host reached via a tool-call ARGUMENT may be YOURS, not the tool's.\n  \
         - a host that reveals internal infrastructure should be removed by hand.\n  \
         - publishing named observations takes on real legal/ethical exposure:\n    \
         form an entity + carry insurance, coordinate disclosure, never punch down (docs/PUBLISHING.md).\n  \
         - it is presence-only and NOT a verdict: matching it is not a clean bill of health.",
        bundle.server,
        if as_name.is_some() {
            " (from --as-name)"
        } else {
            " (your local label)"
        }
    );

    match out {
        Some(path) => {
            if path.exists() && !force {
                bail!(
                    "{} already exists - pass --force to overwrite",
                    path.display()
                );
            }
            store::write_atomic(path, format!("{text}\n").as_bytes())?;
            eprintln!("\nwrote {}", path.display());
        }
        None => println!("{text}"),
    }
    Ok(0)
}

/// `gurgl diff <server> --against <PATH>`: compare the local capture to someone
/// else's SHARED capture. Exploratory, NEVER a pass/fail - a shared capture is an
/// untrusted, presence-only sample authored by a stranger, not a verified
/// reference. It carries no exit-code verdict (0 = compared, 2 = error); matching
/// it is explicitly not a pass and not evidence of no exfiltration.
fn cmd_diff_against(
    store: &Store,
    server: &str,
    against: &Path,
    first_party: &[String],
    json: bool,
) -> Result<i32> {
    let local_v = store.latest(server)?.with_context(|| {
        format!("no local captures for '{server}' - run `gurgl watch {server}` first")
    })?;
    let local = store.load(server, &local_v)?;

    // The other side is loaded as HOSTILE input: capped, control-stripped,
    // re-gated, and reclassified with OUR first_party (never the producer's).
    let loaded = share::load_against(against, server, first_party)?;
    let other = &loaded.snapshot;

    // diff(from = the shared capture, to = local): `added` = hosts WE saw the
    // shared capture did not; `removed` = hosts it saw we did not.
    let d = diff::diff(other, &local);
    let acks = store.acks(server).unwrap_or_default();
    let acked: Vec<String> = acks.iter().map(|a| a.host.clone()).collect();

    // The reproduction gate applies to OUR side too: only stable local additions
    // are comparable, and only the scrutiny-class ones are worth flagging.
    let (scrutiny_acked, scrutiny): (Vec<&diff::HostDelta>, Vec<&diff::HostDelta>) = d
        .stable_unknown_added()
        .into_iter()
        .partition(|h| acked.iter().any(|a| a == &h.name));

    // A shared capture with no flight-plan fingerprint is an unknown method, so
    // treat it as a mismatch (it cannot be assumed to match ours).
    let fp_equal = !other.flightplan.is_empty() && other.flightplan == local.flightplan;
    let shared_fp = if other.flightplan.is_empty() {
        "unknown".to_string()
    } else {
        other.flightplan.clone()
    };

    if json {
        let out = serde_json::json!({
            "schema": "gurgl.diff-against/1",
            "server": server,
            "local_version": local_v,
            "source": loaded.source,
            "you_saw_shared_did_not": d.added.iter().map(|h| &h.name).collect::<Vec<_>>(),
            "you_saw_stable": d.stable_added().iter().map(|h| &h.name).collect::<Vec<_>>(),
            "you_saw_needs_scrutiny": scrutiny.iter().map(|h| &h.name).collect::<Vec<_>>(),
            "shared_saw_you_did_not": d.removed.iter().map(|h| &h.name).collect::<Vec<_>>(),
            "also_present_in_shared": d.unchanged,
            "your_flightplan": local.flightplan,
            "shared_flightplan": shared_fp,
            "flightplan_fingerprint_equal": fp_equal,
            "note": "presence only, and NOT a verdict. A shared capture is one observer's untrusted, \
                     presence-only sample under their own flight plan - not a verified or known-good \
                     reference. Agreement is NOT a pass and NOT evidence of no exfiltration (a tool can \
                     exfiltrate over a host it already contacts). It is not an allowlist. See docs/THREAT-MODEL.md.",
        });
        println!("{}", serde_json::to_string_pretty(&out)?);
        return Ok(0);
    }

    println!(
        "comparing your capture of {server}@{local_v} against a shared capture\n  source: {}",
        loaded.source
    );
    println!(
        "  [the shared capture is one observer's presence-only sample under their own flight plan -\n   \
         NOT a vetted or known-good reference. Having more or fewer hosts than it is expected.]"
    );
    if !fp_equal {
        // Different (or unknown) methods exercise different egress: the delta is
        // largely a method artifact, not the tool. For a foreign capture you
        // usually cannot re-capture the other side, so the remediation differs
        // from the local version-over-version diff.
        println!(
            "  ! flight plans differ (yours: {}, shared: {}): different methods exercise different \
             egress, so this is NOT apples-to-apples. Re-capture locally under the shared plan (if you \
             have it) to compare cleanly; otherwise read every delta as method divergence.",
            local.flightplan, shared_fp
        );
    }

    if d.added.is_empty() {
        // The agreement case is where "matches = clean" is most tempting, so state
        // the trusted-channel limit right here, not only in the footer.
        println!(
            "\n  you observed no hosts beyond the shared capture.\n  \
             this is NOT a pass: matching a shared capture is not a clean bill of health - a tool \
             exfiltrating over a host it already contacts produces an identical set, which gurgl cannot see."
        );
    } else {
        println!("\n  hosts YOU observed that the shared capture did not:");
        for delta in &d.added {
            let flag = match delta.reproducibility {
                Reproducibility::Stable => "",
                Reproducibility::Observed => "  (single observation - reproducibility untested)",
                Reproducibility::Intermittent => "  (intermittent - likely cohort noise)",
            };
            println!("    + {:<40} [{}]{}", delta.name, delta.class, flag);
        }
        if !scrutiny.is_empty() {
            println!(
                "\n  ⚠ {} stable host(s) here matched no known rule - worth a look. This is NOT proof \
                 of wrongdoing: a different version, a server-side cohort, a different flight plan, or \
                 your own tool-call arguments can all add hosts the shared capture lacks:",
                scrutiny.len()
            );
            for u in &scrutiny {
                println!("    {}  [{}]", u.name, u.class);
            }
        }
        if !scrutiny_acked.is_empty() {
            println!(
                "\n  {} of these you previously acknowledged (gurgl ack {server} --list): {}",
                scrutiny_acked.len(),
                scrutiny_acked
                    .iter()
                    .map(|h| h.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
    }

    if !d.removed.is_empty() {
        println!(
            "\n  hosts in the shared capture you did NOT observe ({}):",
            d.removed.len()
        );
        for delta in &d.removed {
            println!("    - {:<40} [{}]", delta.name, delta.class);
        }
        println!(
            "    (a version, cohort, coverage, or flight-plan difference - not \"you are missing something\")"
        );
    }

    // Overlap count last and de-emphasized: agreement is not a score.
    println!(
        "\n  hosts also present in the shared capture: {} (overlap is not verification)",
        d.unchanged
    );

    println!(
        "\nnote: presence only, and NOT a verdict. A shared capture is untrusted, presence-only \
         evidence authored by a stranger - it can miss hosts or list extra ones, and it is not an \
         allowlist. Agreement with it is not a pass and not proof of no exfiltration (docs/THREAT-MODEL.md)."
    );
    Ok(0)
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

    // Live dashboard only when attached to a terminal AND in the foreground;
    // plain lines when piped, with --plain, or backgrounded. A backgrounded
    // `gurgl watch &` still has the tty as stderr, so is_terminal() alone would
    // let it seize the interactive shell's screen.
    let mode = if plain || !std::io::stderr().is_terminal() || !report::terminal_is_foreground() {
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
        // Load the pre-update snapshot CONTENT now, BEFORE capture+save can
        // overwrite a same-version file. This is what lets `--diff` still detect
        // drift on a same-version re-release or an "unknown"-labeled server
        // (labels equal, contents changed) instead of dismissing it as "nothing
        // to compare". A load failure here is per-server, never a batch abort.
        let prev_before: Option<Result<model::Snapshot>> =
            compare_to.as_ref().map(|v| store.load(&spec.name, v));
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
                        "note: this replaced the previous capture of {}@{} (same version label). \
                         `gurgl diff` compares versions by label, so it can't compare two \
                         same-labeled captures - pin distinct versions for a diffable history.",
                        snap.server, snap.version
                    );
                    if snap.version == "unknown" {
                        println!(
                            "      this server reports no version; pin one in gurgl.toml \
                             (version = \"...\") so each capture keeps its own history."
                        );
                    }
                    if store.baseline(&snap.server).as_deref() == Some(snap.version.as_str()) {
                        println!(
                            "      this version is your accepted baseline; the reviewed capture \
                             was replaced - re-review with `gurgl diff {} --baseline`.",
                            snap.server
                        );
                    }
                }
                captured += 1;

                // The audit line for this server, comparing the fresh capture's
                // CONTENT against the pre-update content (loaded before save), so
                // a same-version overwrite is still diffed, not dismissed. Store
                // errors here are per-server notes, never a batch abort.
                if audit {
                    let prev_label = compare_to.as_deref().unwrap_or("?");
                    match prev_before {
                        None => drift_lines.push(format!(
                            "  {:<16} first capture - nothing to compare yet; run \
                             `gurgl accept {}` to set a reviewed baseline",
                            snap.server, snap.server
                        )),
                        Some(Err(e)) => drift_lines.push(format!(
                            "  {:<16} could not compare against {prev_label}: {e:#} - re-run \
                             `gurgl accept {}` or inspect the store",
                            snap.server, snap.server
                        )),
                        Some(Ok(prev_snap)) => {
                            let d = diff::diff(&prev_snap, &snap);
                            let acked: Vec<String> = match store.acks(&snap.server) {
                                Ok(a) => a.into_iter().map(|a| a.host).collect(),
                                Err(e) => {
                                    drift_lines.push(format!(
                                        "  {:<16} acks unreadable ({e:#}); comparing without them",
                                        snap.server
                                    ));
                                    Vec::new()
                                }
                            };
                            let fp_note = if prev_snap.flightplan != snap.flightplan {
                                "  [flight plans differ - method changed, not necessarily the tool]"
                            } else {
                                ""
                            };
                            let scrutiny = drift_hosts(&d, "unknown", &acked);
                            let stable_new = d.stable_added().len();
                            if scrutiny.is_empty() {
                                if prev_label == snap.version
                                    && d.added.is_empty()
                                    && d.removed.is_empty()
                                {
                                    drift_lines.push(format!(
                                        "  {:<16} same version re-capture, no change in observed hosts{fp_note}",
                                        snap.server
                                    ));
                                } else {
                                    drift_lines.push(format!(
                                        "  {:<16} {} -> {}: {} new stable host(s), none needing scrutiny{fp_note}",
                                        snap.server, prev_label, snap.version, stable_new
                                    ));
                                }
                            } else {
                                drifted = true;
                                drift_lines.push(format!(
                                    "  {:<16} {} -> {}: {} new stable host(s) NEED SCRUTINY: {} \
                                     (gurgl diff {}){fp_note}",
                                    snap.server,
                                    prev_label,
                                    snap.version,
                                    scrutiny.len(),
                                    scrutiny.join(", "),
                                    snap.server
                                ));
                            }
                        }
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

/// `gurgl doctor`: readiness + capture-fidelity report for THIS machine.
/// Read-only; runs nothing but version probes. Every finding is phrased as
/// coverage ("a capture here will include/miss X because Y"), never as a
/// safety verdict. Exits 1 when something would block `gurgl watch`.
fn cmd_doctor(cfg: &Config, store: &Store, cfg_path: Option<&Path>) -> Result<i32> {
    let mut blockers = 0usize;
    let ok = |s: &str| println!("  [ok]      {s}");
    let warn = |s: &str| println!("  [warn]    {s}");
    let missing = |s: &str| println!("  [missing] {s}");

    println!("gurgl doctor - readiness and capture fidelity on this machine\n");

    // --- setup ----------------------------------------------------------------
    println!("setup");
    // The path load_config resolved, honoring --config - not a re-derivation
    // that would falsely report "none found" for `gurgl -c <path> doctor`.
    match cfg_path {
        Some(p) => ok(&format!("config: {}", p.display())),
        None => {
            blockers += 1;
            missing("config: none found - run `gurgl init`");
        }
    }
    if cfg.servers.is_empty() {
        warn("servers: none configured - run `gurgl discover --import` or edit gurgl.toml");
    } else {
        ok(&format!("servers: {} configured", cfg.servers.len()));
    }
    let home_bin = config::gurgl_home().join("bin");
    let on_shell_path = std::env::var("PATH")
        .map(|p| std::env::split_paths(&p).any(|d| d == home_bin))
        .unwrap_or(false);
    if on_shell_path {
        ok(&format!(
            "PATH: {} is on this shell's PATH",
            home_bin.display()
        ));
    } else {
        warn(&format!(
            "PATH: {} not on this shell's PATH - run: . \"$HOME/.gurgl/env\"",
            home_bin.display()
        ));
    }
    let captures: usize = store
        .servers()?
        .iter()
        .map(|s| store.versions(s).map(|v| v.len()).unwrap_or(0))
        .sum();
    ok(&format!(
        "store: {} ({captures} capture(s))",
        store.root().display()
    ));

    // --- capture backends -------------------------------------------------------
    println!("\ncapture backends (needed for `watch` only)");
    let sandbox_bin = sandbox::required_binary(cfg.sandbox);
    if observe::on_path(sandbox_bin) {
        ok(&format!("sandbox: {sandbox_bin}"));
    } else {
        blockers += 1;
        missing(&format!(
            "sandbox: {sandbox_bin} - see `gurgl watch`'s preflight for the fix"
        ));
    }
    match probe_version(&cfg.mitmdump, &["--version"]) {
        Some(v) => ok(&format!("proxy: {} ({})", cfg.mitmdump, v)),
        None => {
            blockers += 1;
            missing(&format!("proxy: {} (mitmproxy) not on PATH", cfg.mitmdump));
        }
    }
    let ca = config::gurgl_home()
        .join("mitmproxy")
        .join("mitmproxy-ca-cert.pem");
    if ca.is_file() {
        ok("lab CA: generated");
    } else {
        warn("lab CA: not yet generated (created automatically on the first `watch`)");
    }

    // --- per-server runtimes ----------------------------------------------------
    if !cfg.servers.is_empty() {
        println!("\nconfigured servers");
        for spec in &cfg.servers {
            if observe::on_path(&spec.command) {
                ok(&format!(
                    "{}: launch command '{}' found",
                    spec.name, spec.command
                ));
            } else {
                blockers += 1;
                missing(&format!(
                    "{}: launch command '{}' not on PATH (its runtime, not a gurgl dep)",
                    spec.name, spec.command
                ));
            }
        }
    }

    // --- capture fidelity, measured facts applied to THIS machine ---------------
    // (docs/THREAT-MODEL.md#capture-fidelity is the source for these.)
    println!("\ncapture fidelity (what a capture here would include or miss)");
    match probe_version("node", &["--version"]) {
        Some(v) => {
            let major: u32 = v
                .trim_start_matches('v')
                .split('.')
                .next()
                .and_then(|m| m.parse().ok())
                .unwrap_or(0);
            if major >= 24 {
                ok(&format!(
                    "Node {v}: honors the proxy via NODE_USE_ENV_PROXY - Node/npx servers capture"
                ));
            } else {
                warn(&format!(
                    "Node {v}: ignores proxy env vars (NODE_USE_ENV_PROXY needs Node 24+), so a \
                     capture here will MISS a Node server's own egress - it can look quiet while \
                     talking. Upgrade Node to capture it."
                ));
            }
        }
        None => warn("Node: not found - npx-launched servers cannot run at all here"),
    }
    if cfg!(target_os = "macos") {
        warn(
            "macOS system python3 ignores SSL_CERT_FILE (LibreSSL), so a python server using it \
             fails TLS through the proxy and its egress is MISSED. Use a python.org/homebrew \
             Python for python servers.",
        );
    }
    println!(
        "  [info]    capture mode: env-proxy (the only mode implemented today) - relies on servers\n\
         \x20           honoring proxy env vars; a client that opens raw sockets or pins certs\n\
         \x20           escapes it (docs/THREAT-MODEL.md). Quiet is never proof."
    );
    // Preview whether the forthcoming forced backend (netns + transparent
    // redirect, which would close the raw-socket gap) could run on THIS machine.
    // It is not implemented yet, so say so - never imply a capability we lack.
    match forced_capture_feasible() {
        Ok(()) => println!(
            "  [info]    forced capture (netns + transparent redirect) is not implemented yet; this\n\
             \x20           machine looks capable of running it once it ships."
        ),
        Err(reason) => println!(
            "  [info]    forced capture (not implemented yet) would be unavailable here regardless:\n\
             \x20           {reason}."
        ),
    }

    // --- verdictless wrap-up ------------------------------------------------------
    let next = if blockers > 0 {
        "fix the [missing] items above, then re-run `gurgl doctor`"
    } else if cfg.servers.is_empty() {
        "gurgl discover --import"
    } else if captures == 0 {
        "gurgl watch --all"
    } else {
        "gurgl watch --all --diff   (the drift audit)"
    };
    println!("\nnext: {next}");
    Ok(if blockers > 0 { 1 } else { 0 })
}

/// Run `bin --version`-style probe, first line of stdout.
fn probe_version(bin: &str, args: &[&str]) -> Option<String> {
    let out = std::process::Command::new(bin).args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout);
    let line = s.lines().next()?.trim().to_string();
    (!line.is_empty()).then_some(line)
}

/// Could THIS machine support the forthcoming forced-capture backend (netns +
/// transparent redirect)? Pure detection returning the first concrete blocker so
/// `doctor` can state it plainly. The backend is not implemented yet (slice 1a
/// ships the `capture_mode` labeling only); this is a readiness preview, and the
/// backend slice will reuse it to decide the achievable mode.
#[cfg(target_os = "linux")]
fn forced_capture_feasible() -> Result<(), String> {
    if !observe::on_path("nft") {
        return Err(
            "nftables `nft` is not on PATH (needed for the transparent-redirect rules)".to_string(),
        );
    }
    if !observe::on_path("pasta") && !observe::on_path("slirp4netns") {
        return Err(
            "no rootless netns egress helper found (need `pasta` or `slirp4netns`) - a \
             --unshare-net namespace has no upstream route without one"
                .to_string(),
        );
    }
    // Ubuntu 23.10+ can forbid unprivileged user namespaces via AppArmor; the
    // forced path needs one to own a netns it can add nft rules to without root.
    if read_kernel_flag("/proc/sys/kernel/apparmor_restrict_unprivileged_userns") == Some(true) {
        return Err("unprivileged user namespaces are restricted by AppArmor \
             (kernel.apparmor_restrict_unprivileged_userns=1)"
            .to_string());
    }
    if read_kernel_flag("/proc/sys/kernel/unprivileged_userns_clone") == Some(false) {
        return Err(
            "unprivileged user namespaces are disabled (kernel.unprivileged_userns_clone=0)"
                .to_string(),
        );
    }
    Ok(())
}

/// Non-Linux hosts cannot run the netns/nftables forced backend at all.
#[cfg(not(target_os = "linux"))]
fn forced_capture_feasible() -> Result<(), String> {
    Err("forced capture is Linux-only (it uses network namespaces + nftables)".to_string())
}

/// Read a kernel 0/1 flag file; None if absent or unparseable.
#[cfg(target_os = "linux")]
fn read_kernel_flag(path: &str) -> Option<bool> {
    match std::fs::read_to_string(path).ok()?.trim() {
        "1" => Some(true),
        "0" => Some(false),
        _ => None,
    }
}

/// `gurgl explain`: the latest capture (or one host) narrated in sentences.
/// Every claim stays inside what was observed; the caveats travel with it.
fn cmd_explain(store: &Store, server: &str, host: Option<&str>) -> Result<()> {
    let version = store
        .latest(server)?
        .with_context(|| format!("no captures for '{server}' - run `gurgl watch {server}`"))?;
    let snap = store.load(server, &version)?;
    let acks = store.acks(server)?;
    let times = if snap.trials == 1 {
        "once".to_string()
    } else {
        format!("{} separate times", snap.trials)
    };

    if let Some(name) = host {
        let h = snap
            .hosts
            .iter()
            .find(|h| h.name == name)
            .with_context(|| {
                format!(
                    "'{name}' was not observed in {server}@{version} (see `gurgl show {server}`)"
                )
            })?;
        println!("{name} (observed in {}@{})\n", snap.server, snap.version);
        println!("{}", host_story(h, snap.trials, &acks));
        println!(
            "\nWhat this cannot tell you: what was SENT to it (gurgl records host names, never\n\
             payloads), or anything about runs outside this flight plan."
        );
        return Ok(());
    }

    // Whole-snapshot narration.
    println!("{}@{} in plain language\n", snap.server, snap.version);
    println!(
        "gurgl ran {server} {times}, each inside a sandbox whose traffic passes through a\n\
         local capture proxy, driving the same scripted MCP session every time (flight plan\n\
         {}). Every host the process contacted was recorded.\n",
        snap.flightplan
    );
    if snap.hosts.is_empty() {
        println!(
            "No hosts were observed. That means: under THIS scripted session, on this machine,\n\
             nothing was seen - not that the server never talks. A tool that only reaches out\n\
             on specific inputs needs a flight plan that provides them (docs/USAGE.md)."
        );
        return Ok(());
    }
    println!(
        "It contacted {} host(s) across those runs:\n",
        snap.hosts.len()
    );
    for h in &snap.hosts {
        println!("{}\n", indent(&host_story(h, snap.trials, &acks), "  "));
    }
    let scrutiny: Vec<&model::Host> = snap
        .hosts
        .iter()
        .filter(|h| {
            h.class.needs_scrutiny()
                && h.reproducibility == model::Reproducibility::Stable
                && !acks.iter().any(|a| a.host == h.name)
        })
        .collect();
    if scrutiny.is_empty() {
        println!(
            "Nothing here needs scrutiny right now: every stable host either matched a known\n\
             rule or was already acknowledged by you."
        );
    } else {
        println!(
            "The part deserving your attention: {}. Reproducible, and no rule explains {}.\n\
             `gurgl diff {server}` after the next update shows if anything NEW appears.",
            scrutiny
                .iter()
                .map(|h| h.name.as_str())
                .collect::<Vec<_>>()
                .join(", "),
            if scrutiny.len() == 1 { "it" } else { "them" }
        );
    }
    println!(
        "\nAnd the honest limits: this is presence only, under one scripted session. gurgl\n\
         cannot see payloads, server-side behavior, or exfiltration riding a host the tool\n\
         legitimately uses (docs/THREAT-MODEL.md)."
    );
    Ok(())
}

/// One host's story in sentences: what it is, when it appeared, how reliably,
/// and what (if anything) the user already said about it.
fn host_story(h: &model::Host, trials: u32, acks: &[store::Ack]) -> String {
    let phases = if h.phases.is_empty() {
        "during the session".to_string()
    } else {
        format!("during {}", h.phases.join(" and "))
    };
    let seen = match h.reproducibility {
        model::Reproducibility::Stable => {
            format!("in every one of the {trials} run(s) - reproducible")
        }
        model::Reproducibility::Observed => {
            // A single observation: seen, but the gate could not be applied.
            // Do not call it cohort noise (that needs a battery to establish),
            // and do not call it a reproduced fact either.
            "in a single observation - reproducibility untested (this was one long watch, \
             not a repeated battery); run `gurgl watch` a few times to confirm whether it \
             is stable"
                .to_string()
        }
        model::Reproducibility::Intermittent => format!(
            "in only {} of {trials} runs - NOT reproducible, which usually means server-side \
             A/B or feature-gate noise rather than a change in the tool; gurgl deliberately \
             does not treat it as a finding",
            h.seen_in_trials
        ),
    };
    let what = match h.class {
        model::HostClass::FirstParty => {
            "a domain you declared as first-party for this server".to_string()
        }
        model::HostClass::Telemetry => "a known analytics/crash-reporting vendor".to_string(),
        model::HostClass::TelemetryNamed => {
            "a host that NAMES itself telemetry but matches no known vendor - a hostname is \
             chosen by whoever registers it, so treat this like an unknown"
                .to_string()
        }
        model::HostClass::Registry => {
            "a package registry / code host (expected when a server is launched via npx or \
             uvx, which download the package at start)"
                .to_string()
        }
        model::HostClass::Unknown => "a host matching no known rule".to_string(),
    };
    let ack = acks
        .iter()
        .find(|a| a.host == h.name)
        .map(|a| {
            format!(
                "\nYou acknowledged this host on {}{}.",
                a.date,
                a.note
                    .as_deref()
                    .map(|n| format!(": \"{n}\""))
                    .unwrap_or_default()
            )
        })
        .unwrap_or_default();
    format!("{} - {what}. Seen {seen}, {phases}.{ack}", h.name)
}

fn indent(s: &str, pad: &str) -> String {
    s.lines()
        .map(|l| format!("{pad}{l}"))
        .collect::<Vec<_>>()
        .join("\n")
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

    // You acknowledge a host you SAW in a capture. Requiring at least one
    // capture stops a typo'd server name from silently creating an orphan
    // acks.toml that no diff will ever consult.
    let latest = store.latest(server)?;
    if latest.is_none() {
        bail!(
            "no captures for '{server}' - nothing to acknowledge (typo? run `gurgl list` to see \
             captured servers, or `gurgl watch {server}` first)"
        );
    }
    let ack = store::Ack {
        host: host.to_string(),
        note: note.map(String::from),
        date: today(),
        reviewed_at_version: latest,
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
fn today() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    share::date_from_epoch(secs)
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
    // Checked: a huge value times the unit multiplier would overflow u64 (a debug
    // panic, or a wrapped bogus duration in release).
    let secs = n
        .checked_mul(mult)
        .with_context(|| format!("--for duration '{s}' is too large"))?;
    Ok(std::time::Duration::from_secs(secs))
}

fn cmd_discover(import: bool, json: bool, target: &Path) -> Result<()> {
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
    import_servers(&runnable, target)
}

/// Whether a server's launch references a client-provided runtime variable (e.g.
/// `${CLAUDE_PLUGIN_ROOT}`) that only its client expands - gurgl cannot run it.
fn references_client_runtime(d: &discover::Discovered) -> bool {
    let has_var = |s: &str| s.contains("${");
    d.command.as_deref().map(has_var).unwrap_or(false) || d.args.iter().any(|a| has_var(a))
}

/// Append discovered stdio servers to the resolved config file, skipping any
/// already present. Reports what was imported and what was skipped (by name and
/// source) so the human review the acks/baseline model depends on starts from
/// accurate information.
fn import_servers(stdio: &[&discover::Discovered], path: &Path) -> Result<()> {
    if !path.exists() {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        std::fs::write(path, Config::template())
            .with_context(|| format!("writing {}", path.display()))?;
        println!("\ncreated {}", path.display());
    }

    // If the target exists but does not parse, STOP. Appending to a broken config
    // (the old unwrap_or_default) silently duplicates servers and grows the mess;
    // tell the user to fix it first.
    let existing = Config::load(path).with_context(|| {
        format!(
            "{} exists but does not parse - fix it before importing",
            path.display()
        )
    })?;
    let mut names: std::collections::HashSet<String> =
        existing.servers.iter().map(|s| s.name.clone()).collect();

    let mut text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let mut imported: Vec<(String, String)> = Vec::new();
    let mut skipped: Vec<(String, String)> = Vec::new();
    for d in stdio {
        if !names.insert(d.name.clone()) {
            // Name already present (in the config, or an earlier candidate with
            // this name). Do not silently pick one command over another - list it.
            skipped.push((d.name.clone(), d.source.clone()));
            continue;
        }
        if !text.ends_with('\n') {
            text.push('\n');
        }
        text.push_str(&discover::to_toml_block(d));
        imported.push((d.name.clone(), d.source.clone()));
    }

    if imported.is_empty() {
        println!(
            "\nall discovered stdio servers are already in {}.",
            path.display()
        );
        return Ok(());
    }
    // Atomic replace so a crash/ENOSPC can't truncate the config file.
    store::write_atomic(path, text.as_bytes())?;
    println!(
        "\nimported {} server(s) into {}:",
        imported.len(),
        path.display()
    );
    for (name, source) in &imported {
        println!("  {name:<24} (from {source})");
    }
    if !skipped.is_empty() {
        println!(
            "\nnot imported ({} name(s) already present - if a different command was expected, \
             rename or edit gurgl.toml):",
            skipped.len()
        );
        for (name, source) in &skipped {
            println!("  {name:<24} (also seen from {source})");
        }
    }
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

    let git = |args: &[&str]| -> bool {
        run_cmd(Command::new("git").arg("-C").arg(&src).args(args)).is_ok()
    };

    // Decide whether we can update in place or must re-clone. The managed
    // checkout can be wedged: an interrupted clone (SIGKILL/power loss), a dirty
    // tree (someone edited ~/.gurgl/src), an unfinished merge, or an upstream
    // force-push that `pull --ff-only` can never take. Recover automatically -
    // the checkout is gurgl-managed, so discarding local state is correct.
    let need_clone = if src.join(".git").is_dir() {
        println!(">> updating gurgl source in {} ...", src.display());
        if git(&["pull", "--ff-only"]) {
            false
        } else {
            println!(">> pull failed; resetting the managed checkout to the remote ...");
            !(git(&["fetch", "origin"]) && git(&["reset", "--hard", "origin/HEAD"]))
        }
    } else {
        true
    };

    if need_clone {
        std::fs::create_dir_all(&home).with_context(|| format!("creating {}", home.display()))?;
        if src.exists() {
            println!(">> re-cloning gurgl (previous checkout unusable) ...");
            std::fs::remove_dir_all(&src).with_context(|| format!("clearing {}", src.display()))?;
        } else {
            println!(">> fetching gurgl from {REPO} ...");
        }
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
        Reproducibility::Observed => "observed",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{CaptureMode, Host, HostClass, Snapshot};

    fn snap(version: &str, hosts: Vec<Host>) -> Snapshot {
        Snapshot {
            server: "s".into(),
            version: version.into(),
            captured_at: 0,
            trials: 5,
            flightplan: "fp".into(),
            gurgl_version: "0".into(),
            capture_mode: CaptureMode::EnvProxy,
            reported_version: None,
            version_source: None,
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

    #[test]
    fn capture_mode_note_is_mechanism_only() {
        // Constraint #1/#2: the mode note is a statement about the capture
        // mechanism and must never imply safety or completeness.
        for mode in [CaptureMode::EnvProxy, CaptureMode::Forced] {
            let note = capture_mode_note(mode);
            assert!(!note.is_empty());
            let lc = note.to_ascii_lowercase();
            for forbidden in ["safe", "clean", "verified", "complete"] {
                assert!(
                    !lc.contains(forbidden),
                    "capture_mode_note({mode}) must not imply '{forbidden}': {note}"
                );
            }
        }
        // Each mode names itself and the two read differently.
        assert!(capture_mode_note(CaptureMode::EnvProxy).contains("env-proxy"));
        assert!(capture_mode_note(CaptureMode::Forced).contains("forced"));
        assert_ne!(
            capture_mode_note(CaptureMode::EnvProxy),
            capture_mode_note(CaptureMode::Forced)
        );
    }
}
