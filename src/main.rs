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

    // `-u`/`--update` and `gurgl update` are the same explicit, user-invoked
    // update. Handle it before touching config/store (neither is needed) and
    // before anything else, so it works from a bare `gurgl -u`.
    if cli.update || matches!(cli.command, Some(Commands::Update)) {
        return cmd_update();
    }

    let cfg = load_config(&cli)?;
    let store = build_store(&cli, &cfg)?;

    match &cli.command {
        // Bare `gurgl`: a git-status-style orientation beats generic help. It
        // shows where this machine stands and the one next command that helps.
        None => cmd_orient(&cfg, &store),
        Some(Commands::Update) => unreachable!("handled above"),
        Some(Commands::Init) => cmd_init(&store),
        Some(Commands::List) => cmd_list(&store),
        Some(Commands::Show { server, version }) => cmd_show(&store, server, version.as_deref()),
        Some(Commands::Diff { server, from, to }) => {
            cmd_diff(&store, server, from.as_deref(), to.as_deref())
        }
        Some(Commands::Allow {
            server,
            version,
            format,
        }) => cmd_allow(&store, server, version.as_deref(), format),
        Some(Commands::Watch {
            server,
            all,
            duration,
            until_closed,
        }) => cmd_watch(
            &cfg,
            &store,
            server.as_deref(),
            *all,
            cli.plain,
            duration.as_deref(),
            *until_closed,
        ),
        Some(Commands::Discover { import }) => cmd_discover(*import),
        Some(Commands::Demo) => cmd_demo(),
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
                "\n  ⚠ {} new stable host(s) matched no known rule - review before trusting this update:",
                unknown.len()
            );
            for u in &unknown {
                println!("    {}  [{}]", u.name, u.class);
            }
            // Tell the user what to actually DO, not just that it happened.
            println!(
                "\n  next steps:\n    \
                 1. confirm:  gurgl watch {}   (does it reproduce in a fresh capture?)\n    \
                 2. inspect:  search the package source for the hostname (e.g. grep it in\n                 \
                 the npm tarball or repo) to see what contacts it and why\n    \
                 3. decide:   expected -> add it to `first_party` in gurgl.toml;\n                 \
                 not expected -> stay on {} and investigate before upgrading",
                d.server, d.from_version
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
    duration: Option<&str>,
    until_closed: bool,
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
    for spec in targets {
        if observe::stop_requested() {
            println!("stopped by user; skipping remaining servers");
            break;
        }
        let plan_path = cfg.flightplan_path_for(spec);
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
            return Ok(());
        }
        bail!("no servers were captured (see the messages above)");
    }
    Ok(())
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
        run(Command::new("git")
            .arg("-C")
            .arg(&src)
            .args(["pull", "--ff-only"]))?;
    } else {
        std::fs::create_dir_all(&home).with_context(|| format!("creating {}", home.display()))?;
        if src.exists() {
            std::fs::remove_dir_all(&src).with_context(|| format!("clearing {}", src.display()))?;
        }
        println!(">> fetching gurgl from {REPO} ...");
        run(Command::new("git").arg("clone").arg(REPO).arg(&src))?;
    }

    println!(">> building + installing the update ...");
    run(Command::new("bash")
        .arg(src.join("install.sh"))
        .arg("--no-modify-path")
        .current_dir(&src))?;

    println!("\ngurgl is up to date. Check `gurgl --version`.");
    Ok(())
}

/// Run a subprocess inheriting stdio, with clear errors when the tool is missing
/// or the command fails.
fn run(cmd: &mut std::process::Command) -> Result<()> {
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
