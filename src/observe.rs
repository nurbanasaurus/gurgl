//! The capture pipeline: run a server N times behind the proxy, aggregate the
//! per-trial host sets through the reproduction gate, and produce a Snapshot.
//!
//! `aggregate` (the pure heart) is unit-tested. `run_trial` orchestrates the
//! live capture: start `mitmdump`, launch the sandboxed server wired to it,
//! drive the flight plan over MCP stdio, then read back the hosts it contacted.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use serde_json::Value;

use crate::config::{Config, ServerSpec};
use crate::flightplan::FlightPlan;
use crate::model::{classify, Host, Reproducibility, Snapshot};
use crate::proxy::{FlowHost, RawFlow};
use crate::{mcp, proxy, sandbox};

/// Aggregate per-trial host observations into final hosts, applying the
/// reproduction gate: a host is `Stable` only if it appears in every trial.
pub fn aggregate(trials: &[Vec<FlowHost>], first_party: &[String]) -> Vec<Host> {
    use std::collections::{BTreeMap, BTreeSet};

    let n = trials.len() as u32;
    let mut acc: BTreeMap<String, (u32, Vec<String>)> = BTreeMap::new();

    for trial in trials {
        let mut counted: BTreeSet<&str> = BTreeSet::new();
        for fh in trial {
            let entry = acc.entry(fh.host.clone()).or_insert((0, Vec::new()));
            // Count each host at most once per trial (for the reproduction gate)…
            if counted.insert(fh.host.as_str()) {
                entry.0 += 1;
            }
            // …but union its phases across every occurrence in the trial.
            if let Some(phase) = &fh.phase {
                if !entry.1.contains(phase) {
                    entry.1.push(phase.clone());
                }
            }
        }
    }

    acc.into_iter()
        .map(|(name, (count, phases))| {
            let reproducibility = if n > 0 && count >= n {
                Reproducibility::Stable
            } else {
                Reproducibility::Intermittent
            };
            let class = classify(&name, first_party);
            Host {
                name,
                class,
                reproducibility,
                seen_in_trials: count,
                phases,
            }
        })
        .collect()
}

/// Verify the backends this capture needs are available before we start.
pub fn preflight(cfg: &Config) -> Result<()> {
    let sandbox_bin = sandbox::required_binary(cfg.sandbox);
    if !on_path(sandbox_bin) {
        bail!("sandbox backend '{sandbox_bin}' not found on PATH. Install it, or switch `sandbox` in gurgl.toml.");
    }
    if !on_path(&cfg.mitmdump) {
        bail!(
            "proxy backend '{}' not found on PATH. Install mitmproxy (provides mitmdump).",
            cfg.mitmdump
        );
    }
    Ok(())
}

/// Full capture of one server@version.
pub fn capture(cfg: &Config, spec: &ServerSpec, plan: &FlightPlan) -> Result<Snapshot> {
    preflight(cfg)?;

    let mut trials: Vec<Vec<FlowHost>> = Vec::with_capacity(cfg.trials as usize);
    for i in 1..=cfg.trials {
        eprintln!("  trial {i}/{}", cfg.trials);
        let hosts =
            run_trial(cfg, spec, plan, i).with_context(|| format!("trial {i} of {}", spec.name))?;
        trials.push(hosts);
    }

    let hosts = aggregate(&trials, &spec.first_party);
    let captured_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    Ok(Snapshot {
        server: spec.name.clone(),
        version: spec
            .version
            .clone()
            .unwrap_or_else(|| "unknown".to_string()),
        captured_at,
        trials: cfg.trials,
        flightplan: plan.fingerprint(),
        gurgl_version: env!("CARGO_PKG_VERSION").to_string(),
        hosts,
    })
}

/// Kill (and reap) a child when this guard drops, so an early return mid-trial
/// never leaks a mitmdump or server process.
struct KillOnDrop(Child);
impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Run one trial: start the proxy, launch the sandboxed server through it, drive
/// the flight plan over stdio, then read back the observed hosts.
fn run_trial(
    cfg: &Config,
    spec: &ServerSpec,
    plan: &FlightPlan,
    trial: u32,
) -> Result<Vec<FlowHost>> {
    // Per-trial scratch (its own flow file + addon copy).
    let tmp = std::env::temp_dir().join(format!(
        "gurgl-{}-{}-{}",
        sanitize(&spec.name),
        std::process::id(),
        trial
    ));
    std::fs::create_dir_all(&tmp).with_context(|| format!("creating {}", tmp.display()))?;
    let flows_path = tmp.join("flows.jsonl");
    let addon_path = tmp.join("mitm_flows.py");
    std::fs::write(&addon_path, proxy::FLOWS_ADDON).context("writing mitm addon")?;

    // Stable, isolated mitmproxy conf dir so the CA persists across runs.
    let confdir = mitm_confdir()?;
    std::fs::create_dir_all(&confdir).with_context(|| format!("creating {}", confdir.display()))?;
    let ca_path = confdir.join("mitmproxy-ca-cert.pem");

    // --- start the proxy ---
    let port = free_port()?;
    let proxy_argv = proxy::build_argv(
        &cfg.mitmdump,
        &addon_path.to_string_lossy(),
        &confdir.to_string_lossy(),
        port,
    );
    let proxy_child = Command::new(&proxy_argv[0])
        .args(&proxy_argv[1..])
        .env("GURGL_FLOWOUT", &flows_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .with_context(|| format!("spawning {}", cfg.mitmdump))?;
    let proxy_guard = KillOnDrop(proxy_child);

    wait_for_port(port, Duration::from_secs(20)).context("mitmdump did not start listening")?;
    wait_for_file(&ca_path, Duration::from_secs(15))
        .context("mitmproxy CA cert was not generated")?;

    // --- launch the sandboxed server, wired to the proxy ---
    let penv = sandbox::ProxyEnv {
        https_proxy: format!("http://127.0.0.1:{port}"),
        ca_cert_path: ca_path.to_string_lossy().to_string(),
        flowout_path: flows_path.to_string_lossy().to_string(),
    };
    let argv = sandbox::build_argv(cfg.sandbox, spec, &penv);
    let server = Command::new(&argv[0])
        .args(&argv[1..])
        .envs(penv.vars())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("spawning sandboxed '{}'", spec.command))?;
    let mut server_guard = KillOnDrop(server);

    // Take the pipes (guard already owns the child, so a failure here still kills it).
    let mut stdin = server_guard
        .0
        .stdin
        .take()
        .context("server stdin unavailable")?;
    let stdout = server_guard
        .0
        .stdout
        .take()
        .context("server stdout unavailable")?;
    if let Some(stderr) = server_guard.0.stderr.take() {
        thread::spawn(move || {
            for _ in BufReader::new(stderr).lines() { /* drain so the pipe never blocks */ }
        });
    }
    let rx = spawn_line_reader(stdout);

    // --- drive the flight plan, marking when each phase begins ---
    let mut phase_marks: Vec<(f64, String)> = Vec::new();
    let mut id: u64 = 0;
    let mut chosen_tool: Option<String> = None;

    for step in &plan.steps {
        phase_marks.push((now_epoch(), step.phase.clone()));
        match step.action.as_str() {
            "initialize" => {
                id += 1;
                send(&mut stdin, &mcp::initialize(id));
                let _ = read_response(&rx, id, Duration::from_secs(20));
                send(&mut stdin, &mcp::initialized());
            }
            "tools/list" => {
                id += 1;
                send(&mut stdin, &mcp::tools_list(id));
                if let Some(resp) = read_response(&rx, id, Duration::from_secs(20)) {
                    chosen_tool = pick_benign_tool(&resp, step.tool.as_deref());
                }
            }
            "tools/call" => {
                if let Some(tool) = step.tool.clone().or_else(|| chosen_tool.clone()) {
                    id += 1;
                    send(
                        &mut stdin,
                        &mcp::tools_call(id, &tool, &serde_json::json!({})),
                    );
                    let _ = read_response(&rx, id, Duration::from_secs(25));
                } else {
                    eprintln!("    (no benign tool to call; skipping tools/call step)");
                }
            }
            "sleep" => thread::sleep(Duration::from_secs(step.seconds.unwrap_or(5))),
            other => eprintln!("    (unknown flight-plan action '{other}', skipping)"),
        }
    }

    // --- tear down: close stdin, let requests flush, then kill (guards) ---
    drop(stdin);
    thread::sleep(Duration::from_millis(400));
    drop(server_guard);
    thread::sleep(Duration::from_millis(200));
    drop(proxy_guard);

    // --- read flows, attribute each host to a phase by timestamp ---
    let raw = proxy::parse_flows(&flows_path)?;
    let hosts = attribute_phases(raw, &phase_marks);
    let uniq: std::collections::BTreeSet<&String> = hosts.iter().map(|h| &h.host).collect();
    eprintln!("    observed {} host(s)", uniq.len());
    let _ = std::fs::remove_dir_all(&tmp);
    Ok(hosts)
}

/// De-duplicate raw flows to unique (host, phase) pairs.
fn attribute_phases(raw: Vec<RawFlow>, marks: &[(f64, String)]) -> Vec<FlowHost> {
    use std::collections::BTreeSet;
    let mut seen: BTreeSet<(String, String)> = BTreeSet::new();
    let mut out = Vec::new();
    for f in raw {
        let phase = phase_for(f.time, marks);
        if seen.insert((f.host.clone(), phase.clone())) {
            out.push(FlowHost {
                host: f.host,
                phase: Some(phase),
            });
        }
    }
    out
}

/// The phase whose window contains `t`: the last mark whose start <= t.
fn phase_for(t: f64, marks: &[(f64, String)]) -> String {
    let mut chosen = marks
        .first()
        .map(|m| m.1.clone())
        .unwrap_or_else(|| "session".to_string());
    for (start, phase) in marks {
        if *start <= t {
            chosen = phase.clone();
        } else {
            break;
        }
    }
    chosen
}

/// Choose a benign, read-only-looking tool to exercise. An explicit override
/// wins; otherwise prefer read-y names and never auto-pick a destructive one.
fn pick_benign_tool(resp: &Value, override_tool: Option<&str>) -> Option<String> {
    if let Some(t) = override_tool {
        return Some(t.to_string());
    }
    let tools = resp.get("result")?.get("tools")?.as_array()?;
    let names: Vec<String> = tools
        .iter()
        .filter_map(|t| t.get("name").and_then(|n| n.as_str()).map(String::from))
        .collect();

    const SAFE: &[&str] = &[
        "list", "get", "read", "search", "status", "info", "describe", "fetch", "ping",
    ];
    const UNSAFE: &[&str] = &[
        "delete", "remove", "write", "create", "update", "send", "exec", "run", "kill", "drop",
        "destroy", "put", "post", "move", "rename", "publish",
    ];
    let is_unsafe = |n: &str| {
        let l = n.to_lowercase();
        UNSAFE.iter().any(|u| l.contains(u))
    };

    if let Some(n) = names.iter().find(|n| {
        let l = n.to_lowercase();
        SAFE.iter().any(|s| l.contains(s)) && !is_unsafe(n)
    }) {
        return Some(n.clone());
    }
    names.into_iter().find(|n| !is_unsafe(n))
}

// ---- small process / IO helpers ---------------------------------------------

fn send(stdin: &mut impl Write, msg: &Value) {
    let _ = stdin.write_all(mcp::to_line(msg).as_bytes());
    let _ = stdin.flush();
}

fn spawn_line_reader(stdout: std::process::ChildStdout) -> Receiver<String> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            match line {
                Ok(l) => {
                    if tx.send(l).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });
    rx
}

/// Drain lines until one parses to a JSON-RPC object with the given id.
fn read_response(rx: &Receiver<String>, id: u64, timeout: Duration) -> Option<Value> {
    let deadline = Instant::now() + timeout;
    loop {
        let remaining = deadline.checked_duration_since(Instant::now())?;
        match rx.recv_timeout(remaining) {
            Ok(line) => {
                if let Ok(v) = serde_json::from_str::<Value>(line.trim()) {
                    if v.get("id").and_then(|i| i.as_u64()) == Some(id) {
                        return Some(v);
                    }
                }
            }
            Err(_) => return None,
        }
    }
}

fn free_port() -> Result<u16> {
    let listener =
        std::net::TcpListener::bind("127.0.0.1:0").context("binding an ephemeral port")?;
    Ok(listener.local_addr()?.port())
}

fn wait_for_port(port: u16, timeout: Duration) -> Result<()> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(150));
    }
    bail!("nothing listening on 127.0.0.1:{port} after {timeout:?}")
}

fn wait_for_file(path: &Path, timeout: Duration) -> Result<()> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if path.exists() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(150));
    }
    bail!("{} did not appear after {timeout:?}", path.display())
}

fn mitm_confdir() -> Result<PathBuf> {
    Ok(crate::config::gurgl_home().join("mitmproxy"))
}

fn now_epoch() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect()
}

fn on_path(bin: &str) -> bool {
    if bin.contains('/') {
        return std::path::Path::new(bin).is_file();
    }
    let Some(paths) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&paths).any(|dir| dir.join(bin).is_file())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{HostClass, Reproducibility};

    fn fh(host: &str, phase: &str) -> FlowHost {
        FlowHost {
            host: host.to_string(),
            phase: Some(phase.to_string()),
        }
    }

    #[test]
    fn reproduction_gate_marks_stable_vs_intermittent() {
        let trials = vec![
            vec![
                fh("api.example-vendor.com", "startup"),
                fh("featuregates.org", "startup"),
            ],
            vec![fh("api.example-vendor.com", "tool-call")],
            vec![
                fh("api.example-vendor.com", "idle"),
                fh("featuregates.org", "idle"),
            ],
        ];
        let first_party = vec!["example-vendor.com".to_string()];
        let hosts = aggregate(&trials, &first_party);

        let api = hosts
            .iter()
            .find(|h| h.name == "api.example-vendor.com")
            .unwrap();
        assert_eq!(api.reproducibility, Reproducibility::Stable); // 3/3
        assert_eq!(api.class, HostClass::FirstParty);
        assert_eq!(api.seen_in_trials, 3);

        let gate = hosts.iter().find(|h| h.name == "featuregates.org").unwrap();
        assert_eq!(gate.reproducibility, Reproducibility::Intermittent); // 2/3 -> cohort noise
        assert_eq!(gate.class, HostClass::Telemetry);
    }

    #[test]
    fn phases_unioned_within_a_trial() {
        let trials = vec![vec![
            fh("api.x.com", "startup"),
            fh("api.x.com", "tool-call"),
        ]];
        let hosts = aggregate(&trials, &[]);
        let h = hosts.iter().find(|h| h.name == "api.x.com").unwrap();
        assert_eq!(h.seen_in_trials, 1); // one host, counted once
        assert!(h.phases.contains(&"startup".to_string()));
        assert!(h.phases.contains(&"tool-call".to_string()));
    }

    #[test]
    fn phase_for_picks_last_started_window() {
        let marks = vec![
            (100.0, "startup".to_string()),
            (110.0, "tool-call".to_string()),
            (120.0, "idle".to_string()),
        ];
        assert_eq!(phase_for(105.0, &marks), "startup");
        assert_eq!(phase_for(115.0, &marks), "tool-call");
        assert_eq!(phase_for(130.0, &marks), "idle");
        assert_eq!(phase_for(90.0, &marks), "startup"); // before the first mark
    }

    #[test]
    fn attribute_phases_dedups_host_phase_pairs() {
        let marks = vec![
            (100.0, "startup".to_string()),
            (110.0, "tool-call".to_string()),
        ];
        let raw = vec![
            RawFlow {
                host: "a.com".into(),
                time: 101.0,
            },
            RawFlow {
                host: "a.com".into(),
                time: 102.0,
            }, // same host+phase -> deduped
            RawFlow {
                host: "a.com".into(),
                time: 111.0,
            }, // same host, new phase -> kept
        ];
        let out = attribute_phases(raw, &marks);
        assert_eq!(out.len(), 2);
    }
}
