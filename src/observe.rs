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
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use serde_json::Value;

use crate::config::{Config, ServerSpec};
use crate::flightplan::FlightPlan;
use crate::model::{classify, CaptureMode, Host, HostClass, Reproducibility, Snapshot};
use crate::proxy::{FlowHost, RawFlow};
use crate::report::{self, Reporter};
use crate::{mcp, pkgver, proxy, sandbox};

/// How long a `watch` runs.
#[derive(Debug, Clone, Copy)]
pub enum Monitor {
    /// The default: the repeated-trial battery (`cfg.trials` runs of the plan),
    /// so the reproduction gate can separate stable egress from cohort noise.
    Battery,
    /// One long observation: run the flight plan once, then hold in a live
    /// monitoring phase. `Some(d)` stops after `d`; `None` runs until Ctrl-C.
    Hold(Option<Duration>),
}

/// Process-wide "user asked us to stop" flag, set by a SIGINT handler (or the
/// dashboard's `q` key) so a running watch can break its loop, tear down, and
/// still save. Without this, Ctrl-C would kill us mid-capture and leave the
/// dashboard's alternate screen (and raw keyboard mode) active - Drop does not
/// run on an uncaught signal. A second Ctrl-C restores the default handler and
/// re-raises, as a hard-exit escape hatch if teardown ever wedges.
#[cfg(unix)]
mod interrupt {
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

    static STOP: AtomicBool = AtomicBool::new(false);
    /// SIGINTs received, counted separately from STOP: the dashboard's `q` also
    /// sets STOP, and must NOT make the next (first) Ctrl-C look like a second
    /// one and take the hard-exit path below.
    static SIGINTS: AtomicU32 = AtomicU32::new(0);

    extern "C" fn on_signal(sig: libc::c_int) {
        // Only async-signal-safe operations here: atomics, write(), tcsetattr(),
        // signal(), raise().
        STOP.store(true, Ordering::SeqCst);
        // SIGTERM/SIGHUP request the same clean stop as a first Ctrl-C: the
        // capture loop notices STOP at its next boundary, tears down (restoring
        // the terminal and reaping mitmdump/the server via Drop), and saves what
        // completed. Only SIGINT keeps the double-Ctrl-C hard-exit escape hatch,
        // for when teardown itself wedges.
        if sig == libc::SIGINT && SIGINTS.fetch_add(1, Ordering::SeqCst) >= 1 {
            crate::report::emergency_restore();
            unsafe {
                libc::signal(libc::SIGINT, libc::SIG_DFL);
                libc::raise(libc::SIGINT);
            }
        }
    }

    /// Install the stop handler for SIGINT and, crucially, SIGTERM/SIGHUP too.
    /// Without the latter, `kill`/terminal-close take the default terminate path
    /// with no Drop and no teardown, leaving the tty on the alternate screen in
    /// raw mode and orphaning mitmdump and the sandboxed server.
    pub fn install() {
        unsafe {
            let handler = on_signal as *const () as usize;
            libc::signal(libc::SIGINT, handler);
            libc::signal(libc::SIGTERM, handler);
            libc::signal(libc::SIGHUP, handler);
        }
    }

    pub fn request() {
        STOP.store(true, Ordering::SeqCst);
    }

    pub fn requested() -> bool {
        STOP.load(Ordering::SeqCst)
    }
}
#[cfg(not(unix))]
mod interrupt {
    use std::sync::atomic::{AtomicBool, Ordering};
    static STOP: AtomicBool = AtomicBool::new(false);
    pub fn install() {}
    pub fn request() {
        STOP.store(true, Ordering::SeqCst);
    }
    pub fn requested() -> bool {
        STOP.load(Ordering::SeqCst)
    }
}

/// Arrange for Ctrl-C to request a clean stop rather than kill the process.
pub fn arm_interrupt() {
    interrupt::install();
}

/// Request a clean stop, exactly as Ctrl-C would (used by the dashboard's `q`).
pub fn request_stop() {
    interrupt::request();
}

/// Whether a clean stop has been requested.
pub fn stop_requested() -> bool {
    interrupt::requested()
}

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
            // Count each host at most once per trial (for the reproduction gate)...
            if counted.insert(fh.host.as_str()) {
                entry.0 += 1;
            }
            // ...but union its phases across every occurrence in the trial.
            if let Some(phase) = &fh.phase {
                if !entry.1.contains(phase) {
                    entry.1.push(phase.clone());
                }
            }
        }
    }

    acc.into_iter()
        .map(|(name, (count, phases))| {
            // The reproduction gate needs at least two trials to mean anything:
            // with one observation a host is neither confirmed reproducible nor
            // provably cohort noise, so it is `Observed`, not `Stable`. This is
            // what keeps a `watch --for`/`--until-closed` hold (always one long
            // run) or a `trials = 1` config from reporting single sightings as
            // reproduced facts through diff/drift/allow.
            let reproducibility = if n < 2 {
                Reproducibility::Observed
            } else if count >= n {
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

/// Verify the backends this capture needs are available before we start. Every
/// failure prints the exact fix for THIS machine, not just what is missing.
pub fn preflight(cfg: &Config) -> Result<()> {
    let sandbox_bin = sandbox::required_binary(cfg.sandbox);
    if !on_path(sandbox_bin) {
        bail!(
            "sandbox backend '{sandbox_bin}' not found on PATH.\n  fix: {}\n  (or switch `sandbox` in gurgl.toml; see docs/INSTALL.md)",
            sandbox_fix(sandbox_bin)
        );
    }
    if !on_path(&cfg.mitmdump) {
        bail!(
            "proxy backend '{}' not found on PATH. mitmproxy provides it.\n  fix: {}\n  (re-running ./install.sh also sets this up; see docs/INSTALL.md)",
            cfg.mitmdump,
            mitmproxy_fix()
        );
    }
    Ok(())
}

/// The exact install command for the missing sandbox backend on this machine.
fn sandbox_fix(bin: &str) -> String {
    match bin {
        "bwrap" => {
            for (pm, cmd) in [
                ("apt-get", "sudo apt-get install -y bubblewrap"),
                ("dnf", "sudo dnf install -y bubblewrap"),
                ("pacman", "sudo pacman -S --noconfirm bubblewrap"),
                ("zypper", "sudo zypper install -y bubblewrap"),
            ] {
                if on_path(pm) {
                    return cmd.to_string();
                }
            }
            "install the 'bubblewrap' package with your distro's package manager".to_string()
        }
        "sandbox-exec" => {
            "sandbox-exec ships with macOS; its absence is unexpected. Check your PATH.".to_string()
        }
        "podman" => {
            "install podman (e.g. sudo apt-get install -y podman / brew install podman)".to_string()
        }
        other => format!("install '{other}' with your package manager"),
    }
}

/// The best available install route for mitmproxy on this machine, in the same
/// preference order install.sh uses (brew, pipx, then a dedicated venv).
fn mitmproxy_fix() -> String {
    if on_path("brew") {
        return "brew install mitmproxy".to_string();
    }
    if on_path("pipx") {
        return "pipx install mitmproxy".to_string();
    }
    "python3 -m venv ~/.gurgl/mitmproxy-venv && ~/.gurgl/mitmproxy-venv/bin/pip install mitmproxy \
     && ln -sf ~/.gurgl/mitmproxy-venv/bin/mitmdump ~/.gurgl/bin/mitmdump"
        .to_string()
}

/// Full capture of one server@version. `mode` selects the progress UI (a live
/// dashboard, or plain lines for pipes/scripts).
pub fn capture(
    cfg: &Config,
    spec: &ServerSpec,
    plan: &FlightPlan,
    mode: report::Mode,
    monitor: Monitor,
) -> Result<Snapshot> {
    // Preflight before taking over the terminal, so a missing-backend error
    // prints normally rather than inside the dashboard's alternate screen.
    preflight(cfg)?;
    // The server's own launch command is a runtime of the *target*, not of gurgl
    // (Node for `npx`, Python for `python3`/`uvx`, ...). Check it up front so a
    // missing one is a clear message, not a silent zero-host capture.
    if !on_path(&spec.command) {
        bail!(
            "server command '{}' not found on PATH. It is the runtime your MCP \
             server needs (e.g. Node for npx-based servers), not a gurgl \
             dependency. Install it and retry.",
            spec.command
        );
    }

    // Guarantee the starter config's scratch dir exists so `init && watch`
    // works out of the box. Host-side covers sandbox-exec (macOS, where /tmp is
    // the host's); bwrap creates it inside its tmpfs (see sandbox.rs).
    let _ = std::fs::create_dir_all(crate::config::SCRATCH_DIR);

    // Downloading launchers execute third-party code fetched at capture time.
    // Say so once, plainly - that behavior is surprising from a security tool
    // if left unstated. Printed before the dashboard takes the terminal.
    if matches!(spec.command.as_str(), "npx" | "uvx" | "pipx" | "bunx") {
        eprintln!(
            "note: '{}' runs `{} {}` inside the sandbox - this downloads and executes \
             third-party code as part of the capture.",
            spec.name,
            spec.command,
            spec.args.join(" ")
        );
    }

    // A timed / until-closed watch is a single long observation, not the
    // repeated-trial battery: running the plan N times for minutes each is not
    // what "watch for 5m" means, and the reproduction gate is moot with one run.
    let trial_count = match monitor {
        Monitor::Battery => cfg.trials.max(1),
        Monitor::Hold(_) => 1,
    };
    let mut reporter = report::reporter_for(mode, &spec.name, trial_count);

    let mut trials: Vec<Vec<FlowHost>> = Vec::with_capacity(trial_count as usize);
    let mut reported_version: Option<String> = None;
    let mut installed_version: Option<String> = None;
    for i in 1..=trial_count {
        if stop_requested() {
            break;
        }
        reporter.trial_start(i, trial_count);
        let trial = run_trial(cfg, spec, plan, i, monitor, reporter.as_mut())
            .with_context(|| format!("trial {i} of {}", spec.name))?;
        if reported_version.is_none() {
            reported_version = trial.server_version;
        }
        // The installed version must be consistent across the battery. If two
        // trials resolved DIFFERENT versions, the registry re-released mid-capture
        // and aggregating them would blend two codebases under one label - exactly
        // what the reproduction gate exists to prevent. Bail rather than mislabel.
        if let Some(iv) = trial.installed_version {
            match &installed_version {
                None => installed_version = Some(iv),
                Some(prev) if *prev != iv => bail!(
                    "'{}' resolved different installed versions across trials ({prev} then {iv}) - \
                     a package re-release mid-capture would mix two codebases under one version \
                     label; re-run the capture.",
                    spec.name
                ),
                _ => {}
            }
        }
        // A trial cut short by a stop request is discarded in battery mode: the
        // reproduction gate compares complete runs of the same plan, and a
        // partial run would mark every host it missed as intermittent. A Hold
        // observation is one long session by definition, so it always counts.
        // (run_trial already surfaced the note.)
        if !trial.completed && matches!(monitor, Monitor::Battery) {
            break;
        }
        let uniq: std::collections::BTreeSet<&String> =
            trial.hosts.iter().map(|h| &h.host).collect();
        reporter.trial_end(i, uniq.len());
        trials.push(trial.hosts);
    }

    if trials.is_empty() {
        bail!(
            "stopped before any complete trial of {} - nothing captured",
            spec.name
        );
    }
    let completed_trials = trials.len() as u32;
    let hosts = aggregate(&trials, &spec.first_party);
    let captured_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    // Version precedence: config label > the version the launcher actually
    // installed > the server's self-reported (attacker-chosen) serverInfo.version
    // > "unknown". Deriving from the installed package is what stops a lying
    // serverInfo from being the storage key. See resolve_version.
    let (version, version_source) = resolve_version(
        spec.version.as_deref(),
        installed_version.as_deref(),
        reported_version.as_deref(),
    );

    // Surface a discrepancy neutrally (not an accusation): a package that
    // self-reports one version while installing as another is worth seeing.
    let reported_display = reported_version
        .as_deref()
        .map(sanitize_version)
        .filter(|v| !v.is_empty());
    if let (Some(inst), Some(rep)) = (installed_version.as_deref(), reported_display.as_deref()) {
        let inst = sanitize_version(inst);
        if !inst.is_empty() && inst != rep {
            reporter.note(&format!(
                "version note: '{}' self-reports {rep} but the installed package resolved to {inst}",
                spec.name
            ));
        }
    }

    let snapshot = Snapshot {
        server: spec.name.clone(),
        version,
        captured_at,
        trials: completed_trials,
        flightplan: plan.fingerprint(),
        gurgl_version: env!("CARGO_PKG_VERSION").to_string(),
        // env-proxy is the only implemented capture strategy today; the forced
        // backend (netns + transparent redirect) will stamp Forced here once it
        // lands. Stamp what was actually run, never what was requested.
        capture_mode: CaptureMode::EnvProxy,
        reported_version: reported_display,
        version_source: Some(version_source.as_str().to_string()),
        hosts,
    };
    reporter.finish(&snapshot);
    Ok(snapshot)
}

/// Where a snapshot's `version` came from, in precedence order.
enum VersionSource {
    Config,
    InstalledPackage,
    ServerReported,
    Unknown,
}

impl VersionSource {
    fn as_str(&self) -> &'static str {
        match self {
            VersionSource::Config => "config",
            VersionSource::InstalledPackage => "installed-package",
            VersionSource::ServerReported => "server-reported",
            VersionSource::Unknown => "unknown",
        }
    }
}

/// Resolve the storage version and record where it came from. Precedence: an
/// explicit config label, else the version the launcher actually installed, else
/// the server's self-reported (attacker-chosen) serverInfo.version, else
/// "unknown". A value that sanitizes to empty is skipped, not used. Pure.
fn resolve_version(
    config: Option<&str>,
    installed: Option<&str>,
    reported: Option<&str>,
) -> (String, VersionSource) {
    for (val, src) in [
        (config, VersionSource::Config),
        (installed, VersionSource::InstalledPackage),
        (reported, VersionSource::ServerReported),
    ] {
        if let Some(v) = val {
            let s = sanitize_version(v);
            if !s.is_empty() {
                return (s, src);
            }
        }
    }
    ("unknown".to_string(), VersionSource::Unknown)
}

/// One tool the server advertised in `tools/list`, for `gurgl plan` scaffolding.
pub struct ToolDef {
    pub name: String,
    pub description: Option<String>,
    /// The tool's JSON-Schema `inputSchema` (or Null if it declared none).
    pub input_schema: Value,
}

/// Launch the server ONCE in the sandbox WITHOUT a proxy, drive initialize +
/// tools/list over stdio, and return the advertised tools. Used by `gurgl plan`
/// to scaffold a draft flight plan - it captures nothing and needs no mitmdump.
/// gurgl makes no network call of its own; the server's own egress (e.g. npx
/// downloading the package) is the server's, disclosed the same way `watch` does.
pub fn enumerate_tools(cfg: &Config, spec: &ServerSpec) -> Result<Vec<ToolDef>> {
    // Light preflight: the sandbox backend and the server's own launcher - NOT
    // mitmdump, since enumeration runs no proxy.
    let sandbox_bin = sandbox::required_binary(cfg.sandbox);
    if !on_path(sandbox_bin) {
        bail!(
            "sandbox backend '{sandbox_bin}' not found on PATH.\n  fix: {}",
            sandbox_fix(sandbox_bin)
        );
    }
    if !on_path(&spec.command) {
        bail!(
            "server command '{}' not found on PATH - it is the runtime your MCP server \
             needs (e.g. Node for npx), not a gurgl dependency.",
            spec.command
        );
    }
    if matches!(spec.command.as_str(), "npx" | "uvx" | "pipx" | "bunx") {
        eprintln!(
            "note: '{}' runs `{} {}` inside the sandbox to list its tools - this downloads \
             and executes third-party code (no capture, no proxy).",
            spec.name,
            spec.command,
            spec.args.join(" ")
        );
    }
    // The stock filesystem server needs its allowed dir to exist; mirror capture.
    let _ = std::fs::create_dir_all(crate::config::SCRATCH_DIR);

    // Opt-in pass_env (a server may need an API key to start), minus anything
    // reserved - the same filter capture uses.
    let mut extra_env: Vec<(String, String)> = Vec::new();
    for k in &spec.pass_env {
        if is_capture_reserved(k) {
            continue;
        }
        if let Ok(v) = std::env::var(k) {
            extra_env.push((k.clone(), v));
        }
    }

    // env=None: no CA, no proxy vars, base env - the server runs against the real
    // network so it can start (npx download, live init), which is fine here.
    let argv = sandbox::build_argv(cfg.sandbox, spec, None, &extra_env);
    let scratch = ScratchDir::new(&format!("plan-{}", spec.name))?;
    let mut cmd = Command::new(&argv[0]);
    cmd.args(&argv[1..]);
    if matches!(cfg.sandbox, crate::config::SandboxKind::SandboxExec) {
        // sandbox-exec inherits this process's env, so clear it and set the base
        // env + a writable HOME (bwrap/podman set HOME via argv instead).
        cmd.env_clear();
        for (k, v) in sandbox::base_env() {
            cmd.env(k, v);
        }
        for (k, v) in &extra_env {
            cmd.env(k, v);
        }
        cmd.env("HOME", scratch.path());
    }
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    unsafe {
        use std::os::unix::process::CommandExt;
        cmd.pre_exec(|| {
            libc::setpgid(0, 0);
            Ok(())
        });
    }
    let server = cmd
        .spawn()
        .with_context(|| format!("spawning sandboxed '{}'", spec.command))?;
    let mut guard = KillOnDrop::group(server);
    let mut stdin = guard
        .child
        .stdin
        .take()
        .context("server stdin unavailable")?;
    let stdout = guard
        .child
        .stdout
        .take()
        .context("server stdout unavailable")?;
    let stderr_tail = drain_stderr_tail(guard.child.stderr.take());
    let rx = spawn_line_reader(stdout);

    let mut id = 1u64;
    send(&mut stdin, &mcp::initialize(id));
    if read_response(&rx, id, Duration::from_secs(60)).is_none() {
        if let Ok(Some(status)) = guard.try_wait() {
            bail!("{}", dead_server_msg(&status, "initialize", &stderr_tail));
        }
        let tail = stderr_tail
            .lock()
            .map(|g| g.iter().cloned().collect::<Vec<_>>().join("\n"))
            .unwrap_or_default();
        bail!(
            "'{}' did not respond to initialize within 60s; it may need pass_env vars or \
             network to start.{}",
            spec.name,
            if tail.trim().is_empty() {
                String::new()
            } else {
                format!("\n  server stderr (tail):\n{tail}")
            }
        );
    }
    send(&mut stdin, &mcp::initialized());
    id += 1;
    send(&mut stdin, &mcp::tools_list(id));
    let resp = read_response(&rx, id, Duration::from_secs(30)).with_context(|| {
        format!(
            "'{}' did not answer tools/list; cannot scaffold a plan",
            spec.name
        )
    })?;
    let tools = resp
        .get("result")
        .and_then(|r| r.get("tools"))
        .and_then(|t| t.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|t| {
                    let name = t.get("name").and_then(|n| n.as_str())?.to_string();
                    Some(ToolDef {
                        name,
                        description: t
                            .get("description")
                            .and_then(|d| d.as_str())
                            .map(String::from),
                        input_schema: t.get("inputSchema").cloned().unwrap_or(Value::Null),
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    drop(stdin);
    drop(guard); // kills the server tree
    drop(scratch);
    Ok(tools)
}

/// Kill (and reap) a child when this guard drops, so an early return mid-trial
/// never leaks a mitmdump or server process. When `group` is set (the sandboxed
/// server, which pre_exec'd into its own process group), SIGKILL the whole group
/// first: on macOS sandbox-exec execs the launcher in-process and the real MCP
/// server runs as a grandchild that a single-PID kill would orphan. On
/// Linux/bwrap `--die-with-parent` + `--unshare-pid` already tear down the tree,
/// so the group kill is a harmless belt-and-suspenders there.
struct KillOnDrop {
    child: Child,
    group: bool,
    /// Set once a caller's `try_wait` has reaped the child: its pid may then be
    /// recycled, so Drop must NOT signal the (possibly reused) process group.
    reaped: bool,
}

impl KillOnDrop {
    fn direct(child: Child) -> Self {
        Self {
            child,
            group: false,
            reaped: false,
        }
    }
    fn group(child: Child) -> Self {
        Self {
            child,
            group: true,
            reaped: false,
        }
    }
    /// try_wait, recording when the child has been reaped so Drop does not later
    /// signal a possibly-recycled pid. Prefer this over `self.child.try_wait()`.
    fn try_wait(&mut self) -> std::io::Result<Option<std::process::ExitStatus>> {
        let r = self.child.try_wait();
        if let Ok(Some(_)) = r {
            self.reaped = true;
        }
        r
    }
}

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        // Already reaped (a caller's try_wait saw it exit): the pid may already be
        // recycled by the OS, so the group signal below could hit an unrelated
        // process group. Once the leader is reaped the tree is gone, so there is
        // nothing left to kill - skip it.
        if self.reaped {
            return;
        }
        #[cfg(unix)]
        if self.group {
            // The child is a group leader (setpgid(0,0) in pre_exec), so its pid
            // is the pgid; a negative target signals the whole group, catching
            // grandchildren the direct kill below would miss.
            let pid = self.child.id() as libc::pid_t;
            unsafe {
                libc::kill(-pid, libc::SIGKILL);
            }
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A per-trial scratch dir removed when this guard drops - on EVERY exit path
/// (error, stop, early return), not just the success path. Created with
/// `create_dir` (never create_dir_all): if the path already exists - a planted
/// symlink, or a racing local attacker - creation fails atomically instead of
/// following it. With the unpredictable suffix and 0700 mode, this closes the
/// symlink / addon-substitution window on the world-writable /tmp.
struct ScratchDir(PathBuf);

impl ScratchDir {
    fn new(name_hint: &str) -> Result<Self> {
        let dir = std::env::temp_dir().join(format!(
            "gurgl-{}-{}-{}",
            sanitize(name_hint),
            std::process::id(),
            rand_token()
        ));
        std::fs::create_dir(&dir)
            .with_context(|| format!("creating scratch dir {}", dir.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
        }
        Ok(ScratchDir(dir))
    }
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// An unpredictable per-trial suffix so the scratch path cannot be pre-created
/// to hijack or DoS the capture. /dev/urandom on unix; a time/pid/counter mix
/// otherwise (uniqueness still holds; only unpredictability is lost).
fn rand_token() -> String {
    #[cfg(unix)]
    {
        use std::io::Read;
        if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
            let mut buf = [0u8; 8];
            if f.read_exact(&mut buf).is_ok() {
                return buf.iter().map(|b| format!("{b:02x}")).collect();
            }
        }
    }
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{t:x}-{n:x}")
}

/// One trial's outcome.
struct Trial {
    hosts: Vec<FlowHost>,
    /// The server's self-reported version (from `initialize`), if any.
    server_version: Option<String>,
    /// The version the launcher actually resolved into the sandbox HOME, read
    /// from local files after teardown (`pkgver`). `None` for a non-launcher
    /// command or an unrecognized cache layout.
    installed_version: Option<String>,
    /// False when a stop request cut the flight plan short mid-steps.
    completed: bool,
}

/// Run one trial: start the proxy, launch the sandboxed server through it, drive
/// the flight plan over stdio, then read back the observed hosts.
/// Names gurgl sets to route the sandboxed server's egress through the capture
/// proxy and trust the lab CA. A pass_env entry colliding with any of these would
/// override the capture wiring (routing around mitmdump, or re-enabling a
/// NO_PROXY bypass), silently emptying the capture - so pass_env must not forward
/// them. Compared case-insensitively (proxy vars are honored in both cases).
fn is_capture_reserved(name: &str) -> bool {
    const RESERVED: &[&str] = &[
        "PATH",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
        "NODE_USE_ENV_PROXY",
        "NODE_EXTRA_CA_CERTS",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "REQUESTS_CA_BUNDLE",
        "CURL_CA_BUNDLE",
    ];
    RESERVED.iter().any(|r| r.eq_ignore_ascii_case(name))
}

/// Upper bound on a flight-plan `sleep` step, so a hostile or fat-fingered plan
/// (`seconds` near u64::MAX) cannot overflow `Instant + Duration` (which panics).
/// A sleep step is a short idle window; long observation is `watch --for`.
const MAX_SLEEP_SECS: u64 = 24 * 60 * 60;

fn run_trial(
    cfg: &Config,
    spec: &ServerSpec,
    plan: &FlightPlan,
    trial: u32,
    monitor: Monitor,
    reporter: &mut dyn Reporter,
) -> Result<Trial> {
    // Per-trial scratch (its own flow file + addon copy). ScratchDir creates it
    // with O_EXCL-equivalent semantics (fails rather than following a planted
    // symlink), owner-only, and removes it on EVERY exit path via Drop.
    let scratch = ScratchDir::new(&format!("{}-{}", spec.name, trial))?;
    let tmp = scratch.path();
    let flows_path = tmp.join("flows.jsonl");
    let addon_path = tmp.join("mitm_flows.py");
    std::fs::write(&addon_path, proxy::FLOWS_ADDON).context("writing mitm addon")?;

    // The sandbox HOME is a host-side dir (inside this trial's scratch, so it is
    // 0700 and removed on Drop with everything else). Binding it as HOME lets the
    // package manager's resolved install land on host-readable disk that survives
    // teardown, so pkgver can read the real installed version below.
    let home_dir = tmp.join("home");
    std::fs::create_dir(&home_dir)
        .with_context(|| format!("creating sandbox home {}", home_dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&home_dir, std::fs::Permissions::from_mode(0o700));
    }

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
    let mut proxy_child = Command::new(&proxy_argv[0])
        .args(&proxy_argv[1..])
        .env("GURGL_FLOWOUT", &flows_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("spawning {}", cfg.mitmdump))?;
    // Keep mitmdump's stderr tail. A dead or misconfigured proxy is the classic
    // way a capture silently records nothing and then reads as "no egress"; its
    // last lines are the diagnosis. Discarding them (the old Stdio::null) is
    // what made proxy failure invisible.
    let proxy_stderr_tail = drain_stderr_tail(proxy_child.stderr.take());
    let mut proxy_guard = KillOnDrop::direct(proxy_child);

    wait_for_port(port, Duration::from_secs(20))
        .with_context(|| proxy_start_failure(&proxy_stderr_tail))?;
    wait_for_file(&ca_path, Duration::from_secs(15))
        .context("mitmproxy CA cert was not generated")?;

    // --- launch the sandboxed server, wired to the proxy ---
    let penv = sandbox::ProxyEnv {
        https_proxy: format!("http://127.0.0.1:{port}"),
        ca_cert_path: ca_path.to_string_lossy().to_string(),
        sandbox_home: home_dir.to_string_lossy().to_string(),
    };
    // Forward only the env vars this server explicitly opted into (pass_env),
    // read from gurgl's own environment. The sandbox is otherwise env-cleared so
    // untrusted server code never inherits gurgl's whole environment.
    let mut extra_env: Vec<(String, String)> = Vec::new();
    for k in &spec.pass_env {
        // pass_env must never smuggle in a variable that would redirect or
        // un-capture the sandbox's egress. Forwarding a machine's corporate
        // HTTPS_PROXY/NO_PROXY (or a CA/PATH override) would silently override the
        // capture proxy/CA gurgl set - the child would route around mitmdump and
        // the snapshot would read as "no egress". bwrap/podman apply extra_env
        // AFTER the capture env (last --setenv / -e wins), so without this filter
        // the forwarded var wins on Linux. Drop those names; note once.
        if is_capture_reserved(k) {
            if trial == 1 {
                reporter.note(&format!(
                    "ignoring pass_env '{k}': forwarding it would override gurgl's \
                     capture proxy/CA and blind the capture"
                ));
            }
            continue;
        }
        if let Ok(v) = std::env::var(k) {
            extra_env.push((k.clone(), v));
        }
    }
    let argv = sandbox::build_argv(cfg.sandbox, spec, Some(&penv), &extra_env);
    let mut cmd = Command::new(&argv[0]);
    cmd.args(&argv[1..]);
    // bwrap (--clearenv) and podman (-e only) isolate the child's environment via
    // argv. sandbox-exec's child inherits THIS process's environment, so clear it
    // and set only the capture env plus the forwarded pass_env.
    if matches!(cfg.sandbox, crate::config::SandboxKind::SandboxExec) {
        cmd.env_clear();
        for (k, v) in &extra_env {
            cmd.env(k, v);
        }
        // bwrap/podman set HOME via argv; sandbox-exec's env is applied here, so
        // point HOME at the host-side scratch home (macOS /tmp is the host's, so
        // no bind-mount remap - HOME is the real path) for version derivation.
        if !penv.sandbox_home.is_empty() {
            cmd.env("HOME", &penv.sandbox_home);
        }
    }
    cmd.envs(penv.vars())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // Put the sandboxed server in its own process group so KillOnDrop::group can
    // reap the whole tree - on macOS, sandbox-exec runs the real server as a
    // grandchild a single-PID kill would orphan. setpgid is async-signal-safe,
    // as pre_exec requires.
    #[cfg(unix)]
    unsafe {
        use std::os::unix::process::CommandExt;
        cmd.pre_exec(|| {
            libc::setpgid(0, 0);
            Ok(())
        });
    }
    let server = cmd
        .spawn()
        .with_context(|| format!("spawning sandboxed '{}'", spec.command))?;
    let mut server_guard = KillOnDrop::group(server);

    // Take the pipes (guard already owns the child, so a failure here still kills it).
    let mut stdin = server_guard
        .child
        .stdin
        .take()
        .context("server stdin unavailable")?;
    let stdout = server_guard
        .child
        .stdout
        .take()
        .context("server stdout unavailable")?;
    // Keep the tail of the server's stderr (drained so the pipe never blocks):
    // when the server dies mid-capture, its last lines are the diagnosis.
    let stderr_tail = drain_stderr_tail(server_guard.child.stderr.take());
    let rx = spawn_line_reader(stdout);

    // --- drive the flight plan, marking when each phase begins ---
    let mut phase_marks: Vec<(f64, String)> = Vec::new();
    let mut id: u64 = 0;
    let mut chosen_tool: Option<String> = None;
    // The server's self-reported version from its `initialize` response.
    let mut server_version: Option<String> = None;
    // Hosts already surfaced to the reporter this trial (so the live view shows
    // each once as it first appears).
    let mut surfaced: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();

    for step in &plan.steps {
        // A stop request (Ctrl-C, or `q` in the dashboard) ends the plan at the
        // next step boundary; the sleep/monitor loops below also check per tick.
        // Note here (not in capture()): the trial teardown below leaves time for
        // the dashboard to actually paint it before the screen is restored.
        if stop_requested() {
            break;
        }
        // A live server AND a live proxy are preconditions for a trustworthy
        // capture, in EVERY mode. A server that crashes at launch (missing API
        // key, bad runtime) would otherwise "complete" every step via timeouts
        // and save an EMPTY snapshot reading as "no egress observed"; a dead
        // proxy drops egress the same silent way. Both become errors carrying
        // their stderr tail, never a false-clean snapshot. Hold mode's softer
        // server exit is allowed only later, in the monitor phase, once the
        // scripted plan has actually run.
        if let Ok(Some(status)) = server_guard.try_wait() {
            bail!("{}", dead_server_msg(&status, &step.phase, &stderr_tail));
        }
        check_proxy_alive(&mut proxy_guard.child, &step.phase, &proxy_stderr_tail)?;
        phase_marks.push((now_epoch(), step.phase.clone()));
        reporter.phase(&step.phase);
        match step.action.as_str() {
            "initialize" => {
                id += 1;
                send(&mut stdin, &mcp::initialize(id));
                if let Some(resp) = read_response(&rx, id, Duration::from_secs(20)) {
                    server_version = resp
                        .get("result")
                        .and_then(|r| r.get("serverInfo"))
                        .and_then(|s| s.get("version"))
                        .and_then(|v| v.as_str())
                        .map(str::to_string);
                }
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
                    send(&mut stdin, &mcp::tools_call(id, &tool, &step.tool_args()));
                    let _ = read_response(&rx, id, Duration::from_secs(25));
                } else {
                    reporter.note("no benign tool to call; skipping tools/call step");
                }
            }
            // Poll during the idle sleep too, so late beacons stream in live.
            "sleep" => {
                // Cap the sleep so a near-u64::MAX `seconds` cannot overflow
                // Instant + Duration (which panics); see MAX_SLEEP_SECS.
                let secs = step.seconds.unwrap_or(5).min(MAX_SLEEP_SECS);
                let end = Instant::now() + Duration::from_secs(secs);
                while Instant::now() < end && !stop_requested() {
                    thread::sleep(Duration::from_millis(200));
                    surface_hosts(
                        &flows_path,
                        &step.phase,
                        &spec.first_party,
                        &mut surfaced,
                        reporter,
                    );
                }
            }
            other => reporter.note(&format!("unknown flight-plan action '{other}', skipping")),
        }
        surface_hosts(
            &flows_path,
            &step.phase,
            &spec.first_party,
            &mut surfaced,
            reporter,
        );
    }

    // Catch a crash during the plan's FINAL step too (the boundary check above
    // only runs before each step): a dead server did not complete the method.
    let last_phase = phase_marks
        .last()
        .map(|(_, p)| p.as_str())
        .unwrap_or("startup");
    if !stop_requested() {
        // A dead proxy at the end means the flows we hold may be incomplete, in
        // any mode - never save that as a snapshot.
        check_proxy_alive(&mut proxy_guard.child, last_phase, &proxy_stderr_tail)?;
        if matches!(monitor, Monitor::Battery) {
            if let Ok(Some(status)) = server_guard.try_wait() {
                bail!("{}", dead_server_msg(&status, last_phase, &stderr_tail));
            }
        }
    }

    // The trial is complete only if no stop arrived while the plan ran: a stop
    // can cut ANY step short (sleep breaks per tick, responses return early),
    // including the last one, so "reached the end of the loop" is not enough.
    // Evaluated before the Hold below, where a stop is the normal way out.
    let completed = !stop_requested();
    if !completed {
        // The trial teardown below sleeps long enough for the dashboard's
        // render thread to actually paint this before the screen is restored.
        if matches!(monitor, Monitor::Battery) {
            reporter.note("stopping; discarding the partial trial");
        } else {
            reporter.note("stopping; saving what was captured");
        }
    }

    // --- optional live monitoring hold (watch --for / --until-closed) ---
    // After the scripted plan, keep the server up and stream egress for a fixed
    // time or until Ctrl-C, so you can watch what it beacons at rest.
    if let Monitor::Hold(dur) = monitor {
        let phase = "monitor";
        phase_marks.push((now_epoch(), phase.to_string()));
        reporter.phase(phase);
        let start = Instant::now();
        loop {
            if stop_requested() {
                reporter.note("stopping; saving what was captured");
                break;
            }
            if let Some(d) = dur {
                if start.elapsed() >= d {
                    break;
                }
            }
            // If the server exits on its own, there is nothing left to watch.
            if matches!(server_guard.try_wait(), Ok(Some(_))) {
                reporter.note("server process exited; ending watch");
                break;
            }
            // A dead proxy during the hold is a fidelity failure, not a normal
            // end: error out rather than keep "watching" blind.
            check_proxy_alive(&mut proxy_guard.child, phase, &proxy_stderr_tail)?;
            thread::sleep(Duration::from_millis(200));
            surface_hosts(
                &flows_path,
                phase,
                &spec.first_party,
                &mut surfaced,
                reporter,
            );
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
    // Derive the version the launcher actually resolved: read from the sandbox
    // HOME (host bind, still populated now that the server is dead but before
    // `scratch` drops). Local reads only; a miss is None and the caller falls
    // back to serverInfo/unknown - a layout we don't recognize never errors.
    let installed_version = pkgver::package_from_args(&spec.command, &spec.args)
        .and_then(|pkg| pkgver::installed_version(&spec.command, &pkg, &home_dir));
    // `scratch` (the ScratchDir guard) removes the temp dir on drop at end of
    // scope, including every early-return above - no manual cleanup needed.
    Ok(Trial {
        hosts,
        server_version,
        installed_version,
        completed,
    })
}

/// Compose the error for a server that died mid-plan: what exited, when, its
/// last stderr lines (the actual diagnosis), and the likeliest fixes. This is
/// an error, not an observation - saving an empty snapshot here would read as
/// "no egress observed", which would be false.
fn dead_server_msg(
    status: &std::process::ExitStatus,
    phase: &str,
    stderr_tail: &Mutex<std::collections::VecDeque<String>>,
) -> String {
    format!(
        "server exited ({status}) mid-capture (detected at '{phase}') - nothing was \
         captured (an empty snapshot would falsely read as \"no egress observed\").{}\n  \
         common causes: the server needs env vars (often API keys) from its client config, \
         which gurgl does not copy - set them in gurgl's environment; or its \
         runtime/arguments are wrong for this machine.",
        stderr_diag(stderr_tail)
    )
}

/// Compose the error for a capture proxy that died mid-capture. A dead mitmdump
/// means some egress may have gone unrecorded, so the trial is void: reporting
/// an empty snapshot here would be a false "no egress observed".
fn proxy_dead_msg(
    status: &std::process::ExitStatus,
    phase: &str,
    tail: &Mutex<std::collections::VecDeque<String>>,
) -> String {
    format!(
        "capture proxy (mitmdump) exited ({status}) mid-capture (detected at '{phase}') - the \
         trial cannot be trusted: some egress may have gone unrecorded, which an empty snapshot \
         would falsely read as \"no egress observed\".{}\n  common causes: a stale mitmproxy \
         after a Python upgrade (reinstall: {}), the listen port was taken by another process, \
         or the addon failed to load.",
        stderr_diag(tail),
        mitmproxy_fix()
    )
}

/// Error out if the capture proxy has already exited on its own. Called at every
/// step boundary and during the hold, so a dead proxy stops the trial with a
/// diagnosis instead of yielding a silent, empty, false-clean capture.
fn check_proxy_alive(
    proxy: &mut Child,
    phase: &str,
    tail: &Mutex<std::collections::VecDeque<String>>,
) -> Result<()> {
    if let Ok(Some(status)) = proxy.try_wait() {
        bail!("{}", proxy_dead_msg(&status, phase, tail));
    }
    Ok(())
}

/// Context for `wait_for_port` failing to see mitmdump come up: fold in its
/// stderr so a broken install reads as a fixable diagnosis, not "nothing
/// listening".
fn proxy_start_failure(tail: &Mutex<std::collections::VecDeque<String>>) -> String {
    format!(
        "mitmdump did not start listening.{}\n  reinstall it with: {}",
        stderr_diag(tail),
        mitmproxy_fix()
    )
}

/// Spawn a thread draining a child's stderr into a bounded tail (its last 8
/// lines) so the pipe never blocks the child and the last lines survive to
/// diagnose a mid-capture death. Shared by the server and the proxy.
fn drain_stderr_tail(
    stderr: Option<impl std::io::Read + Send + 'static>,
) -> std::sync::Arc<Mutex<std::collections::VecDeque<String>>> {
    let tail = std::sync::Arc::new(Mutex::new(std::collections::VecDeque::new()));
    if let Some(stderr) = stderr {
        let t = tail.clone();
        thread::spawn(move || {
            let mut r = BufReader::new(stderr);
            let mut line = String::new();
            while let Ok(n) = read_capped_line(&mut r, &mut line) {
                if n == 0 {
                    break; // EOF
                }
                let mut g = t.lock().unwrap_or_else(|e| e.into_inner());
                if g.len() >= 8 {
                    g.pop_front();
                }
                g.push_back(std::mem::take(&mut line));
            }
        });
    }
    tail
}

/// The "last stderr lines" fragment shared by the dead-server and dead-proxy
/// diagnostics.
fn stderr_diag(tail: &Mutex<std::collections::VecDeque<String>>) -> String {
    let lines: Vec<String> = tail
        .lock()
        .map(|t| t.iter().rev().take(3).rev().cloned().collect())
        .unwrap_or_default();
    if lines.is_empty() {
        String::from(" It printed nothing on stderr.")
    } else {
        format!("\n  its last stderr lines:\n    {}", lines.join("\n    "))
    }
}

/// Make a server-reported version safe to use as a snapshot filename, keeping
/// version-y characters and replacing anything else.
fn sanitize_version(v: &str) -> String {
    v.trim()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '+') {
                c
            } else {
                '-'
            }
        })
        .collect()
}

/// Read the flow file mid-capture and hand any not-yet-seen hosts to the
/// reporter (so the dashboard streams hosts as they appear). Tolerant of a
/// partially written file: a failed parse just means we catch them next tick.
fn surface_hosts(
    flows_path: &Path,
    phase: &str,
    first_party: &[String],
    surfaced: &mut std::collections::BTreeSet<String>,
    reporter: &mut dyn Reporter,
) {
    if let Ok(raw) = proxy::parse_flows(flows_path) {
        for f in raw {
            if surfaced.insert(f.host.clone()) {
                let class: HostClass = classify(&f.host, first_party);
                reporter.host(&f.host, class, phase);
            }
        }
    }
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
/// Whether a tool NAME looks state-changing under a purely lexical heuristic.
/// This is a heuristic on the name only (never a safety verdict about the tool):
/// `pick_benign_tool` uses it to avoid calling destructive tools during capture,
/// and `gurgl plan` uses it to skip them when scaffolding a draft flight plan.
pub(crate) fn tool_looks_unsafe(name: &str) -> bool {
    const UNSAFE: &[&str] = &[
        "delete", "remove", "write", "create", "update", "send", "exec", "run", "kill", "drop",
        "destroy", "put", "post", "move", "rename", "publish",
    ];
    let l = name.to_lowercase();
    UNSAFE.iter().any(|u| l.contains(u))
}

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

    if let Some(n) = names.iter().find(|n| {
        let l = n.to_lowercase();
        SAFE.iter().any(|s| l.contains(s)) && !tool_looks_unsafe(n)
    }) {
        return Some(n.clone());
    }
    names.into_iter().find(|n| !tool_looks_unsafe(n))
}

// ---- small process / IO helpers ---------------------------------------------

/// Cap on a single line buffered from a child's stdout/stderr. The observed
/// server is attacker-influenced (CLAUDE.md): a stream with no '\n' would make
/// `BufRead::lines()` grow one String without bound until gurgl is OOM-killed.
/// The JSON-RPC lines gurgl needs are tiny, so this is orders of magnitude over
/// any real line.
const MAX_LINE: usize = 1 << 20; // 1 MiB

/// Read one '\n'-terminated line from `r` into `out`, buffering at most MAX_LINE
/// bytes: excess bytes are consumed (so we resync at the next newline) but never
/// retained, so a hostile or oversized line cannot exhaust memory. Returns the
/// number of bytes consumed (0 only at EOF with nothing left). Invalid UTF-8 is
/// replaced lossily. Uses only BufRead so a pipe is not read byte-by-byte.
fn read_capped_line(r: &mut impl BufRead, out: &mut String) -> std::io::Result<usize> {
    out.clear();
    let mut buf: Vec<u8> = Vec::new();
    let mut total = 0usize;
    loop {
        let available = match r.fill_buf() {
            Ok(b) => b,
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        if available.is_empty() {
            break; // EOF
        }
        match available.iter().position(|&b| b == b'\n') {
            Some(i) => {
                let take = MAX_LINE.saturating_sub(buf.len()).min(i);
                buf.extend_from_slice(&available[..take]);
                total += i + 1;
                r.consume(i + 1);
                break;
            }
            None => {
                let n = available.len();
                let take = MAX_LINE.saturating_sub(buf.len()).min(n);
                buf.extend_from_slice(&available[..take]);
                total += n;
                r.consume(n);
            }
        }
    }
    if total == 0 {
        return Ok(0);
    }
    *out = String::from_utf8_lossy(&buf).into_owned();
    Ok(total)
}

fn send(stdin: &mut impl Write, msg: &Value) {
    let _ = stdin.write_all(mcp::to_line(msg).as_bytes());
    let _ = stdin.flush();
}

fn spawn_line_reader(stdout: std::process::ChildStdout) -> Receiver<String> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let mut r = BufReader::new(stdout);
        let mut line = String::new();
        loop {
            match read_capped_line(&mut r, &mut line) {
                Ok(0) => break, // EOF
                Ok(_) => {
                    if tx.send(std::mem::take(&mut line)).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });
    rx
}

/// Drain lines until one parses to a JSON-RPC object with the given id. Waits in
/// short slices so a stop request (Ctrl-C / `q`) interrupts a slow server
/// instead of blocking the full timeout.
fn read_response(rx: &Receiver<String>, id: u64, timeout: Duration) -> Option<Value> {
    let matches = |line: &str| -> Option<Value> {
        let v = serde_json::from_str::<Value>(line.trim()).ok()?;
        (v.get("id").and_then(|i| i.as_u64()) == Some(id)).then_some(v)
    };
    let deadline = Instant::now() + timeout;
    loop {
        // Consume whatever already arrived before honoring a stop, so a response
        // that IS here (e.g. initialize's serverInfo) isn't thrown away.
        while let Ok(line) = rx.try_recv() {
            if let Some(v) = matches(&line) {
                return Some(v);
            }
        }
        if stop_requested() {
            return None;
        }
        let remaining = deadline.checked_duration_since(Instant::now())?;
        match rx.recv_timeout(remaining.min(Duration::from_millis(250))) {
            Ok(line) => {
                if let Some(v) = matches(&line) {
                    return Some(v);
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => return None,
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
        // Honor Ctrl-C/q during proxy startup too; otherwise a wedged mitmdump
        // makes the watch unresponsive for the full timeout.
        if stop_requested() {
            bail!("stopped by user");
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
        if stop_requested() {
            bail!("stopped by user");
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

pub(crate) fn on_path(bin: &str) -> bool {
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
    fn single_observation_is_observed_not_stable() {
        // One trial (a Hold watch, or trials=1) can never satisfy the gate: the
        // host is Observed, so downstream stable-only filters exclude it from
        // findings, drift, and allowlists. Marking it Stable would report a
        // single sighting as a reproduced fact.
        let trials = vec![vec![fh("beacon.unknown.example", "monitor")]];
        let hosts = aggregate(&trials, &[]);
        let h = &hosts[0];
        assert_eq!(h.reproducibility, Reproducibility::Observed);
        assert_ne!(h.reproducibility, Reproducibility::Stable);
        assert_eq!(h.seen_in_trials, 1);
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

    #[test]
    fn capture_reserved_env_is_case_insensitive() {
        // pass_env must never forward a variable that would override the capture
        // proxy/CA (which would silently blind the capture), in either case.
        for name in [
            "HTTPS_PROXY",
            "https_proxy",
            "HTTP_PROXY",
            "NO_PROXY",
            "no_proxy",
            "ALL_PROXY",
            "PATH",
            "SSL_CERT_FILE",
            "NODE_EXTRA_CA_CERTS",
            "NODE_USE_ENV_PROXY",
            "REQUESTS_CA_BUNDLE",
            "CURL_CA_BUNDLE",
        ] {
            assert!(is_capture_reserved(name), "{name} should be reserved");
        }
        for name in ["GITHUB_TOKEN", "MY_API_KEY", "HOME", "LANG"] {
            assert!(!is_capture_reserved(name), "{name} should be allowed");
        }
    }

    #[test]
    fn resolve_version_precedence() {
        // config > installed > server-reported > unknown.
        let (v, s) = resolve_version(Some("2.0.0"), Some("1.5.0"), Some("9.9.9"));
        assert_eq!((v.as_str(), s.as_str()), ("2.0.0", "config"));
        let (v, s) = resolve_version(None, Some("1.5.0"), Some("9.9.9"));
        assert_eq!((v.as_str(), s.as_str()), ("1.5.0", "installed-package"));
        let (v, s) = resolve_version(None, None, Some("9.9.9"));
        assert_eq!((v.as_str(), s.as_str()), ("9.9.9", "server-reported"));
        let (v, s) = resolve_version(None, None, None);
        assert_eq!((v.as_str(), s.as_str()), ("unknown", "unknown"));
        // A value that sanitizes to empty is skipped, not used as the key.
        let (v, s) = resolve_version(Some("   "), Some("1.5.0"), None);
        assert_eq!((v.as_str(), s.as_str()), ("1.5.0", "installed-package"));
    }

    #[test]
    fn read_capped_line_caps_an_unterminated_stream() {
        use std::io::Cursor;
        // A line far larger than MAX_LINE with no newline must be capped, not
        // buffered whole (the OOM guard), and reported as bytes-consumed > 0.
        let big = vec![b'x'; MAX_LINE * 3];
        let mut r = Cursor::new(big);
        let mut line = String::new();
        let n = read_capped_line(&mut r, &mut line).unwrap();
        assert_eq!(n, MAX_LINE * 3, "all bytes consumed");
        assert_eq!(line.len(), MAX_LINE, "but only MAX_LINE retained");
        // EOF now yields 0.
        assert_eq!(read_capped_line(&mut r, &mut line).unwrap(), 0);
    }

    #[test]
    fn read_capped_line_splits_on_newlines() {
        use std::io::Cursor;
        let mut r = Cursor::new(b"one\ntwo\nthree".to_vec());
        let mut line = String::new();
        read_capped_line(&mut r, &mut line).unwrap();
        assert_eq!(line, "one");
        read_capped_line(&mut r, &mut line).unwrap();
        assert_eq!(line, "two");
        read_capped_line(&mut r, &mut line).unwrap();
        assert_eq!(line, "three"); // trailing, no newline
        assert_eq!(read_capped_line(&mut r, &mut line).unwrap(), 0);
    }
}
