//! Progress reporting for `gurgl watch`.
//!
//! Capture emits events (trial start, phase change, host seen, ...) to a
//! `Reporter`. Two implementations:
//!
//! - `PlainReporter` writes the same terse line-per-trial output gurgl always
//!   has. It is used when stderr is not a terminal (piped, in CI) or with
//!   `--plain`, so scripts and logs are unaffected.
//! - `DashboardReporter` draws a live, colored, in-place view (trial progress,
//!   per-phase timers, hosts streaming in colored by class). Zero extra
//!   dependencies: it is plain ANSI on the alternate screen, redrawn by a small
//!   background thread. It restores the terminal on finish or on drop.
//!
//! Only `watch` uses this; the one-shot commands print normally.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Write};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::model::{HostClass, Reproducibility, Snapshot};

/// Which reporter to use for a capture.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Plain,
    Dashboard,
}

/// Capture-progress sink. All methods have no-op defaults so an implementation
/// overrides only what it cares about.
pub trait Reporter {
    fn trial_start(&mut self, _trial: u32, _trials: u32) {}
    fn phase(&mut self, _phase: &str) {}
    fn host(&mut self, _host: &str, _class: HostClass, _phase: &str) {}
    fn note(&mut self, _msg: &str) {}
    fn trial_end(&mut self, _trial: u32, _hosts: usize) {}
    fn finish(&mut self, _snap: &Snapshot) {}
}

/// Build the reporter for `mode`. Constructing it may take over the terminal
/// (dashboard), so call this only once the capture is actually going to run.
pub fn reporter_for(mode: Mode, server: &str, trials: u32) -> Box<dyn Reporter> {
    match mode {
        Mode::Plain => Box::new(PlainReporter::new(server, trials)),
        Mode::Dashboard => Box::new(DashboardReporter::new(server, trials)),
    }
}

// ---- plain -----------------------------------------------------------------

struct PlainReporter;

impl PlainReporter {
    fn new(server: &str, trials: u32) -> Self {
        eprintln!("capturing {server} ({trials} trials)...");
        PlainReporter
    }
}

impl Reporter for PlainReporter {
    fn trial_start(&mut self, trial: u32, trials: u32) {
        eprintln!("  trial {trial}/{trials}");
    }
    fn note(&mut self, msg: &str) {
        eprintln!("    ({msg})");
    }
    fn trial_end(&mut self, _trial: u32, hosts: usize) {
        eprintln!("    observed {hosts} host(s)");
    }
}

// ---- dashboard -------------------------------------------------------------

const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";
const REV: &str = "\x1b[7m";
const GREEN: &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";
const CYAN: &str = "\x1b[36m";
const BRED: &str = "\x1b[1;31m";

fn class_color(c: HostClass) -> &'static str {
    match c {
        HostClass::FirstParty => GREEN,
        HostClass::Telemetry => YELLOW,
        // Self-named telemetry is NOT vetted: color it like unknown so it never
        // reads as reassuring.
        HostClass::TelemetryNamed => BRED,
        HostClass::Registry => CYAN,
        HostClass::Unknown => BRED,
    }
}

struct PhaseTiming {
    name: String,
    dur: Duration,
    active: bool,
}

struct HostRow {
    class: HostClass,
    /// Phase the host was first surfaced in (shown on the overview row).
    first_phase: String,
    /// Every phase it has been surfaced in, across trials (shown in detail).
    phases: BTreeSet<String>,
    trials_seen: BTreeSet<u32>,
    /// Elapsed watch time when the host first appeared.
    first_seen: Duration,
}

/// What the dashboard is showing: the host list, or one host drilled open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum View {
    Overview,
    Detail,
}

struct DashState {
    server: String,
    trials: u32,
    current_trial: u32,
    current_phase: String,
    note: String,
    start: Instant,
    phase_start: Instant,
    phases: Vec<PhaseTiming>,
    hosts: BTreeMap<String, HostRow>,
    view: View,
    /// The selected host, by name. Hosts stream in concurrently and a BTreeMap
    /// index would silently retarget the open detail view whenever an earlier-
    /// sorting host arrives; the name pins the selection to what the user chose.
    sel: Option<String>,
    done: bool,
}

impl DashState {
    fn finalize_active_phase(&mut self) {
        if let Some(p) = self.phases.iter_mut().find(|p| p.active) {
            p.dur = self.phase_start.elapsed();
            p.active = false;
        }
    }

    /// The selected host's current index in the sorted list (0 when unset or
    /// the selection is somehow gone).
    fn sel_index(&self) -> usize {
        self.sel
            .as_deref()
            .and_then(|h| self.hosts.keys().position(|k| k == h))
            .unwrap_or(0)
    }

    /// Select the host at `idx` (clamped), by name.
    fn select_nth(&mut self, idx: usize) {
        self.sel = self.hosts.keys().nth(idx).cloned();
    }
}

pub struct DashboardReporter {
    state: Arc<Mutex<DashState>>,
    handle: Option<JoinHandle<()>>,
    input_handle: Option<JoinHandle<()>>,
    raw: Option<rawin::Guard>,
    active: bool,
}

impl DashboardReporter {
    fn new(server: &str, trials: u32) -> Self {
        // Enter the alternate screen, hide the cursor, and enable bracketed
        // paste so the live view never scrolls the user's scrollback and pasted
        // text is not read as keystrokes; all restored in teardown().
        let mut err = io::stderr();
        let _ = write!(err, "\x1b[?1049h\x1b[?25l\x1b[?2004h\x1b[2J\x1b[H");
        let _ = err.flush();
        ALT_ACTIVE.store(true, std::sync::atomic::Ordering::Release);

        let now = Instant::now();
        let state = Arc::new(Mutex::new(DashState {
            server: server.to_string(),
            trials,
            current_trial: 0,
            current_phase: "starting".to_string(),
            note: String::new(),
            start: now,
            phase_start: now,
            phases: Vec::new(),
            hosts: BTreeMap::new(),
            view: View::Overview,
            sel: None,
            done: false,
        }));

        // A tiny render thread redraws ~5x/sec so the clocks tick even between
        // events. All it does is read state and paint; capture only mutates.
        let st = state.clone();
        let handle = thread::spawn(move || loop {
            {
                let s = match st.lock() {
                    Ok(s) => s,
                    Err(_) => break,
                };
                if s.done {
                    break;
                }
                let mut err = io::stderr();
                let frame = render(&s);
                let _ = err.write_all(frame.as_bytes());
                let _ = err.flush();
            }
            thread::sleep(Duration::from_millis(200));
        });

        // Keyboard input, when stdin is a terminal: up/down (or j/k) move the
        // selection, enter opens the host detail, esc backs out, 1-9 jump, and
        // q requests the same clean stop as Ctrl-C. Raw mode uses a 100ms read
        // timeout so this thread can poll `done` and exit promptly. Bracketed
        // paste is enabled (in new()) so pasted text - which may contain 'q' -
        // is swallowed instead of interpreted as keystrokes.
        let raw = rawin::enable();
        let input_handle = raw.as_ref().map(|_| {
            let st = state.clone();
            thread::spawn(move || {
                let mut in_paste = false;
                loop {
                    if st.lock().map(|s| s.done).unwrap_or(true) {
                        break;
                    }
                    let Some(b) = rawin::read_byte() else {
                        continue;
                    };
                    let ev = if b == 0x1b {
                        parse_escape(rawin::read_byte)
                    } else if in_paste {
                        None
                    } else {
                        key_for(b).map(Ev::Key)
                    };
                    match ev {
                        Some(Ev::PasteStart) => in_paste = true,
                        Some(Ev::PasteEnd) => in_paste = false,
                        Some(Ev::Key(k)) if !in_paste => {
                            let quit = st.lock().map(|mut s| apply_key(&mut s, k)).unwrap_or(false);
                            if quit {
                                crate::observe::request_stop();
                            }
                        }
                        _ => {}
                    }
                }
            })
        });

        DashboardReporter {
            state,
            handle: Some(handle),
            input_handle,
            raw,
            active: true,
        }
    }

    fn teardown(&mut self) {
        if !self.active {
            return;
        }
        self.active = false;
        if let Ok(mut s) = self.state.lock() {
            s.done = true;
        }
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
        if let Some(h) = self.input_handle.take() {
            let _ = h.join();
        }
        if let Some(g) = self.raw.take() {
            rawin::restore(&g);
        }
        ALT_ACTIVE.store(false, std::sync::atomic::Ordering::Release);
        let mut err = io::stderr();
        // show cursor, disable bracketed paste, leave the alternate screen
        let _ = write!(err, "\x1b[?25h\x1b[?2004l\x1b[?1049l");
        let _ = err.flush();
    }

    fn with<F: FnOnce(&mut DashState)>(&self, f: F) {
        if let Ok(mut s) = self.state.lock() {
            f(&mut s);
        }
    }
}

impl Reporter for DashboardReporter {
    fn trial_start(&mut self, trial: u32, _trials: u32) {
        self.with(|s| {
            s.current_trial = trial;
            s.phases.clear();
            s.note.clear();
        });
    }

    fn phase(&mut self, phase: &str) {
        self.with(|s| {
            s.finalize_active_phase();
            s.phases.push(PhaseTiming {
                name: phase.to_string(),
                dur: Duration::ZERO,
                active: true,
            });
            s.current_phase = phase.to_string();
            s.phase_start = Instant::now();
        });
    }

    fn host(&mut self, host: &str, class: HostClass, phase: &str) {
        self.with(|s| {
            let trial = s.current_trial;
            let elapsed = s.start.elapsed();
            let row = s.hosts.entry(host.to_string()).or_insert_with(|| HostRow {
                class,
                first_phase: phase.to_string(),
                phases: BTreeSet::new(),
                trials_seen: BTreeSet::new(),
                first_seen: elapsed,
            });
            row.class = class;
            row.phases.insert(phase.to_string());
            row.trials_seen.insert(trial);
        });
    }

    fn note(&mut self, msg: &str) {
        self.with(|s| s.note = msg.to_string());
    }

    fn finish(&mut self, snap: &Snapshot) {
        self.teardown();
        // Leave a compact, persistent summary in the real terminal.
        let mut err = io::stderr();
        let _ = writeln!(
            err,
            "{BOLD}{}@{}{RESET}  {} trials, flight plan {}",
            snap.server, snap.version, snap.trials, snap.flightplan
        );
        for h in &snap.hosts {
            let col = class_color(h.class);
            let repro = match h.reproducibility {
                Reproducibility::Stable => "stable",
                Reproducibility::Intermittent => "intermittent",
                Reproducibility::Observed => "observed",
            };
            let name = truncate(&h.name, 40);
            let cls = format!("{:<11}", h.class);
            let _ = writeln!(
                err,
                "  {col}{name:<40}{RESET} {col}{cls}{RESET} {repro:<12} {}/{}",
                h.seen_in_trials, snap.trials
            );
        }
    }
}

impl Drop for DashboardReporter {
    fn drop(&mut self) {
        // Safety net: if capture errored before finish(), still restore the term.
        self.teardown();
    }
}

// ---- keyboard input ----------------------------------------------------------

/// A dashboard key action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Key {
    Up,
    Down,
    Enter,
    Back,
    Jump(usize),
    Quit,
}

/// An input event: a key action, or a bracketed-paste boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ev {
    Key(Key),
    PasteStart,
    PasteEnd,
}

/// Map a plain byte to an action (escape sequences are handled by the reader).
fn key_for(b: u8) -> Option<Key> {
    match b {
        b'k' => Some(Key::Up),
        b'j' => Some(Key::Down),
        b'\r' | b'\n' | b'l' | b' ' => Some(Key::Enter),
        b'h' | b'0' | 0x7f => Some(Key::Back), // 0x7f = backspace
        b'1'..=b'9' => Some(Key::Jump((b - b'1') as usize)),
        b'q' => Some(Key::Quit),
        _ => None,
    }
}

/// Parse the remainder of an escape sequence (the ESC byte is already read).
/// Consumes the WHOLE sequence so tail bytes of longer CSI sequences (modified
/// arrows `ESC [ 1 ; 2 A`, function keys `ESC [ 1 5 ~`) are never re-read as
/// standalone keys - a leaked digit would otherwise trigger Key::Jump.
fn parse_escape(mut next: impl FnMut() -> Option<u8>) -> Option<Ev> {
    match next() {
        // Nothing after ESC within the read timeout: a lone Esc press.
        None => Some(Ev::Key(Key::Back)),
        Some(b'[') => {
            // CSI: parameter (0x30-0x3F) and intermediate (0x20-0x2F) bytes,
            // terminated by a final byte in 0x40-0x7E.
            let mut params: Vec<u8> = Vec::new();
            loop {
                match next() {
                    None => return None, // truncated sequence: discard
                    Some(b @ 0x20..=0x3f) => params.push(b),
                    Some(fin) => {
                        return match (fin, params.as_slice()) {
                            (b'A', []) => Some(Ev::Key(Key::Up)),
                            (b'B', []) => Some(Ev::Key(Key::Down)),
                            (b'~', b"200") => Some(Ev::PasteStart),
                            (b'~', b"201") => Some(Ev::PasteEnd),
                            _ => None,
                        };
                    }
                }
            }
        }
        // SS3 (ESC O x): application-mode arrows / F1-F4; consume and map arrows.
        Some(b'O') => match next() {
            Some(b'A') => Some(Ev::Key(Key::Up)),
            Some(b'B') => Some(Ev::Key(Key::Down)),
            _ => None,
        },
        // Alt+<key> and anything else: ignore.
        _ => None,
    }
}

/// Apply a key to the dashboard state. Returns true when the user asked to quit
/// (the caller requests the clean stop; kept out of here so it stays testable).
fn apply_key(s: &mut DashState, k: Key) -> bool {
    let n = s.hosts.len();
    match k {
        Key::Up => {
            let idx = s.sel_index();
            s.select_nth(idx.saturating_sub(1));
        }
        Key::Down => {
            if n > 0 {
                let idx = s.sel_index();
                s.select_nth((idx + 1).min(n - 1));
            }
        }
        Key::Enter => {
            if n > 0 {
                let idx = s.sel_index();
                s.select_nth(idx); // pin the selection by name before drilling in
                s.view = View::Detail;
            }
        }
        Key::Back => s.view = View::Overview,
        Key::Jump(i) => {
            if i < n {
                s.select_nth(i);
                s.view = View::Detail;
            }
        }
        Key::Quit => return true,
    }
    false
}

/// Raw-ish stdin so single keypresses arrive without Enter and without echo.
/// Unix only; on other platforms the dashboard simply has no keyboard input.
#[cfg(unix)]
mod rawin {
    use std::io::IsTerminal;
    use std::sync::atomic::{AtomicBool, Ordering};

    pub struct Guard {
        orig: libc::termios,
    }

    // For the SIGINT handler's emergency restore (async-signal-safe): the
    // original termios, published via Release once written, and only read after
    // an Acquire swap of RAW_ACTIVE confirms it is valid (so no torn read).
    static RAW_ACTIVE: AtomicBool = AtomicBool::new(false);
    struct TermiosCell(std::cell::UnsafeCell<Option<libc::termios>>);
    // SAFETY: access is ordered through RAW_ACTIVE (write-before-Release-store,
    // read-after-Acquire-swap), so the cell is never accessed concurrently.
    unsafe impl Sync for TermiosCell {}
    static ORIG_TERMIOS: TermiosCell = TermiosCell(std::cell::UnsafeCell::new(None));

    /// Enable raw input. `VMIN=0, VTIME=1` gives reads a 100ms timeout so the
    /// input thread can poll its exit flag instead of blocking forever.
    /// Returns None when stdin is not a terminal, or when we are not the
    /// foreground process group (a backgrounded tcsetattr/read would deliver
    /// SIGTTOU/SIGTTIN, whose default action stops the whole process).
    pub fn enable() -> Option<Guard> {
        if !std::io::stdin().is_terminal() {
            return None;
        }
        unsafe {
            if libc::tcgetpgrp(0) != libc::getpgrp() {
                return None;
            }
            let mut t: libc::termios = std::mem::zeroed();
            if libc::tcgetattr(0, &mut t) != 0 {
                return None;
            }
            let orig = t;
            // Keep ISIG so Ctrl-C still raises SIGINT (the graceful stop).
            t.c_lflag &= !(libc::ICANON | libc::ECHO);
            t.c_cc[libc::VMIN] = 0;
            t.c_cc[libc::VTIME] = 1;
            if libc::tcsetattr(0, libc::TCSANOW, &t) != 0 {
                return None;
            }
            *ORIG_TERMIOS.0.get() = Some(orig);
            RAW_ACTIVE.store(true, Ordering::Release);
            Some(Guard { orig })
        }
    }

    pub fn restore(g: &Guard) {
        RAW_ACTIVE.store(false, Ordering::Release);
        unsafe {
            let _ = libc::tcsetattr(0, libc::TCSANOW, &g.orig);
        }
    }

    /// Best-effort termios restore from a signal handler. Only atomics and
    /// tcsetattr (async-signal-safe per POSIX) are used.
    pub fn emergency_restore() {
        if RAW_ACTIVE.swap(false, Ordering::AcqRel) {
            unsafe {
                if let Some(orig) = *ORIG_TERMIOS.0.get() {
                    let _ = libc::tcsetattr(0, libc::TCSANOW, &orig);
                }
            }
        }
    }

    /// One byte, or None on the 100ms timeout.
    pub fn read_byte() -> Option<u8> {
        let mut b = [0u8; 1];
        let n = unsafe { libc::read(0, b.as_mut_ptr() as *mut libc::c_void, 1) };
        (n == 1).then_some(b[0])
    }
}
#[cfg(not(unix))]
mod rawin {
    pub struct Guard;
    pub fn enable() -> Option<Guard> {
        None
    }
    pub fn restore(_g: &Guard) {}
    pub fn emergency_restore() {}
    pub fn read_byte() -> Option<u8> {
        None
    }
}

/// Whether the dashboard currently owns the alternate screen, for the SIGINT
/// handler's emergency restore.
static ALT_ACTIVE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Best-effort terminal restore for the force-quit path (second Ctrl-C). Called
/// from the signal handler, so only async-signal-safe operations: an atomic,
/// write(2), tcsetattr.
pub fn emergency_restore() {
    use std::sync::atomic::Ordering;
    rawin::emergency_restore();
    if ALT_ACTIVE.swap(false, Ordering::AcqRel) {
        // show cursor, disable bracketed paste, leave the alternate screen
        const SEQ: &[u8] = b"\x1b[?25h\x1b[?2004l\x1b[?1049l";
        #[cfg(unix)]
        unsafe {
            let _ = libc::write(2, SEQ.as_ptr() as *const libc::c_void, SEQ.len());
        }
        #[cfg(not(unix))]
        {
            use std::io::Write;
            let _ = std::io::stderr().write_all(SEQ);
        }
    }
}

// ---- rendering (pure-ish helpers) ------------------------------------------

fn render(s: &DashState) -> String {
    let w = term_width();
    let mut b = String::from("\x1b[H");

    // Title bar (reverse video for a clean, colored separation).
    let left = format!(" gurgl watch   {}", s.server);
    let right = format!("{} ", fmt_clock(s.start.elapsed()));
    let bar = pad_between(&left, &right, w);
    push_line(&mut b, &format!("{REV}{BOLD}{bar}{RESET}"));
    push_line(&mut b, "");

    // Trial progress + current phase.
    let pb = progress_bar(s.current_trial, s.trials, 22);
    push_line(
        &mut b,
        &format!("  trial {}/{}  {pb}", s.current_trial, s.trials),
    );
    push_line(
        &mut b,
        &format!(
            "  phase {BOLD}{}{RESET}  {DIM}{}{RESET}",
            s.current_phase,
            fmt_secs(s.phase_start.elapsed())
        ),
    );
    if !s.note.is_empty() {
        push_line(&mut b, &format!("  {YELLOW}{}{RESET}", s.note));
    }
    push_line(&mut b, "");

    match s.view {
        View::Overview => render_overview(s, &mut b),
        View::Detail => render_detail(s, &mut b),
    }

    // Key menu. Only meaningful when a keyboard is attached, but harmless (and
    // honest about Ctrl-C) either way.
    push_line(&mut b, "");
    let keys = match s.view {
        View::Overview => "  up/down select   enter inspect   q stop+save   ctrl-c stop",
        View::Detail => "  esc back   up/down other host   q stop+save",
    };
    push_line(&mut b, &format!("{DIM}{keys}{RESET}"));

    b.push_str("\x1b[J"); // clear anything left below from a taller previous frame
    b
}

/// The host list plus per-phase timings, with the selected row highlighted.
fn render_overview(s: &DashState, b: &mut String) {
    // Phase timings for the current trial. Column width follows the longest
    // phase name so custom plans (e.g. "fetch-example") stay aligned.
    push_line(b, &format!("  {DIM}phases{RESET}"));
    let name_w = s
        .phases
        .iter()
        .map(|p| p.name.chars().count())
        .max()
        .unwrap_or(0)
        .max(12);
    for p in &s.phases {
        let d = if p.active {
            fmt_secs(s.phase_start.elapsed())
        } else {
            fmt_secs(p.dur)
        };
        let mark = if p.active {
            format!("{GREEN}<{RESET}")
        } else {
            " ".to_string()
        };
        let name = &p.name;
        push_line(b, &format!("    {name:<name_w$} {DIM}{d:>6}{RESET} {mark}"));
    }
    push_line(b, "");

    // Hosts, streaming in, colored by class; the selection follows sort order.
    push_line(b, &format!("  {DIM}hosts  {} seen{RESET}", s.hosts.len()));
    let sel_idx = s.sel_index();
    for (i, (host, row)) in s.hosts.iter().enumerate() {
        let col = class_color(row.class);
        let seen = row.trials_seen.len();
        let nm = format!("{:<40}", truncate(host, 40));
        let cls = format!("{:<11}", row.class);
        let tot = s.trials;
        let ph = &row.first_phase;
        let idx = if i < 9 {
            (i + 1).to_string()
        } else {
            " ".to_string()
        };
        if i == sel_idx {
            push_line(
                b,
                &format!("  {REV}> {idx} {nm} {cls} {seen}/{tot}  {ph}{RESET}"),
            );
        } else {
            push_line(
                b,
                &format!(
                    "    {DIM}{idx}{RESET} {col}{nm}{RESET} {col}{cls}{RESET} {DIM}{seen}/{tot}  {ph}{RESET}"
                ),
            );
        }
    }
}

/// Rich context for the selected host, looked up by name so a concurrently
/// growing host list cannot retarget the open view.
fn render_detail(s: &DashState, b: &mut String) {
    let Some((host, row)) = s
        .sel
        .as_deref()
        .and_then(|h| s.hosts.get_key_value(h))
        .or_else(|| s.hosts.iter().next())
    else {
        push_line(b, &format!("  {DIM}no hosts observed yet{RESET}"));
        return;
    };
    let col = class_color(row.class);
    push_line(b, &format!("  {BOLD}{col}{host}{RESET}"));
    push_line(b, "");
    push_line(
        b,
        &format!(
            "    class    {col}{:<11}{RESET} {DIM}{}{RESET}",
            row.class,
            class_desc(row.class)
        ),
    );
    let trials: Vec<String> = row.trials_seen.iter().map(|t| t.to_string()).collect();
    push_line(
        b,
        &format!(
            "    trials   seen in {}/{} so far {DIM}(trial {}){RESET}",
            row.trials_seen.len(),
            s.trials,
            trials.join(", ")
        ),
    );
    let phases: Vec<&str> = row.phases.iter().map(|p| p.as_str()).collect();
    push_line(b, &format!("    phases   {}", phases.join(", ")));
    push_line(
        b,
        &format!(
            "    first    {DIM}{} after start{RESET}",
            fmt_clock(row.first_seen)
        ),
    );
    push_line(b, "");
    push_line(
        b,
        &format!("    {DIM}presence only: gurgl records hosts contacted under this flight{RESET}"),
    );
    push_line(
        b,
        &format!("    {DIM}plan, never payloads. Absence elsewhere is non-coverage.{RESET}"),
    );
}

/// One line of context per host class, shown in the detail view.
fn class_desc(c: HostClass) -> &'static str {
    match c {
        HostClass::FirstParty => "declared first-party for this server (gurgl.toml)",
        HostClass::Registry => "package/artifact registry, expected for npx/uvx-launched servers",
        HostClass::Telemetry => "known telemetry / feature-gate vendor",
        HostClass::TelemetryNamed => {
            "NAMES itself telemetry/analytics but matches no known vendor. Scrutinize like unknown"
        }
        HostClass::Unknown => "unclassified. Worth a look if stable across trials",
    }
}

/// Append a line, clearing to end-of-line so stale characters from a wider
/// previous frame don't linger.
fn push_line(b: &mut String, s: &str) {
    b.push_str(s);
    b.push_str("\x1b[K\n");
}

fn progress_bar(cur: u32, tot: u32, width: usize) -> String {
    let frac = if tot == 0 {
        0.0
    } else {
        (cur as f64 / tot as f64).clamp(0.0, 1.0)
    };
    let filled = ((frac * width as f64).round() as usize).min(width);
    format!(
        "{GREEN}{}{DIM}{}{RESET}",
        "\u{2588}".repeat(filled),
        "\u{2591}".repeat(width - filled)
    )
}

fn fmt_clock(d: Duration) -> String {
    let s = d.as_secs();
    format!("{:02}:{:02}", s / 60, s % 60)
}

fn fmt_secs(d: Duration) -> String {
    format!("{:.1}s", d.as_secs_f64())
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        s.chars().take(n).collect()
    }
}

fn pad_between(left: &str, right: &str, w: usize) -> String {
    let used = left.chars().count() + right.chars().count();
    let pad = w.saturating_sub(used);
    format!("{left}{}{right}", " ".repeat(pad))
}

fn term_width() -> usize {
    std::env::var("COLUMNS")
        .ok()
        .and_then(|c| c.parse::<usize>().ok())
        .unwrap_or(100)
        .clamp(70, 160)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn progress_bar_fills_proportionally() {
        // 0/4 -> empty, 4/4 -> full, 2/4 -> half. Count the filled blocks.
        let count_filled = |s: &str| s.matches('\u{2588}').count();
        assert_eq!(count_filled(&progress_bar(0, 4, 20)), 0);
        assert_eq!(count_filled(&progress_bar(4, 4, 20)), 20);
        assert_eq!(count_filled(&progress_bar(2, 4, 20)), 10);
        // Never overfills, even if cur > tot.
        assert_eq!(count_filled(&progress_bar(9, 4, 20)), 20);
    }

    #[test]
    fn truncate_respects_limit() {
        assert_eq!(truncate("short", 10), "short");
        assert_eq!(
            truncate("a-very-long-hostname.example.com", 8)
                .chars()
                .count(),
            8
        );
    }

    #[test]
    fn pad_between_fills_width() {
        let out = pad_between("left", "right", 20);
        assert_eq!(out.chars().count(), 20);
        assert!(out.starts_with("left"));
        assert!(out.ends_with("right"));
    }

    #[test]
    fn fmt_clock_is_mm_ss() {
        assert_eq!(fmt_clock(Duration::from_secs(75)), "01:15");
        assert_eq!(fmt_clock(Duration::from_secs(5)), "00:05");
    }

    fn state_with_hosts(n: usize) -> DashState {
        let now = Instant::now();
        let mut hosts = BTreeMap::new();
        for i in 0..n {
            hosts.insert(
                format!("host{i}.example.com"),
                HostRow {
                    class: HostClass::Unknown,
                    first_phase: "startup".into(),
                    phases: BTreeSet::new(),
                    trials_seen: BTreeSet::new(),
                    first_seen: Duration::ZERO,
                },
            );
        }
        DashState {
            server: "s".into(),
            trials: 5,
            current_trial: 1,
            current_phase: "startup".into(),
            note: String::new(),
            start: now,
            phase_start: now,
            phases: Vec::new(),
            hosts,
            view: View::Overview,
            sel: None,
            done: false,
        }
    }

    #[test]
    fn keys_map_to_actions() {
        assert_eq!(key_for(b'j'), Some(Key::Down));
        assert_eq!(key_for(b'k'), Some(Key::Up));
        assert_eq!(key_for(b'\r'), Some(Key::Enter));
        assert_eq!(key_for(b'q'), Some(Key::Quit));
        assert_eq!(key_for(b'3'), Some(Key::Jump(2)));
        assert_eq!(key_for(b'0'), Some(Key::Back));
        assert_eq!(key_for(b'x'), None);
    }

    /// Feed `parse_escape` from a byte script (None = read timeout).
    fn esc(bytes: &[u8]) -> Option<Ev> {
        let mut it = bytes.iter().copied();
        parse_escape(move || it.next())
    }

    #[test]
    fn escape_parser_consumes_whole_sequences() {
        assert_eq!(esc(b"[A"), Some(Ev::Key(Key::Up)));
        assert_eq!(esc(b"[B"), Some(Ev::Key(Key::Down)));
        assert_eq!(esc(b""), Some(Ev::Key(Key::Back))); // lone Esc
                                                        // Modified arrow (Shift+Up) and function keys: fully consumed, ignored.
                                                        // The digits inside must NOT leak out as Key::Jump.
        assert_eq!(esc(b"[1;2A"), None);
        assert_eq!(esc(b"[15~"), None);
        assert_eq!(esc(b"[24~"), None);
        // Bracketed-paste boundaries.
        assert_eq!(esc(b"[200~"), Some(Ev::PasteStart));
        assert_eq!(esc(b"[201~"), Some(Ev::PasteEnd));
        // SS3 arrows (application cursor mode).
        assert_eq!(esc(b"OA"), Some(Ev::Key(Key::Up)));
        assert_eq!(esc(b"OB"), Some(Ev::Key(Key::Down)));
        // Alt+q must not quit.
        assert_eq!(esc(b"q"), None);
    }

    #[test]
    fn selection_clamps_and_drills_down() {
        let mut s = state_with_hosts(3);
        // Down moves, clamped at the last host.
        for _ in 0..10 {
            apply_key(&mut s, Key::Down);
        }
        assert_eq!(s.sel_index(), 2);
        // Up clamps at zero.
        for _ in 0..10 {
            apply_key(&mut s, Key::Up);
        }
        assert_eq!(s.sel_index(), 0);
        // Enter opens detail; Back returns.
        apply_key(&mut s, Key::Enter);
        assert_eq!(s.view, View::Detail);
        apply_key(&mut s, Key::Back);
        assert_eq!(s.view, View::Overview);
        // Jump to a valid row opens it; out-of-range is ignored.
        apply_key(&mut s, Key::Jump(1));
        assert_eq!((s.sel_index(), s.view), (1, View::Detail));
        apply_key(&mut s, Key::Back);
        apply_key(&mut s, Key::Jump(7));
        assert_eq!((s.sel_index(), s.view), (1, View::Overview));
        // Quit is reported to the caller, not applied to state.
        assert!(apply_key(&mut s, Key::Quit));
    }

    #[test]
    fn selection_is_pinned_by_name_across_inserts() {
        let mut s = state_with_hosts(2); // host0, host1
        apply_key(&mut s, Key::Jump(0)); // open host0's detail
        assert_eq!(s.sel.as_deref(), Some("host0.example.com"));
        // A lexicographically earlier host streams in while the detail is open.
        s.hosts.insert(
            "aaa.example.com".into(),
            HostRow {
                class: HostClass::Unknown,
                first_phase: "idle".into(),
                phases: BTreeSet::new(),
                trials_seen: BTreeSet::new(),
                first_seen: Duration::ZERO,
            },
        );
        // The selection still points at host0, not at the new index-0 host.
        assert_eq!(s.sel.as_deref(), Some("host0.example.com"));
        assert_eq!(s.sel_index(), 1);
        let mut out = String::new();
        render_detail(&s, &mut out);
        assert!(out.contains("host0.example.com"));
        assert!(!out.contains("aaa.example.com"));
    }

    #[test]
    fn empty_host_list_never_drills() {
        let mut s = state_with_hosts(0);
        apply_key(&mut s, Key::Down);
        apply_key(&mut s, Key::Enter);
        assert_eq!(s.view, View::Overview);
        assert_eq!(s.sel, None);
        // Rendering the (unreachable) detail view with no hosts must not panic.
        s.view = View::Detail;
        let mut out = String::new();
        render_detail(&s, &mut out);
        assert!(out.contains("no hosts"));
    }
}
