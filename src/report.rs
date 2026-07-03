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
    phase: String,
    trials_seen: BTreeSet<u32>,
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
    done: bool,
}

impl DashState {
    fn finalize_active_phase(&mut self) {
        if let Some(p) = self.phases.iter_mut().find(|p| p.active) {
            p.dur = self.phase_start.elapsed();
            p.active = false;
        }
    }
}

pub struct DashboardReporter {
    state: Arc<Mutex<DashState>>,
    handle: Option<JoinHandle<()>>,
    active: bool,
}

impl DashboardReporter {
    fn new(server: &str, trials: u32) -> Self {
        // Enter the alternate screen and hide the cursor so the live view never
        // scrolls the user's scrollback; it is all restored in teardown().
        let mut err = io::stderr();
        let _ = write!(err, "\x1b[?1049h\x1b[?25l\x1b[2J\x1b[H");
        let _ = err.flush();

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

        DashboardReporter {
            state,
            handle: Some(handle),
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
        let mut err = io::stderr();
        let _ = write!(err, "\x1b[?25h\x1b[?1049l"); // show cursor, leave alt screen
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
        let trial = self.state.lock().map(|s| s.current_trial).unwrap_or(0);
        self.with(|s| {
            let row = s.hosts.entry(host.to_string()).or_insert_with(|| HostRow {
                class,
                phase: phase.to_string(),
                trials_seen: BTreeSet::new(),
            });
            row.class = class;
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

    // Phase timings for the current trial.
    push_line(&mut b, &format!("  {DIM}phases{RESET}"));
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
        push_line(&mut b, &format!("    {name:<12} {DIM}{d:>6}{RESET} {mark}"));
    }
    push_line(&mut b, "");

    // Hosts, streaming in, colored by class.
    push_line(
        &mut b,
        &format!("  {DIM}hosts  {} seen{RESET}", s.hosts.len()),
    );
    for (host, row) in &s.hosts {
        let col = class_color(row.class);
        let seen = row.trials_seen.len();
        let nm = format!("{:<40}", truncate(host, 40));
        let cls = format!("{:<11}", row.class);
        let tot = s.trials;
        let ph = &row.phase;
        push_line(
            &mut b,
            &format!("    {col}{nm}{RESET} {col}{cls}{RESET} {DIM}{seen}/{tot}  {ph}{RESET}"),
        );
    }

    b.push_str("\x1b[J"); // clear anything left below from a taller previous frame
    b
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
}
