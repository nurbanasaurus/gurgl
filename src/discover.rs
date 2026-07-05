//! Discover MCP servers already configured on this machine.
//!
//! Every MCP client stores its servers in a predictable JSON config with an
//! `mcpServers` object (`{ "name": { "command", "args", "env" } }`). gurgl scans
//! two ways so you can see, and then watch, the servers you actually run rather
//! than hand-listing them:
//!
//! 1. the well-known client config files (Claude Desktop, Claude Code's
//!    `~/.claude.json`, Cursor, Windsurf, Cline); and
//! 2. every project-scoped `.mcp.json` under `$HOME` (Claude Code's per-project
//!    config, and where plugins ship theirs) plus every Codex `.codex/config.toml`
//!    (a different, TOML `[mcp_servers.<name>]` shape). Matching those exact names
//!    keeps this precise - unrelated JSON that merely mentions `mcpServers`
//!    (schemas, API discovery docs) is not named `.mcp.json`, so it is not picked
//!    up.
//!
//! Out of scope by design: ChatGPT. Its MCP is remote-only (HTTPS connectors
//! configured in your OpenAI account), so there is no local config to read and no
//! local process to watch - the same reason gurgl lists but never captures
//! `remote (url)` servers.
//!
//! This only reads config files; it never records or prints `env` values (which
//! commonly hold API keys). It reports *that* a server sets env, not what.

use std::path::{Path, PathBuf};

use serde_json::Value;

/// Whether a discovered server is actually turned on in its client, or merely
/// present on disk. Determined from the client's own enable records; when we
/// cannot find a positive "on" record we never claim `Enabled`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Status {
    /// Positively listed as enabled in the client config (authoritative).
    Enabled,
    /// A plugin shipped by a marketplace/plugin dir, but not enabled: available,
    /// not something you turned on.
    Bundled,
    /// Present in a config (a project/user `.mcp.json`, a client's server list)
    /// but not found in any enable record - configured, not confirmed active.
    Configured,
}

impl Status {
    /// Merge order for dedup: when the same server surfaces in several places,
    /// the strongest status wins (Enabled over merely present), so a server
    /// enabled in ANY project is never reported as only configured.
    fn rank(self) -> u8 {
        match self {
            Status::Enabled => 2,
            Status::Bundled | Status::Configured => 1,
        }
    }
}

impl std::fmt::Display for Status {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.pad(match self {
            Status::Enabled => "enabled",
            Status::Bundled => "bundled",
            Status::Configured => "configured",
        })
    }
}

/// One MCP server found in a client config.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Discovered {
    pub name: String,
    /// stdio launch command, if this is a local (subprocess) server.
    pub command: Option<String>,
    pub args: Vec<String>,
    /// Remote endpoint, if this is an SSE/HTTP server (not gurgl-capturable).
    pub url: Option<String>,
    /// Whether the entry defines `env` (may hold secrets; values never read).
    pub has_env: bool,
    /// Human-readable source, e.g. "Claude Code (~/.claude.json)".
    pub source: String,
    /// Whether the client has this server enabled, or it is just present.
    pub status: Status,
    /// The project directory this server belongs to (a `.mcp.json`'s parent, or
    /// a per-project key in `~/.claude.json`), used to match enable records to
    /// the RIGHT project. Internal; not part of the --json output.
    #[serde(skip)]
    pub config_dir: Option<PathBuf>,
}

impl Discovered {
    /// A local stdio server gurgl can launch and capture.
    pub fn is_stdio(&self) -> bool {
        self.command.is_some()
    }
}

/// The client config files gurgl looks in, as (client label, path).
fn config_files() -> Vec<(&'static str, PathBuf)> {
    let mut v = Vec::new();
    let Some(home) = dirs::home_dir() else {
        return v;
    };

    v.push(("Claude Code", home.join(".claude.json")));
    v.push(("Cursor", home.join(".cursor").join("mcp.json")));
    v.push((
        "Windsurf",
        home.join(".codeium")
            .join("windsurf")
            .join("mcp_config.json"),
    ));

    let cline_rel = [
        "Code",
        "User",
        "globalStorage",
        "saoudrizwan.claude-dev",
        "settings",
        "cline_mcp_settings.json",
    ];
    #[cfg(target_os = "macos")]
    {
        let appsup = home.join("Library").join("Application Support");
        v.push((
            "Claude Desktop",
            appsup.join("Claude").join("claude_desktop_config.json"),
        ));
        let mut p = appsup;
        for c in cline_rel {
            p = p.join(c);
        }
        v.push(("Cline (VS Code)", p));
    }
    #[cfg(not(target_os = "macos"))]
    {
        let cfg = home.join(".config");
        v.push((
            "Claude Desktop",
            cfg.join("Claude").join("claude_desktop_config.json"),
        ));
        let mut p = cfg;
        for c in cline_rel {
            p = p.join(c);
        }
        v.push(("Cline (VS Code)", p));
    }

    // Project-local, in the current directory. Resolve to an ABSOLUTE path so the
    // project dir (the key an enable record is matched by) is attributed
    // correctly: a bare ".mcp.json" has an empty parent, which never matches an
    // enable record and, inserted first, would mask the same file the $HOME walk
    // finds with a correct absolute path. Absolute also lets the two dedup.
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    v.push(("project", cwd.join(".mcp.json")));
    v.push(("project", cwd.join(".cursor/mcp.json")));
    v
}

/// Scan the known config files plus every project-scoped `.mcp.json`, and return
/// the MCP servers found.
pub fn discover() -> Vec<Discovered> {
    let mut out = Vec::new();

    // 1) the well-known client config files (fixed locations).
    for (label, path) in config_files() {
        parse_file(&path, label, &mut out);
    }

    // 2) config files found anywhere under $HOME (and the current dir): Claude
    // Code project/plugin `.mcp.json`, and Codex `.codex/config.toml`. The fixed
    // list above never sees these.
    for path in home_config_files() {
        if path.file_name().and_then(|f| f.to_str()) == Some("config.toml") {
            parse_codex_file(&path, &mut out);
        } else {
            let label = label_for(&path);
            parse_file(&path, label, &mut out);
        }
    }

    // Resolve each server's status (enabled / bundled / configured) from the
    // client enable records BEFORE collapsing dupes. The same server can be
    // configured in several projects and enabled in only some; a status computed
    // on whichever entry happened to survive dedup would be arbitrary and could
    // flip between runs with the (filesystem-dependent) walk order.
    let idx = EnabledIndex::load();
    for d in &mut out {
        d.status = idx.status_for(d);
    }
    dedupe_strongest(out)
}

/// The identity two discovered servers are collapsed on: name + launch shape.
type ServerKey = (String, Option<String>, Option<String>, Vec<String>);

/// Collapse exact-duplicate discovered servers (same name/command/url/args) to
/// one row, keeping the strongest status. A server surfaces more than once when a
/// plugin sits in both the install cache and the marketplace, or when the same
/// server is configured in several projects; status must already be resolved.
fn dedupe_strongest(entries: Vec<Discovered>) -> Vec<Discovered> {
    let mut idx_by_key: std::collections::HashMap<ServerKey, usize> =
        std::collections::HashMap::new();
    let mut merged: Vec<Discovered> = Vec::new();
    for d in entries {
        let key = (
            d.name.clone(),
            d.command.clone(),
            d.url.clone(),
            d.args.clone(),
        );
        match idx_by_key.get(&key) {
            Some(&i) => {
                if d.status.rank() > merged[i].status.rank() {
                    merged[i].status = d.status;
                }
            }
            None => {
                idx_by_key.insert(key, merged.len());
                merged.push(d);
            }
        }
    }
    merged
}

/// Read a config file, refusing non-regular files and absurdly large ones. Real
/// config files are tiny; without a cap a multi-GB (or attacker-planted) file
/// named `.mcp.json` would OOM read_to_string.
fn read_capped(path: &Path) -> Option<String> {
    const CAP: u64 = 8 * 1024 * 1024; // 8 MiB - orders of magnitude over any real config
    let meta = std::fs::metadata(path).ok()?;
    if !meta.is_file() || meta.len() > CAP {
        return None;
    }
    std::fs::read_to_string(path).ok()
}

/// Read one JSON config file and append any MCP servers it defines.
fn parse_file(path: &Path, label: &str, out: &mut Vec<Discovered>) {
    let Some(text) = read_capped(path) else {
        return;
    };
    let Ok(json) = serde_json::from_str::<Value>(&text) else {
        return;
    };
    collect(&json, label, path, out);
}

/// Read a Codex `config.toml` and append its `[mcp_servers.<name>]` entries.
/// Codex uses TOML, not the JSON `mcpServers` shape, and either `command`+`args`
/// (stdio) or `url` (Streamable HTTP). A server with `enabled = false` is still
/// listed for inventory (it is left as `Configured`, i.e. present, not on).
fn parse_codex_file(path: &Path, out: &mut Vec<Discovered>) {
    let Some(text) = read_capped(path) else {
        return;
    };
    let Ok(val) = toml::from_str::<toml::Value>(&text) else {
        return;
    };
    let Some(servers) = val.get("mcp_servers").and_then(|v| v.as_table()) else {
        return;
    };
    let src = source("Codex", path);
    let dir = path.parent().map(|p| p.to_path_buf());
    for (name, spec) in servers {
        let command = spec
            .get("command")
            .and_then(|v| v.as_str())
            .map(String::from);
        let url = spec.get("url").and_then(|v| v.as_str()).map(String::from);
        let args = spec
            .get("args")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        let has_env = spec
            .get("env")
            .and_then(|v| v.as_table())
            .map(|t| !t.is_empty())
            .unwrap_or(false);
        out.push(Discovered {
            name: name.clone(),
            command,
            args,
            url,
            has_env,
            source: src.clone(),
            status: Status::Configured,
            config_dir: dir.clone(),
        });
    }
}

/// Recursively find MCP config files under `$HOME` and the current directory:
/// every `.mcp.json` (Claude Code project/plugin configs) and every
/// `.codex/config.toml` (Codex CLI global + per-project config). Heavy or
/// irrelevant directories are pruned and depth is bounded so this stays fast on a
/// large home. macOS `~/Library` is pruned (the Claude Desktop config there is
/// already a fixed location above and is not one of these names).
fn home_config_files() -> Vec<PathBuf> {
    const PRUNE: &[&str] = &[
        "node_modules",
        ".git",
        "target",
        "Library",
        "Caches",
        ".cargo",
        ".rustup",
        ".cache",
        ".npm",
        ".venv",
        "venv",
        "dist",
        "build",
        ".Trash",
        ".gurgl",
        "mitmproxy-venv",
        "site-packages",
    ];
    const MAX_DEPTH: usize = 8;
    const MAX_DIRS: usize = 50_000;

    let mut roots: Vec<PathBuf> = Vec::new();
    if let Some(home) = dirs::home_dir() {
        roots.push(home);
    }
    if let Ok(cwd) = std::env::current_dir() {
        if !roots.iter().any(|r| cwd.starts_with(r)) {
            roots.push(cwd);
        }
    }

    let mut found = Vec::new();
    let mut stack: Vec<(PathBuf, usize)> = roots.into_iter().map(|r| (r, 0)).collect();
    let mut visited = 0usize;
    while let Some((dir, depth)) = stack.pop() {
        if depth > MAX_DEPTH {
            continue;
        }
        visited += 1;
        if visited > MAX_DIRS {
            // Presence, not silence: a truncated scan must never read as a
            // complete inventory (constraint #2). Say the scan stopped short.
            eprintln!(
                "note: config scan stopped after {MAX_DIRS} directories; the inventory may be \
                 incomplete (configs deeper in $HOME were not scanned)."
            );
            break;
        }
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(ft) = entry.file_type() else {
                continue;
            };
            if ft.is_dir() {
                let name = entry.file_name();
                if PRUNE.iter().any(|p| name == std::ffi::OsStr::new(p)) {
                    continue;
                }
                stack.push((entry.path(), depth + 1));
            } else if ft.is_file() {
                // Only regular files. file_type() does not follow symlinks, so a
                // FIFO, socket, device node, or a symlink named `.mcp.json` is
                // skipped here - reading a FIFO would hang gurgl forever, and a
                // symlink could redirect the later open off the intended file.
                let fname = entry.file_name();
                let is_mcp_json = fname.to_str() == Some(".mcp.json");
                // Codex uses `config.toml`, but only a Codex one when it sits
                // inside a `.codex` dir (config.toml is otherwise a common name).
                let is_codex = fname.to_str() == Some("config.toml")
                    && dir.file_name().and_then(|d| d.to_str()) == Some(".codex");
                if is_mcp_json || is_codex {
                    found.push(entry.path());
                }
            }
        }
    }
    found
}

/// A short source label for a discovered `.mcp.json`, by where it lives. A
/// plugin config lives under the Claude plugin root (`~/.claude/plugins/`), NOT
/// anywhere a path merely contains "plugins" - `~/dev/app/plugins/x/.mcp.json`
/// is an ordinary project, not a bundled plugin.
fn label_for(path: &Path) -> &'static str {
    if let Some(home) = dirs::home_dir() {
        if path.starts_with(home.join(".claude").join("plugins")) {
            return "plugin";
        }
    }
    "project"
}

fn collect(json: &Value, label: &str, path: &Path, out: &mut Vec<Discovered>) {
    // Top-level servers belong to the file's own directory. For a project
    // `.mcp.json` that IS the project directory the enable record is keyed by.
    let dir = path.parent().map(|p| p.to_path_buf());
    if let Some(map) = json.get("mcpServers").and_then(|v| v.as_object()) {
        for (name, spec) in map {
            out.push(parse(name, spec, &source(label, path), dir.clone()));
        }
    }
    // Claude Code's ~/.claude.json also nests servers per project; each belongs
    // to its own project key, not the ~/.claude.json file's directory.
    if let Some(projects) = json.get("projects").and_then(|v| v.as_object()) {
        for (proj, pv) in projects {
            if let Some(map) = pv.get("mcpServers").and_then(|v| v.as_object()) {
                for (name, spec) in map {
                    let src = format!("{} [{}]", source(label, path), short(Path::new(proj)));
                    out.push(parse(name, spec, &src, Some(PathBuf::from(proj))));
                }
            }
        }
    }
}

fn parse(name: &str, spec: &Value, source: &str, config_dir: Option<PathBuf>) -> Discovered {
    let command = spec
        .get("command")
        .and_then(|v| v.as_str())
        .map(String::from);
    let url = spec
        .get("url")
        .and_then(|v| v.as_str())
        .map(String::from)
        .or_else(|| {
            spec.get("serverUrl")
                .and_then(|v| v.as_str())
                .map(String::from)
        });
    let args = spec
        .get("args")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let has_env = spec
        .get("env")
        .and_then(|v| v.as_object())
        .map(|o| !o.is_empty())
        .unwrap_or(false);
    Discovered {
        name: name.to_string(),
        command,
        args,
        url,
        has_env,
        source: source.to_string(),
        // Filled in once by `discover()` after the client enable records are read.
        status: Status::Configured,
        config_dir,
    }
}

/// The set of servers/plugins the client(s) have explicitly enabled, read from
/// their own config so gurgl can distinguish "turned on" from "just present".
#[derive(Default)]
struct EnabledIndex {
    /// `.mcp.json` servers a client enabled, as (project_dir, name) pairs. Keyed
    /// by project, NOT flattened by bare name: `enabledMcpjsonServers` is a
    /// per-project record, and a name enabled in project A must not mark a
    /// same-named server in project B as enabled.
    mcp_servers: std::collections::HashSet<(String, String)>,
    /// Plugin names from an `enabledPlugins` record (normalised, `name@mkt` ->
    /// `name`).
    plugins: std::collections::HashSet<String>,
}

impl EnabledIndex {
    /// Read the known enable records. Best-effort and read-only: a missing or
    /// unparseable file just contributes nothing.
    fn load() -> Self {
        let mut idx = EnabledIndex::default();
        let Some(home) = dirs::home_dir() else {
            return idx;
        };

        // Claude Code: per-project `enabledMcpjsonServers` and `enabledPlugins`
        // live in ~/.claude.json.
        if let Some(json) = read_json(&home.join(".claude.json")) {
            if let Some(projects) = json.get("projects").and_then(|v| v.as_object()) {
                for (proj, pv) in projects {
                    if let Some(arr) = pv.get("enabledMcpjsonServers").and_then(|v| v.as_array()) {
                        for name in arr.iter().filter_map(|s| s.as_str()) {
                            idx.mcp_servers.insert((proj.clone(), name.to_string()));
                        }
                    }
                    collect_plugin_ids(pv.get("enabledPlugins"), &mut idx.plugins);
                }
            }
            collect_plugin_ids(json.get("enabledPlugins"), &mut idx.plugins);
        }

        // Plugin enablement can also sit in the user settings.
        for name in ["settings.json", "settings.local.json"] {
            if let Some(json) = read_json(&home.join(".claude").join(name)) {
                collect_plugin_ids(json.get("enabledPlugins"), &mut idx.plugins);
            }
        }
        idx
    }

    fn status_for(&self, d: &Discovered) -> Status {
        // label_for now sets the "plugin" label only for real plugin roots.
        let is_plugin = d.source.starts_with("plugin ");
        let enabled = if is_plugin {
            self.plugins.contains(&d.name)
        } else {
            // Enabled only when THIS server's project has it in its own
            // enabledMcpjsonServers. If we can't determine the project, we never
            // claim Enabled (safe direction: under-report, never over-report).
            match &d.config_dir {
                Some(dir) => self
                    .mcp_servers
                    .contains(&(dir.to_string_lossy().to_string(), d.name.clone())),
                None => false,
            }
        };
        if enabled {
            Status::Enabled
        } else if is_plugin {
            Status::Bundled
        } else {
            Status::Configured
        }
    }
}

fn read_json(path: &Path) -> Option<Value> {
    serde_json::from_str(&read_capped(path)?).ok()
}

/// Pull enabled plugin identifiers from an `enabledPlugins` value, which is
/// either an object (`{"name@mkt": true}`) or an array (`["name@mkt"]`). The
/// marketplace suffix is dropped so it matches a plugin's server name.
fn collect_plugin_ids(v: Option<&Value>, out: &mut std::collections::HashSet<String>) {
    let norm = |k: &str| k.split('@').next().unwrap_or(k).to_string();
    match v {
        Some(Value::Object(m)) => {
            for (k, val) in m {
                if val.as_bool() != Some(false) {
                    out.insert(norm(k));
                }
            }
        }
        Some(Value::Array(a)) => {
            for s in a.iter().filter_map(|s| s.as_str()) {
                out.insert(norm(s));
            }
        }
        _ => {}
    }
}

fn source(label: &str, path: &Path) -> String {
    format!("{label} ({})", short(path))
}

/// Abbreviate a path with `~` for readability.
fn short(path: &Path) -> String {
    if let Some(home) = dirs::home_dir() {
        if let Ok(rest) = path.strip_prefix(&home) {
            return format!("~/{}", rest.display());
        }
    }
    path.display().to_string()
}

/// Render a discovered server as a `[[servers]]` TOML block for import.
///
/// Serialized by the `toml` crate, NOT hand-formatted: a server name or arg from
/// an untrusted client config can contain quotes, backslashes, or control
/// characters, and Rust's `{:?}` debug escaping is not TOML escaping (it emits
/// `\u{7f}`-style sequences TOML rejects). Hand-rolling it produced files that
/// then failed to parse and corrupted `gurgl.toml` on import.
pub fn to_toml_block(d: &Discovered) -> String {
    #[derive(serde::Serialize)]
    struct Entry<'a> {
        name: &'a str,
        command: &'a str,
        args: &'a [String],
    }
    #[derive(serde::Serialize)]
    struct Wrap<'a> {
        servers: Vec<Entry<'a>>,
    }
    let wrap = Wrap {
        servers: vec![Entry {
            name: &d.name,
            command: d.command.as_deref().unwrap_or_default(),
            args: &d.args,
        }],
    };
    // toml::to_string of a single-element array-of-tables yields a well-formed
    // `[[servers]]` block; on the (string-only, never-failing) serialize path an
    // error can't occur, but default to empty rather than panic.
    let mut s = format!("\n{}", toml::to_string(&wrap).unwrap_or_default());
    if d.has_env {
        s.push_str(
            "# NOTE: this server sets env (often API keys) in its client config; gurgl does\n",
        );
        s.push_str(
            "# not copy env. Forward specific vars with `pass_env = [\"NAME\"]` on this server,\n",
        );
        s.push_str("# or set them in gurgl's own environment, so it can launch.\n");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn collect_reads_top_level_and_nested_servers() {
        let cfg = json!({
            "mcpServers": {
                "filesystem": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
                },
                "remote-thing": { "url": "https://mcp.example.com/sse" }
            },
            "projects": {
                "/home/x/proj": {
                    "mcpServers": {
                        "github": {
                            "command": "npx",
                            "args": ["-y", "@modelcontextprotocol/server-github"],
                            "env": { "GITHUB_TOKEN": "secret" }
                        }
                    }
                }
            }
        });
        let mut out = Vec::new();
        collect(&cfg, "Test", Path::new("/cfg.json"), &mut out);

        assert_eq!(out.len(), 3);
        let fs = out.iter().find(|d| d.name == "filesystem").unwrap();
        assert!(fs.is_stdio());
        assert_eq!(fs.command.as_deref(), Some("npx"));
        assert!(!fs.has_env);

        let remote = out.iter().find(|d| d.name == "remote-thing").unwrap();
        assert!(!remote.is_stdio());
        assert_eq!(remote.url.as_deref(), Some("https://mcp.example.com/sse"));

        // env presence is flagged but its value is never captured.
        let gh = out.iter().find(|d| d.name == "github").unwrap();
        assert!(gh.has_env);
    }

    #[test]
    fn toml_block_round_trips_as_valid_server() {
        let d = Discovered {
            name: "filesystem".into(),
            command: Some("npx".into()),
            args: vec![
                "-y".into(),
                "@modelcontextprotocol/server-filesystem".into(),
            ],
            url: None,
            has_env: false,
            source: "Test".into(),
            status: Status::Configured,
            config_dir: None,
        };
        let block = to_toml_block(&d);
        let cfg: crate::config::Config = toml::from_str(&block).unwrap();
        assert_eq!(cfg.servers.len(), 1);
        assert_eq!(cfg.servers[0].name, "filesystem");
        assert_eq!(cfg.servers[0].command, "npx");
        assert_eq!(cfg.servers[0].args.len(), 2);
    }

    #[test]
    fn toml_block_escapes_hostile_strings_into_valid_toml() {
        // A name/arg from an untrusted client config with quotes, a backslash,
        // and a control char. The old `{:?}` hand-formatting emitted invalid
        // TOML (`\u{7f}`) that corrupted gurgl.toml on import; the toml
        // serializer must round-trip it exactly.
        let d = Discovered {
            name: "evil\"name\u{7f}\\x".into(),
            command: Some("npx".into()),
            args: vec!["--flag=\"quoted\"".into(), "tab\there".into()],
            url: None,
            has_env: false,
            source: "Test".into(),
            status: Status::Configured,
            config_dir: None,
        };
        let block = to_toml_block(&d);
        let cfg: crate::config::Config =
            toml::from_str(&block).expect("hostile strings must still produce valid TOML");
        assert_eq!(cfg.servers[0].name, "evil\"name\u{7f}\\x");
        assert_eq!(cfg.servers[0].args[0], "--flag=\"quoted\"");
        assert_eq!(cfg.servers[0].args[1], "tab\there");
    }

    fn disc(name: &str, source: &str, dir: Option<&str>) -> Discovered {
        Discovered {
            name: name.into(),
            command: Some("bun".into()),
            args: vec![],
            url: None,
            has_env: false,
            source: source.into(),
            status: Status::Configured,
            config_dir: dir.map(PathBuf::from),
        }
    }

    #[test]
    fn status_marks_enabled_bundled_and_configured() {
        let mut idx = EnabledIndex::default();
        idx.mcp_servers
            .insert(("/home/x/proj".into(), "statewright".into()));
        idx.plugins.insert("discord".into());

        // A plugin listed in enabledPlugins -> Enabled.
        let on = disc(
            "discord",
            "plugin (~/.claude/plugins/.../discord/.mcp.json)",
            None,
        );
        assert_eq!(idx.status_for(&on), Status::Enabled);

        // A plugin NOT in the enable list -> Bundled (available, not on).
        let off = disc(
            "telegram",
            "plugin (~/.claude/plugins/.../telegram/.mcp.json)",
            None,
        );
        assert_eq!(idx.status_for(&off), Status::Bundled);

        // A project server enabled in ITS project's enabledMcpjsonServers -> Enabled.
        let approved = disc(
            "statewright",
            "project (~/proj/.mcp.json)",
            Some("/home/x/proj"),
        );
        assert_eq!(idx.status_for(&approved), Status::Enabled);

        // The SAME name in a DIFFERENT project must NOT inherit that enable.
        let elsewhere = disc(
            "statewright",
            "project (~/other/.mcp.json)",
            Some("/home/x/other"),
        );
        assert_eq!(idx.status_for(&elsewhere), Status::Configured);

        // A configured-but-unapproved project server -> Configured.
        let pending = disc(
            "monarch",
            "project (~/some/repo/.mcp.json)",
            Some("/home/x/some/repo"),
        );
        assert_eq!(idx.status_for(&pending), Status::Configured);
    }

    #[test]
    fn parse_codex_reads_toml_mcp_servers() {
        let toml_text = r#"
model = "gpt-5"

[mcp_servers.docs]
command = "npx"
args = ["-y", "docs-mcp"]
env = { API_KEY = "x" }

[mcp_servers.remote_tool]
url = "https://mcp.example.com/mcp"
bearer_token_env_var = "TOKEN"
"#;
        let dir = std::env::temp_dir().join("gurgl-codex-test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");
        std::fs::write(&path, toml_text).unwrap();

        let mut out = Vec::new();
        parse_codex_file(&path, &mut out);
        let _ = std::fs::remove_dir_all(&dir);

        assert_eq!(out.len(), 2);
        let docs = out.iter().find(|d| d.name == "docs").unwrap();
        assert!(docs.is_stdio());
        assert_eq!(docs.command.as_deref(), Some("npx"));
        assert_eq!(docs.args, vec!["-y", "docs-mcp"]);
        assert!(docs.has_env);
        assert!(docs.source.starts_with("Codex "));

        let remote = out.iter().find(|d| d.name == "remote_tool").unwrap();
        assert!(!remote.is_stdio());
        assert_eq!(remote.url.as_deref(), Some("https://mcp.example.com/mcp"));
    }

    #[test]
    fn collect_plugin_ids_handles_object_and_array() {
        let mut out = std::collections::HashSet::new();
        collect_plugin_ids(
            Some(&json!({"discord@official": true, "off@official": false})),
            &mut out,
        );
        collect_plugin_ids(Some(&json!(["telegram@official"])), &mut out);
        assert!(out.contains("discord"));
        assert!(out.contains("telegram"));
        assert!(!out.contains("off")); // explicitly false -> not enabled
    }

    #[test]
    fn dedupe_keeps_strongest_status() {
        // The same server (identical command+args) configured in three projects,
        // enabled in only one: the collapsed row must be Enabled regardless of the
        // (filesystem-dependent) order the projects were walked, with one row.
        let mk = |status| Discovered {
            name: "github".into(),
            command: Some("npx".into()),
            args: vec!["-y".into(), "server-github".into()],
            url: None,
            has_env: false,
            source: "x".into(),
            status,
            config_dir: None,
        };
        for order in [
            vec![Status::Configured, Status::Enabled, Status::Configured],
            vec![Status::Enabled, Status::Configured, Status::Configured],
            vec![Status::Configured, Status::Configured, Status::Enabled],
        ] {
            let out = dedupe_strongest(order.into_iter().map(mk).collect());
            assert_eq!(out.len(), 1);
            assert_eq!(out[0].status, Status::Enabled);
        }
    }
}
