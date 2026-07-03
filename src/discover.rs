//! Discover MCP servers already configured on this machine.
//!
//! Every MCP client stores its servers in a predictable JSON config with an
//! `mcpServers` object (`{ "name": { "command", "args", "env" } }`). gurgl scans
//! the well-known locations (Claude Desktop, Claude Code, Cursor, Windsurf,
//! Cline) so you can see, and then watch, the servers you actually run rather
//! than hand-listing them.
//!
//! This only reads config files; it never records or prints `env` values (which
//! commonly hold API keys). It reports *that* a server sets env, not what.

use std::path::{Path, PathBuf};

use serde_json::Value;

/// One MCP server found in a client config.
#[derive(Debug, Clone)]
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

    // Project-local, relative to the current directory.
    v.push(("project", PathBuf::from(".mcp.json")));
    v.push(("project", PathBuf::from(".cursor/mcp.json")));
    v
}

/// Scan every known config file and return the MCP servers found.
pub fn discover() -> Vec<Discovered> {
    let mut out = Vec::new();
    for (label, path) in config_files() {
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        let Ok(json) = serde_json::from_str::<Value>(&text) else {
            continue;
        };
        collect(&json, label, &path, &mut out);
    }
    out
}

fn collect(json: &Value, label: &str, path: &Path, out: &mut Vec<Discovered>) {
    if let Some(map) = json.get("mcpServers").and_then(|v| v.as_object()) {
        for (name, spec) in map {
            out.push(parse(name, spec, &source(label, path)));
        }
    }
    // Claude Code's ~/.claude.json also nests servers per project.
    if let Some(projects) = json.get("projects").and_then(|v| v.as_object()) {
        for (proj, pv) in projects {
            if let Some(map) = pv.get("mcpServers").and_then(|v| v.as_object()) {
                for (name, spec) in map {
                    let src = format!("{} [{}]", source(label, path), short(Path::new(proj)));
                    out.push(parse(name, spec, &src));
                }
            }
        }
    }
}

fn parse(name: &str, spec: &Value, source: &str) -> Discovered {
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
pub fn to_toml_block(d: &Discovered) -> String {
    let cmd = d.command.clone().unwrap_or_default();
    let args = d
        .args
        .iter()
        .map(|a| format!("{a:?}"))
        .collect::<Vec<_>>()
        .join(", ");
    let mut s = format!(
        "\n[[servers]]\nname = {:?}\ncommand = {:?}\nargs = [{}]\n",
        d.name, cmd, args
    );
    if d.has_env {
        s.push_str(
            "# NOTE: this server sets env (often API keys) in its client config; gurgl does\n",
        );
        s.push_str("# not copy env yet, so it may need those set in gurgl's environment to run.\n");
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
        };
        let block = to_toml_block(&d);
        let cfg: crate::config::Config = toml::from_str(&block).unwrap();
        assert_eq!(cfg.servers.len(), 1);
        assert_eq!(cfg.servers[0].name, "filesystem");
        assert_eq!(cfg.servers[0].command, "npx");
        assert_eq!(cfg.servers[0].args.len(), 2);
    }
}
