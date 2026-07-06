//! Derive the version a downloading launcher (npx/uvx/pipx/bunx) actually
//! resolved and installed, by reading the local files it wrote into the sandbox
//! HOME. This is stronger than the server's self-reported `serverInfo.version`
//! (which is attacker-chosen and never a trustworthy storage key) because it
//! reflects what the registry actually served at install time.
//!
//! Everything here is pure and bounded: no network, no shelling out, size-capped
//! reads, a depth/entry-capped walk (the tree was written by untrusted code), and
//! symlinks are never followed. A layout we do not recognize returns `None` so
//! the caller falls back to the server-reported version - degrading gracefully
//! must never turn into erroring a capture. The residual limit (a hostile
//! postinstall can rewrite its own package.json) is stated in docs/THREAT-MODEL.md.

use std::path::Path;

/// Bound the walk so a hostile or huge install tree cannot hang or OOM us.
const MAX_WALK_ENTRIES: usize = 50_000;
const MAX_DEPTH: usize = 10;
const MAX_MANIFEST: u64 = 1024 * 1024;

/// The package a downloading launcher will install, extracted from its argv.
/// Returns `None` for a non-launcher command or when the target cannot be
/// identified - ambiguity is safer as `None` (the caller falls back to
/// serverInfo/unknown) than guessing a wrong package.
pub fn package_from_args(command: &str, args: &[String]) -> Option<String> {
    match launcher(command)? {
        Launcher::Npm => npx_like_package(args),
        Launcher::Uvx => uvx_package(args),
        Launcher::Pipx => pipx_package(args),
    }
}

/// The version resolved for `package` under `home` (the sandbox HOME after the
/// capture ran). `None` if the launcher's cache layout is unrecognized or the
/// package is not found - always a graceful fall-through, never an error.
pub fn installed_version(command: &str, package: &str, home: &Path) -> Option<String> {
    match launcher(command)? {
        Launcher::Npm => npm_installed_version(package, home),
        Launcher::Uvx | Launcher::Pipx => py_installed_version(package, home),
    }
}

enum Launcher {
    Npm,
    Uvx,
    Pipx,
}

/// Map a launch command to its ecosystem. `bunx` shares npm's package identity
/// and node_modules layout, so it rides the npm path (its cache dir differs and
/// may simply miss - that degrades to `None`).
fn launcher(command: &str) -> Option<Launcher> {
    match command.rsplit(['/', '\\']).next().unwrap_or(command) {
        "npx" | "bunx" => Some(Launcher::Npm),
        "uvx" => Some(Launcher::Uvx),
        "pipx" => Some(Launcher::Pipx),
        _ => None,
    }
}

// --- argv parsing (node/npx) -------------------------------------------------

fn npx_like_package(args: &[String]) -> Option<String> {
    let mut explicit: Option<String> = None;
    let mut positional: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if let Some(rest) = a.strip_prefix("--package=") {
            explicit = Some(rest.to_string());
        } else if a == "--package" || a == "-p" {
            if let Some(v) = args.get(i + 1) {
                explicit = Some(v.clone());
                i += 1;
            }
        } else if a.starts_with('-') {
            // A bare flag (e.g. -y/--yes/-q). npx flags we care about are handled
            // above; others we treat as valueless and skip. A flag that actually
            // takes a value can misread its value as the positional package - that
            // just yields a not-found lookup -> None, which is the safe failure.
        } else {
            // The first positional is the command/package to run; its own args
            // follow and must not be considered.
            positional = Some(a.clone());
            break;
        }
        i += 1;
    }
    // An explicit --package wins over the positional bin name (with -p, the
    // positional is the binary, not the package).
    Some(strip_npm_spec(&explicit.or(positional)?))
}

/// `foo@1.2` -> `foo`; `@scope/name@1.2` -> `@scope/name`; a leading `@` scope is
/// preserved, only a trailing version spec is stripped.
fn strip_npm_spec(pkg: &str) -> String {
    if let Some(rest) = pkg.strip_prefix('@') {
        if let Some(slash) = rest.find('/') {
            let scope = &rest[..slash];
            let name_part = &rest[slash + 1..];
            let name = name_part.split('@').next().unwrap_or(name_part);
            return format!("@{scope}/{name}");
        }
        let base = rest.split('@').next().unwrap_or(rest);
        return format!("@{base}");
    }
    pkg.split('@').next().unwrap_or(pkg).to_string()
}

// --- argv parsing (python/uv) ------------------------------------------------

fn uvx_package(args: &[String]) -> Option<String> {
    let mut positional: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if let Some(rest) = a.strip_prefix("--from=") {
            return Some(strip_py_spec(rest));
        } else if a == "--from" {
            return args.get(i + 1).map(|v| strip_py_spec(v));
        } else if matches!(a.as_str(), "--with" | "--python" | "-p") {
            i += 1; // these take a value we skip
        } else if a.starts_with('-') {
            // valueless flag; skip
        } else {
            positional = Some(a.clone());
            break;
        }
        i += 1;
    }
    positional.map(|p| strip_py_spec(&p))
}

fn pipx_package(args: &[String]) -> Option<String> {
    // Only `pipx run <pkg>` installs+runs an ephemeral package.
    let run_idx = args.iter().position(|a| a == "run")?;
    let rest = &args[run_idx + 1..];
    let mut i = 0;
    while i < rest.len() {
        let a = &rest[i];
        if let Some(s) = a.strip_prefix("--spec=") {
            return Some(strip_py_spec(s));
        } else if a == "--spec" {
            return rest.get(i + 1).map(|v| strip_py_spec(v));
        } else if a.starts_with('-') {
            // skip; a value-taking flag degrades to a not-found lookup -> None
        } else {
            return Some(strip_py_spec(a));
        }
        i += 1;
    }
    None
}

/// Strip a PEP 508 version spec (`pkg==1.2`, `pkg>=1`, `pkg@url`) to the bare
/// name.
fn strip_py_spec(pkg: &str) -> String {
    let end = pkg
        .find(|c: char| "=<>!~@ ".contains(c))
        .unwrap_or(pkg.len());
    pkg[..end].to_string()
}

// --- installed-version lookups -----------------------------------------------

fn npm_installed_version(package: &str, home: &Path) -> Option<String> {
    // npx unpacks under ~/.npm/_npx/<hash>/node_modules/<package>/. Search that
    // first (the common, stable case), then fall back to any node_modules under
    // HOME (covers bunx / a launcher that installs into the working dir).
    let npx_root = home.join(".npm").join("_npx");
    let mut budget = MAX_WALK_ENTRIES;
    if let Some(v) = walk_for_node_pkg(&npx_root, package, MAX_DEPTH, &mut budget) {
        return Some(v);
    }
    let mut budget = MAX_WALK_ENTRIES;
    walk_for_node_pkg(home, package, MAX_DEPTH, &mut budget)
}

/// Descend `dir` looking for `node_modules/<package>/package.json` and read its
/// `version`. Depth- and entry-bounded; never follows symlinks.
fn walk_for_node_pkg(
    dir: &Path,
    package: &str,
    depth: usize,
    budget: &mut usize,
) -> Option<String> {
    if depth == 0 || *budget == 0 {
        return None;
    }
    let entries = std::fs::read_dir(dir).ok()?;
    for e in entries.flatten() {
        if *budget == 0 {
            break;
        }
        *budget -= 1;
        let Ok(ft) = e.file_type() else { continue };
        if ft.is_symlink() || !ft.is_dir() {
            continue;
        }
        let path = e.path();
        if e.file_name().to_str() == Some("node_modules") {
            let manifest = path.join(package).join("package.json");
            if let Some(v) = read_json_version(&manifest) {
                return Some(v);
            }
        }
        if let Some(v) = walk_for_node_pkg(&path, package, depth - 1, budget) {
            return Some(v);
        }
    }
    None
}

fn read_json_version(manifest: &Path) -> Option<String> {
    let meta = std::fs::symlink_metadata(manifest).ok()?;
    if !meta.file_type().is_file() || meta.len() > MAX_MANIFEST {
        return None;
    }
    let text = std::fs::read_to_string(manifest).ok()?;
    let v: serde_json::Value = serde_json::from_str(&text).ok()?;
    let ver = v.get("version")?.as_str()?.trim();
    (!ver.is_empty()).then(|| ver.to_string())
}

fn py_installed_version(package: &str, home: &Path) -> Option<String> {
    let norm = pep503_normalize(package);
    // uv keeps built environments/wheels under its cache; pipx under per-package
    // venvs. Search the documented roots; an unrecognized layout misses -> None.
    let roots = [
        home.join(".cache").join("uv"),
        home.join(".local").join("share").join("uv"),
        home.join(".local").join("pipx").join("venvs"),
    ];
    for root in roots {
        let mut budget = MAX_WALK_ENTRIES;
        if let Some(v) = walk_for_dist_info(&root, &norm, MAX_DEPTH, &mut budget) {
            return Some(v);
        }
    }
    None
}

/// Find a `<name>-<version>.dist-info` directory whose PEP 503-normalized name
/// matches `norm`, and return its version. Depth/entry-bounded, no symlinks.
fn walk_for_dist_info(dir: &Path, norm: &str, depth: usize, budget: &mut usize) -> Option<String> {
    if depth == 0 || *budget == 0 {
        return None;
    }
    let entries = std::fs::read_dir(dir).ok()?;
    for e in entries.flatten() {
        if *budget == 0 {
            break;
        }
        *budget -= 1;
        let Ok(ft) = e.file_type() else { continue };
        if ft.is_symlink() || !ft.is_dir() {
            continue;
        }
        if let Some(name) = e.file_name().to_str() {
            if let Some(stem) = name.strip_suffix(".dist-info") {
                if let Some((dist, ver)) = stem.rsplit_once('-') {
                    if pep503_normalize(dist) == norm && !ver.is_empty() {
                        return Some(ver.to_string());
                    }
                }
            }
        }
        if let Some(v) = walk_for_dist_info(&e.path(), norm, depth - 1, budget) {
            return Some(v);
        }
    }
    None
}

/// PEP 503 name normalization: lowercase, and any run of `-`, `_`, `.` collapses
/// to a single `-`.
fn pep503_normalize(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut prev_sep = false;
    for c in name.chars() {
        if matches!(c, '-' | '_' | '.') {
            if !prev_sep && !out.is_empty() {
                out.push('-');
            }
            prev_sep = true;
        } else {
            out.push(c.to_ascii_lowercase());
            prev_sep = false;
        }
    }
    out.trim_matches('-').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn npx_argv_shapes() {
        let p = |a: &[&str]| {
            package_from_args("npx", &a.iter().map(|s| s.to_string()).collect::<Vec<_>>())
        };
        // The common client-config shape.
        assert_eq!(
            p(&["-y", "@modelcontextprotocol/server-filesystem", "/data"]),
            Some("@modelcontextprotocol/server-filesystem".into())
        );
        // A pinned version is stripped, scope preserved.
        assert_eq!(p(&["-y", "@scope/name@1.2.3"]), Some("@scope/name".into()));
        assert_eq!(p(&["foo@2.0.0", "arg"]), Some("foo".into()));
        // Explicit --package wins over the positional binary name.
        assert_eq!(
            p(&["--package", "left-pad@1.0.0", "some-bin"]),
            Some("left-pad".into())
        );
        assert_eq!(p(&["-p", "cowsay", "cowsay", "moo"]), Some("cowsay".into()));
        // A full path to the launcher still resolves.
        assert_eq!(
            package_from_args("/usr/bin/npx", &["-y".into(), "pkg".into()]),
            Some("pkg".into())
        );
        // A non-launcher command derives nothing.
        assert_eq!(package_from_args("node", &["server.js".into()]), None);
    }

    #[test]
    fn uvx_and_pipx_argv_shapes() {
        let uvx = |a: &[&str]| {
            package_from_args("uvx", &a.iter().map(|s| s.to_string()).collect::<Vec<_>>())
        };
        assert_eq!(uvx(&["mcp-server-git"]), Some("mcp-server-git".into()));
        assert_eq!(
            uvx(&["mcp-server-git==0.6.2"]),
            Some("mcp-server-git".into())
        );
        assert_eq!(
            uvx(&["--from", "some-dist==1.0", "the-cmd"]),
            Some("some-dist".into())
        );
        assert_eq!(
            uvx(&["--python", "3.12", "toolname"]),
            Some("toolname".into())
        );

        let pipx = |a: &[&str]| {
            package_from_args("pipx", &a.iter().map(|s| s.to_string()).collect::<Vec<_>>())
        };
        assert_eq!(pipx(&["run", "black"]), Some("black".into()));
        assert_eq!(
            pipx(&["run", "--spec", "black==24.1.0", "black"]),
            Some("black".into())
        );
        // Without `run`, pipx installs nothing ephemeral here.
        assert_eq!(pipx(&["install", "black"]), None);
    }

    #[test]
    fn pep503_normalizes() {
        assert_eq!(pep503_normalize("Foo.Bar_Baz"), "foo-bar-baz");
        assert_eq!(pep503_normalize("mcp__server--git"), "mcp-server-git");
    }

    #[test]
    fn reads_npx_installed_version_from_fixture_tree() {
        let dir = std::env::temp_dir().join(format!("gurgl-pkgver-npx-{}", std::process::id()));
        let pkg_dir = dir
            .join(".npm")
            .join("_npx")
            .join("deadbeef")
            .join("node_modules")
            .join("@modelcontextprotocol")
            .join("server-filesystem");
        fs::create_dir_all(&pkg_dir).unwrap();
        fs::write(
            pkg_dir.join("package.json"),
            r#"{"name":"@modelcontextprotocol/server-filesystem","version":"1.4.2"}"#,
        )
        .unwrap();
        let got = installed_version("npx", "@modelcontextprotocol/server-filesystem", &dir);
        let _ = fs::remove_dir_all(&dir);
        assert_eq!(got, Some("1.4.2".into()));
    }

    #[test]
    fn reads_uvx_version_from_dist_info() {
        let dir = std::env::temp_dir().join(format!("gurgl-pkgver-uvx-{}", std::process::id()));
        let site = dir
            .join(".cache")
            .join("uv")
            .join("builds-v0")
            .join("xyz")
            .join("site-packages");
        fs::create_dir_all(site.join("mcp_server_git-0.6.2.dist-info")).unwrap();
        let got = installed_version("uvx", "mcp-server-git", &dir);
        let _ = fs::remove_dir_all(&dir);
        assert_eq!(got, Some("0.6.2".into()));
    }

    #[test]
    fn unknown_package_or_layout_is_none_not_error() {
        let dir = std::env::temp_dir().join(format!("gurgl-pkgver-none-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let got = installed_version("npx", "not-installed", &dir);
        let _ = fs::remove_dir_all(&dir);
        assert_eq!(got, None);
    }
}
