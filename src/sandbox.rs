//! Sandbox backends.
//!
//! gurgl runs each MCP server in an isolated environment whose only path to the
//! network is the capture proxy, so we see everything it tries to send. Three
//! backends: bubblewrap (Linux default, rootless), podman, and sandbox-exec
//! (macOS-native Seatbelt).
//!
//! ## v1 status
//! `build_argv` (pure command construction) is implemented and tested. Actually
//! forcing *all* egress through the proxy - rather than relying on the client to
//! honor proxy env vars - is the hardening step tracked in docs/ROADMAP.md
//! (transparent redirect). Client cooperation varies and is the honest limit of
//! env-proxy capture: curl and Linux Python honor `HTTPS_PROXY`/`SSL_CERT_FILE`;
//! Node ignores proxy env by default, so gurgl also sets `NODE_USE_ENV_PROXY=1`
//! (Node 24+) which makes its http/https client and fetch route through the
//! proxy (verified). Older runtimes, the macOS system Python, and clients with a
//! pinned or explicitly-set agent still bypass it until transparent redirect
//! lands. See docs/THREAT-MODEL.md#capture-fidelity.

use crate::config::{SandboxKind, ServerSpec};

/// Environment gurgl injects so a cooperating client routes TLS through the
/// capture proxy and trusts the lab CA.
#[derive(Debug, Clone)]
pub struct ProxyEnv {
    /// e.g. "http://127.0.0.1:8080"
    pub https_proxy: String,
    /// Absolute path to the lab CA cert (PEM) inside the sandbox.
    pub ca_cert_path: String,
    /// Host-side directory bound as the sandbox HOME (`/tmp/home` inside
    /// bwrap/podman; used directly on macOS sandbox-exec). It must survive
    /// teardown so gurgl can read the version the launcher resolved into it (see
    /// `pkgver`); the caller removes it after. Empty string = no home binding.
    pub sandbox_home: String,
    /// Forced-capture launch (netns + transparent redirect): the client is
    /// REDIRECTED to the proxy by nftables, never proxied, so the proxy env vars
    /// are omitted (a transparent mitmdump cannot accept a CONNECT and would
    /// break a cooperating client that tried to use them). Only the CA-trust vars
    /// remain, so the intercepting cert is accepted. `false` = env-proxy capture.
    pub forced: bool,
}

/// PATH for a sandboxed child: prepend gurgl's and the user-local bin dirs to the
/// inherited PATH so a runtime installed under the user's home (nvm, ~/.local,
/// gurgl's own node) is resolvable. `npx` runs via `#!/usr/bin/env node`, so node
/// must be found inside the sandbox even when the launching shell's PATH differs.
fn base_path() -> String {
    let home = dirs::home_dir()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_default();
    let inherited = std::env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin".to_string());
    format!("{home}/.gurgl/bin:{home}/.local/bin:{inherited}")
}

/// Minimal environment for a NO-PROXY sandbox launch (`gurgl plan`'s tool
/// enumeration): PATH plus an explicitly-empty NO_PROXY, and nothing that would
/// wire a proxy or CA. The server runs against the real network here - this is an
/// authoring step, not a capture.
pub fn base_env() -> Vec<(String, String)> {
    vec![
        ("PATH".into(), base_path()),
        ("NO_PROXY".into(), String::new()),
        ("no_proxy".into(), String::new()),
    ]
}

impl ProxyEnv {
    /// (KEY, VALUE) pairs to set in the sandboxed process environment.
    pub fn vars(&self) -> Vec<(String, String)> {
        // The CA-trust vars are needed in BOTH modes so the intercepting cert is
        // accepted. GURGL_FLOWOUT is deliberately NOT set here: only the mitmproxy
        // addon reads it, and it runs OUTSIDE the sandbox (gurgl sets it on the
        // mitmdump process directly). Injecting it would advertise the evidence
        // file path and fingerprint the run as "under gurgl".
        let mut v = vec![
            ("PATH".into(), base_path()),
            // Explicitly empty NO_PROXY so an inherited value (or one a client
            // sets by default) cannot carve out hosts that egress unobserved.
            ("NO_PROXY".into(), String::new()),
            ("no_proxy".into(), String::new()),
            ("NODE_EXTRA_CA_CERTS".into(), self.ca_cert_path.clone()),
            ("SSL_CERT_FILE".into(), self.ca_cert_path.clone()),
            ("REQUESTS_CA_BUNDLE".into(), self.ca_cert_path.clone()),
            ("CURL_CA_BUNDLE".into(), self.ca_cert_path.clone()),
        ];
        // Forced mode redirects the client to the proxy with nftables, so it must
        // NOT advertise a proxy: a transparent mitmdump cannot answer a CONNECT,
        // and a cooperating client that honored HTTPS_PROXY would then fail. The
        // redirect captures the raw connection regardless; env-proxy mode instead
        // relies on the client honoring these vars.
        if !self.forced {
            for k in [
                "HTTPS_PROXY",
                "HTTP_PROXY",
                "ALL_PROXY",
                "https_proxy",
                "http_proxy",
                "all_proxy",
            ] {
                v.push((k.into(), self.https_proxy.clone()));
            }
            // Node ignores proxy env by default; this (Node 24+) makes its
            // http/https client AND fetch honor it. Pointless without a proxy, so
            // forced mode omits it (there, the redirect does the forcing).
            v.push(("NODE_USE_ENV_PROXY".into(), "1".into()));
        }
        v
    }
}

/// The nftables ruleset that FORCES a proxy-ignoring client's TCP egress through
/// the transparent proxy, inside the capture network namespace. Pure so it is
/// unit-testable; the caller feeds it to `nft -f -` via `nsenter`.
///
/// It is an `inet` table (an `ip` table would let IPv6 escape) hooking `output`
/// (the traffic is locally generated inside the netns, not forwarded). The
/// `skuid <launcher_uid> return` line is load-bearing: the proxy runs as that uid
/// and its OWN upstream connection to the origin must NOT be re-redirected, or it
/// loops into itself (a flow storm). Everything else on 80/443 is redirected to
/// the proxy; UDP/443 is dropped so a client cannot slip out over QUIC/HTTP-3.
/// Validated by the slice-1b spike (see the netns-spike memory).
pub fn nft_ruleset(launcher_uid: u32, mitm_port: u16) -> String {
    format!(
        "table inet gurgl {{\n  \
           chain out {{\n    \
             type nat hook output priority -100; policy accept;\n    \
             meta skuid {launcher_uid} return\n    \
             tcp dport {mitm_port} return\n    \
             ip daddr 127.0.0.0/8 return\n    \
             tcp dport {{ 80, 443 }} redirect to :{mitm_port}\n    \
             udp dport 443 drop\n  \
           }}\n\
         }}\n"
    )
}

/// Build the argv to launch `spec` under the chosen sandbox backend.
///
/// The returned vector is a full command line: `argv[0]` is the sandbox binary.
/// `extra_env` is the resolved `pass_env` forwarding (var name -> value read
/// from gurgl's own environment). bwrap and podman set the child's environment
/// from argv, so it is threaded in here; sandbox-exec's child inherits the
/// caller's environment, so gurgl clears and re-sets that at spawn time instead.
///
/// `env` is `Some` for a capture launch (proxy + CA + host home wired in) and
/// `None` for a no-proxy authoring launch (`gurgl plan` enumerating tools): with
/// `None` the CA bind and proxy vars are skipped and `base_env()` is used, so the
/// server runs against the real network. The child is still sandboxed either way.
pub fn build_argv(
    kind: SandboxKind,
    spec: &ServerSpec,
    env: Option<&ProxyEnv>,
    extra_env: &[(String, String)],
) -> Vec<String> {
    match kind {
        SandboxKind::Bubblewrap => build_bwrap_argv(spec, env, extra_env),
        SandboxKind::Podman => build_podman_argv(spec, env, extra_env),
        SandboxKind::SandboxExec => build_sandbox_exec_argv(spec, env),
    }
}

/// macOS Seatbelt profile. v1 starting point - NOT a hardened boundary yet.
/// A real least-privilege profile (deny-by-default filesystem, network only to
/// the proxy) is the hardening task mirroring the Linux netns work; see
/// docs/ROADMAP.md. Kept deliberately simple and readable until then.
const SEATBELT_PROFILE: &str = "(version 1)\n(allow default)\n";

fn build_sandbox_exec_argv(spec: &ServerSpec, _env: Option<&ProxyEnv>) -> Vec<String> {
    // Unlike bwrap/podman, sandbox-exec has no env-setting flag: the child
    // inherits the caller's environment, so gurgl applies ProxyEnv::vars() via
    // Command::envs at spawn time instead of on the command line.
    let mut argv = vec![
        "sandbox-exec".to_string(),
        "-p".into(),
        SEATBELT_PROFILE.to_string(),
        "--".into(),
        spec.command.clone(),
    ];
    argv.extend(spec.args.iter().cloned());
    argv
}

fn build_bwrap_argv(
    spec: &ServerSpec,
    env: Option<&ProxyEnv>,
    extra_env: &[(String, String)],
) -> Vec<String> {
    let mut argv = vec![
        "bwrap".to_string(),
        // Start the child from an EMPTY environment: bwrap otherwise passes
        // gurgl's whole environment through, handing exported secrets (AWS keys,
        // GITHUB_TOKEN, ...) to third-party code gurgl itself warns is downloaded
        // and executed as part of the capture. Everything the child legitimately
        // needs is re-set via --setenv below (and opt-in pass_env). Must precede
        // the --setenv args to not wipe them.
        "--clearenv".into(),
        "--ro-bind".into(),
        "/usr".into(),
        "/usr".into(),
        // merged-usr distros symlink these into /usr; -try tolerates absence.
        "--ro-bind-try".into(),
        "/bin".into(),
        "/bin".into(),
        "--ro-bind-try".into(),
        "/sbin".into(),
        "/sbin".into(),
        "--ro-bind-try".into(),
        "/lib".into(),
        "/lib".into(),
        "--ro-bind-try".into(),
        "/lib64".into(),
        "/lib64".into(),
        // /etc for DNS (resolv.conf, nsswitch), the TLS trust store, hosts, etc.
        "--ro-bind".into(),
        "/etc".into(),
        "/etc".into(),
        // Writable, isolated scratch tmpfs for /tmp. HOME (`/tmp/home`) is mounted
        // separately below - as a host-side bind, not a tmpfs dir, so the package
        // the launcher resolves survives teardown for version derivation.
        "--tmpfs".into(),
        "/tmp".into(),
        // The starter config's filesystem server needs its allowed directory to
        // exist; the tmpfs above masks any host-side /tmp/gurgl-scratch, so
        // create it inside the sandbox (the stock server exits if it's absent).
        "--dir".into(),
        crate::config::SCRATCH_DIR.into(),
        "--proc".into(),
        "/proc".into(),
        "--dev".into(),
        "/dev".into(),
        "--setenv".into(),
        "HOME".into(),
        "/tmp/home".into(),
        "--unshare-pid".into(),
        "--die-with-parent".into(),
        // NOTE: we intentionally do NOT --unshare-net here: the client needs to
        // reach the proxy on 127.0.0.1. Forcing *only* the proxy to be reachable
        // (netns + nftables redirect) is the roadmap hardening step.
    ];
    // The lab CA so the client can trust the proxy - only for a capture launch.
    // A no-proxy authoring launch (env=None) has no CA and no proxy to trust.
    if let Some(e) = env {
        argv.push("--ro-bind".into());
        argv.push(e.ca_cert_path.clone());
        argv.push(e.ca_cert_path.clone());
    }
    // Bind the RESOLVED /etc/resolv.conf whenever the sandbox must resolve DNS
    // ITSELF: a no-proxy authoring launch (`gurgl plan`, env=None) and a FORCED
    // capture (the client is redirected, not proxied, so there is no CONNECT for
    // the proxy to resolve on its behalf). env-proxy capture deliberately skips
    // this - DNS goes through the proxy there, so the sandbox needs no resolver
    // (which also stops DNS leaking around the proxy). /etc/resolv.conf is usually
    // a symlink into /run (systemd-resolved) that the /etc bind leaves dangling,
    // so bind the canonical target at its own path. -try tolerates a plain file.
    let needs_own_dns = env.is_none() || env.map(|e| e.forced).unwrap_or(false);
    if needs_own_dns {
        if let Ok(real) = std::fs::canonicalize("/etc/resolv.conf") {
            let p = real.to_string_lossy().to_string();
            argv.push("--ro-bind-try".into());
            argv.push(p.clone());
            argv.push(p);
        }
    }
    // Mount HOME (/tmp/home). Bind a host-side dir when one is given so the
    // package manager's resolved install survives teardown (pkgver reads it after
    // the server is killed); the tmpfs above still masks the rest of /tmp. The
    // --tmpfs /tmp above must precede this, which it does (literal first). Fall
    // back to an in-tmpfs dir when no host home is provided (a no-proxy launch or
    // older callers/tests) - enumeration does not read the resolved version.
    match env {
        Some(e) if !e.sandbox_home.is_empty() => {
            argv.push("--bind".into());
            argv.push(e.sandbox_home.clone());
            argv.push("/tmp/home".into());
        }
        _ => {
            argv.push("--dir".into());
            argv.push("/tmp/home".into());
        }
    }
    // Make user-installed language runtimes reachable. Many MCP servers run on a
    // Node/Python installed under the user's home (nvm, ~/.local, gurgl's own
    // node) rather than in /usr, and would otherwise not exist inside the
    // sandbox. Read-only; -try tolerates absence. (The sandbox is not a security
    // boundary yet; see the module docs and docs/THREAT-MODEL.md.)
    //
    // Skipped in forced mode: the server there runs as a DISTINCT, unprivileged
    // uid that cannot traverse a mode-0750 $HOME, so these binds would fail on
    // EACCES (not the ENOENT that -try tolerates). Forced captures therefore need
    // the server's runtime on a system path (/usr, /opt). This is also a security
    // gain - the untrusted server cannot read the user's home at all.
    let forced = env.map(|e| e.forced).unwrap_or(false);
    if let (false, Some(home)) = (forced, dirs::home_dir()) {
        // Bind ONLY ~/.gurgl/bin, not all of ~/.gurgl: the parent also holds the
        // mitmproxy CA PRIVATE key, every prior snapshot (the egress inventory of
        // every server captured), and the review sidecars - none of which the
        // observed server should read. The public CA cert it needs is bound
        // separately above via env.ca_cert_path.
        for sub in [".local", ".gurgl/bin", ".nvm", ".volta", ".asdf", ".fnm"] {
            let p = home.join(sub).to_string_lossy().to_string();
            argv.push("--ro-bind-try".into());
            argv.push(p.clone());
            argv.push(p);
        }
    }
    // Capture launch wires the proxy/CA env; a no-proxy authoring launch gets a
    // minimal base env (PATH + empty NO_PROXY) so the server runs normally.
    let vars = match env {
        Some(e) => e.vars(),
        None => base_env(),
    };
    for (k, v) in vars {
        argv.push("--setenv".into());
        argv.push(k);
        argv.push(v);
    }
    // Opt-in forwarded env (pass_env), set last so it can supply e.g. an API key
    // the server needs without reopening the whole environment.
    for (k, v) in extra_env {
        argv.push("--setenv".into());
        argv.push(k.clone());
        argv.push(v.clone());
    }
    argv.push("--".into());
    argv.push(spec.command.clone());
    argv.extend(spec.args.iter().cloned());
    argv
}

fn build_podman_argv(
    spec: &ServerSpec,
    env: Option<&ProxyEnv>,
    extra_env: &[(String, String)],
) -> Vec<String> {
    let mut argv = vec![
        "podman".to_string(),
        "run".into(),
        "--rm".into(),
        "-i".into(),
        // Share the host network namespace so the container reaches the capture
        // proxy on 127.0.0.1 - the same model as bwrap, which deliberately does
        // not unshare-net. A private netns (the old `slirp4netns`) made the
        // container's 127.0.0.1 its OWN loopback with the host proxy
        // unreachable, so every capture was silently empty.
        "--network".into(),
        "host".into(),
        // Never pull implicitly: a silent docker.io fetch inside `watch` would be
        // undisclosed, gurgl-initiated network access (constraint #5). If the
        // image is absent, podman errors and the user pulls it explicitly.
        "--pull=never".into(),
    ];
    // The lab CA, read-only - capture launch only. The flow log is written
    // host-side by the mitmdump addon, so it is deliberately NOT mounted.
    if let Some(e) = env {
        argv.push("-v".into());
        argv.push(format!("{}:{}:ro", e.ca_cert_path, e.ca_cert_path));
    }
    // Bind a host-side HOME so the launcher's resolved install survives teardown
    // for version derivation (pkgver). podman sets no HOME by default, so set it
    // explicitly to the mount point.
    if let Some(e) = env {
        if !e.sandbox_home.is_empty() {
            argv.push("-v".into());
            argv.push(format!("{}:/tmp/home", e.sandbox_home));
            argv.push("-e".into());
            argv.push("HOME=/tmp/home".into());
        }
    }
    // podman does not pass host env to the container by default; -e is the only
    // way in, so nothing leaks that we do not name here.
    let vars = match env {
        Some(e) => e.vars(),
        None => base_env(),
    };
    for (k, v) in vars {
        argv.push("-e".into());
        argv.push(format!("{k}={v}"));
    }
    for (k, v) in extra_env {
        argv.push("-e".into());
        argv.push(format!("{k}={v}"));
    }
    // A base image with node available; adjust per server toolchain.
    argv.push("docker.io/library/node:22-slim".into());
    argv.push(spec.command.clone());
    argv.extend(spec.args.iter().cloned());
    argv
}

/// Which sandbox binary must be on PATH for this backend.
pub fn required_binary(kind: SandboxKind) -> &'static str {
    match kind {
        SandboxKind::Bubblewrap => "bwrap",
        SandboxKind::Podman => "podman",
        SandboxKind::SandboxExec => "sandbox-exec",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> ServerSpec {
        ServerSpec {
            name: "filesystem-mcp".into(),
            command: "npx".into(),
            args: vec![
                "-y".into(),
                "@modelcontextprotocol/server-filesystem".into(),
            ],
            version: None,
            first_party: vec![],
            flightplan: None,
            pass_env: vec![],
        }
    }

    fn env() -> ProxyEnv {
        ProxyEnv {
            https_proxy: "http://127.0.0.1:8080".into(),
            ca_cert_path: "/tmp/gurgl-ca.pem".into(),
            sandbox_home: "/tmp/gurgl-home-xyz".into(),
            forced: false,
        }
    }

    #[test]
    fn bwrap_argv_has_command_after_separator() {
        let argv = build_argv(SandboxKind::Bubblewrap, &spec(), Some(&env()), &[]);
        assert_eq!(argv[0], "bwrap");
        let sep = argv.iter().position(|a| a == "--").unwrap();
        assert_eq!(argv[sep + 1], "npx");
        assert!(argv.iter().any(|a| a == "NODE_EXTRA_CA_CERTS"));
    }

    #[test]
    fn bwrap_clears_env_before_setting_it() {
        // --clearenv must appear, and before any --setenv, or it wipes the vars
        // gurgl set (the sandboxed child would then get an empty environment).
        let argv = build_argv(SandboxKind::Bubblewrap, &spec(), Some(&env()), &[]);
        let clear = argv
            .iter()
            .position(|a| a == "--clearenv")
            .expect("clearenv present");
        let first_setenv = argv
            .iter()
            .position(|a| a == "--setenv")
            .expect("a setenv present");
        assert!(clear < first_setenv, "--clearenv must precede --setenv");
        // The CA private key dir (~/.gurgl) must not be bound wholesale; only bin.
        assert!(
            !argv.iter().any(|a| a.ends_with("/.gurgl")),
            "must not ro-bind all of ~/.gurgl"
        );
    }

    #[test]
    fn bwrap_binds_host_home_after_tmpfs() {
        // HOME must be a host bind (so the resolved package survives teardown for
        // version derivation), and it must come AFTER --tmpfs /tmp or the tmpfs
        // would mask it.
        let argv = build_argv(SandboxKind::Bubblewrap, &spec(), Some(&env()), &[]);
        let bind = argv
            .windows(3)
            .position(|w| w[0] == "--bind" && w[1] == "/tmp/gurgl-home-xyz" && w[2] == "/tmp/home")
            .expect("host home is bound to /tmp/home");
        let tmpfs = argv
            .windows(2)
            .position(|w| w[0] == "--tmpfs" && w[1] == "/tmp")
            .expect("/tmp tmpfs present");
        assert!(tmpfs < bind, "--tmpfs /tmp must precede the /tmp/home bind");
        // HOME still points at the mount point.
        assert!(argv
            .windows(3)
            .any(|w| w[0] == "--setenv" && w[1] == "HOME" && w[2] == "/tmp/home"));
    }

    #[test]
    fn bwrap_without_home_falls_back_to_tmpfs_dir() {
        let mut e = env();
        e.sandbox_home = String::new();
        let argv = build_argv(SandboxKind::Bubblewrap, &spec(), Some(&e), &[]);
        assert!(argv
            .windows(2)
            .any(|w| w[0] == "--dir" && w[1] == "/tmp/home"));
        assert!(!argv.iter().any(|a| a == "--bind"));
    }

    #[test]
    fn bwrap_no_proxy_launch_skips_ca_and_proxy_env() {
        // `gurgl plan` enumerates tools with env=None: no CA bind, no proxy env,
        // base env only, and a tmpfs home (no host bind - it reads no version).
        let argv = build_argv(SandboxKind::Bubblewrap, &spec(), None, &[]);
        assert_eq!(argv[0], "bwrap");
        assert!(
            !argv
                .iter()
                .any(|a| a.contains("gurgl-ca") || a == "NODE_EXTRA_CA_CERTS"),
            "no CA bind or CA env in a no-proxy launch"
        );
        assert!(
            !argv.iter().any(|a| a == "HTTPS_PROXY"),
            "no proxy env in a no-proxy launch"
        );
        // PATH is still set (the server's runtime must resolve) and NO_PROXY empty.
        assert!(argv.iter().any(|a| a == "PATH"));
        assert!(argv
            .windows(2)
            .any(|w| w[0] == "--dir" && w[1] == "/tmp/home"));
        let sep = argv.iter().position(|a| a == "--").unwrap();
        assert_eq!(argv[sep + 1], "npx");
    }

    #[test]
    fn podman_binds_host_home() {
        let argv = build_argv(SandboxKind::Podman, &spec(), Some(&env()), &[]);
        assert!(argv
            .windows(2)
            .any(|w| w[0] == "-v" && w[1] == "/tmp/gurgl-home-xyz:/tmp/home"));
        assert!(argv.iter().any(|a| a == "HOME=/tmp/home"));
    }

    #[test]
    fn bwrap_forwards_pass_env() {
        let extra = vec![("MY_TOKEN".to_string(), "s3cr3t".to_string())];
        let argv = build_argv(SandboxKind::Bubblewrap, &spec(), Some(&env()), &extra);
        assert!(argv
            .windows(3)
            .any(|w| w[0] == "--setenv" && w[1] == "MY_TOKEN" && w[2] == "s3cr3t"));
    }

    #[test]
    fn podman_argv_passes_env() {
        let argv = build_argv(SandboxKind::Podman, &spec(), Some(&env()), &[]);
        assert_eq!(argv[0], "podman");
        assert!(argv.iter().any(|a| a.starts_with("HTTPS_PROXY=")));
    }

    #[test]
    fn podman_uses_host_network_and_no_flow_mount() {
        // The container must reach the host proxy on 127.0.0.1 (host network),
        // never a private netns; and it must not mount the flow log (host-side).
        let argv = build_argv(SandboxKind::Podman, &spec(), Some(&env()), &[]);
        assert!(argv
            .windows(2)
            .any(|w| w[0] == "--network" && w[1] == "host"));
        assert!(!argv.iter().any(|a| a.contains("slirp4netns")));
        assert!(argv.iter().any(|a| a == "--pull=never"));
        assert!(
            !argv.iter().any(|a| a.contains("flows")),
            "flow log must not be mounted into the container"
        );
    }

    #[test]
    fn bwrap_forced_skips_home_runtime_binds() {
        // In forced mode the server runs as a distinct unprivileged uid that
        // cannot traverse a mode-0750 $HOME, so the ~/.local/~/.nvm/... binds are
        // omitted (they would hard-fail on EACCES); env-proxy keeps them.
        let mut e = env();
        e.forced = true;
        let forced = build_argv(SandboxKind::Bubblewrap, &spec(), Some(&e), &[]);
        let plain = build_argv(SandboxKind::Bubblewrap, &spec(), Some(&env()), &[]);
        let mentions_local = |argv: &[String]| argv.iter().any(|a| a.ends_with("/.local"));
        assert!(mentions_local(&plain), "env-proxy binds ~/.local");
        assert!(!mentions_local(&forced), "forced must not bind ~/.local");
        // The CA is still bound in both (the server must trust the intercept cert).
        assert!(forced.iter().any(|a| a == "/tmp/gurgl-ca.pem"));
    }

    #[test]
    fn forced_env_drops_proxy_vars_but_keeps_ca_trust() {
        // Forced/transparent capture redirects the client instead of proxying it,
        // so advertising HTTPS_PROXY would break a cooperating client (a
        // transparent mitmdump cannot answer a CONNECT). The CA-trust vars must
        // stay so the intercepting cert is accepted.
        let mut e = env();
        e.forced = true;
        let vars = e.vars();
        let has = |k: &str| vars.iter().any(|(n, _)| n == k);
        assert!(!has("HTTPS_PROXY") && !has("https_proxy") && !has("ALL_PROXY"));
        assert!(!has("NODE_USE_ENV_PROXY"));
        assert!(has("NODE_EXTRA_CA_CERTS") && has("SSL_CERT_FILE") && has("CURL_CA_BUNDLE"));
        assert!(has("PATH") && has("NO_PROXY"));
        // env-proxy mode still advertises the proxy.
        assert!(env().vars().iter().any(|(n, _)| n == "HTTPS_PROXY"));
    }

    #[test]
    fn nft_ruleset_excludes_launcher_uid_and_forces_tcp() {
        let rs = nft_ruleset(0, 8080);
        // inet table (not ip - IPv6 would escape an ip table), output hook.
        assert!(rs.contains("table inet gurgl"));
        assert!(rs.contains("hook output"));
        // The load-bearing loop-breaker: the proxy's own uid is excluded, BEFORE
        // the redirect line (order matters - a return after redirect never runs).
        let excl = rs.find("skuid 0 return").expect("excludes launcher uid");
        let redir = rs.find("redirect to :8080").expect("redirects to the port");
        assert!(excl < redir, "the uid exclusion must precede the redirect");
        assert!(rs.contains("tcp dport { 80, 443 }"));
        // QUIC/HTTP-3 bypass is closed.
        assert!(rs.contains("udp dport 443 drop"));
    }

    #[test]
    fn sandbox_exec_argv_has_profile_and_command() {
        let argv = build_argv(SandboxKind::SandboxExec, &spec(), Some(&env()), &[]);
        assert_eq!(argv[0], "sandbox-exec");
        assert!(argv.iter().any(|a| a == "-p"));
        let sep = argv.iter().position(|a| a == "--").unwrap();
        assert_eq!(argv[sep + 1], "npx");
    }
}
