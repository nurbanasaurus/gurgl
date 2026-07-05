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
}

impl ProxyEnv {
    /// (KEY, VALUE) pairs to set in the sandboxed process environment.
    pub fn vars(&self) -> Vec<(String, String)> {
        // Ensure the sandboxed process can find its runtime on PATH. `npx` runs
        // via `#!/usr/bin/env node`, so node must be resolvable inside the
        // sandbox even when the launching shell's PATH differs. Prepend gurgl's
        // and the user-local bin dirs to the inherited PATH.
        let home = dirs::home_dir()
            .map(|h| h.to_string_lossy().to_string())
            .unwrap_or_default();
        let inherited = std::env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin".to_string());
        let path = format!("{home}/.gurgl/bin:{home}/.local/bin:{inherited}");
        vec![
            ("PATH".into(), path),
            // Route TLS through the proxy. Both cases: clients differ on which
            // they read (curl/Python honor either; Node reads both under the
            // NODE_USE_ENV_PROXY flag below).
            ("HTTPS_PROXY".into(), self.https_proxy.clone()),
            ("HTTP_PROXY".into(), self.https_proxy.clone()),
            ("ALL_PROXY".into(), self.https_proxy.clone()),
            ("https_proxy".into(), self.https_proxy.clone()),
            ("http_proxy".into(), self.https_proxy.clone()),
            ("all_proxy".into(), self.https_proxy.clone()),
            // Explicitly empty NO_PROXY so an inherited value (or one a client
            // sets by default) cannot carve out hosts that then egress
            // unobserved. Empty = no bypass exceptions; capture everything.
            ("NO_PROXY".into(), String::new()),
            ("no_proxy".into(), String::new()),
            // Node ignores proxy env vars by default. This (Node 24+) makes its
            // core http/https client AND fetch honor them; harmless on older Node.
            // Verified: without it, node egress bypasses the proxy entirely.
            ("NODE_USE_ENV_PROXY".into(), "1".into()),
            // CA trust so the intercepting cert is accepted:
            ("NODE_EXTRA_CA_CERTS".into(), self.ca_cert_path.clone()),
            ("SSL_CERT_FILE".into(), self.ca_cert_path.clone()),
            ("REQUESTS_CA_BUNDLE".into(), self.ca_cert_path.clone()),
            ("CURL_CA_BUNDLE".into(), self.ca_cert_path.clone()),
            // NOTE: GURGL_FLOWOUT is deliberately NOT set here. Only the
            // mitmproxy addon reads it, and it runs OUTSIDE the sandbox (gurgl
            // sets it on the mitmdump process directly). Injecting it into the
            // observed server served no purpose and advertised the exact path of
            // the evidence file, plus a "you are under gurgl" fingerprint.
        ]
    }
}

/// Build the argv to launch `spec` under the chosen sandbox backend.
///
/// The returned vector is a full command line: `argv[0]` is the sandbox binary.
/// `extra_env` is the resolved `pass_env` forwarding (var name -> value read
/// from gurgl's own environment). bwrap and podman set the child's environment
/// from argv, so it is threaded in here; sandbox-exec's child inherits the
/// caller's environment, so gurgl clears and re-sets that at spawn time instead.
pub fn build_argv(
    kind: SandboxKind,
    spec: &ServerSpec,
    env: &ProxyEnv,
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

fn build_sandbox_exec_argv(spec: &ServerSpec, _env: &ProxyEnv) -> Vec<String> {
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
    env: &ProxyEnv,
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
        // The lab CA so the client can trust the proxy.
        "--ro-bind".into(),
        env.ca_cert_path.clone(),
        env.ca_cert_path.clone(),
        // Writable, isolated scratch. HOME points inside it so npm/npx caches
        // land in the tmpfs, not on the host.
        "--tmpfs".into(),
        "/tmp".into(),
        "--dir".into(),
        "/tmp/home".into(),
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
    // Make user-installed language runtimes reachable. Many MCP servers run on a
    // Node/Python installed under the user's home (nvm, ~/.local, gurgl's own
    // node) rather than in /usr, and would otherwise not exist inside the
    // sandbox. Read-only; -try tolerates absence. (The sandbox is not a security
    // boundary yet; see the module docs and docs/THREAT-MODEL.md.)
    if let Some(home) = dirs::home_dir() {
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
    for (k, v) in env.vars() {
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
    env: &ProxyEnv,
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
        // The lab CA, read-only. The flow log is written host-side by the
        // mitmdump addon, so it is deliberately NOT mounted into the container.
        "-v".into(),
        format!("{}:{}:ro", env.ca_cert_path, env.ca_cert_path),
    ];
    // podman does not pass host env to the container by default; -e is the only
    // way in, so nothing leaks that we do not name here.
    for (k, v) in env.vars() {
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
        }
    }

    #[test]
    fn bwrap_argv_has_command_after_separator() {
        let argv = build_argv(SandboxKind::Bubblewrap, &spec(), &env(), &[]);
        assert_eq!(argv[0], "bwrap");
        let sep = argv.iter().position(|a| a == "--").unwrap();
        assert_eq!(argv[sep + 1], "npx");
        assert!(argv.iter().any(|a| a == "NODE_EXTRA_CA_CERTS"));
    }

    #[test]
    fn bwrap_clears_env_before_setting_it() {
        // --clearenv must appear, and before any --setenv, or it wipes the vars
        // gurgl set (the sandboxed child would then get an empty environment).
        let argv = build_argv(SandboxKind::Bubblewrap, &spec(), &env(), &[]);
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
    fn bwrap_forwards_pass_env() {
        let extra = vec![("MY_TOKEN".to_string(), "s3cr3t".to_string())];
        let argv = build_argv(SandboxKind::Bubblewrap, &spec(), &env(), &extra);
        assert!(argv
            .windows(3)
            .any(|w| w[0] == "--setenv" && w[1] == "MY_TOKEN" && w[2] == "s3cr3t"));
    }

    #[test]
    fn podman_argv_passes_env() {
        let argv = build_argv(SandboxKind::Podman, &spec(), &env(), &[]);
        assert_eq!(argv[0], "podman");
        assert!(argv.iter().any(|a| a.starts_with("HTTPS_PROXY=")));
    }

    #[test]
    fn podman_uses_host_network_and_no_flow_mount() {
        // The container must reach the host proxy on 127.0.0.1 (host network),
        // never a private netns; and it must not mount the flow log (host-side).
        let argv = build_argv(SandboxKind::Podman, &spec(), &env(), &[]);
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
    fn sandbox_exec_argv_has_profile_and_command() {
        let argv = build_argv(SandboxKind::SandboxExec, &spec(), &env(), &[]);
        assert_eq!(argv[0], "sandbox-exec");
        assert!(argv.iter().any(|a| a == "-p"));
        let sep = argv.iter().position(|a| a == "--").unwrap();
        assert_eq!(argv[sep + 1], "npx");
    }
}
