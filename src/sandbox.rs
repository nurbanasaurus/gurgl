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
    /// Absolute path the mitmproxy addon appends flow records to.
    pub flowout_path: String,
}

impl ProxyEnv {
    /// (KEY, VALUE) pairs to set in the sandboxed process environment.
    pub fn vars(&self) -> Vec<(String, String)> {
        vec![
            // Route TLS through the proxy. Both cases: clients differ on which
            // they read (curl/Python honor either; Node reads both under the
            // NODE_USE_ENV_PROXY flag below).
            ("HTTPS_PROXY".into(), self.https_proxy.clone()),
            ("HTTP_PROXY".into(), self.https_proxy.clone()),
            ("ALL_PROXY".into(), self.https_proxy.clone()),
            ("https_proxy".into(), self.https_proxy.clone()),
            ("http_proxy".into(), self.https_proxy.clone()),
            ("all_proxy".into(), self.https_proxy.clone()),
            // Node ignores proxy env vars by default. This (Node 24+) makes its
            // core http/https client AND fetch honor them; harmless on older Node.
            // Verified: without it, node egress bypasses the proxy entirely.
            ("NODE_USE_ENV_PROXY".into(), "1".into()),
            // CA trust so the intercepting cert is accepted:
            ("NODE_EXTRA_CA_CERTS".into(), self.ca_cert_path.clone()),
            ("SSL_CERT_FILE".into(), self.ca_cert_path.clone()),
            ("REQUESTS_CA_BUNDLE".into(), self.ca_cert_path.clone()),
            ("CURL_CA_BUNDLE".into(), self.ca_cert_path.clone()),
            // gurgl addon coordination:
            ("GURGL_FLOWOUT".into(), self.flowout_path.clone()),
        ]
    }
}

/// Build the argv to launch `spec` under the chosen sandbox backend.
///
/// The returned vector is a full command line: `argv[0]` is the sandbox binary.
pub fn build_argv(kind: SandboxKind, spec: &ServerSpec, env: &ProxyEnv) -> Vec<String> {
    match kind {
        SandboxKind::Bubblewrap => build_bwrap_argv(spec, env),
        SandboxKind::Podman => build_podman_argv(spec, env),
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

fn build_bwrap_argv(spec: &ServerSpec, env: &ProxyEnv) -> Vec<String> {
    let mut argv = vec![
        "bwrap".to_string(),
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
    for (k, v) in env.vars() {
        argv.push("--setenv".into());
        argv.push(k);
        argv.push(v);
    }
    argv.push("--".into());
    argv.push(spec.command.clone());
    argv.extend(spec.args.iter().cloned());
    argv
}

fn build_podman_argv(spec: &ServerSpec, env: &ProxyEnv) -> Vec<String> {
    let mut argv = vec![
        "podman".to_string(),
        "run".into(),
        "--rm".into(),
        "-i".into(),
        "--network".into(),
        "slirp4netns".into(),
        "-v".into(),
        format!("{}:{}:ro", env.ca_cert_path, env.ca_cert_path),
        "-v".into(),
        format!("{}:{}", env.flowout_path, env.flowout_path),
    ];
    for (k, v) in env.vars() {
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
        }
    }

    fn env() -> ProxyEnv {
        ProxyEnv {
            https_proxy: "http://127.0.0.1:8080".into(),
            ca_cert_path: "/tmp/gurgl-ca.pem".into(),
            flowout_path: "/tmp/gurgl-flows.jsonl".into(),
        }
    }

    #[test]
    fn bwrap_argv_has_command_after_separator() {
        let argv = build_argv(SandboxKind::Bubblewrap, &spec(), &env());
        assert_eq!(argv[0], "bwrap");
        let sep = argv.iter().position(|a| a == "--").unwrap();
        assert_eq!(argv[sep + 1], "npx");
        assert!(argv.iter().any(|a| a == "NODE_EXTRA_CA_CERTS"));
    }

    #[test]
    fn podman_argv_passes_env() {
        let argv = build_argv(SandboxKind::Podman, &spec(), &env());
        assert_eq!(argv[0], "podman");
        assert!(argv.iter().any(|a| a.starts_with("HTTPS_PROXY=")));
    }

    #[test]
    fn sandbox_exec_argv_has_profile_and_command() {
        let argv = build_argv(SandboxKind::SandboxExec, &spec(), &env());
        assert_eq!(argv[0], "sandbox-exec");
        assert!(argv.iter().any(|a| a == "-p"));
        let sep = argv.iter().position(|a| a == "--").unwrap();
        assert_eq!(argv[sep + 1], "npx");
    }
}
