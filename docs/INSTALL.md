# Installing gurgl

gurgl is a single Rust binary. It installs into one self-contained directory,
**`~/.gurgl`** (override with `$GURGL_HOME`), so the whole install is a directory
you can inspect, back up, or delete.

```
~/.gurgl/
├── bin/gurgl          the binary
├── env                source it to add ~/.gurgl/bin to PATH
├── gurgl.toml         your config          (gurgl init)
├── flightplans/       the scripted battery (gurgl init)
├── snapshots/         captured egress
└── mitmproxy/         the lab CA           (first `gurgl watch`)
```

- **Supported today:** Linux and macOS (Apple Silicon & Intel).
- **Windows:** not yet - [tracked for later](ROADMAP.md).

---

## TL;DR

```sh
git clone https://github.com/nurbanasaurus/gurgl
cd gurgl && ./install.sh
. ~/.gurgl/env
gurgl --version
```

`./install.sh` also installs the capture deps (sandbox backend + mitmproxy)
automatically. The per-OS commands in step 3 are for reference or if you ran
`./install.sh --no-deps`.

---

## 1. Install the binary

### Option A - the installer script (recommended)

Works on Linux and macOS. It installs the Rust toolchain if missing, builds
gurgl, installs it to `~/.gurgl/bin`, and writes `~/.gurgl/env`.

```sh
git clone https://github.com/nurbanasaurus/gurgl
cd gurgl
./install.sh
```

Custom location:

```sh
GURGL_HOME="$HOME/tools/gurgl" ./install.sh
```

### Option B - with cargo directly

If you already have Rust ([rustup.rs](https://rustup.rs)):

```sh
git clone https://github.com/nurbanasaurus/gurgl
cd gurgl
cargo install --path . --root ~/.gurgl --locked
```

---

## 2. Put gurgl on your PATH

The installer writes a sourceable `env` file (rustup-style). Add one line to
your shell profile so every new shell can find gurgl:

```sh
# bash
echo '. "$HOME/.gurgl/env"' >> ~/.bashrc

# zsh (default on macOS)
echo '. "$HOME/.gurgl/env"' >> ~/.zshrc

# fish
echo 'fish_add_path $HOME/.gurgl/bin' >> ~/.config/fish/config.fish
```

Then reload (`. ~/.gurgl/env`, or open a new terminal) and check:

```sh
gurgl --version
gurgl --config examples/gurgl.toml diff example-mcp   # works with no backend
```

---

## 3. Install the capture backends (only for `gurgl watch`)

**`./install.sh` already installs these for you** (unless you passed
`--no-deps`). This section is reference: what the deps are, and how to install
them by hand if the automatic step couldn't.

`list` / `show` / `diff` / `allow` work with nothing extra. **Capture** needs
two things: a **sandbox** to run the server in, and **mitmproxy** to observe its
TLS egress.

> **macOS capture caveat.** mitmproxy intercepts TLS with a local CA that the
> client must trust. gurgl passes that CA via env vars: **Node** honors
> `NODE_EXTRA_CA_CERTS` on every platform (so `npx`-based MCP servers capture
> fine), but the macOS **system `python3` ignores `SSL_CERT_FILE`** and won't
> trust it, so a server run under `/usr/bin/python3` captures **zero** hosts on
> macOS. gurgl deliberately does not add its CA to the system trust store. See
> [THREAT-MODEL.md](THREAT-MODEL.md#capture-fidelity).

### macOS

```sh
# sandbox: sandbox-exec ships with macOS - nothing to install.
# capture proxy:
brew install mitmproxy
```

No Homebrew? `pipx install mitmproxy` (`brew install pipx` first) also works.

### Debian / Ubuntu

```sh
sudo apt update
sudo apt install -y bubblewrap pipx
pipx install mitmproxy
pipx ensurepath          # puts ~/.local/bin (mitmdump) on PATH; reopen your shell
```

If `pipx` is unavailable on an older release:

```sh
python3 -m pip install --user mitmproxy   # add --break-system-packages on PEP 668 systems
```

### Fedora / RHEL

```sh
sudo dnf install -y bubblewrap pipx
pipx install mitmproxy
pipx ensurepath
```

### Arch

```sh
sudo pacman -S --needed bubblewrap mitmproxy
```

### Verify the backends are found

```sh
command -v mitmdump      # the capture proxy
command -v bwrap         # Linux sandbox   (macOS: command -v sandbox-exec)
```

If `mitmdump` isn't on your PATH but you installed it, point gurgl at it
explicitly in `~/.gurgl/gurgl.toml`:

```toml
mitmdump = "/home/you/.local/bin/mitmdump"
```

`gurgl watch` preflights both backends and stops with a clear message naming the
missing one before it launches anything.

---

## 4. First run

```sh
gurgl init                    # creates ~/.gurgl/gurgl.toml + the default flight plan
$EDITOR ~/.gurgl/gurgl.toml   # add the MCP servers you run
gurgl watch --all             # capture them
gurgl show <server>           # see the hosts
```

See **[USAGE.md](USAGE.md)** for the config schema and every command.

---

## Installing on a remote machine (Tailscale / SSH)

Build **on** the target (no cross-compile SDK needed), from your dev box:

```sh
make deploy HOST=my-mac       # an ssh alias, MagicDNS FQDN, or IP
```

This rsyncs the source to `~/gurgl-src` on the host, builds natively, and
installs to `~/.gurgl/bin` there. Then, on the remote, install that host's
capture backends (step 3) and add `~/.gurgl/bin` to its PATH (`. ~/.gurgl/env`).

> **Gotcha:** don't pass a bare hostname that parses as hex (e.g. `0x69` →
> `0.0.0.105`). Use an `~/.ssh/config` alias, a MagicDNS FQDN, or an IP.

---

## Updating

gurgl never self-updates (it makes no network calls of its own). Update in place:

```sh
cd gurgl && make update       # git pull --ff-only && ./install.sh
```

Remote hosts: `make deploy HOST=my-mac` re-syncs and rebuilds.

---

## Uninstall

```sh
rm -rf ~/.gurgl               # binary, config, snapshots, CA - everything
```

Remove the `. "$HOME/.gurgl/env"` line from your shell profile. The lab CA lived
only under `~/.gurgl/mitmproxy` and was never added to any system trust store,
so there's nothing else to clean up.
