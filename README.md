# remote-sandbox-quicksand

A Python execution server for coding agents that runs commands inside a [Quicksand](https://microsoft.github.io/quicksand/) QEMU virtual machine. It implements the shared [Remote Sandbox protocol](https://github.com/prime-radiant-inc/remote-sandbox/blob/main/SPEC.md), alongside [remote-sandbox-v86](https://github.com/prime-radiant-inc/remote-sandbox-v86) and [remote-sandbox-container](https://github.com/prime-radiant-inc/remote-sandbox-container): the same buffered and streaming shell APIs, Codex endpoint, browser terminal, host mounts, and allow-listed HTTP(S) proxy, with a full virtual machine as the sandbox.

## Start

Requirements: [`uv`](https://docs.astral.sh/uv/) and a host supported by Quicksand. This release is tested on Apple silicon macOS with HVF acceleration. QEMU and the Alpine image arrive as Python wheels; no Homebrew, Docker or separate VM tooling is needed.

```sh
uv run remote-sandbox-quicksand --preserve-paths \
  --mount-rw project=/absolute/path/to/project \
  --mount-ro reference=/absolute/path/to/reference
```

The server listens on `127.0.0.1:8688`, so it can run beside the v86 (`8686`) and container (`8687`) servers. Mounts appear at `/mnt/project` and `/mnt/reference`; `--preserve-paths` also binds them at their original absolute host paths for clients that send host paths. The first mount is the default working directory; without mounts it is `/workspace`. Stop the server with Ctrl-C to shut down and discard the VM. Files in writable mounts persist on the host; all other guest changes are disposable.

The VM gets two CPUs and 1 GiB of memory by default (`--cpus`, `--memory`). `--accel tcg` forces software emulation when hardware acceleration is unavailable. Run `uv run remote-sandbox-quicksand --help` for every option.

## Guest images

**Alpine (default).** Quicksand's Alpine 3.23 image lacks Bash and Python, which the protocol and agent need. On first use, the server boots that image once, installs `bash`, `python3`, `git` and `ripgrep` from `https://dl-cdn.alpinelinux.org` through its own allow-listed proxy (only GET/HEAD to that origin), and saves the result as a Quicksand save under `~/.cache/remote-sandbox-quicksand/images/`. On an Apple silicon Mac this took about seven seconds and produced a 65 MB save; later starts boot it directly and serve requests in about a second.

```sh
uv run remote-sandbox-quicksand --prepare-image                  # prepare now, then exit
uv run remote-sandbox-quicksand --packages git,ripgrep,nodejs,npm,uv,jq
```

`--packages` replaces the optional package list (`bash` and `python3` are always included) and prepares a separately cached image. The cache key covers the Quicksand Alpine build, architecture and package list, so a Quicksand upgrade prepares a fresh image. Each prepared image records its installed package versions in `remote-sandbox-image.json`. Alpine package versions come from the 3.23 branch at preparation time. Set `--cache-dir` or `XDG_CACHE_HOME` to move the cache.

**Ubuntu 24.04 (optional).** Quicksand's Ubuntu image already includes Bash and Python 3.12. Its image wheel (about 300 MB) comes from Microsoft's Quicksand package index and is not installed by default:

```sh
uv run --extra ubuntu remote-sandbox-quicksand --image ubuntu
```

`--image` also accepts a Quicksand save directory, provided it has `/bin/bash` and `python3`.

## How it works

```text
host: remote-sandbox-quicksand (aiohttp)                    guest: Quicksand VM
  /exec, /exec/ws, /codex ── virtio-serial port ───────────▶ guest_agent.py (python3)
  9p fsdev (readonly=on for ro mounts) ─────────────────────▶ /mnt/<name>
  host proxy ◀── bridge ◀── QEMU guestfwd stream ◀── guest-mux ◀── 127.0.0.1:3128 ◀── HTTP(S)_PROXY
```

Quicksand boots the VM and its own guest agent installs this server's agent from the Python package. The private agent speaks length-prefixed JSON over a dedicated virtio-serial port, separate from Quicksand's agent channel and unreachable through guest networking. It runs each command as `/bin/bash -c` in its own process group, streams binary output, and performs Codex filesystem operations inside the guest. These modules, the HTTP/WebSocket/Codex adapters, and the proxy engine are shared with `remote-sandbox-container`; see [PROVENANCE.md](PROVENANCE.md).

Host directories use QEMU virtio-9p mounts. Read-only mounts set QEMU's `readonly=on`, so the host rejects writes regardless of guest privileges. The VM starts with Quicksand's `NetworkMode.NONE`, which removes its default NIC, host agent port forward and SMB relay.

## Browser terminal

Open `http://127.0.0.1:8688/` to run commands through the streaming WebSocket API, with stdin, EOF, cancel, history and **Copy session**. Each run starts a new Bash process; files persist for the VM's lifetime. The terminal uses pipes, not a PTY. The HTML, CSS and JavaScript are a pinned bundle of [`remote-sandbox-ui`](https://github.com/prime-radiant-inc/remote-sandbox-ui) 0.2.0; update it with that repository's `scripts/sync.py`, as described in its README.

## Controlled network access

Without `--proxy-config` the VM has no network interface. With a policy file, it gets exactly one: a QEMU user-mode NIC with `restrict=on` and a single `guestfwd` rule, `10.0.2.101:3128`, connected to a host stream.

```sh
uv run remote-sandbox-quicksand --proxy-config examples/proxy-public.json
```

QEMU's `guestfwd` TCP backend is one persistent byte stream, so a small static Go helper ([`guest-mux`](guest-mux/guest_mux.go), from the Quicksand proxy prototype) listens on guest `127.0.0.1:3128` and multiplexes each connection over that stream. The host [bridge](src/remote_sandbox_quicksand/proxy_bridge.py) opens one connection per channel to the embedded host proxy and nowhere else. Commands receive standard proxy variables, `NODE_USE_ENV_PROXY=1`, and a CA bundle containing the proxy's public certificate.

The proxy, policy format, management page and API are the same as the container server's and follow the protocol's proxy profile: exact-origin allow rules with optional methods, paths and CIDRs; public addresses only by default; credential placeholders replaced on the host; secret redaction; and live policy edits at `http://127.0.0.1:8688/proxy` that close existing connections. [examples/proxy.json](examples/proxy.json) demonstrates credential substitution and needs `OPENAI_API_KEY` in the server's environment. Removing proxy variables cannot open another route: QEMU drops everything except the guestfwd stream. If the guestfwd stream fails, proxy access fails closed until restart; `/health` reports `proxyTransport`.

## Agents

Agent integrations are maintained in [remote-sandbox](https://github.com/prime-radiant-inc/remote-sandbox):

- [Claude Code](https://github.com/prime-radiant-inc/remote-sandbox/tree/main/claude-code): set `REMOTE_SANDBOX_API_URL=http://127.0.0.1:8688` and start this server with `--preserve-paths --mount-rw project=$PWD`.
- [Codex](https://github.com/prime-radiant-inc/remote-sandbox/tree/main/codex): use executor URL `ws://127.0.0.1:8688/codex`.
- [Pi](https://github.com/prime-radiant-inc/remote-sandbox/tree/main/pi): use `--sandbox-url http://127.0.0.1:8688`. Pi's `find` tool needs Python 3.13 in the guest; both images ship Python 3.12, so it fails while Pi's other tools work.

## Scope

- Commands and Codex filesystem operations run in the VM as guest root. The VM is the isolation boundary; guest root cannot change QEMU's mount modes or network restrictions.
- Mounts deliberately expose host directories. Read-write mounts change host files immediately; host changes are visible in the guest. Guest root can follow symlinks only within the guest view. Do not expose a writable hardlink alias of a file in a read-only mount; this backend does not reproduce v86's hardlink checks.
- The guest agent and proxy helper are not trusted by the host. The host bounds frame sizes and validates messages; a compromised guest can disrupt its own commands or proxy access, but not reach other destinations or host credentials.
- Quicksand's own guest agent remains in the VM and is used only by the host for setup.
- The execution listener is for trusted local clients, with the same browser token, Origin and Host checks as the other servers.

## Test

```sh
uv run pytest -m 'not integration'
node --test tests/test_terminal_js.mjs
uv run ruff check .
```

Tests marked `integration` boot real VMs and are opt-in:

```sh
RUN_QUICKSAND_TESTS=1 uv run pytest -m integration
RUN_QUICKSAND_TESTS=1 SANDBOX_TEST_IMAGE=ubuntu uv run --extra ubuntu pytest -m integration
RUN_QUICKSAND_TESTS=1 RUN_SANDBOX_TOOL_IMAGE_TESTS=1 uv run pytest tests/test_proxy_integration.py
REMOTE_SANDBOX_CLIENT=/absolute/path/to/remote-sandbox/claude-code/remote_sandbox_exec.py \
  RUN_QUICKSAND_TESTS=1 uv run pytest tests/test_legacy_client.py tests/test_real_clients.py
```

The tool-image tests prepare an Alpine image with Node, npm and uv and check they reach a synthetic HTTPS service only through the proxy. The mux bridge tests also compile `guest-mux` for the host when Go is installed. To rebuild the bundled helpers, run `guest-mux/build.sh`; Go 1.27.2 reproduces the committed binaries exactly.

See [verification](docs/verification.md) for recorded results, including the shared conformance suite.
