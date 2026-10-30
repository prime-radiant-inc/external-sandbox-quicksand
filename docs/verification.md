# Verification

Recorded on 9 October 2026 on an Apple M5 Max running macOS 26.4, with Python 3.14.3, Quicksand 0.12.0 (core 0.13.0, QEMU 0.5.12) and HVF acceleration. Every result below used server code from commit `a93aa17`; later commits changed only tests and documentation. All runs used real Quicksand VMs. No fake execution backend or paid model call was involved.

## Shared conformance suite

The [remote-sandbox](https://github.com/prime-radiant-inc/remote-sandbox) runner at `98fa5d7` ran against dedicated servers. Each server had writable `/mnt/spec-rw` and read-only `/mnt/spec-ro` mounts, a deny-all initial proxy policy (`{"allow": []}`), and the generated localhost TLS fixture. All five profiles were selected:

| Image | Profiles | Result | `conforms` |
| --- | --- | --- | --- |
| Prepared Alpine 3.23 (bash, git, python3, ripgrep) | core, browser, mounts, proxy, proxy-tls | **116 passed** | true |
| Ubuntu 24.04 (`--image ubuntu`) | core, browser, mounts, proxy, proxy-tls | **116 passed** | true |

To reproduce, generate the fixture with `uv run --project ../remote-sandbox remote-sandbox-proxy-fixture work/tls`, then start a dedicated server from a shell that has sourced `work/tls/server-env.sh`:

```sh
uv run remote-sandbox-quicksand --port 18788 --proxy-config work/deny-all.json \
  --mount-rw spec-rw=$PWD/work/spec-rw --mount-ro spec-ro=$PWD/work/spec-ro
```

Then run the suite from the `remote-sandbox` checkout:

```sh
uv run remote-sandbox-conformance --url http://127.0.0.1:18788 \
  --profile browser --profile mounts --profile proxy-tls \
  --rw-dir /mnt/spec-rw --ro-dir /mnt/spec-ro \
  --proxy-tls-cert ../remote-sandbox-quicksand/work/tls/cert.pem \
  --proxy-tls-key ../remote-sandbox-quicksand/work/tls/key.pem -q
```

Add `--image ubuntu` and run the server with `uv run --extra ubuntu` for the Ubuntu result.

## Project tests

| Suite | Result |
| --- | --- |
| Unit and protocol tests (`-m 'not integration'`) | 232 passed; 5 shared-client checks skipped without `REMOTE_SANDBOX_CLIENT` |
| Shared streaming client with `REMOTE_SANDBOX_CLIENT` set to `remote-sandbox/claude-code/remote_sandbox_exec.py` | 5 passed |
| Mux bridge with the real `guest-mux` helper built for the host | included above; 8 concurrent ~200 KB round trips |
| Bundled UI JavaScript tests, local assets and the live server's pages | 26 passed, 1 mode-specific skip, in each mode |
| Real-VM integration, Alpine | 18 passed, 4 tool-image tests skipped |
| Real-VM integration, Ubuntu | 18 passed, 4 tool-image tests skipped |
| Proxy integration with the Alpine tool image (Node 24, npm, uv, jq) | 9 passed |
| Real Codex CLI 0.164.0 against a running server (exec, native `apply_patch` on rw and ro mounts) | 2 passed |

The Codex CLI was installed separately at the pinned version 0.164.0. The test uses deterministic loopback model responses.

## Agent clients

- **Claude Code shell prefix:** the shared streaming client passed the tests above against both a test server and a real VM.
- **Pi:** the shared extension's integration tests (`remote-sandbox/pi` at `71c61d4`, Pi 0.85.1) passed 12 of 12 against the prepared Alpine image, whose guest runs Python 3.12. The server had the example public-site proxy policy and a writable project mount.

## Measurements

- Preparing the default Alpine image from scratch took about 7 seconds and produced a 65 MB Quicksand save.
- Starting the server with that cached image, until `/health` answered, took about 1 second.
- A trivial `POST /exec` round trip took about 11 ms.

These are single observations on one machine, not benchmarks.
