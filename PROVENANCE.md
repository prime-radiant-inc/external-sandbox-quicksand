# Provenance

This project began on 9 October 2026 with `uv init --app --package remote-sandbox-quicksand`. `--package` adds the build system needed for the `remote-sandbox-quicksand` command. The repository was initialized separately with `git init`, because the parent directory is inside another Git working tree.

## Shared server code

The HTTP, streaming WebSocket and Codex adapters, browser routes, guest agent, guest filesystem operations, and host proxy engine were copied from [remote-sandbox-container](https://github.com/prime-radiant-inc/remote-sandbox-container) at commit `b26d3f5c6a610fcdd61e03b7911228225b8b1c74`, with the module renamed to `remote_sandbox_quicksand`. That commit passed the shared conformance suite in all profiles. Changes from the copied code:

- `backend.py` replaces the Apple Container lifecycle with a Quicksand VM. The guest agent transport is a dedicated virtio-serial port instead of a container's stdin/stdout.
- `guest_agent.py` opens that port, restores default SIGINT/SIGQUIT handling for commands, and supervises the guest-mux helper instead of relaying proxy streams over its own channel.
- The container's `proxy_relay.py` and `guest_proxy.py` are replaced by `proxy_bridge.py` and the guest-mux helper.
- `proxy.py` closes active connections before waiting for its listener to close.
- Branding and error messages name the VM instead of a container.
- `images.py` is new: Alpine image preparation and caching.

The container's protocol, proxy, UI-adapter and client tests were copied with the same renames. The backend, CLI and integration tests were adapted for Quicksand.

## Guest proxy multiplexer

`guest-mux/guest_mux.go` and the bridge design come from the Quicksand parent-process egress proxy prototype (`quicksand-proxy-prototype`, archive manifest dated 8 October 2026). The Go source is unchanged. `proxy_bridge.py` adapts the prototype's `guest_relay.py`, keeping its wire format and limits. It adds a fixed target, a readiness wait, and refusal of replacement transports. The prototype's mitmproxy-based egress proxy was not used; this server keeps the shared proxy engine and policy format.

The bundled binaries are the prototype's prebuilt files. Rebuilding the unchanged source with `guest-mux/build.sh` (Go 1.27.2, `-trimpath -ldflags '-s -w'`, `CGO_ENABLED=0`) reproduces them byte for byte:

| File | SHA-256 |
| --- | --- |
| `guest-mux/guest_mux.go` | `a4ea4490df7278c74dac5fb825b7cc8cbc8e1567400b5ae333ec854a75ca11f6` |
| `guest_bin/guest-mux-linux-arm64` | `cf60291a818a2ca9dd6cccf7c70e8c8997ca633525d9f585b846577a5e9c1551` |
| `guest_bin/guest-mux-linux-amd64` | `0371898cb7a4c589850f21a6c4bb7b1599eea4c5be4708e4b72eb04c4df797fe` |

## Browser UI

`src/remote_sandbox_quicksand/ui/` is [remote-sandbox-ui](https://github.com/prime-radiant-inc/remote-sandbox-ui) 0.2.0 at `fdbe4530c6ec72636f949bc4e1b2e0e2e3cc3392`, imported with that repository's `scripts/sync.py`. `manifest.json` records the file hashes.

## Quicksand

[Quicksand](https://microsoft.github.io/quicksand/) is used unmodified as a dependency: `quick-sandbox` 0.12.0, `quicksand-core` 0.13.0, `quicksand-qemu` 0.5.12 and `quicksand-alpine` 0.10.0 from PyPI. The optional `quicksand-ubuntu` 0.10.0 comes from Microsoft's index at `https://microsoft.github.io/quicksand/simple/`, because its PyPI release is an image-less stub. This project relies on some Quicksand internals, so those versions are pinned exactly:

- the virtio-serial bus created for Quicksand's own agent
- the 9p mount arguments
- `extra_qemu_args` ordering
- the private `_cleanup()` used after a partial start

Prepared Alpine images are built locally from Quicksand's Alpine 3.23 image and packages from `https://dl-cdn.alpinelinux.org`. No VM image is committed to this repository.

## Rename to External Sandbox — 30 October 2026

The project, its GitHub repository, distribution, command and Python module are now `external-sandbox-quicksand` / `external_sandbox_quicksand`, matching the rename of the shared protocol project from Remote Sandbox to External Sandbox. Environment variables use the `EXTERNAL_SANDBOX_` prefix, the prepared-image cache moved to `~/.cache/external-sandbox-quicksand`, guest paths and the agent's virtio-serial port name follow the new name, and the shared UI bundle is `external-sandbox-ui` 0.3.0. Wire protocol, default ports and behaviour are unchanged. The names, paths and commits recorded above describe earlier states and are preserved as written.
