"""Guest images: a prepared Alpine save by default, or Quicksand's stock Ubuntu.

Quicksand's Alpine image has neither Bash nor Python. The first run boots that
image once, installs the required packages from Alpine's HTTPS repository
through this server's own allow-listed proxy, and saves the result as a
Quicksand save in the cache directory. Later runs boot the save directly.
"""
from __future__ import annotations

import asyncio
import contextlib
import fcntl
import hashlib
import json
import os
import re
import shlex
import shutil
import sys
import tempfile
import time
from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

REQUIRED_PACKAGES = ("bash", "python3")
DEFAULT_PACKAGES = ("bash", "python3", "git", "ripgrep")
ALPINE_REPOSITORY = "https://dl-cdn.alpinelinux.org"
ALPINE_POLICY = {"allow": [{"origin": ALPINE_REPOSITORY, "methods": ["GET", "HEAD"]}]}
METADATA = "external-sandbox-image.json"
SCHEMA = 1
PACKAGE_NAME = re.compile(r"[a-z0-9][a-z0-9+._-]{0,63}")
GUEST_HELPER = "/tmp/external-sandbox-guest-mux"


@dataclass(frozen=True)
class GuestImage:
    reference: str  # Passed to Quicksand: a base image name or save directory.
    label: str


def cache_root(override=None) -> Path:
    if override:
        return Path(override).expanduser().absolute()
    base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(base).expanduser().absolute() / "external-sandbox-quicksand"


def parse_packages(text) -> tuple[str, ...]:
    """Required packages plus the default set, or plus an explicit comma-separated list."""
    if text is None:
        return tuple(sorted(DEFAULT_PACKAGES))
    names = [name.strip() for name in text.split(",") if name.strip()]
    for name in names:
        if not PACKAGE_NAME.fullmatch(name):
            raise ValueError(f"Invalid Alpine package name: {name}")
    if len(names) > 64:
        raise ValueError("At most 64 extra packages are supported")
    return tuple(sorted(set(REQUIRED_PACKAGES) | set(names)))


def host_image_arch() -> str:
    from quicksand_core.host import Architecture
    from quicksand_core.qemu.platform import get_platform_config

    return "arm64" if get_platform_config().arch.arch_type == Architecture.ARM64 else "amd64"


def alpine_identity(packages) -> dict:
    """Everything that determines the prepared image's contents."""
    import quicksand_alpine

    arch = host_image_arch()
    base = quicksand_alpine.image.resolve(arch).chain[0]
    buildhash = base.with_name(base.name + ".buildhash")
    return {"schema": SCHEMA, "base": "alpine", "distribution": quicksand_alpine.DISTRO_VERSION,
            "quicksandAlpine": version("quicksand-alpine"), "quicksandCore": version("quicksand-core"),
            "buildhash": buildhash.read_text().strip() if buildhash.exists() else None,
            "arch": arch, "packages": list(packages)}


def alpine_key(identity) -> str:
    return hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()[:16]


def _log(message):
    print(f"external-sandbox-quicksand: {message}", file=sys.stderr, flush=True)


async def resolve_image(name="alpine", packages=None, cache_dir=None, accel="auto") -> GuestImage:
    if name == "alpine":
        return await ensure_alpine(parse_packages(packages), cache_root(cache_dir), accel)
    if packages is not None:
        raise ValueError("--packages applies only to the prepared Alpine image")
    if name == "ubuntu":
        try:
            version("quicksand-ubuntu")
            import quicksand_ubuntu

            quicksand_ubuntu.image.resolve(host_image_arch())
        except (PackageNotFoundError, ImportError, FileNotFoundError):
            raise ValueError("The Ubuntu image is optional; install it with "
                             "`uv sync --extra ubuntu` or run `uv run --extra ubuntu external-sandbox-quicksand`") from None
        return GuestImage("ubuntu", "ubuntu")
    # Another Quicksand image name or save directory. It must provide bash and python3.
    path = Path(name).expanduser()
    return GuestImage(str(path.absolute()) if path.exists() else name, name)


async def ensure_alpine(packages, root: Path, accel) -> GuestImage:
    identity = alpine_identity(packages)
    target = root / "images" / f"alpine-{identity['distribution']}-{identity['arch']}-{alpine_key(identity)}"
    label = f"alpine-{identity['distribution']}+{','.join(packages)}"
    if (target / METADATA).is_file():
        return GuestImage(str(target), label)
    target.parent.mkdir(parents=True, exist_ok=True)
    with open(root / "images" / ".lock", "w") as lock:
        # Another server may be preparing the same image; wait for it rather than racing.
        await asyncio.to_thread(fcntl.flock, lock.fileno(), fcntl.LOCK_EX)
        try:
            if not (target / METADATA).is_file():
                await prepare_alpine(identity, target, accel)
        finally:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
    return GuestImage(str(target), label)


async def prepare_alpine(identity, target: Path, accel):
    from quicksand_core import NetworkMode, Sandbox
    from quicksand_core.qemu.arch import MachineType
    from quicksand_core.qemu.platform import get_platform_config

    from .proxy import HostProxy
    from .proxy_bridge import GUEST_ADDRESS, GUEST_LISTEN, GUEST_PORT, MuxBridge, guestfwd_netdev_args
    from .proxy_policy import ProxyPolicy

    packages = identity["packages"]
    _log(f"preparing Alpine {identity['distribution']} image with {', '.join(packages)} "
         f"(first run only; downloads from {ALPINE_REPOSITORY} through the managed proxy)")
    started = time.monotonic()
    staging = Path(tempfile.mkdtemp(prefix=".staging-", dir=target.parent))
    proxy = HostProxy(ProxyPolicy.from_config(ALPINE_POLICY))
    bridge = None
    sandbox = None
    try:
        await proxy.start()
        bridge = await MuxBridge(proxy.address).start()
        mmio = get_platform_config().arch.machine_type == MachineType.VIRT
        sandbox = Sandbox(image="alpine", network_mode=NetworkMode.NONE, accel=accel, cpus=2, memory="1024M",
                          extra_qemu_args=guestfwd_netdev_args(bridge.port, mmio=mmio))
        await sandbox.start()

        async def run(command, *, stdin=None, timeout=60):
            result = await sandbox.execute(command, timeout=timeout, stdin=stdin)
            if result.exit_code != 0:
                raise RuntimeError(f"Image preparation failed: {command.split()[0]}: "
                                   f"{(result.stderr or result.stdout).strip()[-2000:]}")
            return result.stdout

        machine = (await run("uname -m")).strip()
        arch = {"aarch64": "arm64", "x86_64": "amd64"}.get(machine)
        if arch != identity["arch"]:
            raise RuntimeError(f"Unexpected Alpine guest architecture: {machine}")
        helper = Path(__file__).resolve().parent / "guest_bin" / f"guest-mux-linux-{arch}"
        await run(f"cat > {GUEST_HELPER} && chmod 700 {GUEST_HELPER}", stdin=helper.read_bytes())
        await run("i=0; until ip -4 addr show | grep -q 'inet 10\\.'; do "
                  "i=$((i+1)); [ $i -gt 150 ] && exit 1; sleep 0.2; done")
        await run(f"setsid {GUEST_HELPER} {GUEST_LISTEN} {GUEST_ADDRESS}:{GUEST_PORT} "
                  f"</dev/null >{GUEST_HELPER}.log 2>&1 & echo $! > {GUEST_HELPER}.pid")
        await bridge.wait_ready(30)
        await run("cat /etc/ssl/certs/ca-certificates.crt - > /tmp/external-sandbox-ca.pem", stdin=proxy.ca_pem)
        proxy_env = (f"HTTPS_PROXY=http://{GUEST_LISTEN} https_proxy=http://{GUEST_LISTEN} "
                     "SSL_CERT_FILE=/tmp/external-sandbox-ca.pem")
        await run(f"env {proxy_env} apk add --no-cache -- {' '.join(map(shlex.quote, packages))}", timeout=900)
        installed = (await run("apk info -v | sort")).split()
        checks = (await run("bash --version | head -1; python3 --version")).strip()
        # Leave nothing from this session in the saved disk: no helper, CA or package cache.
        await run(f"kill $(cat {GUEST_HELPER}.pid) 2>/dev/null; rm -f {GUEST_HELPER} {GUEST_HELPER}.log {GUEST_HELPER}.pid "
                  "/tmp/external-sandbox-ca.pem; rm -rf /var/cache/apk/*")
        await sandbox.save("image", workspace=staging)
        metadata = {**identity, "installed": installed, "checks": checks.splitlines(),
                    "createdAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
        (staging / "image" / METADATA).write_text(json.dumps(metadata, indent=2) + "\n")
        os.replace(staging / "image", target)
        _log(f"prepared {target} in {time.monotonic() - started:.0f}s")
    finally:
        if sandbox is not None:
            with contextlib.suppress(Exception):
                if sandbox.is_running:
                    await sandbox.stop()
                else:
                    await sandbox._cleanup()
        if bridge is not None:
            await bridge.close()
        await proxy.close()
        shutil.rmtree(staging, ignore_errors=True)
