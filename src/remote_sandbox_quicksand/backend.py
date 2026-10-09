"""Backend-neutral process interface and Quicksand VM lifecycle/transport."""
from __future__ import annotations

import asyncio
import base64
import contextlib
import json
import re
import shlex
import shutil
import struct
import tempfile
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Protocol


MAX_FRAME = 24 * 1024 * 1024


class BusyError(RuntimeError):
    status_code = 429
    statusCode = 429


class GuestError(RuntimeError):
    def __init__(self, error):
        super().__init__(error.get("message", "Guest operation failed"))
        self.errno = error.get("errno")
        self.code = error.get("code")
        self.data = error.get("data")


@dataclass
class Mount:
    name: str
    hostPath: str
    mode: str = "rw"
    preservedPaths: list[str] = field(default_factory=list)

    @property
    def guestPath(self):
        return f"/mnt/{self.name}"

    def info(self):
        return {**asdict(self), "guestPath": self.guestPath}


def parse_mounts(specs: list[tuple[str, str]], preserve_paths=False) -> list[Mount]:
    mounts = []
    protected = ["/bin", "/sbin", "/etc", "/usr", "/lib", "/lib64", "/dev", "/proc", "/sys", "/run",
                 "/mnt", "/workspace", "/home", "/opt", "/tmp"]
    for spec, mode in specs:
        if mode not in ("ro", "rw"):
            raise ValueError("Mount mode must be ro or rw")
        name, sep, value = spec.partition("=")
        raw = value if sep else spec
        if not raw:
            raise ValueError("Mount path must not be empty")
        requested = Path(raw).expanduser().absolute()
        source = requested.resolve(strict=True)
        name = name if sep else requested.name
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", name):
            raise ValueError(f"Invalid mount name: {name}")
        if any(m.name == name for m in mounts):
            raise ValueError(f"Duplicate mount name: {name}")
        if not source.is_dir():
            raise ValueError(f"Mount is not a directory: {source}")
        if any(c in str(source) for c in (",", "\n", "\0")):
            raise ValueError("Mount paths cannot contain commas, newlines, or NUL")
        aliases = list(dict.fromkeys([str(requested), str(source)])) if preserve_paths else []
        for alias in aliases:
            if alias == "/" or any(alias == p or alias.startswith(p + "/") or p.startswith(alias + "/") for p in protected):
                raise ValueError(f"Cannot preserve guest system path {alias}; use /mnt/{name}")
            if any(c in alias for c in (",", "\n", "\0")):
                raise ValueError("Preserved paths cannot contain commas, newlines, or NUL")
        for previous in mounts:
            other = Path(previous.hostPath)
            if mode != previous.mode and (source == other or source.is_relative_to(other) or other.is_relative_to(source)):
                raise ValueError("Read-only and writable host mounts must not overlap")
        mounts.append(Mount(name, str(source), mode, aliases))
    return mounts


class Process:
    def __init__(self, backend, ident):
        self.backend, self.id = backend, ident
        self.events = asyncio.Queue(maxsize=64)  # <= ~1.4 MiB of encoded output
        self.finished = asyncio.get_running_loop().create_future()
        self.failed = False

    def feed(self, message):
        if self.failed:
            return
        if self.events.full():
            self.fail("Process output consumer exceeded the bounded output buffer")
            asyncio.create_task(self.backend._terminate_quietly(self.id))
            return
        self.events.put_nowait(message)
        if message["type"] in ("exit", "error") and not self.finished.done():
            self.finished.set_result(None)

    def fail(self, message):
        self.failed = True
        while not self.events.empty():
            self.events.get_nowait()
        self.events.put_nowait({"type": "error", "error": message})
        if not self.finished.done():
            self.finished.set_result(None)

    async def write(self, data: bytes):
        if len(data) > 32768:
            raise ValueError("stdin chunk exceeds 32 KiB")
        await self.backend._rpc("write", {"processId": self.id, "data": base64.b64encode(data).decode()}, timeout=300)

    async def close_stdin(self):
        await self.backend._rpc("eof", {"processId": self.id}, timeout=300)

    async def signal(self, sig):
        await self.backend._rpc("signal", {"processId": self.id, "signal": sig})

    async def terminate(self):
        if not self.finished.done():
            await self.backend._terminate_quietly(self.id)
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(asyncio.shield(self.finished), 5)


class Backend(Protocol):
    """Public adapters depend only on this interface."""
    def info(self) -> dict: ...
    def environment(self) -> dict: ...
    async def start(self, argv, cwd=None, env=None, stdin=True, timeout_ms=None, max_output_bytes=16777216, arg0=None) -> Process: ...
    async def fs(self, method, params, session_id) -> dict: ...
    async def close_fs_session(self, session_id): ...


GUEST_DIR = "/opt/remote-sandbox-quicksand"
GUEST_FILES = ("guest_agent.py", "guest_fs.py")
AGENT_PORT_NAME = "remote-sandbox.agent.0"
AGENT_LOG = "/var/log/remote-sandbox-agent.log"
GUEST_ARCHITECTURES = {"aarch64": "arm64", "arm64": "arm64", "x86_64": "amd64", "amd64": "amd64"}


class QuicksandBackend:
    """One Quicksand VM, driven through a private agent on a dedicated virtio-serial port.

    Quicksand boots the VM and its own guest agent installs this server's agent.
    The VM has no network interface unless the managed proxy is enabled; then its
    only NIC is restricted (QEMU ``restrict=on``) and has one guestfwd stream to
    the host proxy bridge.
    """

    def __init__(self, mounts=None, image="alpine", image_label=None, cpus=2, memory=512, accel="auto",
                 proxy=None, boot_timeout=None, sandbox_factory=None):
        self.mounts = mounts or []
        self.image, self.image_label = image, image_label or str(image)
        self.cpus, self.memory, self.accel = cpus, memory, accel
        self.boot_timeout = boot_timeout
        self.sandbox_factory = sandbox_factory
        self.sandbox = None
        self.temp_dir = None
        self.writer = None
        self.processes = {}
        self.pending = {}
        self.counter = 0
        self.lock = asyncio.Lock()
        self.reader_task = None
        self.ready = None
        self.closed = False
        self._env = {}
        self.architecture = "unknown"
        self.accelerator = None
        self.proxy = proxy
        self.bridge = None

    @property
    def default_cwd(self):
        return self.mounts[0].guestPath if self.mounts else "/workspace"

    def environment(self):
        return dict(self._env)

    def info(self):
        result = {"status": "stopped" if self.closed else "ready", "backend": "quicksand",
                  "architecture": self.architecture, "shell": "/bin/bash", "network": False,
                  "proxyEnabled": self.proxy is not None,
                  "mounts": [m.info() for m in self.mounts], "defaultCwd": self.default_cwd,
                  "activeCommands": len(self.processes), "image": self.image_label,
                  "accelerator": self.accelerator}
        if self.bridge is not None:
            result["proxyTransport"] = "connected" if self.bridge.connected else "disconnected"
        return result

    def qemu_args(self, socket_path):
        """Extra QEMU arguments: the agent port, plus the proxy NIC when enabled."""
        args = ["-chardev", f"socket,path={socket_path},server=on,wait=off,id=rsagent",
                "-device", f"virtserialport,chardev=rsagent,name={AGENT_PORT_NAME}"]
        if self.bridge is not None:
            from quicksand_core.qemu.arch import MachineType
            from quicksand_core.qemu.platform import get_platform_config

            from .proxy_bridge import guestfwd_netdev_args
            mmio = get_platform_config().arch.machine_type == MachineType.VIRT
            args += guestfwd_netdev_args(self.bridge.port, mmio=mmio)
        return args

    def create_sandbox(self, socket_path):
        from quicksand_core import Mount as QuicksandMount, NetworkMode, Sandbox

        factory = self.sandbox_factory or Sandbox
        options = {}
        if self.boot_timeout is not None:
            options["boot_timeout"] = self.boot_timeout
        # NONE removes Quicksand's default NIC, SMB relay and agent port forward.
        # The managed proxy, if any, adds its own restricted NIC in qemu_args().
        return factory(image=self.image, network_mode=NetworkMode.NONE, cpus=self.cpus,
                       memory=f"{self.memory}M", accel=self.accel, extra_qemu_args=self.qemu_args(socket_path),
                       mounts=[QuicksandMount(host=m.hostPath, guest=m.guestPath, readonly=m.mode == "ro", type="9p")
                               for m in self.mounts], **options)

    async def _guest(self, command, *, stdin=None, timeout=60):
        """Run a fixed setup command through Quicksand's own guest agent."""
        result = await self.sandbox.execute(command, timeout=timeout, stdin=stdin)
        if result.exit_code != 0:
            raise RuntimeError(f"Guest setup failed ({result.exit_code}): {(result.stderr or result.stdout).strip()}")
        return result.stdout

    async def _install_guest_files(self):
        package = Path(__file__).resolve().parent
        await self._guest(f"mkdir -p {GUEST_DIR} && chmod 755 {GUEST_DIR}")
        for name in GUEST_FILES:
            await self._guest(f"cat > {GUEST_DIR}/{name} && chmod 644 {GUEST_DIR}/{name}",
                              stdin=(package / name).read_bytes())
        if self.proxy is None:
            return None
        machine = (await self._guest("uname -m")).strip()
        arch = GUEST_ARCHITECTURES.get(machine)
        if arch is None:
            raise RuntimeError(f"Unsupported guest architecture for the proxy helper: {machine}")
        helper = f"{GUEST_DIR}/guest-mux"
        await self._guest(f"cat > {helper} && chmod 755 {helper}",
                          stdin=(package / "guest_bin" / f"guest-mux-linux-{arch}").read_bytes())
        return helper

    async def _bind_preserved_paths(self):
        for mount in self.mounts:
            for alias in mount.preservedPaths:
                command = f"mkdir -p {shlex.quote(alias)} && mount --bind {shlex.quote(mount.guestPath)} {shlex.quote(alias)}"
                if mount.mode == "ro":
                    command += f" && mount -o remount,bind,ro {shlex.quote(alias)}"
                await self._guest(command)

    async def boot(self):
        if self.proxy is not None:
            from .proxy_bridge import MuxBridge
            self.bridge = await MuxBridge(self.proxy.address).start()
        self.ready = asyncio.get_running_loop().create_future()
        # Unix socket paths are short-limited; keep this out of long per-user temp paths.
        self.temp_dir = Path(tempfile.mkdtemp(prefix="rsq-", dir="/tmp" if Path("/tmp").is_dir() else None))
        socket_path = self.temp_dir / "agent.sock"
        try:
            self.sandbox = self.create_sandbox(socket_path)
            await self.sandbox.start()
            accelerator = getattr(self.sandbox, "accelerator", None)
            self.accelerator = getattr(accelerator, "value", accelerator)
            # Connect before the agent opens its port: a virtio console read
            # reports EOF while no host endpoint is attached.
            reader, self.writer = await asyncio.open_unix_connection(str(socket_path), limit=MAX_FRAME + 4)
            self.reader_task = asyncio.create_task(self._read(reader))
            helper = await self._install_guest_files()
            await self._bind_preserved_paths()
            await self._guest(f"REMOTE_SANDBOX_QUICKSAND_GUEST=1 setsid python3 -I -u {GUEST_DIR}/guest_agent.py "
                              f"--port /dev/virtio-ports/{AGENT_PORT_NAME} </dev/null >>{AGENT_LOG} 2>&1 &")
            try:
                ready = await asyncio.wait_for(asyncio.shield(self.ready), 60)
            except TimeoutError:
                log = await self.sandbox.execute(f"tail -c 4000 {AGENT_LOG}")
                raise RuntimeError(f"Guest agent did not start: {log.stdout.strip() or 'no log output'}") from None
            if not ready.get("bash"):
                raise RuntimeError("The guest image must provide /bin/bash")
            if self.proxy is not None:
                result = await self._rpc("configure_proxy", {"caPem": self.proxy.ca_pem, "helper": helper})
                await self.bridge.wait_ready(30)
                self._env.update(self.proxy.guest_env)
                self._env.update(result["environment"])
        except BaseException:
            await self.close()
            raise
        return self

    async def _read(self, reader):
        try:
            while True:
                size = struct.unpack(">I", await reader.readexactly(4))[0]
                if size > MAX_FRAME:
                    raise RuntimeError("Invalid guest agent frame")
                value = json.loads(await reader.readexactly(size))
                if value.get("event") == "ready":
                    self._env = value["environment"]
                    self.architecture = value["architecture"]
                    if not self.ready.done():
                        self.ready.set_result(value)
                elif value.get("event") == "process":
                    ident, message = value["processId"], value["message"]
                    process = self.processes.get(ident)
                    if process:
                        process.feed(message)
                        if message["type"] in ("exit", "error"):
                            self.processes.pop(ident, None)
                else:
                    future = self.pending.get(value.get("id"))
                    if future and not future.done():
                        if "error" in value:
                            future.set_exception(GuestError(value["error"]))
                        else:
                            future.set_result(value.get("result"))
        except (Exception, asyncio.CancelledError) as exc:
            reason = f"Guest agent disconnected: {str(exc) or type(exc).__name__}"
            if self.ready and not self.ready.done():
                self.ready.set_exception(RuntimeError(reason))
            for future in self.pending.values():
                if not future.done():
                    future.set_exception(RuntimeError(reason))
            for process in self.processes.values():
                process.fail(reason)
            self.processes.clear()
        finally:
            # A malformed or closed private transport must not leave a live command channel.
            if self.writer:
                self.writer.close()

    def _available(self):
        return not self.closed and self.writer is not None and not self.writer.is_closing()

    async def _send(self, value):
        if not self._available():
            raise RuntimeError("Guest agent is not running")
        payload = json.dumps(value, ensure_ascii=True).encode()
        if len(payload) > MAX_FRAME:
            raise ValueError("Agent request exceeds frame limit")
        async with self.lock:
            self.writer.write(struct.pack(">I", len(payload)) + payload)
            await self.writer.drain()

    async def _rpc(self, method, params, timeout=30):
        if not self._available():
            raise RuntimeError("Guest agent is not running")
        self.counter += 1
        ident = self.counter
        future = asyncio.get_running_loop().create_future()
        self.pending[ident] = future
        try:
            await self._send({"id": ident, "method": method, "params": params})
            return await asyncio.wait_for(future, timeout)
        finally:
            self.pending.pop(ident, None)
            if not future.done():
                future.cancel()

    async def start(self, argv, cwd=None, env=None, stdin=True, timeout_ms=None, max_output_bytes=16777216, arg0=None):
        if len(self.processes) >= 16:
            raise BusyError("Maximum 16 concurrent commands")
        ident = uuid.uuid4().hex
        process = Process(self, ident)
        self.processes[ident] = process
        # Never interpolate a command into a host shell. Exact argv crosses framed JSON.
        task = asyncio.create_task(self._rpc("start", {"processId": ident, "argv": argv,
            "cwd": cwd or self.default_cwd, "env": self.environment() if env is None else env,
            "stdin": stdin, "timeoutMs": timeout_ms, "maxOutputBytes": max_output_bytes, "arg0": arg0}))
        try:
            await asyncio.shield(task)
            return process
        except BaseException:
            # The spawn could have succeeded before cancellation reached this coroutine.
            with contextlib.suppress(Exception, asyncio.CancelledError):
                await asyncio.wait_for(asyncio.shield(task), 30)
            await self._terminate_quietly(ident)
            self.processes.pop(ident, None)
            raise

    async def _terminate_quietly(self, ident):
        with contextlib.suppress(Exception):
            await self._rpc("terminate", {"processId": ident}, timeout=5)

    async def fs(self, method, params, session_id):
        return await self._rpc("fs", {"sessionId": session_id, "method": method, "params": params})

    async def close_fs_session(self, session_id):
        with contextlib.suppress(Exception):
            await self._rpc("close_fs", {"sessionId": session_id})

    async def close(self):
        if self.closed:
            return
        self.closed = True
        try:
            if self.writer:
                self.writer.close()
            if self.sandbox is not None:
                if self.sandbox.is_running:
                    await self.sandbox.stop()
                else:
                    # A partially started VM is not marked running; its cleanup
                    # still terminates QEMU and removes Quicksand's temp files.
                    await self.sandbox._cleanup()
        finally:
            if self.reader_task and not self.reader_task.done():
                self.reader_task.cancel()
            await asyncio.gather(*(t for t in (self.reader_task,) if t), return_exceptions=True)
            if self.bridge is not None:
                await self.bridge.close()
            if self.temp_dir is not None:
                shutil.rmtree(self.temp_dir, ignore_errors=True)
