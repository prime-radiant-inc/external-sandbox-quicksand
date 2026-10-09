"""Private framed RPC agent. This module runs inside the Quicksand VM, never on the host.

The host reaches it over a dedicated virtio-serial port, separate from Quicksand's
own guest agent and unreachable through guest networking.
"""
from __future__ import annotations

import asyncio
import base64
import contextlib
import errno
import json
import os
import signal
import socket
import struct
import sys
import time

MAX_FRAME = 24 * 1024 * 1024
PROXY_PORT = 3128
PROXY_LISTEN = f"127.0.0.1:{PROXY_PORT}"
PROXY_FORWARD = "10.0.2.101:3128"
BASE_ENV = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": "/home/agent", "SHELL": "/bin/bash",
            "USER": "agent", "LOGNAME": "agent", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}


class WriteProtocol(asyncio.streams.FlowControlMixin):
    def __init__(self, loop):
        super().__init__(loop=loop)
        self.closed = loop.create_future()

    def connection_lost(self, exc):
        super().connection_lost(exc)
        if not self.closed.done():
            self.closed.set_result(None)

    def _get_close_waiter(self, stream):
        return self.closed


class Agent:
    def __init__(self, writer):
        self.writer = writer
        self.lock = asyncio.Lock()
        self.jobs = {}
        self.sessions = {}
        self.tasks = set()
        self.proxy = None

    async def send(self, value):
        data = json.dumps(value, separators=(",", ":"), ensure_ascii=True).encode()
        if len(data) > MAX_FRAME:
            raise RuntimeError("Agent response exceeds frame limit")
        async with self.lock:
            self.writer.write(struct.pack(">I", len(data)) + data)
            await self.writer.drain()

    async def handle(self, message):
        ident = message["id"]
        try:
            result = await self.dispatch(message["method"], message.get("params", {}))
            await self.send({"id": ident, "result": result})
        except Exception as exc:
            number = getattr(exc, "errno", None)
            if isinstance(exc, BrokenPipeError) and number is None:
                number = errno.EPIPE
            error = {"message": str(exc), "errno": number,
                     "code": getattr(exc, "code", errno.errorcode.get(number)),
                     "data": getattr(exc, "data", None)}
            await self.send({"id": ident, "error": error})

    async def dispatch(self, method, p):
        if method == "configure_proxy":
            if self.proxy is not None:
                raise ValueError("Guest proxy is already configured")
            self.proxy = GuestMux()
            try:
                environment = await self.proxy.start(p["caPem"], p["helper"])
            except BaseException:
                await self.proxy.close()
                self.proxy = None
                raise
            return {"environment": environment}
        if method == "start":
            if len(self.jobs) >= 16:
                raise RuntimeError("Too many concurrent processes")
            ident = p["processId"]
            if ident in self.jobs:
                raise ValueError("Duplicate process ID")
            # Environment replacement is intentional; never inherit the host or agent environment.
            argv = p["argv"]
            executable = argv[0]
            if p.get("arg0") is not None:
                argv = [p["arg0"], *argv[1:]]
            child = await asyncio.create_subprocess_exec(*argv, executable=executable,
                cwd=p["cwd"], env=p["env"], start_new_session=True,
                stdin=asyncio.subprocess.PIPE if p.get("stdin", True) else asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            job = Job(self, ident, child, p)
            self.jobs[ident] = job
            job.task = asyncio.create_task(job.run())
            return {"processId": ident}
        if method in ("write", "eof", "signal", "terminate"):
            job = self.jobs.get(p["processId"])
            if not job:
                if method in ("terminate", "signal", "eof"):
                    return {}
                raise BrokenPipeError(errno.EPIPE, "Process stdin is closed")
            if method == "write":
                if not job.child.stdin or job.child.stdin.is_closing():
                    raise BrokenPipeError(errno.EPIPE, "Process stdin is closed")
                data = base64.b64decode(p["data"], validate=True)
                if len(data) > 32768:
                    raise ValueError("stdin chunk exceeds 32 KiB")
                async with job.input_lock:
                    job.child.stdin.write(data)
                    await job.child.stdin.drain()
            elif method == "eof":
                async with job.input_lock:
                    if job.child.stdin:
                        job.child.stdin.close()
            else:
                job.kill(signal.SIGKILL if method == "terminate" else p["signal"])
            return {}
        if method == "fs":
            from guest_fs import FileSystemSession
            session = self.sessions.setdefault(p["sessionId"], FileSystemSession())
            return session.handle(p["method"], p["params"])
        if method == "close_fs":
            session = self.sessions.pop(p["sessionId"], None)
            if session and hasattr(session, "close"):
                session.close()
            return {}
        raise ValueError("Unknown private agent method")


class Job:
    def __init__(self, agent, ident, child, options):
        self.agent, self.id, self.child, self.options = agent, ident, child, options
        self.input_lock = asyncio.Lock()
        self.total = 0
        self.timed_out = self.output_limit = False
        self.started = time.monotonic()
        self.task = None

    def kill(self, sig):
        with contextlib.suppress(ProcessLookupError):
            os.killpg(self.child.pid, sig)

    async def output(self, stream, kind):
        while data := await stream.read(16384):
            remaining = self.options["maxOutputBytes"] - self.total
            self.total += len(data)
            if len(data) > remaining:
                data = data[:max(0, remaining)]
                self.output_limit = True
                self.kill(signal.SIGKILL)
            if data:
                await self.agent.send({"event": "process", "processId": self.id,
                    "message": {"type": kind, "data": base64.b64encode(data).decode()}})

    async def deadline(self):
        timeout = self.options.get("timeoutMs")
        if timeout is not None:
            await asyncio.sleep(timeout / 1000)
            self.timed_out = True
            self.kill(signal.SIGKILL)

    async def run(self):
        timer = asyncio.create_task(self.deadline())
        pumps = [asyncio.create_task(self.output(self.child.stdout, "stdout")),
                 asyncio.create_task(self.output(self.child.stderr, "stderr"))]
        try:
            # A descendant can keep pipes open after its parent exits. Kill that group
            # before joining pumps; no background processes survive a command.
            while self.child.returncode is None:
                await asyncio.sleep(0.01)
            self.kill(signal.SIGKILL)
            try:
                await asyncio.wait_for(asyncio.gather(*pumps), 2)
            except TimeoutError:
                # A deliberate setsid() escape may retain these descriptors. It
                # must not hold the API request open forever after its leader exits.
                for stream in (self.child.stdout, self.child.stderr):
                    stream._transport.close()
                await self.agent.send({"event": "process", "processId": self.id, "message": {
                    "type": "error", "error": "A descendant retained output pipes after command exit; restart the sandbox to clear escaped processes"}})
                return
            code = await self.child.wait()
            await self.agent.send({"event": "process", "processId": self.id, "message": {
                "type": "exit", "exitCode": code if code >= 0 else None, "signal": -code if code < 0 else None,
                "timedOut": self.timed_out, "outputLimitExceeded": self.output_limit,
                "durationMs": round((time.monotonic() - self.started) * 1000)}})
        finally:
            timer.cancel()
            self.kill(signal.SIGKILL)
            for task in pumps:
                if not task.done():
                    task.cancel()
            self.agent.jobs.pop(self.id, None)


class GuestMux:
    """Supervise the static guest-mux helper and publish proxy settings for commands.

    The helper listens on guest loopback and carries each connection over the QEMU
    guestfwd stream to the host proxy. Policy and upstream networking stay on the host.
    """

    def __init__(self):
        self.child = None
        self.environment = {}

    async def start(self, ca_pem, helper, directory="/run/remote-sandbox-proxy"):
        # Only public CA material reaches the guest. Preserve public system roots
        # for applications that also communicate with guest-local HTTPS services.
        if not isinstance(ca_pem, str) or len(ca_pem) > 65536 or "-----BEGIN CERTIFICATE-----" not in ca_pem:
            raise ValueError("Invalid proxy CA certificate")
        if "PRIVATE KEY" in ca_pem:
            raise ValueError("Refusing private key material in the guest")
        if not isinstance(helper, str) or not helper.startswith("/opt/remote-sandbox-quicksand/"):
            raise ValueError("Invalid guest proxy helper path")
        roots = ""
        for candidate in ("/etc/ssl/certs/ca-certificates.crt", "/etc/ssl/cert.pem"):
            if os.path.isfile(candidate):
                with open(candidate) as fp:
                    roots = fp.read()
                break
        os.makedirs(directory, mode=0o755, exist_ok=True)
        bundle = os.path.join(directory, "ca-bundle.pem")
        # Replace atomically; never follow a guest-created symlink to another path.
        temporary = os.path.join(directory, f".ca-{os.getpid()}.pem")
        with open(temporary, "x") as fp:
            fp.write(roots + "\n" + ca_pem)
        os.replace(temporary, bundle)
        await wait_for_network(30)
        log = open(os.path.join(directory, "guest-mux.log"), "ab")
        try:
            self.child = await asyncio.create_subprocess_exec(
                helper, PROXY_LISTEN, PROXY_FORWARD, stdin=asyncio.subprocess.DEVNULL,
                stdout=log, stderr=log, start_new_session=True)
        finally:
            log.close()
        # The helper listens before dialing the guestfwd address, and exits if that
        # fails. Probe its listener without connecting; the host confirms the handshake.
        for _ in range(100):
            if self.child.returncode is not None:
                raise RuntimeError(f"Guest proxy helper exited with status {self.child.returncode}")
            if loopback_listening(PROXY_PORT):
                break
            await asyncio.sleep(0.05)
        else:
            raise RuntimeError("Guest proxy helper did not start listening")
        endpoint = f"http://{PROXY_LISTEN}"
        self.environment = {key: endpoint for key in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy")}
        self.environment.update({"NO_PROXY": "", "no_proxy": ""})
        self.environment["NODE_USE_ENV_PROXY"] = "1"
        self.environment.update({key: bundle for key in (
            "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "NODE_EXTRA_CA_CERTS")})
        return self.environment

    async def close(self):
        if self.child and self.child.returncode is None:
            with contextlib.suppress(ProcessLookupError):
                self.child.kill()
            await self.child.wait()


def loopback_listening(port):
    expected = f"0100007F:{port:04X}"
    with contextlib.suppress(OSError), open("/proc/net/tcp") as table:
        for line in table.readlines()[1:]:
            fields = line.split()
            if len(fields) > 3 and fields[1] == expected and fields[3] == "0A":
                return True
    return False


def has_ipv4_address():
    import fcntl
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        for _, name in socket.if_nameindex():
            if name == "lo":
                continue
            with contextlib.suppress(OSError):
                fcntl.ioctl(probe.fileno(), 0x8915, struct.pack("256s", name.encode()[:15]))  # SIOCGIFADDR
                return True
    return False


async def wait_for_network(timeout):
    deadline = time.monotonic() + timeout
    while not has_ipv4_address():
        if time.monotonic() > deadline:
            raise RuntimeError("Guest network interface did not receive an address")
        await asyncio.sleep(0.2)


async def main():
    if sys.platform != "linux" or os.environ.get("REMOTE_SANDBOX_QUICKSAND_GUEST") != "1":
        raise SystemExit("This agent must run inside the managed Quicksand VM")
    if len(sys.argv) != 3 or sys.argv[1] != "--port" or not sys.argv[2].startswith("/dev/"):
        raise SystemExit("usage: guest_agent.py --port /dev/virtio-ports/NAME")
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    # The agent starts as a background job of a non-interactive shell, which ignores
    # SIGINT and SIGQUIT. Ignored dispositions survive exec, so restore the defaults
    # that commands expect before starting any of them.
    for number in (signal.SIGINT, signal.SIGQUIT):
        signal.signal(number, signal.SIG_DFL)
    os.makedirs("/workspace", exist_ok=True)
    os.makedirs("/home/agent", exist_ok=True)
    loop = asyncio.get_running_loop()
    port = os.open(sys.argv[2], os.O_RDWR | os.O_NOCTTY | os.O_CLOEXEC)
    reader = asyncio.StreamReader(limit=MAX_FRAME + 4)
    await loop.connect_read_pipe(lambda: asyncio.StreamReaderProtocol(reader), os.fdopen(port, "rb", buffering=0))
    transport, protocol = await loop.connect_write_pipe(lambda: WriteProtocol(loop),
                                                        os.fdopen(os.dup(port), "wb", buffering=0))
    writer = asyncio.StreamWriter(transport, protocol, None, loop)
    agent = Agent(writer)
    await agent.send({"event": "ready", "environment": BASE_ENV, "architecture": os.uname().machine,
                      "bash": os.access("/bin/bash", os.X_OK)})
    try:
        while True:
            size = struct.unpack(">I", await reader.readexactly(4))[0]
            if size > MAX_FRAME:
                raise ValueError("Agent request exceeds frame limit")
            message = json.loads(await reader.readexactly(size))
            if len(agent.tasks) >= 256:
                await agent.send({"id": message.get("id"), "error": {"message": "Too many pending requests"}})
                continue
            task = asyncio.create_task(agent.handle(message))
            agent.tasks.add(task)
            task.add_done_callback(agent.tasks.discard)
    except asyncio.IncompleteReadError:
        pass
    finally:
        if agent.proxy is not None:
            await agent.proxy.close()
        jobs = list(agent.jobs.values())
        for job in jobs:
            job.kill(signal.SIGKILL)
        await asyncio.gather(*(job.task for job in jobs), return_exceptions=True)
        for task in list(agent.tasks):
            task.cancel()
        writer.close()


if __name__ == "__main__":
    asyncio.run(main())
