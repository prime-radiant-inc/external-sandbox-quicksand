"""Codex rust-v0.154.0 exec-server wire compatibility over /codex.

This endpoint intentionally has no thread/shellCommand method or host fallback.
"""

import asyncio
import base64
from collections import OrderedDict, deque
from dataclasses import dataclass, field
import errno
import hashlib
import json
import re
import uuid

from aiohttp import WSMsgType, web

from .app_state import BACKEND, CODEX_CONNECTIONS
from .guest_fs import guest_path_from_uri, guest_path_to_uri

MAX_MESSAGE = 12 * 1024 * 1024
MAX_INTEGER = 2**53 - 1
DEFAULT_ENV = {
    "PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": "/home/agent", "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8", "USER": "agent", "LOGNAME": "agent", "SHELL": "/bin/bash",
}
TRANSPORT_SECRETS = {
    "CODEX_EXEC_SERVER_NOISE_AUTH_TOKEN", "NODE_REPL_AUTH_TOKEN", "OPENAI_FEDERATION_RULE_ID",
    "OPENAI_IDENTITY_TOKEN_FILE", "OPENAI_WORKLOAD_IDENTITY_CONTEXT",
}
CORE_ENV = {"PATH", "SHELL", "TMPDIR", "TEMP", "TMP", "HOME", "LANG", "LC_ALL", "LC_CTYPE", "LOGNAME", "USER"}


class RpcError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.rpc_code = code


def invalid(message):
    raise RpcError(-32602, message)


def text(value, name, maximum=4096):
    try:
        valid = isinstance(value, str) and "\0" not in value and len(value.encode()) <= maximum
    except UnicodeError:
        valid = False
    if not valid:
        invalid(f"Invalid {name}")
    return value


def integer(value, name, fallback, maximum):
    if value is None:
        return fallback
    if type(value) is not int or not 0 <= value <= maximum:
        invalid(f"Invalid {name}")
    return value


def environment(value):
    if not isinstance(value, dict) or len(value) > 128:
        invalid("env must contain at most 128 string values")
    result, size = {}, 0
    for key, item in value.items():
        if not isinstance(key, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
            invalid("Invalid environment key")
        result[key] = text(item, "environment value", 32768)
        size += len(key.encode()) + len(item.encode()) + 2
    if size > 32768:
        invalid("Environment exceeds 32 KiB")
    return result


def matches(pattern, key):
    expression = "".join(".*" if char == "*" else "." if char == "?" else re.escape(char) for char in pattern)
    return re.fullmatch(expression, key, re.I) is not None


def check_sandbox(params):
    context = params.get("sandbox")
    if context is not None:
        if (not isinstance(context, dict) or not isinstance(context.get("permissions"), dict)
                or context["permissions"].get("type") != "disabled"):
            invalid("Additional Codex sandbox policies are unsupported. Use danger-full-access inside this VM; host access is limited by its mounts and network policy.")
    if params.get("enforceManagedNetwork") or params.get("managedNetwork") is not None or params.get("networkProxy") is not None:
        invalid("Codex-managed networking is unsupported; configure the sandbox proxy policy instead.")


@dataclass
class ProcessRecord:
    id: str
    stdin: bool
    child: object = None
    announced: bool = False
    notifications: list = field(default_factory=list)
    chunks: deque = field(default_factory=deque)
    bytes: int = 0
    next_seq: int = 1
    closed: bool = False
    exit_code: int | None = None
    failure: str | None = None
    lost_through: int = 0
    changed: asyncio.Event = field(default_factory=asyncio.Event)
    writes: OrderedDict = field(default_factory=OrderedDict)
    consumer: asyncio.Task | None = None
    cancelled: bool = False


class CodexSession:
    def __init__(self, backend, send):
        self.backend = backend
        self.send = send
        self.state = "new"
        self.session_id = str(uuid.uuid4())
        self.processes = OrderedDict()
        self.retained_bytes = 0
        self.fs_lock = asyncio.Lock()
        self._close_lock = asyncio.Lock()
        self._starting = set()

    @property
    def is_initialized(self):
        return self.state == "ready"

    def environment_info(self):
        return {
            "shell": {"name": "bash", "path": "/bin/bash"}, "executorVersion": "0.0.0",
            "cwd": guest_path_to_uri(self.backend.info().get("defaultCwd", "/workspace")),
            "userHomeDir": "file:///home/agent", "platformOs": "linux",
            "temporaryDirectories": ["file:///tmp"], "tempDir": "file:///tmp", "capabilities": {},
        }

    async def dispatch(self, message):
        if self.state == "closed":
            return
        if not isinstance(message, dict) or not isinstance(message.get("method"), str):
            raise RpcError(-32600, "Invalid RPC envelope")
        if "id" not in message:
            if message["method"] == "initialized" and self.state == "initialized":
                self.state = "ready"
            return
        request_id = message["id"]
        if not ((isinstance(request_id, str) and len(request_id) <= 256)
                or (type(request_id) is int and abs(request_id) <= MAX_INTEGER)):
            raise RpcError(-32600, "Invalid request ID")
        try:
            params = message.get("params")
            if params is None:
                params = {}
            if not isinstance(params, dict):
                invalid("params must be an object")
            result = await self.request(message["method"], params)
            if self.state == "closed":
                return
            self.send({"id": request_id, "result": result})
            if message["method"] == "process/start":
                record = self.processes[params["processId"]]
                record.announced = True
                for notification in record.notifications:
                    self.send(notification)
                record.notifications.clear()
        except Exception as error:
            if self.state == "closed":
                return
            error_code = getattr(error, "code", None) or errno.errorcode.get(getattr(error, "errno", None))
            rpc_code = getattr(error, "rpc_code", None)
            if rpc_code is None:
                rpc_code = -32601 if error_code == "ENOSYS" else -32004 if error_code == "ENOENT" else -32600 if error_code in ("EINVAL", "EACCES", "EPERM") else -32603
            detail = {"code": rpc_code, "message": str(error)}
            if error_code:
                detail["data"] = {"code": error_code}
            self.send({"id": request_id, "error": detail})

    def emit(self, record, method, params):
        if self.state == "closed":
            return
        notification = {"method": method, "params": {"processId": record.id, **params}}
        if record.announced:
            self.send(notification)
        else:
            record.notifications.append(notification)
        record.changed.set()

    def finish(self, record, exit_code, failure=None):
        if record.closed:
            return
        record.closed = True
        record.exit_code = exit_code
        record.failure = failure
        record.writes.clear()
        self.emit(record, "process/exited", {"seq": record.next_seq, "exitCode": exit_code, "sandboxDenied": False})
        record.next_seq += 1
        self.emit(record, "process/closed", {"seq": record.next_seq})
        record.next_seq += 1

    def process(self, params):
        record = self.processes.get(text(params.get("processId"), "processId", 256))
        if record is None:
            invalid("Unknown process ID")
        return record

    async def request(self, method, params):
        if method == "initialize":
            if self.state != "new":
                invalid("Session already initialized")
            if not text(params.get("clientName"), "clientName", 256):
                invalid("clientName must not be empty")
            if params.get("resumeSessionId") is not None:
                invalid("Session resumption is unsupported; initialize a new connection")
            self.state = "initialized"
            return {"sessionId": self.session_id, "environmentInfo": self.environment_info()}
        if self.state != "ready":
            raise RpcError(-32002, "initialize and initialized are required")
        if method == "environment/info":
            return self.environment_info()
        if method == "environment/status":
            return {"status": "ready"}
        if method.startswith("fs/"):
            check_sandbox(params)
            fields = {key: value for key, value in params.items() if key != "sandbox"}
            async with self.fs_lock:
                if self.state == "closed":
                    return {}
                return await self.backend.fs(method, fields, self.session_id)
        if method == "process/start":
            return await self.start(params)
        if method == "process/read":
            record = self.process(params)
            after = integer(params.get("afterSeq"), "afterSeq", 0, MAX_INTEGER)
            maximum = integer(params.get("maxBytes"), "maxBytes", 1024 * 1024, 16 * 1024 * 1024)
            wait = integer(params.get("waitMs"), "waitMs", 0, 30000)
            if not record.closed and record.next_seq <= after + 1 and wait:
                record.changed.clear()
                try:
                    await asyncio.wait_for(record.changed.wait(), wait / 1000)
                except TimeoutError:
                    pass
            chunks, size, next_seq = [], 0, record.next_seq
            for chunk in record.chunks:
                if chunk["seq"] <= after:
                    continue
                length = len(base64.b64decode(chunk["chunk"]))
                if chunks and size + length > maximum:
                    break
                chunks.append(chunk)
                size += length
                next_seq = chunk["seq"] + 1
                if size >= maximum:
                    break
            if params.get("maxBytes") is None:
                next_seq = record.next_seq
            return {"chunks": chunks, "nextSeq": next_seq, "exited": record.closed,
                    "exitCode": record.exit_code, "closed": record.closed, "sandboxDenied": False,
                    "failure": "Requested output is older than the retained output buffer" if after < record.lost_through else record.failure}
        if method == "process/write":
            return await self.write(params)
        if method == "process/signal":
            record = self.processes.get(text(params.get("processId"), "processId", 256))
            if params.get("signal") != "interrupt":
                invalid("Only the interrupt signal is supported")
            if record is not None and not record.closed:
                if record.child is None:
                    invalid("Process is not ready for signals")
                await record.child.signal(2)
            return {}
        if method == "process/terminate":
            record = self.processes.get(text(params.get("processId"), "processId", 256))
            running = record is not None and not record.closed
            if running:
                record.cancelled = True
                if record.child is not None:
                    await record.child.terminate()
            return {"running": running}
        raise RpcError(-32601, f"Unsupported exec-server method: {method}")

    async def write(self, params):
        record = self.processes.get(text(params.get("processId"), "processId", 256))
        if record is None:
            return {"status": "unknownProcess"}
        if record.child is None:
            return {"status": "starting"}
        if record.closed or not record.stdin:
            return {"status": "stdinClosed"}
        identifier = text(params.get("writeId"), "writeId", 256)
        if not identifier:
            invalid("writeId must not be empty")
        encoded = text(params.get("chunk"), "chunk", 43692)
        try:
            data = base64.b64decode(encoded, validate=True)
        except ValueError:
            invalid("stdin requires canonical base64, at most 32 KiB")
        if len(data) > 32768 or base64.b64encode(data).decode() != encoded:
            invalid("stdin requires canonical base64, at most 32 KiB")
        digest = hashlib.sha256(data).digest()
        prior = record.writes.get(identifier)
        if prior:
            if prior[0] != digest:
                invalid("writeId reused with different data")
            return await asyncio.shield(prior[1])

        async def do_write():
            try:
                await record.child.write(data)
                return {"status": "accepted"}
            except Exception as error:
                code = getattr(error, "code", None) or errno.errorcode.get(getattr(error, "errno", None))
                if code in ("EPIPE", "ESRCH", "ENOENT"):
                    record.stdin = False
                    return {"status": "stdinClosed"}
                raise

        result = asyncio.create_task(do_write())
        record.writes[identifier] = (digest, result)
        if len(record.writes) > 4096:
            record.writes.popitem(last=False)
        return await asyncio.shield(result)

    async def start(self, params):
        check_sandbox(params)
        if params.get("tty") is not False:
            invalid("PTY execution is unsupported; disable features.unified_exec_tty in Codex")
        if "pipeStdin" in params and type(params["pipeStdin"]) is not bool:
            invalid("pipeStdin must be boolean")
        if params.get("shellSnapshot") is not None:
            invalid("Executor shell snapshots are unsupported")
        identifier = text(params.get("processId"), "processId", 256)
        if not identifier or identifier in self.processes:
            invalid("processId must be new and nonempty")
        argv = params.get("argv")
        if not isinstance(argv, list) or not 1 <= len(argv) <= 1024:
            invalid("argv must be a nonempty array")
        argv = [text(arg, "argv", 65536) for arg in argv]
        if not argv[0] or sum(len(arg.encode()) + 1 for arg in argv) > 65536:
            invalid("argv exceeds 64 KiB")
        cwd = guest_path_from_uri(params.get("cwd"))
        overrides = environment(params.get("env"))
        env = {}
        policy = params.get("envPolicy")
        if policy is not None:
            if not isinstance(policy, dict) or policy.get("inherit") not in ("all", "core", "none"):
                invalid("Invalid envPolicy")
            if policy["inherit"] != "none":
                env = dict(self.backend.environment() if hasattr(self.backend, "environment") else DEFAULT_ENV)
            if policy["inherit"] == "core":
                env = {key: value for key, value in env.items() if key.upper() in CORE_ENV}
            for field_ in ("exclude", "includeOnly"):
                patterns = policy.get(field_)
                if not isinstance(patterns, list) or len(patterns) > 128 or any(not isinstance(p, str) or len(p) > 256 for p in patterns):
                    invalid(f"Invalid envPolicy.{field_}")
            env = {key: value for key, value in env.items()
                   if (policy.get("ignoreDefaultExcludes") or not re.search("key|secret|token", key, re.I))
                   and not any(matches(pattern, key) for pattern in policy["exclude"])}
            env.update(environment({} if policy.get("set") is None else policy["set"]))
            if policy["includeOnly"]:
                env = {key: value for key, value in env.items() if any(matches(pattern, key) for pattern in policy["includeOnly"])}
        env.update(overrides)
        env = {key: value for key, value in env.items() if key.upper() not in TRANSPORT_SECRETS}
        environment(env)
        arg0 = None if params.get("arg0") is None else text(params["arg0"], "arg0", 65536)
        if len(self.processes) >= 128:
            for key, record in self.processes.items():
                if record.closed:
                    self.retained_bytes -= record.bytes
                    del self.processes[key]
                    break
        if len(self.processes) >= 128:
            invalid("Too many retained processes")
        record = ProcessRecord(identifier, params.get("pipeStdin") is True)
        self.processes[identifier] = record
        starting_task = asyncio.current_task()
        self._starting.add(starting_task)
        try:
            record.child = await self.backend.start(argv, cwd=cwd, env=env, stdin=record.stdin,
                                                    timeout_ms=None, max_output_bytes=16 * 1024 * 1024, arg0=arg0)
            if self.state == "closed" or record.cancelled:
                await record.child.terminate()
            record.consumer = asyncio.create_task(self.consume(record))
            return {"processId": identifier, "sandboxType": "none"}
        except Exception:
            self.retained_bytes -= record.bytes
            self.processes.pop(identifier, None)
            raise
        finally:
            self._starting.discard(starting_task)

    def evict(self, record):
        chunk = record.chunks.popleft()
        length = len(base64.b64decode(chunk["chunk"]))
        record.bytes -= length
        self.retained_bytes -= length
        record.lost_through = chunk["seq"]

    async def consume(self, record):
        try:
            while self.state != "closed":
                event = await record.child.events.get()
                if event["type"] in ("stdout", "stderr"):
                    chunk = {"seq": record.next_seq, "stream": event["type"], "chunk": event["data"]}
                    record.next_seq += 1
                    length = len(base64.b64decode(event["data"]))
                    record.chunks.append(chunk)
                    record.bytes += length
                    self.retained_bytes += length
                    while record.bytes > 1024 * 1024 or len(record.chunks) > 8192:
                        self.evict(record)
                    for other in self.processes.values():
                        while self.retained_bytes > 8 * 1024 * 1024 and other.chunks:
                            self.evict(other)
                    self.emit(record, "process/output", chunk)
                elif event["type"] == "exit":
                    failure = "Process timed out" if event.get("timedOut") else "Process output exceeded 16 MiB" if event.get("outputLimitExceeded") else None
                    code = event.get("exitCode")
                    if code is None:
                        code = 128 + (event.get("signal") or 9)
                    self.finish(record, 125 if failure else code, failure)
                    return
                elif event["type"] == "error":
                    self.finish(record, 125, event.get("error") or event.get("message", "Guest process failed"))
                    return
        except asyncio.CancelledError:
            raise
        except Exception as error:
            self.finish(record, 125, str(error))

    async def close(self):
        async with self._close_lock:
            if self.state == "closed":
                return
            self.state = "closed"
            await asyncio.gather(*self._starting, return_exceptions=True)
            children = []
            consumers = []
            for record in self.processes.values():
                record.cancelled = True
                if record.child is not None and not record.closed:
                    children.append(record.child.terminate())
                if record.consumer is not None:
                    record.consumer.cancel()
                    consumers.append(record.consumer)
                record.changed.set()
                record.notifications.clear()
                record.chunks.clear()
                record.writes.clear()
            await asyncio.gather(*children, *consumers, return_exceptions=True)
            async with self.fs_lock:
                await self.backend.close_fs_session(self.session_id)
            self.processes.clear()
            self.retained_bytes = 0


async def codex_handler(request):
    connections = request.app[CODEX_CONNECTIONS]
    if len(connections) >= 16:
        raise web.HTTPServiceUnavailable(text="Codex connection limit reached")
    ws = web.WebSocketResponse(max_msg_size=MAX_MESSAGE, compress=False)
    connections.add(ws)
    queue = asyncio.Queue()
    queued_bytes = 0
    pending_bytes = 0
    pending = set()
    initialized = asyncio.Event()
    session = None

    def send(message):
        nonlocal queued_bytes
        if ws.closed:
            return
        encoded = json.dumps(message, separators=(",", ":"), ensure_ascii=True)
        size = len(encoded.encode())
        transport_size = request.transport.get_write_buffer_size() if request.transport else 0
        if queued_bytes + size + transport_size > MAX_MESSAGE:
            asyncio.create_task(ws.close(code=1008, message=b"Codex output buffer exceeded"))
            return
        queued_bytes += size
        queue.put_nowait((encoded, size))

    async def writer():
        nonlocal queued_bytes
        try:
            while True:
                encoded, size = await queue.get()
                await ws.send_str(encoded)
                queued_bytes -= size
        except (ConnectionError, RuntimeError):
            await ws.close()

    async def deadline():
        try:
            await asyncio.wait_for(initialized.wait(), 10)
        except TimeoutError:
            await ws.close(code=1008, message=b"Codex initialization timed out")

    async def dispatch(raw, size):
        nonlocal pending_bytes
        try:
            def reject_constant(value):
                raise ValueError(f"Invalid JSON constant: {value}")
            await session.dispatch(json.loads(raw, parse_constant=reject_constant))
            if session.is_initialized:
                initialized.set()
        except Exception:
            await ws.close(code=1008, message=b"Invalid Codex RPC message")
        finally:
            pending_bytes -= size

    tasks = []
    try:
        await ws.prepare(request)
        session = CodexSession(request.app[BACKEND], send)
        tasks = [asyncio.create_task(writer()), asyncio.create_task(deadline())]
        async for message in ws:
            if message.type not in (WSMsgType.TEXT, WSMsgType.BINARY):
                if message.type == WSMsgType.ERROR:
                    break
                continue
            try:
                raw = message.data.decode("utf-8", errors="strict") if isinstance(message.data, bytes) else message.data
            except UnicodeError:
                await ws.close(code=1008, message=b"Invalid UTF-8")
                break
            size = len(raw.encode())
            if len(pending) >= 32 or pending_bytes + size > MAX_MESSAGE:
                await ws.close(code=1008, message=b"Too many pending Codex requests")
                break
            pending_bytes += size
            task = asyncio.create_task(dispatch(raw, size))
            pending.add(task)
            task.add_done_callback(pending.discard)
    finally:
        connections.discard(ws)

        async def cleanup():
            for task in tasks:
                task.cancel()
            # Let an in-flight spawn finish so its process can be terminated;
            # never abandon it between guest spawn and handle creation.
            if session is not None:
                await session.close()
            for task in pending:
                task.cancel()
            await asyncio.gather(*tasks, *pending, return_exceptions=True)

        cleanup_task = asyncio.create_task(cleanup())
        try:
            # aiohttp can cancel the handler when the peer closes its TCP
            # connection. Cleanup must survive that cancellation.
            await asyncio.shield(cleanup_task)
        except asyncio.CancelledError:
            await cleanup_task
            raise
    return ws
