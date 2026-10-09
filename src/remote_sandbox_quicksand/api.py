"""HTTP and byte-preserving WebSocket API shared with remote-sandbox-v86."""

from __future__ import annotations

import asyncio
import base64
import binascii
import contextlib
import json
import re
from typing import Any

from aiohttp import WSMsgType, web

from .app_state import BACKEND, CODEX_CONNECTIONS, HTTP_EXECUTIONS, SHELL_SESSIONS

MAX_BODY_BYTES = 256 * 1024
MAX_STDIN_BYTES = 32 * 1024
MAX_STDIN_QUEUE_BYTES = 256 * 1024
MAX_STDIN_QUEUE_MESSAGES = 256
MAX_OUTPUT_BUFFER_BYTES = 1024 * 1024
START_DEADLINE_SECONDS = 10
SEND_DEADLINE_SECONDS = 5
SAFE_INTEGER = 2**53 - 1
REQUEST_KEYS = {"command", "cwd", "env", "stdin", "timeoutMs", "maxOutputBytes"}


def _pipe_closed(error):
    return isinstance(error, (BrokenPipeError, ProcessLookupError)) or getattr(error, "code", None) in {"EPIPE", "ESRCH"}


class RequestError(ValueError):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status_code = status


def _json(value: Any, status: int = 200, headers: dict | None = None) -> web.Response:
    return web.json_response(value, status=status, headers={
        "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", **(headers or {}),
    })


def check_browser_access(request: web.Request) -> None:
    if request.path in {"/", "/terminal.js"}:
        from .terminal import check_terminal_access

        check_terminal_access(request)
    elif request.path == "/exec/ws" and ("Origin" in request.headers or any(
            key.lower().startswith("sec-fetch-") for key in request.headers)):
        from .terminal import check_terminal_access

        check_terminal_access(request, websocket=True)
    elif "Origin" in request.headers and request.path not in {"/proxy", "/proxy/api"}:
        raise RequestError(403, "Browser Origin requests are not allowed.")
    hosts = request.headers.getall("Host", [])
    match = re.fullmatch(r"(?:localhost|127\.0\.0\.1|\[::1\])(?::([0-9]{1,5}))?", hosts[0], re.I) if len(hosts) == 1 else None
    if not match or (match[1] is not None and not 1 <= int(match[1]) <= 65535):
        raise RequestError(403, "Host must be localhost, 127.0.0.1, or [::1].")
    if not request.raw_path.startswith("/"):
        raise RequestError(400, "An absolute-path request target is required.")


@web.middleware
async def _errors(request: web.Request, handler):
    try:
        check_browser_access(request)
        return await handler(request)
    except RequestError as error:
        return _json({"error": str(error)}, error.status_code)
    except web.HTTPException as error:
        headers = {"Allow": error.headers["Allow"]} if "Allow" in error.headers else None
        return _json({"error": error.reason}, error.status, headers)
    except Exception as error:
        status = 429 if getattr(error, "status_code", getattr(error, "statusCode", None)) == 429 else 500
        return _json({"error": str(error) or "Execution failed."}, status)


def _string(value: Any, field: str, maximum: int, allow_nul: bool = False) -> str:
    if not isinstance(value, str):
        raise RequestError(400, f"{field} must be a string.")
    try:
        size = len(value.encode("utf-8"))
    except UnicodeEncodeError as error:
        raise RequestError(400, f"{field} must be valid UTF-8.") from error
    if size > maximum:
        raise RequestError(400, f"{field} exceeds {maximum} UTF-8 bytes.")
    if not allow_nul and "\0" in value:
        raise RequestError(400, f"{field} must not contain NUL bytes.")
    return value


def _integer(value: Any, field: str, maximum: int) -> int:
    if type(value) not in (int, float) or not 1 <= value <= maximum or int(value) != value:
        raise RequestError(400, f"{field} must be an integer from 1 to {maximum}.")
    return int(value)


def validate_exec(value: Any, streaming: bool = False) -> dict:
    if not isinstance(value, dict):
        raise RequestError(400, "JSON body must be an object.")
    allowed = REQUEST_KEYS | {"type"} if streaming else REQUEST_KEYS
    for key in value:
        if key not in allowed:
            raise RequestError(400, f"Unknown field: {key}.")
    command = _string(value.get("command"), "command", 64 * 1024)
    if not command.strip():
        raise RequestError(400, "command must not be empty.")
    result = {
        "command": command,
        "timeoutMs": _integer(value.get("timeoutMs", 30_000), "timeoutMs", 300_000),
        "maxOutputBytes": _integer(value.get("maxOutputBytes", 4 * 1024 * 1024), "maxOutputBytes", 16 * 1024 * 1024),
    }
    if "cwd" in value:
        result["cwd"] = _string(value["cwd"], "cwd", 4096)
        if not result["cwd"].startswith("/"):
            raise RequestError(400, "cwd must be an absolute path inside the sandbox.")
    if streaming:
        if type(value.get("stdin", True)) is not bool:
            raise RequestError(400, "stdin must be a boolean.")
        result["stdin"] = value.get("stdin", True)
    elif "stdin" in value:
        result["stdin"] = _string(value["stdin"], "stdin", MAX_STDIN_BYTES, allow_nul=True)
    if "env" in value:
        env = value["env"]
        if not isinstance(env, dict):
            raise RequestError(400, "env must be an object of string values.")
        if len(env) > 128:
            raise RequestError(400, "env must have at most 128 entries.")
        size = 0
        for key, raw in env.items():
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
                raise RequestError(400, f"Invalid environment variable name: {key}.")
            item = _string(raw, f"env.{key}", 32 * 1024)
            size += len(key.encode()) + len(item.encode()) + 2
            if size > 32 * 1024:
                raise RequestError(400, "env exceeds 32768 UTF-8 bytes.")
        result["env"] = env.copy()
    return result


def _parse_json(data: str | bytes) -> Any:
    def invalid_constant(value):
        raise ValueError(f"Invalid JSON constant: {value}")
    return json.loads(data, parse_constant=invalid_constant)


async def _start(backend, fields: dict, stdin: bool):
    return await backend.start(
        ["/bin/bash", "-c", fields["command"]],
        cwd=fields.get("cwd"), env={**backend.environment(), **fields.get("env", {})},
        stdin=stdin, timeout_ms=fields["timeoutMs"], max_output_bytes=fields["maxOutputBytes"],
    )


async def _health(request):
    return _json({"status": "ready", **request.app[BACKEND].info()})


async def _mounts(request):
    return _json({"mounts": request.app[BACKEND].info().get("mounts", [])})


async def _execute(request):
    if request.headers.get("Content-Type", "").split(";", 1)[0].strip().lower() != "application/json":
        raise RequestError(415, "Content-Type must be application/json.")
    if request.headers.get("Content-Encoding", "identity") != "identity":
        raise RequestError(415, "Compressed request bodies are not supported.")
    try:
        body = await request.read()
    except web.HTTPRequestEntityTooLarge as error:
        raise RequestError(413, f"Request body exceeds {MAX_BODY_BYTES} bytes.") from error
    if len(body) > MAX_BODY_BYTES:
        raise RequestError(413, f"Request body exceeds {MAX_BODY_BYTES} bytes.")
    try:
        fields = validate_exec(_parse_json(body.decode("utf-8")))
    except (UnicodeError, json.JSONDecodeError, ValueError) as error:
        if isinstance(error, RequestError):
            raise
        raise RequestError(400, "Request body must be valid UTF-8 JSON.") from error

    async def run():
        process = None
        writer = None
        next_event = None
        completed = False
        try:
            data = fields.get("stdin", "").encode("utf-8")
            process = await _start(request.app[BACKEND], fields, bool(data))

            async def write_input():
                if data:
                    try:
                        await process.write(data)
                        await process.close_stdin()
                    except Exception as error:
                        if not _pipe_closed(error):
                            raise
            writer = asyncio.create_task(write_input())
            output = {"stdout": bytearray(), "stderr": bytearray()}
            while True:
                next_event = asyncio.create_task(process.events.get())
                if writer is not None:
                    done, _ = await asyncio.wait({next_event, writer}, return_when=asyncio.FIRST_COMPLETED)
                    if writer in done:
                        await writer
                        writer = None
                event = await next_event
                if event["type"] in output:
                    output[event["type"]].extend(base64.b64decode(event["data"]))
                elif event["type"] == "error":
                    raise RuntimeError(event["error"])
                elif event["type"] == "exit":
                    completed = True
                    return {**{name: bytes(data).decode("utf-8", "replace") for name, data in output.items()},
                            **{key: value for key, value in event.items() if key != "type"}}
        finally:
            if next_event:
                next_event.cancel()
                await asyncio.gather(next_event, return_exceptions=True)
            if writer:
                writer.cancel()
                await asyncio.gather(writer, return_exceptions=True)
            if process and not completed:
                await process.terminate()

    async def disconnected():
        while request.transport is not None and not request.transport.is_closing():
            await asyncio.sleep(0.05)

    execution = asyncio.create_task(run())
    monitor = asyncio.create_task(disconnected())
    request.app[HTTP_EXECUTIONS].add(execution)
    try:
        done, _ = await asyncio.wait({execution, monitor}, return_when=asyncio.FIRST_COMPLETED)
        if execution not in done:
            raise asyncio.CancelledError
        return _json(await execution)
    finally:
        monitor.cancel()
        execution.cancel()
        await asyncio.gather(execution, monitor, return_exceptions=True)
        request.app[HTTP_EXECUTIONS].discard(execution)


def _stdin_bytes(value):
    message = "stdin data must be canonical base64 encoding at most 32768 bytes."
    if not isinstance(value, str) or len(value) > ((MAX_STDIN_BYTES + 2) // 3) * 4:
        raise ValueError(message)
    try:
        data = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as error:
        raise ValueError(message) from error
    if len(data) > MAX_STDIN_BYTES or base64.b64encode(data).decode() != value:
        raise ValueError(message)
    return data


class ShellSession:
    def __init__(self, request, ws):
        self.request, self.ws = request, ws
        self.process = None
        self.process_ready = asyncio.Event()
        self.received_start = False
        self.stdin_enabled = False
        self.eof_requested = False
        self.stdin_closed = False
        self.last_stdin_id = -1
        self.queued_bytes = self.queued_messages = 0
        self.input_queue = asyncio.Queue()
        self.send_lock = asyncio.Lock()
        self.tasks = set()
        self.terminal = self.completed = self.canceled = False
        self.start_task = None

    def task(self, coroutine):
        task = asyncio.create_task(coroutine)
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)
        return task

    async def send(self, value):
        if self.terminal or self.ws.closed:
            return
        encoded = json.dumps(value, separators=(",", ":"))
        transport = self.request.transport
        async with self.send_lock:
            if self.terminal or self.ws.closed:
                return
            buffered = transport.get_write_buffer_size() if transport else 0
            if buffered + len(encoded.encode()) > MAX_OUTPUT_BUFFER_BYTES:
                raise RuntimeError("WebSocket output buffer exceeded 1048576 bytes; execution canceled.")
            try:
                async with asyncio.timeout(SEND_DEADLINE_SECONDS):
                    await self.ws.send_str(encoded)
            except TimeoutError as error:
                raise RuntimeError("WebSocket output buffer stalled; execution canceled.") from error

    async def cancel(self):
        if self.canceled:
            return
        self.canceled = True
        if self.process:
            await self.process.terminate()
        elif self.start_task:
            self.start_task.cancel()
            if not self.terminal:
                await self.fail("Execution canceled during startup.")

    async def fail(self, message, code=1011):
        if self.terminal:
            return
        self.terminal = True
        # Termination bypasses any blocked stdin or socket write.
        self.task(self.cancel())
        with contextlib.suppress(Exception):
            async with asyncio.timeout(1):
                await self.ws.send_json({"type": "error", "error": message})
                await self.ws.close(code=code)

    async def input_closed(self):
        if not self.stdin_closed:
            self.stdin_closed = True
            await self.send({"type": "stdin_closed"})

    async def start(self, fields):
        try:
            self.process = await _start(self.request.app[BACKEND], fields, self.stdin_enabled)
            if self.terminal or self.canceled:
                await self.process.terminate()
                return
            await self.send({"type": "started", "processId": self.process.id})
            self.process_ready.set()
            self.task(self.output())
        except asyncio.CancelledError:
            raise
        except Exception as error:
            await self.fail(str(error))

    async def output(self):
        try:
            while not self.terminal:
                event = await self.process.events.get()
                if event["type"] == "error":
                    await self.fail(event["error"])
                    return
                if event["type"] == "exit":
                    if self.eof_requested:
                        await self.input_closed()
                    await self.send(event)
                    self.completed = self.terminal = True
                    await self.ws.close(code=1000)
                    return
                await self.send(event)
        except asyncio.CancelledError:
            raise
        except Exception as error:
            await self.fail(str(error), 1013 if "output buffer" in str(error) else 1011)

    async def inputs(self):
        await self.process_ready.wait()
        while not self.terminal:
            data, sequence = await self.input_queue.get()
            try:
                if self.stdin_closed or self.canceled:
                    continue
                if data is None:
                    await self.process.close_stdin()
                    await self.input_closed()
                else:
                    await self.process.write(data)
                    if not self.canceled:
                        await self.send({"type": "stdin_ack", "id": sequence})
            except asyncio.CancelledError:
                raise
            except Exception as error:
                if _pipe_closed(error):
                    await self.input_closed()
                else:
                    await self.fail(str(error))
            finally:
                self.queued_bytes -= len(data) if data is not None else 0
                self.queued_messages -= 1

    def queue_input(self, data, sequence=None):
        self.queued_bytes += len(data) if data is not None else 0
        self.queued_messages += 1
        if self.queued_bytes > MAX_STDIN_QUEUE_BYTES or self.queued_messages > MAX_STDIN_QUEUE_MESSAGES:
            raise ValueError("Pending stdin queue exceeded its limit.")
        self.input_queue.put_nowait((data, sequence))

    async def message(self, value):
        if not isinstance(value, dict) or not isinstance(value.get("type"), str):
            raise ValueError("A JSON object with a type field is required.")
        kind = value["type"]
        if not self.received_start:
            if kind != "start":
                raise ValueError("The first message must have type start.")
            fields = validate_exec(value, streaming=True)
            self.received_start = True
            self.stdin_enabled = fields["stdin"]
            self.start_task = self.task(self.start(fields))
            self.task(self.inputs())
            return
        if kind == "start":
            raise ValueError("Only one start message is allowed per connection.")
        allowed = {"type", "id", "data"} if kind == "stdin" else {"type"}
        for key in value:
            if key not in allowed:
                raise ValueError(f"Unknown field: {key}.")
        if kind == "cancel":
            self.task(self.cancel())
        elif kind == "stdin":
            if not self.stdin_enabled or self.eof_requested or self.stdin_closed:
                raise ValueError("stdin is closed.")
            sequence = value.get("id")
            if type(sequence) not in (int, float) or not 0 <= sequence <= SAFE_INTEGER or int(sequence) != sequence or sequence <= self.last_stdin_id:
                raise ValueError("stdin id must be a strictly increasing nonnegative safe integer.")
            sequence = int(sequence)
            data = _stdin_bytes(value.get("data"))
            self.last_stdin_id = sequence
            self.queue_input(data, sequence)
        elif kind == "stdin_eof":
            if not self.stdin_enabled or self.eof_requested or self.stdin_closed:
                raise ValueError("stdin is already closed.")
            self.eof_requested = True
            self.queue_input(None)
        else:
            raise ValueError(f"Unknown message type: {kind}.")

    async def run(self):
        try:
            while not self.terminal:
                try:
                    frame = await self.ws.receive(timeout=None if self.received_start else START_DEADLINE_SECONDS)
                except TimeoutError:
                    await self.fail("A start message is required within 10 seconds.", 1008)
                    break
                if frame.type in {WSMsgType.CLOSE, WSMsgType.CLOSED, WSMsgType.CLOSING, WSMsgType.ERROR}:
                    break
                try:
                    if frame.type != WSMsgType.TEXT:
                        raise ValueError("WebSocket messages must be UTF-8 JSON text.")
                    try:
                        value = _parse_json(frame.data)
                    except (ValueError, UnicodeError) as error:
                        raise ValueError("WebSocket messages must contain valid JSON.") from error
                    await self.message(value)
                except ValueError as error:
                    await self.fail(str(error), 1008)
        finally:
            self.terminal = True
            if not self.completed:
                await self.cancel()
            pending = list(self.tasks)
            for task in pending:
                task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)
            if self.process and not self.completed:
                await self.process.terminate()
            if not self.ws.closed:
                await self.ws.close()


async def _websocket(request):
    ws = web.WebSocketResponse(max_msg_size=MAX_BODY_BYTES, compress=False, autoping=True,
                              protocols=("sandbox-terminal",))
    await ws.prepare(request)
    session = ShellSession(request, ws)
    request.app[SHELL_SESSIONS].add(session)
    try:
        await session.run()
    finally:
        request.app[SHELL_SESSIONS].discard(session)
    return ws


async def _shutdown(app):
    await asyncio.gather(*(ws.close(code=1001) for ws in list(app[CODEX_CONNECTIONS])), return_exceptions=True)
    sessions = list(app[SHELL_SESSIONS])
    await asyncio.gather(*(session.cancel() for session in sessions), return_exceptions=True)
    await asyncio.gather(*(session.ws.close(code=1001) for session in sessions), return_exceptions=True)
    executions = list(app[HTTP_EXECUTIONS])
    for task in executions:
        task.cancel()
    await asyncio.gather(*executions, return_exceptions=True)


def create_app(backend, proxy=None) -> web.Application:
    from .codex import codex_handler
    from .terminal import install_terminal

    # Some aiohttp versions reject at >= their limit; enforce our exact limit above.
    app = web.Application(middlewares=[_errors], client_max_size=MAX_BODY_BYTES + 1)
    app[BACKEND] = backend
    app[SHELL_SESSIONS] = set()
    app[CODEX_CONNECTIONS] = set()
    app[HTTP_EXECUTIONS] = set()
    install_terminal(app, backend)
    app.router.add_get("/health", _health, allow_head=False)
    app.router.add_get("/mounts", _mounts, allow_head=False)
    app.router.add_post("/exec", _execute)
    app.router.add_get("/exec/ws", _websocket, allow_head=False)
    app.router.add_get("/codex", codex_handler, allow_head=False)
    if proxy is not None:
        from .proxy_management import install_proxy_management

        install_proxy_management(app, proxy)
    app.on_shutdown.append(_shutdown)
    return app
