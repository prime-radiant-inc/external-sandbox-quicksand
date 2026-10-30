import asyncio
import base64
import contextlib

import pytest
from aiohttp import WSMsgType
from aiohttp.test_utils import TestClient, TestServer

from external_sandbox_quicksand.api import create_app


EXIT = {"type": "exit", "exitCode": 17, "signal": None, "timedOut": False,
        "outputLimitExceeded": False, "durationMs": 123}


class FakeProcess:
    def __init__(self):
        self.id = "process-1"
        self.events = asyncio.Queue()
        self.inputs = []
        self.terminated = asyncio.Event()
        self.write_gate = None
        self.write_started = asyncio.Event()
        self.finish_on_eof = False
        self.echo = False

    async def write(self, data):
        self.inputs.append(data)
        self.write_started.set()
        if self.write_gate:
            await self.write_gate.wait()
        if self.echo:
            self.events.put_nowait({"type": "stdout", "data": base64.b64encode(data).decode()})

    async def close_stdin(self):
        self.inputs.append("eof")
        if self.finish_on_eof:
            self.events.put_nowait(EXIT.copy())

    async def terminate(self):
        if not self.terminated.is_set():
            self.terminated.set()
            self.events.put_nowait({**EXIT, "exitCode": None, "signal": 15})


class FakeBackend:
    def __init__(self):
        self.process = FakeProcess()
        self.calls = []
        self.start_gate = None
        self.start_entered = asyncio.Event()
        self.start_canceled = asyncio.Event()
        self.start_error = None

    def info(self):
        return {"backend": "test", "mounts": [{"hostPath": "/tmp/example", "guestPath": "/workspace"}]}

    def environment(self):
        return {"PATH": "/usr/bin:/bin", "BASE": "present"}

    async def start(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        self.start_entered.set()
        if self.start_error:
            raise self.start_error
        if self.start_gate:
            try:
                await self.start_gate.wait()
            except asyncio.CancelledError:
                self.start_canceled.set()
                raise
        return self.process


@pytest.fixture
async def server():
    backend = FakeBackend()
    async with TestClient(TestServer(create_app(backend))) as client:
        yield client, backend


async def receive(ws, kind):
    async with asyncio.timeout(3):
        while True:
            frame = await ws.receive()
            assert frame.type == WSMsgType.TEXT, frame
            data = frame.json()
            if data["type"] == kind:
                return data


async def started(client, **fields):
    ws = await client.ws_connect("/exec/ws")
    await ws.send_json({"type": "start", "command": "cat", **fields})
    assert await receive(ws, "started") == {"type": "started", "processId": "process-1"}
    return ws


async def test_health_mounts_and_access_boundary(server):
    client, backend = server
    response = await client.get("/health")
    assert await response.json() == {"status": "ready", **backend.info()}
    assert response.headers["Cache-Control"] == "no-store"
    assert (await (await client.get("/mounts")).json())["mounts"] == backend.info()["mounts"]
    for headers in [{"Origin": "http://localhost"}, {"Host": "evil.example"}, {"Host": "127.0.0.1:0"}]:
        response = await client.get("/health", headers=headers)
        assert response.status == 403
    assert (await client.get("/absent")).status == 404
    assert (await client.get("/exec")).status == 405
    assert not backend.calls


async def test_http_stdin_output_defaults_and_separate_streams(server):
    client, backend = server
    backend.process.echo = backend.process.finish_on_eof = True
    backend.process.events.put_nowait({"type": "stderr", "data": base64.b64encode(b"warning\n").decode()})
    response = await client.post("/exec", json={"command": "cat", "stdin": "hello\0world", "cwd": "/workspace", "env": {"BASE": "override"}})
    assert response.status == 200
    assert await response.json() == {**{key: value for key, value in EXIT.items() if key != "type"}, "stdout": "hello\0world", "stderr": "warning\n"}
    argv, options = backend.calls[0]
    assert argv == ["/bin/bash", "-c", "cat"]
    assert options["env"] == {"PATH": "/usr/bin:/bin", "BASE": "override"}
    assert options["timeout_ms"] == 30000
    assert options["max_output_bytes"] == 4 * 1024 * 1024
    assert options["cwd"] == "/workspace"
    assert backend.process.inputs == [b"hello\0world", "eof"]


@pytest.mark.parametrize("body", [None, [], {}, {"command": ""}, {"command": "true", "unknown": 1},
    {"command": "true", "cwd": "relative"}, {"command": "true", "env": {"BAD-NAME": "x"}},
    {"command": "true", "timeoutMs": True}, {"command": "true", "timeoutMs": 300001},
    {"command": "true", "maxOutputBytes": 16777217}, {"command": "a\0b"},
    {"command": "true", "stdin": "x" * 32769}])
async def test_http_rejects_invalid_body_without_execution(server, body):
    client, backend = server
    import json
    response = await client.post("/exec", data=json.dumps(body), headers={"Content-Type": "application/json"})
    assert response.status == 400
    assert not backend.calls


async def test_http_body_and_media_limits(server):
    client, backend = server
    assert (await client.post("/exec", data="{}")).status == 415
    assert (await client.post("/exec", data=b'\xff', headers={"Content-Type": "application/json"})).status == 400
    assert (await client.post("/exec", data=b" " * (256 * 1024 + 1), headers={"Content-Type": "application/json"})).status == 413
    assert not backend.calls


async def test_binary_safe_streaming_stdin_ack_and_exit_order(server):
    client, backend = server
    process = backend.process
    process.write_gate = asyncio.Event()
    process.finish_on_eof = True
    ws = await started(client, cwd="/workspace", env={"A": "b"})
    payload = bytes([0, 255, 195, 169, 10])
    await ws.send_json({"type": "stdin", "id": 0, "data": base64.b64encode(payload).decode()})
    await ws.send_json({"type": "stdin", "id": 1, "data": "YQ=="})
    await ws.send_json({"type": "stdin_eof"})
    await process.write_started.wait()
    assert process.inputs == [payload]
    process.events.put_nowait({"type": "stdout", "data": base64.b64encode(payload).decode()})
    process.events.put_nowait({"type": "stderr", "data": "d2FybmluZw=="})
    assert base64.b64decode((await receive(ws, "stdout"))["data"]) == payload
    assert base64.b64decode((await receive(ws, "stderr"))["data"]) == b"warning"
    process.write_gate.set()
    assert await receive(ws, "stdin_ack") == {"type": "stdin_ack", "id": 0}
    assert await receive(ws, "stdin_ack") == {"type": "stdin_ack", "id": 1}
    await receive(ws, "stdin_closed")
    assert await receive(ws, "exit") == EXIT
    assert (await ws.receive()).type == WSMsgType.CLOSE
    assert ws.close_code == 1000
    assert process.inputs == [payload, b"a", "eof"]
    assert not process.terminated.is_set()


async def test_output_before_start_returns_is_sent_after_started(server):
    client, backend = server
    backend.process.events.put_nowait({"type": "stdout", "data": "ZWFybHk="})
    ws = await started(client)
    assert await receive(ws, "stdout") == {"type": "stdout", "data": "ZWFybHk="}


async def test_stdin_during_startup_remains_ordered(server):
    client, backend = server
    backend.start_gate = asyncio.Event()
    ws = await client.ws_connect("/exec/ws")
    await ws.send_json({"type": "start", "command": "cat"})
    await ws.send_json({"type": "stdin", "id": 1, "data": "YQ=="})
    await ws.send_json({"type": "stdin_eof"})
    await backend.start_entered.wait()
    backend.start_gate.set()
    await receive(ws, "started")
    await receive(ws, "stdin_closed")
    assert backend.process.inputs == [b"a", "eof"]


async def test_cancel_bypasses_blocked_stdin(server):
    client, backend = server
    backend.process.write_gate = asyncio.Event()
    ws = await started(client)
    await ws.send_json({"type": "stdin", "id": 0, "data": "YQ=="})
    await backend.process.write_started.wait()
    await ws.send_json({"type": "cancel"})
    result = await receive(ws, "exit")
    assert result["signal"] == 15
    assert backend.process.terminated.is_set()


async def test_disconnect_cancels_pending_startup(server):
    client, backend = server
    backend.start_gate = asyncio.Event()
    ws = await client.ws_connect("/exec/ws")
    await ws.send_json({"type": "start", "command": "sleep 60"})
    await backend.start_entered.wait()
    await ws.close()
    async with asyncio.timeout(2):
        await backend.start_canceled.wait()


async def test_disconnect_cancels_running_process(server):
    client, backend = server
    ws = await started(client)
    await ws.close()
    async with asyncio.timeout(2):
        await backend.process.terminated.wait()


async def test_cancel_during_startup_closes_with_error(server):
    client, backend = server
    backend.start_gate = asyncio.Event()
    ws = await client.ws_connect("/exec/ws")
    await ws.send_json({"type": "start", "command": "sleep 60"})
    await backend.start_entered.wait()
    await ws.send_json({"type": "cancel"})
    assert "canceled" in (await receive(ws, "error"))["error"]
    await ws.close()


@pytest.mark.parametrize("frame", [None, [], {"type": "stdin", "id": 0, "data": "YQ=="},
    {"type": "start", "command": ""}, {"type": "start", "command": "true", "stdin": "text"},
    {"type": "start", "command": "true", "unknown": 1}])
async def test_invalid_first_frame_never_executes(server, frame):
    client, backend = server
    ws = await client.ws_connect("/exec/ws")
    await ws.send_json(frame)
    await receive(ws, "error")
    await ws.receive()
    assert ws.close_code == 1008
    assert not backend.calls


@pytest.mark.parametrize("frame", [{"type": "start", "command": "again"}, {"type": "unknown"},
    {"type": "stdin", "id": -1, "data": "YQ=="}, {"type": "stdin", "id": 0.1, "data": "YQ=="},
    {"type": "stdin", "id": 0, "data": "a==="}, {"type": "stdin", "id": 0, "data": "YQ"},
    {"type": "stdin", "id": 0, "data": "YR=="}, {"type": "stdin", "id": 0, "data": "YQ==\n"},
    {"type": "stdin_eof", "extra": True}, {"type": "cancel", "extra": True}])
async def test_invalid_frames_cancel_process(server, frame):
    client, backend = server
    ws = await started(client)
    await ws.send_json(frame)
    await receive(ws, "error")
    await ws.receive()
    assert ws.close_code == 1008
    assert backend.process.terminated.is_set()
    assert not backend.process.inputs


async def test_stdin_startup_queue_is_bounded(server):
    client, backend = server
    backend.start_gate = asyncio.Event()
    ws = await client.ws_connect("/exec/ws")
    await ws.send_json({"type": "start", "command": "cat"})
    await backend.start_entered.wait()
    for sequence in range(9):
        await ws.send_json({"type": "stdin", "id": sequence, "data": base64.b64encode(bytes(32768)).decode()})
    assert "queue" in (await receive(ws, "error"))["error"]
    async with asyncio.timeout(2):
        await backend.start_canceled.wait()


async def test_large_output_chunk_explicitly_fails_and_cancels(server):
    client, backend = server
    ws = await started(client)
    backend.process.events.put_nowait({"type": "stdout", "data": base64.b64encode(bytes(1024 * 1024)).decode()})
    assert "output buffer" in (await receive(ws, "error"))["error"]
    await ws.receive()
    assert ws.close_code == 1013
    assert backend.process.terminated.is_set()


async def test_binary_and_malformed_frames(server):
    client, backend = server
    for data in [b"{}", "{"]:
        ws = await client.ws_connect("/exec/ws")
        await (ws.send_bytes(data) if isinstance(data, bytes) else ws.send_str(data))
        await receive(ws, "error")
        await ws.close()
    assert not backend.calls


async def test_http_disconnect_terminates_process(server):
    client, backend = server
    task = asyncio.create_task(client.post("/exec", json={"command": "sleep 60"}))
    await backend.start_entered.wait()
    task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await task
    async with asyncio.timeout(2):
        await backend.process.terminated.wait()


async def test_busy_backend_preserves_http_status(server):
    client, backend = server

    class Busy(RuntimeError):
        status_code = 429
    backend.start_error = Busy("Sandbox is busy.")
    response = await client.post("/exec", json={"command": "true"})
    assert response.status == 429
    assert await response.json() == {"error": "Sandbox is busy."}


async def test_shutdown_cancels_websocket_process(server):
    client, backend = server
    ws = await started(client)
    await client.server.close()
    assert backend.process.terminated.is_set()
    await ws.close()


async def test_idle_socket_start_deadline(server, monkeypatch):
    monkeypatch.setattr("external_sandbox_quicksand.api.START_DEADLINE_SECONDS", 0.01)
    client, backend = server
    ws = await client.ws_connect("/exec/ws")
    assert "within 10 seconds" in (await receive(ws, "error"))["error"]
    await ws.receive()
    assert ws.close_code == 1008
    assert not backend.calls


async def test_slow_reader_cancels_with_explicit_error(server, monkeypatch):
    monkeypatch.setattr("external_sandbox_quicksand.api.SEND_DEADLINE_SECONDS", 0.05)
    client, backend = server
    ws = await started(client)
    # Stop network reads altogether so the server cannot drain its bounded writer.
    transport = ws._response.connection.transport
    transport.pause_reading()
    chunk = {"type": "stdout", "data": base64.b64encode(bytes(32768)).decode()}
    for _ in range(1024):
        backend.process.events.put_nowait(chunk)
    async with asyncio.timeout(3):
        await backend.process.terminated.wait()
    transport.resume_reading()
    assert "output buffer" in (await receive(ws, "error"))["error"]
    await ws.receive()
    assert ws.close_code == 1013


async def test_pipe_closed_error_preserves_final_output(server):
    client, backend = server

    async def broken_pipe(data):
        error = RuntimeError("Broken pipe")
        error.code = "EPIPE"
        raise error

    backend.process.write = broken_pipe
    ws = await started(client)
    await ws.send_json({"type": "stdin", "id": 0, "data": "YQ=="})
    await receive(ws, "stdin_closed")
    backend.process.events.put_nowait({"type": "stdout", "data": "ZG9uZQ=="})
    backend.process.events.put_nowait(EXIT.copy())
    assert base64.b64decode((await receive(ws, "stdout"))["data"]) == b"done"
    assert await receive(ws, "exit") == EXIT


async def test_whole_json_numbers_match_javascript_validation(server):
    client, backend = server
    ws = await started(client, timeoutMs=30000.0)
    await ws.send_str('{"type":"stdin","id":1.0,"data":"YQ=="}')
    assert await receive(ws, "stdin_ack") == {"type": "stdin_ack", "id": 1}


async def test_http_stdin_failure_returns_error_and_cancels(server):
    client, backend = server

    async def failed_write(data):
        raise RuntimeError("Guest input transport failed")

    backend.process.write = failed_write
    async with asyncio.timeout(2):
        response = await client.post("/exec", json={"command": "cat", "stdin": "a"})
    assert response.status == 500
    assert await response.json() == {"error": "Guest input transport failed"}
    assert backend.process.terminated.is_set()
