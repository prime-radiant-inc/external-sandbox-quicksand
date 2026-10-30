import asyncio
import base64
import errno
import unittest

from external_sandbox_quicksand.codex import CodexSession, MAX_MESSAGE, codex_handler
from external_sandbox_quicksand.app_state import BACKEND, CODEX_CONNECTIONS


START = {"processId": "chosen", "argv": ["/bin/bash", "-c", "echo hi"],
         "cwd": "file:///mnt/project", "env": {}, "tty": False}


class FakeProcess:
    id = "private-guest-id"

    def __init__(self):
        self.events = asyncio.Queue()
        self.writes = []
        self.signals = []
        self.terminated = 0

    async def write(self, data):
        self.writes.append(data)

    async def signal(self, sig):
        self.signals.append(sig)

    async def terminate(self):
        self.terminated += 1

    async def output(self, stream, data):
        await self.events.put({"type": stream, "data": base64.b64encode(data).decode()})
        await asyncio.sleep(0)

    async def finish(self, code=7, **fields):
        await self.events.put({"type": "exit", "exitCode": code, **fields})
        await asyncio.sleep(0)


class FakeBackend:
    def __init__(self):
        self.starts = []
        self.children = []
        self.closed_sessions = []
        self.fs_calls = []
        self.close_done = asyncio.Event()

    def info(self):
        return {"defaultCwd": "/mnt/project"}

    def environment(self):
        return {"PATH": "/usr/bin:/bin", "HOME": "/home/agent", "http_proxy": "http://guest-proxy",
                "TEST_A": "first", "TEST_AB": "second", "PRIVATE_SECRET": "do-not-inherit"}

    async def start(self, argv, **kwargs):
        self.starts.append({"argv": argv, **kwargs})
        child = FakeProcess()
        self.children.append(child)
        await child.events.put({"type": "stdout", "data": "ZWFybHkK"})
        return child

    async def fs(self, method, params, session_id):
        self.fs_calls.append((method, params, session_id))
        raise FileNotFoundError(errno.ENOENT, "No such file")

    async def close_fs_session(self, session_id):
        self.closed_sessions.append(session_id)
        self.close_done.set()


class CodexTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.backend = FakeBackend()
        self.messages = []
        self.session = CodexSession(self.backend, self.messages.append)
        self.next_id = 0

    async def asyncTearDown(self):
        await self.session.close()

    async def request(self, method, params=None):
        self.next_id += 1
        current = self.next_id
        await self.session.dispatch({"id": current, "method": method, "params": params or {}})
        return next(message for message in self.messages if message.get("id") == current)

    async def initialize(self):
        result = await self.request("initialize", {"clientName": "test"})
        self.assertEqual(result["result"]["environmentInfo"]["platformOs"], "linux")
        await self.session.dispatch({"method": "initialized"})

    async def test_handshake_argv_and_ordered_output_replay(self):
        await self.initialize()
        start = await self.request("process/start", START)
        self.assertEqual(start["result"], {"processId": "chosen", "sandboxType": "none"})
        self.assertEqual(self.backend.starts[0], {"argv": START["argv"], "cwd": "/mnt/project", "env": {},
                         "stdin": False, "timeout_ms": None, "max_output_bytes": 16777216, "arg0": None})
        child = self.backend.children[0]
        await child.output("stderr", b"error\n")
        await child.finish()
        notifications = [m for m in self.messages if m.get("method", "").startswith("process/")]
        self.assertEqual([(m["method"], m["params"]["seq"]) for m in notifications],
                         [("process/output", 1), ("process/output", 2), ("process/exited", 3), ("process/closed", 4)])
        self.assertLess(self.messages.index(start), self.messages.index(notifications[0]))
        replay = (await self.request("process/read", {"processId": "chosen", "afterSeq": 1}))["result"]
        self.assertEqual(base64.b64decode(replay["chunks"][0]["chunk"]), b"error\n")
        self.assertEqual((replay["exitCode"], replay["closed"], replay["nextSeq"]), (7, True, 5))

    async def test_fs_error_maps_to_protocol_not_found(self):
        await self.initialize()
        result = await self.request("fs/getMetadata", {"path": "file:///missing", "sandbox": {"permissions": {"type": "disabled"}}})
        self.assertEqual(result["error"]["code"], -32004)
        self.assertEqual(result["error"]["data"], {"code": "ENOENT"})
        self.assertNotIn("sandbox", self.backend.fs_calls[0][1])

    async def test_environment_filtering_and_secret_removal(self):
        await self.initialize()
        result = await self.request("process/start", {**START,
            "env": {"OPENAI_IDENTITY_TOKEN_FILE": "/private/token", "CUSTOM": "explicit"},
            "envPolicy": {"inherit": "all", "ignoreDefaultExcludes": True, "exclude": ["http_*"], "set": {}, "includeOnly": ["TEST_?"]}})
        self.assertIn("result", result)
        self.assertEqual(self.backend.starts[0]["env"], {"TEST_A": "first", "CUSTOM": "explicit"})

    async def test_stdin_retry_dedup_interrupt_and_disconnect(self):
        await self.initialize()
        await self.request("process/start", {**START, "pipeStdin": True})
        params = {"processId": "chosen", "writeId": "one", "chunk": "bGluZQo="}
        a, b = await asyncio.gather(self.request("process/write", params), self.request("process/write", params))
        self.assertEqual(a["result"], {"status": "accepted"})
        self.assertEqual(b["result"], {"status": "accepted"})
        child = self.backend.children[0]
        self.assertEqual(child.writes, [b"line\n"])
        self.assertIn("error", await self.request("process/write", {**params, "chunk": "Yg=="}))
        await self.request("process/signal", {"processId": "chosen", "signal": "interrupt"})
        self.assertEqual(child.signals, [2])
        await self.session.close()
        self.assertEqual(child.terminated, 1)
        self.assertEqual(self.backend.closed_sessions, [self.session.session_id])

    async def test_policy_requirements_and_shell_shortcut_fail_closed(self):
        await self.initialize()
        for override in [{"tty": True}, {"sandbox": {"permissions": {"type": "managed"}}},
                         {"enforceManagedNetwork": True}, {"networkProxy": {}}, {"shellSnapshot": {}},
                         {"managedNetwork": {}}, {"env": {"TOKEN": 42}}, {"argv": []},
                         {"cwd": "file://remote/etc/passwd"}, {"processId": ""}]:
            self.assertIn("error", await self.request("process/start", {**START, **override}), override)
        self.assertEqual(self.backend.starts, [])
        result = await self.request("thread/shellCommand", {"command": "touch /host-must-not-run"})
        self.assertEqual(result["error"]["code"], -32601)
        self.assertEqual(self.backend.starts, [])

    async def test_handshake_required_and_ids_rejected(self):
        self.assertEqual((await self.request("process/start", START))["error"]["code"], -32002)
        await self.initialize()
        await self.request("process/start", START)
        self.assertIn("error", await self.request("process/start", START))
        self.assertIn("error", await self.request("initialize", {"clientName": "again"}))

    async def test_read_output_eviction_and_failure(self):
        await self.initialize()
        await self.request("process/start", START)
        child = self.backend.children[0]
        for _ in range(17):
            await child.output("stdout", b"x" * 65536)
        replay = (await self.request("process/read", {"processId": "chosen", "afterSeq": 0}))["result"]
        self.assertIn("older", replay["failure"])
        self.assertLessEqual(sum(len(base64.b64decode(c["chunk"])) for c in replay["chunks"]), 1024 * 1024)
        await child.finish(None, outputLimitExceeded=True)
        done = (await self.request("process/read", {"processId": "chosen"}))["result"]
        self.assertEqual(done["exitCode"], 125)
        self.assertEqual(done["failure"], "Requested output is older than the retained output buffer")

    async def test_wait_for_output(self):
        await self.initialize()
        await self.request("process/start", START)
        await asyncio.sleep(0)
        reader = asyncio.create_task(self.request("process/read", {"processId": "chosen", "afterSeq": 1, "waitMs": 1000}))
        await asyncio.sleep(0)
        await self.backend.children[0].output("stdout", b"later")
        result = (await reader)["result"]
        self.assertEqual(base64.b64decode(result["chunks"][0]["chunk"]), b"later")

    async def test_disconnect_during_spawn_cleans_up(self):
        await self.initialize()
        gate = asyncio.Event()
        original = self.backend.start

        async def delayed(*args, **kwargs):
            await gate.wait()
            return await original(*args, **kwargs)

        self.backend.start = delayed
        start = asyncio.create_task(self.session.dispatch({"id": 99, "method": "process/start", "params": START}))
        await asyncio.sleep(0)
        close = asyncio.create_task(self.session.close())
        await asyncio.sleep(0)
        gate.set()
        await asyncio.gather(start, close)
        self.assertGreaterEqual(self.backend.children[0].terminated, 1)
        self.assertFalse(any(m.get("id") == 99 for m in self.messages))


class CodexWebSocketTests(unittest.IsolatedAsyncioTestCase):
    async def test_wire_handshake_and_unsupported_shell(self):
        from aiohttp import web
        from aiohttp.test_utils import TestClient, TestServer

        backend = FakeBackend()
        app = web.Application()
        app[BACKEND] = backend
        app[CODEX_CONNECTIONS] = set()
        app.router.add_get("/codex", codex_handler)
        async with TestClient(TestServer(app)) as client:
            async with client.ws_connect("/codex", max_msg_size=MAX_MESSAGE) as ws:
                await ws.send_json({"id": 1, "method": "initialize", "params": {"clientName": "test"}})
                self.assertIn("environmentInfo", (await ws.receive_json())["result"])
                await ws.send_json({"method": "initialized"})
                await ws.send_json({"id": 2, "method": "thread/shellCommand", "params": {"command": "false"}})
                self.assertEqual((await ws.receive_json())["error"]["code"], -32601)
                await ws.send_json({"id": 3, "method": "process/start", "params": START})
                self.assertEqual((await ws.receive_json())["id"], 3)
                self.assertEqual((await ws.receive_json())["method"], "process/output")
            await asyncio.wait_for(backend.close_done.wait(), 1)
        self.assertEqual(backend.children[0].terminated, 1)
