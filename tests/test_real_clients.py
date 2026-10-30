"""Opt-in external-client compatibility and protocol checks in a Quicksand VM."""

import asyncio
import base64
import os

import aiohttp
from aiohttp.test_utils import TestServer
import pytest

from external_sandbox_quicksand.api import create_app
from test_quicksand_integration import sandbox as sandbox  # shared module-scoped fixture


pytestmark = [pytest.mark.integration, pytest.mark.asyncio(loop_scope="module"),
              pytest.mark.skipif(os.environ.get("RUN_QUICKSAND_TESTS") != "1",
                                 reason="Set RUN_QUICKSAND_TESTS=1")]


async def idle(backend):
    async with asyncio.timeout(5):
        while backend.info()["activeCommands"]:
            await asyncio.sleep(0.01)


async def test_shared_uv_client_real_binary_io_and_exit(external_streaming_client, sandbox):
    backend, rw, _ = sandbox
    async with TestServer(create_app(backend)) as server:
        env = {key: value for key, value in os.environ.items() if not key.startswith(("EXTERNAL_SANDBOX_", "V86_"))}
        env["EXTERNAL_SANDBOX_API_URL"] = str(server.make_url("/"))
        # /mounts maps this real host cwd into /mnt/project inside the VM.
        command = "printf 'prefix\\000\\377'; cat; printf 'stderr\\000\\377\\n' >&2; exit 23"
        client = await asyncio.create_subprocess_exec("uv", "run", "--quiet", "--script", str(external_streaming_client), command,
            env=env, cwd=rw, stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        payload = bytes(range(256)) * 1024  # 256 KiB: eight acknowledged stdin chunks.
        try:
            async with asyncio.timeout(30):
                stdout, stderr = await client.communicate(payload)
        finally:
            if client.returncode is None:
                client.kill()
                await client.wait()
        assert client.returncode == 23, stderr
        assert stdout == b"prefix\0\xff" + payload
        assert stderr == b"stderr\0\xff\n"
        await idle(backend)


async def test_real_websocket_timeout_reports_and_cleans_process(sandbox):
    backend, _, _ = sandbox
    async with TestServer(create_app(backend)) as server, aiohttp.ClientSession() as client:
        async with client.ws_connect(server.make_url("/exec/ws")) as ws:
            await ws.send_json({"type": "start", "command": "printf ready; sleep 60", "stdin": False, "timeoutMs": 100})
            assert (await ws.receive_json())["type"] == "started"
            output = bytearray()
            async with asyncio.timeout(5):
                while True:
                    event = await ws.receive_json()
                    if event["type"] == "stdout":
                        output.extend(base64.b64decode(event["data"]))
                    elif event["type"] == "exit":
                        assert event["timedOut"] is True
                        assert event["signal"] == 9
                        break
                    else:
                        pytest.fail(str(event))
            assert output == b"ready"
        await idle(backend)


@pytest.mark.parametrize("abrupt", [True, False])
async def test_real_disconnect_cancels_process(sandbox, abrupt):
    backend, _, _ = sandbox
    async with TestServer(create_app(backend)) as server, aiohttp.ClientSession() as client:
        ws = await client.ws_connect(server.make_url("/exec/ws"))
        await ws.send_json({"type": "start", "command": "sleep 60", "stdin": False})
        assert (await ws.receive_json())["type"] == "started"
        assert backend.info()["activeCommands"] == 1
        if abrupt:
            # Abort TCP without a WebSocket handshake; aiohttp cancels its handler.
            ws._response.connection.transport.abort()
        else:
            await ws.close()
        await idle(backend)
