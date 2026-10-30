"""Check this API against an explicitly selected external streaming client."""

import asyncio
import base64
import os
import sys

import pytest
from aiohttp.test_utils import TestServer

from external_sandbox_quicksand.api import create_app
from test_api import EXIT, FakeBackend


@pytest.mark.parametrize("prefix", ["EXTERNAL_SANDBOX_", "V86_"])
@pytest.mark.parametrize("forward_stdin", [True, False])
async def test_client_binary_streams_and_exit_status(external_streaming_client, forward_stdin, prefix):
    backend = FakeBackend()
    backend.process.echo = True
    backend.process.finish_on_eof = True
    warning = b"separate stderr\x00\xff\n"
    backend.process.events.put_nowait({"type": "stderr", "data": base64.b64encode(warning).decode()})
    output = b"initial output\x00\xff\n"
    backend.process.events.put_nowait({"type": "stdout", "data": base64.b64encode(output).decode()})
    if not forward_stdin:
        backend.process.events.put_nowait(EXIT.copy())
    async with TestServer(create_app(backend)) as server:
        env = {key: value for key, value in os.environ.items() if not key.startswith(("EXTERNAL_SANDBOX_", "V86_"))}
        env.update({prefix + "API_URL": str(server.make_url("/")), prefix + "CWD": "/workspace"})
        # Invoke the interpreter already managed by uv.
        command = "cat; printf 'this exact command is never evaluated on the host'"
        args = [sys.executable, str(external_streaming_client), *([] if forward_stdin else ["--no-stdin"]), command]
        client = await asyncio.create_subprocess_exec(*args, env=env, stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        payload = bytes(range(256)) * 512 if forward_stdin else b""
        try:
            async with asyncio.timeout(10):
                stdout, stderr = await client.communicate(payload)
        finally:
            if client.returncode is None:
                client.kill()
                await client.wait()
        assert client.returncode == 17, stderr
        assert stdout == output + payload
        assert stderr == warning
        assert backend.calls[0][0] == ["/bin/bash", "-c", command]
        assert backend.calls[0][1]["stdin"] is forward_stdin
        assert backend.calls[0][1]["cwd"] == "/workspace"
        if forward_stdin:
            assert b"".join(item for item in backend.process.inputs if isinstance(item, bytes)) == payload
            assert backend.process.inputs[-1] == "eof"


async def test_legacy_client_maps_host_cwd_through_mounts(external_streaming_client, tmp_path):
    backend = FakeBackend()
    backend.info = lambda: {"mounts": [{"hostPath": str(tmp_path), "guestPath": "/mnt/demo", "preservedPaths": []}]}
    child_dir = tmp_path / "nested"
    child_dir.mkdir()
    backend.process.events.put_nowait({**EXIT, "exitCode": 0})
    async with TestServer(create_app(backend)) as server:
        env = {key: value for key, value in os.environ.items() if not key.startswith(("EXTERNAL_SANDBOX_", "V86_"))}
        env["EXTERNAL_SANDBOX_API_URL"] = str(server.make_url("/"))
        client = await asyncio.create_subprocess_exec(sys.executable, str(external_streaming_client), "--no-stdin", "pwd",
            env=env, cwd=child_dir, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        async with asyncio.timeout(10):
            stdout, stderr = await client.communicate()
        assert client.returncode == 0, stderr
        assert backend.calls[0][1]["cwd"] == "/mnt/demo/nested"
