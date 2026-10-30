"""Real Codex + running server; deterministic local model responses, no API key.

Opt in with SANDBOX_EXEC_SERVER_URL, SANDBOX_TEST_RW, and SANDBOX_TEST_RO.
The two directories must already be mounted as project (rw) and reference (ro).
"""

from __future__ import annotations

import asyncio
import json
import os
import shlex
import shutil
import subprocess
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

import pytest


def response_events(response_id: str, item: dict) -> bytes:
    events = [
        {"type": "response.created", "response": {"id": response_id}},
        {"type": "response.output_item.done", "item": item},
        {
            "type": "response.completed",
            "response": {
                "id": response_id,
                "usage": {
                    "input_tokens": 0,
                    "input_tokens_details": None,
                    "output_tokens": 0,
                    "output_tokens_details": None,
                    "total_tokens": 0,
                },
            },
        },
    ]
    return "".join(
        f"event: {event['type']}\ndata: {json.dumps(event)}\n\n" for event in events
    ).encode()


@pytest.mark.integration
def test_real_codex_cli_remote_execution_and_native_patch(tmp_path: Path):
    url = os.environ.get("SANDBOX_EXEC_SERVER_URL")
    rw_setting = os.environ.get("SANDBOX_TEST_RW")
    ro_setting = os.environ.get("SANDBOX_TEST_RO")
    if not (url and rw_setting and ro_setting):
        pytest.skip("Set SANDBOX_EXEC_SERVER_URL, SANDBOX_TEST_RW and SANDBOX_TEST_RO")
    parsed = urlsplit(url)
    assert parsed.scheme == "ws" and parsed.hostname in {"localhost", "127.0.0.1"}
    assert parsed.path == "/codex" and not parsed.username and not parsed.password
    rw_root, ro_root = Path(rw_setting).resolve(), Path(ro_setting).resolve()
    assert rw_root.is_dir() and ro_root.is_dir(), "Fixture mount directories must exist"

    state = tmp_path / "codex-state"
    state.mkdir()
    # Deliberately omit user auth, proxy settings, plugins, and provider keys.
    # These overrides apply only to the child CLI, never the user's profile.
    child_env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "CODEX_HOME": str(state),
        "CODEX_SQLITE_HOME": str(state),
        "TERM": "dumb",
    }
    binary = os.environ.get("CODEX_CLI_BIN", "codex")
    try:
        version = subprocess.run(
            [binary, "--version"],
            cwd=tmp_path,
            env=child_env,
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        ).stdout.strip()
    except FileNotFoundError:
        pytest.skip("Install Codex CLI 0.164.0 or set CODEX_CLI_BIN")
    assert version == "codex-cli 0.164.0", "The experimental exec-server protocol is pinned"

    rw = Path(tempfile.mkdtemp(prefix="codex-fixture-", dir=rw_root))
    ro = Path(tempfile.mkdtemp(prefix="codex-fixture-", dir=ro_root))
    guest_rw = f"/mnt/project/{rw.name}"
    guest_ro = f"/mnt/reference/{ro.name}"
    (ro / "input.txt").write_text("live readonly fixture\n")
    command = "\n".join(
        [
            "set -eu",
            "printf 'system='; uname -s",
            "printf 'architecture='; uname -m",
            f"printf 'readonly='; cat {shlex.quote(guest_ro + '/input.txt')}",
            f"printf 'created through Codex in a sandbox\\n' > {shlex.quote(guest_rw + '/codex-result.txt')}",
            "printf 'stderr from sandbox\\n' >&2",
            f"if printf forbidden > {shlex.quote(guest_ro + '/forbidden.txt')}; then echo READONLY_BYPASSED; exit 99; fi",
            "printf 'readonly write denied\\n'",
        ]
    )
    requests: list[dict] = []
    fixture_errors: list[str] = []

    class Provider(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_POST(self):
            try:
                assert self.path == "/v1/responses"
                assert self.headers.get("Authorization") is None, "Credentials reached fixture"
                length = int(self.headers.get("Content-Length", "0"))
                assert 0 < length <= 4 * 1024 * 1024
                requests.append(json.loads(self.rfile.read(length)))
                ordinal = len(requests)
                assert ordinal <= 4, "Expected three tools and one final response"
                if ordinal == 1:
                    item = {
                        "type": "function_call",
                        "call_id": "sandbox-command",
                        "name": "exec_command",
                        "arguments": json.dumps(
                            {
                                "cmd": command,
                                "workdir": guest_rw,
                                "login": False,
                                "yield_time_ms": 30_000,
                                "environment_id": "sandbox",
                            }
                        ),
                    }
                elif ordinal < 4:
                    target = guest_rw if ordinal == 2 else guest_ro
                    item = {
                        "type": "custom_tool_call",
                        "call_id": "sandbox-patch-rw" if ordinal == 2 else "sandbox-patch-ro",
                        "name": "apply_patch",
                        "input": "\n".join(
                            [
                                "*** Begin Patch",
                                f"*** Add File: {target}/codex-patch.txt",
                                "+created by remote apply_patch",
                                "*** End Patch",
                            ]
                        ),
                    }
                else:
                    item = {
                        "type": "message",
                        "role": "assistant",
                        "id": "sandbox-final",
                        "content": [
                            {"type": "output_text", "text": "Verified the sandbox execution fixture."}
                        ],
                    }
                body = response_events(f"sandbox-response-{ordinal}", item)
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            except (AssertionError, ValueError, KeyError, OSError) as error:
                fixture_errors.append(repr(error))
                self.send_error(500, "Local fixture rejected the request")

    provider = ThreadingHTTPServer(("127.0.0.1", 0), Provider)
    provider_thread = threading.Thread(target=provider.serve_forever, daemon=True)
    provider_thread.start()
    try:
        (state / "config.toml").write_text(
            f'''model = "gpt-5.5"
model_provider = "sandbox_fixture"
approval_policy = "never"
sandbox_mode = "danger-full-access"
check_for_update_on_startup = false

[features]
unified_exec = true
shell_snapshot = false
unified_exec_tty = false

[analytics]
enabled = false

[feedback]
enabled = false

[model_providers.sandbox_fixture]
name = "Deterministic loopback fixture"
base_url = "http://127.0.0.1:{provider.server_port}/v1"
wire_api = "responses"
requires_openai_auth = false
supports_websockets = false
request_max_retries = 0
stream_max_retries = 0
'''
        )
        (state / "environments.toml").write_text(
            f'''default = "sandbox"
include_local = false

[[environments]]
id = "sandbox"
url = {json.dumps(url)}
connect_timeout_sec = 5
initialize_timeout_sec = 10
'''
        )
        result = subprocess.run(
            [
                binary,
                "exec",
                "--skip-git-repo-check",
                "--ephemeral",
                "--ignore-rules",
                "--json",
                "--color",
                "never",
                "--cd",
                str(rw),
                "Run the supplied fixture command in the sandbox environment and report completion.",
            ],
            cwd=rw,
            env=child_env,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=90,
            check=False,
        )
        diagnostic = result.stdout + "\n" + result.stderr
        assert result.returncode == 0, diagnostic
        assert not fixture_errors, (fixture_errors, diagnostic)
        assert len(requests) == 4, diagnostic

        def tool_output(index: int, kind: str, call_id: str):
            outputs = [
                item
                for item in requests[index].get("input", [])
                if item.get("type") == kind and item.get("call_id") == call_id
            ]
            assert len(outputs) == 1, (requests[index], diagnostic)
            return outputs[0]["output"]

        execution = json.dumps(tool_output(1, "function_call_output", "sandbox-command"))
        assert "system=Linux" in execution, execution
        assert "readonly=live readonly fixture" in execution, execution
        assert "stderr from sandbox" in execution, execution
        assert "readonly write denied" in execution, execution
        assert "READONLY_BYPASSED" not in execution, execution
        assert (rw / "codex-result.txt").read_text() == "created through Codex in a sandbox\n"

        writable = json.dumps(tool_output(2, "custom_tool_call_output", "sandbox-patch-rw"))
        readonly = json.dumps(tool_output(3, "custom_tool_call_output", "sandbox-patch-ro"))
        assert "Success" in writable, writable
        assert any(word in readonly.lower() for word in ["failed", "denied", "read-only", "eacces", "erofs"]), readonly
        assert (rw / "codex-patch.txt").read_text() == "created by remote apply_patch\n"
        assert (ro / "input.txt").read_text() == "live readonly fixture\n"
        assert sorted(path.name for path in ro.iterdir()) == ["input.txt"]
        assert "Verified the sandbox execution fixture" in result.stdout, diagnostic
    finally:
        provider.shutdown()
        provider.server_close()
        provider_thread.join(timeout=5)
        shutil.rmtree(rw)
        shutil.rmtree(ro)


@pytest.mark.integration
async def test_real_codex_shell_shortcut_fails_without_local_environment(tmp_path: Path):
    """Exercise the actual App Server route used by !command, without a turn.

    The command is a side-effect-free sentinel. It must never run: the request
    must fail while selecting a local environment, before launching a shell.
    """
    url = os.environ.get("SANDBOX_EXEC_SERVER_URL")
    rw_setting = os.environ.get("SANDBOX_TEST_RW")
    if not (url and rw_setting):
        pytest.skip("Set SANDBOX_EXEC_SERVER_URL and SANDBOX_TEST_RW")
    parsed = urlsplit(url)
    assert parsed.scheme == "ws" and parsed.hostname in {"localhost", "127.0.0.1"}
    assert parsed.path == "/codex" and not parsed.username and not parsed.password
    project = Path(rw_setting).resolve()
    assert project.is_dir()

    state = tmp_path / "codex-state"
    state.mkdir()
    child_env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "CODEX_HOME": str(state),
        "CODEX_SQLITE_HOME": str(state),
        "TERM": "dumb",
    }
    binary = os.environ.get("CODEX_CLI_BIN", "codex")
    try:
        version = subprocess.run(
            [binary, "--version"], cwd=tmp_path, env=child_env,
            capture_output=True, text=True, timeout=10, check=True,
        ).stdout.strip()
    except FileNotFoundError:
        pytest.skip("Install Codex CLI 0.164.0 or set CODEX_CLI_BIN")
    assert version == "codex-cli 0.164.0", "The experimental App Server behavior is pinned"

    provider_requests = []

    class NoInference(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_POST(self):
            provider_requests.append((self.command, self.path))
            self.send_error(500, "This test must not request inference")

        do_GET = do_POST

    provider = ThreadingHTTPServer(("127.0.0.1", 0), NoInference)
    provider_thread = threading.Thread(target=provider.serve_forever, daemon=True)
    provider_thread.start()
    (state / "config.toml").write_text(
        f'''model = "gpt-5.5"
model_provider = "no_inference"
approval_policy = "never"
sandbox_mode = "danger-full-access"
check_for_update_on_startup = false

[features]
unified_exec = true
shell_snapshot = false
unified_exec_tty = false

[analytics]
enabled = false

[feedback]
enabled = false

[model_providers.no_inference]
name = "No inference permitted"
base_url = "http://127.0.0.1:{provider.server_port}/v1"
wire_api = "responses"
requires_openai_auth = false
supports_websockets = false
request_max_retries = 0
stream_max_retries = 0
'''
    )
    (state / "environments.toml").write_text(
        f'''default = "sandbox"
include_local = false

[[environments]]
id = "sandbox"
url = {json.dumps(url)}
connect_timeout_sec = 5
initialize_timeout_sec = 10
'''
    )
    child = None
    stderr_task = None
    messages = []
    try:
        child = await asyncio.create_subprocess_exec(
            binary, "app-server", "--listen", "stdio://",
            cwd=project, env=child_env,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stderr_task = asyncio.create_task(child.stderr.read())

        async def send(value):
            child.stdin.write(json.dumps(value).encode() + b"\n")
            await child.stdin.drain()

        async def rpc(identifier, method, params):
            await send({"id": identifier, "method": method, "params": params})
            async with asyncio.timeout(30):
                while True:
                    line = await child.stdout.readline()
                    assert line, f"App Server closed unexpectedly: {messages!r}"
                    value = json.loads(line)
                    messages.append(value)
                    if value.get("id") == identifier:
                        return value

        initialized = await rpc(1, "initialize", {
            "clientInfo": {"name": "sandbox_exec_fixture", "version": "0.1.0"},
            "capabilities": {"experimentalApi": True},
        })
        assert "result" in initialized, initialized
        await send({"method": "initialized"})
        started = await rpc(2, "thread/start", {
            "cwd": str(project),
            "approvalPolicy": "never",
            "sandbox": "danger-full-access",
            "ephemeral": True,
        })
        assert "result" in started, started
        thread_id = started["result"]["thread"]["id"]
        rejected = await rpc(3, "thread/shellCommand", {
            "threadId": thread_id,
            "command": "printf SANDBOX_EXEC_UNEXPECTED_SHELL_COMMAND",
            "timeoutMs": 1000,
        })
        assert "error" in rejected and "result" not in rejected, rejected
        assert "local environment is not configured" in rejected["error"]["message"], rejected
        assert not provider_requests, provider_requests
        assert all(message.get("method") != "item/started" for message in messages), messages
        assert "SANDBOX_EXEC_UNEXPECTED_SHELL_COMMAND" not in json.dumps(messages), messages
    finally:
        if child is not None:
            if child.stdin is not None:
                child.stdin.close()
            try:
                await asyncio.wait_for(child.wait(), 5)
            except TimeoutError:
                child.kill()
                await child.wait()
        stderr = await stderr_task if stderr_task is not None else b""
        provider.shutdown()
        provider.server_close()
        provider_thread.join(timeout=5)
        assert b"SANDBOX_EXEC_UNEXPECTED_SHELL_COMMAND" not in stderr, stderr.decode(errors="replace")
