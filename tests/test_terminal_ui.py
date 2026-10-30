"""Browser authorization and unchanged streaming execution contract."""

import asyncio
import base64
import re
from html.parser import HTMLParser
from importlib.resources import files

import pytest
from aiohttp import WSServerHandshakeError, WSMsgType
from aiohttp.test_utils import TestClient, TestServer

from external_sandbox_quicksand.api import create_app
from test_api import EXIT, FakeBackend, receive


async def terminal_token(client):
    response = await client.get("/")
    assert response.status == 200
    html = await response.text()
    match = re.search(r'<meta name="terminal-token" content="([^"]+)"', html)
    assert match, "The page must expose its instance token to its own JavaScript"
    return match[1], html, response


def browser_headers(client):
    return {"Origin": str(client.make_url("/")).rstrip("/"), "Sec-Fetch-Site": "same-origin"}


def browser_protocols(token):
    return ("sandbox-terminal", "sandbox-token." + token)


@pytest.fixture
async def terminal_server():
    backend = FakeBackend()
    async with TestClient(TestServer(create_app(backend))) as client:
        token, _, _ = await terminal_token(client)
        yield client, backend, token


async def test_homepage_and_bundled_javascript(terminal_server):
    client, backend, _ = terminal_server
    token, html, page = await terminal_token(client)
    assert len(token) >= 32
    assert "/terminal.js" in html
    assert "<title>External sandbox terminal</title>" in html
    assert '<div class="eyebrow">External sandbox Quicksand</div>' in html
    assert "__TITLE__" not in html and "__BRAND__" not in html
    assert page.content_type == "text/html"
    assert page.headers["Cache-Control"] == "no-store"
    assert "frame-ancestors 'none'" in page.headers["Content-Security-Policy"]
    assert page.headers["X-Content-Type-Options"] == "nosniff"
    assert page.headers["Referrer-Policy"] == "no-referrer"
    script = await client.get("/terminal.js", headers=browser_headers(client))
    assert script.status == 200
    assert script.content_type in {"application/javascript", "text/javascript"}
    assert script.headers["Cache-Control"] == "no-store"
    assert token not in await script.text()
    assert await script.read() == files("external_sandbox_quicksand").joinpath("ui", "assets", "terminal.js").read_bytes()
    assert "Access-Control-Allow-Origin" not in script.headers
    assert not backend.calls


async def test_browser_streams_both_outputs_and_reports_exit(terminal_server):
    client, backend, token = terminal_server
    backend.process.events.put_nowait({"type": "stdout", "data": base64.b64encode(b"hello \xe2\x98\x83\n").decode()})
    backend.process.events.put_nowait({"type": "stderr", "data": base64.b64encode(b"warning\n").decode()})
    backend.process.events.put_nowait(EXIT.copy())
    ws = await client.ws_connect("/exec/ws", headers=browser_headers(client), protocols=browser_protocols(token))
    assert ws.protocol == "sandbox-terminal"
    assert ws._response.headers["Sec-WebSocket-Protocol"] == "sandbox-terminal"
    assert token not in str(ws._response.headers)
    await ws.send_json({"type": "start", "command": "printf hello; exit 17", "cwd": "/workspace", "stdin": True})
    assert await receive(ws, "started") == {"type": "started", "processId": "process-1"}
    assert base64.b64decode((await receive(ws, "stdout"))["data"]) == b"hello \xe2\x98\x83\n"
    assert base64.b64decode((await receive(ws, "stderr"))["data"]) == b"warning\n"
    assert await receive(ws, "exit") == EXIT
    assert (await ws.receive()).type == WSMsgType.CLOSE
    assert ws.close_code == 1000
    assert backend.calls[0][0] == ["/bin/bash", "-c", "printf hello; exit 17"]
    assert backend.calls[0][1]["cwd"] == "/workspace"


async def test_browser_interactive_stdin_acknowledgement_and_eof(terminal_server):
    client, backend, token = terminal_server
    backend.process.finish_on_eof = True
    ws = await client.ws_connect("/exec/ws", headers=browser_headers(client), protocols=browser_protocols(token))
    await ws.send_json({"type": "start", "command": "cat", "stdin": True})
    await receive(ws, "started")
    payload = "typed from the browser: snowman ☃\n".encode()
    await ws.send_json({"type": "stdin", "id": 0, "data": base64.b64encode(payload).decode()})
    assert await receive(ws, "stdin_ack") == {"type": "stdin_ack", "id": 0}
    await ws.send_json({"type": "stdin_eof"})
    assert await receive(ws, "stdin_closed") == {"type": "stdin_closed"}
    assert await receive(ws, "exit") == EXIT
    assert backend.process.inputs == [payload, "eof"]
    await ws.close()


@pytest.mark.parametrize("cancel_via_message", [True, False])
async def test_browser_cancel_and_page_disconnect_terminate_command(terminal_server, cancel_via_message):
    client, backend, token = terminal_server
    ws = await client.ws_connect("/exec/ws", headers=browser_headers(client), protocols=browser_protocols(token))
    await ws.send_json({"type": "start", "command": "sleep 60", "stdin": True})
    await receive(ws, "started")
    if cancel_via_message:
        await ws.send_json({"type": "cancel"})
        result = await receive(ws, "exit")
        assert result["signal"] == 15
    else:
        await ws.close()
    await asyncio.wait_for(backend.process.terminated.wait(), 3)
    await ws.close()


@pytest.mark.parametrize("offered", [
    (), ("sandbox-terminal",), ("sandbox-token.{token}",),
    ("sandbox-terminal", "sandbox-token.wrong"),
    ("sandbox-terminal", "sandbox-token.{token}", "unexpected"),
    ("sandbox-terminal", "sandbox-terminal", "sandbox-token.{token}"),
    ("sandbox-terminal", "sandbox-token.{token}", "sandbox-token.{token}"),
])
async def test_browser_socket_rejects_missing_wrong_or_ambiguous_token(terminal_server, offered):
    client, backend, token = terminal_server
    protocols = tuple(item.format(token=token) for item in offered)
    with pytest.raises(WSServerHandshakeError) as caught:
        await client.ws_connect("/exec/ws", headers=browser_headers(client), protocols=protocols)
    assert caught.value.status == 403
    assert not backend.calls


@pytest.mark.parametrize("origin", ["https://evil.example", "null", "http://127.0.0.1:1", "http://localhost:1"])
async def test_browser_socket_rejects_foreign_null_and_wrong_port_origins(terminal_server, origin):
    client, backend, token = terminal_server
    with pytest.raises(WSServerHandshakeError) as caught:
        await client.ws_connect("/exec/ws", headers={"Origin": origin}, protocols=browser_protocols(token))
    assert caught.value.status == 403
    assert not backend.calls


@pytest.mark.parametrize("site", ["cross-site", "same-site"])
async def test_cross_origin_fetch_metadata_is_denied_even_with_correct_token(terminal_server, site):
    client, backend, token = terminal_server
    with pytest.raises(WSServerHandshakeError) as caught:
        await client.ws_connect("/exec/ws", headers={**browser_headers(client), "Sec-Fetch-Site": site}, protocols=browser_protocols(token))
    assert caught.value.status == 403
    assert not backend.calls


async def test_browser_metadata_cannot_bypass_token_checks_by_omitting_origin(terminal_server):
    client, backend, token = terminal_server
    with pytest.raises(WSServerHandshakeError) as caught:
        await client.ws_connect("/exec/ws", headers={"Sec-Fetch-Site": "same-origin"}, protocols=browser_protocols(token))
    assert caught.value.status == 403
    assert not backend.calls


@pytest.mark.parametrize("cwd", [
    '/workspace" autofocus onfocus="alert(document.domain)',
    '/workspace/__NONCE__/__TOKEN__/__TITLE__/__BRAND__/__CWD__/__NETWORK__/__PROXY_LINK__',
])
async def test_homepage_escapes_untrusted_working_directory(cwd):
    class Inputs(HTMLParser):
        def __init__(self):
            super().__init__()
            self.fields = []

        def handle_starttag(self, tag, attrs):
            if tag == "input":
                self.fields.append(dict(attrs))

    backend = FakeBackend()
    backend.info = lambda: {"defaultCwd": cwd}
    async with TestClient(TestServer(create_app(backend))) as client:
        _, html, _ = await terminal_token(client)
        parser = Inputs()
        parser.feed(html)
        field = next(item for item in parser.fields if item.get("id") == "cwd")
        assert field["value"] == cwd
        assert "autofocus" not in field and "onfocus" not in field


async def test_duplicate_origin_and_subprotocol_headers_are_denied(terminal_server):
    client, backend, token = terminal_server
    origin = browser_headers(client)["Origin"]
    protocols = ", ".join(browser_protocols(token))
    cases = [
        [("Origin", origin), ("Origin", origin), ("Sec-WebSocket-Protocol", protocols)],
        [("Origin", origin), ("Sec-WebSocket-Protocol", protocols), ("Sec-WebSocket-Protocol", protocols)],
    ]
    for headers in cases:
        with pytest.raises(WSServerHandshakeError) as caught:
            await client.ws_connect("/exec/ws", headers=headers)
        assert caught.value.status == 403
    assert not backend.calls


@pytest.mark.parametrize("path", ["/", "/terminal.js"])
@pytest.mark.parametrize("extra", [
    {"Origin": "https://evil.example"}, {"Origin": "null"},
    {"Host": "rebind.evil.example"}, {"Sec-Fetch-Site": "cross-site"},
])
async def test_terminal_assets_reject_cross_origin_and_rebinding_access(terminal_server, path, extra):
    client, backend, _ = terminal_server
    response = await client.get(path, headers=extra)
    assert response.status == 403
    assert "Access-Control-Allow-Origin" not in response.headers
    assert not backend.calls


async def test_legacy_originless_websocket_still_executes_without_token(terminal_server):
    client, backend, _ = terminal_server
    backend.process.events.put_nowait(EXIT.copy())
    ws = await client.ws_connect("/exec/ws")
    assert ws.protocol is None
    await ws.send_json({"type": "start", "command": "true", "stdin": False})
    await receive(ws, "started")
    assert await receive(ws, "exit") == EXIT
    assert len(backend.calls) == 1
    await ws.close()


async def test_terminal_token_does_not_authorize_other_browser_apis(terminal_server):
    client, backend, token = terminal_server
    headers = {**browser_headers(client), "Sec-WebSocket-Protocol": ", ".join(browser_protocols(token))}
    for path in ["/health", "/mounts", "/codex", "/exec/ws/extra"]:
        assert (await client.get(path, headers=headers)).status == 403
    assert (await client.post("/exec", headers=headers, json={"command": "true"})).status == 403
    assert not backend.calls


async def test_terminal_token_cannot_be_reused_for_another_server(terminal_server):
    _, _, token = terminal_server
    backend = FakeBackend()
    async with TestClient(TestServer(create_app(backend))) as client:
        fresh, _, _ = await terminal_token(client)
        assert fresh != token
        with pytest.raises(WSServerHandshakeError) as caught:
            await client.ws_connect("/exec/ws", headers=browser_headers(client), protocols=browser_protocols(token))
        assert caught.value.status == 403
        assert not backend.calls
