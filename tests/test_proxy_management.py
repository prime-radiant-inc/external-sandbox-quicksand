import copy
import json
import re

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from external_sandbox_quicksand.proxy_management import install_proxy_management


POLICY = {"allow": [{"origin": "https://api.example.test", "methods": ["GET"],
                    "credential": {"header": "Authorization", "placeholder": "Bearer demo-token",
                                   "prefix": "Bearer ", "secretEnv": "EXAMPLE_API_KEY"}}],
          "guestEnv": {"EXAMPLE_API_KEY": "demo-token"}}


class FakeProxy:
    def __init__(self):
        self.policy = copy.deepcopy(POLICY)
        self.events = []
        self.private_secret = "host-secret-never-in-the-management-ui"
        self.updates = []

    def snapshot(self):
        return {"enabled": True, "policy": copy.deepcopy(self.policy), "events": copy.deepcopy(self.events)}

    def update_policy(self, config):
        self.updates.append(config)
        if set(config) - {"allow", "guestEnv"} or not isinstance(config.get("allow"), list):
            # The API must not leak even an unsafe upstream validation message.
            raise ValueError(self.private_secret)
        self.policy = copy.deepcopy(config)


async def page_token(client):
    response = await client.get("/proxy")
    assert response.status == 200
    html = await response.text()
    return re.search(r'<meta name="proxy-token" content="([^"]+)"', html)[1], html, response


@pytest.fixture
async def server():
    proxy = FakeProxy()
    app = web.Application()
    install_proxy_management(app, proxy)
    async with TestClient(TestServer(app)) as client:
        token, _, _ = await page_token(client)
        yield client, proxy, {"X-Proxy-Token": token}


async def test_management_page_and_safe_snapshot(server):
    client, proxy, headers = server
    token, html, page = await page_token(client)
    assert token == headers["X-Proxy-Token"]
    assert "Runtime only" in html
    assert "secretEnv" in html
    assert "textContent" in html
    assert "innerHTML" not in html
    assert "insertAdjacentHTML" not in html
    assert "http://" not in html and "https://" not in html
    assert "frame-ancestors 'none'" in page.headers["Content-Security-Policy"]
    assert page.headers["Referrer-Policy"] == "no-referrer"
    assert page.headers["X-Frame-Options"] == "DENY"
    nonce = re.search(r'<script nonce="([^"]+)"', html)[1]
    assert f"script-src 'nonce-{nonce}'" in page.headers["Content-Security-Policy"]
    response = await client.get("/proxy/api", headers=headers)
    assert response.status == 200
    assert await response.json() == proxy.snapshot()
    assert "Access-Control-Allow-Origin" not in response.headers
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert proxy.private_secret not in html + await response.text()
    # The page only embeds its token, never dynamic policy/event data.
    assert "api.example.test" not in html


@pytest.mark.parametrize("method", ["GET", "PUT"])
@pytest.mark.parametrize("token", [None, "wrong-token"])
async def test_json_requires_token(server, method, token):
    client, proxy, _ = server
    headers = {"X-Proxy-Token": token} if token else {}
    response = await client.request(method, "/proxy/api", headers=headers, json={"allow": []})
    assert response.status == 403
    assert not proxy.updates


@pytest.mark.parametrize("path", ["/proxy", "/proxy/api"])
@pytest.mark.parametrize("extra", [
    {"Origin": "https://evil.example"}, {"Origin": "null"}, {"Origin": "http://localhost"},
    {"Host": "rebinding.evil.test"}, {"Host": "127.0.0.1:0"}, {"Host": "127.0.0.1:65536"},
    {"Sec-Fetch-Site": "cross-site"}, {"Sec-Fetch-Site": "same-site"},
])
async def test_cross_origin_and_rebinding_requests_are_denied(server, path, extra):
    client, _, headers = server
    response = await client.get(path, headers={**headers, **extra})
    assert response.status == 403
    assert "Access-Control-Allow-Origin" not in response.headers


async def test_same_origin_policy_change_and_validation_are_atomic(server):
    client, proxy, headers = server
    headers = {**headers, "Origin": str(client.make_url("/")).rstrip("/"), "Sec-Fetch-Site": "same-origin"}
    changed = {"allow": [{"origin": "https://packages.example.test", "methods": ["GET"]}]}
    response = await client.put("/proxy/api", headers=headers, json=changed)
    assert response.status == 200
    assert (await response.json())["policy"] == changed
    assert proxy.policy == changed
    rejected = await client.put("/proxy/api", headers=headers, json={"allow": "invalid"})
    assert rejected.status == 400
    assert "unchanged" in (await rejected.json())["error"]
    assert proxy.private_secret not in await rejected.text()
    assert proxy.policy == changed
    current = await client.get("/proxy/api", headers=headers)
    assert (await current.json())["policy"] == changed


async def test_cross_origin_mutation_is_rejected_before_update(server):
    client, proxy, headers = server
    response = await client.put("/proxy/api", headers={**headers, "Origin": "https://evil.example"}, json={"allow": []})
    assert response.status == 403
    assert proxy.policy == POLICY and not proxy.updates
    preflight = await client.options("/proxy/api", headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "PUT"})
    assert preflight.status == 405
    assert "Access-Control-Allow-Origin" not in preflight.headers


@pytest.mark.parametrize("body", [b"not JSON", b"[]", b"null", b'"string"', b"{\"allow\":NaN}", b"\xff"])
async def test_invalid_json_never_reaches_proxy(server, body):
    client, proxy, headers = server
    response = await client.put("/proxy/api", headers={**headers, "Content-Type": "application/json"}, data=body)
    assert response.status == 400
    assert not proxy.updates


async def test_policy_content_type_encoding_and_size_limits(server):
    client, proxy, headers = server
    response = await client.put("/proxy/api", headers=headers, data="{}")
    assert response.status == 415
    response = await client.put("/proxy/api", headers={**headers, "Content-Type": "application/json", "Content-Encoding": "br"}, data=b"{}")
    assert response.status in {400, 415}  # aiohttp can reject unsupported encoding before dispatch.
    response = await client.put("/proxy/api", headers={**headers, "Content-Type": "application/json"}, data=b" " * (256 * 1024 + 1))
    assert response.status == 413
    assert not proxy.updates


async def test_untrusted_activity_is_data_not_html(server):
    client, proxy, headers = server
    payload = '</script><img src=x onerror="alert(document.domain)">'
    proxy.events = [{"time": "2026-09-18T00:00:00Z", "origin": payload, "method": "GET", "result": "denied", "reason": payload}]
    response = await client.get("/proxy/api", headers=headers)
    assert response.content_type == "application/json"
    assert (await response.json())["events"][0]["reason"] == payload
    _, html, _ = await page_token(client)
    assert payload not in html
    assert "element.textContent = text" in html
    assert "rows.append(row)" in html
    assert proxy.private_secret not in json.dumps(await response.json())


async def test_management_tokens_differ_between_server_instances(server):
    _, _, headers = server
    other = web.Application()
    install_proxy_management(other, FakeProxy())
    async with TestClient(TestServer(other)) as client:
        token, _, _ = await page_token(client)
        assert token != headers["X-Proxy-Token"]
        response = await client.get("/proxy/api", headers=headers)
        assert response.status == 403


async def test_duplicate_token_or_origin_is_rejected(server):
    client, _, headers = server
    token = headers["X-Proxy-Token"]
    origin = str(client.make_url("/")).rstrip("/")
    response = await client.get("/proxy/api", headers=[("X-Proxy-Token", token), ("X-Proxy-Token", token)])
    assert response.status == 403
    response = await client.get("/proxy/api", headers=[("X-Proxy-Token", token), ("Origin", origin), ("Origin", origin)])
    assert response.status == 403


async def test_management_integrates_without_relaxing_other_browser_apis():
    from external_sandbox_quicksand.api import create_app

    proxy = FakeProxy()
    # No execution operations should be reached by any of these browser calls.
    async with TestClient(TestServer(create_app(object(), proxy=proxy))) as client:
        token, _, _ = await page_token(client)
        origin = str(client.make_url("/")).rstrip("/")
        headers = {"X-Proxy-Token": token, "Origin": origin, "Sec-Fetch-Site": "same-origin"}
        assert (await client.get("/proxy/api", headers=headers)).status == 200
        assert (await client.put("/proxy/api", headers=headers, json={"allow": []})).status == 200
        for path in ["/health", "/mounts", "/exec/ws", "/codex", "/proxy/api/extra"]:
            assert (await client.get(path, headers=headers)).status == 403
        assert (await client.post("/exec", headers=headers, json={"command": "true"})).status == 403
