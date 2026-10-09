import asyncio
import contextlib
import json
import socket
import ssl

import aiohttp
import pytest
from aiohttp import web

from remote_sandbox_quicksand.proxy import HostProxy, LiteralRedactor
from remote_sandbox_quicksand.proxy_certificates import CertificateAuthority
from remote_sandbox_quicksand.proxy_policy import PolicyConfigError, ProxyPolicy


SECRET = "synthetic-host-secret-that-never-enters-the-guest"
TOKEN = "Bearer harmless-placeholder"


@contextlib.asynccontextmanager
async def upstream(handler, *, tls=False, certificate_host="upstream.example.test"):
    app = web.Application()
    app.router.add_route("*", "/{tail:.*}", handler)
    runner = web.AppRunner(app, access_log=None)
    await runner.setup()
    ca = CertificateAuthority() if tls else None
    context = ca.server_context(certificate_host) if ca else None
    site = web.TCPSite(runner, "127.0.0.1", 0, ssl_context=context)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    try:
        yield port, ca
    finally:
        await runner.cleanup()


@contextlib.asynccontextmanager
async def proxy_for(port, *, tls=False, ca=None, credential=False, rule_options=None):
    origin = f"{'https' if tls else 'http'}://{'upstream.example.test' if tls else '127.0.0.1'}:{port}"
    rule = {"origin": origin, "allowCidrs": ["127.0.0.0/8"], **(rule_options or {})}
    if credential:
        rule["credential"] = {"header": "Authorization", "placeholder": TOKEN,
                              "secretEnv": "DEMO_KEY", "prefix": "Bearer "}
    policy = ProxyPolicy.from_config({"allow": [rule], "guestEnv": {"DEMO_KEY": "harmless-placeholder"}},
                                    {"DEMO_KEY": SECRET})
    context = ssl.create_default_context(cadata=ca.pem) if ca else None
    proxy = HostProxy(policy, upstream_ssl_context=context)
    await proxy.start()
    try:
        yield proxy, origin
    finally:
        await proxy.close()


@pytest.fixture
async def local_dns(monkeypatch):
    loop = asyncio.get_running_loop()
    actual = loop.getaddrinfo
    calls = []

    async def resolve(host, port, **kwargs):
        if host == "upstream.example.test":
            calls.append(host)
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))]
        return await actual(host, port, **kwargs)

    monkeypatch.setattr(loop, "getaddrinfo", resolve)
    return calls


def proxy_url(proxy):
    return "http://%s:%d" % proxy.address


async def raw(proxy, request, *, tls_host=None):
    reader, writer = await asyncio.open_connection(*proxy.address)
    try:
        if tls_host:
            writer.write(f"CONNECT {tls_host} HTTP/1.1\r\nHost: {tls_host}\r\n\r\n".encode())
            await writer.drain()
            reply = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 3)
            assert reply.startswith(b"HTTP/1.1 200"), reply
            context = ssl.create_default_context(cadata=proxy.ca_pem)
            await writer.start_tls(context, server_hostname=tls_host.split(":")[0])
        writer.write(request)
        await writer.drain()
        return await asyncio.wait_for(reader.read(), 5)
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()


def test_literal_redactor_chunk_boundaries_and_sse():
    for width in range(1, len(SECRET) + 3):
        source = ("prefix " + SECRET + " middle " + SECRET + " end").encode()
        redactor = LiteralRedactor((SECRET,))
        result = b"".join(redactor.feed(source[index:index + width]) for index in range(0, len(source), width))
        result += redactor.feed(b"", final=True)
        assert result == b"prefix [REDACTED] middle [REDACTED] end"
    redactor = LiteralRedactor((SECRET,))
    assert redactor.feed(b"data: first\n\n") == b"data: first\n\n"
    assert redactor.feed(SECRET[:12].encode()) == b""
    assert redactor.feed(SECRET[12:].encode() + b"\n\n") == b"[REDACTED]\n\n"
    # A suffix that is also a prefix must not split an already-complete secret.
    redactor = LiteralRedactor(("ababa", "another"))
    assert redactor.feed(b"ababa") + redactor.feed(b"", final=True) == b"[REDACTED]"


def test_activity_redacts_long_secrets_before_truncation():
    import time

    secret = "synthetic-private-" + "s" * 3000
    policy = ProxyPolicy.from_config({"allow": [{
        "origin": "https://example.test", "credential": {
            "header": "Authorization", "placeholder": "public-token", "secretEnv": "LONG_KEY",
        },
    }]}, {"LONG_KEY": secret})
    proxy = HostProxy(policy)
    proxy._event(policy, time.monotonic(), "GET", "https://example.test/" + secret,
                 403, "denied", "policy_denied")
    assert proxy.snapshot()["events"][-1]["path"] == "/[REDACTED]"


async def test_http_binary_request_redirect_and_hop_header_filtering():
    received = []

    async def handler(request):
        received.append((request.path, dict(request.headers), await request.read()))
        if request.path == "/redirect":
            raise web.HTTPFound("http://not-allowed.invalid/target")
        return web.Response(body=received[-1][2], headers={"X-Reply": "works"})

    async with upstream(handler) as (port, _), proxy_for(port) as (proxy, origin):
        async with aiohttp.ClientSession() as client:
            payload = bytes(range(256)) * 1024
            async with client.post(origin + "/binary", data=payload, proxy=proxy_url(proxy),
                                   headers={"Proxy-Authorization": "should-not-forward",
                                            "Connection": "X-Hop", "X-Hop": "secret-hop"}) as response:
                assert response.status == 200
                assert await response.read() == payload
            async with client.get(origin + "/redirect", proxy=proxy_url(proxy), allow_redirects=False) as response:
                assert response.status == 302
                assert response.headers["Location"] == "http://not-allowed.invalid/target"
                await response.read()
        assert len(received) == 2
        assert "Proxy-Authorization" not in received[0][1]
        assert "X-Hop" not in received[0][1]
        assert received[0][1]["Accept-Encoding"] == "identity"


async def test_https_injection_redacts_headers_chunks_and_query_free_events(local_dns):
    received = []

    async def handler(request):
        received.append((dict(request.headers), await request.read()))
        response = web.StreamResponse(headers={"X-Echo": SECRET, "Content-Type": "text/event-stream"})
        await response.prepare(request)
        await response.write(b"data: first\n\n")
        await asyncio.sleep(0.05)
        for part in (SECRET[:10], SECRET[10:25], SECRET[25:]):
            await response.write(part.encode())
            await asyncio.sleep(0.01)
        await response.write(b"\n\n")
        return response

    async with upstream(handler, tls=True) as (port, ca), proxy_for(port, tls=True, ca=ca, credential=True) as (proxy, origin):
        trust = ssl.create_default_context(cadata=proxy.ca_pem)
        async with aiohttp.ClientSession() as client:
            async with client.post(origin + "/events?do-not-log=this-value", data=b"input\x00data",
                                   headers={"Authorization": TOKEN}, proxy=proxy_url(proxy), ssl=trust) as response:
                assert response.status == 200
                assert response.headers["X-Echo"] == "[REDACTED]"
                assert await asyncio.wait_for(response.content.readexactly(13), 0.2) == b"data: first\n\n"
                assert await response.read() == b"[REDACTED]\n\n"
        await asyncio.sleep(0)
        assert received[0][0]["Authorization"] == "Bearer " + SECRET
        assert received[0][1] == b"input\x00data"
        assert local_dns == ["upstream.example.test"]  # aiohttp never resolves again.
        snapshot = proxy.snapshot()
        assert snapshot["events"][-1]["credentialInjected"]
        assert snapshot["events"][-1]["path"] == "/events"
        rendered = json.dumps(snapshot)
        assert SECRET not in rendered and "do-not-log" not in rendered and "this-value" not in rendered


async def test_denied_origin_method_path_placeholder_and_host_never_contact_upstream(local_dns):
    received = []

    async def handler(request):
        received.append(request.path)
        return web.Response(text="unexpected")

    async with upstream(handler, tls=True) as (port, ca), proxy_for(
        port, tls=True, ca=ca, credential=True, rule_options={"methods": ["POST"], "paths": ["/allowed"]}
    ) as (proxy, origin):
        trust = ssl.create_default_context(cadata=proxy.ca_pem)
        async with aiohttp.ClientSession() as client:
            for method, path, token in [("GET", "/allowed", TOKEN), ("POST", "/wrong", TOKEN),
                                        ("POST", "/allowed", "Bearer wrong"), ("POST", "/allowed", "")]:
                async with client.request(method, origin + path, proxy=proxy_url(proxy), ssl=trust,
                                          headers={"Authorization": token}) as response:
                    assert response.status == 403
                    assert SECRET not in await response.text()
            with pytest.raises(aiohttp.ClientHttpProxyError) as error:
                await client.get("https://not-allowed.invalid/", proxy=proxy_url(proxy), ssl=trust)
            assert error.value.status == 403
        for target, host in [("/allowed", "different.example.test"),
                             ("https://different.example.test/allowed", f"upstream.example.test:{port}")]:
            request = (f"POST {target} HTTP/1.1\r\nHost: {host}\r\nAuthorization: {TOKEN}\r\n"
                       "Content-Length: 0\r\n\r\n").encode()
            reply = await raw(proxy, request, tls_host=f"upstream.example.test:{port}")
            assert reply.startswith(b"HTTP/1.1 403"), reply
        assert received == []
        assert local_dns == []


async def test_upstream_certificate_verification_cannot_be_disabled(local_dns):
    received = []

    async def handler(request):
        received.append(request.path)
        return web.Response(text="unexpected")

    async with upstream(handler, tls=True) as (port, _), proxy_for(port, tls=True) as (proxy, origin):
        async with aiohttp.ClientSession() as client:
            async with client.get(origin + "/", proxy=proxy_url(proxy),
                                  ssl=ssl.create_default_context(cadata=proxy.ca_pem)) as response:
                assert response.status == 502
                assert await response.text() == "502 Bad Gateway\n"
        assert received == []
    context = ssl._create_unverified_context()
    with pytest.raises(ValueError, match="verification"):
        HostProxy(ProxyPolicy.from_config({"allow": []}), upstream_ssl_context=context)


async def test_upstream_checks_original_hostname_even_after_numeric_ip_pinning(local_dns):
    received = []

    async def handler(request):
        received.append(request.path)
        return web.Response(text="unexpected")

    async with upstream(handler, tls=True, certificate_host="wrong.example.test") as (port, ca):
        async with proxy_for(port, tls=True, ca=ca) as (proxy, origin):
            async with aiohttp.ClientSession() as client:
                async with client.get(origin, proxy=proxy_url(proxy),
                                      ssl=ssl.create_default_context(cadata=proxy.ca_pem)) as response:
                    assert response.status == 502
                    await response.read()
            assert received == []


async def test_framing_conflicts_duplicate_credentials_and_transport_header_credentials(local_dns):
    received = []

    async def handler(request):
        received.append(request.path)
        return web.Response(text="unexpected")

    async with upstream(handler, tls=True) as (port, ca), proxy_for(port, tls=True, ca=ca, credential=True) as (proxy, origin):
        authority = f"upstream.example.test:{port}"
        variants = [
            f"Authorization: {TOKEN}\r\nauthorization: {TOKEN}\r\nContent-Length: 0\r\n",
            f"Authorization: {TOKEN}\r\nConnection: authorization\r\nContent-Length: 0\r\n",
            f"Authorization: {TOKEN}\r\nContent-Length: 0\r\nContent-Length: 1\r\n",
        ]
        for extra in variants:
            request = f"POST / HTTP/1.1\r\nHost: {authority}\r\n{extra}\r\n".encode()
            response = await raw(proxy, request, tls_host=authority)
            assert response.split(b" ")[1] in (b"400", b"403")
            assert SECRET.encode() not in response
        assert received == []


async def test_response_limit_and_request_idle_timeout(monkeypatch):
    import remote_sandbox_quicksand.proxy as engine

    async def handler(request):
        return web.Response(body=b"x" * 1025)

    monkeypatch.setattr(engine, "MAX_RESPONSE", 1024)
    monkeypatch.setattr(engine, "IDLE_TIMEOUT", 0.05)
    async with upstream(handler) as (port, _), proxy_for(port) as (proxy, origin):
        async with aiohttp.ClientSession() as client:
            async with client.get(origin, proxy=proxy_url(proxy)) as response:
                assert response.status == 502
                assert b"x" * 1025 not in await response.read()
        reader, writer = await asyncio.open_connection(*proxy.address)
        writer.write(f"POST {origin}/ HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Length: 1\r\n\r\n".encode())
        await writer.drain()
        assert (await asyncio.wait_for(reader.read(), 2)).startswith(b"HTTP/1.1 504")
        writer.close()
        await writer.wait_closed()
        assert proxy._buffered_request_bytes == 0


async def test_headers_and_aggregate_upload_memory_are_bounded(monkeypatch):
    import remote_sandbox_quicksand.proxy as engine

    received = []

    async def handler(request):
        received.append(request.path)
        return web.Response(text="unexpected")

    monkeypatch.setattr(engine, "MAX_BUFFERED_REQUESTS", 1024)
    async with upstream(handler) as (port, _), proxy_for(port) as (proxy, origin):
        request = (f"POST {origin}/ HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Length: 1025\r\n\r\n".encode()
                   + b"x" * 1025)
        assert (await raw(proxy, request)).startswith(b"HTTP/1.1 503")
        request = f"GET {origin}/ HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n".encode()
        request += b"".join(f"X-Header-{index}: present\r\n".encode() for index in range(101)) + b"\r\n"
        assert (await raw(proxy, request)).startswith(b"HTTP/1.1 431")
        assert received == []
        assert proxy._buffered_request_bytes == 0


async def test_dns_private_ip_denied_without_explicit_cidr(local_dns):
    received = []

    async def handler(request):
        received.append(request.path)
        return web.Response(text="unexpected")

    async with upstream(handler, tls=True) as (port, ca):
        origin = f"https://upstream.example.test:{port}"
        proxy = HostProxy(ProxyPolicy.from_config({"allow": [{"origin": origin}]}),
                          upstream_ssl_context=ssl.create_default_context(cadata=ca.pem))
        await proxy.start()
        try:
            async with aiohttp.ClientSession() as client:
                async with client.get(origin, proxy=proxy_url(proxy),
                                      ssl=ssl.create_default_context(cadata=proxy.ca_pem)) as response:
                    assert response.status == 403
                    await response.read()
            assert received == []
        finally:
            await proxy.close()


async def test_compression_is_denied_before_response_headers_escape():
    async def handler(request):
        return web.Response(body=b"compressed-secret", headers={"Content-Encoding": "gzip"})

    async with upstream(handler) as (port, _), proxy_for(port) as (proxy, origin):
        async with aiohttp.ClientSession() as client:
            async with client.get(origin, proxy=proxy_url(proxy)) as response:
                assert response.status == 502
                assert b"compressed-secret" not in await response.read()


async def test_malformed_requests_upgrades_and_oversized_bodies_never_reach_upstream():
    received = []

    async def handler(request):
        received.append(request.path)
        return web.Response(text="unexpected")

    async with upstream(handler) as (port, _), proxy_for(port) as (proxy, origin):
        for headers in [
            "Host: wrong.test\r\n", f"Host: 127.0.0.1:{port}\r\nUpgrade: websocket\r\n",
            f"Host: 127.0.0.1:{port}\r\nContent-Length: 16777217\r\n",
            f"Host: 127.0.0.1:{port}\r\nConnection: host\r\n",
        ]:
            reply = await raw(proxy, f"POST {origin}/ HTTP/1.1\r\n{headers}\r\n".encode())
            assert reply.split(b" ")[1] in (b"400", b"403", b"413")
        assert received == []


async def test_policy_updates_are_atomic_revoke_streams_and_require_stable_guest_env():
    release = asyncio.Event()

    async def handler(request):
        response = web.StreamResponse()
        await response.prepare(request)
        await response.write(b"first")
        await release.wait()
        return response

    async with upstream(handler) as (port, _), proxy_for(port) as (proxy, origin):
        before = proxy.snapshot()["policy"]
        with pytest.raises(PolicyConfigError):
            proxy.update_policy({"allow": [], "typo": True})
        assert proxy.snapshot()["policy"] == before
        with pytest.raises(PolicyConfigError, match="guestEnv"):
            proxy.update_policy({"allow": []})
        async with aiohttp.ClientSession() as client:
            response = await client.get(origin, proxy=proxy_url(proxy))
            assert await response.content.readexactly(5) == b"first"
            proxy.update_policy({"allow": [], "guestEnv": dict(proxy.guest_env)})
            with pytest.raises(aiohttp.ClientPayloadError):
                await asyncio.wait_for(response.read(), 3)
            async with client.get(origin, proxy=proxy_url(proxy)) as denied:
                assert denied.status == 403
                await denied.read()
        release.set()
        assert proxy.snapshot()["policy"]["allow"] == []
