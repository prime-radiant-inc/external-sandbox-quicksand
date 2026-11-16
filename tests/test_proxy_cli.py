"""Proxy opt-in, early validation, and lifecycle ownership."""
import asyncio
import re
import types

import aiohttp
import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from external_sandbox_quicksand import cli
from external_sandbox_quicksand.api import create_app
from external_sandbox_quicksand.images import GuestImage


@pytest.fixture(autouse=True)
def prepared_image(monkeypatch):
    async def resolve(name, packages, cache_dir, accel):
        return GuestImage("/cache/alpine-save", "alpine-test")

    monkeypatch.setattr(cli, "resolve_image", resolve)


def test_proxy_is_explicit_and_default_port_is_unchanged():
    args = cli.parser().parse_args([])
    assert args.proxy is False and args.proxy_config is None and args.port == 8688
    assert args.image == "alpine" and args.packages is None and args.accel == "auto"
    args = cli.parser().parse_args(["--proxy-config", "policy.local.json", "--port", "0"])
    assert args.proxy_config == "policy.local.json" and args.port == 0
    args = cli.parser().parse_args(["--proxy"])
    assert args.proxy is True and args.proxy_config is None


def test_startup_proxy_is_absent_deny_all_or_from_the_policy_file(monkeypatch):
    loaded = []
    monkeypatch.setattr(cli, "load_policy", lambda path: loaded.append(path) or cli.ProxyPolicy.from_config(
        {"allow": [{"origin": "https://api.example.test"}]}, {}))
    parse = cli.parser().parse_args
    assert cli.startup_proxy(parse([])) is None
    deny_all = cli.startup_proxy(parse(["--proxy"]))
    assert deny_all.snapshot()["policy"] == {"allow": []} and deny_all.guest_env == {}
    assert loaded == []
    for arguments in (["--proxy-config", "policy.json"], ["--proxy", "--proxy-config", "policy.json"]):
        configured = cli.startup_proxy(parse(arguments))
        assert [rule["origin"] for rule in configured.snapshot()["policy"]["allow"]] == ["https://api.example.test"]
    assert loaded == ["policy.json", "policy.json"]


async def test_proxy_flag_denies_every_request_until_a_rule_is_added_on_the_proxy_page():
    backend = types.SimpleNamespace(info=lambda: {})
    async with TestClient(TestServer(create_app(backend))) as offline:
        assert (await offline.get("/proxy")).status == 404

    async def reached(request):
        return web.Response(text="reached upstream")

    upstream = web.Application()
    upstream.router.add_get("/hello", reached)
    proxy = cli.startup_proxy(cli.parser().parse_args(["--proxy"]))
    await proxy.start()
    try:
        async with TestServer(upstream) as target, TestClient(TestServer(create_app(backend, proxy=proxy))) as client, \
                aiohttp.ClientSession() as guest:
            origin = f"http://127.0.0.1:{target.port}"
            proxy_url = "http://%s:%d" % proxy.address

            async def fetch():
                async with guest.get(origin + "/hello", proxy=proxy_url) as response:
                    return response.status, await response.text()

            page = await client.get("/proxy")
            assert page.status == 200
            headers = {"X-Proxy-Token": re.search(r'<meta name="proxy-token" content="([^"]+)"', await page.text())[1]}
            assert (await (await client.get("/proxy/api", headers=headers)).json())["policy"] == {"allow": []}
            assert (await fetch())[0] == 403
            update = await client.put("/proxy/api", headers=headers,
                                      json={"allow": [{"origin": origin, "allowCidrs": ["127.0.0.1/32"]}]})
            assert update.status == 200, await update.text()
            assert await fetch() == (200, "reached upstream")
    finally:
        await proxy.close()


async def test_bad_policy_fails_before_vm_creation(monkeypatch):
    calls = []

    def invalid_policy(path):
        raise ValueError("Invalid proxy configuration")

    monkeypatch.setattr(cli, "load_policy", invalid_policy)
    monkeypatch.setattr(cli, "QuicksandBackend", lambda *a, **kw: calls.append(kw))
    with pytest.raises(ValueError, match="Invalid proxy configuration"):
        await cli.serve(cli.parser().parse_args(["--proxy-config", "invalid.json"]))
    assert calls == []


@pytest.mark.parametrize("failure", ["proxy", "vm"])
async def test_startup_failure_closes_vm_before_proxy(monkeypatch, failure):
    calls = []

    class Proxy:
        def __init__(self, policy):
            assert policy == "compiled-policy"

        async def start(self):
            calls.append("proxy.start")
            if failure == "proxy":
                raise RuntimeError("proxy failed")

        async def close(self):
            calls.append("proxy.close")

    class Backend:
        def __init__(self, *args, proxy=None, **kwargs):
            assert isinstance(proxy, Proxy)

        async def boot(self):
            calls.append("vm.boot")
            raise RuntimeError("vm failed")

        async def close(self):
            calls.append("vm.close")

    monkeypatch.setattr(cli, "load_policy", lambda path: "compiled-policy")
    monkeypatch.setattr(cli, "HostProxy", Proxy)
    monkeypatch.setattr(cli, "QuicksandBackend", Backend)
    with pytest.raises(RuntimeError, match=f"{failure} failed"):
        await cli.serve(cli.parser().parse_args(["--proxy-config", "policy.json"]))
    expected = ["proxy.start"] + (["vm.boot"] if failure == "vm" else [])
    assert calls == expected + ["vm.close", "proxy.close"]


async def test_cancel_during_startup_cancels_boot_and_closes_both(monkeypatch):
    calls = []
    started = asyncio.Event()

    class Proxy:
        def __init__(self, policy):
            pass

        async def start(self):
            started.set()
            try:
                await asyncio.sleep(60)
            finally:
                calls.append("proxy.start-cancelled")

        async def close(self):
            calls.append("proxy.close")

    class Backend:
        def __init__(self, *a, **kw):
            pass

        async def boot(self):
            pytest.fail("VM must not boot after startup cancellation")

        async def close(self):
            calls.append("vm.close")

    monkeypatch.setattr(cli, "load_policy", lambda path: None)
    monkeypatch.setattr(cli, "HostProxy", Proxy)
    monkeypatch.setattr(cli, "QuicksandBackend", Backend)
    task = asyncio.create_task(cli.serve(cli.parser().parse_args(["--proxy-config", "policy.json"])))
    await started.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert calls == ["proxy.start-cancelled", "vm.close", "proxy.close"]
