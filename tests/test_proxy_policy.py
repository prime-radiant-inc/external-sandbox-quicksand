import asyncio
import json
import socket

import pytest

from external_sandbox_quicksand.proxy_policy import PolicyConfigError, PolicyError, ProxyPolicy, load_policy


def config(**overrides):
    return {"allow": [{"origin": "https://api.example.test", **overrides}]}


@pytest.mark.parametrize("origin", [
    "http://*.example.test", "http://example.test/", "HTTP://example.test",
    "http://EXAMPLE.test", "https://example.test:443", "http://example.test:0",
    "http://example.test.", "http://user:pass@example.test", "http://127.1",
    "http://0177.0.0.1", "http://0x7f.0.0.1", "http://2130706433",
    "http://[::1%25lo0]", "https://example.test#fragment",
])
def test_ambiguous_origins_rejected(origin):
    with pytest.raises(PolicyConfigError, match="Invalid proxy configuration"):
        ProxyPolicy.from_config(config(origin=origin))


@pytest.mark.parametrize("rule", [
    {"paths": ["//other.test/path"]}, {"paths": ["/a/../b"]},
    {"paths": ["/a/%2e%2E/b"]}, {"paths": ["/path?q=token"]},
    {"allowCidrs": ["10.0.0.0/255.0.0.0"]}, {"allowCidrs": ["::ffff:192.0.2.0/80"]},
    {"allowCidrs": ["10.0.0.0/08"]}, {"allowCidrs": []}, {"methods": None},
    {"methods": []}, {"methods": ["GET", "GET"]}, {"methods": ["get"]},
    {"accidentalTypo": True},
])
def test_invalid_rule_fields_fail_closed(rule):
    with pytest.raises(PolicyConfigError):
        ProxyPolicy.from_config(config(**rule))


def test_credentials_require_https_exact_placeholder_and_host_secret():
    credential = {"header": "Authorization", "placeholder": "Bearer guest-token",
                  "secretEnv": "SERVICE_KEY", "prefix": "Bearer "}
    value = config(credential=credential, methods=["POST"], paths=["/v1/request"])
    value["guestEnv"] = {"SERVICE_KEY": "guest-token", "LITERAL": "$SERVICE_KEY"}
    policy = ProxyPolicy.from_config(value, {"SERVICE_KEY": "host-super-secret"})
    rule, headers, _, _ = policy.authorize("https://api.example.test/v1/request?arg=1", "POST",
                                          [("Authorization", "Bearer guest-token")])
    assert headers["authorization"] == "Bearer host-super-secret"
    assert policy.guest_env["SERVICE_KEY"] == "guest-token"
    assert policy.guest_env["LITERAL"] == "$SERVICE_KEY"
    assert "host-super-secret" not in repr(policy)
    assert "host-super-secret" not in repr(rule)
    assert "host-super-secret" not in json.dumps(policy.configuration())
    for url, method, headers in [
        ("https://api.example.test/v1/request", "GET", [("Authorization", "Bearer guest-token")]),
        ("https://api.example.test/other", "POST", [("Authorization", "Bearer guest-token")]),
        ("https://api.example.test/v1/request", "POST", []),
        ("https://api.example.test/v1/request", "POST", [("Authorization", "Bearer wrong")]),
        ("https://api.example.test/v1/request", "POST", [("Authorization", "Bearer guest-token"),
                                                        ("authorization", "Bearer guest-token")]),
    ]:
        with pytest.raises(PolicyError):
            policy.authorize(url, method, headers)
    with pytest.raises(PolicyConfigError):
        ProxyPolicy.from_config(config(origin="http://api.example.test", credential=credential),
                                {"SERVICE_KEY": "host-super-secret"})
    for secrets in ({}, {"SERVICE_KEY": ""}, {"SERVICE_KEY": "real\nsecret"}):
        with pytest.raises(PolicyConfigError):
            ProxyPolicy.from_config(value, secrets)
    value["guestEnv"]["OTHER_KEY"] = "Bearer host-super-secret"
    with pytest.raises(PolicyConfigError):
        ProxyPolicy.from_config(value, {"SERVICE_KEY": "host-super-secret"})


@pytest.mark.parametrize("header", ["Host", "Connection", "Transfer-Encoding", "Proxy-Authorization",
                                   "Content-Length", "Upgrade", "Accept-Encoding"])
def test_credentials_cannot_replace_transport_headers(header):
    with pytest.raises(PolicyConfigError):
        ProxyPolicy.from_config(config(credential={"header": header, "placeholder": "dummy",
                                                  "secretEnv": "KEY"}), {"KEY": "real-secret"})


@pytest.mark.parametrize("address", [
    "127.0.0.1", "10.0.0.1", "169.254.169.254", "100.64.0.1", "192.0.2.1", "224.0.0.1",
    "::1", "::ffff:127.0.0.1", "fc00::1", "fe80::1", "2002:7f00:1::1", "2001:db8::1",
])
def test_default_policy_denies_special_addresses(address):
    rule = ProxyPolicy.from_config(config()).rules["https://api.example.test"]
    assert not rule.permits_address(address)


async def test_dns_result_checked_and_selected_numeric_address_returned(monkeypatch):
    calls = []

    async def resolve(host, port, **kwargs):
        calls.append((host, port))
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.215.14", port))]

    monkeypatch.setattr(asyncio.get_running_loop(), "getaddrinfo", resolve)
    policy = ProxyPolicy.from_config(config())
    rule = policy.rules["https://api.example.test"]
    assert await policy.resolve("api.example.test", 443, rule) == ("93.184.215.14", socket.AF_INET)
    assert calls == [("api.example.test", 443)]
    private = ProxyPolicy.from_config(config(allowCidrs=["127.0.0.0/8"]))
    assert await private.resolve("api.example.test", 443, private.rules[rule.origin]) == ("127.0.0.1", socket.AF_INET)
    with pytest.raises(PolicyError):
        await policy.resolve("127.0.0.1", 443, rule)
    with pytest.raises(PolicyError):
        await private.resolve("api.example.test", 443, rule)


def test_loader_is_bounded_and_errors_do_not_reflect_input(tmp_path):
    path = tmp_path / "policy.json"
    path.write_text(json.dumps({"allow": []}))
    assert not load_policy(path).rules
    for text in ('{"real-secret":', "x" * (256 * 1024 + 1)):
        path.write_text(text)
        with pytest.raises(PolicyConfigError) as error:
            load_policy(path)
        assert "real-secret" not in str(error.value)
