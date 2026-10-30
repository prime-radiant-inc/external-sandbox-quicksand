"""Strict, host-owned policy for the managed HTTP(S) proxy.

Configuration intentionally matches the v86 managed proxy. No exception includes
configuration values, URLs, credentials, or resolver error text.
"""

from __future__ import annotations

import asyncio
import copy
import ipaddress
import json
import os
import re
import socket
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from urllib.parse import SplitResult, urlsplit


class PolicyError(ValueError):
    """A safe-to-display, deliberately nonspecific policy failure."""

    def __init__(self, message: str = "Proxy policy denied request"):
        super().__init__(message)


class PolicyConfigError(ValueError):
    def __init__(self, message: str = "Invalid proxy configuration"):
        super().__init__(message)


ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
HEADER_NAME = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")
HEADER_VALUE = re.compile(r"[\x20-\x7e]*\Z")
METHOD = re.compile(r"[A-Z]+\Z")
FORBIDDEN_CREDENTIAL_HEADERS = frozenset({
    "host", "connection", "content-length", "transfer-encoding", "upgrade",
    "trailer", "te", "proxy-connection", "proxy-authorization", "proxy-authenticate",
    "expect", "accept-encoding", "content-encoding",
})
NONPUBLIC_V4 = tuple(ipaddress.ip_network(value) for value in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
    "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16",
    "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
))
GLOBAL_V6 = ipaddress.ip_network("2000::/3")
NONPUBLIC_V6 = tuple(ipaddress.ip_network(value) for value in (
    "2001::/23", "2001:db8::/32", "2002::/16", "3fff::/20",
))


def _object(value, allowed):
    if not isinstance(value, dict) or set(value) - set(allowed):
        raise PolicyConfigError()
    return value


def _text(value, *, empty=False):
    if (not isinstance(value, str) or (not empty and not value)
            or len(value.encode("utf-8")) > 16384
            or re.search(r"[\x00-\x1f\x7f]", value)):
        raise PolicyConfigError()
    return value


def _list(value, validate):
    if value is None:
        return None
    if not isinstance(value, list) or not value or len(value) > 1024:
        raise PolicyConfigError()
    result = tuple(validate(item) for item in value)
    if len(result) != len(set(result)):
        raise PolicyConfigError()
    return result


def canonical_origin(value: str) -> tuple[str, str, int]:
    """Require an unambiguous canonical origin, rather than repairing a URL."""
    try:
        if not isinstance(value, str) or not value.isascii() or re.search(r"[\s\\%]", value):
            raise ValueError()
        url = urlsplit(value)
        if (url.scheme not in ("http", "https") or not url.hostname or url.username is not None
                or url.password is not None or url.path or url.query or url.fragment):
            raise ValueError()
        host = url.hostname
        port = url.port or (443 if url.scheme == "https" else 80)
        if url.port == 0:
            raise ValueError()
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            if (len(host) > 253 or not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", part)
                                         for part in host.split("."))
                    or all(re.fullmatch(r"(?:[0-9]+|0x[0-9a-f]+)", part)
                           for part in host.split("."))):
                raise ValueError() from None
            rendered = host
        else:
            rendered = f"[{address.compressed}]" if address.version == 6 else str(address)
        canonical = f"{url.scheme}://{rendered}"
        if port != (443 if url.scheme == "https" else 80):
            canonical += f":{port}"
        if canonical != value:
            raise ValueError()
        return canonical, host, port
    except (ValueError, TypeError, UnicodeError):
        raise PolicyConfigError() from None


def request_url(value: str) -> tuple[SplitResult, str, str, int]:
    """Parse a request without accepting URL parser normalization conveniences."""
    try:
        if (not value.isascii() or re.search(r"[\x00-\x20\x7f\\]", value)
                or "#" in value):
            raise ValueError()
        url = urlsplit(value)
        origin, host, port = canonical_origin(f"{url.scheme}://{url.netloc}")
        if url.path and (not url.path.startswith("/") or url.path.startswith("//")):
            raise ValueError()
        return url, origin, host, port
    except (ValueError, TypeError, UnicodeError):
        raise PolicyError() from None


def _path(value):
    value = _text(value)
    if (not value.isascii() or not value.startswith("/") or value.startswith("//")
            or any(char in value for char in "?#\\ ")
            or any(re.sub("%2e", ".", part, flags=re.IGNORECASE) in (".", "..")
                   for part in value.split("/"))):
        raise PolicyConfigError()
    return value


def _method(value):
    value = _text(value)
    if not METHOD.fullmatch(value):
        raise PolicyConfigError()
    return value


def numeric_address(value):
    if "%" in value:
        raise ValueError()
    address = ipaddress.ip_address(value)
    return address.ipv4_mapped or address if address.version == 6 else address


def _network(value):
    value = _text(value)
    try:
        if not re.fullmatch(r"[^/]+/(0|[1-9][0-9]*)", value) or "%" in value:
            raise ValueError()
        source_address, source_prefix = value.split("/")
        original = ipaddress.ip_address(source_address)
        if original.version == 6 and original.ipv4_mapped and int(source_prefix) < 96:
            raise ValueError()
        network = ipaddress.ip_network(value, strict=False)
        if network.version == 6 and network.network_address.ipv4_mapped:
            if network.prefixlen < 96:
                raise ValueError()
            network = ipaddress.ip_network((network.network_address.ipv4_mapped, network.prefixlen - 96))
        return network
    except ValueError:
        raise PolicyConfigError() from None


def _cidr(value):
    _network(value)
    return value


def _public(address):
    if address.version == 4:
        return not any(address in network for network in NONPUBLIC_V4)
    return address in GLOBAL_V6 and not any(address in network for network in NONPUBLIC_V6)


@dataclass(frozen=True)
class Rule:
    origin: str
    methods: tuple[str, ...] | None
    paths: tuple[str, ...] | None
    ranges: tuple | None
    credential_header: str | None = None
    placeholder: str | None = field(default=None, repr=False)
    credential_value: str | None = field(default=None, repr=False)

    def permits_address(self, value: str) -> bool:
        try:
            address = numeric_address(value)
        except ValueError:
            return False
        return (any(address.version == network.version and address in network for network in self.ranges)
                if self.ranges is not None else _public(address))


@dataclass(frozen=True, repr=False)
class ProxyPolicy:
    rules: Mapping[str, Rule]
    guest_env: Mapping[str, str]
    secret_values: tuple[str, ...] = field(repr=False)
    _config: dict = field(repr=False)
    _secrets: Mapping[str, str] = field(repr=False)

    @classmethod
    def from_config(cls, value, secrets: Mapping[str, str] | None = None):
        """Validate everything, including secret availability, before startup."""
        try:
            return cls._compile(value, os.environ if secrets is None else secrets)
        except (PolicyConfigError, ValueError, TypeError, UnicodeError, OverflowError):
            raise PolicyConfigError() from None

    @classmethod
    def _compile(cls, value, secrets):
        root = _object(value, ("allow", "guestEnv"))
        entries = root.get("allow")
        if not isinstance(entries, list) or len(entries) > 64:
            raise PolicyConfigError()
        rules = {}
        real_values = set()
        normalized = {"allow": []}
        for value in entries:
            value = _object(value, ("origin", "methods", "paths", "allowCidrs", "credential"))
            origin, _, _ = canonical_origin(_text(value.get("origin")))
            if origin in rules:
                raise PolicyConfigError()
            # Explicit null is not an omitted optional property.
            if any(value.get(key) is None for key in set(value) - {"origin"}):
                raise PolicyConfigError()
            methods = _list(value.get("methods"), _method)
            paths = _list(value.get("paths"), _path)
            cidrs = _list(value.get("allowCidrs"), _cidr)
            header = placeholder = credential_value = None
            config = copy.deepcopy(value)
            if "credential" in value:
                credential = _object(value["credential"], ("header", "placeholder", "secretEnv", "prefix"))
                header = _text(credential.get("header")).lower()
                placeholder = _text(credential.get("placeholder"))
                secret_env = _text(credential.get("secretEnv"))
                prefix = _text(credential.get("prefix", ""), empty=True)
                if (not origin.startswith("https://") or not HEADER_NAME.fullmatch(header)
                        or header in FORBIDDEN_CREDENTIAL_HEADERS
                        or not HEADER_VALUE.fullmatch(placeholder) or not HEADER_VALUE.fullmatch(prefix)
                        or not ENV_NAME.fullmatch(secret_env)):
                    raise PolicyConfigError()
                secret = secrets.get(secret_env)
                if (not isinstance(secret, str) or not secret.strip() or len(secret) > 16384
                        or not HEADER_VALUE.fullmatch(secret)):
                    raise PolicyConfigError()
                credential_value = prefix + secret
                real_values.add(secret)
                config["credential"] = {"header": header, "placeholder": placeholder,
                                        "secretEnv": secret_env, "prefix": prefix}
            rules[origin] = Rule(origin, methods, paths,
                                 tuple(_network(cidr) for cidr in cidrs) if cidrs else None,
                                 header, placeholder, credential_value)
            normalized["allow"].append(config)
        guest_env = root.get("guestEnv", {})
        if not isinstance(guest_env, dict) or len(guest_env) > 128:
            raise PolicyConfigError()
        for name, value in guest_env.items():
            if not isinstance(name, str) or not ENV_NAME.fullmatch(name):
                raise PolicyConfigError()
            _text(value, empty=True)
        guest_values = list(guest_env.values()) + [rule.placeholder for rule in rules.values() if rule.placeholder]
        if any(secret in value for secret in real_values for value in guest_values):
            raise PolicyConfigError()
        if "guestEnv" in root:
            normalized["guestEnv"] = copy.deepcopy(guest_env)
        return cls(MappingProxyType(rules), MappingProxyType(dict(guest_env)),
                   tuple(sorted(real_values, key=len, reverse=True)), normalized,
                   MappingProxyType(dict(secrets)))

    def configuration(self):
        # Secrets are never configured by value; redact accidental appearances
        # elsewhere as a further defense for the management UI.
        return self.redact(copy.deepcopy(self._config))

    def redact(self, value):
        if isinstance(value, str):
            replacement = "" if any(secret in "[REDACTED]" for secret in self.secret_values) else "[REDACTED]"
            for secret in self.secret_values:
                value = value.replace(secret, replacement)
            return value
        if isinstance(value, dict):
            return {self.redact(key): self.redact(item) for key, item in value.items()}
        if isinstance(value, (tuple, list)):
            return [self.redact(item) for item in value]
        return value

    def authorize(self, value: str, method: str, headers: list[tuple[str, str]]):
        url, origin, host, port = request_url(value)
        rule = self.rules.get(origin)
        if (rule is None or not METHOD.fullmatch(method) or method == "CONNECT"
                or (rule.methods is not None and method not in rule.methods)
                or (rule.paths is not None and (url.path or "/") not in rule.paths)):
            raise PolicyError()
        outgoing = {}
        for name, item in headers:
            name = name.lower()
            if (not HEADER_NAME.fullmatch(name) or name in outgoing
                    or re.search(r"[\x00-\x1f\x7f]", item)):
                raise PolicyError()
            outgoing[name] = item
        if rule.credential_header:
            if outgoing.get(rule.credential_header) != rule.placeholder:
                raise PolicyError()
            outgoing[rule.credential_header] = rule.credential_value
        return rule, outgoing, host, port

    async def resolve(self, host: str, port: int, rule: Rule) -> tuple[str, int]:
        if self.rules.get(rule.origin) is not rule:
            raise PolicyError()
        try:
            try:
                candidates = [numeric_address(host)]
            except ValueError:
                records = await asyncio.wait_for(asyncio.get_running_loop().getaddrinfo(
                    host, port, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM), timeout=15)
                candidates = [numeric_address(record[4][0]) for record in records]
            for address in candidates:
                if rule.permits_address(str(address)):
                    return str(address), socket.AF_INET if address.version == 4 else socket.AF_INET6
        except (OSError, ValueError, TimeoutError):
            pass
        raise PolicyError()


def load_policy(path: str | Path, secrets: Mapping[str, str] | None = None) -> ProxyPolicy:
    """Synchronous startup loader; cap input and never reflect JSON or secrets."""
    try:
        with open(path, "rb") as stream:
            source = stream.read(256 * 1024 + 1)
        if len(source) > 256 * 1024:
            raise PolicyConfigError()
        value = json.loads(source)
    except (OSError, ValueError, UnicodeError):
        raise PolicyConfigError("Could not read valid proxy configuration") from None
    return ProxyPolicy.from_config(value, secrets)
