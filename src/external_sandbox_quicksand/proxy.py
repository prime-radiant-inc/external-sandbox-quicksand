"""Embedded host HTTP(S) proxy. The VM only transports bytes to it.

The listener accepts one request per connection (plus an optional CONNECT/TLS
handshake), deliberately closing rather than supporting pipelining or upgrades.
HTTP response bodies stream with backpressure, including SSE.
"""

from __future__ import annotations

import asyncio
import contextlib
import datetime
import http
import re
import socket
import ssl
import time
from collections import deque
from urllib.parse import urlsplit

import aiohttp
import h11
from aiohttp.abc import AbstractResolver
from yarl import URL

from .proxy_certificates import CertificateAuthority
from .proxy_policy import (
    PolicyConfigError, PolicyError, ProxyPolicy, canonical_origin, load_policy, request_url,
)

__all__ = ["HostProxy", "ProxyPolicy", "load_policy"]

MAX_HEADERS = 64 * 1024
MAX_HEADER_COUNT = 100
MAX_REQUEST = 16 * 1024 * 1024
MAX_BUFFERED_REQUESTS = 64 * 1024 * 1024
MAX_RESPONSE = 256 * 1024 * 1024
MAX_CONNECTIONS = 64
IDLE_TIMEOUT = 120
REQUEST_TIMEOUT = 300
HOP_HEADERS = frozenset({
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "proxy-connection", "te", "trailer", "transfer-encoding", "upgrade",
})


class ProxyFailure(Exception):
    def __init__(self, status: int, reason: str):
        self.status = status
        self.reason = reason
        super().__init__(reason)


class LiteralRedactor:
    """Filter literal secrets across chunks without delaying ordinary SSE data."""

    def __init__(self, secrets):
        self.secrets = tuple(secret.encode("ascii") for secret in secrets)
        self._pattern = (re.compile(b"|".join(re.escape(value) for value in self.secrets))
                         if self.secrets else None)
        self._replacement = b"[REDACTED]"
        if any(secret in self._replacement for secret in self.secrets):
            self._replacement = b""
        self._pending = b""
        self._failure = []
        for secret in self.secrets:
            failure = [0] * len(secret)
            position = 0
            for index in range(1, len(secret)):
                while position and secret[index] != secret[position]:
                    position = failure[position - 1]
                if secret[index] == secret[position]:
                    position += 1
                failure[index] = position
            self._failure.append(failure)

    def _suffix(self, data):
        longest = 0
        for secret, failure in zip(self.secrets, self._failure):
            position = 0
            for byte in data[-(len(secret) - 1):] if len(secret) > 1 else b"":
                while position and byte != secret[position]:
                    position = failure[position - 1]
                if byte == secret[position]:
                    position += 1
            longest = max(longest, position)
        return longest

    def feed(self, data: bytes, *, final=False) -> bytes:
        if self._pattern is None:
            return data
        data = self._pending + data
        self._pending = b""
        pieces = []
        end = 0
        for match in self._pattern.finditer(data):
            pieces.extend((data[end:match.start()], self._replacement))
            end = match.end()
        tail = data[end:]
        hold = 0 if final else self._suffix(tail)
        if hold:
            self._pending = tail[-hold:]
            tail = tail[:-hold]
        pieces.append(tail)
        return b"".join(pieces)


class _PinnedResolver(AbstractResolver):
    def __init__(self, expected_host, address, family):
        self.expected_host = expected_host
        self.address = address
        self.family = family

    async def resolve(self, host, port=0, family=socket.AF_INET):
        if host != self.expected_host:
            raise OSError("Unexpected upstream hostname")
        return [{"hostname": host, "host": self.address, "port": port,
                 "family": self.family, "proto": socket.IPPROTO_TCP,
                 "flags": socket.AI_NUMERICHOST}]

    async def close(self):
        pass


def _origin_for_authority(authority: str, scheme: str) -> str:
    """Normalize only an explicit default port; reject all other URL ambiguity."""
    try:
        if (not authority or any(char in authority for char in "/?#@\\%")
                or re.search(r"[\x00-\x20\x7f]", authority)):
            raise ValueError()
        parts = urlsplit(f"{scheme}://{authority}")
        port = parts.port
        host = parts.hostname
        if not host or port == 0:
            raise ValueError()
        rendered = f"[{host}]" if ":" in host else host
        if port and port != (443 if scheme == "https" else 80):
            rendered += f":{port}"
        # Apart from default ports, authorities must already use canonical case,
        # IP spelling, and decimal ports. This excludes legacy numeric-IP forms.
        permitted_authorities = {rendered, rendered + (":443" if scheme == "https" else ":80")}
        if authority not in permitted_authorities:
            raise ValueError()
        origin, _, _ = canonical_origin(f"{scheme}://{rendered}")
        return origin
    except (ValueError, TypeError):
        raise PolicyError() from None


def _absolute_url(target: str) -> str:
    try:
        parts = urlsplit(target)
        if parts.scheme not in ("http", "https") or "#" in target:
            raise ValueError()
        origin = _origin_for_authority(parts.netloc, parts.scheme)
        value = origin + (parts.path or "/") + ("?" + parts.query if "?" in target else "")
        request_url(value)
        return value
    except (ValueError, TypeError):
        raise PolicyError() from None


class HostProxy:
    def __init__(self, policy: ProxyPolicy, *, upstream_ssl_context: ssl.SSLContext | None = None):
        self.policy = policy
        self._ca = CertificateAuthority()
        self._contexts: dict[str, ssl.SSLContext] = {}
        self._upstream_ssl = upstream_ssl_context or ssl.create_default_context()
        if (self._upstream_ssl.verify_mode != ssl.CERT_REQUIRED
                or not self._upstream_ssl.check_hostname):
            raise ValueError("Upstream TLS verification must remain enabled")
        self._server = None
        self._address = None
        self._tasks: set[asyncio.Task] = set()
        self._writers: set[asyncio.StreamWriter] = set()
        self._events = deque(maxlen=500)
        self._buffered_request_bytes = 0

    @property
    def address(self) -> tuple[str, int]:
        if self._address is None:
            raise RuntimeError("Proxy has not started")
        return self._address

    @property
    def ca_pem(self) -> str:
        return self._ca.pem

    @property
    def guest_env(self) -> dict:
        return dict(self.policy.guest_env)

    async def start(self):
        if self._server is not None:
            raise RuntimeError("Proxy already started")
        self._server = await asyncio.start_server(self._accept, "127.0.0.1", 0,
                                                  limit=MAX_HEADERS, backlog=MAX_CONNECTIONS)
        self._address = self._server.sockets[0].getsockname()[:2]

    async def close(self):
        # Server.wait_closed() waits for active connections, so close them first.
        if self._server is not None:
            self._server.close()
        for writer in list(self._writers):
            writer.close()
        tasks = list(self._tasks)
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        if self._server is not None:
            await self._server.wait_closed()
            self._server = None
        self._contexts.clear()
        self._address = None

    def snapshot(self) -> dict:
        return {"enabled": True, "policy": self.policy.configuration(),
                "events": self.policy.redact(list(self._events))}

    def update_policy(self, config):
        replacement = ProxyPolicy.from_config(config, self.policy._secrets)
        if replacement.guest_env != self.policy.guest_env:
            raise PolicyConfigError("Changing guestEnv requires restarting the server")
        self.policy = replacement
        self._contexts.clear()
        # Revocation applies to already-open streams too. The management request
        # runs outside this listener, so it is not one of these tasks.
        for writer in list(self._writers):
            writer.close()
        for task in list(self._tasks):
            task.cancel()

    def _event(self, policy, start, method, url, status, decision, reason, injected=False):
        origin = path = ""
        if url:
            with contextlib.suppress(ValueError):
                parts, origin, _, _ = request_url(url)
                path = parts.path or "/"
        event = {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            # Redact before truncation so a display limit cannot reveal the
            # beginning of a long credential embedded in a malicious pathname.
            "method": policy.redact(method)[:32], "origin": policy.redact(origin)[:512],
            "path": policy.redact(path)[:2048],
            "status": status, "decision": decision, "reason": reason,
            "durationMs": round((time.monotonic() - start) * 1000),
            "credentialInjected": bool(injected),
        }
        self._events.append(policy.redact(event))

    def _accept(self, reader, writer):
        if len(self._tasks) >= MAX_CONNECTIONS:
            # No await or extra retained task for over-capacity peers.
            writer.write(b"HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
            writer.close()
            return
        task = asyncio.create_task(self._handle(reader, writer))
        self._tasks.add(task)
        self._writers.add(writer)
        task.add_done_callback(self._tasks.discard)
        # A task canceled before its first instruction does not run _handle's
        # finally block. Keep lifecycle bookkeeping correct in that race too.
        task.add_done_callback(lambda done: self._writers.discard(writer))

    async def _next(self, reader, connection):
        while True:
            event = connection.next_event()
            if event is not h11.NEED_DATA:
                return event
            data = await asyncio.wait_for(reader.read(16384), timeout=IDLE_TIMEOUT)
            connection.receive_data(data)

    async def _request(self, reader, connection):
        request = await self._next(reader, connection)
        if not isinstance(request, h11.Request):
            raise ProxyFailure(400, "invalid_request")
        if (len(request.headers) > MAX_HEADER_COUNT
                or sum(len(name) + len(value) + 4 for name, value in request.headers)
                + len(request.target) + len(request.method) > MAX_HEADERS):
            raise ProxyFailure(431, "headers_too_large")
        if request.http_version != b"1.1":
            raise ProxyFailure(400, "http_version_not_supported")
        return request

    async def _body(self, reader, writer, connection, headers, budget):
        length = headers.get("content-length")
        if length is not None and (not length.isdecimal() or int(length) > MAX_REQUEST):
            raise ProxyFailure(413, "request_too_large")
        if headers.get("expect", "").lower() == "100-continue":
            writer.write(connection.send(h11.InformationalResponse(status_code=100, headers=[])))
            await writer.drain()
        elif "expect" in headers:
            raise ProxyFailure(417, "expectation_not_supported")
        body = bytearray()
        while True:
            event = await self._next(reader, connection)
            if isinstance(event, h11.EndOfMessage):
                if event.headers:
                    raise ProxyFailure(400, "request_trailers_not_supported")
                return bytes(body)
            if not isinstance(event, h11.Data):
                raise ProxyFailure(400, "invalid_request_body")
            size = len(event.data)
            if len(body) + size > MAX_REQUEST:
                raise ProxyFailure(413, "request_too_large")
            if self._buffered_request_bytes + size > MAX_BUFFERED_REQUESTS:
                raise ProxyFailure(503, "request_buffer_limit")
            self._buffered_request_bytes += size
            budget[0] += size
            body.extend(event.data)

    async def _handle(self, reader, writer):
        policy = self.policy
        start = time.monotonic()
        method = url = ""
        connection = h11.Connection(h11.SERVER, max_incomplete_event_size=MAX_HEADERS)
        budget = [0]
        response_started = [False]
        in_tls_handshake = False
        injected = False
        status = 502
        decision = "error"
        reason = "upstream_error"
        try:
            async with asyncio.timeout(REQUEST_TIMEOUT):
                request = await self._request(reader, connection)
                method = request.method.decode("ascii")
                target = request.target.decode("ascii")
                tunnel_origin = None
                if method == "CONNECT":
                    tunnel_origin = _origin_for_authority(target, "https")
                    url = tunnel_origin + "/"
                    if tunnel_origin not in policy.rules:
                        raise PolicyError()
                    connect_headers = {name.decode("ascii"): value.decode("latin-1")
                                       for name, value in request.headers}
                    self._check_headers(connect_headers, tunnel_origin)
                    if (connect_headers.get("content-length", "0") != "0"
                            or "transfer-encoding" in connect_headers):
                        raise ProxyFailure(400, "connect_body_not_supported")
                    event = await self._next(reader, connection)
                    if not isinstance(event, h11.EndOfMessage) or event.headers or connection.trailing_data[0]:
                        raise ProxyFailure(400, "invalid_connect")
                    _, host, _ = canonical_origin(tunnel_origin)
                    context = self._contexts.get(host)
                    if context is None:
                        context = self._ca.server_context(host)
                        self._contexts[host] = context
                    writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    await writer.drain()
                    in_tls_handshake = True
                    await writer.start_tls(context, ssl_handshake_timeout=15, ssl_shutdown_timeout=2)
                    in_tls_handshake = False
                    connection = h11.Connection(h11.SERVER, max_incomplete_event_size=MAX_HEADERS)
                    request = await self._request(reader, connection)
                    method = request.method.decode("ascii")
                    target = request.target.decode("ascii")
                if tunnel_origin:
                    if target.startswith("/") and not target.startswith("//"):
                        url = tunnel_origin + target
                        request_url(url)
                    else:
                        url = _absolute_url(target)
                        if request_url(url)[1] != tunnel_origin:
                            raise PolicyError()
                else:
                    url = _absolute_url(target)
                    if request_url(url)[0].scheme != "http":
                        raise PolicyError()
                headers = [(name.decode("ascii"), value.decode("latin-1"))
                           for name, value in request.headers]
                rule, outgoing, host, port = policy.authorize(url, method, headers)
                self._check_headers(outgoing, rule.origin)
                if rule.credential_header in self._connection_tokens(outgoing):
                    raise PolicyError()
                body = await self._body(reader, writer, connection, outgoing, budget)
                address, family = await policy.resolve(host, port, rule)
                injected = rule.credential_header is not None
                status = await self._forward(writer, connection, policy, method, url, outgoing,
                                             body, host, address, family, response_started)
                decision, reason = "allowed", "completed"
        except PolicyError:
            status, decision, reason = 403, "denied", "policy_denied"
        except ProxyFailure as error:
            status, reason = error.status, error.reason
        except TimeoutError:
            status, reason = 504, "timeout"
        except (aiohttp.ClientError, OSError, ssl.SSLError):
            status, reason = 502, "upstream_or_transport_error"
        except (h11.RemoteProtocolError, h11.LocalProtocolError, UnicodeError, ValueError):
            status, reason = 400, "invalid_http"
        except asyncio.CancelledError:
            status, reason = 503, "proxy_closed_or_policy_updated"
            raise
        except Exception:
            # Do not let an unexpected exception reflect upstream data or a
            # credential in an asyncio task traceback or management event.
            status, reason = 502, "proxy_error"
        finally:
            self._buffered_request_bytes -= budget[0]
            if decision != "allowed" and not response_started[0] and not in_tls_handshake:
                with contextlib.suppress(Exception):
                    await self._error(writer, status)
            self._event(policy, start, method, url, status, decision, reason, injected)
            self._writers.discard(writer)
            writer.close()
            with contextlib.suppress(Exception, asyncio.CancelledError):
                await asyncio.wait_for(writer.wait_closed(), timeout=2)

    @staticmethod
    def _connection_tokens(headers):
        return {item.strip().lower() for item in headers.get("connection", "").split(",") if item.strip()}

    def _check_headers(self, headers, origin):
        host = headers.get("host")
        if host is None or _origin_for_authority(host, urlsplit(origin).scheme) != origin:
            raise PolicyError()
        if "upgrade" in headers or "upgrade" in self._connection_tokens(headers):
            raise ProxyFailure(400, "upgrades_not_supported")
        if self._connection_tokens(headers) & {"host", "content-length", "transfer-encoding"}:
            raise ProxyFailure(400, "invalid_connection_header")

    async def _error(self, writer, status):
        phrase = http.HTTPStatus(status).phrase
        body = f"{status} {phrase}\n".encode("ascii")
        writer.write((f"HTTP/1.1 {status} {phrase}\r\nConnection: close\r\n"
                      f"Content-Type: text/plain\r\nContent-Length: {len(body)}\r\n\r\n").encode("ascii") + body)
        await asyncio.wait_for(writer.drain(), timeout=2)

    async def _forward(self, writer, connection, policy, method, url, headers, body,
                       host, address, family, response_started):
        blocked = HOP_HEADERS | self._connection_tokens(headers) | {"host", "content-length", "expect"}
        outgoing = {name: value for name, value in headers.items() if name not in blocked}
        outgoing["host"] = urlsplit(url).netloc
        outgoing["accept-encoding"] = "identity"
        outgoing["connection"] = "close"
        resolver = _PinnedResolver(host, address, family)
        connector = aiohttp.TCPConnector(resolver=resolver, use_dns_cache=False, force_close=True,
                                        limit=1, ssl=self._upstream_ssl)
        timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT, connect=15, sock_read=IDLE_TIMEOUT)
        async with aiohttp.ClientSession(connector=connector, trust_env=False,
                                         cookie_jar=aiohttp.DummyCookieJar(), auto_decompress=False,
                                         timeout=timeout, skip_auto_headers={"User-Agent", "Accept", "Content-Type"},
                                         max_line_size=MAX_HEADERS, max_field_size=MAX_HEADERS) as session:
            async with session.request(method, URL(url, encoded=True), headers=outgoing,
                                       data=body if body else None, allow_redirects=False,
                                       proxy=None) as response:
                if response.status == 101:
                    raise ProxyFailure(502, "upstream_upgrade_not_supported")
                if (len(response.raw_headers) > MAX_HEADER_COUNT
                        or sum(len(name) + len(value) + 4 for name, value in response.raw_headers) > MAX_HEADERS):
                    raise ProxyFailure(502, "upstream_headers_too_large")
                encodings = response.headers.getall("Content-Encoding", [])
                if any(value.strip().lower() != "identity" for value in encodings):
                    raise ProxyFailure(502, "upstream_compression_not_supported")
                if response.content_length is not None and response.content_length > MAX_RESPONSE:
                    raise ProxyFailure(502, "response_too_large")
                connection_values = response.headers.getall("Connection", [])
                connection_tokens = {item.strip().lower() for value in connection_values for item in value.split(",")}
                blocked = HOP_HEADERS | connection_tokens | {"content-length", "content-encoding"}
                response_headers = []
                for name, value in response.raw_headers:
                    if name.decode("ascii").lower() in blocked:
                        continue
                    if any(secret.encode("ascii") in name for secret in policy.secret_values):
                        continue
                    redactor = LiteralRedactor(policy.secret_values)
                    response_headers.append((name, redactor.feed(value, final=True)))
                response_headers.append((b"connection", b"close"))
                writer.write(connection.send(h11.Response(status_code=response.status, headers=response_headers)))
                response_started[0] = True
                await asyncio.wait_for(writer.drain(), timeout=IDLE_TIMEOUT)
                redactor = LiteralRedactor(policy.secret_values)
                total = 0
                sent = 0
                async for chunk in response.content.iter_chunked(65536):
                    total += len(chunk)
                    if total > MAX_RESPONSE:
                        raise ProxyFailure(502, "response_too_large")
                    filtered = redactor.feed(chunk)
                    if filtered:
                        sent += len(filtered)
                        if sent > MAX_RESPONSE:
                            raise ProxyFailure(502, "response_too_large")
                        writer.write(connection.send(h11.Data(data=filtered)))
                        await asyncio.wait_for(writer.drain(), timeout=IDLE_TIMEOUT)
                final = redactor.feed(b"", final=True)
                if final:
                    if sent + len(final) > MAX_RESPONSE:
                        raise ProxyFailure(502, "response_too_large")
                    writer.write(connection.send(h11.Data(data=final)))
                writer.write(connection.send(h11.EndOfMessage()))
                await asyncio.wait_for(writer.drain(), timeout=IDLE_TIMEOUT)
                return response.status
