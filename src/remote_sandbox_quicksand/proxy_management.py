"""Local, token-protected management page for the host's egress proxy.

The proxy object owns policy validation and sanitization. Its snapshot() must
return only the safe policy and bounded, sanitized activity events; it must
never return host credential values, request headers, or request/response bodies.
"""

from __future__ import annotations

import json
import re
import secrets
from importlib.resources import files
from typing import Protocol

from aiohttp import web


MAX_POLICY_BYTES = 256 * 1024
_LOOPBACK_HOST = re.compile(r"(?:localhost|127\.0\.0\.1|\[::1\])(?::([0-9]{1,5}))?", re.I)


class ManagedProxy(Protocol):
    def snapshot(self) -> dict: ...
    def update_policy(self, config: dict) -> None: ...


def _access_error(request: web.Request, token: str | None = None) -> str | None:
    hosts = request.headers.getall("Host", [])
    match = _LOOPBACK_HOST.fullmatch(hosts[0]) if len(hosts) == 1 else None
    if not match or (match[1] is not None and not 1 <= int(match[1]) <= 65535):
        return "A loopback Host is required."
    if not request.raw_path.startswith("/"):
        return "An absolute-path request target is required."
    origins = request.headers.getall("Origin", [])
    if origins and (len(origins) != 1 or origins[0] != f"{request.scheme}://{hosts[0]}"):
        return "Only this page's origin is allowed."
    if request.headers.get("Sec-Fetch-Site", "") not in {"", "none", "same-origin"}:
        return "Cross-origin browser access is not allowed."
    if token is not None:
        supplied = request.headers.getall("X-Proxy-Token", [])
        if len(supplied) != 1 or not secrets.compare_digest(supplied[0].encode(), token.encode()):
            return "The proxy management token is required."
    return None


def _headers() -> dict[str, str]:
    return {
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "X-Frame-Options": "DENY",
        "Cross-Origin-Resource-Policy": "same-origin",
    }


def _json(value, status=200):
    return web.json_response(value, status=status, headers=_headers())


def install_proxy_management(app: web.Application, proxy: ManagedProxy) -> None:
    """Add /proxy and /proxy/api before the application starts serving.

    One token is created for this proxy's server lifetime. The surrounding API
    middleware must permit Origin headers only on these exact two paths; all
    management handlers then perform their own Host/origin/token checks.
    """
    token = secrets.token_urlsafe(32)

    async def page(request):
        if error := _access_error(request):
            return _json({"error": error}, 403)
        nonce = secrets.token_urlsafe(24)
        headers = _headers()
        headers["Content-Security-Policy"] = (
            f"default-src 'none'; script-src 'nonce-{nonce}'; style-src 'nonce-{nonce}'; "
            "connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'"
        )
        headers["Cross-Origin-Opener-Policy"] = "same-origin"
        values = {"__NONCE__": nonce, "__TOKEN__": token}
        html = re.sub("|".join(values), lambda match: values[match[0]], _PAGE)
        return web.Response(text=html, content_type="text/html", headers=headers)

    async def snapshot(request):
        if error := _access_error(request, token):
            return _json({"error": error}, 403)
        return _json(proxy.snapshot())

    async def update(request):
        if error := _access_error(request, token):
            return _json({"error": error}, 403)
        if request.content_type != "application/json":
            return _json({"error": "Content-Type must be application/json."}, 415)
        if request.headers.get("Content-Encoding", "identity") != "identity":
            return _json({"error": "Compressed request bodies are not supported."}, 415)
        try:
            body = await request.content.read(MAX_POLICY_BYTES + 1)
            # A single stream read may be short. Accumulate up to the fixed cap.
            while len(body) <= MAX_POLICY_BYTES and not request.content.at_eof():
                chunk = await request.content.read(MAX_POLICY_BYTES + 1 - len(body))
                if not chunk:
                    break
                body += chunk
            if len(body) > MAX_POLICY_BYTES:
                return _json({"error": "Policy exceeds 262144 bytes."}, 413)

            def reject_constant(value):
                raise ValueError("Non-finite JSON number")

            config = json.loads(body.decode("utf-8"), parse_constant=reject_constant)
            if not isinstance(config, dict):
                raise ValueError("A policy object is required")
        except (UnicodeError, ValueError, RecursionError):
            return _json({"error": "The policy must be a valid UTF-8 JSON object."}, 400)
        try:
            # Validation and replacement are synchronous and atomic in HostProxy.
            proxy.update_policy(config)
        except ValueError:
            # Engine exceptions could contain supplied data or secret values.
            return _json({"error": "Policy rejected; the current policy is unchanged. Check policy fields, allowed origins, and host secret environment variable names. Changing guestEnv requires a restart."}, 400)
        return _json(proxy.snapshot())

    app.router.add_get("/proxy", page, allow_head=False)
    app.router.add_get("/proxy/api", snapshot, allow_head=False)
    app.router.add_put("/proxy/api", update)


_PAGE = files(__package__).joinpath("ui", "assets", "proxy.html").read_text(encoding="utf-8")
