"""Local command terminal, using the existing streaming shell WebSocket API."""
from __future__ import annotations

import html
import re
import secrets
from importlib.resources import files

from aiohttp import web

TERMINAL_TOKEN = web.AppKey("terminal_token", str)
_HOST = re.compile(r"(?:localhost|127\.0\.0\.1|\[::1\])(?::([0-9]{1,5}))?", re.I)


def check_terminal_access(request: web.Request, *, websocket=False) -> None:
    """Authorize the browser exception without opening legacy execution routes."""
    hosts = request.headers.getall("Host", [])
    match = _HOST.fullmatch(hosts[0]) if len(hosts) == 1 else None
    if not match or (match[1] is not None and not 1 <= int(match[1]) <= 65535):
        raise web.HTTPForbidden(reason="A loopback Host is required")
    origins = request.headers.getall("Origin", [])
    expected = f"{request.scheme}://{hosts[0]}"
    if origins and (len(origins) != 1 or origins[0] != expected):
        raise web.HTTPForbidden(reason="Only this page's origin is allowed")
    sites = request.headers.getall("Sec-Fetch-Site", [])
    if len(sites) > 1 or (sites and sites[0] not in {"none", "same-origin"}):
        raise web.HTTPForbidden(reason="Cross-origin browser access is not allowed")
    if not websocket:
        return
    if not origins:
        raise web.HTTPForbidden(reason="Browser WebSockets require a same-origin Origin")
    headers = request.headers.getall("Sec-WebSocket-Protocol", [])
    protocols = [part.strip() for part in headers[0].split(",")] if len(headers) == 1 else []
    tokens = [part.removeprefix("sandbox-token.") for part in protocols if part.startswith("sandbox-token.")]
    token = request.app.get(TERMINAL_TOKEN, "")
    if (len(protocols) != 2 or protocols.count("sandbox-terminal") != 1 or len(tokens) != 1
            or not token or not secrets.compare_digest(tokens[0].encode(), token.encode())):
        raise web.HTTPForbidden(reason="The terminal session token is required")


def _headers():
    return {"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer", "X-Frame-Options": "DENY",
            "Cross-Origin-Resource-Policy": "same-origin"}


def install_terminal(app: web.Application, backend) -> None:
    app[TERMINAL_TOKEN] = secrets.token_urlsafe(32)

    async def homepage(request):
        check_terminal_access(request)
        info = backend.info()
        nonce = secrets.token_urlsafe(24)
        network = "Managed proxy" if info.get("proxyEnabled") else "Network disabled"
        link = '<a id="proxy-link" href="/proxy" target="_blank" rel="noopener">Network policy ↗</a>' if info.get("proxyEnabled") else ""
        values = {"__NONCE__": nonce, "__TOKEN__": app[TERMINAL_TOKEN],
                  "__TITLE__": html.escape("Remote sandbox terminal", quote=True),
                  "__BRAND__": html.escape("Remote sandbox Quicksand", quote=True),
                  "__CWD__": html.escape(str(info.get("defaultCwd", "/workspace")), quote=True),
                  "__NETWORK__": network, "__PROXY_LINK__": link}
        # Replace only tokens in the original template, never tokens inside a
        # user-supplied directory name that has already been escaped.
        page = re.sub("|".join(values), lambda match: values[match[0]], _PAGE)
        headers = _headers()
        websocket_origin = f"{'wss' if request.scheme == 'https' else 'ws'}://{request.host}"
        headers["Content-Security-Policy"] = (
            f"default-src 'none'; script-src 'self'; style-src 'nonce-{nonce}'; "
            f"connect-src 'self' {websocket_origin}; base-uri 'none'; frame-ancestors 'none'; form-action 'none'"
        )
        headers["Cross-Origin-Opener-Policy"] = "same-origin"
        return web.Response(text=page, content_type="text/html", headers=headers)

    async def javascript(request):
        check_terminal_access(request)
        return web.Response(body=files(__package__).joinpath("ui", "assets", "terminal.js").read_bytes(),
                            content_type="text/javascript", headers=_headers())

    app.router.add_get("/", homepage, allow_head=False)
    app.router.add_get("/terminal.js", javascript, allow_head=False)


_PAGE = files(__package__).joinpath("ui", "assets", "terminal.html").read_text(encoding="utf-8")
