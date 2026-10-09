"""Shared typed aiohttp application keys."""

from aiohttp import web

BACKEND = web.AppKey("backend", object)
SHELL_SESSIONS = web.AppKey("shell_sessions", set)
HTTP_EXECUTIONS = web.AppKey("http_executions", set)
CODEX_CONNECTIONS = web.AppKey("codex_connections", set)
