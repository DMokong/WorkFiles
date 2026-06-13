"""web - scope-bound HTTP requests.

Single tool: http_request. Scope guard rejects out-of-scope URLs at the
hook layer; this tool also re-checks as defence in depth.
"""

from __future__ import annotations

import urllib.error
import urllib.request
from typing import Any

from ._context import ToolContext
from ._sdk_shim import create_sdk_mcp_server, tool

PACK_NAME = "web"

_READ_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
_WRITE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
_ALLOWED_METHODS = _READ_METHODS | _WRITE_METHODS


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse to auto-follow redirects.

    The scope guard only sees the *initial* URL. If urllib transparently
    followed a 3xx, an in-scope target could bounce the agent to an
    out-of-scope host (e.g. the cloud metadata endpoint) with no fresh scope
    check. Instead we surface the 3xx response verbatim; the agent must issue a
    new, separately-scope-checked request to follow it.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        return None


def _build_no_redirect_opener() -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(_NoRedirect)


def build_pack(ctx: ToolContext):
    @tool(
        "web__http_request",
        "Perform an HTTP request against an in-scope URL. Returns status, headers, body (truncated).",
        {
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "method": {"type": "string", "default": "GET"},
                "headers": {"type": "object", "additionalProperties": {"type": "string"}},
                "body": {"type": "string"},
                "max_body_bytes": {"type": "integer", "default": 65536},
            },
            "required": ["url"],
        },
    )
    async def http_request(
        url: str,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        body: str | None = None,
        max_body_bytes: int = 65536,
    ) -> dict[str, Any]:
        ctx.assert_in_scope("web__http_request", {"url": url})
        method_upper = method.upper()
        if method_upper not in _ALLOWED_METHODS:
            raise ValueError(f"method {method!r} not allowed; choose from {sorted(_ALLOWED_METHODS)}")
        if method_upper in _WRITE_METHODS and not ctx.engagement.scope.allow_write_methods:
            raise PermissionError(
                f"method {method_upper} is a state-changing verb; the engagement is "
                "read-only (set scope.allow_write_methods: true to authorize writes)"
            )

        req = urllib.request.Request(url, method=method_upper)
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        data = body.encode("utf-8") if body is not None else None
        # Use a non-redirecting opener: a 3xx is returned verbatim, never
        # auto-followed, so the agent cannot be bounced to an unscoped host.
        opener = _build_no_redirect_opener()
        try:
            with opener.open(req, data=data, timeout=20) as resp:
                raw = resp.read(max_body_bytes + 1)
                truncated = len(raw) > max_body_bytes
                payload = raw[:max_body_bytes].decode("utf-8", errors="replace")
                return {
                    "url": url,
                    "method": method_upper,
                    "status": resp.status,
                    "headers": dict(resp.headers.items()),
                    "body": payload,
                    "truncated": truncated,
                }
        except urllib.error.HTTPError as e:
            return {
                "url": url,
                "method": method_upper,
                "status": e.code,
                "headers": dict(e.headers.items()) if e.headers else {},
                "body": (e.read(max_body_bytes) if e.fp else b"").decode("utf-8", errors="replace"),
                "error": str(e),
            }
        except urllib.error.URLError as e:
            return {"url": url, "method": method_upper, "error": str(e.reason)}

    @tool(
        "web__inspect_headers",
        "Issue HEAD against an in-scope URL and return security-relevant header analysis.",
        {
            "type": "object",
            "properties": {"url": {"type": "string"}},
            "required": ["url"],
        },
    )
    async def inspect_headers(url: str) -> dict[str, Any]:
        ctx.assert_in_scope("web__inspect_headers", {"url": url})
        head = await http_request(url=url, method="HEAD")  # type: ignore[misc]
        if "headers" not in head:
            return head
        h = {k.lower(): v for k, v in head["headers"].items()}
        return {
            "url": url,
            "status": head.get("status"),
            "missing": [
                name
                for name in (
                    "strict-transport-security",
                    "content-security-policy",
                    "x-content-type-options",
                    "x-frame-options",
                    "referrer-policy",
                )
                if name not in h
            ],
            "present": h,
        }

    return create_sdk_mcp_server(
        name="web",
        version="0.1.0",
        tools=[http_request, inspect_headers],
    )
