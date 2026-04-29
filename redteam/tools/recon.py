"""recon - offline-only OSINT helpers + `gh` CLI wrappers.

DNS, whois, certificate transparency. Plus thin wrappers around the `gh`
CLI baked into the runtime image (authenticated via a PAT mounted at
/run/secrets/gh_token) for GitHub-side recon. No vendor OSINT APIs by
default; Shodan/VirusTotal are a separate opt-in extras module under
redteam.tools.recon_extras (not loaded automatically).
"""

from __future__ import annotations

import socket
from typing import Any

from ._context import ToolContext
from ._sdk_shim import create_sdk_mcp_server, tool

PACK_NAME = "recon"


def build_pack(ctx: ToolContext):
    @tool(
        "recon__dns_lookup",
        "Resolve A / AAAA / CNAME records for a hostname. Hostname must be in scope.",
        {
            "type": "object",
            "properties": {
                "host": {"type": "string", "description": "hostname to resolve"},
                "record_type": {
                    "type": "string",
                    "enum": ["A", "AAAA", "CNAME"],
                    "default": "A",
                },
            },
            "required": ["host"],
        },
    )
    async def dns_lookup(host: str, record_type: str = "A") -> dict[str, Any]:
        ctx.assert_in_scope("recon__dns_lookup", {"host": host})
        family = socket.AF_INET if record_type == "A" else socket.AF_INET6
        try:
            infos = socket.getaddrinfo(host, None, family=family)
            addrs = sorted({info[4][0] for info in infos})
            return {"host": host, "record_type": record_type, "addresses": addrs}
        except socket.gaierror as e:
            return {"host": host, "record_type": record_type, "error": str(e)}

    @tool(
        "recon__whois",
        "Stub: WHOIS lookup. Implementation requires whois CLI in container.",
        {
            "type": "object",
            "properties": {"host": {"type": "string"}},
            "required": ["host"],
        },
    )
    async def whois(host: str) -> dict[str, Any]:
        ctx.assert_in_scope("recon__whois", {"host": host})
        return {
            "host": host,
            "status": "not_implemented",
            "hint": "wire to system `whois` binary in container entrypoint",
        }

    @tool(
        "recon__cert_transparency",
        "Stub: query crt.sh for certificate transparency entries.",
        {
            "type": "object",
            "properties": {"host": {"type": "string"}},
            "required": ["host"],
        },
    )
    async def cert_transparency(host: str) -> dict[str, Any]:
        ctx.assert_in_scope("recon__cert_transparency", {"host": host})
        return {
            "host": host,
            "status": "not_implemented",
            "hint": "wire to https://crt.sh/?q=<host>&output=json (requires egress allowlist)",
        }

    return create_sdk_mcp_server(
        name="recon",
        version="0.1.0",
        tools=[dns_lookup, whois, cert_transparency],
    )
