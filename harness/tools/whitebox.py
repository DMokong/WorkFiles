"""whitebox - tools over the read-only assets mount.

Bridges the operator-supplied source / IaC / specs / artefacts into
agent-callable tools. Refuses any write attempt as defence-in-depth on
top of the container's ro bind mount.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from ._context import ToolContext
from ._sdk_shim import create_sdk_mcp_server, tool

PACK_NAME = "whitebox"

_MAX_GREP_MATCHES = 200
_MAX_FILE_BYTES = 256 * 1024


def build_pack(ctx: ToolContext):
    if ctx.assets is None or not ctx.assets.entries:
        raise ValueError(
            "whitebox pack requires assets - engagement YAML must populate assets:"
        )

    host_roots = {str(e.host_path): e for e in ctx.assets.entries}

    def _resolve_under_assets(p: str) -> Path:
        target = Path(p).resolve()
        for host_root in host_roots:
            root = Path(host_root)
            try:
                target.relative_to(root)
                return target
            except ValueError:
                continue
        raise PermissionError(f"path {p!r} is outside the assets mount")

    @tool(
        "whitebox__list_assets",
        "List the indexed asset entries available to the agent (kind, role, paths, metadata).",
        {"type": "object", "properties": {}},
    )
    async def list_assets() -> dict[str, Any]:
        return ctx.assets.to_dict()

    @tool(
        "whitebox__repo_grep",
        "Regex search across an indexed source repo. Read-only.",
        {
            "type": "object",
            "properties": {
                "pattern": {"type": "string"},
                "role": {"type": "string", "description": "matches the source_repos.role from the YAML"},
                "max_matches": {"type": "integer", "default": 100},
            },
            "required": ["pattern", "role"],
        },
    )
    async def repo_grep(pattern: str, role: str, max_matches: int = 100) -> dict[str, Any]:
        try:
            regex = re.compile(pattern)
        except re.error as e:
            raise ValueError(f"invalid regex: {e}") from e
        cap = min(max_matches, _MAX_GREP_MATCHES)
        repo = next(
            (e for e in ctx.assets.by_kind("source") if e.metadata.get("role") == role),
            None,
        )
        if repo is None:
            raise ValueError(f"no source repo with role={role!r}")
        matches: list[dict[str, Any]] = []
        for path in repo.host_path.rglob("*"):
            if not path.is_file():
                continue
            if path.stat().st_size > _MAX_FILE_BYTES:
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue
            for line_no, line in enumerate(text.splitlines(), start=1):
                if regex.search(line):
                    matches.append(
                        {
                            "path": str(path.relative_to(repo.host_path)),
                            "line": line_no,
                            "text": line[:300],
                        }
                    )
                    if len(matches) >= cap:
                        return {"role": role, "pattern": pattern, "matches": matches, "truncated": True}
        return {"role": role, "pattern": pattern, "matches": matches, "truncated": False}

    @tool(
        "whitebox__repo_read",
        "Read a file under an indexed source repo (UTF-8, max 256 KiB).",
        {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
    )
    async def repo_read(path: str) -> dict[str, Any]:
        target = _resolve_under_assets(path)
        if not target.is_file():
            raise FileNotFoundError(f"not a file: {path}")
        if target.stat().st_size > _MAX_FILE_BYTES:
            raise ValueError(f"file too large ({target.stat().st_size} bytes)")
        return {"path": path, "content": target.read_text(encoding="utf-8", errors="replace")}

    @tool(
        "whitebox__semgrep_scan",
        "Stub: run `semgrep --config auto` against a source repo. Returns SARIF-shaped findings.",
        {
            "type": "object",
            "properties": {"role": {"type": "string"}},
            "required": ["role"],
        },
    )
    async def semgrep_scan(role: str) -> dict[str, Any]:
        return {
            "role": role,
            "status": "not_implemented",
            "hint": "shell out to `semgrep --config auto --json` against the repo's host_path",
        }

    @tool(
        "whitebox__iac_scan",
        "Stub: run tfsec / checkov / kube-linter against an indexed IaC asset.",
        {
            "type": "object",
            "properties": {"kind": {"type": "string", "enum": ["terraform", "kubernetes"]}},
            "required": ["kind"],
        },
    )
    async def iac_scan(kind: str) -> dict[str, Any]:
        return {
            "kind": kind,
            "status": "not_implemented",
            "hint": "tfsec for terraform, kube-linter for kubernetes; outputs normalised to SARIF",
        }

    @tool(
        "whitebox__openapi_diff",
        "Stub: compare an OpenAPI spec to live endpoint discovery to surface undocumented endpoints.",
        {"type": "object", "properties": {}},
    )
    async def openapi_diff() -> dict[str, Any]:
        return {
            "status": "not_implemented",
            "hint": "parse spec entries from assets.specs[kind=openapi]; cross-ref with web pack discovery",
        }

    @tool(
        "whitebox__sbom_query",
        "Stub: query a CycloneDX/SPDX SBOM for components matching CVE / package name.",
        {
            "type": "object",
            "properties": {"package": {"type": "string"}},
            "required": ["package"],
        },
    )
    async def sbom_query(package: str) -> dict[str, Any]:
        return {
            "package": package,
            "status": "not_implemented",
            "hint": "load CycloneDX JSON from assets.artefacts[kind=cyclonedx]",
        }

    @tool(
        "whitebox__dependency_audit",
        "Stub: run language-native dependency audit (pip-audit, npm audit, etc.) over a source repo.",
        {
            "type": "object",
            "properties": {"role": {"type": "string"}},
            "required": ["role"],
        },
    )
    async def dependency_audit(role: str) -> dict[str, Any]:
        return {
            "role": role,
            "status": "not_implemented",
            "hint": "dispatch on language metadata; never modifies the repo",
        }

    return create_sdk_mcp_server(
        name="whitebox",
        version="0.1.0",
        tools=[
            list_assets,
            repo_grep,
            repo_read,
            semgrep_scan,
            iac_scan,
            openapi_diff,
            sbom_query,
            dependency_audit,
        ],
    )
