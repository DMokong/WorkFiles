"""recon - offline-only OSINT helpers + `gh` CLI wrappers.

DNS, whois, certificate transparency. Plus thin, **read-only** wrappers
around the `gh` CLI baked into the runtime image (authenticated via a PAT
mounted at /run/secrets/gh_token) for GitHub-side recon. No vendor OSINT
APIs by default; Shodan/VirusTotal are a separate opt-in extras module
under redteam.tools.recon_extras (not loaded automatically).

GitHub is reached via `gh`, never a GitHub MCP (a deliberate v1 tradeoff -
see CLAUDE.md). Security posture of the gh_* tools:
  - **Read-only.** Only search / view (no issue/gist/PR create, no clone).
  - **Org-scoped per call.** Every search requires an explicit `owner`
    (org/user); there is no unqualified, all-of-GitHub query. When the
    engagement sets `scope.github_orgs`, `owner` is *enforced* to be one of
    them (the real engagement-level binding). Query strings carrying a
    scope-broadening GitHub qualifier (`org:` / `owner:` / `user:` / `repo:`)
    are refused so a query can't escape `--owner`. When `github_orgs` is
    empty, any owner is allowed and the mounted PAT's scope is the boundary.
  - **No shell.** `gh` is invoked with a list argv; owner/repo/query are
    validated (GitHub login/repo grammar; leading-`-` rejected) so a value
    can't be smuggled in as a flag or a shell metacharacter.
  - **Total.** A missing binary / non-zero exit / timeout / non-JSON output /
    non-integer limit degrades to a structured ``{"status": "error", ...}``
    dict, never a raise.
The scope guard treats them as targetless (they don't hit engagement scope
targets); see redteam/hooks/scope_guard.py::_TARGETLESS_TOOLS.
"""

from __future__ import annotations

import json
import re
import shutil
import socket
import subprocess
from typing import Any

from ._context import ToolContext
from ._sdk_shim import create_sdk_mcp_server, tool

PACK_NAME = "recon"

_GH_TIMEOUT_S = 30.0
# GitHub login (org/user) grammar: alphanumeric or single hyphens, <=39 chars.
# `\Z` (not `$`) so a trailing newline can't sneak past the anchor.
_OWNER_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38}\Z")
# owner/repo: owner as above, repo is [A-Za-z0-9._-], <=100 chars.
_REPO_RE = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38}/[A-Za-z0-9._-]{1,100}\Z"
)
# GitHub search qualifiers that RESELECT scope (vs. narrow within it). A query
# carrying one of these could return results outside the requested --owner.
_SCOPE_QUALIFIER_RE = re.compile(r"(?i)\b(?:org|owner|user|repo):")


def _gh_bin() -> str | None:
    return shutil.which("gh")


def _run_gh(args: list[str], timeout: float = _GH_TIMEOUT_S) -> dict[str, Any]:
    """Run `gh <args>` with a list argv (no shell). Never raises.

    Returns ``{"status": "ok", "stdout": ...}`` or a structured error.
    """
    gh = _gh_bin()
    if gh is None:
        return {
            "status": "error",
            "error": "gh CLI not found on PATH (recon GitHub tools need the "
            "runtime image's `gh`, authenticated via /run/secrets/gh_token)",
        }
    try:
        proc = subprocess.run(
            [gh, *args],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {"status": "error", "error": f"gh timed out after {timeout:.0f}s"}
    except OSError as e:  # binary vanished between which() and exec, perms, ...
        return {"status": "error", "error": f"gh invocation failed: {e}"}
    if proc.returncode != 0:
        return {
            "status": "error",
            "exit_code": proc.returncode,
            "stderr": (proc.stderr or "").strip()[:2000],
        }
    return {"status": "ok", "stdout": proc.stdout or ""}


def _parse_json_output(res: dict[str, Any]) -> dict[str, Any]:
    """Parse a `_run_gh` result's stdout as JSON, or pass the error through."""
    if res.get("status") != "ok":
        return res
    try:
        return {"status": "ok", "data": json.loads(res["stdout"] or "[]")}
    except (json.JSONDecodeError, ValueError) as e:
        return {"status": "error", "error": f"could not parse gh JSON output: {e}"}


def _valid_query(q: str) -> bool:
    # A leading '-' would be read as a gh flag; also require some content.
    return bool(q) and q.strip() != "" and not q.startswith("-")


def _clamp_limit(limit: Any) -> int | None:
    """Coerce+clamp a limit to 1..100, or None if it isn't an integer."""
    try:
        n = int(limit)
    except (TypeError, ValueError):
        return None
    return max(1, min(n, 100))


def _owner_allowed(engagement: Any, owner: str) -> bool:
    """True if `owner` is permitted by the engagement's github_orgs allowlist.

    Empty allowlist -> any owner (PAT-bound). Case-insensitive membership.
    """
    allow = getattr(engagement.scope, "github_orgs", []) or []
    if not allow:
        return True
    return owner.lower() in {o.lower() for o in allow}


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

    @tool(
        "recon__gh_search_code",
        "Search code across a GitHub org/user via the `gh` CLI (read-only). "
        "`owner` is required so the search is org-scoped, never global.",
        {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "code search query"},
                "owner": {"type": "string", "description": "GitHub org/user to scope to"},
                "limit": {"type": "integer", "default": 30, "minimum": 1, "maximum": 100},
            },
            "required": ["query", "owner"],
        },
    )
    async def gh_search_code(query: str, owner: str, limit: int = 30) -> dict[str, Any]:
        ctx.assert_in_scope("recon__gh_search_code", {"query": query, "owner": owner})
        if not _OWNER_RE.match(owner):
            return {"status": "error", "error": f"invalid owner {owner!r}"}
        if not _owner_allowed(ctx.engagement, owner):
            return {"status": "error", "error": f"owner {owner!r} not in engagement scope.github_orgs"}
        if not _valid_query(query):
            return {"status": "error", "error": "query must be non-empty and not start with '-'"}
        if _SCOPE_QUALIFIER_RE.search(query):
            return {"status": "error", "error": "query may not carry an org:/owner:/user:/repo: qualifier"}
        n = _clamp_limit(limit)
        if n is None:
            return {"status": "error", "error": "limit must be an integer"}
        res = _parse_json_output(
            _run_gh(
                ["search", "code", query, "--owner", owner, "--limit", str(n),
                 "--json", "path,repository,textMatches,url"]
            )
        )
        if res.get("status") != "ok":
            return res
        data = res["data"]
        return {"status": "ok", "owner": owner, "query": query, "count": len(data), "results": data}

    @tool(
        "recon__gh_search_repos",
        "Find repositories owned by a GitHub org/user via `gh` (read-only). "
        "`owner` is required; `query` is optional free text.",
        {
            "type": "object",
            "properties": {
                "owner": {"type": "string", "description": "GitHub org/user to scope to"},
                "query": {"type": "string", "description": "optional repo search terms"},
                "limit": {"type": "integer", "default": 30, "minimum": 1, "maximum": 100},
            },
            "required": ["owner"],
        },
    )
    async def gh_search_repos(owner: str, query: str = "", limit: int = 30) -> dict[str, Any]:
        ctx.assert_in_scope("recon__gh_search_repos", {"owner": owner})
        if not _OWNER_RE.match(owner):
            return {"status": "error", "error": f"invalid owner {owner!r}"}
        if not _owner_allowed(ctx.engagement, owner):
            return {"status": "error", "error": f"owner {owner!r} not in engagement scope.github_orgs"}
        if query and query.startswith("-"):
            return {"status": "error", "error": "query must not start with '-'"}
        if query and _SCOPE_QUALIFIER_RE.search(query):
            return {"status": "error", "error": "query may not carry an org:/owner:/user:/repo: qualifier"}
        n = _clamp_limit(limit)
        if n is None:
            return {"status": "error", "error": "limit must be an integer"}
        args = ["search", "repos", "--owner", owner, "--limit", str(n),
                "--json", "fullName,description,visibility,updatedAt,url"]
        if query:
            args.append(query)
        res = _parse_json_output(_run_gh(args))
        if res.get("status") != "ok":
            return res
        data = res["data"]
        return {"status": "ok", "owner": owner, "count": len(data), "results": data}

    @tool(
        "recon__gh_repo_view",
        "View a single repository's metadata via `gh repo view` (read-only). "
        "`repo` must be in `owner/name` form.",
        {
            "type": "object",
            "properties": {
                "repo": {"type": "string", "description": "repository as owner/name"},
            },
            "required": ["repo"],
        },
    )
    async def gh_repo_view(repo: str) -> dict[str, Any]:
        ctx.assert_in_scope("recon__gh_repo_view", {"repo": repo})
        if not _REPO_RE.match(repo):
            return {"status": "error", "error": f"repo must be owner/name, got {repo!r}"}
        owner = repo.split("/", 1)[0]
        if not _owner_allowed(ctx.engagement, owner):
            return {"status": "error", "error": f"owner {owner!r} not in engagement scope.github_orgs"}
        res = _parse_json_output(
            _run_gh(
                ["repo", "view", repo, "--json",
                 "name,description,visibility,defaultBranchRef,pushedAt,url,languages,isArchived"]
            )
        )
        if res.get("status") != "ok":
            return res
        return {"status": "ok", "repo": res["data"]}

    return create_sdk_mcp_server(
        name="recon",
        version="0.1.0",
        tools=[
            dns_lookup,
            whois,
            cert_transparency,
            gh_search_code,
            gh_search_repos,
            gh_repo_view,
        ],
    )
