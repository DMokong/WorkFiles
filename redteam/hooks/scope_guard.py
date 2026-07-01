"""Scope guard - PreToolUse hook that denies out-of-scope tool calls.

Defence-in-depth model: this hook is the *gate* (refuses execution before
it starts), and tool packs run their own scope check inside their handler
as the *lock*. Both must agree before a tool call lands at its target.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import unquote, urlparse

from ..engagement import Engagement


def _strip_mcp_prefix(tool_name: str) -> str:
    """Strip the SDK's ``mcp__<server>__`` prefix from a tool name.

    The Agent SDK exposes in-process MCP tools to hooks as
    ``mcp__<server>__<tool>``. Because our ``@tool`` names already embed the
    pack prefix (e.g. ``whitebox__repo_read``), the delivered name is
    ``mcp__whitebox__whitebox__repo_read``. We normalise back to the registered
    tool name so the targetless allowlist and pack-level reasoning still match.
    """
    if tool_name.startswith("mcp__"):
        parts = tool_name.split("__")
        if len(parts) >= 3:
            return "__".join(parts[2:])
    return tool_name


def _canonical_path(path: str) -> str:
    """Canonicalise a URL path for prefix matching.

    Normalises the many ways HTTP servers treat as equivalent, so an
    out_of_scope deny rule cannot be evaded by rewriting the path. Defeats:
    percent-encoding (including multiple layers), backslashes, duplicate
    slashes, ``.``/``..`` segments, null-byte/semicolon truncation, and
    trailing dots/spaces on a segment (Windows/Apache/IIS strip these). Over-
    normalising is safe here: it can only make a deny rule match *more*.
    """
    prev = None
    cur = path or "/"
    # Repeatedly percent-decode to defeat double/triple encoding.
    for _ in range(8):
        if cur == prev:
            break
        prev = cur
        cur = unquote(cur)
    cur = cur.replace("\\", "/")  # some servers treat \ as a path separator
    parts: list[str] = []
    for raw in cur.split("/"):
        seg = raw.split("\x00", 1)[0]  # null-byte truncation
        seg = seg.split(";", 1)[0]  # path parameters (e.g. /admin;jsessionid=..)
        if seg in ("", "."):
            continue
        if seg == "..":
            if parts:
                parts.pop()
            continue
        seg = seg.rstrip(". ")  # trailing dots/spaces server-side stripping
        if not seg:
            continue
        parts.append(seg)
    return ("/" + "/".join(parts)).lower()


@dataclass(frozen=True)
class ScopeDecision:
    allowed: bool
    reason: str
    matched_target: str | None = None


# Tool input keys that may contain a target URL/host/CIDR. We probe these
# in order; first match wins. Tools we author always use one of these names.
_TARGET_KEYS = ("url", "target", "host", "endpoint", "address", "cidr")


class ScopeGuard:
    """Wraps an Engagement and answers "is this tool call in scope?"."""

    def __init__(self, engagement: Engagement):
        self.engagement = engagement
        self._target_matchers = [_compile_matcher(t) for t in engagement.scope.targets]
        self._deny_matchers = [_compile_matcher(t) for t in engagement.scope.out_of_scope]
        self._egress_hosts = {h.lower() for h in engagement.scope.egress_allowlist}

    def check(self, tool_name: str, tool_input: dict[str, Any]) -> ScopeDecision:
        # Pull a candidate target from common input keys.
        candidate = _extract_target(tool_input)

        if candidate is None:
            # No target field - allow only if the tool is explicitly target-less.
            # For unknown tools without a target, deny by default. Normalise the
            # SDK's mcp__<server>__ prefix before consulting the allowlist.
            if _is_targetless_tool(_strip_mcp_prefix(tool_name)):
                return ScopeDecision(True, "targetless tool, allowed by policy")
            return ScopeDecision(
                False,
                f"tool {tool_name!r} called without a target field; expected one of {list(_TARGET_KEYS)}",
            )

        # 1. out_of_scope deny wins.
        for matcher in self._deny_matchers:
            if matcher.matches(candidate):
                return ScopeDecision(
                    False,
                    f"target {candidate!r} hits out_of_scope rule {matcher.spec!r}",
                    matched_target=matcher.spec,
                )

        # 2. must match a target rule.
        for matcher in self._target_matchers:
            if matcher.matches(candidate):
                # 3. for URL targets, additionally check egress allowlist.
                # An empty egress_allowlist means deny-all egress except the
                # scope targets themselves - it must NOT short-circuit the check.
                host = _candidate_host(candidate)
                if (
                    host
                    and host.lower() not in self._egress_hosts
                    and not any(m.matches(host) for m in self._target_matchers)
                ):
                    return ScopeDecision(
                        False,
                        f"host {host!r} not in egress_allowlist",
                        matched_target=matcher.spec,
                    )
                return ScopeDecision(
                    True,
                    f"matched target {matcher.spec!r}",
                    matched_target=matcher.spec,
                )

        return ScopeDecision(False, f"target {candidate!r} not in scope.targets")


def _extract_target(tool_input: dict[str, Any]) -> str | None:
    for key in _TARGET_KEYS:
        v = tool_input.get(key)
        if isinstance(v, str) and v:
            return v
    return None


def _candidate_host(candidate: str) -> str | None:
    if "://" in candidate:
        return urlparse(candidate).hostname
    return None


# Targetless tools that legitimately have no scope - report writers, in-process
# helpers that operate purely on already-fetched data, etc. Conservative list.
_TARGETLESS_TOOLS = frozenset(
    {
        "report__write_finding",
        # recon GitHub tools reach github.com via the authenticated `gh` CLI,
        # not an engagement scope target; they are read-only + org-scoped
        # per call (see redteam/tools/recon.py).
        "recon__gh_search_code",
        "recon__gh_search_repos",
        "recon__gh_repo_view",
        "whitebox__list_assets",
        "whitebox__repo_grep",
        "whitebox__repo_read",
        "whitebox__semgrep_scan",
        "whitebox__iac_scan",
        "whitebox__openapi_diff",
        "whitebox__sbom_query",
        "whitebox__dependency_audit",
    }
)


def _is_targetless_tool(name: str) -> bool:
    return name in _TARGETLESS_TOOLS


@dataclass(frozen=True)
class _Matcher:
    spec: str

    def matches(self, candidate: str) -> bool:
        raise NotImplementedError


@dataclass(frozen=True)
class _UrlPrefixMatcher(_Matcher):
    scheme: str = ""
    host: str = ""
    path_prefix: str = ""

    def matches(self, candidate: str) -> bool:
        if "://" in candidate:
            parsed = urlparse(candidate)
            if self.scheme and parsed.scheme != self.scheme:
                return False
            if parsed.hostname != self.host:
                return False
            return _canonical_path(parsed.path).startswith(self.path_prefix)
        return candidate.lower() == self.host.lower()


@dataclass(frozen=True)
class _CidrMatcher(_Matcher):
    network: ipaddress._BaseNetwork = None  # type: ignore[assignment]

    def matches(self, candidate: str) -> bool:
        host = _candidate_host(candidate) or candidate
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            return False
        return ip in self.network  # type: ignore[operator]


@dataclass(frozen=True)
class _HostMatcher(_Matcher):
    host: str = ""

    def matches(self, candidate: str) -> bool:
        target_host = _candidate_host(candidate) or candidate
        return target_host.lower() == self.host.lower()


_HOSTNAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9\-\.]{0,252}$")


def _compile_matcher(spec: str) -> _Matcher:
    if "://" in spec:
        parsed = urlparse(spec)
        return _UrlPrefixMatcher(
            spec=spec,
            scheme=parsed.scheme,
            host=parsed.hostname or "",
            path_prefix=_canonical_path(parsed.path),
        )
    try:
        net = ipaddress.ip_network(spec, strict=False)
        return _CidrMatcher(spec=spec, network=net)
    except ValueError:
        if not _HOSTNAME_RE.match(spec):
            raise ValueError(f"unrecognised scope spec: {spec!r}")
        return _HostMatcher(spec=spec, host=spec)
