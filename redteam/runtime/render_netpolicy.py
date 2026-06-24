"""Render ``scope.egress_allowlist`` into an nftables default-deny ruleset.

The container starts with no egress policy; the entrypoint pipes this module's
stdout into ``nft -f -`` (as root, before dropping privileges) so the run is
boxed by an in-kernel allow-list. The module *consumes* ``netpolicy.json`` --
the deny-by-default template that pins the always-allowed endpoints, the
metadata endpoints that must never be reachable, and the ``from_engagement``
selectors that pull the per-engagement allow-list out of the YAML.

Security invariants (do not relax without an explicit request -- CLAUDE.md #2/#3
and the deny-wins model):

* The egress chain policy is ``drop`` (default-deny). An empty or absent
  ``egress_allowlist`` yields default-deny + always_allow, never an open chain.
* The ``deny_egress`` endpoints (cloud metadata / IMDS) are dropped *before*
  any accept and are scrubbed from the allow set, so IMDS stays unreachable
  even if an allow-list entry resolves onto it -- the RT-01 SSRF vector.

Known limitations (defence-in-depth; the host network policy / security group is
the durable backstop):

* Hostnames are resolved to addresses at render time, so an address set baked at
  startup can drift if a CDN rotates IPs.
* DNS (udp/tcp port 53) is accepted to any destination so allow-listed hostnames
  resolve. That leaves a covert channel (data smuggled in QNAMEs to an
  attacker-controlled nameserver). Pinning DNS to the container's resolver is a
  v-next hardening; it is environment-fragile (embedded Docker DNS, etc.).
"""

from __future__ import annotations

import ipaddress
import json
import socket
import sys
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any

import yaml

Resolver = Callable[[str], list[str]]

_TABLE = "redteam"


def _safe_comment(text: str, limit: int = 120) -> str:
    """Neutralise a value before it goes into a ``#`` comment line.

    The renderer runs in the entrypoint on the *raw* engagement YAML (before the
    CLI's pydantic + signature checks), so an allow-list entry is attacker-shaped
    input here. Strip anything that could break out of a single comment line into
    top-level nft syntax (newlines, control chars) and bound the length.
    """
    cleaned = "".join(ch if (ch.isprintable() and ch not in "\r\n") else " " for ch in text)
    if len(cleaned) > limit:
        cleaned = cleaned[:limit] + "..."
    return cleaned


def default_resolver(host: str) -> list[str]:
    """Resolve ``host`` to a de-duplicated list of A/AAAA addresses.

    Raises ``OSError`` (like ``socket.getaddrinfo``) when the name does not
    resolve; callers are expected to skip such hosts rather than fail the run.
    """
    infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    addrs: list[str] = []
    for info in infos:
        addr = info[4][0]
        if addr not in addrs:
            addrs.append(addr)
    return addrs


# ---------------------------------------------------------------- from_engagement
def select_from_engagement(expr: str, engagement: dict) -> list[str]:
    """Evaluate one minimal JSONPath selector against ``engagement``.

    Supports exactly the shapes used by ``netpolicy.json``: ``$.a.b`` (scalar)
    and ``$.a.b[*]`` (iterate a list). Anything missing yields ``[]`` rather
    than raising -- a netpolicy that names a field the engagement omits should
    contribute nothing, not crash the boot.
    """
    if not expr.startswith("$."):
        return []
    body = expr[2:]
    iterate = body.endswith("[*]")
    if iterate:
        body = body[: -len("[*]")]

    node: Any = engagement
    for key in body.split("."):
        if not isinstance(node, dict) or key not in node:
            return []
        node = node[key]

    if iterate:
        if not isinstance(node, list):
            return []
        return [str(v) for v in node]
    if isinstance(node, (list, dict)):
        return []
    return [str(node)]


def engagement_egress_hosts(netpolicy: dict, engagement: dict) -> list[str]:
    """Flatten every ``from_engagement`` selector into an ordered host list."""
    hosts: list[str] = []
    for expr in netpolicy.get("from_engagement", []):
        for host in select_from_engagement(expr, engagement):
            if host not in hosts:
                hosts.append(host)
    return hosts


# ---------------------------------------------------------------- classification
def _classify(entry: str) -> str:
    """Bucket an allow-list entry: ipv4 / ipv6 / cidr4 / cidr6 / hostname."""
    if "/" in entry:
        try:
            net = ipaddress.ip_network(entry, strict=False)
        except ValueError:
            return "hostname"
        return "cidr6" if net.version == 6 else "cidr4"
    try:
        ip = ipaddress.ip_address(entry)
    except ValueError:
        return "hostname"
    return "ipv6" if ip.version == 6 else "ipv4"


def _collapse(entries: Iterable[str]) -> list[str]:
    """Collapse a same-family list of IPs/CIDRs into non-overlapping networks.

    nft rejects overlapping or duplicate elements in a ``flags interval`` set, so
    an allow-list that names a host and its CIDR (or nested CIDRs, or a bare IP
    and its /32) would otherwise make ``nft -f`` fail and brick the boot. Bare
    addresses become /32 (or /128) networks; ``collapse_addresses`` then merges
    overlaps and adjacencies. Non-IP entries (shouldn't occur here) pass through.
    """
    nets = []
    passthrough: list[str] = []
    for entry in entries:
        try:
            nets.append(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            passthrough.append(entry)
    return [str(n) for n in ipaddress.collapse_addresses(nets)] + passthrough


def _resolve_entries(
    entries: Iterable[str],
    resolver: Resolver,
    deny: set[ipaddress._BaseAddress],
    notes: list[str],
) -> tuple[list[str], list[str]]:
    """Map allow-list entries to (ipv4-or-cidr4, ipv6-or-cidr6) element lists.

    Literal addresses/CIDRs pass through untouched; hostnames are resolved.
    Any address equal to an IMDS endpoint in ``deny`` is dropped on the floor
    here -- belt to the explicit drop rules' suspenders. The comparison parses
    addresses, so a non-canonical spelling of the metadata IP is still caught.
    Unresolvable hostnames are skipped and recorded in ``notes``.
    """
    v4: list[str] = []
    v6: list[str] = []

    def _add(addr: str) -> None:
        bare = addr.split("/")[0]
        try:
            parsed = ipaddress.ip_address(bare)
        except ValueError:
            parsed = None
        if parsed is not None and parsed in deny:
            notes.append(f"refused metadata address in allow-list: {addr}")
            return
        kind = _classify(addr)
        bucket = v6 if kind in ("ipv6", "cidr6") else v4
        if addr not in bucket:
            bucket.append(addr)

    for entry in entries:
        kind = _classify(entry)
        if kind in ("ipv4", "ipv6", "cidr4", "cidr6"):
            _add(entry)
            continue
        try:
            resolved = resolver(entry)
        except OSError as exc:
            notes.append(f"unresolved host skipped: {entry} ({exc})")
            continue
        if not resolved:
            notes.append(f"unresolved host skipped: {entry} (no addresses)")
            continue
        for addr in resolved:
            _add(addr)
    return v4, v6


# ---------------------------------------------------------------- render
def render_nft(
    netpolicy: dict,
    engagement: dict,
    *,
    resolver: Resolver | None = None,
) -> str:
    """Return an ``nft -f`` ruleset enforcing default-deny egress."""
    resolver = resolver or default_resolver

    deny_entries = list(netpolicy.get("deny_egress", []))
    deny_set: set[ipaddress._BaseAddress] = set()
    for entry in deny_entries:
        try:
            deny_set.add(ipaddress.ip_address(entry.split("/")[0]))
        except ValueError:
            continue

    allow_hosts: list[str] = []
    for host in list(netpolicy.get("always_allow", [])) + engagement_egress_hosts(
        netpolicy, engagement
    ):
        if host not in allow_hosts:
            allow_hosts.append(host)

    notes: list[str] = []
    v4, v6 = _resolve_entries(allow_hosts, resolver, deny_set, notes)
    # Collapse each family so the interval sets carry no overlapping elements.
    v4 = _collapse(v4)
    v6 = _collapse(v6)

    deny_v4 = [e for e in deny_entries if _classify(e) in ("ipv4", "cidr4")]
    deny_v6 = [e for e in deny_entries if _classify(e) in ("ipv6", "cidr6")]

    lines: list[str] = []
    lines.append("#!/usr/sbin/nft -f")
    lines.append("# Rendered by redteam.runtime.render_netpolicy -- DO NOT EDIT BY HAND.")
    lines.append(f"# policy={netpolicy.get('policy', 'default-deny')}")
    for host in allow_hosts:
        lines.append(f"#   allow-host: {_safe_comment(host)}")
    for note in notes:
        lines.append(f"#   note: {_safe_comment(note)}")
    lines.append("")
    lines.append("flush ruleset")
    lines.append("")
    lines.append(f"table inet {_TABLE} {{")

    # Named sets keep the chain compact and let nft do longest-prefix matching.
    lines.append("    set allowed_v4 {")
    lines.append("        type ipv4_addr")
    lines.append("        flags interval")
    if v4:
        lines.append("        elements = { " + ", ".join(v4) + " }")
    lines.append("    }")
    lines.append("    set allowed_v6 {")
    lines.append("        type ipv6_addr")
    lines.append("        flags interval")
    if v6:
        lines.append("        elements = { " + ", ".join(v6) + " }")
    lines.append("    }")
    lines.append("")
    lines.append("    chain output {")
    lines.append("        type filter hook output priority 0; policy drop;")
    lines.append("        # deny-wins: metadata endpoints dropped before ANY accept (RT-01)")
    for entry in deny_v4:
        lines.append(f"        ip daddr {entry} drop")
    for entry in deny_v6:
        lines.append(f"        ip6 daddr {entry} drop")
    lines.append("        # infrastructure: loopback, established flows, DNS resolution")
    lines.append('        oif "lo" accept')
    lines.append("        ct state established,related accept")
    lines.append("        udp dport 53 accept")
    lines.append("        tcp dport 53 accept")
    lines.append("        # allow-listed destinations (always_allow + engagement egress)")
    if v4:
        lines.append("        ip daddr @allowed_v4 accept")
    if v6:
        lines.append("        ip6 daddr @allowed_v6 accept")
    lines.append('        log prefix "redteam-egress-drop " flags all counter')
    lines.append("        # everything else hits policy drop")
    lines.append("    }")
    lines.append("}")
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------- CLI
_USAGE = "usage: python -m redteam.runtime.render_netpolicy <netpolicy.json> <engagement.yaml>"


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 2:
        print(_USAGE, file=sys.stderr)
        return 64
    netpolicy_path, engagement_path = Path(args[0]), Path(args[1])
    try:
        netpolicy = json.loads(netpolicy_path.read_text())
        engagement = yaml.safe_load(engagement_path.read_text()) or {}
    except (OSError, ValueError) as exc:
        print(f"render_netpolicy: cannot read inputs: {exc}", file=sys.stderr)
        return 65
    if not isinstance(engagement, dict):
        print("render_netpolicy: engagement YAML is not a mapping", file=sys.stderr)
        return 65
    sys.stdout.write(render_nft(netpolicy, engagement))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
