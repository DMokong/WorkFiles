"""Regression tests for RT-23: container egress netpolicy rendering.

RT-23 has container-only parts (writable HOME, gosu drop, tmpfs) that are
exercised by the docker smoke check, not pytest. The *render* logic, however,
is pure and security-critical, so it lives in `redteam.runtime.render_netpolicy`
and is pinned here:

- the egress chain is default-deny (`policy drop`);
- the cloud-metadata endpoints (IMDS) are dropped BEFORE any accept and are
  never added to the allow set, so they stay unreachable even if an allow-list
  entry resolves to them (the RT-01 vector);
- an empty/absent egress_allowlist still yields default-deny + always_allow,
  never an open chain (RT-07 spirit);
- the template's `from_engagement` JSONPath selectors are evaluated against the
  engagement YAML, so `netpolicy.json` is actually consumed.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from redteam.runtime import render_netpolicy as rnp

REPO_ROOT = Path(__file__).resolve().parent.parent
NETPOLICY = json.loads((REPO_ROOT / "redteam" / "runtime" / "netpolicy.json").read_text())


def _fake_resolver(mapping: dict[str, list[str]]):
    """A DNS-free resolver: returns mapping[host], or raises like getaddrinfo."""

    def resolve(host: str) -> list[str]:
        if host not in mapping:
            raise OSError(f"name resolution failed for {host}")
        return mapping[host]

    return resolve


def _allowed_elements(out: str, set_name: str) -> list[str]:
    """Extract the element list of an `allowed_v4`/`allowed_v6` set from output."""
    lines = out.splitlines()
    for i, line in enumerate(lines):
        if line.strip() == f"set {set_name} {{":
            for body in lines[i:]:
                stripped = body.strip()
                if stripped.startswith("elements = {"):
                    inner = stripped[stripped.index("{") + 1 : stripped.rindex("}")]
                    return [e.strip() for e in inner.split(",") if e.strip()]
                if stripped == "}":
                    return []
    return []


def _render(engagement: dict, mapping: dict[str, list[str]] | None = None, netpolicy=None) -> str:
    mapping = mapping or {}
    return rnp.render_nft(
        netpolicy if netpolicy is not None else NETPOLICY,
        engagement,
        resolver=_fake_resolver(mapping),
    )


# ---------------------------------------------------------------- from_engagement
class TestFromEngagement:
    def test_extracts_egress_allowlist(self):
        eng = {"scope": {"egress_allowlist": ["a.example.com", "b.example.com"]}}
        assert rnp.engagement_egress_hosts(NETPOLICY, eng) == ["a.example.com", "b.example.com"]

    def test_missing_scope_yields_empty(self):
        assert rnp.engagement_egress_hosts(NETPOLICY, {}) == []

    def test_empty_allowlist_yields_empty(self):
        eng = {"scope": {"egress_allowlist": []}}
        assert rnp.engagement_egress_hosts(NETPOLICY, eng) == []

    def test_star_selector_on_list(self):
        eng = {"scope": {"egress_allowlist": ["x"]}}
        assert rnp.select_from_engagement("$.scope.egress_allowlist[*]", eng) == ["x"]

    def test_plain_selector_returns_scalar(self):
        eng = {"reporting": {"format": "sarif"}}
        assert rnp.select_from_engagement("$.reporting.format", eng) == ["sarif"]


# ---------------------------------------------------------------- default-deny
class TestDefaultDeny:
    def test_output_chain_policy_is_drop(self):
        out = _render({"scope": {"egress_allowlist": ["a.example.com"]}}, {"a.example.com": ["1.2.3.4"]})
        assert "hook output" in out
        assert "policy drop" in out

    def test_empty_allowlist_still_default_deny_with_always_allow(self):
        # No engagement egress at all: the chain must NOT become permissive, and
        # the template's always_allow (api.anthropic.com) must still be present.
        out = _render({"scope": {"egress_allowlist": []}}, {"api.anthropic.com": ["9.9.9.9"]})
        assert "policy drop" in out
        assert "9.9.9.9" in out  # always_allow resolved and accepted
        assert "0.0.0.0/0 accept" not in out  # never open the chain

    def test_no_egress_section_does_not_crash_and_stays_closed(self):
        out = _render({}, {"api.anthropic.com": ["9.9.9.9"]})
        assert "policy drop" in out


# ---------------------------------------------------------------- IMDS deny-wins
class TestImdsDeny:
    def test_imds_dropped(self):
        out = _render({"scope": {"egress_allowlist": ["a.example.com"]}}, {"a.example.com": ["1.2.3.4"]})
        assert "169.254.169.254" in out
        assert "fd00:ec2::254" in out

    def test_imds_drop_precedes_any_accept(self):
        out = _render({"scope": {"egress_allowlist": ["a.example.com"]}}, {"a.example.com": ["1.2.3.4"]})
        # nft evaluates a chain top-to-bottom; the security property is RULE
        # order, not where a set element is declared. The metadata drop rule must
        # precede the allow-list accept rule so it can never be shadowed.
        drop_idx = out.index("ip daddr 169.254.169.254 drop")
        allow_accept_idx = out.index("ip daddr @allowed_v4 accept")
        assert drop_idx < allow_accept_idx

    def test_imds_denied_even_if_allowlisted(self):
        # An engagement (or a compromised resolver) that maps an allow-listed host
        # onto the metadata IP must NOT open IMDS: the address is excluded from the
        # allow set AND the explicit drop precedes every accept.
        eng = {"scope": {"egress_allowlist": ["sneaky.example.com"]}}
        out = _render(eng, {"sneaky.example.com": ["169.254.169.254"]})
        # IMDS must never appear inside a set `elements = { ... }` (an allow), and
        # in any non-comment rule line it may appear only in a drop rule.
        for line in out.splitlines():
            stripped = line.strip()
            if stripped.startswith("#") or "169.254.169.254" not in line:
                continue
            assert "elements" not in line, f"IMDS leaked into an allow set: {line!r}"
            assert "drop" in line, f"IMDS leaked into a non-drop rule: {line!r}"

    def test_noncanonical_imds_ipv6_refused_from_allow_set(self):
        # The scrub must compare PARSED addresses, not raw strings: an expanded
        # spelling of the metadata IPv6 address is the same host and must never
        # become an allowed_v6 element (defense-in-depth behind the explicit drop).
        eng = {"scope": {"egress_allowlist": ["fd00:ec2:0:0:0:0:0:254"]}}
        out = _render(eng, mapping={})  # literal IPv6 -> no resolver needed
        for elem in _allowed_elements(out, "allowed_v6"):
            addr = elem.split("/")[0]
            assert __import__("ipaddress").ip_address(addr) != __import__("ipaddress").ip_address(
                "fd00:ec2::254"
            ), f"non-canonical IMDS leaked into allow set: {elem}"
        assert "fd00:ec2::254 drop" in out  # explicit drop still present


# ---------------------------------------------------------------- host classification
class TestHostClassification:
    def test_literal_ipv4_passes_without_resolution(self):
        # A bare IP in the allow-list must not be sent to the resolver.
        out = _render({"scope": {"egress_allowlist": ["203.0.113.5"]}}, mapping={})
        assert "203.0.113.5" in out

    def test_cidr_passes_through(self):
        out = _render({"scope": {"egress_allowlist": ["10.20.0.0/24"]}}, mapping={})
        assert "10.20.0.0/24" in out

    def test_ipv6_literal_passes_through(self):
        out = _render({"scope": {"egress_allowlist": ["2606:4700::1"]}}, mapping={})
        assert "2606:4700::1" in out

    def test_malicious_host_cannot_inject_nft_rules(self):
        # The renderer runs in the entrypoint on the RAW engagement YAML, before
        # the CLI's pydantic/signature checks. A crafted egress entry with a
        # newline must not break out of its `#` comment into a top-level nft line
        # that could open the chain.
        evil = "evil\n        ip daddr 0.0.0.0/0 accept"
        out = _render({"scope": {"egress_allowlist": [evil]}}, mapping={})
        # The injected text may survive (neutralised) inside a comment, but never
        # as a non-comment line: every physical line is either a comment or known
        # ruleset syntax, so no bare injected accept can open the chain.
        for line in out.splitlines():
            if line.lstrip().startswith("#"):
                continue
            assert "0.0.0.0/0" not in line
            if "accept" in line:
                assert line.lstrip().startswith(("oif", "ct", "udp", "tcp", "ip daddr @", "ip6 daddr @"))

    def test_overlapping_allow_entries_are_collapsed(self):
        # nft rejects overlapping/duplicate elements in a `flags interval` set, so
        # an operator allow-listing a host AND its CIDR (or nested CIDRs, or a bare
        # IP plus its /32) must not brick the boot. The renderer must collapse the
        # bucket into non-overlapping elements.
        eng = {"scope": {"egress_allowlist": ["10.20.0.0/16", "10.20.0.0/24", "10.20.0.5", "api.x"]}}
        out = _render(eng, {"api.x": ["10.20.0.7"], "api.anthropic.com": ["9.9.9.9"]})
        elems = _allowed_elements(out, "allowed_v4")
        nets = [__import__("ipaddress").ip_network(e, strict=False) for e in elems]
        collapsed = list(__import__("ipaddress").collapse_addresses(nets))
        assert nets == collapsed, f"overlapping elements emitted: {elems}"
        # the /16 should have absorbed the /24, the .5 and the resolved .7
        assert any(str(n) == "10.20.0.0/16" for n in nets)
        assert not any(str(n) == "10.20.0.0/24" for n in nets)

    def test_bare_ip_and_its_slash32_do_not_both_appear(self):
        eng = {"scope": {"egress_allowlist": ["1.2.3.4", "1.2.3.4/32"]}}
        out = _render(eng, {"api.anthropic.com": ["9.9.9.9"]})
        elems = _allowed_elements(out, "allowed_v4")
        bare = [e for e in elems if e.split("/")[0] == "1.2.3.4"]
        assert len(bare) == 1, f"duplicate singleton emitted: {elems}"

    def test_unresolvable_host_skipped_not_crashed(self):
        # b.example.com is absent from the resolver mapping -> getaddrinfo raises.
        # The render must skip it (with a comment) and still emit a valid ruleset.
        out = _render(
            {"scope": {"egress_allowlist": ["a.example.com", "b.example.com"]}},
            {"a.example.com": ["1.2.3.4"]},
        )
        assert "1.2.3.4" in out
        assert "policy drop" in out
        assert "b.example.com" in out  # noted as a skipped/unresolved comment


# ---------------------------------------------------------------- CLI entrypoint
class TestCli:
    def test_module_runs_and_emits_ruleset(self, tmp_path: Path):
        eng = tmp_path / "eng.yaml"
        eng.write_text("scope:\n  egress_allowlist:\n    - 203.0.113.5\n")
        np = tmp_path / "netpolicy.json"
        np.write_text(json.dumps(NETPOLICY))
        proc = subprocess.run(
            [sys.executable, "-m", "redteam.runtime.render_netpolicy", str(np), str(eng)],
            capture_output=True,
            text=True,
            cwd=REPO_ROOT,
        )
        assert proc.returncode == 0, proc.stderr
        assert "policy drop" in proc.stdout
        assert "203.0.113.5" in proc.stdout
        assert "169.254.169.254" in proc.stdout

    def test_bad_args_nonzero(self):
        proc = subprocess.run(
            [sys.executable, "-m", "redteam.runtime.render_netpolicy"],
            capture_output=True,
            text=True,
            cwd=REPO_ROOT,
        )
        assert proc.returncode != 0
