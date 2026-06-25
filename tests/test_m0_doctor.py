"""M0: readiness checks for `redteam doctor`.

M0 unblocks a real engagement by making the agent loop *runnable*: the Claude
Agent SDK spawns the `claude` CLI as its transport, so the container must ship
that binary and the harness must be able to (a) find it and (b) tell, without
spending a token, whether the run can reach a model backend. These pure checks
back the `redteam doctor` command; the live spawn-to-auth probe is a thin
wrapper over the SDK whose *error classification* is pinned here.
"""

from __future__ import annotations

from redteam import preflight


# ---------------------------------------------------------------- backend
class TestDetectBackend:
    def test_anthropic_api_key(self):
        r = preflight.detect_backend({"ANTHROPIC_API_KEY": "sk-ant-xxx"})
        assert r.backend == "anthropic_api_key"
        assert r.ready is True
        assert r.missing == []

    def test_no_backend(self):
        r = preflight.detect_backend({})
        assert r.backend == "none"
        assert r.ready is False

    def test_bedrock_uses_aws_chain(self):
        # CLAUDE_CODE_USE_BEDROCK selects Bedrock; creds come from the AWS chain
        # at runtime (we can't verify them here), so ready is True with a note.
        r = preflight.detect_backend({"CLAUDE_CODE_USE_BEDROCK": "1", "AWS_REGION": "us-east-1"})
        assert r.backend == "bedrock"
        assert r.ready is True

    def test_bedrock_overrides_api_key(self):
        # ANTHROPIC_API_KEY is IGNORED once a cloud backend is selected, so the
        # detected backend must be bedrock, not anthropic_api_key.
        r = preflight.detect_backend({"CLAUDE_CODE_USE_BEDROCK": "1", "ANTHROPIC_API_KEY": "sk-x"})
        assert r.backend == "bedrock"

    def test_vertex_requires_project(self):
        r = preflight.detect_backend({"CLAUDE_CODE_USE_VERTEX": "1"})
        assert r.backend == "vertex"
        assert r.ready is False
        assert "ANTHROPIC_VERTEX_PROJECT_ID" in r.missing

    def test_vertex_ready_with_project(self):
        r = preflight.detect_backend(
            {"CLAUDE_CODE_USE_VERTEX": "true", "ANTHROPIC_VERTEX_PROJECT_ID": "p", "CLOUD_ML_REGION": "global"}
        )
        assert r.backend == "vertex"
        assert r.ready is True
        assert r.missing == []

    def test_truthy_values(self):
        for v in ("1", "true", "TRUE", "yes"):
            assert preflight.detect_backend({"CLAUDE_CODE_USE_BEDROCK": v}).backend == "bedrock"
        for v in ("0", "false", "", "no"):
            assert preflight.detect_backend({"CLAUDE_CODE_USE_BEDROCK": v}).backend == "none"


# ---------------------------------------------------------------- version
class TestCliVersion:
    def test_meets_minimum(self):
        assert preflight.cli_version_ok("2.1.191") is True
        assert preflight.cli_version_ok("2.0.0") is True

    def test_below_minimum(self):
        assert preflight.cli_version_ok("1.9.9") is False

    def test_unparseable_is_not_ok(self):
        assert preflight.cli_version_ok("") is False
        assert preflight.cli_version_ok("garbage") is False

    def test_extracts_from_v_output(self):
        # `claude -v` prints e.g. "2.1.191 (Claude Code)".
        assert preflight.cli_version_ok("2.1.191 (Claude Code)") is True

    def test_tolerates_v_prefix_and_two_part(self):
        # Don't FAIL a perfectly good CLI over a cosmetic version shape.
        assert preflight.cli_version_ok("v2.1.0") is True
        assert preflight.cli_version_ok("2.0") is True  # two-part -> patch 0
        assert preflight.cli_version_ok("v1.9") is False


class TestFindCli:
    def test_uses_path_first(self, monkeypatch):
        monkeypatch.setattr(preflight.shutil, "which", lambda _: "/usr/bin/claude")
        assert preflight.find_cli() == "/usr/bin/claude"

    def test_falls_back_to_known_install_locations(self, tmp_path, monkeypatch):
        # The SDK checks several non-PATH locations (npm-global, ~/.local, etc).
        # doctor must agree, or it FAILs a CLI a real run would happily spawn.
        monkeypatch.setattr(preflight.shutil, "which", lambda _: None)
        fake = tmp_path / "claude"
        fake.write_text("#!/bin/sh\n")
        assert preflight.find_cli(fallbacks=[tmp_path / "nope", fake]) == str(fake)

    def test_none_when_absent_everywhere(self, tmp_path, monkeypatch):
        monkeypatch.setattr(preflight.shutil, "which", lambda _: None)
        assert preflight.find_cli(fallbacks=[tmp_path / "nope"]) is None


# ---------------------------------------------------------------- probe classification
class TestProbeClassification:
    def test_no_error_is_ok(self):
        assert preflight.classify_probe_error(None) == "ok"

    def test_cli_missing(self):
        from claude_agent_sdk import CLINotFoundError

        assert preflight.classify_probe_error(CLINotFoundError("nope")) == "cli_missing"

    def test_other_error_means_transport_reached(self):
        # Any non-CLINotFound error (auth failure, process exit) means the CLI
        # WAS found and spawned — the transport is wired; only creds are absent.
        assert preflight.classify_probe_error(RuntimeError("auth required")) == "transport_reached"
