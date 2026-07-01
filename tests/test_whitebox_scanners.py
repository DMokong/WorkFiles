"""whitebox real scanners (build-next #6): semgrep / tfsec / checkov.

The scanners exit NON-ZERO when they find issues, so the tools parse stdout
JSON regardless of exit code (a findings-present run is success, not error).
Everything is total: a missing binary / timeout / non-JSON output degrades to
a structured error, never a raise. Every test mocks the subprocess.
"""

from __future__ import annotations

import json

from redteam.assets import build_index
from redteam.engagement import Engagement
from redteam.hooks.audit_writer import AuditWriter
from redteam.hooks.scope_guard import ScopeGuard
from redteam.ledger.chain import LedgerWriter
from redteam.tools import _scanners, whitebox
from redteam.tools._context import ToolContext


def _ctx(tmp_path, minimal_engagement_dict) -> ToolContext:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("x = 1\n")
    tf = tmp_path / "infra"
    tf.mkdir()
    (tf / "main.tf").write_text("resource {}\n")
    k8s = tmp_path / "k8s"
    k8s.mkdir()
    (k8s / "deploy.yaml").write_text("kind: Deployment\n")
    d = {
        **minimal_engagement_dict,
        "tools": ["whitebox", "report"],
        "assets": {
            "source_repos": [{"path": str(repo), "language": "python", "role": "backend"}],
            "iac": [
                {"path": str(tf), "kind": "terraform"},
                {"path": str(k8s), "kind": "kubernetes"},
            ],
        },
    }
    eng = Engagement.model_validate(d)
    return ToolContext(
        engagement=eng,
        scope=ScopeGuard(eng),
        audit=AuditWriter(LedgerWriter(tmp_path / "l.jsonl")),
        assets=build_index(eng.assets, host_root=tmp_path, require_exists=False),
        audit_dir=tmp_path / "audit",
    )


def _tools(ctx, monkeypatch) -> dict:
    cap: dict = {}
    monkeypatch.setattr(
        whitebox, "create_sdk_mcp_server", lambda name, version, tools: cap.update(t=tools)
    )
    whitebox.build_pack(ctx)
    return {t.name: t for t in cap["t"]}


def _fake_scanner(returncode=0, stdout="{}", stderr=""):
    def run(argv, timeout=None):
        run.calls.append(argv)
        return {"status": "ran", "returncode": returncode, "stdout": stdout, "stderr": stderr}

    run.calls = []
    return run


# ---- pure parser unit tests -------------------------------------------------


def test_parse_semgrep_normalizes() -> None:
    data = {
        "results": [
            {
                "check_id": "python.lang.security.audit.exec",
                "path": "app/db.py",
                "start": {"line": 10},
                "extra": {"severity": "ERROR", "message": "exec is dangerous"},
            }
        ]
    }
    out = _scanners.parse_semgrep(data)
    assert out == [
        {
            "scanner": "semgrep",
            "rule_id": "python.lang.security.audit.exec",
            "severity": "ERROR",
            "message": "exec is dangerous",
            "path": "app/db.py",
            "line": 10,
        }
    ]


def test_parse_tfsec_handles_null_results() -> None:
    assert _scanners.parse_tfsec({"results": None}) == []
    data = {
        "results": [
            {
                "rule_id": "aws-s3-enable-bucket-encryption",
                "severity": "HIGH",
                "description": "Bucket does not have encryption enabled",
                "location": {"filename": "main.tf", "start_line": 12},
            }
        ]
    }
    out = _scanners.parse_tfsec(data)
    assert out[0]["scanner"] == "tfsec"
    assert out[0]["rule_id"] == "aws-s3-enable-bucket-encryption"
    assert out[0]["path"] == "main.tf" and out[0]["line"] == 12


def test_parse_checkov_dict_and_list_forms() -> None:
    one = {
        "check_type": "terraform",
        "results": {
            "failed_checks": [
                {
                    "check_id": "CKV_AWS_18",
                    "check_name": "Ensure S3 has access logging",
                    "file_path": "/main.tf",
                    "file_line_range": [1, 5],
                    "severity": "LOW",
                }
            ]
        },
    }
    out = _scanners.parse_checkov(one)
    assert out[0]["scanner"] == "checkov" and out[0]["rule_id"] == "CKV_AWS_18"
    assert out[0]["path"] == "/main.tf" and out[0]["line"] == 1
    # checkov can emit a top-level list (one object per framework).
    assert _scanners.parse_checkov([one, one]) == out + out


def test_parsers_skip_malformed_items_without_raising() -> None:
    assert _scanners.parse_semgrep({"results": [{"garbage": True}, 42, None]}) == []
    assert _scanners.parse_tfsec({"results": [{"nope": 1}]})[0]["path"] == ""
    assert _scanners.parse_checkov({"results": {"failed_checks": ["bad"]}}) == []


def test_parsers_total_on_non_list_results() -> None:
    # A truthy non-list `results` must NOT be iterated (would raise TypeError).
    assert _scanners.parse_semgrep({"results": 5}) == []
    assert _scanners.parse_tfsec({"results": True}) == []
    assert _scanners.parse_checkov({"results": {"failed_checks": 5}}) == []


# ---- semgrep_scan tool ------------------------------------------------------


async def test_semgrep_scan_builds_argv_and_parses(tmp_path, minimal_engagement_dict, monkeypatch) -> None:
    run = _fake_scanner(
        returncode=1,  # semgrep exits 1 when it FINDS something — must still be ok
        stdout=json.dumps(
            {"results": [{"check_id": "r1", "path": "a.py", "start": {"line": 3},
                          "extra": {"severity": "WARNING", "message": "m"}}]}
        ),
    )
    monkeypatch.setattr(_scanners, "run_scanner", run)
    ctx = _ctx(tmp_path, minimal_engagement_dict)
    res = await _tools(ctx, monkeypatch)["whitebox__semgrep_scan"].handler(role="backend")

    argv = run.calls[0]
    assert argv[0] == "semgrep" and "--json" in argv and "--config" in argv
    assert str((tmp_path / "repo").resolve()) in argv
    assert res["status"] == "ok" and res["count"] == 1
    assert res["findings"][0]["rule_id"] == "r1"


async def test_semgrep_scan_missing_binary_errors(tmp_path, minimal_engagement_dict, monkeypatch) -> None:
    monkeypatch.setattr(_scanners, "run_scanner", lambda argv, timeout=None: {"status": "error", "error": "semgrep not found"})
    ctx = _ctx(tmp_path, minimal_engagement_dict)
    res = await _tools(ctx, monkeypatch)["whitebox__semgrep_scan"].handler(role="backend")
    assert res["status"] == "error" and "not found" in res["error"]


async def test_semgrep_scan_nonjson_output_errors(tmp_path, minimal_engagement_dict, monkeypatch) -> None:
    run = _fake_scanner(returncode=2, stdout="Traceback: semgrep crashed", stderr="boom")
    monkeypatch.setattr(_scanners, "run_scanner", run)
    ctx = _ctx(tmp_path, minimal_engagement_dict)
    res = await _tools(ctx, monkeypatch)["whitebox__semgrep_scan"].handler(role="backend")
    assert res["status"] == "error" and "json" in res["error"].lower()


async def test_semgrep_scan_empty_stdout_is_error_not_clean(tmp_path, minimal_engagement_dict, monkeypatch) -> None:
    # A crashed scan (empty stdout, exit >=2) must NOT be laundered into "ok, 0
    # findings" — empty output is never a valid clean scan for these tools.
    run = _fake_scanner(returncode=2, stdout="", stderr="fatal: could not reach registry")
    monkeypatch.setattr(_scanners, "run_scanner", run)
    ctx = _ctx(tmp_path, minimal_engagement_dict)
    res = await _tools(ctx, monkeypatch)["whitebox__semgrep_scan"].handler(role="backend")
    assert res["status"] == "error"


async def test_semgrep_unknown_role_errors_without_running(tmp_path, minimal_engagement_dict, monkeypatch) -> None:
    run = _fake_scanner()
    monkeypatch.setattr(_scanners, "run_scanner", run)
    ctx = _ctx(tmp_path, minimal_engagement_dict)
    res = await _tools(ctx, monkeypatch)["whitebox__semgrep_scan"].handler(role="nonesuch")
    assert res["status"] == "error" and run.calls == []


# ---- iac_scan tool ----------------------------------------------------------


async def test_iac_scan_terraform_uses_tfsec(tmp_path, minimal_engagement_dict, monkeypatch) -> None:
    run = _fake_scanner(
        returncode=1,
        stdout=json.dumps(
            {"results": [{"rule_id": "aws-x", "severity": "HIGH", "description": "d",
                          "location": {"filename": "main.tf", "start_line": 4}}]}
        ),
    )
    monkeypatch.setattr(_scanners, "run_scanner", run)
    ctx = _ctx(tmp_path, minimal_engagement_dict)
    res = await _tools(ctx, monkeypatch)["whitebox__iac_scan"].handler(kind="terraform")

    argv = run.calls[0]
    assert argv[0] == "tfsec" and "json" in " ".join(argv)
    assert str((tmp_path / "infra").resolve()) in argv
    assert res["status"] == "ok" and res["scanner"] == "tfsec" and res["count"] == 1


async def test_iac_scan_kubernetes_uses_checkov(tmp_path, minimal_engagement_dict, monkeypatch) -> None:
    run = _fake_scanner(
        returncode=1,
        stdout=json.dumps(
            {"check_type": "kubernetes",
             "results": {"failed_checks": [{"check_id": "CKV_K8S_1", "check_name": "n",
                                            "file_path": "/deploy.yaml", "file_line_range": [1, 2]}]}}
        ),
    )
    monkeypatch.setattr(_scanners, "run_scanner", run)
    ctx = _ctx(tmp_path, minimal_engagement_dict)
    res = await _tools(ctx, monkeypatch)["whitebox__iac_scan"].handler(kind="kubernetes")

    argv = run.calls[0]
    assert argv[0] == "checkov"
    assert res["status"] == "ok" and res["scanner"] == "checkov" and res["count"] == 1


async def test_iac_scan_terraform_scanner_override_checkov(tmp_path, minimal_engagement_dict, monkeypatch) -> None:
    run = _fake_scanner(stdout=json.dumps({"results": {"failed_checks": []}}))
    monkeypatch.setattr(_scanners, "run_scanner", run)
    ctx = _ctx(tmp_path, minimal_engagement_dict)
    res = await _tools(ctx, monkeypatch)["whitebox__iac_scan"].handler(kind="terraform", scanner="checkov")
    assert run.calls[0][0] == "checkov" and res["scanner"] == "checkov"


async def test_iac_scan_rejects_tfsec_for_kubernetes(tmp_path, minimal_engagement_dict, monkeypatch) -> None:
    run = _fake_scanner()
    monkeypatch.setattr(_scanners, "run_scanner", run)
    ctx = _ctx(tmp_path, minimal_engagement_dict)
    res = await _tools(ctx, monkeypatch)["whitebox__iac_scan"].handler(kind="kubernetes", scanner="tfsec")
    assert res["status"] == "error" and run.calls == []


async def test_iac_scan_unknown_kind_errors_without_running(tmp_path, minimal_engagement_dict, monkeypatch) -> None:
    run = _fake_scanner()
    monkeypatch.setattr(_scanners, "run_scanner", run)
    ctx = _ctx(tmp_path, minimal_engagement_dict)
    # No cloudformation asset indexed -> nothing to scan.
    res = await _tools(ctx, monkeypatch)["whitebox__iac_scan"].handler(kind="terraform", scanner="nope")
    assert res["status"] == "error"


# ---- run_scanner is total ---------------------------------------------------


def test_run_scanner_missing_binary(monkeypatch) -> None:
    monkeypatch.setattr(_scanners.shutil, "which", lambda name: None)
    res = _scanners.run_scanner(["semgrep", "--json"], timeout=5)
    assert res["status"] == "error" and "not found" in res["error"].lower()


def test_run_scanner_timeout(monkeypatch) -> None:
    import subprocess

    monkeypatch.setattr(_scanners.shutil, "which", lambda name: "/usr/bin/" + name)

    def boom(argv, **kwargs):
        raise subprocess.TimeoutExpired(argv, kwargs.get("timeout", 5))

    monkeypatch.setattr(_scanners.subprocess, "run", boom)
    res = _scanners.run_scanner(["tfsec", "."], timeout=5)
    assert res["status"] == "error" and "tim" in res["error"].lower()


def test_run_scanner_success_passes_through(monkeypatch) -> None:
    import subprocess

    monkeypatch.setattr(_scanners.shutil, "which", lambda name: "/usr/bin/" + name)
    monkeypatch.setattr(
        _scanners.subprocess,
        "run",
        lambda argv, **kw: subprocess.CompletedProcess(argv, 1, '{"results": []}', ""),
    )
    res = _scanners.run_scanner(["semgrep", "--json", "."], timeout=5)
    assert res["status"] == "ran" and res["returncode"] == 1 and res["stdout"] == '{"results": []}'
