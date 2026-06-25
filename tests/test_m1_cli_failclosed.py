"""M1 / RT-26: the `run` CLI fails CLEANLY (no raw traceback) on a bad engagement.

A real first engagement will hit ragged inputs; setup errors must surface as a
one-line message and a non-zero exit, not a stack trace.
"""

from __future__ import annotations

from click.testing import CliRunner

from redteam.cli import main


def test_run_malformed_yaml_exits_clean(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("id: [unterminated\noperator: x\n")  # not valid YAML
    result = CliRunner().invoke(main, ["run", str(bad), "--dry-run"])
    assert result.exit_code == 1
    combined = result.output + (result.stderr if result.stderr_bytes else "")
    assert "INVALID" in combined


def test_run_schema_violation_exits_clean(tmp_path):
    # Parses as YAML but violates the schema (missing required fields) -> exit 1,
    # not a pydantic traceback.
    bad = tmp_path / "incomplete.yaml"
    bad.write_text("id: ENG-X\noperator: not-an-email\n")
    result = CliRunner().invoke(main, ["run", str(bad), "--dry-run"])
    assert result.exit_code == 1
    combined = result.output + (result.stderr if result.stderr_bytes else "")
    assert "INVALID" in combined
