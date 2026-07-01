"""Static-analysis scanner runners + output normalisers (build-next #6).

Thin, **total** wrappers around `semgrep`, `tfsec`, and `checkov` for the
whitebox pack. Two facts drive the design:

  1. These scanners **exit non-zero when they FIND issues** (semgrep 1 on
     findings / >=2 on error; tfsec 1 on issues; checkov 1 on failed checks).
     So the exit code is NOT a success signal - we parse stdout as JSON
     regardless of returncode and treat "valid JSON" as success, "unparseable
     output" as the real error.
  2. Everything degrades to a structured ``{"status": "error", ...}`` dict:
     missing binary / timeout / OSError / non-JSON output never raise.

`run_scanner` invokes the tool with a list argv (no shell). The scanned path
is always an operator-supplied asset host_path resolved by build_index - never
a value the agent typed - so there is no path/argument injection surface here.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from typing import Any

# Scanners can be slow on a large tree; cap so a hung scan can't wedge a turn.
DEFAULT_TIMEOUT_S = 300.0


def run_scanner(argv: list[str], timeout: float = DEFAULT_TIMEOUT_S) -> dict[str, Any]:
    """Run `argv` (argv[0] is a binary NAME resolved on PATH). Never raises.

    Returns ``{"status": "ran", "returncode", "stdout", "stderr"}`` on any
    completed execution (the caller judges success by parsing stdout), or a
    structured ``{"status": "error", ...}`` for missing binary / timeout / OS
    error.
    """
    binary = shutil.which(argv[0])
    if binary is None:
        return {"status": "error", "error": f"{argv[0]} not found on PATH (install it in the runtime image)"}
    try:
        proc = subprocess.run(
            [binary, *argv[1:]],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {"status": "error", "error": f"{argv[0]} timed out after {timeout:.0f}s"}
    except OSError as e:
        return {"status": "error", "error": f"{argv[0]} invocation failed: {e}"}
    return {
        "status": "ran",
        "returncode": proc.returncode,
        "stdout": proc.stdout or "",
        "stderr": proc.stderr or "",
    }


def load_json(res: dict[str, Any]) -> tuple[Any, str | None]:
    """Parse a run_scanner result's stdout as JSON.

    Returns ``(data, None)`` on success or ``(None, error_message)`` - the
    latter is the genuine failure signal (the tool crashed / printed a traceback
    instead of JSON), distinct from a findings-present non-zero exit.
    """
    if res.get("status") != "ran":
        return None, res.get("error", "scanner did not run")
    stdout = res.get("stdout") or ""
    if not stdout.strip():
        # Empty stdout is never a valid clean scan for semgrep/tfsec/checkov -
        # they always print a JSON envelope. Empty means the tool failed before
        # producing output; treat as an error, NOT a clean "0 findings".
        return None, "scanner produced no JSON output (likely crashed before emitting results)"
    try:
        return json.loads(stdout), None
    except (json.JSONDecodeError, ValueError) as e:
        return None, f"could not parse scanner JSON output: {e}"


# --- normalisers: each maps a scanner's JSON to a common finding shape -------
# {"scanner", "rule_id", "severity", "message", "path", "line"}


def _as_int(v: Any) -> int | None:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _as_list(v: Any) -> list[Any]:
    """Return v if it is a list, else [] - so a scanner emitting a scalar (or
    null) where we expect an array degrades to no findings, never a TypeError."""
    return v if isinstance(v, list) else []


def parse_semgrep(data: Any) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    if not isinstance(data, dict):
        return out
    for r in _as_list(data.get("results")):
        if not isinstance(r, dict):
            continue
        extra = r.get("extra") if isinstance(r.get("extra"), dict) else {}
        start = r.get("start") if isinstance(r.get("start"), dict) else {}
        if not r.get("check_id"):
            continue
        out.append(
            {
                "scanner": "semgrep",
                "rule_id": str(r.get("check_id", "")),
                "severity": str(extra.get("severity", "")),
                "message": str(extra.get("message", "")),
                "path": str(r.get("path", "")),
                "line": _as_int(start.get("line")),
            }
        )
    return out


def parse_tfsec(data: Any) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    if not isinstance(data, dict):
        return out
    for r in _as_list(data.get("results")):
        if not isinstance(r, dict):
            continue
        loc = r.get("location") if isinstance(r.get("location"), dict) else {}
        out.append(
            {
                "scanner": "tfsec",
                "rule_id": str(r.get("rule_id") or r.get("long_id") or ""),
                "severity": str(r.get("severity", "")),
                "message": str(r.get("description", "")),
                "path": str(loc.get("filename", "")),
                "line": _as_int(loc.get("start_line")),
            }
        )
    return out


def parse_checkov(data: Any) -> list[dict[str, Any]]:
    # checkov emits either one object or a top-level list (one per framework).
    if isinstance(data, list):
        out: list[dict[str, Any]] = []
        for item in data:
            out.extend(parse_checkov(item))
        return out
    out = []
    if not isinstance(data, dict):
        return out
    results = data.get("results") if isinstance(data.get("results"), dict) else {}
    for c in _as_list(results.get("failed_checks")):
        if not isinstance(c, dict):
            continue
        rng = c.get("file_line_range")
        line = _as_int(rng[0]) if isinstance(rng, list) and rng else None
        out.append(
            {
                "scanner": "checkov",
                "rule_id": str(c.get("check_id", "")),
                "severity": str(c.get("severity") or "UNKNOWN"),
                "message": str(c.get("check_name", "")),
                "path": str(c.get("file_path", "")),
                "line": line,
            }
        )
    return out


# --- scanner dispatch: argv builders + one-call orchestration ----------------

_ARGV = {
    # `--config auto` pulls rules from the semgrep.dev registry at runtime, so
    # semgrep.dev must be in scope.egress_allowlist or the default-deny nft
    # ruleset blocks it (which now surfaces as an error, not a false clean scan).
    "semgrep": lambda p: ["semgrep", "--config", "auto", "--json", "--quiet", str(p)],
    "tfsec": lambda p: ["tfsec", str(p), "--format", "json", "--no-color"],
    "checkov": lambda p: ["checkov", "-d", str(p), "-o", "json", "--compact", "--quiet"],
}
_PARSERS = {"semgrep": parse_semgrep, "tfsec": parse_tfsec, "checkov": parse_checkov}


def scan(scanner: str, path: Any, timeout: float = DEFAULT_TIMEOUT_S) -> dict[str, Any]:
    """Run `scanner` against `path` and return normalised findings (total).

    Success (parseable JSON, any exit code) ->
      ``{"status": "ok", "scanner", "exit_code", "findings": [...]}``.
    Genuine failure (missing binary / timeout / non-JSON) -> structured error.
    """
    if scanner not in _ARGV:
        return {"status": "error", "error": f"unsupported scanner {scanner!r}"}
    res = run_scanner(_ARGV[scanner](path), timeout=timeout)
    data, err = load_json(res)
    if err is not None:
        out: dict[str, Any] = {"status": "error", "error": err}
        if res.get("status") == "ran":  # ran but printed non-JSON: keep diagnostics
            out["exit_code"] = res.get("returncode")
            out["stderr"] = (res.get("stderr") or "")[:1000]
        return out
    return {
        "status": "ok",
        "scanner": scanner,
        "exit_code": res.get("returncode"),
        "findings": _PARSERS[scanner](data),
    }
