"""M3 cwe.py — deterministic keyword -> vuln_class / CWE mapping."""

from __future__ import annotations

import pytest

from redteam.pipeline import cwe


@pytest.mark.parametrize(
    "text, vuln_class, cwe_id",
    [
        ("SQL injection in get_user via f-string", "sqli", "CWE-89"),
        ("Server-side request forgery in fetch_preview", "ssrf", "CWE-918"),
        ("Hardcoded API credential in config module", "secret", "CWE-798"),
        ("Missing authentication on admin metrics endpoint", "missing-auth", "CWE-306"),
        ("Path traversal in file download handler", "path-traversal", "CWE-22"),
        ("OS command injection via the ping endpoint", "command-injection", "CWE-78"),
        ("Reflected XSS in the search box", "xss", "CWE-79"),
        ("IDOR on invoice download lets users read others' invoices", "idor", "CWE-639"),
        ("Flask app is running with debug=True in production", "debug-enabled", "CWE-489"),
    ],
)
def test_classify_and_cwe(text, vuln_class, cwe_id):
    assert cwe.classify(text) == vuln_class
    got = cwe.cwe_for(text)
    assert got is not None
    assert got[0] == cwe_id
    assert isinstance(got[1], str) and got[1]  # human-readable name present


def test_unmatched_is_other_and_no_cwe():
    assert cwe.classify("some unremarkable observation") == "other"
    assert cwe.cwe_for("some unremarkable observation") is None


def test_cwe_falls_back_to_supplied_vuln_class():
    # No keyword hit in the text, but the agent already labelled the class.
    assert cwe.cwe_for("nondescript title", vuln_class="ssrf") == (
        "CWE-918",
        cwe.cwe_for("ssrf attempt")[1],
    )


def test_sql_injection_not_misread_as_command_injection():
    # "injection" is shared vocabulary; SQLi must win over command-injection.
    assert cwe.classify("SQL injection reachable from id parameter") == "sqli"
