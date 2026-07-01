"""Deterministic keyword -> vuln_class / CWE mapping.

Single source of truth for the finding taxonomy the pipeline uses. ``models``
derives a stable ``vuln_class`` for dedup grouping from this table; the enrich
stage uses the same table to attach ``cwe`` + ``cwe_name``. Ordering matters —
more specific patterns come first (e.g. SQL injection before the generic
"injection" family) and the first match wins.
"""

from __future__ import annotations

import re

# (compiled pattern, vuln_class label, CWE id, CWE name). First match wins.
_TAXONOMY: list[tuple[re.Pattern[str], str, str, str]] = [
    (
        re.compile(r"\bsql\s*inject|\bsqli\b", re.I),
        "sqli",
        "CWE-89",
        "Improper Neutralization of Special Elements used in an SQL Command "
        "('SQL Injection')",
    ),
    (
        re.compile(
            r"\bos\s*command\s*inject|\bcommand\s*inject|\bcmdi\b|"
            r"\bos\.system\b|subprocess[^\n]*shell\s*=\s*true",
            re.I,
        ),
        "command-injection",
        "CWE-78",
        "Improper Neutralization of Special Elements used in an OS Command "
        "('OS Command Injection')",
    ),
    (
        re.compile(r"\bssrf\b|server[\s-]*side\s+request\s+forgery", re.I),
        "ssrf",
        "CWE-918",
        "Server-Side Request Forgery (SSRF)",
    ),
    (
        re.compile(r"\bidor\b|insecure\s+direct\s+object\s+reference", re.I),
        "idor",
        "CWE-639",
        "Authorization Bypass Through User-Controlled Key",
    ),
    (
        re.compile(
            r"broken\s+access\s+control|improper\s+access\s+control|"
            r"missing\s+authoriz",
            re.I,
        ),
        "access-control",
        "CWE-284",
        "Improper Access Control",
    ),
    (
        re.compile(r"path\s*traversal|directory\s*traversal|\.\./", re.I),
        "path-traversal",
        "CWE-22",
        "Improper Limitation of a Pathname to a Restricted Directory "
        "('Path Traversal')",
    ),
    (
        re.compile(
            r"hard[\s_-]*cod\w*[\s\w]{0,40}"
            r"(?:secret|api\s*key|password|credential|token|\bkey\b)",
            re.I,
        ),
        "secret",
        "CWE-798",
        "Use of Hard-coded Credentials",
    ),
    (
        re.compile(
            r"(?:missing|no|without|lacks?|absent|unauthenticated)"
            r"[\s\w]{0,20}auth(?:enticat|n)|no\s+auth\b",
            re.I,
        ),
        "missing-auth",
        "CWE-306",
        "Missing Authentication for Critical Function",
    ),
    (
        re.compile(r"\bxss\b|cross[\s-]*site\s+scripting", re.I),
        "xss",
        "CWE-79",
        "Improper Neutralization of Input During Web Page Generation "
        "('Cross-site Scripting')",
    ),
    (
        re.compile(r"debug\s*=\s*true|debug\s+mode|debugger\b|werkzeug", re.I),
        "debug-enabled",
        "CWE-489",
        "Active Debug Code",
    ),
]

# vuln_class label -> (CWE id, CWE name), for the fallback when the free text
# has no keyword hit but the agent already labelled the finding's class.
_CLASS_TO_CWE: dict[str, tuple[str, str]] = {
    vuln_class: (cwe_id, cwe_name)
    for _pat, vuln_class, cwe_id, cwe_name in _TAXONOMY
}


def _match(text: str) -> tuple[str, str, str] | None:
    """First taxonomy hit as ``(vuln_class, cwe_id, cwe_name)`` or None."""
    for pat, vuln_class, cwe_id, cwe_name in _TAXONOMY:
        if pat.search(text or ""):
            return vuln_class, cwe_id, cwe_name
    return None


def classify(text: str) -> str:
    """Derive a stable ``vuln_class`` label from free text (``"other"`` if none)."""
    hit = _match(text)
    return hit[0] if hit else "other"


def cwe_for(text: str, vuln_class: str | None = None) -> tuple[str, str] | None:
    """Best ``(cwe_id, cwe_name)`` for the text; fall back to a supplied class.

    Returns None when neither the text nor the supplied ``vuln_class`` maps to a
    known CWE — the caller leaves ``cwe``/``cwe_name`` unset in that case.
    """
    hit = _match(text)
    if hit:
        return hit[1], hit[2]
    if vuln_class:
        return _CLASS_TO_CWE.get(vuln_class)
    return None
