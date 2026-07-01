"""Deterministic Jira idempotency logic (build-next #5).

The Atlassian MCP is agent-driven, so the harness owns the *deterministic*
part: a stable external key (so a re-run updates the same ticket), the JQL to
find it, the issue payload, and the create-vs-update decision. All pure, no
network. report.py (live) and the M3 triage output both derive the SAME key
from a finding's (engagement_id, title, location), so they converge on one
ticket per finding.
"""

from __future__ import annotations

from redteam import jira


def test_external_key_format_and_determinism() -> None:
    k = jira.external_key("ENG-1", "SQL injection", "app/db.py:10")
    assert k.startswith("redteam-ENG-1-")
    assert len(k.split("-")[-1]) == 12  # 12-hex fingerprint
    # Deterministic: same inputs -> same key.
    assert k == jira.external_key("ENG-1", "SQL injection", "app/db.py:10")


def test_external_key_normalizes_title_and_location() -> None:
    a = jira.external_key("ENG-1", "SQL Injection", "app/db.py:10")
    b = jira.external_key("ENG-1", "  sql   injection ", "app\\db.py:10")
    assert a == b  # case, whitespace, path-separator normalised


def test_external_key_varies_by_identity() -> None:
    base = jira.external_key("ENG-1", "SQLi", "a.py:1")
    assert jira.external_key("ENG-1", "XSS", "a.py:1") != base  # title
    assert jira.external_key("ENG-1", "SQLi", "b.py:1") != base  # location
    assert jira.external_key("ENG-2", "SQLi", "a.py:1") != base  # engagement


def test_severity_to_priority() -> None:
    assert jira.severity_to_priority("critical") == "Highest"
    assert jira.severity_to_priority("high") == "High"
    assert jira.severity_to_priority("info") == "Lowest"
    assert jira.severity_to_priority("nonsense") == "Medium"  # safe default


def test_jql_for_key_quotes_and_scopes() -> None:
    k = jira.external_key("ENG-1", "t", "a.py:1")
    q = jira.jql_for_key(k, project_key="SEC")
    assert f'labels = "{k}"' in q
    assert 'project = "SEC"' in q
    # Without a project the label clause is still present, no project clause.
    assert "project" not in jira.jql_for_key(k)


def test_build_issue_fields_shape() -> None:
    fields = jira.build_issue_fields(
        "ENG-1", "SQL injection", "critical", "user input reaches query", "app/db.py:10", "SEC"
    )
    assert fields["project"] == {"key": "SEC"}
    assert fields["issuetype"] == {"name": "Bug"}
    assert fields["priority"] == {"name": "Highest"}
    key = jira.external_key("ENG-1", "SQL injection", "app/db.py:10")
    assert key in fields["labels"] and "redteam" in fields["labels"]
    assert fields["summary"].startswith("[redteam] SQL injection")
    assert "app/db.py:10" in fields["description"] and "ENG-1" in fields["description"]
    assert all(" " not in label for label in fields["labels"])  # Jira labels are space-free


def test_build_issue_fields_truncates_summary() -> None:
    fields = jira.build_issue_fields("ENG-1", "x" * 400, "low", "d", None, "SEC")
    assert len(fields["summary"]) <= 255


def test_plan_upsert_creates_when_no_existing() -> None:
    plan = jira.plan_upsert("ENG-1", "SQLi", "high", "d", "a.py:1", "SEC", existing_issues=[])
    assert plan["action"] == "create" and plan["issue_key"] is None
    assert plan["external_key"] == jira.external_key("ENG-1", "SQLi", "a.py:1")
    assert plan["fields"]["project"] == {"key": "SEC"}


def test_plan_upsert_updates_when_label_matches() -> None:
    key = jira.external_key("ENG-1", "SQLi", "a.py:1")
    existing = [{"key": "SEC-42", "fields": {"labels": ["redteam", key]}}]
    plan = jira.plan_upsert("ENG-1", "SQLi", "high", "d", "a.py:1", "SEC", existing_issues=existing)
    assert plan["action"] == "update" and plan["issue_key"] == "SEC-42"


def test_external_key_sanitizes_hostile_engagement_id() -> None:
    # A tampered ledger's engagement_id must not produce an unsafe key/label.
    k = jira.external_key('X" OR labels = "y', "t", "l")
    assert '"' not in k and " " not in k
    # Still deterministic.
    assert k == jira.external_key('X" OR labels = "y', "t", "l")


def test_build_issue_fields_labels_always_safe() -> None:
    fields = jira.build_issue_fields('X" OR x', "title", "high", "d", None, "SEC")
    for label in fields["labels"]:
        assert '"' not in label and " " not in label


def test_jql_for_key_escapes_embedded_quotes() -> None:
    # Defense-in-depth: even a quote-bearing operand must not break the literal.
    q = jira.jql_for_key('a"b', project_key='c"d')
    assert 'a\\"b' in q and 'c\\"d' in q


def test_plan_upsert_ignores_nonmatching_and_malformed() -> None:
    existing = [
        {"key": "SEC-1", "fields": {"labels": ["redteam", "redteam-OTHER-abc123"]}},
        "garbage",
        {"no_key": True},
        {"key": "SEC-2"},  # no fields
    ]
    plan = jira.plan_upsert("ENG-1", "SQLi", "high", "d", "a.py:1", "SEC", existing_issues=existing)
    assert plan["action"] == "create" and plan["issue_key"] is None
