"""Deterministic Jira idempotency logic (build-next #5).

The Atlassian MCP is *agent-driven*: the model calls the `atlassian__*` tools
to search/create/update Jira issues. The harness owns only the deterministic
scaffolding that makes those calls idempotent:

  - `external_key(engagement_id, title, location)` — a stable per-finding key
    (`redteam-<engagement>-<12hex>`). A re-run over the same finding yields the
    same key, so the ticket is updated in place instead of duplicated.
  - `jql_for_key(key, project)` — the JQL to locate an existing ticket by that
    key (stored as a Jira label).
  - `build_issue_fields(...)` — the create/update payload (summary, priority,
    labels, description).
  - `plan_upsert(...)` — given the search result, decide create vs update.

Both the live report tool (`report__jira_upsert`) and the M3 triage output
(`<stem>.jira.json`) derive the SAME key from a finding's
(engagement_id, title, location), so they converge on one ticket per finding.
No network here — all pure and unit-tested.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

# Jira "priority" name per finding severity. Standard Jira priority scheme.
_PRIORITY = {
    "info": "Lowest",
    "low": "Low",
    "medium": "Medium",
    "high": "High",
    "critical": "Highest",
}

_SUMMARY_MAX = 255  # Jira summary hard limit
_WS = re.compile(r"\s+")
# Characters kept in the engagement-id slug of an external key. The key becomes
# a Jira LABEL (must be space/quote-free) and is embedded in JQL, so anything
# outside this set (e.g. from a tampered ledger's engagement_id) is dropped -
# a valid schema-conformant id (^[A-Z0-9][A-Z0-9\-_]{2,63}$) is unchanged.
_UNSAFE_ID = re.compile(r"[^A-Za-z0-9._-]+")


def _norm(s: str | None) -> str:
    """Case/whitespace/separator-insensitive normalisation for the fingerprint."""
    if not s:
        return ""
    return _WS.sub(" ", s.replace("\\", "/").strip().lower())


def _safe_id(engagement_id: str) -> str:
    """Strip an engagement id to a label/JQL-safe slug (identity for valid ids)."""
    return _UNSAFE_ID.sub("", str(engagement_id))


def _jql_quote(value: str) -> str:
    """Escape a value for a JQL double-quoted string literal (\\ and ")."""
    return str(value).replace("\\", "\\\\").replace('"', '\\"')


def external_key(engagement_id: str, title: str, location: str | None) -> str:
    """Stable idempotency key for a finding: ``redteam-<engagement>-<12hex>``.

    The fingerprint is over the normalised (location, title) so the same finding
    maps to the same key across re-runs (and identically from report.py and the
    triage pipeline). engagement_id scopes the key so two engagements never
    collide on one ticket, and is sanitised so an untrusted ledger value can't
    produce an unsafe label / JQL fragment.
    """
    material = f"{_norm(location)}\x00{_norm(title)}".encode("utf-8")
    digest = hashlib.sha256(material).hexdigest()[:12]
    return f"redteam-{_safe_id(engagement_id)}-{digest}"


def severity_to_priority(severity: str) -> str:
    return _PRIORITY.get(str(severity).lower(), "Medium")


def jql_for_key(key: str, project_key: str | None = None) -> str:
    """JQL that finds the ticket carrying ``key`` as a label.

    Both operands are escaped for the JQL string literal (defence-in-depth):
    `key` is already sanitised by external_key, and project_key is validated at
    its ingress points, but escaping here guarantees no operand can break out.
    """
    clauses = [f'labels = "{_jql_quote(key)}"']
    if project_key:
        clauses.append(f'project = "{_jql_quote(project_key)}"')
    return " AND ".join(clauses) + " ORDER BY created ASC"


def build_issue_fields(
    engagement_id: str,
    title: str,
    severity: str,
    description: str,
    location: str | None,
    project_key: str,
    external_key_value: str | None = None,
) -> dict[str, Any]:
    """The Jira issue ``fields`` payload used for both create and update."""
    key = external_key_value or external_key(engagement_id, title, location)
    summary = f"[redteam] {title}".strip()[:_SUMMARY_MAX]
    desc_parts = [description or ""]
    if location:
        desc_parts.append(f"Location: {location}")
    desc_parts.append(f"Engagement: {engagement_id}")
    desc_parts.append(f"redteam-key: {key}")
    labels = [key, "redteam", f"severity-{str(severity).lower()}"]
    return {
        "project": {"key": project_key},
        "summary": summary,
        "description": "\n\n".join(p for p in desc_parts if p),
        "issuetype": {"name": "Bug"},
        "priority": {"name": severity_to_priority(severity)},
        "labels": labels,
    }


def _match_existing(existing_issues: Any, key: str) -> str | None:
    """Return the Jira issue key of an existing ticket carrying ``key`` (label).

    Defensive: `existing_issues` comes from an MCP search reply, so tolerate
    non-list input, non-dict items, and missing fields/labels without raising.
    """
    if not isinstance(existing_issues, list):
        return None
    for issue in existing_issues:
        if not isinstance(issue, dict):
            continue
        fields = issue.get("fields")
        labels = fields.get("labels") if isinstance(fields, dict) else None
        if isinstance(labels, list) and key in labels and issue.get("key"):
            return str(issue["key"])
    return None


def plan_upsert(
    engagement_id: str,
    title: str,
    severity: str,
    description: str,
    location: str | None,
    project_key: str,
    existing_issues: Any = None,
) -> dict[str, Any]:
    """Decide whether to create or update, and return the full upsert plan.

    `existing_issues` is the Atlassian search result for `jql_for_key`. A match
    (an issue already labelled with our external key) -> update that issue;
    otherwise create. The caller (agent or operator) performs the actual MCP
    create/update using ``fields``.
    """
    key = external_key(engagement_id, title, location)
    issue_key = _match_existing(existing_issues, key)
    return {
        "action": "update" if issue_key else "create",
        "external_key": key,
        "issue_key": issue_key,
        "jql": jql_for_key(key, project_key),
        "fields": build_issue_fields(
            engagement_id, title, severity, description, location, project_key, external_key_value=key
        ),
    }
