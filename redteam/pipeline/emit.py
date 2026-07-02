"""Emit the triaged report: refined SARIF + markdown + triage.json.

Deterministic and side-effect-safe: the SARIF and triage.json are written with
the same atomic serialize-first/temp+rename primitive the live report writer
uses, so a crash mid-write can never leave a half-written artifact.
"""

from __future__ import annotations

from pathlib import Path

from .. import jira
from ..tools.report import SARIF_LEVEL, _atomic_write_json, _atomic_write_text
from .models import Finding, TriageReport

_SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_CWE_TAXONOMY_URI = "https://cwe.mitre.org/data/published/cwe_latest.xml"


def emit_report(
    report: TriageReport, out_dir: Path, stem: str, jira_project: str | None = None
) -> dict[str, Path]:
    """Write the triage artifacts under ``out_dir`` and return their paths.

    Always emits SARIF + markdown + triage.json. When ``jira_project`` is given,
    also emits ``<stem>.jira.json`` — a per-kept-finding idempotent Jira upsert
    bundle whose external keys match report.py's live tool, so re-running triage
    over a re-run engagement updates the same tickets in place.
    """
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    sarif_path = out_dir / f"{stem}.triaged.sarif"
    md_path = out_dir / f"{stem}.report.md"
    json_path = out_dir / f"{stem}.triage.json"

    _atomic_write_json(sarif_path, _build_sarif(report))
    _atomic_write_json(json_path, report.model_dump(mode="json"))
    _atomic_write_text(md_path, _build_markdown(report))

    paths = {"sarif": sarif_path, "markdown": md_path, "triage_json": json_path}
    if jira_project:
        jira_path = out_dir / f"{stem}.jira.json"
        _atomic_write_json(jira_path, _build_jira_bundle(report, jira_project))
        paths["jira"] = jira_path
    return paths


def _build_jira_bundle(report: TriageReport, project_key: str) -> dict:
    """Per-kept-finding idempotent upsert plan (no network; applied by the agent
    or an operator against the Atlassian MCP)."""
    issues = [
        {
            "external_key": jira.external_key(report.engagement_id, f.title, f.location),
            "jql": jira.jql_for_key(
                jira.external_key(report.engagement_id, f.title, f.location), project_key
            ),
            "fields": jira.build_issue_fields(
                report.engagement_id, f.title, f.severity, f.description, f.location, project_key
            ),
        }
        for f in report.findings
    ]
    return {
        "project": project_key,
        "engagement_id": report.engagement_id,
        "apply": "For each issue: search Jira with `jql`; if it returns a match, edit "
        "that issue with `fields`, else create a new issue with `fields`.",
        "issues": issues,
    }


# --- SARIF -------------------------------------------------------------------


def _build_sarif(report: TriageReport) -> dict:
    results = [_sarif_result(f) for f in report.findings]
    taxa = _cwe_taxa(report.findings)
    run: dict = {
        "tool": {
            "driver": {
                "name": "redteam-triage",
                "version": "0.1.0",
                "informationUri": "https://example.invalid/redteam",
            }
        },
        "results": results,
    }
    if taxa:
        run["taxonomies"] = [
            {
                "name": "CWE",
                "organization": "MITRE",
                "shortDescription": {"text": "Common Weakness Enumeration"},
                "downloadUri": _CWE_TAXONOMY_URI,
                "taxa": taxa,
            }
        ]
    return {"$schema": _SARIF_SCHEMA, "version": "2.1.0", "runs": [run]}


def _sarif_result(f: Finding) -> dict:
    parsed = f.parsed_location()
    result: dict = {
        "ruleId": f.cwe or f.vuln_class or f.title,
        "level": SARIF_LEVEL.get(f.severity, "warning"),
        "message": {"text": f.description or f.title},
        "properties": _sarif_properties(f),
    }
    if parsed:
        result["locations"] = [_physical(parsed[0], parsed[1], parsed[2])]
    if f.duplicates:
        result["relatedLocations"] = [
            _physical(d.file, d.line, d.line) for d in f.duplicates
        ]
    if f.cwe:
        result["taxa"] = [{"toolComponent": {"name": "CWE"}, "id": f.cwe}]
    return result


def _sarif_properties(f: Finding) -> dict:
    props: dict = {"severity": f.severity, "vulnClass": f.vuln_class}
    if f.cwe:
        props["cwe"] = f.cwe
        props["cweName"] = f.cwe_name
    if f.cvss_score is not None:
        props["cvssScore"] = f.cvss_score
        props["cvssRating"] = f.cvss_rating
        props["cvssSource"] = f.cvss_source
    if f.cvss_environmental_score is not None:
        props["cvssEnvironmentalScore"] = f.cvss_environmental_score
        props["cvssEnvironmentalRating"] = f.cvss_environmental_rating
    if f.cvss_vector:
        props["cvssVector"] = f.cvss_vector
    if f.priority_score is not None:
        props["priorityScore"] = f.priority_score
        props["priorityRating"] = f.priority_rating
    if f.verdict:
        props["verdict"] = f.verdict
        props["verdictConfidence"] = f.verdict_confidence
        if f.verdict_reason:
            props["verdictReason"] = f.verdict_reason
    return props


def _physical(uri: str, start: int | None, end: int | None) -> dict:
    loc: dict = {"physicalLocation": {"artifactLocation": {"uri": uri}}}
    # SARIF 2.1.0 requires startLine >= 1 and endLine >= startLine. A finding
    # from an untrusted agent may carry line 0 or a reversed range; emit a valid
    # region (omitting it entirely when the start line is unusable) rather than a
    # document a strict SARIF consumer would reject.
    if start is not None and start >= 1:
        region: dict = {"startLine": start}
        if end is not None and end > start:
            region["endLine"] = end
        loc["physicalLocation"]["region"] = region
    return loc


def _cwe_taxa(findings: list[Finding]) -> list[dict]:
    seen: dict[str, str] = {}
    for f in findings:
        if f.cwe and f.cwe not in seen:
            seen[f.cwe] = f.cwe_name or f.cwe
    return [{"id": cwe, "name": name} for cwe, name in seen.items()]


# --- markdown ----------------------------------------------------------------


def _build_markdown(report: TriageReport) -> str:
    m = report.metrics
    lines: list[str] = [
        f"# Triage report — {report.engagement_id}",
        "",
        "## Summary",
        "",
        f"- Findings kept: **{len(report.findings)}**",
        f"- Findings dropped: **{len(report.dropped)}**",
        f"- Exploit chains: **{len(report.chains)}**",
    ]
    if m.get("verified"):
        precision = m.get("precision")
        if precision is not None:
            lines.append(f"- Verified precision: **{precision:.0%}**")
    if report.degraded:
        lines.append(f"- ⚠️ Degraded: {report.degraded_reason}")
    lines += ["", "## Findings", ""]

    if report.findings:
        lines.append("| # | Priority | Severity | CWE | CVSS | Env | Verdict | Location | Title |")
        lines.append("|---|---|---|---|---|---|---|---|---|")
        for i, f in enumerate(report.findings):
            cvss = f"{f.cvss_score} ({f.cvss_rating})" if f.cvss_score is not None else "-"
            env = f"{f.cvss_environmental_score}" if f.cvss_environmental_score is not None else "-"
            prio = (
                f"{f.priority_rating} ({f.priority_score})"
                if f.priority_score is not None
                else "-"
            )
            verdict = f.verdict or "-"
            if f.verdict and f.verdict_confidence is not None:
                verdict = f"{f.verdict} ({f.verdict_confidence}/10)"
            lines.append(
                f"| {i} | {prio} | {f.severity} | {f.cwe or '-'} | {cvss} | {env} | {verdict} "
                f"| {_md_cell(f.location or '-')} | {_md_cell(f.title)} |"
            )
    else:
        lines.append("_No findings survived triage._")

    if report.chains:
        lines += ["", "## Exploit chains", ""]
        for c in report.chains:
            step_titles = ", ".join(
                f"[{s}] {report.findings[s].title}"
                for s in c.steps
                if 0 <= s < len(report.findings)
            )
            lines.append(f"### {c.title} ({c.severity})")
            lines.append(f"- Steps: {step_titles}")
            if c.narrative:
                lines.append(f"- {_md_cell(c.narrative)}")
            lines.append("")

    lines += ["", "## Dropped findings", ""]
    if report.dropped:
        lines.append("| Reason | Title | Location | Detail |")
        lines.append("|---|---|---|---|")
        for d in report.dropped:
            lines.append(
                f"| {d.reason} | {_md_cell(d.finding.title)} "
                f"| {_md_cell(d.finding.location or '-')} | {_md_cell(d.detail)} |"
            )
    else:
        lines.append("_None._")

    return "\n".join(lines) + "\n"


def _md_cell(text: str) -> str:
    """Make untrusted free text safe inside a markdown table cell.

    Escapes pipes and collapses newlines so a hostile finding string can't add
    columns/rows, and neutralises inline-link (``](``) and code-span (`` ` ``)
    syntax so it can't inject active markup into a report viewer.
    """
    out = (text or "").replace("|", "\\|").replace("\r", " ").replace("\n", " ")
    return out.replace("](", "]\\(").replace("`", "\\`")
