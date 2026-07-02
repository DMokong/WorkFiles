"""Triage stages: prefilter, dedup, enrich (deterministic) + run_triage.

The deterministic stages are *total*: they never raise on a bad finding; instead
they drop it and record a ``DroppedFinding`` with a reason. The model-driven
verify/chain stages (added on top of this orchestration) are opt-in.
"""

from __future__ import annotations

import asyncio
import json
import re
import time
from collections import Counter
from collections.abc import Awaitable, Callable
from pathlib import Path

from . import cwe, cvss
from .models import Chain, DropReason, DroppedFinding, DupLocation, Finding, TriageReport

_DEFAULT_LINE_TOLERANCE = 10
_VERIFY_CONCURRENCY = 4
_SOURCE_CONTEXT_LINES = 25
_SOURCE_MAX_BYTES = 256 * 1024

# An ``ask`` callable: (system, user, *, model) -> assistant text.
AskFn = Callable[..., Awaitable[str]]


def resolve_under_root(root: Path, relpath: str) -> Path | None:
    """Resolve ``relpath`` under ``root``, returning the path only if it stays
    inside ``root`` AND is an existing file; else None.

    Mirrors the whitebox containment discipline (``_resolve_under_assets``): a
    ``..`` escape or an absolute path that leaves the asset scope resolves to
    None, so a malicious ``location`` cannot make the pipeline read outside the
    reviewed source tree.
    """
    root = Path(root).resolve()
    try:
        candidate = (root / relpath).resolve()
        candidate.relative_to(root)
        # is_file() is inside the try: an over-long path component raises
        # OSError(ENAMETOOLONG) on Linux, which must degrade to None, not crash.
        return candidate if candidate.is_file() else None
    except (ValueError, OSError):
        return None


# --- prefilter (VVAH S5) -----------------------------------------------------


def prefilter(
    findings: list[Finding], *, assets_root: Path | None
) -> tuple[list[Finding], list[DroppedFinding]]:
    """Drop findings with no substance, no usable location, or (when
    ``assets_root`` is set) a location that does not resolve to a real file
    inside the asset scope."""
    kept: list[Finding] = []
    dropped: list[DroppedFinding] = []
    for f in findings:
        if not f.description.strip() and not f.evidence:
            dropped.append(_drop(f, "NO_EVIDENCE", "empty description and evidence"))
            continue
        parsed = f.parsed_location()
        if parsed is None:
            dropped.append(_drop(f, "BAD_LOCATION", f"unparseable location {f.location!r}"))
            continue
        if assets_root is not None:
            resolved = resolve_under_root(assets_root, parsed[0])
            if resolved is None:
                dropped.append(
                    _drop(f, "FILE_NOT_FOUND", f"{parsed[0]} not found under asset scope")
                )
                continue
        kept.append(f)
    return kept, dropped


# --- dedup (VVAH S7a) --------------------------------------------------------


def dedup(
    findings: list[Finding], *, line_tolerance: int = _DEFAULT_LINE_TOLERANCE
) -> tuple[list[Finding], list[DroppedFinding]]:
    """Collapse findings that share ``(file, vuln_class)`` and whose line ranges
    are within ``line_tolerance`` (or overlap). The first in reading order is
    canonical; the rest merge into its ``duplicates`` and drop as ``DUPLICATE``."""
    kept: list[Finding] = []
    dropped: list[DroppedFinding] = []
    # Group by (file, vuln_class) without reordering, so the kept list preserves
    # reading order and the first member of each group is its canonical.
    groups: dict[tuple[str, str], list[Finding]] = {}
    for f in findings:
        parsed = f.parsed_location()
        if parsed is not None:
            groups.setdefault((parsed[0], f.derived_vuln_class()), []).append(f)

    seen: set[int] = set()
    for f in findings:
        if id(f) in seen:
            continue
        seen.add(id(f))
        kept.append(f)
        parsed = f.parsed_location()
        if parsed is None:  # defensive — prefilter normally removes these
            continue
        # f is the first unseen member of its group (all earlier members are
        # already seen), so it is the canonical; merge later within-tolerance
        # members into it.
        c_start, c_end = parsed[1], parsed[2]
        for other in groups[(parsed[0], f.derived_vuln_class())]:
            if id(other) in seen:
                continue
            o = other.parsed_location()
            if o and _within(c_start, c_end, o[1], o[2], line_tolerance):
                f.duplicates.append(DupLocation(file=o[0], line=o[1]))
                dropped.append(_drop(other, "DUPLICATE", f"duplicate of {f.title!r}"))
                seen.add(id(other))
    return kept, dropped


def _within(a_start: int, a_end: int, b_start: int, b_end: int, tol: int) -> bool:
    """True if line ranges [a] and [b] overlap or are within ``tol`` lines."""
    gap = max(b_start - a_end, a_start - b_end, 0)
    return gap <= tol


# --- enrich (deterministic; runs after verify) -------------------------------


def enrich(
    findings: list[Finding], *, security_requirements: dict[str, str] | None = None
) -> None:
    """Attach ``vuln_class``, ``cwe``/``cwe_name`` and CVSS (base + environmental)
    to each finding in place. Uses a verify-produced ``cvss_vector`` when present,
    else a severity-band score. ``security_requirements`` (engagement-wide
    ``{"CR","IR","AR"}``) feed the environmental score."""
    for f in findings:
        f.vuln_class = f.derived_vuln_class()
        text = f"{f.title} {f.description}"
        hit = cwe.cwe_for(text, f.vuln_class)
        if hit:
            f.cwe, f.cwe_name = hit
        if f.cvss_vector:
            scored = cvss.base_score(f.cvss_vector)
            if scored:
                f.cvss_score, f.cvss_rating = scored
                f.cvss_source = "vector"
                env = cvss.environmental_score(f.cvss_vector, requirements=security_requirements)
                # A garbage MODIFIED metric can make environmental_score fail even
                # on a valid base vector; fall back to base so every scored finding
                # carries an environmental value.
                f.cvss_environmental_score, f.cvss_environmental_rating = env or scored
                continue
        f.cvss_score, f.cvss_rating = cvss.severity_band(f.severity)
        f.cvss_source = "severity_band"
        # No vector to modify: environmental defaults to the band score.
        f.cvss_environmental_score, f.cvss_environmental_rating = f.cvss_score, f.cvss_rating


# --- prioritise (deterministic; runs after chains) ---------------------------


def _priority_rating(score: int) -> str:
    if score >= 80:
        return "P1"
    if score >= 60:
        return "P2"
    if score >= 40:
        return "P3"
    return "P4"


def prioritize(findings: list[Finding], chains: list[Chain]) -> None:
    """Set an offensive ``priority_score`` (0..100) + ``priority_rating`` (P1..P4)
    on each finding in place.

    A deterministic blend, NOT a CVSS score: it starts from the environmental
    CVSS (defensive severity) and adds offensive signals an attacker cares about
    - network reachability / no auth / no interaction, a confirmed verdict, and
    membership in a validated exploit chain. Weights are intentionally simple and
    tunable; the point is a stable ordering of what to exploit first.
    """
    in_chain = {s for c in chains for s in c.steps}
    for idx, f in enumerate(findings):
        # Prefer the environmental score; an explicit 0.0 is a real value, not
        # "missing", so use None checks rather than truthiness.
        score10 = f.cvss_environmental_score
        if score10 is None:
            score10 = f.cvss_score
        base = (score10 if score10 is not None else 0.0) * 10.0  # 0..100
        bonus = 0.0
        m = cvss.metrics(f.cvss_vector) if f.cvss_vector else None
        if m:  # exploitability signals (max +15)
            bonus += 5 if m.get("AV") == "N" else 0
            bonus += 3 if m.get("AC") == "L" else 0
            bonus += 4 if m.get("PR") == "N" else 0
            bonus += 3 if m.get("UI") == "N" else 0
        if f.verdict == "TRUE_POSITIVE":  # confirmed (max +15, scaled by confidence)
            conf = f.verdict_confidence if f.verdict_confidence is not None else 7
            bonus += (max(0, min(conf, 10)) / 10.0) * 15
        if idx in in_chain:  # a step in a validated exploit chain (+20)
            bonus += 20
        score = int(round(max(0.0, min(base + bonus, 100.0))))
        f.priority_score = score
        f.priority_rating = _priority_rating(score)


# --- verify (opt-in LLM, VVAH S6) -------------------------------------------

_VERIFY_SYSTEM = (
    "You are an adversarial security reviewer. You have NO tools: reason ONLY "
    "from the finding and the source excerpt included in the message — do not "
    "attempt to read files, search, or call any tool. Assume the finding is a "
    "FALSE POSITIVE until the shown code convinces you otherwise; look in the "
    "excerpt for upstream validation, sanitisation, or access controls that "
    "would neutralise it, then decide.\n\n"
    "End your reply with EXACTLY this grammar on its own final lines:\n"
    "VERDICT: TRUE_POSITIVE|FALSE_POSITIVE (confidence: N/10) — <one-line reason>\n"
    "Optionally, on the next line, a CVSS 3.1 base vector:\n"
    "CVSS: CVSS:3.1/AV:.../AC:.../PR:.../UI:.../S:.../C:.../I:.../A:...\n"
    "Do not add anything after the VERDICT/CVSS lines."
)

_VERDICT_RE = re.compile(
    r"VERDICT:\s*(TRUE_POSITIVE|FALSE_POSITIVE)"
    r"(?:\s*\(\s*confidence:\s*(\d+)\s*/\s*10\s*\))?"
    r"\s*[—:\-]*\s*(.*)",
    re.I,
)
_CVSS_RE = re.compile(r"(CVSS:3\.\d/[A-Za-z:/.]+)", re.I)


def parse_verdict(reply: str) -> dict | None:
    """Parse the adversarial reviewer's reply grammar bottom-up.

    Returns ``{"verdict", "confidence", "reason", "cvss_vector"}`` or None. None
    is returned when there is no VERDICT line OR when the reply contains
    *conflicting* verdicts (both TRUE_POSITIVE and FALSE_POSITIVE) — an ambiguous
    reply must not be trusted in either direction (a trailing decoy line cannot
    launder a refuted finding to confirmed, nor drop a confirmed one). The caller
    keeps a None-verdict finding as UNVERIFIED — never as FALSE_POSITIVE.
    """
    if not reply:
        return None
    matches = [m for m in (_VERDICT_RE.search(ln) for ln in reply.splitlines()) if m]
    if not matches:
        return None
    if len({m.group(1).upper() for m in matches}) > 1:
        return None  # conflicting verdicts -> ambiguous -> UNVERIFIED (fail-closed)
    m = matches[-1]  # bottom-up: last line wins among same-verdict lines
    conf = None
    if m.group(2) is not None:
        conf = max(0, min(10, int(m.group(2))))
    cvss_match = _CVSS_RE.search(reply)
    return {
        "verdict": m.group(1).upper(),
        "confidence": conf,
        "reason": m.group(3).strip(),
        "cvss_vector": cvss_match.group(1) if cvss_match else None,
    }


def _source_window(assets_root: Path | None, finding: Finding) -> str:
    """A numbered slice of source around the finding's location, or a note when
    it cannot be read (no assets_root, unresolved/oversized file)."""
    parsed = finding.parsed_location()
    if assets_root is None or parsed is None:
        return "(source unavailable — verifying from the finding text alone)"
    path = resolve_under_root(assets_root, parsed[0])
    if path is None:
        return "(source unavailable — file not found under asset scope)"
    try:
        if path.stat().st_size > _SOURCE_MAX_BYTES:
            return "(source unavailable — file too large)"
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return "(source unavailable — read error)"
    start = max(parsed[1] - _SOURCE_CONTEXT_LINES, 1)
    end = min(parsed[2] + _SOURCE_CONTEXT_LINES, len(lines))
    numbered = [f"{n:>5}  {lines[n - 1]}" for n in range(start, end + 1)]
    return "\n".join(numbered)


def _verify_user_prompt(finding: Finding, source: str) -> str:
    return (
        f"Finding: {finding.title}\n"
        f"Severity (as reported): {finding.severity}\n"
        f"Location: {finding.location}\n"
        f"Description: {finding.description}\n"
        f"Evidence: {finding.evidence}\n\n"
        f"Source around the location:\n{source}\n"
    )


async def verify_findings(
    findings: list[Finding],
    *,
    ask: AskFn,
    min_confidence: int = 7,
    assets_root: Path | None = None,
    model: str | None = None,
    concurrency: int = _VERIFY_CONCURRENCY,
) -> tuple[list[Finding], list[DroppedFinding], bool]:
    """Adversarially verify each finding with one bounded-concurrency ``ask``.

    Gate: TRUE_POSITIVE at/above ``min_confidence`` is kept; a lower-confidence
    TRUE_POSITIVE drops as UNCONFIRMED; FALSE_POSITIVE drops; an unparseable or
    errored reply becomes UNVERIFIED and is KEPT. Returns
    ``(kept, dropped, degraded)`` where degraded is True only if *every* call
    failed (the stage effectively did not run).
    """
    if not findings:
        return [], [], False

    sem = asyncio.Semaphore(max(1, concurrency))

    async def _one(f: Finding) -> tuple[Finding, dict | None, bool]:
        async with sem:
            try:
                source = _source_window(assets_root, f)
                reply = await ask(_VERIFY_SYSTEM, _verify_user_prompt(f, source), model=model)
                return f, parse_verdict(reply), False
            except Exception:  # noqa: BLE001 - a per-finding failure -> UNVERIFIED
                return f, None, True

    outcomes = await asyncio.gather(*(_one(f) for f in findings))

    kept: list[Finding] = []
    dropped: list[DroppedFinding] = []
    errors = 0
    for f, parsed, errored in outcomes:
        if errored:
            errors += 1
        if parsed is None:
            f.verdict = "UNVERIFIED"
            f.verdict_reason = "verify reply could not be parsed" if not errored else "verify call failed"
            kept.append(f)
            continue
        if parsed["verdict"] == "FALSE_POSITIVE":
            f.verdict = "FALSE_POSITIVE"
            f.verdict_confidence = parsed["confidence"]
            f.verdict_reason = parsed["reason"]
            dropped.append(_drop(f, "FALSE_POSITIVE", parsed["reason"]))
            continue
        # TRUE_POSITIVE — apply the confidence gate.
        if parsed["confidence"] is None:
            # Affirmed as a true positive but unquantified: keep it rather than
            # drop a possibly-real finding, but do not claim it as confirmed.
            f.verdict = "UNVERIFIED"
            f.verdict_reason = parsed["reason"] or "true positive without a confidence score"
            kept.append(f)
            continue
        conf = parsed["confidence"]
        f.verdict = "TRUE_POSITIVE"
        f.verdict_confidence = conf
        f.verdict_reason = parsed["reason"]
        if conf >= min_confidence:
            if parsed["cvss_vector"]:
                f.cvss_vector = parsed["cvss_vector"]
            kept.append(f)
        else:
            dropped.append(_drop(f, "UNCONFIRMED", f"confidence {conf} < {min_confidence}"))

    degraded = errors == len(findings)
    return kept, dropped, degraded


# --- chain (opt-in LLM, VVAH S8) --------------------------------------------

_SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

_CHAIN_SYSTEM = (
    "You are a security analyst composing exploit chains. You have NO tools: "
    "reason ONLY from the numbered findings in the message. Identify "
    "combinations that compose into a single attack path (e.g. info-leak + "
    "auth-bypass + memory-corruption). Only chain findings that genuinely "
    "enable each other.\n\n"
    "Reply with ONLY a JSON array (no prose). Each element:\n"
    '{"title": str, "steps": [finding_index, ...], "severity": '
    '"info|low|medium|high|critical", "narrative": str}\n'
    "Each chain MUST reference at least two distinct finding indices. If no "
    "findings meaningfully chain, reply with []."
)


# Bounds so an adversarial/degenerate model reply cannot hang or blow the stack.
_MAX_JSON_SCAN = 200_000  # chars of a reply we will scan for JSON
_MAX_JSON_ATTEMPTS = 64  # candidate start positions we will try to parse


def _iter_json_values(text: str):
    """Yield each top-level JSON value found in ``text`` (bounded, total).

    Uses ``json.JSONDecoder().raw_decode`` at each ``[``/``{`` — single-pass and
    C-level, so a wall of unbalanced/deeply-nested brackets (which made the old
    balanced scan O(n^2) and let ``RecursionError`` escape) is cheap and safe:
    both a parse error and a ``RecursionError`` just skip that position, and the
    scan is capped in input length and number of attempts.
    """
    if not text:
        return
    cleaned = re.sub(r"```(?:json)?", "", text)
    if len(cleaned) > _MAX_JSON_SCAN:
        cleaned = cleaned[:_MAX_JSON_SCAN]
    decoder = json.JSONDecoder()
    attempts = 0
    i = 0
    n = len(cleaned)
    while i < n:
        if cleaned[i] in "[{":
            attempts += 1
            if attempts > _MAX_JSON_ATTEMPTS:
                return
            try:
                obj, end = decoder.raw_decode(cleaned, i)
            except (ValueError, RecursionError):
                i += 1
                continue
            yield obj
            i = max(end, i + 1)
            continue
        i += 1


def extract_json(text: str) -> object | None:
    """The first top-level JSON value in ``text`` (array/object), or None.

    Tolerant of code fences and surrounding prose; respects strings; never raises
    or hangs on garbage/decoy/adversarial input.
    """
    return next(_iter_json_values(text), None)


def _chain_items(data: object) -> list | None:
    """Coerce a parsed JSON value into a list of candidate chain objects."""
    if isinstance(data, dict):
        chains = data.get("chains")
        return chains if isinstance(chains, list) else [data]
    if isinstance(data, list):
        return data
    return None


def _validate_chains(items: list, findings: list[Finding]) -> list[Chain]:
    chains: list[Chain] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        try:
            chain = Chain.model_validate(item)
        except Exception:  # noqa: BLE001 - skip a malformed chain object
            continue
        valid_steps: list[int] = []
        for s in chain.steps:
            if 0 <= s < len(findings) and s not in valid_steps:
                valid_steps.append(s)
        if len(valid_steps) < 2:
            continue
        chain.steps = valid_steps
        if not item.get("severity"):
            chain.severity = _max_severity(findings, valid_steps)
        chains.append(chain)
    return chains


def _chain_user_prompt(findings: list[Finding]) -> str:
    blocks = []
    for i, f in enumerate(findings):
        loc = f.location or "unknown"
        blocks.append(f"[{i}] {f.derived_vuln_class()} @ {loc} — {f.title} ({f.severity})")
    return "Confirmed findings:\n" + "\n".join(blocks) + "\n"


def _max_severity(findings: list[Finding], steps: list[int]) -> str:
    sevs = [findings[s].severity for s in steps]
    return max(sevs, key=lambda s: _SEVERITY_ORDER.get(s, 0)) if sevs else "info"


async def build_chains(
    findings: list[Finding], *, ask: AskFn, model: str | None = None
) -> tuple[list[Chain], bool]:
    """Ask the model for exploit chains over the kept findings.

    Deterministically validates every step index is in range and that a chain
    has >=2 distinct in-range steps; invalid chains are dropped. Returns
    ``(chains, degraded)`` — degraded is True only when the model call failed or
    its reply had no extractable JSON (a valid reply with zero chains is not a
    degradation)."""
    if len(findings) < 2:
        return [], False
    try:
        reply = await ask(_CHAIN_SYSTEM, _chain_user_prompt(findings), model=model)
    except Exception:  # noqa: BLE001 - chain failure degrades to no chains
        return [], True

    # Scan every top-level JSON value: a leading decoy scalar/array must not mask
    # the real chain payload behind it. The first payload that yields >=1 valid
    # chain wins; a payload that yields none (e.g. `[]` / `{"chains": []}`) is a
    # legitimate "no chains" (not degraded); no JSON payload at all degrades.
    saw_payload = False
    for data in _iter_json_values(reply):
        items = _chain_items(data)
        if items is None:
            continue
        saw_payload = True
        chains = _validate_chains(items, findings)
        if chains:
            return chains, False
    return ([], False) if saw_payload else ([], True)


# --- orchestration -----------------------------------------------------------


def run_triage(
    findings: list[Finding],
    *,
    engagement_id: str = "",
    assets_root: Path | None = None,
    line_tolerance: int = _DEFAULT_LINE_TOLERANCE,
    verify: bool = False,
    chain: bool = False,
    min_confidence: int = 7,
    security_requirements: dict[str, str] | None = None,
    ask: AskFn | None = None,
    model: str | None = None,
) -> TriageReport:
    """Triage: prefilter -> dedup -> [verify] -> enrich -> [chain] -> prioritise -> report.

    The deterministic core is credential-free and total. The opt-in ``verify``
    and ``chain`` stages use ``ask`` (defaulting to the ``llm.ask`` seam,
    resolved lazily so tests can inject/patch it) and are driven synchronously
    here via ``asyncio.run`` — a per-stage failure degrades, never crashes.
    """
    if (verify or chain) and ask is None:
        from . import llm

        ask = llm.ask

    timings: dict[str, float] = {}
    input_count = len(findings)
    degraded = False
    degraded_reasons: list[str] = []

    t0 = time.perf_counter()
    survivors, pre_dropped = prefilter(findings, assets_root=assets_root)
    timings["prefilter_ms"] = (time.perf_counter() - t0) * 1000

    t0 = time.perf_counter()
    canonical, dup_dropped = dedup(survivors, line_tolerance=line_tolerance)
    timings["dedup_ms"] = (time.perf_counter() - t0) * 1000

    dropped = pre_dropped + dup_dropped
    verified_total = 0
    confirmed_tp = 0

    if verify:
        verified_total = len(canonical)
        t0 = time.perf_counter()
        canonical, verify_dropped, verify_degraded = asyncio.run(
            verify_findings(
                canonical,
                ask=ask,
                min_confidence=min_confidence,
                assets_root=assets_root,
                model=model,
            )
        )
        timings["verify_ms"] = (time.perf_counter() - t0) * 1000
        dropped += verify_dropped
        confirmed_tp = sum(1 for f in canonical if f.verdict == "TRUE_POSITIVE")
        if verify_degraded:
            degraded = True
            degraded_reasons.append("verify stage failed for every finding")

    t0 = time.perf_counter()
    enrich(canonical, security_requirements=security_requirements)
    timings["enrich_ms"] = (time.perf_counter() - t0) * 1000

    chains: list[Chain] = []
    if chain:
        t0 = time.perf_counter()
        chains, chain_degraded = asyncio.run(build_chains(canonical, ask=ask, model=model))
        timings["chain_ms"] = (time.perf_counter() - t0) * 1000
        if chain_degraded:
            degraded = True
            degraded_reasons.append("chain stage produced no parseable result")

    # Offensive priority uses the environmental CVSS (from enrich) and chain
    # membership (from the chain stage), so it runs last. Always runs.
    prioritize(canonical, chains)

    metrics: dict = {
        "input": input_count,
        "kept": len(canonical),
        "dropped": len(dropped),
        "dropped_by_reason": dict(Counter(d.reason for d in dropped)),
        "chains": len(chains),
        "verified": verify,
        "timings_ms": {k: round(v, 2) for k, v in timings.items()},
    }
    if verify:
        metrics["precision"] = round(confirmed_tp / verified_total, 4) if verified_total else None

    return TriageReport(
        engagement_id=engagement_id,
        findings=canonical,
        dropped=dropped,
        chains=chains,
        metrics=metrics,
        degraded=degraded,
        degraded_reason="; ".join(degraded_reasons),
    )


def _drop(finding: Finding, reason: DropReason, detail: str = "") -> DroppedFinding:
    return DroppedFinding(finding=finding, reason=reason, detail=detail)
