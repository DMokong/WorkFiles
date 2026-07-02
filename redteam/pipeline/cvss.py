"""Deterministic CVSS 3.1 base + environmental score from a vector.

Implements the FIRST.org CVSS v3.1 *base* metric equations exactly, plus the
*environmental* score (modified base metrics + Security Requirements CR/IR/AR)
per spec section 7.3. Temporal metrics are treated as Not Defined (a documented
v-next). When a finding carries no vector, ``severity_band`` maps the agent's
coarse severity to a representative score so every kept finding still has a
number.
"""

from __future__ import annotations

import math

# --- base metric weights (CVSS v3.1 spec, section 7) ---
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}
# Privileges Required depends on Scope (Changed raises the L/H weights).
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}
# Security Requirement multipliers (CR/IR/AR). Medium and Not-Defined are 1.0.
_REQ = {"H": 1.5, "M": 1.0, "L": 0.5, "X": 1.0}

_REQUIRED = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")

# Representative scores for the severity-band fallback (no vector available).
_SEVERITY_BAND = {
    "critical": 9.3,
    "high": 7.8,
    "medium": 5.5,
    "low": 2.5,
    "info": 0.0,
}


def _roundup(value: float) -> float:
    """CVSS v3.1 Roundup: round *up* to one decimal place (spec Appendix A)."""
    int_input = round(value * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000.0
    return (math.floor(int_input / 10000) + 1) / 10.0


def _parse_vector(vector: str) -> dict[str, str] | None:
    """Metrics dict from a ``CVSS:3.x/AV:N/...`` string, or None if unusable."""
    if not vector or "/" not in vector:
        return None
    metrics: dict[str, str] = {}
    for part in vector.split("/"):
        if part.upper().startswith("CVSS:"):
            continue
        key, sep, val = part.partition(":")
        if sep:
            metrics[key.strip().upper()] = val.strip().upper()
    if not all(k in metrics for k in _REQUIRED):
        return None
    return metrics


def metrics(vector: str) -> dict[str, str] | None:
    """Public: parsed metric dict for a valid base vector, else None.

    Lets other stages read exploitability metrics (AV/AC/PR/UI) without
    re-parsing the vector string themselves.
    """
    return _parse_vector(vector)


def rating_for(score: float) -> str:
    """Qualitative rating for a base score (CVSS v3.1 severity rating scale)."""
    if score <= 0:
        return "None"
    if score < 4.0:
        return "Low"
    if score < 7.0:
        return "Medium"
    if score < 9.0:
        return "High"
    return "Critical"


def base_score(vector: str) -> tuple[float, str] | None:
    """``(base_score, rating)`` for a CVSS 3.1 vector, or None if not computable.

    Returns None for a garbage vector, a vector missing a required base metric,
    or an out-of-range metric value — the caller then uses ``severity_band``.
    """
    metrics = _parse_vector(vector)
    if metrics is None:
        return None
    scope_changed = metrics["S"] == "C"
    pr_table = _PR_CHANGED if scope_changed else _PR_UNCHANGED
    try:
        av = _AV[metrics["AV"]]
        ac = _AC[metrics["AC"]]
        pr = pr_table[metrics["PR"]]
        ui = _UI[metrics["UI"]]
        c = _CIA[metrics["C"]]
        i = _CIA[metrics["I"]]
        a = _CIA[metrics["A"]]
    except KeyError:
        return None  # an unrecognised metric value

    isc_base = 1 - ((1 - c) * (1 - i) * (1 - a))
    if scope_changed:
        impact = 7.52 * (isc_base - 0.029) - 3.25 * (isc_base - 0.02) ** 15
    else:
        impact = 6.42 * isc_base
    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        score = 0.0
    elif scope_changed:
        score = _roundup(min(1.08 * (impact + exploitability), 10))
    else:
        score = _roundup(min(impact + exploitability, 10))
    return score, rating_for(score)


def environmental_score(
    vector: str, requirements: dict[str, str] | None = None
) -> tuple[float, str] | None:
    """``(environmental_score, rating)`` for a CVSS 3.1 vector, or None.

    Applies the CVSS 3.1 environmental equation: modified base metrics
    (``MAV``/``MAC``/``MPR``/``MUI``/``MS``/``MC``/``MI``/``MA``) taken from the
    vector if present (else the base value), and Security Requirements
    ``CR``/``IR``/``AR`` taken from ``requirements`` (engagement-wide), else the
    vector, else Not Defined. With no environmental inputs the result equals the
    base score for scope-UNCHANGED vectors; for scope-CHANGED (``S:C``) vectors
    CVSS 3.1's environmental modified-impact formula genuinely differs from the
    base impact formula, so env can differ from base by ~0.1 even with no inputs
    (this is spec-correct). Temporal metrics are treated as Not Defined (1.0).
    """
    metrics = _parse_vector(vector)
    if metrics is None:
        return None
    if requirements:
        for k in ("CR", "IR", "AR"):
            v = requirements.get(k)
            if v:
                metrics[k] = v.strip().upper()
    try:
        return _environmental_from_metrics(metrics)
    except KeyError:
        return None  # an unrecognised modified-metric value


def _mod(metrics: dict[str, str], modified_key: str, base_key: str) -> str:
    """Value of a modified base metric, falling back to the base metric.

    A missing or explicit ``X`` (Not Defined) modified metric uses the base.
    """
    v = metrics.get(modified_key)
    return metrics[base_key] if not v or v == "X" else v


def _environmental_from_metrics(m: dict[str, str]) -> tuple[float, str]:
    mav = _AV[_mod(m, "MAV", "AV")]
    mac = _AC[_mod(m, "MAC", "AC")]
    mui = _UI[_mod(m, "MUI", "UI")]
    ms_changed = _mod(m, "MS", "S") == "C"
    mpr = (_PR_CHANGED if ms_changed else _PR_UNCHANGED)[_mod(m, "MPR", "PR")]
    mc = _CIA[_mod(m, "MC", "C")]
    mi = _CIA[_mod(m, "MI", "I")]
    ma = _CIA[_mod(m, "MA", "A")]
    cr = _REQ[m.get("CR", "X")]
    ir = _REQ[m.get("IR", "X")]
    ar = _REQ[m.get("AR", "X")]

    miss = min(1 - (1 - mc * cr) * (1 - mi * ir) * (1 - ma * ar), 0.915)
    if ms_changed:
        mod_impact = 7.52 * (miss - 0.029) - 3.25 * (miss * 0.9731 - 0.02) ** 13
    else:
        mod_impact = 6.42 * miss
    mod_exploit = 8.22 * mav * mac * mpr * mui

    if mod_impact <= 0:
        score = 0.0
    elif ms_changed:
        score = _roundup(min(1.08 * (mod_impact + mod_exploit), 10))
    else:
        score = _roundup(min(mod_impact + mod_exploit, 10))
    return score, rating_for(score)


def severity_band(severity: str) -> tuple[float, str]:
    """Representative ``(score, rating)`` for a coarse severity label."""
    score = _SEVERITY_BAND.get((severity or "").strip().lower(), 0.0)
    return score, rating_for(score)
