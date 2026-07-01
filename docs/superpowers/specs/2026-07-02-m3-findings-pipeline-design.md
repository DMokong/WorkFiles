# M3 — `redteam triage`: findings pipeline (design spec)

**Status:** approved design, not yet implemented · **Date:** 2026-07-02 ·
**Branch:** `claude/security-testing-harness-X0QVs`

## Context

An engagement (`redteam run`) produces raw findings: the agent calls
`report__write_finding`, which records each finding into the tamper-evident
ledger (`finding.recorded` entries) and an incrementally-written SARIF file. The
first live engagement (2026-06-26) proved this works, but also showed the gap:
finding **capture** happens, yet there is no structural guarantee of finding
**quality** — no verification, deduplication, or enrichment. That is exactly the
strength of Visa's VVAH pipeline (see `docs/review-findings.json` and the VVAH
comparison in the session history), whose stages S5–S9 are: prefilter → verify →
dedup → chain → SARIF.

M3 builds that trust backend as a **separate, re-runnable `redteam triage`
command** that consumes a completed engagement's findings and emits a refined,
verified, enriched, chained report. It is the "workflow-shaped trust backend"
half of the hybrid *autonomous-agent-then-workflow* architecture.

## Goals

- Turn raw `finding.recorded` entries into trustworthy findings: deduplicated,
  CWE/CVSS-enriched, optionally adversarially verified, and composed into exploit
  chains — plus a refined SARIF and a human-readable markdown report.
- **Hybrid trust model:** deterministic stages (prefilter, dedup, enrich, emit)
  always run and need no model/credentials; the model-driven stages (verify,
  chain) are opt-in flags and reuse the engagement's backend.
- Read-only over the sealed engagement ledger (the authoritative record) — never
  mutate or re-seal it.
- Follow the repo's fail-closed, well-bounded-modules conventions; every
  model-output path degrades gracefully and never crashes the pipeline.

## Non-goals (explicit v-next, mark clearly in code/docs)

- Semantic/LLM dedup (v1 dedup is deterministic only).
- CMDB / environmental CVSS scoring and OffensivePriority (no CMDB in scope).
- Jira/Atlassian upsert of triaged findings (separate from M3).
- Multi-backend model routing (uses the one engagement backend).

## Design decisions (the forks we settled)

1. **Verify mechanism = hybrid.** Deterministic prefilter/dedup/enrich/emit
   always; LLM adversarial verify + chain opt-in (`--verify` / `--chain`).
2. **Placement = separate `redteam triage` subcommand** over the ledger, not
   inline in `run`. Decoupled and re-runnable; deterministic path is
   credential-free.
3. **Scope = full v1 including chaining** (prefilter, dedup, enrich, verify,
   chain, emit). Semantic dedup / CMDB / offensive-priority deferred.

## Architecture

New package `redteam/pipeline/`:

```
redteam/pipeline/
├── __init__.py
├── models.py     # Finding, DupLocation, Chain, DroppedFinding, TriageReport (pydantic)
├── load.py       # ledger finding.recorded payloads -> list[Finding]  (tolerant)
├── cwe.py        # keyword->CWE regex map + CWE id->name table (deterministic)
├── cvss.py       # CVSS 3.1 base score from a vector; severity-band fallback
├── llm.py        # one-shot model seam: ask(system, user, *, model=None) -> str
├── stages.py     # prefilter, dedup, enrich, verify, chain + run_triage() orchestration
└── emit.py       # refined SARIF (atomic) + markdown report + triage.json
```

CLI: a new `triage` command in `redteam/cli.py`.

**Reuse existing code (do not duplicate):**
- `redteam/tools/report.py::_atomic_write_json` for the atomic SARIF write.
- `redteam/preflight.py::detect_backend` to check a model backend exists before
  `--verify`/`--chain`, and to fail closed cleanly if not.
- The whitebox containment pattern (`redteam/tools/whitebox.py::_resolve_under_assets`)
  when the verify stage reads source around a finding's location — the pipeline
  must not read outside the asset scope.
- The SARIF result shape and level mapping already in `report.py`
  (`info/low->note, medium->warning, high/critical->error`).

## Data model (`models.py`)

All pydantic `BaseModel`. Field validators should be tolerant (coerce/skip, never
crash on a malformed agent finding) — mirror the robustness discipline VVAH uses.

```python
class DupLocation(BaseModel):
    file: str
    line: int | None = None

class Finding(BaseModel):
    # from the agent (report__write_finding)
    title: str
    severity: Literal["info", "low", "medium", "high", "critical"]
    description: str = ""
    evidence: dict = {}
    location: str | None = None          # "file:line" or "file:start-end"
    vuln_class: str | None = None        # derived if absent (keyword)
    ts: str | None = None
    # deterministic enrichment
    cwe: str | None = None               # "CWE-89"
    cwe_name: str | None = None
    cvss_vector: str | None = None       # "CVSS:3.1/AV:N/..."
    cvss_score: float | None = None
    cvss_rating: str | None = None       # Critical/High/Medium/Low/None
    cvss_source: Literal["vector", "severity_band"] | None = None
    # dedup
    duplicates: list[DupLocation] = []
    # verify (opt-in)
    verdict: Literal["TRUE_POSITIVE", "FALSE_POSITIVE", "UNVERIFIED"] | None = None
    verdict_confidence: int | None = None    # 0..10
    verdict_reason: str = ""

    def canonical_key(self, line_bucket: int = 10) -> tuple:
        # (file, line // bucket, vuln_class) — used by dedup
        ...

class Chain(BaseModel):
    title: str
    steps: list[int]        # indices into the final ranked findings list (>=2, validated)
    severity: str
    narrative: str = ""

class DroppedFinding(BaseModel):
    finding: Finding
    reason: Literal["NO_EVIDENCE", "BAD_LOCATION", "FILE_NOT_FOUND",
                    "DUPLICATE", "FALSE_POSITIVE", "UNCONFIRMED"]
    detail: str = ""

class TriageReport(BaseModel):
    engagement_id: str
    findings: list[Finding]         # canonical, kept (verified if --verify)
    dropped: list[DroppedFinding]
    chains: list[Chain]
    metrics: dict                   # counts, precision (if verified), stage timings
    degraded: bool = False
    degraded_reason: str = ""
```

## Stages (`stages.py`)

Orchestrator:
```python
def run_triage(findings: list[Finding], *, assets_root: Path | None,
               verify: bool = False, chain: bool = False,
               min_confidence: int = 7, ask=llm.ask) -> TriageReport
```
`ask` is injected for testability (default `llm.ask`).

1. **prefilter** (deterministic, VVAH S5). Drop a finding when:
   - `description` empty AND `evidence` empty, or
   - `location` missing / not `file:line`-shaped, or
   - (when `assets_root`) the referenced file does not resolve to an existing
     file **under the asset scope** (use the whitebox containment resolver).
   Record each as `DroppedFinding(reason=NO_EVIDENCE|BAD_LOCATION|FILE_NOT_FOUND)`.

2. **dedup** (deterministic, VVAH S7a). Group by `canonical_key`; within a group,
   the first is canonical, the rest merge as `DupLocation`s (dropped as
   `DUPLICATE`). Two findings dedup when same `(file, vuln_class)` AND line within
   `line_tolerance` (default 10) or overlapping ranges.

**Execution order:** prefilter → dedup → **verify (opt)** → **enrich** → chain
(opt) → emit. Enrich runs *after* verify so a verify-produced CVSS vector is what
gets scored (CWE assignment is order-independent; CVSS scoring is not).

3. **verify** (opt-in LLM, VVAH S6). For each canonical finding, one `ask()`:
   - system: adversarial reviewer — *assume the finding is a FALSE POSITIVE until
     personally confirmed from the code; walk callers; look for upstream
     controls; then emit a verdict.*
   - user: the finding (title/severity/description/evidence/location) + the source
     around `location` (read via the contained resolver; a window of lines).
   - required reply grammar (last lines), parsed by regex bottom-up:
     `VERDICT: TRUE_POSITIVE|FALSE_POSITIVE (confidence: N/10) — <reason>` and
     optional `CVSS: CVSS:3.1/...`.
   - deterministic gate: `TRUE_POSITIVE` & `confidence >= min_confidence` → kept
     (set verdict fields; if a CVSS vector was returned, it flows into enrich);
     `TRUE_POSITIVE` below gate → dropped `UNCONFIRMED`; unparseable reply →
     `verdict="UNVERIFIED"` and **kept** (NOT laundered to FP); `FALSE_POSITIVE`
     → dropped `FALSE_POSITIVE`.
   - run findings concurrently with a bounded pool (e.g. asyncio.gather over a
     semaphore, size ~4). Any exception on a finding → `UNVERIFIED` (never crash).

4. **enrich** (deterministic; runs after verify).
   - **CWE** (`cwe.py`): ordered keyword→CWE regexes over `title + description +
     vuln_class` (e.g. `\bsql\s*inject`→CWE-89, `\bssrf\b`→CWE-918, hardcoded
     secret/key/password→CWE-798, missing/no auth→CWE-306, broken access
     control/IDOR→CWE-284/639, `debug=True`/debugger→CWE-489, path traversal
     →CWE-22, command inj→CWE-78), then a `vuln_class`→CWE fallback; attach
     `cwe` + `cwe_name`.
   - **CVSS** (`cvss.py`): if `cvss_vector` present (from verify), compute the
     FIRST.org CVSS 3.1 **base** score + rating deterministically and set
     `cvss_source="vector"`. Else derive a band score from `severity`
     (critical≈9.3, high≈7.8, medium≈5.5, low≈2.5, info≈0.0), `cvss_source=
     "severity_band"`. Rating bands: Critical 9.0–10, High 7.0–8.9, Medium
     4.0–6.9, Low 0.1–3.9, None 0.

5. **chain** (opt-in LLM, VVAH S8). One `ask()` over all kept findings rendered as
   indexed blocks (`[i] <vuln_class> @ file:lines — title`), asking for
   combinations that compose into an attack path (e.g. info-leak + auth-bypass +
   memory-corruption). Reply is a small JSON (use a robust extractor) of
   `{title, steps:[i...], severity, narrative}`. Deterministically validate step
   indices are in range and `len>=2`; drop invalid chains; on any parse failure
   set `chains=[]` (degrade, do not crash).

6. **emit** (`emit.py`, deterministic).
   - refined **SARIF 2.1.0** at `<out>/<stem>.triaged.sarif` (atomic via
     `report._atomic_write_json`): one result per kept finding with `ruleId`
     (CWE or vuln_class), `level`, `message`, `properties`
     (severity, cwe/cweName, cvssScore/cvssRating/cvssVector, verdict/confidence),
     `relatedLocations` for dedup DupLocations, and a CWE taxonomy block. Reuse
     `report.py`'s level mapping.
   - **markdown** report at `<out>/<stem>.report.md`: summary, metrics (kept /
     dropped / precision if verified), a findings table (severity · CWE · CVSS ·
     verdict · location), exploit chains, and a dropped-findings appendix (reason
     per finding).
   - **`triage.json`** at `<out>/<stem>.triage.json`: the full `TriageReport`.

## Load (`load.py`)

```python
def findings_from_ledger(ledger_path: Path) -> tuple[str, list[Finding]]
```
Parse each JSONL line → `payload = rec.get("payload", rec)`; for
`payload["kind"] == "finding.recorded"`, coerce `payload["finding"]` into a
`Finding` (tolerant; skip + log a malformed one). Return `(engagement_id,
findings)`. Also read `session.start`/signature for the engagement id if needed.

## Model seam (`llm.py`)

```python
async def ask(system: str, user: str, *, model: str | None = None,
              timeout_s: float = 120) -> str
```
One-shot, no tools (pure reasoning). Implement over the Agent SDK's one-shot
`query()` (spawns the `claude` CLI, so it reuses the engagement's auth — host
Claude Code login today, Bedrock/Vertex later). **Confirm the exact `query()` /
`ClaudeAgentOptions` usage against the installed SDK (claude_agent_sdk 0.2.98)**
— set `system_prompt=system`, `max_turns=1`, no `mcp_servers`; collect the
assistant text from the streamed messages. Fail with a clear error the CLI turns
into a clean exit if no backend is configured (mirror `_run_with_sdk`).

Provide a sync wrapper if the stages are easier to drive synchronously, or keep
`run_triage` async. Keep `ask` injectable so tests never spawn a model.

## CLI (`redteam/cli.py`)

```
redteam triage <ledger.jsonl> [--assets-root DIR] [--verify] [--chain]
               [--min-confidence 7] [--out DIR] [--model ID]
```
- default `--out` = the ledger's parent dir; output stem from the ledger name.
- deterministic stages always run; `--verify` and/or `--chain` require a model
  backend (`preflight.detect_backend`) — if absent, exit cleanly with a message
  (like the RT-26 `run` path), do not traceback.
- print a short summary (kept / dropped / chains / precision) and the artifact
  paths, mirroring the `run` command's end-of-run summary.

## Error handling / fail-closed

- Deterministic stages are total (never raise on a bad finding — drop + record).
- Every `ask()` call is wrapped; verify failure → `UNVERIFIED`, chain failure →
  `chains=[]`; set `degraded=True` + `degraded_reason` when a whole LLM stage
  falls back.
- Robust reply parsing: verdict via bottom-up regex; chain via a
  brace-balanced/escape-tolerant JSON extractor (port the small VVAH-style
  extractor or write an equivalent). A decoy/garbage reply must never crash.
- Reading source for verify is confined to the asset scope (containment resolver)
  — a malicious `location` cannot escape it.

## Testing

- **Deterministic (no model):** `load` tolerance; `prefilter` each drop reason;
  `dedup` collapse + DupLocation; `cwe` mapping (representative classes);
  `cvss` from a known vector and the severity-band fallback + ratings; `emit`
  SARIF shape (levels, CWE taxonomy, relatedLocations) and markdown structure.
- **LLM stages (mocked `ask`):** verify verdict parse + gate (keep / drop-FP /
  drop-UNCONFIRMED / UNVERIFIED-not-laundered), concurrency, exception→UNVERIFIED;
  chain index validation + degrade on garbage.
- **End-to-end fixture:** capture the live run's 6-finding ledger as
  `tests/fixtures/live-6-findings.jsonl` (copy from
  `audit/whitebox-first/ENG-WHITEBOX-FIRST.jsonl`) and run `triage` deterministically
  → assert 6 kept, CWE/CVSS present, refined SARIF + markdown emitted; then the
  `--verify` path with a canned `ask` that confirms 5 and refutes 1 → assert the
  gate drops the refuted one.
- **Adversarial verification workflow** after the batch (per the repo cadence):
  one reviewer per stage + a regression hunter; fix what it finds; re-verify.
- Optional **live** check: `redteam triage <live ledger> --verify --chain` against
  the host `claude` to confirm the model stages run end-to-end (consumes credits).

## Acceptance criteria

1. `redteam triage <ledger>` (deterministic) over the 6-finding fixture produces a
   refined SARIF + markdown + triage.json with all 6 findings CWE/CVSS-enriched
   and any duplicates collapsed — no model, no creds.
2. `--verify` (mocked in tests; live-capable) applies the confidence gate: a
   refuted finding is dropped `FALSE_POSITIVE`, an unparseable verdict becomes
   `UNVERIFIED` (kept), the rest kept with verdict + confidence.
3. `--chain` produces validated chains (≥2 in-range steps) or degrades to none.
4. `--verify`/`--chain` with no backend exits cleanly (no traceback).
5. Full suite green + ruff clean; the pipeline never crashes on malformed findings
   or garbage model output; adversarial verification passed.

## References

- VVAH stage mapping: prefilter=S5, verify=S6, dedup=S7a, chain=S8, SARIF=S9.
- Reuse: `report._atomic_write_json`, `report` SARIF level map, `preflight.detect_backend`,
  whitebox containment resolver, the SDK `query()` one-shot.
- Ledger finding shape: `payload.kind == "finding.recorded"`,
  `payload.finding = {title, severity, description, evidence, location, ts, engagement_id}`.
