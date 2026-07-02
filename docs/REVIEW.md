# redteam — Blueprint Review

**Repo:** `redteam` · **Branch:** `claude/security-testing-harness-X0QVs` · **Date:** 2026-06-12

> Machine-readable companion: [`docs/review-findings.json`](review-findings.json).
> Every finding carries `file:line`, a reproduction/evidence note, and a fix.

> **Update 2026-06-12 — RT-01..RT-08 fixed.** The three critical and eight
> high-severity findings RT-01 through RT-08 have been implemented and verified
> (39 regression tests in `tests/test_fixes_rt01_08.py`; full suite 66 passed;
> ruff clean). Each fix was adversarially re-reviewed; RT-06 was re-hardened
> after the first review pass found it incomplete (trailing-dot / semicolon
> path-param bypasses) and then independently re-verified. Incidentally fixed:
> RT-19 (entry_count), and partially RT-15 (subagents are now real
> `AgentDefinition`s with mapped tool subsets) and RT-26 (the PreToolUse hook
> now fails closed). Two small residuals remain and are noted in the JSON:
> RT-07's bare-host/CIDR egress (the "or" alternative) and RT-03's container
> `/assets` mount (harmless for host-path whitebox). See the per-finding
> `fix_note` fields in `review-findings.json`.

> **Update 2026-06-14 — RT-09, RT-10, RT-12, RT-13, RT-14, RT-15 fixed.** The
> remaining six high-severity findings are done (18 tests in
> `tests/test_fixes_rt09_15.py`; full suite 84 passed; ruff clean). Adversarial
> re-review caught and then fixed two of them mid-batch: RT-12 (a naive-datetime
> window would crash `covers()` — now rejected at parse) and RT-15 (an empty
> `tools: []` became "inherit all" — now correctly zero, with malformed input
> failing closed). All **14 of the critical/high findings (RT-01..RT-15) are now
> resolved.** Next blocker for an actual container run is **RT-23** (the SDK
> needs a writable `HOME` under the read-only rootfs).

> **Update 2026-06-24 — RT-23 fixed (container run unblocked).** The read-only
> rootfs container now completes startup end-to-end. The entrypoint gives the
> SDK a writable state dir (`/home/redteam` tmpfs → `HOME`/`CLAUDE_CONFIG_DIR`,
> chowned + write-probed as uid 10001, fail-closed exit 71/72), and a new
> `redteam/runtime/render_netpolicy.py` **consumes** `netpolicy.json` to render
> the engagement's `egress_allowlist` into an **nft default-deny** ruleset
> (IMDS dropped before any accept; loaded via `nft -f -`, fail-closed exit 70).
> `atlassian_token` became an opt-in overlay (`docker-compose.atlassian.yml`).
> 21 unit tests (`tests/test_fixes_rt23.py`) + a real `docker compose run`
> smoke (`tests/container/smoke_rt23.sh`); full suite 105 passed; ruff clean.
> Adversarial re-review caught and fixed two defects mid-batch: **F1** — an
> overlapping allow-list (host + its CIDR) made `nft -f` reject the ruleset and
> brick the boot (now collapsed with `ipaddress.collapse_addresses`); **F2** —
> the IMDS allow-set scrub was string-compared, so a non-canonical IPv6 IMDS
> spelling slipped in (the explicit drop still won by ordering; now scrubbed by
> parsed address). The reviewers also flagged that the renderer and the CLI
> could read two *different* engagements, so the egress box and the run are now
> pinned to a single engagement path. Residual (low, documented): DNS egress is
> accepted to any host (covert channel); resolved-hostname IP sets can drift
> (the host network policy / security group is the durable backstop). With
> RT-23 done, the remaining open items are the lower-severity hardening sweep
> (RT-11, RT-16–RT-22, RT-24–RT-31).

> **Update 2026-06-26 — M0+M1: the harness can run a contained engagement
> end-to-end (closes RT-21 and the CLI-run slice of RT-26).** *M0 (runnable
> transport):* the runtime image now ships Node + a pinned
> `@anthropic-ai/claude-code` (the Agent SDK spawns the `claude` CLI as its
> transport); a new `redteam doctor [--probe]` command + `redteam/preflight.py`
> verify readiness without spending a token, and the entrypoint now gates the
> egress netpolicy + engagement-path append to engagement-bearing subcommands so
> diagnostics work with no engagement mounted. Proven in-container:
> `docker compose run redteam doctor --probe` shows the SDK spawning the CLI
> transport under the read-only rootfs. *M1 (trustworthy output):* the report
> SARIF write is now atomic (temp + `os.replace`, serialize-first) and
> lock-serialized (**RT-21 fixed**), with a corrupt base quarantined; the CLI
> `run` path fails closed with clean exit codes (RT-26 CLI slice); and the
> cage-validation (allow / deny / outside-window / fail-closed, each recorded in
> the ledger) plus an end-to-end seal→`redteam-verify`→SARIF flow are pinned as
> contract tests. 32 new tests (full suite 135 passed; ruff clean).
> Adversarial re-review (3 reviewers) caught and fixed a probe that orphaned the
> `claude` subprocess on timeout, a `cli_missing`-vs-`sdk_missing` mislabel,
> `find_cli` diverging from the SDK's fallback paths, and `doctor --probe`
> phoning home with no egress box (CLI telemetry/autoupdater now disabled at the
> image). **Residual:** a true *autonomous* live run needs model credentials
> (`ANTHROPIC_API_KEY`, or `CLAUDE_CODE_USE_BEDROCK`/`_VERTEX` + creds, with the
> backend host added to `egress_allowlist`) — everything up to that boundary is
> verified; `engagements/whitebox-first.example.yaml` is the contained first-run
> template. RT-17 and the seal-swallow slice of RT-26 stay open.

> **Update 2026-06-26 (later) — FIRST REAL AUTONOMOUS ENGAGEMENT RAN
> SUCCESSFULLY** (host headless `claude` 2.1.191). Against a planted-vulnerable
> backend, the agent autonomously ran the loop, the scope-guard cage **denied
> `ToolSearch`/`Read` and allowed the whitelisted `whitebox`/`report` tools
> live**, and it recorded **6 correct findings** (SQLi, broken access control,
> unauthenticated PII export, hardcoded Stripe + DB secrets, Flask debug RCE) via
> `report__write_finding` → 6 SARIF results + 6 `finding.recorded` entries; the
> 42-entry hash-chained ledger sealed and `redteam-verify` passed. The *first*
> attempt also did exactly what a live smoke is for: it exposed a **critical
> runtime-only bug all 138 unit tests missed** — the SDK invokes a tool handler
> with a single `args` dict and expects `{"content": [...]}` back, but our
> handlers took unpacked params and returned raw dicts, so *every tool crashed*.
> Fixed with a dual-convention adapter in `redteam/tools/_sdk_shim.py` (pinned by
> `tests/test_m1_tool_sdk_contract.py`) and re-verified by a clean re-run. Open
> follow-ups the live run surfaced: finding capture is prompt-driven, not
> structurally enforced (motivates an M3 verify/report pipeline), and RT-20's
> PostToolUse/budget accounting is imprecise (11 post-records for 19 allowed
> calls).

> **Update 2026-07-02 — M3: the `redteam triage` findings-quality pipeline (the
> workflow-shaped trust backend).** The live run proved finding *capture* works
> but nothing guaranteed finding *quality*. M3 adds a separate, re-runnable
> `redteam triage <ledger>` command that reads the sealed ledger **read-only**
> (hash-verified unchanged before/after) and emits a refined, deduplicated,
> CWE/CVSS-enriched report — SARIF 2.1.0 + markdown + `triage.json`. The
> deterministic stages (**prefilter → dedup → enrich → emit**) need no model or
> credentials and are *total* (a malformed finding is dropped-and-recorded,
> never raised); adversarial LLM **verify** (confidence-gated; an unparseable or
> conflicting verdict becomes UNVERIFIED and is **kept**, never laundered to
> FALSE_POSITIVE) and exploit-**chain** synthesis are opt-in flags gated on a
> configured backend (`preflight.detect_backend`), driven over the SDK's one-shot
> `query()`. Built strictly TDD (**266 passed, ruff clean**). A five-reviewer
> adversarial workflow + a focused re-verifier caught and fixed **14 defects** —
> the sharpest being an `extract_json` **O(N²) hang** and an uncaught
> `RecursionError` on adversarial model output (both violated *never hang/crash*;
> fixed with a bounded `raw_decode`-based extractor), a **schema-invalid SARIF**
> `startLine:0`, **verdict laundering** via a conflicting bottom-up verdict line,
> and **enrich trusting a ledger-injected CVSS vector** (fixed by whitelisting
> only the agent's report fields at load). Every model-output path degrades; the
> pipeline never crashes on a malformed finding or garbage model reply. v-next
> (documented non-goals): semantic dedup, CMDB/environmental CVSS +
> offensive-priority, Jira upsert of triaged findings, multi-backend routing.

> **Update 2026-07-02 (later) — build-next #2: the KMS sealer switch is wired.**
> The `Sealer` protocol + `KmsHmacSealer` existed and `verify.py` already
> dispatched on `seal["method"]`, but `Orchestrator.seal()` still used the file
> HMAC key. Now `build_sealer(env)` returns a `KmsHmacSealer` when
> `REDTEAM_KMS_KEY_ID` is set (region from `REDTEAM_KMS_REGION` → `AWS_REGION`
> → `AWS_DEFAULT_REGION`) and `None` otherwise; `LedgerWriter` takes an
> injected `sealer` that is **authoritative over** the file key; the CLI `run`
> path injects `build_sealer(os.environ)` beside `load_hmac_key()`. So the
> container seals with **KMS** (`kms:GenerateMac`) while local pytest keeps the
> file-key fallback — which now records `method: "file"` so the verifier
> dispatches explicitly. `KmsHmacSealer.write_seal()` owns the KMS seal-file
> format (the `write_kms_seal` free fn delegates to it); **boto3 stays lazy**
> (import-safe, no live AWS call in any mocked test). Fail-closed preserved:
> `seal()` still raises when neither a sealer nor a key is present, and a real
> `kms:GenerateMac` error propagates (botocore errors aren't `RuntimeError`)
> rather than silently producing an unsealed ledger. Built TDD
> (`tests/test_kms_sealer_switch.py`, **280 passed, ruff clean**) and hardened
> by a three-agent adversarial pass (seal/verify correctness + fail-closed,
> regression hunter, hard-constraint compliance) — all clean; the only flag was
> the CLAUDE.md doc-sync this batch applies. A live KMS seal is unexercisable
> here (no AWS creds on the host); the boto3-mocked tests cover
> sign/verify/write_seal/round-trip.

> **Update 2026-07-02 (later still) — build-next #4: recon `gh_*` tools.**
> Three **read-only, org-scoped** GitHub recon tools (`gh_search_code`,
> `gh_search_repos`, `gh_repo_view`) that shell out to the `gh` CLI baked into
> the runtime image (list argv, **no shell**), added to the scope guard's
> targetless allowlist (GitHub egress is via the authenticated `gh`, not an
> engagement scope target). Built TDD; a two-agent adversarial pass
> (security/injection+containment, regression) found no command/flag injection
> but surfaced **three real gaps between the guarantees the docstring claimed
> and what the code enforced**, all fixed in-batch: (1) "org-scoped, never
> global" wasn't *enforced* — `owner` was unbound to the engagement and a
> `query` could smuggle `org:`/`user:`/`repo:` GitHub qualifiers to escape
> `--owner`; now a new optional `scope.github_orgs` allowlist binds the owner
> when set, and scope-broadening query qualifiers are refused; (2) `int(limit)`
> sat outside the try/except, so a non-int `limit` raised — contradicting the
> "total, never raise" contract; now `_clamp_limit` returns a structured error;
> (3) the login/repo regexes used `$` (accepts a trailing newline) → switched
> to `\Z`. Full suite **302 passed, ruff clean**. The mounted PAT's scope
> stays the ultimate boundary — the docstring now says so honestly instead of
> overclaiming. `whois` / `cert_transparency` remain documented stubs.

> **Update 2026-07-02 (later still²) — build-next #6: real semgrep / tfsec /
> checkov.** New `redteam/tools/_scanners.py` runs the three scanners for the
> whitebox pack and normalises each tool's JSON to one finding shape;
> `whitebox__semgrep_scan` (by `role`) and `whitebox__iac_scan` (by `kind`,
> optional `scanner` override) replace the `not_implemented` stubs. The
> load-bearing subtlety: **these scanners exit non-zero when they find
> issues**, so the code parses stdout JSON *regardless of exit code* — valid
> JSON is success, unparseable output is the error. No shell (list argv), and
> the scanned path is always a resolved asset host_path, never agent-typed, so
> there's no injection surface. Built TDD; a two-agent adversarial pass
> (correctness/schema-fidelity/totality + regression) confirmed the parser keys
> match the real semgrep/tfsec/checkov schemas and found **two real totality
> defects**, both fixed: (1) `json.loads(stdout or "{}")` **laundered an
> empty-stdout crash** (exit ≥2, output only on stderr) into a clean "ok, 0
> findings" — a security scanner silently reporting a failed run as clean is a
> trust bug; empty/whitespace stdout is now an error; (2) the parsers raised
> `TypeError` on a truthy non-list `results`/`failed_checks` — now guarded by
> `_as_list`. Full suite **320 passed, ruff clean**. `sbom_query` /
> `openapi_diff` / `dependency_audit` remain documented stubs. NB: `semgrep
> --config auto` needs `semgrep.dev` in the egress allowlist (added to the
> example).

> **Update 2026-07-02 (later⁴) — build-next #5: idempotent Atlassian/Jira
> upsert.** The Atlassian MCP is *agent-driven*, so the harness owns only the
> deterministic scaffolding: new `redteam/jira.py` computes a stable
> `external_key` (`redteam-<engagement>-<12hex>` over normalised
> title+location, so a re-run updates the same ticket), the JQL to find it, the
> issue `fields`, and the create-vs-update decision. Wired into `report.py` as
> the **gated** `report__jira_upsert` tool (only when the atlassian MCP is
> enabled AND `reporting.jira_project` is set) and into the M3 triage output as
> a `<stem>.jira.json` bundle (`redteam triage --jira-project SEC`). Both the
> live tool and triage derive the SAME key, so they converge on one ticket per
> finding. Built TDD; a two-agent adversarial pass (security + regression)
> **confirmed a real JQL-injection** confined to the triage path — the
> `--jira-project` CLI flag bypassed the schema validator, and a **tampered
> ledger's `engagement_id`** flowed unvalidated into the JQL and Jira labels
> (the repo's own "tampered ledger must not inject trust" threat model). Fixed
> defence-in-depth: the engagement id is **sanitised** inside `external_key`
> (always a space/quote-free label; identity for schema-valid ids),
> `jql_for_key` **escapes** `\` and `"` in both operands, and `--jira-project`
> is validated with the same grammar as the schema field (exit 2 on a bad key).
> Full suite **344 passed, ruff clean**. (Noted, out of scope: `triage` still
> doesn't verify the ledger seal before triaging — the injection is neutralised
> regardless.) Third-party MCP allowlist stays `{atlassian}`.

> **Update 2026-07-02 (later⁵) — build-next #7: OTel exporter + starter Grafana
> dashboard.** `docker compose -f redteam/runtime/docker-compose.yml --profile
> dev up` now lights up Grafana with **populated** panels, no manual import. The
> redteam service sets the (docs-confirmed) Claude Code telemetry env
> (`CLAUDE_CODE_ENABLE_TELEMETRY=1`, `OTEL_METRICS_EXPORTER`/`_LOGS_EXPORTER=otlp`,
> `OTEL_EXPORTER_OTLP_PROTOCOL=grpc` → the collector on `:4317`); the collector
> routes **metrics→Prometheus** (`:8889`, scraped) and **traces→Tempo**; and
> Grafana **auto-provisions** both datasources + the `redteam-engagement`
> dashboard (six `claude_code_*` metric panels). New `tempo.yaml` /
> `prometheus.yml` / `grafana/provisioning/*` / dashboard JSON; the old
> import-only `grafana_dashboard.json` is superseded. Built with contract tests
> (`tests/test_otel_provisioning.py`) + `docker compose config` validation. A
> two-agent adversarial pass (wiring + regression) traced every hop for
> port/name consistency and caught **two real defects**, both fixed: (1) the
> collector's Prometheus exporter defaults `add_metric_suffixes: true`, which
> inserts the unit into names (`claude_code_token_usage_tokens_total`, …) and
> would have left three panels on "No data" — set `add_metric_suffixes: false`
> and query plain `claude_code_*` names; (2) the Tempo traces panel could never
> populate (Claude Code traces are beta-gated and the app's `telemetry.py` is a
> no-op tracer — RT-22), so the dead panel was removed while keeping the Tempo
> datasource + traces pipeline wired for when trace export lands. Full suite
> **352 passed, ruff clean**. Noted (not auto-fixed, to preserve the security
> model): the default-deny egress nft ruleset drops OTLP to the collector in the
> hardened container — the dev stack needs `REDTEAM_NETPOLICY_OPTIONAL=1` or the
> collector in `egress_allowlist`.

> **Update 2026-07-02 (later⁶) — build-next #8 (part 1): environmental CVSS +
> offensive-priority scoring.** The first M3 v-next slice. `cvss.py` gains
> `environmental_score` — the full CVSS 3.1 §7.3 environmental equation
> (modified base metrics + Security Requirements CR/IR/AR; temporal treated as
> Not Defined) — feeding the deterministic `enrich` stage; a new
> `stages.prioritize` (run after chains) blends environmental CVSS with the
> offensive signals an attacker cares about — network reachability / no-auth /
> no-interaction, a confirmed verdict, and exploit-chain membership — into a
> 0–100 score and a P1–P4 tier. Driven by `redteam triage
> --security-requirements CR:H,IR:H`; surfaced in SARIF props, the markdown
> Priority/Env columns, and `triage.json`. Built TDD; a two-agent adversarial
> pass **independently cross-checked the environmental math two ways** — a
> from-scratch reimplementation of the FIRST.org equations over 9,984 vectors
> **and** the RedHat `cvss` library over 2,400 vectors — **0 mismatches**. It
> found **three real defects**, all fixed: (1) the docstring/test wrongly
> claimed `env == base` as a *general* identity, but CVSS 3.1's base vs
> environmental scope-changed impact formulas genuinely differ (`^15` vs
> `·0.9731^13`), so an `S:C` vector with no inputs legitimately gives env ≠
> base (e.g. 6.9→7.0) — corrected to scope the identity to `S:U`; (2) a garbage
> *modified* metric left the env score `None` → now falls back to base; (3)
> `prioritize` used `env or base` truthiness, mis-treating a legitimate `0.0`
> env score as missing → explicit `None` checks. Full suite **373 passed, ruff
> clean**. Still deferred (#8): semantic/LLM dedup, multi-backend
> `--verify`/`--chain` routing, per-asset CMDB environmental inputs.

> **Update 2026-07-02 (later⁷) — build-next #8 (part 2): semantic/LLM dedup.**
> Opt-in `stages.semantic_dedup_findings` (`redteam triage --semantic-dedup`,
> gated on `model_stage_ready`) runs a model pass over the deterministic
> survivors to merge same-root-cause findings the `(file, vuln_class)` dedup
> misses (reworded / reclassified / just outside the line tolerance). The design
> is dominated by one risk — a **false negative**, where wrongly merging two
> distinct findings makes a real vuln vanish — so it is conservative by
> construction: a duplicate must **share the canonical's file**, indices are
> validated in-range + **disjoint**, every merge is **recorded** in
> `report.dropped` (auditable/recoverable, never silently deleted), and a
> bad/unparseable/errored reply **degrades** (keeps everything). Built TDD; a
> two-agent adversarial pass verified all four safeguards hold by tracing + a
> live battery, and caught **one confirmed high-severity totality bug**: `_as_index`
> ran `int()` on a quoted index with no digit cap, so a model reply with a
> >4300-digit string index crashed `run_triage` (Py3.14's int-from-str limit) —
> the exact trap `models.py` already guards with `\d{1,9}`. Fixed by capping the
> quoted-index length + a defensive parse wrapper; also accepted a bare
> single-group object for parity with the chain stage. Full suite **386 passed,
> ruff clean**; the default (no-flag) path is byte-for-byte unchanged. Remaining
> #8: multi-backend model routing, per-asset CMDB environmental inputs.

> **Update 2026-07-02 (later⁸) — build-next #8 (part 3): multi-backend model
> routing.** The last self-contained #8 item. `llm.resolve_model(models, stage,
> default)` + a `models` param on `run_triage` let each model stage route to its
> own model id — `redteam triage --verify-model … --chain-model … --dedup-model
> …`, falling back to `--model`. (The Agent SDK's one-shot `query()` reads the
> backend from the process env, not per-call, so this routes the model *id* per
> stage; per-stage *provider* switching is beyond the seam — documented as
> such.) Built TDD (a system-prompt spy asserts each stage gets its routed
> model); a focused review confirmed the new module-top `from .llm import
> resolve_model` does **not** leak the SDK into the deterministic path
> (live-checked `sys.modules`), each stage routes the correct key, and the
> no-override path is byte-for-byte unchanged. Full suite **391 passed, ruff
> clean**. The only remaining roadmap item is CMDB-sourced per-asset
> environmental inputs (needs a real CMDB; out of scope).

## How this review was produced

Two multi-agent review workflows were run over the repo: a first pass of 9
subsystem reviewers with adversarial verification, then an exhaustive pass of
14 dimensions (adding concurrency/async, packaging, subagent prompts,
observability, and a holistic threat-model lens) plus completeness-critic and
gap-review rounds. That produced ~250 raw findings and 203 adversarial
verdicts (155 confirmed / 19 partial / 16 refuted / 13 intended-stub). The raw
output was **merged with a full, independent file-by-file read of the entire
repo**; severities were adjudicated by hand, duplicates collapsed, and several
agent claims tempered or refuted (see *Refuted / tempered* below). Two findings
were confirmed by actually running the CLI.

A note on process: the exhaustive workflow was interrupted mid-run (in-flight
subagents are torn down when new input arrives), so its final synthesis was
written here from the recovered structured outputs plus the independent read,
rather than from the workflow's own synthesis agent. Nothing was lost — 233 of
241 agents had already completed and their structured findings were harvested
from disk.

---

## Executive summary

This is a genuinely well-architected **seed/blueprint**, and the parts the
project says are load-bearing (the engagement schema, the hash-chained ledger,
the policy-spine structure, the real-vs-stub discipline) are mostly sound. The
hash chain in particular is correctly built and tamper-evident.

But the review found **real defects concentrated in exactly the components
CLAUDE.md lists as "real and tested,"** plus several security issues that are
not documented anywhere as known gaps. The headline items: the documented
quickstart command (`redteam run … --dry-run`) **crashes in two independent
ways**; the SDK integration seam is **wrong-shaped**, so the policy gate that is
the whole safety story may never engage; and there is a **live SSRF→AWS-metadata
credential-theft path** (the egress template allow-lists the instance-metadata
IP and the web tool follows redirects with only the first URL scope-checked).
The scope guard has a URL-canonicalization deny bypass and an empty-allowlist
egress bypass; `whitebox__repo_grep` can read host files via a symlink planted
in an operator-cloned repo; the engagement time-window is dead code; and the
audit-volume ownership prevents the container from writing the ledger at all.

None of these would have been caught by the current test suite, which passes
27/27 but does not exercise the security-critical behaviours.

**Grade:** Strong design, B/B+ as a blueprint. The architecture will absorb
every fix below without restructuring — but several of these must be fixed
before the harness can be trusted to contain an agent, and a few before it runs
at all.

### Severity counts (distinct, deduplicated)

| Severity | Count | IDs |
|---|---|---|
| Critical | 3 | RT-01, RT-04, RT-08 |
| High | 11 | RT-02, RT-03, RT-05, RT-06, RT-07, RT-09, RT-10, RT-12, RT-13, RT-14, RT-15 |
| Medium | 13 | RT-11, RT-16, RT-17, RT-18, RT-20, RT-21, RT-22, RT-23, RT-24, RT-25, RT-26, RT-28, RT-29 |
| Low | 3 | RT-19, RT-27, RT-30 |
| Nit | 1 | RT-31 |

---

## Cross-cutting themes

1. **The safety story rests on an SDK seam that doesn't exist yet.** The whole
   design is "the hook is the gate, the tool is the lock." But the hook/option
   shapes passed to the SDK are wrong (RT-04), the tool names won't match what
   the SDK emits (RT-05), and none of it is exercised because the SDK isn't
   installed and no test covers the seam. Until the gate is proven to engage,
   every other policy guarantee is unverified. **This belongs at the top of the
   work order, above the currently-listed "wire auth" task.**

2. **"Real and tested" overstates the test coverage.** The components on that
   list (engagement, scope_guard, chain, assets, orchestrator) do have tests,
   but they pin happy paths and a couple of deny cases. The dead time-window
   (RT-12), the URL deny bypass (RT-06), the empty-egress bypass (RT-07), the
   broken dry-run (RT-02), and the unreachable cloud pack (RT-11) all coexist
   with a green suite.

3. **Scope containment is defeatable at several layers.** URL non-
   canonicalization (RT-06), empty-egress (RT-07), redirect-following SSRF
   (RT-01/RT-10), symlink escape from the assets mount (RT-09), and method
   safety being prompt-only (RT-10) each let an agent reach somewhere it
   shouldn't. Defence-in-depth is the stated model; right now the layers have
   correlated holes.

4. **Documented stubs are fine; the bugs hiding *inside* the stubs are not.**
   The team marks stubs honestly. But some stubs ship a latent defect that will
   bite when wired: the egress template allow-lists IMDS (RT-01), `verify`
   returns success without a key (RT-13), and the auth design has a chicken-and-
   egg signing problem (RT-08). These need fixing *before* the corresponding
   "build-next" task, not during it.

5. **Concurrency is unguarded but currently masked.** The ledger and budget have
   no locks and rely on hooks never running concurrently (RT-17). That holds
   only as long as the SDK serializes hook execution; it's a latent corruption
   waiting on a change in execution model.

---

## Findings

Severity, status, and `file:line` are listed for each. "Intended-stub" means a
documented v1 cut; everything else is a real defect.

### Critical

#### RT-01 — SSRF to AWS instance-metadata enables role-credential theft · security · *confirmed*
`redteam/runtime/netpolicy.json:4-7`, `redteam/tools/web.py:51-67`

`netpolicy.json` `always_allow` lists `169.254.169.254` (the EC2 instance-
metadata endpoint). `web__http_request` uses `urllib.request.urlopen`, which
**follows 3xx redirects**, and only the *first* URL is scope-checked
(`ctx.assert_in_scope` at `web.py:42`). An in-scope target that returns
`302 Location: http://169.254.169.254/latest/meta-data/iam/security-credentials/...`
lets a confused or compromised agent read the harness's own AWS workload-role
credentials — the same role used for KMS sealing.
**Fix:** disable auto-redirect in the web pack (custom opener that re-runs the
scope check on every hop); require IMDSv2 (hop limit 1 + session token); remove
`169.254.169.254` from `always_allow` and provide boto3 credentials by a path
the agent's HTTP tool cannot reach (separate netns / proxy).

#### RT-04 — SDK hook/agent/option seam is wrong-shaped; the policy gate may not engage · design-inconsistency · *confirmed*
`redteam/cli.py:77`, `redteam/orchestrator.py:88-138`, `redteam/orchestrator.py:208-215`

`cli` splats `build_options()` into `ClaudeAgentOptions(**options)` with no
adapter, despite the docstring claiming conversion. Against the real Python
Agent SDK: `permission_mode="dontAsk"` is not a valid mode; `PreToolUse` must be
a `HookMatcher` list whose callbacks take `(input, tool_use_id, context)` and
return output under `hookSpecificOutput`, **not** a single payload dict
returning a top-level `permissionDecision`; `SessionStart`/`SessionEnd` are not
tool-gating hooks in that shape; and `agents` must be `AgentDefinition` objects,
here passed as raw markdown strings. The net effect is either a `TypeError` at
construction or a **deny the SDK silently ignores (fail-open)** — the worst
outcome for a harness whose entire safety story is "the hook is the gate."
**Fix:** write the real adapter at the `_build_hooks` seam (CLAUDE.md calls this
*the* SDK seam): wrap hooks in `HookMatcher`, map returns to
`hookSpecificOutput`, fix `permission_mode`, build `AgentDefinition` objects
with per-subagent tool subsets. Add a contract test that builds a real
`ClaudeAgentOptions` from `build_options()`.

#### RT-08 — Operator signature is never verified; field optional; chicken-and-egg; principal unbound · security · *confirmed (wiring = intended-stub; design flaws real)*
`redteam/engagement.py:193,227-232`, `redteam/cli.py:48`, `redteam/auth.py`, `engagements/example.yaml:12-15`

`from_yaml` never calls `SignatureVerifier` (documented stub, CLAUDE.md build-
next #1), so any unsigned YAML runs. Beyond the wiring — which is the documented
part — there are three design flaws that are **not** documented and must be
resolved before wiring: `operator_signature` is `Optional[str] = None` with no
required check; the signature is embedded in the very YAML it signs (signing
changes the bytes, so verification can never pass), while `example.yaml`'s own
header signs to a **detached** `.sig`, contradicting the schema; and nothing
binds the ssh `-I` principal to the `operator` email, so an operator could
present any authorized principal's signature.
**Fix:** decide detached-sidecar vs canonical-YAML-minus-signature *before*
wiring; make the signature required (non-dry-run); bind `principal == operator`;
wire verify into `from_yaml` and record the result as ledger entry 0.

### High

#### RT-02 — `redteam run --dry-run` is not dry and crashes before the flag is checked · bug · *confirmed by execution*
`redteam/cli.py:46-61`, `redteam/orchestrator.py:52`
`cli.run` constructs `Orchestrator` before checking `dry_run`; `__init__`
unconditionally `mkdir`s `audit_dir` (default `/audit`, read-only on a host) and
opens the ledger. The documented smoke test crashes with
`OSError: Read-only file system: '/audit'`.
**Fix:** make `--dry-run` construct nothing on disk; gate all filesystem side
effects behind `if not dry_run`. Add a CLI smoke test.

#### RT-03 — Asset paths resolve against the engagement-file parent, not the repo/clone root · bug · *confirmed by execution*
`redteam/orchestrator.py:61`, `redteam/assets.py:115-120`, `redteam/runtime/docker-compose.yml:31`, `engagements/example.yaml:38-48`
`build_index(host_root=engagement_path.parent)` resolves `example.yaml`'s
`./targets/example-api` to `engagements/targets/example-api` (doesn't exist) →
`FileNotFoundError`. In-container the mismatch compounds: compose bind-mounts
`./targets` at `/assets:ro`, but the index computes `host_path` under
`/engagements` and whitebox reads `host_path` (not `container_path`), so whitebox
can never read the assets even after the path bug is fixed.
**Fix:** resolve asset paths against a fixed documented root (repo root / CWD)
consistent with where operators clone (`./targets`) and where compose mounts
(`/assets`); read via `container_path` in-container; add a test using
`example.yaml`'s layout.

#### RT-05 — In-process MCP tool names get an `mcp__` prefix that breaks targetless-allow and the allowlist · bug · *confirmed*
`redteam/orchestrator.py:102-116`, `redteam/hooks/scope_guard.py:101-113`, `redteam/mcp_external.py:66-72`
The SDK exposes in-process MCP tools as `mcp__<server>__<tool>`, and `@tool`
names already embed the pack prefix (e.g. `whitebox__repo_read`), so the real
name is `mcp__whitebox__whitebox__repo_read`. `_TARGETLESS_TOOLS` entries and
`allowed_tools` wildcards (`whitebox__*`) won't match; external `jira__search`
already contains `__` so `prefixed_tool_names` never adds the `atlassian`
prefix. Fails closed (everything denied) — dead-on-arrival rather than unsafe,
but the whole tool surface is unreachable.
**Fix:** centralize tool-name derivation; compute the names the SDK actually
emits in `scope_guard` and `allowed_tools`; add a test pinning the format.

#### RT-06 — Scope-guard URL path-prefix match is not canonicalized (out_of_scope deny bypass) · security · *confirmed*
`redteam/hooks/scope_guard.py:134-142`
`_UrlPrefixMatcher.matches` does raw `parsed.path.startswith(path_prefix)`. With
`out_of_scope: https://staging.example.com/admin`, all of `/%61dmin` (percent-
encoded), `//admin` (double slash), and `/Admin` (case) evade the deny and then
match the in-scope target. Deny-wins ordering is correct but defeatable by
anyone who encodes a URL — including the agent under test.
**Fix:** canonicalize before matching (lowercase host, percent-decode path,
collapse slashes, resolve dot-segments); add adversarial tests.

#### RT-07 — Empty `egress_allowlist` silently disables egress checking · security · *confirmed*
`redteam/hooks/scope_guard.py:66-75`, `redteam/engagement.py:52`
`if host and self._egress_hosts and host not in egress` short-circuits when
`_egress_hosts` is empty, so an omitted/empty allowlist permits any host that
matches a target rule — the opposite of PLAN's default-deny. Egress is also only
checked for URL candidates; bare-host/CIDR targets skip it.
**Fix:** treat empty egress as deny-all (with `api.anthropic.com` implicit), or
reject empty at parse time; apply the egress check to host/CIDR candidates too.

#### RT-09 — `whitebox__repo_grep` (and asset file-count) follow symlinks out of the read-only mount · security · *confirmed*
`redteam/tools/whitebox.py:63-96`, `redteam/assets.py:123-127`
`repo_read` is safe — `_resolve_under_assets` resolves symlinks **then** checks
containment. `repo_grep` is not: it `rglob`s the repo and `read_text`s every
file with no symlink/containment check, so a symlink inside an operator-cloned
target repo (attacker-influenceable content) pointing at `/etc/passwd` or
`/run/secrets/gh_token` is read and returned to the agent. `assets._count_files`
likewise follows symlinks. Both whitebox tools are in `_TARGETLESS_TOOLS`, so the
scope-guard gate never inspects them — the tool "lock" is the only defence, and
it's missing here.
**Fix:** resolve+contain every path `repo_grep` visits (reuse
`_resolve_under_assets`); skip symlinks pointing outside the roots; add a
symlink-escape test.

#### RT-10 — `web__http_request` allows write verbs and follows redirects with no enforcement · security · *confirmed*
`redteam/tools/web.py:16,42-78`
`_ALLOWED_METHODS` includes `POST/PUT/PATCH/DELETE`; the "no write/delete" rule
lives only in prompts, enforced nowhere. `urllib` follows redirects (see RT-01).
A confused/compromised agent can issue destructive HTTP against an in-scope
target and be redirected off-scope.
**Fix:** gate write methods behind an explicit engagement flag (default read-
only GET/HEAD/OPTIONS); disable auto-redirect or re-scope each hop.

#### RT-12 — Engagement time-window is parsed but never enforced · missing-validation · *confirmed*
`redteam/engagement.py:33-46`
`Window.covers()` is dead code (no caller anywhere). PLAN calls the window a
"hard time bound," but an engagement YAML authorizes a run at any time, forever.
This is **not** flagged as a stub — `engagement.py` is on the "real and tested"
list.
**Fix:** check the window at session start and in `_pre_tool_use` (deny + ledger
entry when outside); decide the naive-timestamp policy explicitly.

#### RT-13 — `redteam-verify` exits 0 with only a WARN when no HMAC key is supplied · security · *confirmed*
`redteam/ledger/verify.py:53-62`
PLAN's documented auditor flow is `redteam-verify <ledger> <seal>` (no key).
Without `--hmac-key-file`, verify prints `WARN` and returns 0, though it only
checked that the seal's `head_hash`/`entry_count` match the attacker-
recomputable chain. An attacker who truncates the ledger, recomputes the head,
and rewrites the seal JSON passes with exit 0. The HMAC is the only trust anchor
and it's skipped.
**Fix:** exit non-zero when a seal is present but unverifiable; for KMS seals,
require `kms:VerifyMac` and dispatch on `seal["method"]`.

#### RT-14 — Audit named volume is root-owned and shadows the Dockerfile chown; non-root uid cannot write the ledger · bug · *confirmed*
`redteam/runtime/docker-compose.yml:22,33,67`, `redteam/runtime/Dockerfile:49-51`
`Dockerfile` chowns `/audit` to uid 10001, but the named volume `audit:` mounts
over `/audit` at runtime created `root:root`, so uid 10001 cannot write — the
first ledger append fails. Classic Docker volume-ownership gotcha.
**Fix:** pre-create/chown the volume dir via an init step, set the volume uid, or
chown in entrypoint with the needed privilege; add a container smoke test that
writes one ledger entry.

#### RT-15 — Subagent tool-scoping is not enforced; frontmatter is loaded as a raw prompt string · security · *confirmed*
`redteam/orchestrator.py:208-215`, `redteam/subagents/exploiter.md`
`_build_subagents` reads each `.md` as a string and passes it as the agent
value. The YAML frontmatter `tools:` (the deliberately narrow set for the
dangerous `exploiter`) is never parsed into an `AgentDefinition` tool subset, so
per-subagent tool restriction is cosmetic and the frontmatter leaks into the
prompt as literal text. The frontmatter tool names also wouldn't match SDK names
(see RT-05).
**Fix:** parse frontmatter; build `AgentDefinition(description, prompt, tools=…)`
with the mapped subset; restrict each subagent to its tools.

### Medium

- **RT-11 — cloud pack is unreachable under the scope guard and advertises GCP/Azure** · design-inconsistency · `redteam/tools/cloud.py:17-50`, `redteam/hooks/scope_guard.py:28,101-113`. The `provider` key isn't in `_TARGET_KEYS` and the tools aren't targetless, so the guard denies them; the pack can never run. The enum also advertises `gcp`/`azure`, violating the AWS-only constraint. *Fix:* make cloud tools targetless (scope-check ARNs inside) or give them a target key; restrict the enum to `aws`.
- **RT-16 — Dockerfile drops scanner version pins via unquoted shell redirection; unpinned 'latest' binaries; no checksums** · supply-chain · `redteam/runtime/Dockerfile:1,26-41`. `pip install … semgrep>=1.70 checkov>=3.2` is unquoted, so `>=…` is parsed as a shell redirect — the floors are dropped and junk files are written; tfsec/kube-linter use `releases/latest` with no checksum; awscli has no GPG verification; base image not digest-pinned. *Fix:* quote specs, pin + verify, digest-pin the base.
- **RT-17 — No locking on ledger/budget; blocking I/O inside async hooks** · concurrency (latent) · `redteam/ledger/chain.py:93-108`, `redteam/budget.py`, `redteam/tools/web.py:56`. Safe only while hooks never run concurrently (`append()` has no internal await); the read-modify-write of `_seq`/`_head_hash` and budget counters race the moment the SDK uses threads or adds an await. Sync I/O (`fsync`, `urlopen`, `subprocess.run`) in async paths stalls the loop. *Fix:* `asyncio.Lock` around append/budget; offload blocking I/O to threads.
- **RT-18 — Redactor misses standard secrets and over-redacts the audit trail** · security · `redteam/hooks/redactor.py:14-23`. `Authorization: Bearer …` is not matched (pattern needs `:`/`=` immediately after the keyword); the AWS-secret regex `[A-Za-z0-9/+=]{40}` matches any 40-char hash (mass over-redaction — the failure the file's own comment forbids); no PII handling despite PLAN. *Fix:* fix the auth pattern, constrain the AWS pattern, add PII detectors for the telemetry path.
- **RT-20 — Budget semantics: turns count tool calls, `>=` boundary, cost may never capture model tokens** · bug · `redteam/budget.py:20,31-43`, `redteam/orchestrator.py:178-191`. `record_turn` fires per PostToolUse (caps tool calls, while `max_turns` is *also* the SDK turn cap); PostToolUse may fire on denied calls; `cost_usd` from tool events may never include model-token cost, so `max_usd` may never trip. *Fix:* separate turns from tool calls; confirm/wire the SDK cost signal; count only successful allowed calls.
- **RT-21 — SARIF writer is a non-atomic read-modify-write (race + corruption + unbounded growth)** · bug · `redteam/tools/report.py:94-115`. Re-reads/rewrites the whole doc per finding; concurrent findings clobber; a crash mid-write corrupts it. *Fix:* append-only results journal merged at end, or temp-file + atomic rename under a lock.
- **RT-22 — Observability is largely unwired vs the PLAN's claims** · plan-drift · `redteam/hooks/telemetry.py`, `redteam/runtime/otel/collector.yaml:22-23`, `docker-compose.yml:62-64`. Only `tool.denied` is emitted (no `tool.invoked`/`finding.recorded`, `tool_span` unused, no metrics); no OTel SDK init in code; `tls insecure:true` is unconditional (applies to the prod endpoint); dev Grafana enables anonymous Admin. *Fix:* emit the missing events, gate `insecure` to dev, align the dashboard.
- **RT-23 — Container hardening gaps** · design-inconsistency · `docker-compose.yml:17-37`, `entrypoint.sh:14-25`, `netpolicy.json`. `read_only:true` likely breaks the SDK's `~/.claude` session writes (PLAN says those are mirrored to the ledger); the entrypoint only logs (renders no iptables) and `netpolicy.json` is consumed by no code; `atlassian_token` is always required. *Fix:* writable HOME (tmpfs) or relocate SDK state; render nft rules; consume or delete `netpolicy.json`; conditional secret.
- **RT-24 — Schema validation gaps** · missing-validation · `redteam/engagement.py:49-95,185-232`. No list-length caps (DoS); userinfo URLs (`https://host@evil.com` → `urlparse` hostname is `evil.com`); weak hostname regex (wildcards, `a..b`, trailing dots); unchecked `Reporting.destination` path; no YAML size cap. *Fix:* reject userinfo/unintended ports, tighten the regex, cap lengths/size, constrain destination to the audit dir.
- **RT-25 — Asset containment not enforced (absolute/`..` escape host_root)** · security · `redteam/assets.py:115-120`. `_resolve_required` doesn't assert containment under `host_root`. Operator-controlled, but pairs badly with RT-09. *Fix:* assert `relative_to(allowed_root)` after `resolve()`.
- **RT-26 — Thin error handling around setup, hooks, and seal** · bug · `redteam/orchestrator.py:52,217-235`, `cli.py:46-62`. No try/except around setup; hooks may raise instead of returning a deny (fail-open if the SDK ignores raises); `seal()` silently swallows the no-key `RuntimeError`. *Fix:* hooks always return a safe decision (default deny on internal error); clean setup errors; log skipped seals.
- **RT-28 — Test suite is shallow relative to the "real and tested" claim** · test-gap · `tests/`. Zero tests for hooks, CLI, budget, redactor, verify, CIDR, multi-deny, egress-deny, window, symlink escape, relative-asset resolution; `test_kms_seal` mocks boto3. The suite is green while the bugs above are live. *Fix:* add the targeted tests listed in the JSON entry.
- **RT-29 — Documentation drift would mislead a future session** · doc-issue · `README.md:23,74`, `docs/PLAN.md`, `CLAUDE.md:110-128`. README claims a KMS-sealed ledger (file HMAC is the only wired path); PLAN claims session-JSONL mirroring (no code), Jira upsert (not implemented), and an 11-scenario verification plan that's mostly aspirational. *Fix:* mark not-yet-wired features; revise the build-next order.

### Low / Nit

- **RT-19 — `RunResult.entry_count` reports `budget.turns`, not the ledger sequence** · bug (tempered) · `redteam/orchestrator.py:226`. Cosmetic mislabel only — the *seal* uses `ledger._seq` correctly, so this does **not** cause seal-verification failure (an over-statement several agents made). *Fix:* read `entry_count` from the ledger.
- **RT-27 — External MCP preflight reachability is promised but absent** · plan-drift · `redteam/mcp_external.py:1-49`. Docstring/PLAN promise an `mcp.external.unreachable` record; only `registered` is written. `prefixed_tool_names` is dead. *Fix:* add the preflight or trim the claim.
- **RT-30 — Unused dependencies and missing metadata** · dependency · `pyproject.toml`. `cryptography` and `anyio` are declared but unused; no license/author; `ruff` unconfigured; SDK floor unbounded. *Fix:* drop/curate deps, add metadata, pin a tested SDK range.
- **RT-31 — Minor code-smells and dead code** · nit · `orchestrator.py:98,238-243`, `mcp_external.py:66-72`, `whitebox.py:47-48`. Throwaway set vs `PACKS`; duplicated `_extract_target`; dead `prefixed_tool_names`; `list_assets` returns host paths. *Fix:* reuse `PACKS`, share one extractor, drop dead code, return container paths.

---

## Refuted / tempered (things *not* to worry about)

These were raised by reviewers but do not hold up, or were overstated:

- **`web__inspect_headers` skips its scope check** — refuted. It calls
  `ctx.assert_in_scope` at `web.py:90`; `recon`/`web`/`network` all run their own
  "lock" check.
- **`RunResult.entry_count` mislabel causes seal-verification failure** —
  refuted/overstated. The seal uses `ledger._seq`; only the CLI summary number is
  wrong (RT-19).
- **`auth` `NamedTemporaryFile` world-readable race / not flushed** — refuted.
  Created mode 0600; the signed body goes via stdin (no temp file); the file is
  closed before `ssh-keygen` reads it and unlinked in `finally`.
- **`file://`/`gopher://` SSRF via the web tool** — refuted. Non-matching
  scheme/host fail the scope matchers; `file://` is denied. The real SSRF vector
  is redirects from an in-scope https target (RT-01/RT-10).
- **The ledger hash chain is forgeable / reorderable** — refuted. The chain
  binds `prev_hash + seq + canonical(payload)`; reorder/insert/delete/mutate are
  all detected on replay. Chain construction is sound.

## Intended v1 stubs (documented — not defects)

- `auth.SignatureVerifier` not wired into `from_yaml` (CLAUDE.md #1). *The
  absence of wiring is documented; the design flaws around it (RT-08) are not.*
- KMS sealer not wired; orchestrator uses file HMAC; `verify.py` has no KMS
  dispatch (CLAUDE.md #2). *But the `verify` exit-0-on-no-key trap (RT-13) is a
  real defect.*
- `entrypoint.sh` renders no iptables (CLAUDE.md #3). *But the `netpolicy.json`
  IMDS allow-list (RT-01) is a real defect in the template it will render.*
- `recon gh_*`, `whitebox semgrep|tfsec|checkov`, `report` Jira upsert, and
  `cloud` bodies return `not_implemented` (CLAUDE.md #4–6). Expected.
- `docker-compose` references `.secrets/*` that don't exist yet (README tells the
  operator to create them).

---

## What's genuinely good

- **Hash-chained ledger (`ledger/chain.py`)** is the strongest file: payload hash
  binds `prev_hash + seq + canonical JSON`, `fsync` per append, resume replays
  and re-verifies — reorder/insert/delete/mutate all caught.
- **External-MCP allowlist** is enforced twice (parse-time validator + runtime
  re-assert that raises `PermissionError`) — exactly the deliberate-code-change
  posture CLAUDE.md mandates.
- **Clean module seams:** `_sdk_shim` keeps the package importable without the
  SDK; `ToolContext` gives packs a uniform context; policy is centralized in
  hooks.
- **`recon`/`web`/`network` tools run their own defence-in-depth scope check**
  (`assert_in_scope`), matching the gate+lock model.
- **Subagent prompts are well-written on content** (scope discipline, read-only
  rules, confirm-twice, clean hand-off formats); the gap is structural
  enforcement (RT-15).
- **Honest documentation discipline** (real-vs-stub marking, "What NOT to do,"
  explicit constraints) is better than most production repos.

---

## Recommended build order (revising CLAUDE.md's "what to build next")

The current list opens with "wire auth." Two things belong in front of it, and
one decision belongs inside it:

0. **Fix the smoke path** so the repo runs end-to-end as documented: `--dry-run`
   constructs nothing (RT-02); resolve asset paths against a fixed root and
   reconcile compose mounts (RT-03); add a CLI smoke test.
1. **Prove the SDK seam** before anything depends on it: install the SDK in dev
   extras; add a contract test building real `ClaudeAgentOptions` from
   `build_options()`; write the hook adapter and fix `permission_mode`,
   `AgentDefinition` agents, and tool-name prefixes (RT-04/RT-05). Everything
   else assumes the gate works.
2. **Close the live security gaps:** remove IMDS from the egress template +
   disable/re-scope web redirects + require IMDSv2 (RT-01/RT-10); canonicalize
   scope-guard URLs (RT-06); make empty egress deny-all (RT-07); contain
   `repo_grep` symlinks (RT-09); enforce the time window (RT-12).
3. **Wire auth** — after deciding detached-vs-embedded signing and binding
   `principal == operator`; make the signature required (RT-08).
4. **Make the audit trail trustworthy:** `redteam-verify` fails closed without a
   key + dispatches on seal method (RT-13); add the `Sealer` protocol and default
   to KMS in-container (CLAUDE.md #2); lock the ledger/budget (RT-17).
5. **Container correctness:** fix the audit-volume ownership (RT-14); writable
   HOME for SDK state + render egress nft rules (RT-23); pin+verify Dockerfile
   artifacts (RT-16).
6. **Then the existing CLAUDE.md items 4–7** (`gh_*` tools, Atlassian/Jira
   upsert, real scanners, OTel dashboard), folding in RT-11 (cloud
   reachability), RT-18 (redactor + PII), RT-21 (SARIF atomicity), RT-22
   (telemetry events).
7. **Backfill the test suite (RT-28)** alongside each fix so the security-
   critical behaviours are pinned.

---

## Appendix — reproduction commands

```bash
pip install -e ".[dev]"
pytest -q                                                  # 27 pass (shallow; see RT-28)
redteam validate engagements/example.yaml                  # OK
redteam run engagements/example.yaml --dry-run             # RT-02: OSError /audit
redteam run engagements/example.yaml --dry-run --audit-dir /tmp/x   # RT-03: FileNotFoundError targets/example-api
grep -rn 'covers(' redteam/                                # RT-12: definition only, no caller
```
