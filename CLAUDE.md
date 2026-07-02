# CLAUDE.md

Orientation for any Claude session continuing this project.

## What this repo is

A **seed / blueprint** for a modular security testing harness built on
the Claude Agent SDK. It is intentionally not yet functional end-to-end:
the schemas, contracts, file layout, and policy spine are real; many
tool-pack bodies and the runtime wiring are stubs marked clearly.

The full design lives in `docs/PLAN.md`. **Read it before making
non-trivial changes** — most apparent omissions are deliberate v1 scope
cuts, not gaps.

## Hard constraints (do not relax without an explicit user request)

1. **Package name is `redteam`.** Not `harness`, not anything else. The
   filename `docs/PLAN.md` was once `i-want-to-design-modular-squid.md`
   in the planning system; that was a slug artefact, no Squid the proxy
   involvement.
2. **Third-party MCP allowlist is `{atlassian}` only.** Enforced at
   parse time in `redteam/engagement.py::ALLOWED_EXTERNAL_MCPS`. GitHub
   is reached via the `gh` CLI baked into the runtime image — *not* via
   any GitHub MCP. Adding a second provider must be a deliberate code
   change, not a YAML flag flip.
3. **Engagements are signed by SSH keys** (`ssh-keygen -Y sign`)
   verified against `engagements/authorized_signers`. See
   `redteam/auth.py`. No GPG, no sigstore in v1.
4. **Audit-ledger seal is AWS KMS HMAC** (`kms:GenerateMac` /
   `kms:VerifyMac`). See `redteam/ledger/kms_seal.py`. The legacy
   file-key path in `redteam/ledger/chain.py` exists only for local
   pytest; the orchestrator should default to KMS in-container.
5. **Cloud pack is AWS-only.** GCP / Azure are out of scope for v1.
6. **No pause/resume of long engagements** in v1.

## Repo layout (high level)

```
redteam/                package
├── cli.py              click entry point: `redteam run` / `triage` / `validate` / `doctor`
├── orchestrator.py     ClaudeSDKClient wiring; thin
├── engagement.py       pydantic schema (single source of truth)
├── preflight.py        readiness checks (CLI/backend/dirs) + model-stage gate
├── auth.py             SSH-signature verification (stub)
├── assets.py           read-only mount of pre-cloned repos / IaC / specs
├── budget.py           turn / cost / per-target call accounting
├── mcp_external.py     adapter for the atlassian entry only
├── hooks/              policy spine (scope_guard, audit_writer, redactor, telemetry)
├── ledger/             append-only hash-chained JSONL + KMS seal + verifier
├── tools/              first-party in-process MCP servers (stubbed bodies)
├── pipeline/           M3 `redteam triage`: prefilter/dedup/enrich + opt-in verify/chain
├── subagents/          markdown system prompts for recon / analyst / whitebox / exploiter
└── runtime/            Dockerfile, docker-compose.yml, entrypoint, netpolicy, otel/

engagements/            example.yaml + authorized_signers (SSH allowed-signers)
targets/                operator clones target repos here via `gh repo clone`
tests/                  pytest contracts that pin behaviour; some skip when tools missing
docs/PLAN.md            full design doc
```

## Status: what's real vs. stubbed

**Real and tested:**
- `redteam/engagement.py` — full pydantic schema, allowlist, validators
- `redteam/hooks/scope_guard.py` — URL / CIDR / hostname matchers, deny-wins
- `redteam/ledger/chain.py` — hash-chained append, replay, tamper detection
- `redteam/assets.py` — read-only mount index with metadata
- `redteam/orchestrator.py` — hook dispatch, budget gate, subagent loading
- `redteam/auth.py` — SSH detached-signature verification (`ssh-keygen -Y`);
  `redteam run` gates a real run on it before the orchestrator is built
  (tested in `tests/test_signature_verify.py`)
- `redteam/runtime/render_netpolicy.py` + `entrypoint.sh` — render
  `scope.egress_allowlist` into an nft default-deny ruleset (IMDS denied
  first; overlapping entries collapsed) and load it before privilege drop;
  unit-tested in `tests/test_fixes_rt23.py` and smoke-checked end-to-end via
  `tests/container/smoke_rt23.sh` (RT-23)
- `redteam/tools/report.py` — atomic SARIF writer (temp + `os.replace`,
  serialize-first) under an asyncio.Lock; corrupt base quarantined (RT-21)
- `redteam/jira.py` — deterministic Atlassian/Jira idempotency logic
  (build-next #5): stable `external_key` (sanitised id → safe label + escaped
  JQL), `jql_for_key`, `build_issue_fields`, `plan_upsert`. Consumed by the
  gated `report__jira_upsert` tool and the M3 `<stem>.jira.json` bundle. Pure,
  no network. Tested in `tests/test_jira.py`
- `redteam/ledger/kms_seal.py` — KMS HMAC seal is **wired** (build-next #2):
  `build_sealer(env)` returns a `KmsHmacSealer` when `REDTEAM_KMS_KEY_ID` is
  set (else `None`); `LedgerWriter` takes an injected `sealer` that is
  authoritative over the file HMAC key; the CLI `run` path injects
  `build_sealer(os.environ)`. The file-key path in `chain.py` stays as the
  local-pytest fallback and now records `method: "file"`. `verify.py`
  dispatches on `seal["method"]`. boto3 stays lazy (import-safe, no live AWS
  call in any mocked test). Tested in `tests/test_kms_sealer_switch.py`
- `redteam/preflight.py` + `redteam doctor [--probe]` — readiness checks
  (claude CLI present/recent, model backend incl. Bedrock/Vertex, writable
  dirs); `--probe` spawns the SDK transport to prove the agent loop launches
- The runtime image ships **Node + a pinned `@anthropic-ai/claude-code`** —
  the Agent SDK spawns the `claude` CLI as its transport, so the container
  runs a *contained* engagement end-to-end (`engagements/whitebox-first.example.yaml`).
  A true autonomous run still needs a model backend (key, or
  `CLAUDE_CODE_USE_BEDROCK`/`_VERTEX` + creds, with the backend host added to
  `egress_allowlist`).
- **M3 — `redteam/pipeline/` + `redteam triage <ledger>` (DONE, live-verified).**
  A separate, re-runnable command that reads a sealed engagement ledger
  **read-only** and emits a refined report: prefilter → dedup → CWE/CVSS-enrich
  → emit (SARIF 2.1.0 + markdown + `triage.json`). Deterministic stages need no
  model/creds and are *total* (a bad finding is dropped-and-recorded, never
  raised). Opt-in `--verify` (adversarial, confidence-gated; unparseable /
  conflicting verdicts → UNVERIFIED and **kept**, never laundered to FP) and
  `--chain` (validated ≥2-step exploit chains) reuse the engagement backend via
  the SDK one-shot `query()`, gated on `preflight.model_stage_ready`. Built TDD;
  a five-reviewer adversarial pass + a live run (precision 1.0, 3 chains)
  hardened it. See `docs/superpowers/specs/2026-07-02-m3-findings-pipeline-design.md`
  and the M3 batch in `docs/review-findings.json`.

**Stubbed / blueprint-only (clearly marked):**
- `redteam/tools/{web,cloud,network,report}.py` — MCP-shaped but most tool
  bodies return `not_implemented` (report is real). In `whitebox.py`,
  `repo_read` / `repo_grep` / `list_assets` and now `semgrep_scan` / `iac_scan`
  are **real** (build-next #6 — see `redteam/tools/_scanners.py`); `sbom_query`
  / `openapi_diff` / `dependency_audit` remain stubs. In `recon.py`, the `gh_*`
  tools are **real** (build-next #4): read-only, org-scoped `gh` CLI wrappers
  (`gh_search_code` / `gh_search_repos` / `gh_repo_view`), argv-not-shell,
  input-validated, total; `whois` / `cert_transparency` remain stubs.
  Tested in `tests/test_recon_gh.py` + `tests/test_whitebox_scanners.py`
- `redteam/runtime/docker-compose.yml` — references `.secrets/` files
  (`anthropic_api_key`, `gh_token`) that do not exist; create them before
  bringing the stack up. `atlassian_token` is opt-in via the
  `docker-compose.atlassian.yml` overlay (only when an engagement enables
  the atlassian MCP).

## Conventions

- Tool functions take a target via `url` / `target` / `host` / `endpoint`
  / `address` / `cidr` — the scope guard inspects exactly these keys.
- Targetless tools (`report__write_finding`, the `whitebox__*` family)
  are listed explicitly in `redteam/hooks/scope_guard.py::_TARGETLESS_TOOLS`.
- New tool packs go under `redteam/tools/<name>.py`, expose `PACK_NAME`
  and `build_pack(ctx)`, and get listed in `redteam/tools/__init__.py::PACKS`.
- New subagents go under `redteam/subagents/<name>.md` and are loaded
  by name from the engagement YAML.
- Hooks dispatch through `Orchestrator._build_hooks()`; treat that as
  the SDK seam — adapt to the SDK's actual API there, don't sprinkle
  imports across the package.
- **`redteam triage` is READ-ONLY over the sealed ledger** — it must never
  mutate, append to, or re-seal it. Its only writes are the three artifacts
  under `--out` (`.triaged.sarif` / `.report.md` / `.triage.json`).
- **Triage stages must degrade, never crash.** Deterministic stages drop-and-
  record a bad finding (never raise); every model-output path is wrapped
  (verify failure → UNVERIFIED-kept, chain failure → `chains=[]` + degraded).
- **The verify/chain model turns get NO tools** (`allowed_tools=[]` in
  `pipeline/llm.py::_query_options`). This is load-bearing: it keeps the model
  inside the pipeline's source-containment (it reasons only from the excerpt
  `stages._source_window` feeds it, never the host CLI's Read/Grep/Bash) and
  stops tool_use blocks from exhausting `max_turns=1`. The verify/chain system
  prompts say "you have NO tools" to match — don't reintroduce "walk the
  callers"-style investigation.
- `pipeline/load.py` imports **only the agent's report fields** from the ledger
  (a whitelist); enrichment/verify fields (`cvss_*`, `verdict*`, `cwe*`) are set
  by the pipeline, so a tampered ledger can't inject verify-grade trust.

## Build & test

```bash
pip install -e ".[dev]"                       # install in editable mode
redteam validate engagements/example.yaml      # parse-only check
redteam run engagements/example.yaml --dry-run # build options without calling SDK
redteam doctor                                 # readiness check (no token spend)
pytest                                         # contract + RT/M-batch tests

# M3 triage over a completed engagement's ledger (deterministic = no creds):
redteam triage /audit/ENG-ID.jsonl --assets-root ./targets/example-api
# add --verify and/or --chain to run the opt-in model stages (needs a backend
# or a logged-in `claude` CLI); --out defaults to the ledger's parent dir.
```

Container path (`ENGAGEMENT` is the in-CONTAINER path; compose mounts
`./engagements` at `/engagements`):

```bash
ENGAGEMENT=/engagements/example.yaml \
  docker compose -f redteam/runtime/docker-compose.yml up --abort-on-container-exit redteam
```

## What to build next (suggested order)

**The roadmap is essentially complete.** #1–#7 are all DONE (this session
landed #2 KMS sealer, #4 recon `gh_*`, #5 Jira upsert, #6 real scanners, #7
OTel/Grafana; #1 signature verify and #3 nftables were done earlier), and #8
(M3 v-next) is done except for CMDB-sourced per-asset environmental inputs,
which needs a real CMDB and is out of scope. The one remaining sub-item:
environmental CVSS + offensive-priority, semantic/LLM dedup, and multi-backend
model routing all landed this session. Each item below is kept for provenance
(strikethrough = done):

1. ~~Wire signature verification so an unsigned/bad-signed YAML never reaches
   the orchestrator.~~ **Done:** `redteam run` verifies the detached operator
   signature (`auth.verify_engagement_file` against
   `engagements/authorized_signers`) and exits (code 3) *before* constructing
   the orchestrator; `--skip-signature` is the dev-only escape, and
   `--dry-run`/`validate` intentionally skip it. (The seam is the CLI run gate,
   not `Engagement.from_yaml` — same guarantee.)
2. ~~Finish the KMS sealer switch.~~ **Done:** `build_sealer(env)`
   (`redteam/ledger/kms_seal.py`) returns a `KmsHmacSealer` when
   `REDTEAM_KMS_KEY_ID` is set, else `None`. `LedgerWriter` takes an injected
   `sealer` (authoritative over the file HMAC key); `Orchestrator` passes it
   through; the CLI `run` injects `build_sealer(os.environ)`, so the container
   seals with KMS and local pytest keeps the file-key path (`method: "file"`).
   `verify.py` dispatches on `seal["method"]`. `KmsHmacSealer.write_seal()`
   owns the KMS seal-file format; boto3 stays lazy. Tested in
   `tests/test_kms_sealer_switch.py` and hardened by a three-agent adversarial
   pass (seal correctness / regression / hard-constraint). A live KMS seal
   can't run on this host (no AWS creds); the boto3-mocked tests cover
   sign/verify/round-trip.
3. ~~Render `scope.egress_allowlist` into nftables in `entrypoint.sh`.~~
   **Done (RT-23):** `redteam/runtime/render_netpolicy.py` renders a
   default-deny nft ruleset (IMDS denied first, overlapping entries
   collapsed); the entrypoint loads it and fails closed.
4. ~~Implement the recon `gh_*` tools as wrappers around the `gh` CLI.~~
   **Done:** `recon__gh_search_code` / `gh_search_repos` / `gh_repo_view`
   shell out to `gh` (list argv, no shell), are read-only and org-scoped
   (every search carries `--owner`; `scope.github_orgs`, if set, *enforces*
   the owner; scope-broadening `org:`/`user:`/`repo:` query qualifiers are
   refused), and are total (missing binary / non-zero exit / timeout /
   non-JSON / bad limit → structured error, never a raise). Listed targetless
   in `scope_guard.py`. Optional new engagement field `scope.github_orgs`.
   Tested in `tests/test_recon_gh.py` (22 cases) + hardened by a two-agent
   adversarial pass (injection/containment + regression).
5. ~~Implement Atlassian MCP wiring + idempotent Jira upsert.~~ **Done:**
   `redteam/jira.py` owns the deterministic scaffolding (the Atlassian MCP is
   agent-driven): `external_key(engagement_id, title, location)` =
   `redteam-<engagement>-<12hex>` (a re-run yields the same key → the ticket is
   updated, not duplicated), `jql_for_key`, `build_issue_fields`, `plan_upsert`
   (create-vs-update). Wired into `report.py` as the gated `report__jira_upsert`
   tool (only when the atlassian MCP is enabled AND `reporting.jira_project` is
   set) and into the M3 triage output as a `<stem>.jira.json` bundle
   (`redteam triage --jira-project SEC`). New optional field
   `reporting.jira_project`. Security: engagement_id is sanitised in the key
   (safe Jira label) and JQL operands are escaped; `--jira-project` is validated
   — a two-agent adversarial pass caught a JQL-injection via the CLI flag and a
   tampered-ledger engagement_id, both fixed. `report.py` (live) and triage
   derive the SAME key so they converge on one ticket per finding. Tested in
   `tests/test_jira.py` / `test_report_jira.py` / `test_triage_jira.py`.
6. ~~Real semgrep / tfsec / checkov calls in `whitebox.py`.~~ **Done:**
   `redteam/tools/_scanners.py` runs semgrep (source) / tfsec + checkov (IaC)
   via a list argv (no shell; the scanned path is always a resolved asset
   host_path, never agent-typed) and normalises each tool's JSON to a common
   finding shape. Load-bearing subtlety: these scanners **exit non-zero when
   they find issues**, so output is parsed regardless of exit code — valid JSON
   = success, unparseable/empty output = error (an empty-stdout crash is NOT
   laundered into a clean scan). All paths are total. `whitebox__semgrep_scan`
   (by `role`) and `whitebox__iac_scan` (by `kind`, optional `scanner`
   override) wire it up. Tested in `tests/test_whitebox_scanners.py` (18
   cases) + a two-agent adversarial pass (correctness/totality + regression).
   NB: `semgrep --config auto` needs `semgrep.dev` in `egress_allowlist`.
7. ~~OTel exporter — confirm SDK env vars and add a starter dashboard
   provisioning file.~~ **Done:** the redteam service sets the Claude Code
   telemetry env (`CLAUDE_CODE_ENABLE_TELEMETRY=1`, `OTEL_METRICS_EXPORTER`/
   `OTEL_LOGS_EXPORTER=otlp`, `OTEL_EXPORTER_OTLP_PROTOCOL=grpc` → the collector
   on `:4317`), the collector routes metrics→Prometheus (`:8889`, scraped) and
   traces→Tempo, and Grafana auto-provisions both datasources + the
   `redteam-engagement` dashboard (Claude Code `claude_code_*` metric panels).
   `docker compose -f redteam/runtime/docker-compose.yml --profile dev up`
   lights it up with no manual import. Metric names use
   `add_metric_suffixes: false` (plain dots→underscores) so the panel queries
   match. Contract-tested in `tests/test_otel_provisioning.py`. NB: the
   default-deny egress nft ruleset drops OTLP to the collector in the hardened
   container — run the dev stack with `REDTEAM_NETPOLICY_OPTIONAL=1` or add the
   collector to `egress_allowlist`. (Traces populate once trace export is
   enabled — Claude Code beta flag or an app TracerProvider, RT-22.)
8. **M3 v-next (partially done).**
   - ~~environmental CVSS + offensive-priority scoring~~ **Done:**
     `cvss.environmental_score` (CVSS 3.1 §7.3 modified base + Security
     Requirements CR/IR/AR; cross-checked 0-mismatch vs the RedHat `cvss` lib
     over ~12k vectors) feeds the enrich stage; a new deterministic
     `stages.prioritize` (env-CVSS + exploitability + verdict + chain
     membership → 0-100 score + P1-P4 tier) runs after chains. Driven by
     `redteam triage --security-requirements CR:H,IR:H`; surfaced in SARIF
     props, the markdown Priority/Env columns, and `triage.json`. Tested in
     `tests/test_m3_cvss.py` + `tests/test_m3_priority.py`.
   - ~~semantic/LLM dedup~~ **Done:** opt-in `stages.semantic_dedup_findings`
     (`redteam triage --semantic-dedup`, gated on `model_stage_ready`) runs a
     model pass on the deterministic survivors to merge same-root-cause
     findings the `(file, vuln_class)` dedup misses. Conservative by design —
     the danger is a false-negative (a merged finding vanishing): a duplicate
     must share the canonical's file, indices are validated in-range + disjoint,
     every merge is recorded in `report.dropped` (auditable/recoverable), and a
     bad/unparseable/errored reply degrades (keeps everything). Total (hardened
     against a >4300-digit index crash). Tested in
     `tests/test_m3_semantic_dedup.py`.
   - ~~multi-backend model routing~~ **Done:** `llm.resolve_model(models,
     stage, default)` + a `models` param on `run_triage` route each model stage
     to its own model id — `redteam triage --verify-model … --chain-model …
     --dedup-model …` (falling back to `--model`). The ambient backend (env) is
     shared, so this routes the model *id* per stage, not the provider per call.
     Tested in `tests/test_m3_model_routing.py`.
   - **Still deferred:** CMDB-sourced per-asset environmental inputs — v1 takes
     engagement-wide Security Requirements from `--security-requirements`, not a
     CMDB (needs a real CMDB integration; out of scope here). **This is the last
     open roadmap item.**

## What NOT to do

- Don't add a second third-party MCP (no Burp, Shodan, GitLab, etc.).
  If the next session needs one, raise it with the user first.
- Don't replace `gh` CLI with the GitHub MCP. The user explicitly chose
  this tradeoff; revisiting it is a user decision.
- Don't add GCP or Azure to the cloud pack in v1.
- Don't broaden tool allowlists or weaken scope-guard defaults to "make
  things work" during development. The defence-in-depth model (hook is
  the gate, tool is the lock) is load-bearing.
