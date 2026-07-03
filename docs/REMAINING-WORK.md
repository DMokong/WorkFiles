# Remaining work

Single, self-contained backlog for anyone picking up `redteam` in a later
session or a different workspace. It consolidates what is **not** done and where
to start. Everything here is on `main` as of commit `9026c62`.

## Where the truth lives

- **`docs/review-findings.json`** — the structured source of truth: every review
  finding (`RT-01..RT-31`) with severity/status/recommendation, plus the
  `meta.fix_batches` history (each batch's scope, verification, and `residual`).
- **`docs/REVIEW.md`** — the narrative, dated log of every batch.
- **`CLAUDE.md`** — orientation + hard constraints + the "What to build next"
  roadmap (now almost entirely struck through).
- **This file** — the actionable open-items digest that ties those together.

## Status in one line

Roadmap items **#1–#7 are done**, and **#8 (M3 v-next)** is done except for one
sub-item (CMDB inputs, below). What remains is: **one roadmap feature that needs
an external system**, a set of **confirmed-but-unfixed review findings**
(mostly medium/low hardening), **live/deploy verification gaps** (things tested
by mock that a real run would confirm), and a handful of **intended stubs**.
Full suite: 391 passed, ruff clean.

---

## A. Remaining roadmap feature

### A1. CMDB-sourced per-asset environmental CVSS inputs  *(the last #8 item)*
- **What:** feed the environmental CVSS + offensive-priority scoring
  (`redteam/pipeline/cvss.py::environmental_score`, `stages.py::prioritize`) with
  **per-asset** Security Requirements / modified metrics pulled from a CMDB,
  instead of the current **engagement-wide** `--security-requirements` flag.
- **Why not done:** needs a real CMDB integration + a per-asset data source; not
  buildable/testable in a credential-less workspace.
- **Start at:** `stages.enrich(security_requirements=...)` already threads a
  requirements dict; extend it to a per-finding/per-asset lookup keyed by the
  finding's file/asset. Add the CMDB client behind a seam like the `llm.ask`
  seam so it stays mockable. Keep it opt-in and total (missing CMDB entry →
  fall back to the engagement-wide requirements → base).

---

## B. Open review findings (confirmed, not yet fixed)

From `docs/review-findings.json`. Ordered by severity. "Partial" = this session
moved it but left work.

### Medium
- **RT-11 — cloud pack unreachable + advertises GCP/Azure.** The cloud tools take
  no target key so the scope guard denies them, and the enum lists GCP/Azure
  (v1 is AWS-only). *Fix:* add the cloud tools to `_TARGETLESS_TOOLS` (and
  scope-check ARNs inside the tool) or give them a target-bearing key; restrict
  the enum to `aws`. (`redteam/tools/cloud.py`, `redteam/hooks/scope_guard.py`.)
- ~~**RT-16 — Dockerfile scanner pins dropped; unpinned `latest`; no
  checksums.**~~ **DONE:** base image digest-pinned; pip scanner specs quoted +
  exact-pinned (fixes the `>=`-as-redirection bug); awscli + tfsec version-pinned
  and SHA256-verified; kube-linter removed (unused); per-install `--version`
  smoke-checks. Contract-tested (`tests/test_dockerfile_rt16.py`); the
  base-digest + awscli/tfsec checksum-install layers were live-built
  (linux/amd64).
- **RT-16-followup — NodeSource `curl … | bash` is unverified RCE.** Flagged by
  the RT-16 review (out of RT-16's scanner scope): `Dockerfile:~35` runs
  `curl -fsSL https://deb.nodesource.com/setup_20.x | bash -` — the *nodejs apt
  package* it configures is GPG-verified, but the setup script piped to bash is
  not. *Fix:* set up the NodeSource apt repo + keyring manually (pinned) instead
  of piping the script. Lower-priority follow-ups: `@anthropic-ai/claude-code`
  has no npm integrity hash/lockfile; apt packages (gh/nmap/…) float on the
  distro. (`redteam/runtime/Dockerfile`.)
- **RT-17 — no locking on ledger/budget; blocking I/O in async hooks (latent).**
  `report.py` got an `asyncio.Lock` for the SARIF write (RT-21), but the ledger
  `append()` and budget mutation are still unlocked, and hook bodies do blocking
  file I/O. *Fix:* `asyncio.Lock` around `LedgerWriter.append()` + budget
  mutation; move blocking I/O to a thread (`anyio.to_thread`).
  (`redteam/ledger/chain.py`, `redteam/budget.py`, `redteam/orchestrator.py`.)
- **RT-18 — Redactor misses standard secrets and over-redacts.** *Fix:* match
  `Authorization: <scheme> <token>`, anchor/contextualize the AWS-secret
  pattern, add PII detectors (email/SSN/cc/phone) on the telemetry path.
  (`redteam/hooks/redactor.py`.)
- **RT-20 — budget semantics.** `turns` counts tool calls; the boundary is `>=`;
  model-token cost may never be captured. *Fix:* separate turns from tool calls,
  confirm the SDK cost signal and wire model-token cost, count only
  successful+allowed calls. (`redteam/budget.py`, `redteam/orchestrator.py`.)
- **RT-22 — observability partially unwired *(Partial after #7)*.** #7 wired the
  **Claude Code CLI** telemetry (metrics→Prometheus, auto-provisioned Grafana)
  and confirmed the env vars. **Still open:** the redteam **app's own**
  `telemetry.py` is a no-op tracer — no `TracerProvider`/exporter is configured,
  so `tool_span` / `event_finding` record nothing and the Tempo traces panel
  stays empty. *Fix:* configure a real OTel `TracerProvider` + OTLP span
  exporter at orchestrator start; emit `tool.invoked` + `finding.recorded`; wrap
  tool execution in `tool_span`; gate `tls insecure` to the dev profile.
  (`redteam/hooks/telemetry.py`, `redteam/orchestrator.py`.)
- **RT-24 — schema validation gaps.** userinfo/port in URLs, weak hostname
  regex, list-size DoS, `Reporting.destination` traversal, YAML size. *Fix:*
  reject userinfo/unintended ports, tighten the hostname regex, cap list lengths
  + YAML size, constrain `destination` to the audit dir. (`redteam/engagement.py`.)
- **RT-25 — asset containment not enforced at parse time.** Absolute paths and
  `../` can escape `host_root`. Runtime whitebox tools do contain
  (`resolve_under_root` / `_resolve_under_assets`), but `assets.build_index`
  doesn't assert it. *Fix:* after `resolve()`, assert `relative_to(allowed_root)`
  and reject absolute/escaping asset paths at parse time. (`redteam/assets.py`.)
- **RT-26 — thin error handling *(Partial)*.** The CLI-run slice + the fail-closed
  hook `try/except` are done; remaining: log when the seal is skipped for a
  missing key, and broaden setup/hook error paths. (`redteam/orchestrator.py`.)
- **RT-28 — shallow test suite *(largely mitigated this session)*.** 270→391
  tests, with new CLI/SDK-contract/adversarial/symlink/window/verify/redactor-
  adjacent coverage across the batches. Re-audit RT-28's checklist against the
  current suite and close or re-scope it. (`tests/`.)
- **RT-29 — documentation drift *(largely mitigated)*.** Every batch this session
  kept `CLAUDE.md` / `REVIEW.md` / `review-findings.json` in sync. Do a final
  pass over `docs/PLAN.md` for any remaining not-yet-wired claims.

### Low / nit
- **RT-19 (low)** — `RunResult.entry_count` reports `budget.turns`, not the
  ledger sequence (cosmetic). *Fix:* set it from the ledger `_seq`.
  (`redteam/orchestrator.py`.)
- **RT-27 (low)** — external-MCP preflight reachability is promised but absent.
  *Fix:* add a connectivity check that records `mcp.external.unreachable`, or
  trim the claim. (`redteam/mcp_external.py`.)
- **RT-30 (low)** — unused deps + missing package metadata (license/author, SDK
  pin range). (`pyproject.toml`.)
- **RT-31 (nit)** — minor code smells / dead code (reuse `PACKS`, share one
  `_extract_target`, `list_assets` returning host vs container paths).

---

## C. Live / deploy verification gaps

Everything below is **implemented and mock/contract-tested**, but was **not
exercised against the live system** here (no AWS/Jira/Grafana creds; live model
runs cost credits). A future workspace with the right access should confirm:

- **KMS seal (build-next #2).** boto3-mocked tests pass; a live
  `kms:GenerateMac`/`VerifyMac` round trip needs AWS creds + the workload IAM
  role on the key ARN. Deploy note: the container defaults to KMS only when
  `REDTEAM_KMS_KEY_ID` is set.
- **Jira upsert (build-next #5).** The idempotency logic + `.jira.json` bundle
  are tested; applying the bundle against a **real Jira** via the Atlassian MCP
  (agent- or operator-driven) is untested. Also: `redteam triage` does **not
  verify the ledger seal** before triaging (a pre-existing M3 property — the
  #5 JQL-injection is neutralized regardless, but seal verification is worth
  adding; ties to RT-13/RT-26).
- **OTel/Grafana (build-next #7).** `docker compose config` validates and the
  provisioning is contract-tested, but `--profile dev up` with a real engagement
  wasn't run. **Egress caveat:** the default-deny nft ruleset drops OTLP to the
  collector in the hardened container — the dev stack needs
  `REDTEAM_NETPOLICY_OPTIONAL=1` or the collector added to `egress_allowlist`
  (documented in the compose file; not auto-punched, to preserve the security
  model).
- **Model stages live.** verify/chain/semantic-dedup/model-routing are covered
  by injected-`ask` spies; a live model run would re-confirm end-to-end (the M3
  live run earlier hit precision 1.0 + 3 chains, but the v-next stages weren't
  re-run live).
- **Container-side #6.** semgrep / tfsec / checkov are now installed, pinned, and
  checksum-verified in the image (RT-16 done); the base-digest + awscli/tfsec
  checksum-install layers were live-built (linux/amd64). Remaining: a **full**
  image build (the heavy node/npm/pip layers weren't rebuilt to completion here
  under arm64→amd64 emulation) and a live whitebox run where the scanners scan a
  real repo. `semgrep --config auto` needs `semgrep.dev` in `egress_allowlist`.

---

## D. Intended stubs (NOT bugs — documented v1 scope cuts)

Do not "fix" these without a scope decision; they return `not_implemented` on
purpose:
- **recon:** `whois` (needs the `whois` binary), `cert_transparency` (needs
  crt.sh egress).
- **whitebox:** `sbom_query`, `openapi_diff`, `dependency_audit`.
- **cloud pack:** `list_buckets` / `describe_iam` (the only fully-stubbed pack;
  `web` and `network` are real). Ties to RT-11.
- **Third-party MCP allowlist stays `{atlassian}`** and **GitHub stays on the
  `gh` CLI** — both are deliberate; changing them is a user decision (CLAUDE.md).

---

## E. Suggested pickup order

1. ~~RT-16 + container-side #6~~ **DONE** — scanners are pinned + checksum-verified
   in the image; next is a full-image build + a live whitebox run (see §C).
2. **RT-22 app tracer** — a real `TracerProvider` so the app's own spans/events
   populate Tempo (completes the #7 observability story).
3. **RT-17 / RT-20 / RT-26** — the ledger/budget/error-handling hardening cluster.
4. **RT-24 / RT-25** — schema + asset-containment validation at parse time.
5. **RT-18** — redactor secrets/PII.
6. **A1 (CMDB)** — when a CMDB is available.
7. **Low/nit:** RT-11, RT-19, RT-27, RT-29 (PLAN pass), RT-30, RT-31.
