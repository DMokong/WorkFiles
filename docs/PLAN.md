# Modular Security Testing Harness on the Claude Agent SDK

> **Package name**: `redteam/`. CLI: `redteam run engagement.yaml`.
> Verifier CLI: `redteam-verify`. (The plan-file slug "squid" is just an
> artifact of the original filename — no Squid the proxy involvement.)

## Context

The org needs a controlled, repeatable way to run authorized red-team
engagements against its own systems. The harness must let an operator
define a scope, hand the agent an objective, and walk away — while keeping
the four properties non-negotiable:

- **Observability** — live visibility into every model decision and tool
  call as a run progresses.
- **Auditability** — a tamper-evident, post-hoc record of *what* the agent
  did, *what input* prompted it, and *who* authorized the engagement.
- **Customisability** — per-engagement scope, tool allowlists, network
  egress rules, and pluggable test modules without touching the core.
- **Autonomy** — long unattended runs that respect budget/turn caps,
  decompose work into subagents, and only escalate when an operator is
  required.

The repo is greenfield (`/home/user/WorkFiles`, branch
`claude/security-testing-harness-X0QVs`, no commits). Built in **Python**
on the Claude Agent SDK. Each engagement runs in an **ephemeral container**.
Engagements are defined as **YAML scope + natural-language objective**.

---

## Architecture overview

```
┌───────────────────────────────────────────────────────────────┐
│ Engagement spec  (YAML scope + NL objective + operator sig)   │
└──────────────────────┬────────────────────────────────────────┘
                       ▼
┌───────────────────────────────────────────────────────────────┐
│ Runtime: ephemeral Docker container, scoped egress, no        │
│ persistent state outside mounted audit volume                 │
└──────────────────────┬────────────────────────────────────────┘
                       ▼
┌───────────────────────────────────────────────────────────────┐
│ Orchestrator (Python)                                         │
│   ClaudeSDKClient → agent loop → subagent decomposition       │
└──────────────────────┬────────────────────────────────────────┘
                       ▼
┌───────────────────────────────────────────────────────────────┐
│ Policy spine (hooks)                                          │
│   PreToolUse  — scope check, payload allowlist, budget gate   │
│   PostToolUse — capture, redact, emit telemetry, hash-chain   │
│   SessionStart/End — seal & sign the audit ledger             │
└──────────────────────┬────────────────────────────────────────┘
                       ▼
┌───────────────────────────────────────────────────────────────┐
│ Tool packs (in-process MCP servers)                           │
│   recon | web | cloud | code | network | report               │
└──────────────────────┬────────────────────────────────────────┘
                       ▼
┌───────────────────────────────────────────────────────────────┐
│ Sinks: OTel collector (live)  +  signed JSONL ledger (audit)  │
└───────────────────────────────────────────────────────────────┘
```

---

## Repo layout

```
/home/user/WorkFiles/
├── pyproject.toml                  # claude-agent-sdk, pydantic, opentelemetry, pyyaml, boto3
├── README.md
├── redteam/                        # core package
│   ├── __init__.py
│   ├── cli.py                      # `redteam run engagement.yaml`
│   ├── orchestrator.py             # ClaudeSDKClient setup + run loop
│   ├── engagement.py               # pydantic models + SSH-sig verify
│   ├── budget.py                   # cost/turn/tool-call accounting
│   ├── hooks/
│   │   ├── scope_guard.py          # PreToolUse: enforce target/egress allowlist
│   │   ├── audit_writer.py         # Pre+Post: append to ledger
│   │   ├── redactor.py             # Post: scrub secrets before telemetry
│   │   └── telemetry.py            # Post: emit OTel spans + structured events
│   ├── ledger/
│   │   ├── chain.py                # hash-chained append-only JSONL
│   │   ├── kms_seal.py             # KMS GenerateMac on session end
│   │   └── verify.py               # standalone redteam-verify CLI (KMS VerifyMac)
│   ├── tools/                      # in-process stdio MCP servers, one per pack
│   │   ├── recon.py                # DNS, whois, CT, gh CLI wrappers
│   │   ├── web.py                  # http_get/post, fuzzer, header check
│   │   ├── cloud.py                # AWS-only read-only enumeration (boto3)
│   │   ├── network.py              # nmap-lite (scope-bound), tcp connect probe
│   │   ├── whitebox.py             # semgrep, tfsec, checkov, openapi_diff
│   │   └── report.py               # SARIF writer + Jira upsert via Atlassian MCP
│   ├── mcp_external.py             # adapter for the atlassian entry only
│   ├── assets.py                   # mount + index source/IaC/specs read-only
│   ├── subagents/
│   │   ├── recon.md
│   │   ├── analyst.md
│   │   ├── whitebox.md
│   │   └── exploiter.md
│   └── runtime/
│       ├── Dockerfile              # python:3.12-slim + gh + awscli + scanners
│       ├── docker-compose.yml      # harness + OTel collector + dev Grafana stack
│       ├── entrypoint.sh           # mounts audit + assets ro, drops caps, launches redteam
│       ├── netpolicy.json          # egress allowlist template
│       └── otel/
│           ├── collector.yaml      # OTLP in → traces:Tempo, metrics:Prometheus
│           ├── tempo.yaml          # dev traces backend
│           ├── prometheus.yml      # scrapes the collector's :8889 metrics
│           └── grafana/            # auto-provisioned datasources + dashboard
│               ├── provisioning/{datasources,dashboards}/*.yaml
│               └── dashboards/redteam-engagement.json
├── engagements/
│   ├── example.yaml                # sample scoped engagement
│   └── authorized_signers          # SSH allowed-signers file for ssh-keygen -Y verify
├── targets/                        # operator clones target repos here via `gh`
│   └── .gitkeep
└── tests/
    ├── test_scope_guard.py
    ├── test_ledger_chain.py
    ├── test_engagement_schema.py
    ├── test_signature_verify.py
    ├── test_kms_seal.py
    ├── test_external_mcp_allowlist.py
    └── test_assets_mount.py
```

---

## Engagement spec (the customisability surface)

Every run is rooted in one YAML file. The operator's NL objective is a
field inside it, so scope and intent are versioned together.

```yaml
# engagements/example.yaml
id: ENG-2026-04-001
operator: alice@example.com
operator_signature: |                    # ssh-keygen -Y sign output, armored
  -----BEGIN SSH SIGNATURE-----
  ...
  -----END SSH SIGNATURE-----
authorized_by: ciso@example.com
window:                                  # hard time bound
  start: 2026-04-27T09:00:00Z
  end:   2026-04-27T17:00:00Z

scope:
  targets:                               # only these hosts/CIDRs are in-scope
    - https://staging.example.com
    - 10.20.0.0/24
  out_of_scope:                          # explicit deny wins
    - https://staging.example.com/admin
  egress_allowlist:                      # container netpolicy
    - api.anthropic.com                  # always required
    - mcp.atlassian.com                  # only if external_mcp.atlassian enabled
    - api.github.com                     # only if `gh` is used during the run
    - kms.us-east-1.amazonaws.com        # for ledger seal HMAC

# OPTIONAL whitebox surface — if the operator can supply source code,
# IaC, OpenAPI specs, build artefacts, etc., the agent gets a much
# stronger attack surface than blackbox alone. All paths are mounted
# READ-ONLY into the container and never written back.
assets:
  source_repos:
    - path: ./targets/example-api          # local clone, ro-bind into container
      language: python
      role: backend
    - path: ./targets/example-web
      language: typescript
      role: frontend
  iac:
    - path: ./targets/example-infra/terraform
      kind: terraform
    - path: ./targets/example-infra/k8s
      kind: kubernetes
  specs:
    - path: ./targets/example-api/openapi.yaml
      kind: openapi
  artefacts:                               # optional: built images, SBOMs
    - path: ./targets/sboms/api.cdx.json
      kind: cyclonedx

budget:
  max_turns: 200
  max_usd: 25.00
  max_tool_calls_per_target: 50

tools:                                   # tool packs to load (everything else off)
  - recon
  - web
  - whitebox          # only loaded if `assets:` is non-empty
  - report

subagents: [recon, analyst]              # which subagents are spawnable

# Optional third-party MCP servers. v1 supports exactly ONE: Atlassian
# Rovo (Jira + Confluence). The schema rejects any other name at parse
# time. GitHub is reached via the `gh` CLI baked into the runtime image,
# not via an MCP server. Everything else is bespoke under redteam/tools/.
external_mcp:
  - name: atlassian              # Atlassian Rovo MCP
    transport: http
    url: https://mcp.atlassian.com/v1/sse
    allowed_tools:
      - jira__search             # read
      - jira__get_issue          # read
      - jira__create_issue       # write — used by `report` to upsert findings
      - jira__update_issue       # write — idempotent finding upsert
      - confluence__search       # read
      - confluence__get_page     # read

objective: |
  Identify any unauthenticated endpoints under staging.example.com that
  expose user PII. Cross-reference findings with the OpenAPI spec and
  the backend source tree. Do NOT attempt write/delete operations.
  Confirm findings with at least two independent requests before
  reporting.

reporting:
  format: sarif
  destination: /audit/findings.sarif
```

The pydantic schema in `redteam/engagement.py` rejects malformed files and
is the single source of truth that hooks consult at runtime.

---

## Orchestrator (`redteam/orchestrator.py`)

Thin wrapper around `ClaudeSDKClient`:

1. Parse + verify engagement signature.
2. Build `ClaudeAgentOptions`:
   - `system_prompt` — combines org-wide red-team rules of engagement +
     the YAML `objective`.
   - `allowed_tools` — derived from `tools` in YAML (everything else is
     unreachable).
   - `permission_mode="dontAsk"` — no human prompts; hooks decide.
   - `hooks` — register PreToolUse, PostToolUse, SessionStart, SessionEnd.
   - `agents` — register subagents from `subagents/` markdown files,
     each with their own tool subset.
   - `mcp_servers` — register the in-process tool packs from `redteam/tools/`.
   - `max_turns` and budget callbacks.
3. Call `client.query(objective)` and stream messages, letting hooks do
   the heavy lifting. The orchestrator itself has very little logic —
   policy lives in hooks, capability lives in tool packs.
4. On `error_max_turns` / `error_max_budget_usd` result subtypes, seal
   the ledger and exit non-zero.

Reuses SDK primitives directly — no custom agent loop. Subagent
decomposition (recon → analyst → exploiter) is requested by the parent
agent via the Task tool, scoped by the YAML `subagents` list.

---

## Policy spine — hooks (`redteam/hooks/`)

The hook layer is where all four requirements converge.

| Hook         | Purpose                                                         |
|--------------|-----------------------------------------------------------------|
| `scope_guard.PreToolUse`  | Reject tool calls whose target/URL/CIDR isn't in `scope.targets` or hits `out_of_scope`. Reject if egress destination not in allowlist. Decision: `deny` with reason captured in audit. |
| `audit_writer.PreToolUse` | Append `{ts, session_id, tool, input, decision_pending}` to the ledger before execution. |
| `audit_writer.PostToolUse`| Append `{ts, session_id, tool, output_hash, duration, cost}`; link to pre-record by `tool_use_id`. |
| `redactor.PostToolUse`    | Strip secrets/tokens/PII from `tool_response` before it goes to telemetry (the ledger keeps the raw hash, redacted body). |
| `telemetry.PostToolUse`   | Emit OTel span + structured event to the configured collector. |
| `SessionStart`            | Write engagement YAML + operator signature as ledger entry 0. |
| `SessionEnd`              | Compute final hash chain head, sign with HMAC key from container env, write `ledger.seal`. |

**Reused primitives** (from research):
- SDK's PreToolUse `permissionDecision: "deny"` blocks execution natively.
- SDK's session JSONL at `~/.claude/projects/<cwd>/sessions/<uuid>.jsonl`
  is mirrored into our signed ledger — we don't reinvent transcript
  storage, we add tamper-evidence on top.
- SDK's built-in OpenTelemetry instrumentation handles model spans and
  token metrics; the `telemetry` hook only adds tool-level enrichment.

---

## Tool packs and MCP architecture

Two layers exist, with a clear seam between them:

### A. First-party packs (in-process, ours)

Every starter pack ships as an **in-process stdio MCP server** registered
via the SDK's `mcp_servers` option (Python `create_sdk_mcp_server` /
equivalent). They run inside the harness process, in the same container,
under the same scope guard. **No third-party MCP platforms or network
calls to external MCP brokers.** Operators add a pack by dropping a
Python file in `redteam/tools/` and listing it under `tools:` in the
YAML — no core changes.

Starter packs:

- **recon** — DNS lookups, cert transparency, whois. Plus thin
  wrappers around `gh` (e.g. `gh_repo_list`, `gh_search_code` for the
  org's GitHub) authenticated via the mounted PAT. No vendor OSINT
  APIs by default; Shodan/VT are a separate opt-in extras module —
  see "Third-party HTTP/API dependencies" below.
- **web** — `http_request(method, url, body, headers)` constrained by
  scope guard; header inspector; simple parameter fuzzer.
- **cloud** — AWS-only, read-only boto3 wrappers (S3 list, IAM
  describe, EC2/ECS/Lambda enumeration, etc.; no mutation verbs).
  GCP/Azure are out of scope for v1.
- **network** — TCP connect probe + lightweight port scan, both bound
  by `scope.targets` CIDRs.
- **whitebox** — operates over the read-only `assets:` mount. Provides
  `repo_grep`, `repo_read`, `semgrep_scan`, `dependency_audit`,
  `iac_scan` (tfsec / checkov / kube-linter), `openapi_diff`,
  `sbom_query`. The mount is populated *before* the engagement starts
  by the operator running `gh repo clone` / `gh repo sync` into
  `./targets/` — see "Asset fetch workflow" below.
- **report** — canonical finding writer. Always writes SARIF to the
  audit volume. If `external_mcp.atlassian` is enabled, also upserts a
  Jira ticket per finding (deterministic external key prevents
  duplicates on re-runs).

Each tool function does an internal scope check as a defence-in-depth
backup to `scope_guard` — the hook is the gate, the tool is the lock.

### B. Third-party MCP — exactly one: Atlassian Rovo (Jira + Confluence)

We are deliberately conservative about external MCP dependencies. v1
supports exactly **one** third-party MCP server, opt-in per engagement:

- **Atlassian Rovo MCP** — Jira + Confluence. Read paths give the agent
  context (existing tickets, architecture docs). The write path is
  used by the `report` pack to **upsert Jira tickets** for findings
  (create-or-update by deterministic key derived from finding hash, so
  re-runs don't spam tickets).

**GitHub is *not* an MCP dependency.** The runtime image bakes in the
`gh` CLI, authenticated via a PAT mounted at `/run/secrets/gh_token`.
Recon, whitebox, and asset-fetch use `gh repo clone`, `gh api`, etc.
directly — no MCP broker, no Copilot dependency. This keeps the
GitHub integration to a tool the org already trusts.

The pydantic schema for `external_mcp:` validates
`name in {"atlassian"}` at parse time and rejects anything else.
Adding a second provider in future is a deliberate, reviewed code
change — not a YAML flag flip. Anything else we'd reach for via a
vendor MCP (web proxy, scanner, SIEM) we build as a bespoke in-process
pack under `redteam/tools/`.

Rules that apply to Atlassian:

- Not loaded by default. An empty `external_mcp:` means none.
- The entry must specify `allowed_tools` (a subset of the supported
  Jira/Confluence tools). Tool names carry the `atlassian__` prefix
  and pass through the same `scope_guard` PreToolUse hook.
- `mcp.atlassian.com` must be in `egress_allowlist` or the netpolicy
  drops the connection.
- The audit ledger records that the Atlassian MCP served each
  cross-system call, so reviewers can tell first-party from
  third-party action.

### Third-party HTTP/API dependencies (separate from MCP)

Some recon work historically pulls from external HTTP APIs (Shodan,
VirusTotal, etc.). To stay consistent with the "minimise third-party
platform dependency" stance, the **default `recon` pack is offline
only**: DNS, whois, certificate transparency (CT logs are a
distributed system, not a vendor), and parsing data the operator
provides. Any vendor-API integration (Shodan, VT) is a **separate
opt-in extras module** the operator must explicitly enable per
engagement and is treated as third-party platform usage in the audit
ledger.

---

## Container runtime (`redteam/runtime/`)

- Base: `python:3.12-slim`.
- Bundled tooling in the image: `gh` CLI, `nmap` (scope-bound),
  `semgrep`, `tfsec`, `checkov`, `kube-linter`, `awscli` v2.
- Orchestration: **docker compose**. One compose project per engagement;
  spins up the harness container, a local OTel collector, and (in dev)
  the local Grafana stack.
- Hardening: drop all Linux caps except those needed by network tools;
  run as non-root UID; rootfs read-only except `/audit` and `/tmp`.
- Network: outbound default-deny via iptables/nftables; the entrypoint
  reads `scope.egress_allowlist` and renders a netpolicy at startup.
  The Anthropic API endpoint is always permitted.
- Secrets (mounted as files under `/run/secrets/`, never env):
  - `anthropic_api_key`
  - `gh_token` — PAT with read access to org repos used by recon and
    asset-fetch
  - `atlassian_token` — only mounted when `external_mcp.atlassian` is
    enabled
  - AWS auth via instance profile / SSO short-lived creds — no static
    keys mounted
- **Assets mount** (whitebox surface): every path under `assets:` in
  the YAML is bind-mounted **read-only** under `/assets/<role>/...`
  inside the container. `redteam/assets.py` validates each path
  exists, indexes it (file count, language, top-level dirs), and
  exposes the index to the `whitebox` tool pack and the `whitebox`
  subagent. The agent cannot modify or exfiltrate these files outside
  what `egress_allowlist` permits.
- The container's audit volume is the only writable surface that
  survives the run. Operator collects it after exit.

This sits beneath the SDK's own bwrap/Seatbelt sandbox — defence in
depth, since the March 2026 evasion notes the OS-level sandbox is
defence layer 2, not layer 1.

### Asset fetch workflow (whitebox)

Operator workflow before `redteam run`:

```bash
# one-time per engagement, on the operator's workstation
gh auth login                                    # PAT or SSO
gh repo clone myorg/example-api ./targets/example-api
gh repo clone myorg/example-infra ./targets/example-infra
# update before re-running:
gh repo sync ./targets/example-api
```

The compose file bind-mounts `./targets/` read-only into the
container. The harness never invokes `gh clone`/`gh sync` on its own —
asset selection is an explicit operator action, version-pinned by
whatever the working tree contains at run time. (The `recon` pack's
`gh_search_code` etc. are **runtime** lookups against the live org
GitHub for things outside the pre-cloned set, not asset fetches.)

---

## Audit ledger (`redteam/ledger/`)

- Append-only JSONL at `/audit/<engagement_id>.jsonl`.
- Each entry: `{seq, ts, prev_hash, payload, payload_hash}`.
- Hash chain so any post-hoc edit invalidates downstream entries.
- On `SessionEnd`, an HMAC over the chain head is generated by **AWS
  KMS** (`kms:GenerateMac`, HMAC_SHA256) and written to
  `<engagement_id>.seal` alongside the KMS key ARN. Key material
  never leaves KMS.
- `redteam-verify <ledger> <seal>` is a standalone CLI (no SDK
  dependency) that calls `kms:VerifyMac`. Auditors run it with
  verify-only IAM, so they can confirm authenticity without ever
  having sign permission and without trusting the harness.

### Recommendations (decisions previously deferred)

- **Operator signature mechanism: SSH signatures via `ssh-keygen -Y
  sign`.** Operators already have SSH keys for GitHub auth, no new
  PKI is needed, and `ssh-keygen -Y verify` works offline. The list
  of authorised signers lives in `engagements/authorized_signers`
  (one `principal cert-authority? key` line per operator), checked
  into the repo and reviewed via PR. Rotating an operator out is a
  PR removing their line. We get crypto-strong attribution without
  the GPG keyring tax or a full sigstore/Fulcio rollout.

- **HMAC seal key custody: AWS KMS HMAC key.** Org is AWS-only, so
  KMS is the natural fit. Container assumes a workload role with
  `kms:GenerateMac` (and nothing else) on a single key ARN; the
  verifier role gets `kms:VerifyMac` only. Key material never
  touches the harness or the operator workstation, key usage is
  CloudTrail-logged for auditors, and revocation is "disable the
  key in KMS." If the org later wants HSM-backed keys, switch the
  KMS key origin to `EXTERNAL` or CloudHSM-backed without changing
  the harness.

---

## Observability

- SDK's built-in OpenTelemetry instrumentation is enabled via env vars
  in the container entrypoint.
- The compose file ships a **local OTel collector** as a sidecar.
  Exporter destination is configurable via env: by default it forwards
  to a local Grafana stack (Tempo / Loki / Mimir) included in the
  compose file for dev, or to the central org Grafana stack in
  production via OTLP/HTTP.
- Our `telemetry` hook adds three structured event types:
  `tool.invoked`, `tool.denied`, `finding.recorded`.
- Live operator UX is "watch the local Grafana board"; no bespoke
  dashboard in v1, only a checked-in starter dashboard JSON.

---

## Phased delivery

1. **Phase 1 — scaffold (week 1)**: pyproject, engagement schema
   (incl. SSH-signature verification + `external_mcp:` allowlist of
   `{atlassian}`), CLI, orchestrator wiring `ClaudeSDKClient` with one
   trivial tool pack (`recon`, DNS-only). Goal: `redteam run
   example.yaml` produces a transcript.
2. **Phase 2 — policy spine (week 2)**: scope_guard, audit_writer,
   ledger hash chain + KMS-backed seal + `redteam-verify`. Goal:
   out-of-scope tool calls denied; ledger verifies after a run.
3. **Phase 3 — runtime hardening (week 3)**: Dockerfile (with `gh`,
   `awscli`, semgrep et al.), docker-compose, netpolicy, secret
   mounting, asset-fetch docs. Goal: a run inside the container can
   only reach allowlisted hosts.
4. **Phase 4 — modules + subagents (week 4)**: web, cloud (AWS-only),
   network, whitebox packs; Atlassian MCP wiring + Jira upsert in
   `report`; recon/analyst/whitebox/exploiter subagents. Goal:
   end-to-end run on a staging target produces a SARIF report and a
   matching Jira ticket per finding.
5. **Phase 5 — observability polish (week 5)**: local OTel collector +
   Grafana stack compose service, exporter env wiring for central
   stack, starter dashboard JSON, redactor refinement, runbook docs.

**Out of scope for v1**: pause/resume of long engagements, GCP/Azure
cloud packs, GitHub MCP, additional third-party MCP providers,
sigstore/Fulcio signing.

---

## Verification

End-to-end test plan once Phase 2 is in:

1. **Schema** — `pytest tests/test_engagement_schema.py` covers happy
   path + each rejection case (missing operator, bad CIDR, etc.).
2. **Scope guard unit** — `pytest tests/test_scope_guard.py` feeds
   crafted tool inputs and asserts deny decisions.
3. **Ledger chain** — `pytest tests/test_ledger_chain.py` writes
   entries, mutates one, asserts `verify.py` flags it.
4. **Container egress** — run the container with an engagement that
   allowlists only `example.com`; have the agent attempt a request to
   `evil.example.net`; assert iptables drop + scope_guard deny + ledger
   entry of type `tool.denied`.
5. **Assets read-only** — `pytest tests/test_assets_mount.py` confirms
   each `assets:` path mounts read-only, indexing populates correctly,
   and a write attempt from the `whitebox` pack fails.
6. **Engagement signature** — sign an engagement with an authorized
   SSH key and a non-authorized one; assert the second is rejected
   with a clear error before any session starts.
7. **External MCP allowlist** — declare `external_mcp: [{name: burp,
   ...}]` in YAML; assert pydantic rejects at parse time. Then enable
   `atlassian` with `mcp.atlassian.com` *not* in `egress_allowlist`;
   assert the connection is dropped and ledger records
   `mcp.external.unreachable`.
8. **Jira upsert idempotency** — run the same engagement twice;
   assert the second run updates (not duplicates) the existing
   tickets via the deterministic external key.
9. **Whitebox + blackbox crossover** — engagement with `assets:`
   pointing at a small repo containing a known endpoint absent from
   the OpenAPI spec; assert the agent surfaces the discrepancy and
   the `web` pack is then invoked against that endpoint.
10. **Live engagement (dogfood)** — run `engagements/example.yaml`
    against a deliberately-vulnerable staging target (e.g., a local
    OWASP juice-shop instance) with its source repo cloned via `gh`
    into `./targets/`. Confirm: agent finishes within budget,
    findings appear in SARIF, Jira tickets created (if Atlassian
    enabled), ledger seals via KMS, Grafana shows complete trace.
11. **Audit replay** — give the sealed ledger to a teammate with
    `kms:VerifyMac`-only IAM; they run `redteam-verify <ledger>
    <seal>` and inspect entries without ever running the harness or
    holding sign permission.

---

## Critical files to be created

- `redteam/orchestrator.py` — SDK client setup, hook registration.
- `redteam/engagement.py` — YAML schema with SSH-signature verification
  and `external_mcp:` allowlist of `{atlassian}`.
- `redteam/hooks/scope_guard.py` — gate enforcing target / egress
  allowlists for first-party and Atlassian MCP tool calls.
- `redteam/hooks/audit_writer.py` + `redteam/ledger/chain.py` +
  `redteam/ledger/kms_seal.py` — hash-chained ledger with KMS HMAC seal.
- `redteam/ledger/verify.py` — standalone `redteam-verify` CLI using
  `kms:VerifyMac`.
- `redteam/assets.py` — read-only mount + indexing of pre-cloned
  source / IaC / specs.
- `redteam/mcp_external.py` — adapter for the Atlassian Rovo MCP entry.
- `redteam/tools/recon.py` — DNS/whois/CT + `gh` CLI wrappers.
- `redteam/tools/cloud.py` — AWS-only read-only enumeration.
- `redteam/tools/whitebox.py` — bridge between the assets mount and the
  agent (semgrep, tfsec, checkov, openapi_diff, etc.).
- `redteam/tools/report.py` — SARIF writer + idempotent Jira upsert
  via Atlassian MCP.
- `redteam/runtime/Dockerfile` — image with `gh`, `awscli`, semgrep,
  tfsec, checkov, kube-linter.
- `redteam/runtime/docker-compose.yml` — harness + OTel collector + dev
  Grafana stack.
- `redteam/runtime/entrypoint.sh` + `netpolicy.json` — blast-radius
  boundary.
- `engagements/example.yaml` + `engagements/authorized_signers` — the
  canonical engagement template and the SSH signer allowlist.
