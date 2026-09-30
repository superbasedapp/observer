# Guard compliance mapping — SOC 2 CC-series & NIST 800-53

This is the field-level mapping the §14.4 evidence pack references
(guard spec `docs/plans/guard-layer-implementation-spec-2026-06-10.md`).
It maps the guard layer's audit data and controls onto SOC 2 Trust
Services (Common Criteria) and NIST 800-53 rev. 5 AU-2 / AU-3 / AU-9 /
AC-6, and states plainly what the guard does **not** establish (the
§21 honesty rule: every claim traces to a spec section).

An assessor-facing package is produced locally, with no network calls:

| Command | Evidence produced |
|---|---|
| `observer guard report --period 2026-05 [--json]` | The assembled evidence pack: effective policy at period start/end, policy-change log, verdict statistics, audit-chain verification result, coverage matrix, active-approval exception register (§14.4) |
| `observer guard export --period 2026-05 --format jsonl\|cef` | The raw audit rows for the period, for SIEM ingestion or sampling (§11.4) |
| `observer guard verify-audit` | Chain verification with a gating exit code (§10.4) |
| `observer guard rules --effective` | The rule set in force on this node right now (§11.1) |

## SOC 2 — Common Criteria mapping

| Criterion | Guard control | Spec |
|---|---|---|
| CC6.1 — logical access controls restrict protected-resource access | Policy engine deny/ask on destructive, boundary and exfil actions in enforce mode; native-dialect compilation gives a second, daemon-independent enforcement plane | §4–§6, §13.2 |
| CC6.8 — detection/prevention of unauthorized software | MCP server inventory + pinning + rug-pull detection (R-301/302/303/305); poisoning heuristics; on-demand registry reputation (opt-in) | §9, §15.3 |
| CC7.1 — monitoring for configuration changes | Native-config drift detection (R-204), hook-integrity and bundle-signature posture rows (R-205), MCP config re-scan on change | §13.2, §14.2 |
| CC7.2 — anomaly monitoring | Verdict event stream over every evaluable agent action; budget breach rules (B-601/602); stuck-loop anomaly (A-610, flag-only by design) | §7, §12 |
| CC7.3 — evaluation of security events | Severity grading (info/warn/high/critical) on every verdict; desktop + webhook alerting thresholds; optional LLM-judge review (opt-in, advisory-only) | §3.4, §15.2, §15.4 |
| CC8.1 — change management | guard_policy_state append-only version log (who/when/what per policy load); Ed25519-signed org policy bundles with monotonic versions and a strictness-floor merge | §10.1, §14.2 |

## NIST 800-53 rev. 5 mapping

### AU-2 — Event logging

Logged event types (one `guard_events` row per verdict worth
recording, across hook, watcher and proxy channels — §10.1): rule
verdicts by category (destructive / boundary / exfil / posture / mcp /
taint / budget / anomaly / injection), enforcement outcomes and
degradations (approvals), guard internal errors (`guard_error` rows,
fail-open visibility per Q2), cloud-feature calls (`source` field,
§15), and policy-source loads (`guard_policy_state`).

### AU-3 — Content of audit records

Field-level mapping of one `guard_events` row (visible verbatim in
`observer guard export --format jsonl`):

| AU-3 element | guard_events field(s) |
|---|---|
| What type of event | `event_kind`, `rule_id`, `category` |
| When it occurred | `ts` (event time, UTC) |
| Where it occurred | `tool`, `session_id`, anchors `action_id` / `api_turn_id` |
| Source of the event | `source` (builtin / user / project / org / llm_judge), `tool` |
| Outcome | `decision`, `enforced`, `degraded_from` |
| Subject/object identity | `target_hash` (always), `target_excerpt` / `reason` / `taint_origin` (bounded excerpts, node-local; stripped from org push unless the node opts into full content — §10.2) |

### AU-9 — Protection of audit information

Each row carries a SHA-256 hash chained over the previous row's hash
plus the row's canonical bytes (§10.4). `observer guard verify-audit`
walks every link and reports the first divergence; retention pruning
writes a checkpoint so verification re-anchors after a prune (§10.3).

**Honest scope (spec F4):** this is tamper-EVIDENT, not tamper-proof.
It catches silent row edits and mid-chain deletions by anything that
does not deliberately re-chain; an attacker with write access to the
SQLite file could recompute the whole chain. Where AU-9 requires
stronger guarantees, ship the export stream to an external
write-once store on a schedule (`guard export` is designed for
exactly this) — the org push pipeline (§14.3) provides an off-node
copy of the hash-graded rows as well.

### AC-6 — Least privilege

- Enforce mode denies/asks on actions outside the policy envelope;
  observe mode records the same verdicts without blocking (D2 —
  fresh installs observe first, §4.1).
- `guard_approvals` is the reviewable exception register (§14.4):
  every grant records rule, scope (session / project / global),
  approver identity (`granted_by`, including `llm_judge` for the
  opt-in §15.2 path), and expiry. The evidence pack renders the
  active set; expired-but-recent grants are retained for review
  (§10.3).
- Org policy bundles are a one-way strictness floor: the org can
  escalate node verdicts, never relax them; node operators can
  tighten further (§4.6, §14.2).
- Org-server RBAC separates `policy_admin` (author/sign bundles)
  from `security_viewer` (read rollups) from members (§14.5).

## What the guard does NOT do

Read with §1.3's gap table (F1–F9). The load-bearing ones for an
assessment:

- **Coverage is per-channel, not absolute (F1/F2).** Only hook-capable
  clients with documented deny semantics can be blocked pre-execution;
  most adapters are watcher-channel post-hoc flagging. The §6.5
  coverage matrix in the evidence pack states per-client capability —
  present it alongside any enforcement claim.
- **Tool-call blocking and prompt-submit blocking are TWO separate
  levers (2026-09-22 control-coverage investigation).** A tool whose
  §6.5 bucket is `sandbox_enforce`/`recorded_acceptance` (no blocking
  hook on an already-decided tool CALL) can still carry a real, wired,
  vendor-verified prompt-submit block/ask channel
  (`internal/guard.ConformanceMatrix()`) that stops the developer's
  PROMPT before it reaches the model at all — Poolside is the sharpest
  example: `recorded_acceptance` on the call, `block_ask` on the
  prompt. `internal/controlcoverage` is the ONE join of both
  classifications plus the budget-admission channel and route proof;
  it drives `observer adapters`'s PROMPT column, `observer doctor
  <tool>`'s control-coverage line, and the org dashboard Security
  page's "Control coverage" table (`GET /api/org/guard/coverage`,
  AUDITED per-developer, admin/policy_admin/security_viewer/lead-scoped
  — the same guard-role gate as the rest of this page). Before this,
  `internal/orgserver/recordedaccept` (Settings) was the ONLY org-side
  consumer of the tool-call classification, and only for its 16
  no-lever rows; an admin reading a Cursor-only or goose-only
  developer's row had no fleet-wide way to see which of the four
  levers — tool-call / prompt-submit / budget / route-proof — actually
  apply.
- **The audit chain proves integrity, not completeness.** An agent
  whose capture channel was disabled produces no rows; posture rules
  (hook-integrity, yolo flags) flag known-degraded states but cannot
  prove absence of gaps.
- **Node-local data is operator-readable.** The DB belongs to the
  developer (D2 single-operator posture); the chain makes edits
  evident, not impossible.

These statements are positioning, not disclaimers: the evidence pack
is credible precisely because it documents its own boundaries.
