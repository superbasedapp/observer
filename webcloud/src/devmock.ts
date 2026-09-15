// DEV-ONLY portal API mock.
//
// The authed pages fetch /portal/api/* and /portal/auth/*, which do not
// exist under a bare `vite` dev server, so with no mock every page renders
// its error/loading state. This module monkeypatches window.fetch for
// /portal/* paths so the redesign can be seen with representative data — it
// is imported by main.tsx ONLY behind `import.meta.env.DEV`, via a dynamic
// import, so it is tree-shaken out of the production build entirely. It
// never touches api.ts or consent.ts: the real data layer runs unchanged
// against these canned responses.
//
// Mode is read from localStorage key "sbci_devmock" so the orchestrator can
// flip states from the browser console and reload:
//
//   localStorage.setItem("sbci_devmock", "populated"); // default — full data
//   localStorage.setItem("sbci_devmock", "empty");     // empty states
//   localStorage.setItem("sbci_devmock", "signedout"); // the SignIn page
//   localStorage.setItem("sbci_devmock", "consent");   // the ConsentSetup screen
//
// then reload the page. The Billing page has two further states reachable
// via a `?billing=canceled` / `?billing=live` query flag — see the "Billing"
// section below.

type Mode = "populated" | "empty" | "signedout" | "consent";

function isMode(v: string | null): v is Mode {
  return (
    v === "populated" || v === "empty" || v === "signedout" || v === "consent"
  );
}

function mode(): Mode {
  // A ?mock=<mode> query param wins (handy for one-shot/headless captures);
  // otherwise the persisted localStorage choice; otherwise populated.
  try {
    const q = new URLSearchParams(window.location.search).get("mock");
    if (isMode(q)) return q;
  } catch {
    /* fall through */
  }
  try {
    const v = localStorage.getItem("sbci_devmock");
    if (isMode(v)) return v;
  } catch {
    /* fall through */
  }
  return "populated";
}

const SESSION = {
  account_id: "acct_dev_local",
  csrf_token: "dev-csrf-token",
  expires_at: new Date(Date.now() + 3600_000).toISOString(),
  auth_mode: "workos" as const,
  // The display identity the real server captures from the WorkOS sign-in, so
  // the top bar renders a name here the way it does in production.
  profile: {
    email: "dev@superbased.app",
    display_name: "Dev Developer",
  },
};

const CONSENT_PURPOSES = [
  { id: "structural_activity_insights", mandatory: true },
  { id: "bounded_context_enrichment", mandatory: false },
  { id: "community_cohort_benchmarking", mandatory: false },
];

const CONSENT_NOTICE =
  "These are portal-plane preferences for your signed-in account. They are " +
  "not what lets a device upload - that grant is made and withdrawn on the " +
  "device itself.";

function consentBody(m: Mode) {
  if (m === "consent") {
    return { choices: null, purposes: CONSENT_PURPOSES, notice: CONSENT_NOTICE };
  }
  return {
    choices: {
      structural_activity_insights: true,
      bounded_context_enrichment: true,
      community_cohort_benchmarking: true,
    },
    purposes: CONSENT_PURPOSES,
    updated_at: "2026-08-30T10:12:00Z",
    notice: CONSENT_NOTICE,
  };
}

function insightsBody(m: Mode) {
  const disclosure =
    "Structural insights are built from the account-day windows your devices " +
    "sync under your standing grant. Every card names the span it covers.";
  if (m === "empty") {
    return {
      window: { from: "", to: "", days: 30, devices: 0 },
      days: [],
      summary: {
        active_days: 0,
        session_count: 0,
        action_count: 0,
        tokens_in: 0,
        tokens_out: 0,
        cache_read_tokens: 0,
        cost_usd: 0,
        tool_mix: [],
        model_family_mix: [],
        sessions_with_outcomes: 0,
        sessions_with_verification: 0,
        verification_coverage_band: "none",
        outcome_evidence_band: "none",
        max_device_count: 0,
        first_day: "",
        last_day: "",
      },
      coverage: {
        devices: 0,
        snapshots: 0,
        first_day: "",
        last_day: "",
        days: 0,
      },
      enrichment: {
        jobs_by_state: {},
        jobs_total: 0,
        results_total: 0,
        last_result_at: null,
        disclosure:
          "Enrichment jobs run once you grant the bounded-excerpts purpose.",
      },
      structural_disclosure: disclosure,
    };
  }
  return {
    window: { from: "2026-08-25", to: "2026-08-31", days: 30, devices: 2 },
    days: [
      {
        period: "2026-08-29",
        device_count: 2,
        session_count: 14,
        action_count: 612,
        tokens_in: 840_000,
        tokens_out: 190_000,
        cache_read_tokens: 2_100_000,
        cost_usd: 3.41,
        tool_mix: [],
        model_family_mix: [],
        sessions_with_outcomes: 9,
        sessions_with_verification: 6,
        verification_coverage_band: "medium",
        outcome_evidence_band: "medium",
        computed_at: "2026-08-30T00:00:00Z",
      },
      {
        period: "2026-08-30",
        device_count: 2,
        session_count: 20,
        action_count: 903,
        tokens_in: 1_120_000,
        tokens_out: 260_000,
        cache_read_tokens: 3_050_000,
        cost_usd: 5.02,
        tool_mix: [],
        model_family_mix: [],
        sessions_with_outcomes: 15,
        sessions_with_verification: 11,
        verification_coverage_band: "high",
        outcome_evidence_band: "high",
        computed_at: "2026-08-31T00:00:00Z",
      },
    ],
    summary: {
      active_days: 6,
      session_count: 87,
      action_count: 3894,
      tokens_in: 5_240_000,
      tokens_out: 1_180_000,
      cache_read_tokens: 14_600_000,
      cost_usd: 21.87,
      tool_mix: [
        { key: "claude-code", count: 42 },
        { key: "codex", count: 21 },
        { key: "cursor", count: 14 },
        { key: "opencode", count: 7 },
        { key: "gemini", count: 3 },
      ],
      model_family_mix: [
        { key: "claude-opus", count: 38 },
        { key: "claude-sonnet", count: 29 },
        { key: "gpt-5", count: 15 },
        { key: "gemini-2.5", count: 5 },
      ],
      sessions_with_outcomes: 61,
      sessions_with_verification: 44,
      verification_coverage_band: "high",
      outcome_evidence_band: "medium",
      max_device_count: 2,
      first_day: "2026-08-25",
      last_day: "2026-08-31",
    },
    coverage: {
      devices: 2,
      snapshots: 6,
      first_day: "2026-08-25",
      last_day: "2026-08-31",
      days: 6,
    },
    enrichment: {
      jobs_by_state: { completed: 48, running: 2, queued: 1 },
      jobs_total: 51,
      results_total: 48,
      last_result_at: "2026-08-31T09:41:00Z",
      disclosure:
        "Enrichment jobs run on the bounded excerpts you granted; results are " +
        "session titles, tags and descriptions.",
    },
    structural_disclosure: disclosure,
  };
}

function usageBody(m: Mode) {
  if (m === "empty") {
    return {
      feature: "session_enrichment",
      plan: "free",
      plan_label: "Signed-in Free",
      plan_version: 1,
      budget_pool: "shared-free",
      plan_overridden: false,
      daily_used: 0,
      daily_cap: 5,
      monthly_used: 0,
      monthly_cap: 100,
      concurrency_used: 0,
      concurrency_cap: 2,
      warnings: [],
      jobs_by_state: {},
      jobs_total: 0,
      daily_resets_at: "2026-09-01T00:00:00Z",
      monthly_resets_at: "2026-10-01T00:00:00Z",
      concurrency_note:
        "At most 2 enrichment jobs run at once; the rest queue until a slot frees.",
    };
  }
  return {
    feature: "session_enrichment",
    plan: "free",
    plan_label: "Signed-in Free",
    plan_version: 1,
    budget_pool: "shared-free",
    plan_overridden: false,
    daily_used: 4,
    daily_cap: 5,
    monthly_used: 72,
    monthly_cap: 100,
    concurrency_used: 1,
    concurrency_cap: 2,
    warnings: [
      {
        window: "daily",
        level: "critical" as const,
        used: 4,
        cap: 5,
        used_fraction: 0.8,
      },
    ],
    jobs_by_state: { completed: 48, running: 1, queued: 1, failed: 2 },
    jobs_total: 52,
    daily_resets_at: "2026-09-01T00:00:00Z",
    monthly_resets_at: "2026-10-01T00:00:00Z",
    concurrency_note:
      "At most 2 enrichment jobs run at once; the rest queue until a slot frees.",
  };
}

// ---- Billing (W9 / R4, checkout-conflict + resubscribe follow-up) ---------
//
// Paddle is the merchant of record. `plan` reuses the usage-snapshot shape
// (usageBody-style) so the caps in force render regardless of tier. Following
// the file's populated/empty convention: `populated` shows a subscribed Plus
// account (exercises the rich subscription UI, incl. Paddle's hosted
// management links), `empty` shows the free-tier state (has_subscription
// false) with a purchasable checkout catalogue — the realistic default for
// most accounts, and the shape that exercises the Upgrade flow.
//
// `checkout` is present in every branch (GET /portal/api/billing always
// reports it, even for a subscribed account, since Paddle.js and the price
// catalogue also back the plan-change path later): one sandbox $15/mo price
// with a 7-day trial, matching the operator's Paddle configuration.
//
// Two more states are reachable via a `?billing=` query flag (independent of
// the populated/empty/signedout/consent `mode()` above, since they are
// Billing-page-specific and the review that added them wanted them
// exercisable without disturbing every other page's mock data):
//
//   ?billing=canceled  — a subscription whose status is "canceled" but whose
//                         current_period_end is still in the future, so the
//                         Billing page's "access continues until <date>"
//                         copy and the "Subscribe again" offer card are both
//                         reachable in `npm run dev`.
//   ?billing=live       — leaves GET /portal/api/billing alone but makes
//                         POST /portal/api/billing/checkout answer 409
//                         already_subscribed, the same honest response the
//                         real server now sends when a live (active/
//                         trialing/past_due/paused) row already exists —
//                         reachable from the free-plan Offer card without
//                         needing a real race between two tabs.
type BillingFlag = "default" | "canceled" | "live";

function billingFlag(): BillingFlag {
  try {
    const v = new URLSearchParams(window.location.search).get("billing");
    if (v === "canceled" || v === "live") return v;
  } catch {
    /* fall through */
  }
  return "default";
}
const MOCK_CHECKOUT = {
  available: true,
  environment: "sandbox",
  client_token: "test_dev_mock_client_token",
  prices: [
    {
      price_id: "pri_dev_mock_plus_monthly",
      plan_name: "Plus",
      plan_version: 1,
      interval: "month",
      display: "$15/mo",
    },
  ],
  trial_days: 7,
};

const FREE_PLAN = {
  feature: "session_enrichment",
  plan: "free",
  plan_label: "Signed-in Free",
  plan_version: 1,
  budget_pool: "shared-free",
  plan_overridden: false,
  daily_used: 0,
  daily_cap: 5,
  monthly_used: 0,
  monthly_cap: 100,
  concurrency_used: 0,
  concurrency_cap: 2,
  warnings: [],
  jobs_by_state: {},
  jobs_total: 0,
  daily_resets_at: "2026-09-03T00:00:00Z",
  monthly_resets_at: "2026-10-01T00:00:00Z",
  concurrency_note:
    "At most 2 enrichment jobs run at once; the rest queue until a slot frees.",
};

// PLUS_PLAN is the entitlement snapshot for an account with a live paid
// subscription. It also backs a canceled-but-not-yet-lapsed row (?billing=
// canceled): Paddle access, and therefore these caps, still hold until
// current_period_end even after the status flips to "canceled".
const PLUS_PLAN = {
  feature: "session_enrichment",
  plan: "plus",
  plan_label: "Plus",
  plan_version: 1,
  budget_pool: "plus",
  plan_overridden: false,
  daily_used: 6,
  daily_cap: 25,
  monthly_used: 118,
  monthly_cap: 500,
  concurrency_used: 1,
  concurrency_cap: 4,
  warnings: [],
  jobs_by_state: { completed: 112, running: 1, queued: 0, failed: 5 },
  jobs_total: 118,
  daily_resets_at: "2026-09-03T00:00:00Z",
  monthly_resets_at: "2026-10-01T00:00:00Z",
  concurrency_note:
    "At most 4 enrichment jobs run at once; the rest queue until a slot frees.",
};

function billingBody(m: Mode) {
  if (billingFlag() === "canceled") {
    // Status is "canceled" but current_period_end is 5 days out, and there
    // are deliberately no management_urls - Paddle's hosted "cancel" link
    // would be dead for an already-canceled subscription, so the Billing
    // page must not render ManagementLinks for this row at all.
    return {
      has_subscription: true,
      subscription: {
        subscription_id: "sub_01hz9k3m4n5p6q7r8s9t0u1v2w",
        customer_id: "ctm_01hz9k3m4n5p6q7r8s9t0u1v2w",
        plan_name: "Plus",
        plan_version: 1,
        status: "canceled" as const,
        current_period_end: new Date(
          Date.now() + 5 * 24 * 3600_000,
        ).toISOString(),
        canceled_at: new Date(Date.now() - 2 * 24 * 3600_000).toISOString(),
      },
      checkout: MOCK_CHECKOUT,
      plan: PLUS_PLAN,
    };
  }

  if (m === "empty") {
    return {
      has_subscription: false,
      plan: FREE_PLAN,
      checkout: MOCK_CHECKOUT,
    };
  }

  return {
    has_subscription: true,
    subscription: {
      subscription_id: "sub_01hz9k3m4n5p6q7r8s9t0u1v2w",
      customer_id: "ctm_01hz9k3m4n5p6q7r8s9t0u1v2w",
      plan_name: "Plus",
      plan_version: 1,
      status: "active" as const,
      current_period_end: "2026-09-30T00:00:00Z",
      management_urls: {
        update_payment_method:
          "https://sandbox-customer-portal.paddle.com/subscriptions/sub_01hz9k3m4n5p6q7r8s9t0u1v2w/update-payment-method",
        cancel:
          "https://sandbox-customer-portal.paddle.com/subscriptions/sub_01hz9k3m4n5p6q7r8s9t0u1v2w/cancel",
      },
    },
    checkout: MOCK_CHECKOUT,
    plan: PLUS_PLAN,
  };
}

// ---- Browser sessions ("sign out everywhere") ------------------------------
//
// A small stateful mock (module scope, resets on reload) so "Sign out
// everywhere" is demonstrably real in the preview: revoking removes every
// OTHER session immediately, and revoking without keep_current also clears
// the mock's own session (the SPA then treats itself as signed out on its
// next call, exactly like the real server clearing the cookie).
interface MockBrowserSession {
  id: string;
  created_at: string;
  last_seen_at?: string;
  expires_at: string;
  idle_expires_at?: string;
}

let MOCK_BROWSER_SESSIONS: MockBrowserSession[] | null = null;
const MOCK_CURRENT_SESSION_ID = "bsess_current";

function browserSessions(): MockBrowserSession[] {
  if (MOCK_BROWSER_SESSIONS === null) {
    MOCK_BROWSER_SESSIONS = [
      {
        id: MOCK_CURRENT_SESSION_ID,
        created_at: "2026-08-31T09:00:00Z",
        last_seen_at: new Date().toISOString(),
        expires_at: new Date(Date.now() + 24 * 3600_000).toISOString(),
        idle_expires_at: new Date(Date.now() + 2 * 3600_000).toISOString(),
      },
      {
        id: "bsess_other_phone",
        created_at: "2026-08-29T18:22:00Z",
        last_seen_at: "2026-08-31T07:41:00Z",
        expires_at: new Date(Date.now() + 20 * 3600_000).toISOString(),
        idle_expires_at: new Date(Date.now() + 3600_000).toISOString(),
      },
    ];
  }
  return MOCK_BROWSER_SESSIONS;
}

function browserSessionsListBody(m: Mode) {
  return {
    sessions: browserSessions().map((s) => ({
      ...s,
      is_current: m !== "empty" && s.id === MOCK_CURRENT_SESSION_ID,
    })),
  };
}

function revokeAllBrowserSessionsBody(keepCurrent: boolean) {
  const before = browserSessions().length;
  MOCK_BROWSER_SESSIONS = keepCurrent
    ? browserSessions().filter((s) => s.id === MOCK_CURRENT_SESSION_ID)
    : [];
  return { status: "revoked", revoked: before - MOCK_BROWSER_SESSIONS.length };
}

function devicesBody(m: Mode) {
  if (m === "empty") return { devices: [] };
  return {
    devices: [
      {
        id: "dev_01",
        thumbprint: "9f2a7c41b8e6d5330a1c4e77b2f9a0d1",
        label: "workstation-wsl",
        created_at: "2026-08-20T14:03:00Z",
        revoked: false,
      },
      {
        id: "dev_02",
        thumbprint: "3b1e88af04c7d29615ab77e0c9f4d2aa",
        label: "macbook-pro",
        created_at: "2026-08-24T09:18:00Z",
        revoked: false,
      },
    ],
  };
}

function grantsBody(m: Mode) {
  if (m === "empty") {
    return {
      grants: [],
      current_schema_version: "session-evidence.v1",
      current_data_dictionary: "sha256:abc…",
      retention_state: "none",
      retention_detail: "No snapshots are stored yet.",
      stored_snapshots: 0,
      stored_account_days: 0,
      contributing_device_count: 0,
    };
  }
  return {
    grants: [
      {
        purpose: "structural_activity_insights",
        field_classes: ["metadata", "counts", "outcomes"],
        schema_version: "session-evidence.v1",
        data_dictionary_digest: "sha256:9c1f4a2b7e0d5638aa4c",
        dictionary_current: true,
        consent_generation: 2,
        declared_timezone: "America/Los_Angeles",
        source_window_rule: "completed-local-day",
        first_seen_at: "2026-08-20T14:05:00Z",
        updated_at: "2026-08-30T10:12:00Z",
        revoked_at: "",
        state: "active",
      },
    ],
    current_schema_version: "session-evidence.v1",
    current_data_dictionary: "sha256:9c1f4a2b7e0d5638aa4c",
    retention_state: "rolling-90d",
    retention_detail:
      "Structural snapshots are retained for 90 days, then aged out. " +
      "Revoking a grant stops new uploads under it immediately.",
    stored_snapshots: 6,
    stored_account_days: 6,
    contributing_device_count: 2,
  };
}

function consentsBody(m: Mode) {
  if (m === "empty") return { purposes: [], generation: 0 };
  return {
    purposes: [
      "structural_activity_insights",
      "bounded_context_enrichment",
      "community_cohort_benchmarking",
    ],
    generation: 2,
  };
}

// ---- Sessions + corrections (W6c) -----------------------------------------
//
// A small STATEFUL mock so the edit flow is real in the preview: a correction
// POST validates the If-Match ETag, appends a revision, bumps the ETag, and
// replays on a repeated idempotency key — exactly the shape the server ships.
// State resets on reload (module scope), which is fine for a design preview.

interface MockRevision {
  revision_seq: number;
  editor: string;
  source: string;
  correction: Record<string, unknown>;
  created_at: string;
}
interface MockResult {
  result_id: string;
  created_at: string;
  ai_source: boolean;
  superseded: boolean;
  superseded_by?: string;
  correction_seq: number;
  tombstoned: boolean;
  result?: Record<string, unknown>;
  revisions: MockRevision[];
  // idempotency-key -> the response body already returned for that key.
  idem: Record<string, unknown>;
}
interface MockSession {
  cloud_session_id: string;
  tool: string;
  model_family: string;
  created_at: string;
  head_result_id: string;
  results: MockResult[];
}

function etagOf(r: MockResult): string {
  return r.result_id + "." + String(r.correction_seq);
}

// effectiveTitle mirrors the server: the latest user title correction, else the
// head AI title.
function effectiveTitle(sess: MockSession): string {
  const head = sess.results.find((r) => r.result_id === sess.head_result_id);
  if (!head) return "";
  let title = (head.result?.title as string) ?? "";
  for (const rev of head.revisions.slice().sort((a, b) => a.revision_seq - b.revision_seq)) {
    if (typeof rev.correction.title === "string") title = rev.correction.title;
  }
  return title;
}

function sessionEdited(sess: MockSession): boolean {
  return sess.results.some((r) => r.revisions.length > 0);
}

function makeSessions(): MockSession[] {
  return [
    {
      cloud_session_id: "sess_7f3a91c2",
      tool: "claude-code",
      model_family: "claude-opus",
      created_at: "2026-08-31T09:41:00Z",
      head_result_id: "res_a1",
      results: [
        {
          result_id: "res_a1",
          created_at: "2026-08-31T09:42:00Z",
          ai_source: true,
          superseded: false,
          correction_seq: 1,
          tombstoned: false,
          result: {
            title: "Refactor the token dedup path",
            taxonomy_tags: ["refactor", "tokens"],
            suggested_tags: ["dedup", "sqlite"],
            description:
              "Reworked the per-account token dedup allocator and its migration.",
            confidence: "medium",
            evidence_refs: [],
            limitations: ["No test run was observed in this window."],
            work_done: [
              "Reworked the per-account token dedup allocator so a fork no longer reuses a sibling's call id.",
              "Edited 14 Go files across the store and adapter packages and added one schema migration.",
            ],
            plans_implemented: [
              "The allocator rewrite the session opened with was carried through.",
              "The backfill pass the developer asked for later was started but not finished.",
            ],
            issues_found: [
              "Two sessions sharing a call id were collapsing into one token row.",
            ],
            failures: [
              "Six test runs finished with no recorded result, so the suite's outcome is unknown.",
            ],
            next_steps: [
              "Re-run the suite without piping it so the exit status is recorded.",
              "Finish the backfill pass over the already-stored token rows.",
            ],
            schema_version: "session-enrichment.v2",
          },
          revisions: [
            {
              revision_seq: 1,
              editor: "user",
              source: "portal",
              correction: { title: "Token dedup: per-account allocator + migration" },
              created_at: "2026-08-31T10:03:00Z",
            },
          ],
          idem: {},
        },
      ],
    },
    {
      cloud_session_id: "sess_2b8e04d6",
      tool: "codex",
      model_family: "gpt-5",
      created_at: "2026-08-30T16:12:00Z",
      head_result_id: "res_b1",
      results: [
        {
          result_id: "res_b1",
          created_at: "2026-08-30T16:40:00Z",
          ai_source: true,
          superseded: false,
          correction_seq: 0,
          tombstoned: false,
          result: {
            title: "Add the edge rate-limit counters",
            taxonomy_tags: ["feature", "security"],
            suggested_tags: ["rate-limit", "cloudflare"],
            description: "Shared Postgres fixed-window counters behind the edge.",
            confidence: "high",
            evidence_refs: [],
            limitations: [],
            work_done: [
              "Added shared fixed-window rate-limit counters and wired them into the edge worker.",
            ],
            plans_implemented: [
              "Every ask in the opening prompt landed; nothing was left open.",
            ],
            issues_found: [],
            failures: [],
            next_steps: [],
            schema_version: "session-enrichment.v2",
          },
          revisions: [],
          idem: {},
        },
        {
          result_id: "res_b0",
          created_at: "2026-08-30T16:20:00Z",
          ai_source: true,
          superseded: true,
          superseded_by: "res_b1",
          correction_seq: 0,
          tombstoned: false,
          result: {
            title: "Rate limits (first pass)",
            taxonomy_tags: ["feature"],
            suggested_tags: [],
            description: "An earlier enrichment, superseded by a regeneration.",
            confidence: "low",
            evidence_refs: [],
            limitations: [],
            schema_version: "session-enrichment.v2",
          },
          revisions: [],
          idem: {},
        },
      ],
    },
  ];
}

let MOCK_SESSIONS: MockSession[] | null = null;
function sessions(): MockSession[] {
  if (MOCK_SESSIONS === null) MOCK_SESSIONS = makeSessions();
  return MOCK_SESSIONS;
}

function findResult(resultID: string): MockResult | null {
  for (const s of sessions()) {
    for (const r of s.results) {
      if (r.result_id === resultID) return r;
    }
  }
  return null;
}

function sessionsListBody(m: Mode) {
  if (m === "empty") return { sessions: [], has_more: false };
  return {
    sessions: sessions().map((s) => ({
      cloud_session_id: s.cloud_session_id,
      tool: s.tool,
      model_family: s.model_family,
      created_at: s.created_at,
      result_count: s.results.length,
      edited: sessionEdited(s),
      effective_title: effectiveTitle(s),
      tombstoned: false,
    })),
    has_more: false,
  };
}

function sessionDetailBody(id: string): Response {
  const s = sessions().find((x) => x.cloud_session_id === id);
  if (!s) return json({ error: "no such session", code: "session_not_found" }, 404);
  return json({
    cloud_session_id: s.cloud_session_id,
    tool: s.tool,
    model_family: s.model_family,
    created_at: s.created_at,
    head_result_id: s.head_result_id,
    results: s.results.map((r) => ({
      result_id: r.result_id,
      created_at: r.created_at,
      ai_source: r.ai_source,
      superseded: r.superseded,
      superseded_by: r.superseded_by,
      etag: etagOf(r),
      tombstoned: r.tombstoned,
      result: r.tombstoned ? undefined : r.result,
      revisions: r.revisions,
    })),
  });
}

async function correctionResponse(
  resultID: string,
  init: RequestInit | undefined,
): Promise<Response> {
  const r = findResult(resultID);
  if (!r) return json({ error: "no such result", code: "result_not_found" }, 404);
  if (r.tombstoned)
    return json({ error: "tombstoned", code: "result_tombstoned" }, 410);

  const headers = new Headers(init?.headers);
  const ifMatch = (headers.get("If-Match") ?? "").trim();
  if (ifMatch === "")
    return json({ error: "missing If-Match", code: "missing_if_match" }, 428);
  const idem = (headers.get("Idempotency-Key") ?? "").trim();
  if (idem === "")
    return json({ error: "missing key", code: "missing_idempotency_key" }, 400);

  // Idempotency replay comes BEFORE the If-Match check, exactly like the store.
  if (r.idem[idem]) {
    return json(r.idem[idem], 200);
  }

  const dot = ifMatch.lastIndexOf(".");
  const seq = dot < 0 ? NaN : Number(ifMatch.slice(dot + 1));
  const etagResult = dot < 0 ? "" : ifMatch.slice(0, dot);
  if (etagResult !== resultID || Number.isNaN(seq))
    return json({ error: "bad ETag", code: "bad_if_match" }, 400);

  if (seq !== r.correction_seq) {
    // Hand back the CURRENT ETag so the client re-reads and retries.
    return new Response(
      JSON.stringify({ error: "the result changed", code: "etag_mismatch" }),
      {
        status: 412,
        headers: { "Content-Type": "application/json", ETag: etagOf(r) },
      },
    );
  }

  let body: Record<string, unknown> = {};
  try {
    body = JSON.parse((init?.body as string) ?? "{}");
  } catch {
    return json({ error: "bad JSON", code: "bad_request" }, 400);
  }
  const newSeq = r.correction_seq + 1;
  const revSeq =
    r.revisions.reduce((mx, x) => Math.max(mx, x.revision_seq), 0) + 1;
  r.revisions.push({
    revision_seq: revSeq,
    editor: "user",
    source: "portal",
    correction: body,
    created_at: new Date().toISOString(),
  });
  r.correction_seq = newSeq;
  const resp = {
    result_id: resultID,
    revision_seq: revSeq,
    etag: etagOf(r),
    replayed: false,
  };
  r.idem[idem] = resp;
  return new Response(JSON.stringify(resp), {
    status: 200,
    headers: { "Content-Type": "application/json", ETag: etagOf(r) },
  });
}

// ---- Community percentiles (W5 / R3) --------------------------------------
//
// A representative static response: a >=30 cohort with a few (k-suppressed)
// bands and the developer contributing. The metric/cohort selectors are driven
// by the catalog below, and the community handler reads the ?metric=/?cohort=
// query so switching selectors in the preview shows coherent data. `empty`
// mode returns an under-floor cohort (no bands) so the honest empty state is
// reachable.

const COMMUNITY_METRICS = [
  {
    id: "sessions_per_active_day",
    version: 1,
    label: "Sessions per active day",
    unit: "sessions/day",
    description:
      "How many distinct AI coding sessions you run on the days you are " +
      "active. Measured over completed local days in the window.",
    band_edges: [1, 2, 3, 5, 8, 13],
  },
  {
    id: "cache_read_ratio",
    version: 1,
    label: "Cache read ratio",
    unit: "%",
    description:
      "Share of your input tokens served from the provider prompt cache. " +
      "Higher means more of your context was reused rather than re-sent.",
    band_edges: [10, 25, 40, 55, 70, 85],
  },
];

const COMMUNITY_COHORTS = [
  {
    key: "global",
    label: "All developers",
    description: "Every developer who has opted in to community benchmarking.",
  },
  {
    key: "tool:claude-code",
    label: "Claude Code users",
    description:
      "Developers whose activity in the window was mostly Claude Code.",
  },
];

// A per-metric distribution. Band 0 is deliberately omitted from the first
// metric to show that suppressed cells are simply absent (not zero-filled).
const COMMUNITY_BANDS: Record<
  string,
  { cohort_size: number; bands: { band: number; count: number }[]; own_band: number; own_value: number }
> = {
  sessions_per_active_day: {
    cohort_size: 41,
    bands: [
      { band: 1, count: 8 },
      { band: 2, count: 14 },
      { band: 3, count: 22 },
      { band: 4, count: 17 },
      { band: 5, count: 9 },
      { band: 6, count: 4 },
    ],
    own_band: 3,
    own_value: 3.4,
  },
  cache_read_ratio: {
    cohort_size: 38,
    bands: [
      { band: 2, count: 6 },
      { band: 3, count: 15 },
      { band: 4, count: 19 },
      { band: 5, count: 12 },
      { band: 6, count: 7 },
    ],
    own_band: 5,
    own_value: 71,
  },
};

// The catalog is the same in every mode: even when a cohort is under-floor the
// selectors still render, and only the distribution comes back empty.
function communityMetricsBody() {
  return { metrics: COMMUNITY_METRICS, cohorts: COMMUNITY_COHORTS };
}

function communityBody(m: Mode, search: string) {
  const params = new URLSearchParams(search);
  const metricId = params.get("metric") ?? COMMUNITY_METRICS[0].id;
  const cohort = params.get("cohort") ?? "global";
  const metric =
    COMMUNITY_METRICS.find((x) => x.id === metricId) ?? COMMUNITY_METRICS[0];

  if (m === "empty") {
    return {
      cohort_key: cohort,
      metric_id: metric.id,
      metric_version: metric.version,
      metric_label: metric.label,
      metric_unit: metric.unit,
      window_id: "",
      cohort_size: 0,
      band_edges: metric.band_edges,
      bands: [],
      own: { contributed: false },
    };
  }

  const dist = COMMUNITY_BANDS[metric.id] ?? COMMUNITY_BANDS[COMMUNITY_METRICS[0].id];
  return {
    cohort_key: cohort,
    metric_id: metric.id,
    metric_version: metric.version,
    metric_label: metric.label,
    metric_unit: metric.unit,
    window_id: "2026-08",
    cohort_size: dist.cohort_size,
    band_edges: metric.band_edges,
    bands: dist.bands,
    own: {
      contributed: true,
      value: dist.own_value,
      band: dist.own_band,
    },
  };
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

async function route(
  path: string,
  method: string,
  init: RequestInit | undefined,
  search: string,
): Promise<Response | null> {
  const m = mode();

  // Community percentiles (W5). Exact metrics path before the base path.
  if (path === "/portal/api/community/metrics") {
    return json(communityMetricsBody());
  }
  if (path === "/portal/api/community") {
    return json(communityBody(m, search));
  }

  // Browser sessions ("sign out everywhere"). MUST come before the W6c
  // sessions block below: "/portal/api/sessions/browser" would otherwise be
  // swallowed by that block's startsWith("/portal/api/sessions/") detail
  // route and read as an unknown cloud-session id.
  if (path === "/portal/api/sessions/browser" && method === "GET") {
    return json(browserSessionsListBody(m));
  }
  if (path === "/portal/api/sessions/browser/revoke-all" && method === "POST") {
    let keepCurrent = false;
    try {
      const body = JSON.parse((init?.body as string) ?? "{}");
      keepCurrent = body.keep_current === true;
    } catch {
      // Treat an unparseable body like the default {} — revoke everything.
    }
    return json(revokeAllBrowserSessionsBody(keepCurrent));
  }

  // Sessions + corrections (W6c). Order matters: the exact list path before
  // the detail prefix.
  if (path === "/portal/api/sessions") return json(sessionsListBody(m));
  if (path.startsWith("/portal/api/sessions/")) {
    const id = decodeURIComponent(path.slice("/portal/api/sessions/".length));
    return sessionDetailBody(id);
  }
  if (
    path.startsWith("/portal/api/results/") &&
    path.endsWith("/correction") &&
    method === "POST"
  ) {
    const mid = path.slice(
      "/portal/api/results/".length,
      path.length - "/correction".length,
    );
    return correctionResponse(decodeURIComponent(mid), init);
  }

  if (path === "/portal/api/session") {
    return m === "signedout" ? json({ error: "not signed in" }, 401) : json(SESSION);
  }
  if (path === "/portal/api/auth-config") {
    return json({ auth_mode: "workos", workos_browser_enabled: true });
  }
  if (path === "/portal/auth/login" && method === "POST") {
    return json({
      account_id: SESSION.account_id,
      csrf_token: SESSION.csrf_token,
      expires_at: SESSION.expires_at,
      profile: SESSION.profile,
    });
  }
  if (path === "/portal/auth/logout") return new Response(null, { status: 204 });

  if (path === "/portal/api/consent") {
    return json(consentBody(m));
  }
  if (path === "/portal/api/insights") return json(insightsBody(m));
  if (path === "/portal/api/usage") return json(usageBody(m));
  if (path === "/portal/api/billing") return json(billingBody(m));
  if (path === "/portal/api/billing/checkout" && method === "POST") {
    if (billingFlag() === "live") {
      return json(
        {
          error: "you already have an active subscription",
          code: "already_subscribed",
        },
        409,
      );
    }
    return json({
      price_id: MOCK_CHECKOUT.prices[0]?.price_id ?? "pri_dev_mock_plus_monthly",
      expires_at: new Date(Date.now() + 30 * 60_000).toISOString(),
      custom_data: {
        account_id: SESSION.account_id,
        checkout_nonce: "nonce_dev_mock_" + Math.random().toString(36).slice(2),
      },
    });
  }
  if (path === "/portal/api/devices") return json(devicesBody(m));
  if (path.startsWith("/portal/api/devices/") && method === "DELETE") {
    return new Response(null, { status: 204 });
  }
  if (path === "/portal/api/grants") return json(grantsBody(m));
  if (path === "/portal/api/consents") return json(consentsBody(m));
  if (path === "/portal/api/deletion-requests" && method === "POST") {
    return json({
      id: "del_dev_01",
      state: "pending",
      jobs_canceled: 2,
      devices_revoked: 2,
      tokens_revoked: 3,
    });
  }

  return null;
}

/** installDevMock patches window.fetch to answer /portal/* requests with
 * sample data. No-op for non-portal URLs (which pass through to the real
 * fetch). Idempotent. */
export function installDevMock(): void {
  const real = window.fetch.bind(window);
  const patched = async (
    input: RequestInfo | URL,
    init?: RequestInit,
  ): Promise<Response> => {
    const url =
      typeof input === "string"
        ? input
        : input instanceof URL
          ? input.toString()
          : input.url;
    const method = (
      init?.method ??
      (input instanceof Request ? input.method : "GET")
    ).toUpperCase();
    // Compare on pathname only so query strings (?days=…) still match; the
    // raw search is passed alongside for handlers that vary on it (community).
    let path = url;
    let search = "";
    try {
      const u = new URL(url, window.location.origin);
      path = u.pathname;
      search = u.search;
    } catch {
      /* keep raw */
    }
    if (path.startsWith("/portal/")) {
      const res = await route(path, method, init, search);
      if (res) return res;
    }
    return real(input, init);
  };
  window.fetch = patched as typeof window.fetch;

  // A small fixed ribbon so it is obvious the data is mocked, plus the
  // current mode. DEV builds only.
  const el = document.createElement("div");
  el.className = "devmock-ribbon";
  el.textContent = "dev mock: " + mode();
  document.body.appendChild(el);

  // eslint-disable-next-line no-console
  console.info(
    "[devmock] portal API mocked. Set localStorage.sbci_devmock to " +
      '"populated" | "empty" | "signedout" | "consent" and reload.',
  );
}
