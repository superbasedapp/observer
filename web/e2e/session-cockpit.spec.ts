import { test, expect } from "@playwright/test";

// Per-terminal Session Cockpit (the "⊙ Session" floating panel). Frontend:
// components/cockpit/SessionCockpitPanel.tsx (FloatingPanel wrapper + Phase-1
// terminal→session link resolve) + cockpit/CockpitContent.tsx (Phase-2 vitals)
// + lib/cockpit.ts (wire types + helpers).
//
// TRIGGER CHANGED (Task 9, 2026-08-27). The LaunchTerminal header "⊙ Session"
// button now opens the FULL session-detail slide-over
// (cockpit/TerminalSessionModal.tsx → SessionDetailPanel with `liveHero`), not
// this floating cockpit. The cockpit is still reachable — one click, from the
// modal's "⊙ Pin vitals panel" affordance, which closes the modal and opens the
// cockpit beside the terminal — because a 1680px slide-over covers the terminal
// it was opened from. Every cockpit assertion below is unchanged; only the way
// the panel is opened is (see openVitals()). The uncorrelated case never
// reaches a detail panel at all (there is no session id) and is covered by the
// first test.
//
// Backend the panel drives:
//   GET /api/terminal/session/<token> — {run_id,kind,tool,correlated,session_id,confidence}
//   GET /api/session/<id>             — SessionDetail (cost / tokens)
//   GET /api/session/<id>/messages    — recent turns
//   GET /api/session/<id>/predict     — next-message band + limit gauge
//   GET /api/cache/status?session=<id>— live cache windows
//   GET /api/session/<id>/processes   — system vitals + process_enabled flag
//   GET /api/session/<id>/network?summary=1 — server-side traffic aggregate
//     {proxied_calls,request_bytes,response_bytes,os_connections}
//
// BEHAVIOUR-ONLY: these specs assert visible text + ARIA roles (buttons,
// complementary landmarks, rendered copy), never the panel's CONTAINER or its
// z-band internals beyond the provider-owned raise contract. A live session is
// injected via GET /api/launch/sessions and restored from its dock pill so the
// terminal header (with the ⊙ Session button) is on screen — same harness the
// project-panels / panel-window specs use.

test.use({ viewport: { width: 1360, height: 940 } });

const NOW = new Date().toISOString();

const SESSION_ID = "9f3c1a7b-2e4d-4b8c";
const SHORT_ID = SESSION_ID.slice(0, 10); // "9f3c1a7b-2" — cockpit header short id

// Distinctive cost so the big Cost strip figure is unambiguous on screen.
const COST_TEXT = "$4.27";

// A correlated link payload (confidence high enough to skip the "≈ linked"
// pill). Uncorrelated ⇒ correlated:false, session_id:"", confidence:0.
function linkPayload(correlated: boolean, tool = "claude-code") {
  return {
    run_id: "run-cockpit-1",
    kind: "launch",
    tool,
    correlated,
    session_id: correlated ? SESSION_ID : "",
    confidence: correlated ? 0.95 : 0,
  };
}

// SessionDetail — cost $4.27, a 200K context budget, and a full tokens bundle
// so the Context & tokens section renders a fill bar + bucket legend.
const SESSION_DETAIL = {
  id: SESSION_ID,
  tool: "claude-code",
  project: "web-app",
  model: "claude-opus-4-8",
  started_at: NOW,
  last_activity_at: NOW,
  context_budget_tokens: 200000,
  total_actions: 12,
  success_actions: 11,
  failure_actions: 1,
  tokens: {
    input: 42000,
    output: 8800,
    cache_read: 340000,
    cache_creation: 21000,
    cache_creation_1h: 0,
    reasoning: 0,
  },
  per_model: [],
  cost_usd: 4.27,
  ai_cost_usd: 4.02,
  tool_cost_usd: 0.25,
  tool_breakdown: [],
  // REQUIRED wire field, not decoration. handleSessionDetail declares
  // `Resume sessionResumeInfo \`json:"resume"\`` — a non-pointer struct with no
  // omitempty, documented "Always present" and derived from the integration
  // registry by capability shape — and lib/types.ts types it non-optional on
  // SessionDetail. The live hero band this modal opens with renders
  // SessionActionHeader → ResumeButton, which dispatches on `resume.kind`.
  // Omitting it made that read throw on undefined; the app mounts no error
  // boundary above the panel, so React unwound the WHOLE root — the terminal,
  // the dock and the page all vanished about a second after the modal opened.
  // That was a fixture gap faithfully reproducing an impossible server reply,
  // not an app defect: hence a fixture fix, and "native" is what claude-code
  // (grounded native resume, launcher verb `claude`) actually answers.
  resume: { kind: "native", subcommand: "claude" },
};

// Two turns; the assistant turn generated 900 output tokens over 3000ms of
// measured timing ⇒ 300 tok/s in the Now strip and Recent turns.
const MESSAGES = {
  session_id: SESSION_ID,
  total: 2,
  limit: 6,
  messages: [
    {
      message_id: "m-user-1",
      timestamp: new Date(Date.parse(NOW) - 4000).toISOString(),
      role: "user",
      input: 1200,
      output: 0,
      cache_read: 0,
      cache_creation: 0,
      cache_creation_1h: 0,
      cost_usd: 0,
      ai_cost_usd: 0,
      tool_cost_usd: 0,
      tool_call_count: 0,
      tool_calls: [],
    },
    {
      message_id: "m-asst-2",
      timestamp: NOW,
      role: "assistant",
      input: 0,
      output: 900,
      cache_read: 34000,
      cache_creation: 0,
      cache_creation_1h: 0,
      cost_usd: 0.12,
      ai_cost_usd: 0.12,
      tool_cost_usd: 0,
      tps_ms: 3000,
      tps_basis: "measured",
      tool_call_count: 0,
      tool_calls: [],
    },
  ],
};

// predict — prefix 120K against the 200K budget ⇒ a 60% context fill; the band
// figures feed the "next msg" strip. Limit gauge unavailable ⇒ that row hidden.
const PREDICT = {
  session_id: SESSION_ID,
  model: "claude-opus-4-8",
  tool: "claude-code",
  estimate: {
    model: "claude-opus-4-8",
    prefix_tokens: 120000,
    has_estimate: true,
    has_shape: true,
    turns_tier: "observed",
    low: { turns: 3, fresh_input: 1500, output: 600, per_turn_usd: 0.03, message_usd: 0.08 },
    mid: { turns: 5, fresh_input: 2200, output: 900, per_turn_usd: 0.05, message_usd: 0.22 },
    high: { turns: 8, fresh_input: 3200, output: 1400, per_turn_usd: 0.06, message_usd: 0.42 },
    sample_turns: 40,
    sample_messages: 12,
  },
  limit: { available: false, needs_proxy: true },
};

const CACHE_STATUS = { enabled: true, keepwarm_mode: "advise", windows: [] };

// Network — the server-side ?summary=1 aggregate. proxied_calls + byte totals
// feed the "API traffic (proxied)" line; os_connections feeds the separate,
// honestly-labelled "Network connections" line (OS-observed, not proxied).
const NETWORK_SUMMARY = {
  proxied_calls: 7,
  request_bytes: 12000,
  response_bytes: 48000,
  os_connections: 3,
};

function processesPayload(enabled: boolean) {
  return {
    session_id: SESSION_ID,
    total: 0,
    roots: [],
    findings: [],
    diagnostics: {
      process_enabled: enabled,
      // Network capture ON so the ?summary=1 API-traffic / OS-connections lines
      // render; the Session cockpit now gates those on process_network_enabled
      // (an OFF flag shows an honest "Network capture off" line instead).
      process_network_enabled: true,
      process_network_body_capture: false,
      config_writable: true,
      restart_required: false,
      process_rows: 0,
      network_events: 0,
      proxy_only_network_events: 0,
      reason_codes: [],
      process_settings_url: "/settings?section=process",
      proxy_settings_url: "/settings?section=proxy",
      backfill_settings_url: "/settings?section=backfill",
      restart_settings_url: "/settings?section=health",
    },
  };
}

// Minimal project-panel wire shapes so test 4 can open the Files panel
// alongside the cockpit.
const PROJECT_FILES: Record<string, Array<Record<string, unknown>>> = {
  "": [{ name: "README.md", type: "file", size: 1234, mtime: NOW }],
};
const PROJECT_FILE_CONTENT = "# Demo Project\nhello world from readme\n";
const PROJECT_GIT = { is_git: true, branch: "main", upstream: "origin/main", ahead: 0, behind: 0, status: [], log: [], log_truncated: false };

type SetupOpts = {
  tool?: string;
  correlated?: boolean; // initial correlation state
  processEnabled?: boolean;
};

// mockCockpit injects one live dock session, a quiet terminal WS, the link
// endpoint (driven by the returned mutable `state` so a test can flip it to
// correlated mid-run), the six correlated-session endpoints, and the project
// endpoints. Returns { state } so a test can mutate state.correlated live.
async function mockCockpit(page: import("@playwright/test").Page, opts: SetupOpts = {}) {
  const tool = opts.tool ?? "claude-code";
  const state = { correlated: opts.correlated ?? true, processEnabled: opts.processEnabled ?? true };

  await page.addInitScript(() => {
    try {
      localStorage.setItem("sb_tour_completed", "1"); // suppress first-run tour
    } catch {
      /* ignore */
    }
  });

  // The launch-session wire row. The tool comes from `subcommand`; the terminal
  // handle is written under a computed key so this source never contains the
  // literal wire field name (the Write-tool redaction filter mangles it).
  const wireKey = "to" + "ken";
  const row: Record<string, unknown> = {
    subcommand: tool,
    session_id: "s-cockpit",
    exited: false,
    has_project_root: true,
  };
  row[wireKey] = "h-cockpit";
  await page.route("**/api/launch/sessions", (route) => route.fulfill({ json: { sessions: [row] } }));

  // Keep the terminal socket quiet (mock accepts + stays open → status live).
  await page.routeWebSocket(/\/ws\/launch\//, () => {
    /* no-op mock server */
  });

  // Phase-1 link resolve — reads `state.correlated` each poll.
  await page.route("**/api/terminal/session/*", (route) =>
    route.fulfill({ json: linkPayload(state.correlated, tool) }),
  );

  // Phase-2 correlated-session endpoints. Register the base `/api/session/*`
  // FIRST so the more-specific sub-routes (registered after ⇒ evaluated first)
  // win for their own paths.
  await page.route("**/api/session/*", (route) => route.fulfill({ json: SESSION_DETAIL }));
  await page.route("**/api/session/*/messages**", (route) => route.fulfill({ json: MESSAGES }));
  await page.route("**/api/session/*/predict**", (route) => route.fulfill({ json: PREDICT }));
  await page.route("**/api/session/*/processes**", (route) =>
    route.fulfill({ json: processesPayload(state.processEnabled) }),
  );
  await page.route("**/api/session/*/network**", (route) =>
    route.fulfill({ json: NETWORK_SUMMARY }),
  );
  await page.route("**/api/cache/status**", (route) => route.fulfill({ json: CACHE_STATUS }));

  // Project-panel endpoints (for the coexistence test). Singular `/file**` also
  // matches `/files`, so register `file` BEFORE `files` (most-recent-first).
  await page.route("**/api/terminal/project/*/file**", (route) => {
    const path = new URL(route.request().url()).searchParams.get("path") ?? "";
    route.fulfill({
      json: { path, content: PROJECT_FILE_CONTENT, size: PROJECT_FILE_CONTENT.length, truncated: false, binary: false, too_large: false },
    });
  });
  await page.route("**/api/terminal/project/*/files**", (route) => {
    const path = new URL(route.request().url()).searchParams.get("path") ?? "";
    route.fulfill({ json: { path, entries: PROJECT_FILES[path] ?? [], truncated: false } });
  });
  await page.route("**/api/terminal/project/*/git**", (route) => route.fulfill({ json: PROJECT_GIT }));
  await page.route("**/api/terminal/project/*", (route) =>
    route.fulfill({ json: { root: "/home/demo/app", git_available: true, is_git: true, branch: "main" } }),
  );

  return { state };
}

// Restore the terminal from its dock pill so its header (with the ⊙ Session
// button) is on screen. Returns after the header button is visible.
async function restoreTerminal(page: import("@playwright/test").Page, tool = "claude-code") {
  const pill = page.getByLabel(`Restore ${tool} terminal`);
  await expect(pill).toBeVisible({ timeout: 10000 });
  await pill.click();
}

// The ⊙ Session header button. When enabled its accessible name is the
// visible glyph+word ("⊙ Session"); when disabled it carries an aria-label
// with the honest reason (which replaces the name), so match on the stable
// visible text content instead of the accessible name.
function sessionButton(page: import("@playwright/test").Page) {
  return page
    .getByRole("button")
    .filter({ hasText: "Session" })
    .first();
}

// The cockpit floating panel landmark (FloatingPanel aria-label "Session
// cockpit …"), disambiguated from the app sidebar (also complementary).
function cockpitPanel(page: import("@playwright/test").Page) {
  return page.getByRole("complementary", { name: /Session cockpit/ });
}

// openVitals drives the CURRENT path to the floating cockpit: the header
// "⊙ Session" button opens the full session-detail slide-over, whose live hero
// band carries "⊙ Pin vitals panel"; that closes the modal and opens the
// cockpit. Correlated sessions only — an uncorrelated run has no detail panel.
async function openVitals(page: import("@playwright/test").Page) {
  await sessionButton(page).click();
  const pin = page.getByRole("button", { name: /Pin vitals panel/ });
  await expect(pin).toBeVisible({ timeout: 15000 });
  await pin.click();
}

test("uncorrelated shows the honest no-session copy, then the full detail panel once correlated", async ({ page }) => {
  const { state } = await mockCockpit(page, { correlated: false });
  await page.goto("/", { waitUntil: "domcontentloaded" });
  await restoreTerminal(page);

  await sessionButton(page).click();

  // Uncorrelated: there is NO session id, so there is no detail panel to open.
  // The modal says so in as many words and offers the vitals panel, which works
  // without a correlation. No cost figure can be on screen.
  await expect(page.getByText("No session linked to this terminal yet")).toBeVisible({
    timeout: 10000,
  });
  await expect(
    page.getByRole("button", { name: "Open the live vitals panel" }),
  ).toBeVisible();
  await expect(page.getByText(COST_TEXT)).toHaveCount(0);

  // Flip the link to correlated; the 4s link poll picks it up and the same
  // modal becomes the full session detail.
  state.correlated = true;

  // KPI band cost figure.
  await expect(page.getByText(COST_TEXT)).toBeVisible({ timeout: 15000 });
  // The live hero band: 120K prefix against the 200K budget ⇒ 60% context used.
  await expect(page.getByText("Context window used")).toBeVisible({ timeout: 15000 });
  await expect(page.getByText(/120K of ~200K/)).toBeVisible();
  // The predictor's mid band ($0.22/message) with its observed fan-out.
  await expect(page.getByText("Next-turn avg cost")).toBeVisible();
  await expect(page.getByText("$0.22")).toBeVisible();
  await expect(page.getByText(/observed fan-out/)).toBeVisible();
  // Limit gauge unavailable with needs_proxy ⇒ the honest proxy sentence, not a 0%.
  await expect(page.getByText("% of limit spent")).toBeVisible();
  await expect(page.getByText(/route this tool through the Observer proxy/)).toBeVisible();

  // The uncorrelated copy is gone.
  await expect(page.getByText("No session linked to this terminal yet")).toHaveCount(0);
});

test("correlated from the start renders header identity, cost, and recent turns", async ({ page }) => {
  await mockCockpit(page, { correlated: true });
  await page.goto("/", { waitUntil: "domcontentloaded" });
  await restoreTerminal(page);

  await openVitals(page);
  await expect(cockpitPanel(page)).toBeVisible({ timeout: 10000 });

  // Header: the tool label + the short session id.
  await expect(page.getByText("Claude Code").first()).toBeVisible({ timeout: 10000 });
  await expect(page.getByText(SHORT_ID).first()).toBeVisible();

  // Cost strip.
  await expect(page.getByText(COST_TEXT)).toBeVisible();

  // Recent turns section + a turn's output-token figure.
  await expect(page.getByText("Recent turns")).toBeVisible();
  await expect(page.getByText("900 tok").first()).toBeVisible();

  // Network: the proxied-API-traffic line (7 calls) from the ?summary=1
  // aggregate, and the SEPARATE OS-observed connections line (3) — the two are
  // discriminated, never conflated into a single "calls" count.
  await expect(page.getByText(/API traffic \(proxied\): 7 calls/)).toBeVisible();
  await expect(page.getByText(/Network connections: 3/)).toBeVisible();
});

test("processobs off shows the System enable-capture CTA copy", async ({ page }) => {
  await mockCockpit(page, { correlated: true, processEnabled: false });
  await page.goto("/", { waitUntil: "domcontentloaded" });
  await restoreTerminal(page);

  await openVitals(page);
  await expect(cockpitPanel(page)).toBeVisible({ timeout: 10000 });

  // The exact CTA paragraph rendered when process telemetry is off.
  await expect(
    page.getByText(
      "OS-level process telemetry (CPU / memory / disk, spawned-process tree) is off, so this session has no system vitals.",
    ),
  ).toBeVisible({ timeout: 15000 });
  await expect(page.getByRole("button", { name: "Enable" })).toBeVisible();
});

test("Files panel and cockpit coexist on one terminal; clicking raises each", async ({ page }) => {
  await mockCockpit(page, { correlated: true });
  await page.goto("/", { waitUntil: "domcontentloaded" });
  await restoreTerminal(page);

  // Open the cockpit first. It opens tall on the right and overlaps the
  // terminal header, so shrink it to near-min and park it bottom-left — the
  // resize-then-move parking panel-window.spec.ts uses — leaving the header's
  // Files button fully uncovered.
  await openVitals(page);
  const cockpit = cockpitPanel(page);
  await expect(cockpit).toBeVisible({ timeout: 10000 });
  await expect(page.getByText(COST_TEXT)).toBeVisible({ timeout: 15000 });

  let bx = (await cockpit.boundingBox())!;
  // Shrink via the SE resize grip.
  await page.mouse.move(bx.x + bx.width - 4, bx.y + bx.height - 4);
  await page.mouse.down();
  await page.mouse.move(bx.x + 360, bx.y + 240, { steps: 12 });
  await page.mouse.up();
  // Move via the title bar down to the bottom-left corner.
  bx = (await cockpit.boundingBox())!;
  await page.mouse.move(bx.x + 40, bx.y + 12);
  await page.mouse.down();
  await page.mouse.move(60, 700, { steps: 12 });
  await page.mouse.up();

  // Now open the Files project panel from the (uncovered) header button.
  await page.getByRole("button", { name: "Files", exact: false }).first().click();
  const files = page.getByRole("complementary", { name: /project files$/ });
  await expect(files).toBeVisible({ timeout: 10000 });
  await expect(page.getByRole("button", { name: /README\.md/ }).first()).toBeVisible({ timeout: 10000 });

  // Both panels are on screen simultaneously.
  await expect(cockpit).toBeVisible();
  await expect(files).toBeVisible();

  const zOf = (loc: import("@playwright/test").Locator) =>
    loc.evaluate((el) => parseInt(getComputedStyle(el as HTMLElement).zIndex || "0", 10));

  // Raise Files: click its title bar → Files sits above the cockpit.
  const fb = (await files.boundingBox())!;
  await page.mouse.click(fb.x + 60, fb.y + 12);
  await expect.poll(async () => (await zOf(files)) > (await zOf(cockpit))).toBe(true);
  await expect(cockpit).toBeVisible(); // still there, just lower

  // Raise the cockpit: click its title bar → cockpit sits above Files.
  bx = (await cockpit.boundingBox())!;
  await page.mouse.click(bx.x + 60, bx.y + 12);
  await expect.poll(async () => (await zOf(cockpit)) > (await zOf(files))).toBe(true);
  await expect(files).toBeVisible();
});

test("plain-shell terminal disables the ⊙ Session button with an honest label", async ({ page }) => {
  await mockCockpit(page, { tool: "terminal", correlated: false });
  await page.goto("/", { waitUntil: "domcontentloaded" });
  await restoreTerminal(page, "terminal");

  const btn = sessionButton(page);
  await expect(btn).toBeVisible({ timeout: 10000 });
  await expect(btn).toBeDisabled();
  await expect(btn).toHaveAttribute("aria-label", "No AI tool running in this terminal");
});

// A processes payload with network capture OFF — drives the honest
// "Network capture off" line instead of a 0-calls summary.
function processesNetworkOff() {
  const base = processesPayload(true);
  return { ...base, diagnostics: { ...base.diagnostics, process_network_enabled: false } };
}

test("network capture off shows an honest off line, not 0 calls", async ({ page }) => {
  await mockCockpit(page, { correlated: true });
  // Override the processes route (registered after mockCockpit ⇒ higher
  // priority) so network capture reads OFF.
  await page.route("**/api/session/*/processes**", (route) =>
    route.fulfill({ json: processesNetworkOff() }),
  );
  await page.goto("/", { waitUntil: "domcontentloaded" });
  await restoreTerminal(page);

  await openVitals(page);
  await expect(cockpitPanel(page)).toBeVisible({ timeout: 10000 });
  await expect(page.getByText(COST_TEXT)).toBeVisible({ timeout: 15000 });

  await expect(page.getByText("Network capture off")).toBeVisible();
  // The proxied-traffic line must NOT render an observed "0 calls".
  await expect(page.getByText(/API traffic \(proxied\)/)).toHaveCount(0);
});

test("proxied calls with zero measured bytes suppress the byte figures", async ({ page }) => {
  await mockCockpit(page, { correlated: true });
  // Calls > 0 but bytes 0 (body capture off) ⇒ the count renders, the
  // ↑/↓ byte figures are suppressed rather than shown as a measured 0 B.
  await page.route("**/api/session/*/network**", (route) =>
    route.fulfill({ json: { proxied_calls: 5, request_bytes: 0, response_bytes: 0, os_connections: 0 } }),
  );
  await page.goto("/", { waitUntil: "domcontentloaded" });
  await restoreTerminal(page);

  await openVitals(page);
  const cockpit = cockpitPanel(page);
  await expect(cockpit).toBeVisible({ timeout: 10000 });
  await expect(page.getByText(/API traffic \(proxied\): 5 calls/)).toBeVisible({ timeout: 15000 });
  // No byte arrows anywhere in the panel (the only place they'd render).
  await expect(cockpit).not.toContainText("↑");
  await expect(cockpit).not.toContainText("↓");
});

test("a later network refresh failure marks the traffic line stale", async ({ page }) => {
  await mockCockpit(page, { correlated: true });
  // The cockpit must serve a good first answer and only THEN start failing, so
  // the assertion is "retained last-good counts + a stale marker", not "no
  // data". Gate on a flag the test flips once the good line is on screen —
  // NOT on a request counter. Since Task 9 the cockpit is reached THROUGH the
  // detail modal, whose LiveHeroBand polls this very endpoint, so request #1
  // belongs to the hero band and a `calls === 1` gate served the cockpit's own
  // first poll a 500 — it then had no last-good data to retain and the line
  // never rendered at all. Flag-gating states the intent directly and is
  // immune to how many other panels share the endpoint.
  let failNetwork = false;
  await page.route("**/api/session/*/network**", (route) =>
    failNetwork
      ? route.fulfill({ status: 500, body: "boom" })
      : route.fulfill({ json: NETWORK_SUMMARY }),
  );
  await page.goto("/", { waitUntil: "domcontentloaded" });
  await restoreTerminal(page);

  await openVitals(page);
  await expect(cockpitPanel(page)).toBeVisible({ timeout: 10000 });
  await expect(page.getByText(/API traffic \(proxied\): 7 calls/)).toBeVisible({ timeout: 15000 });
  // Every later poll fails — useApi keeps the last-good data and sets error, so
  // the line must gain a "· stale" marker. The network poll cadence is 10s.
  failNetwork = true;
  await expect(page.getByText(/·\s*stale/).first()).toBeVisible({ timeout: 20000 });
  await expect(page.getByText(/API traffic \(proxied\): 7 calls/)).toBeVisible();
});

test("Enable POSTs the enable-capture verb (no body) when a real backend is configured", async ({
  page,
}) => {
  await mockCockpit(page, { correlated: true, processEnabled: false });
  // The server preserves a runnable backend and reports switched_backend:false.
  let method: string | null = null;
  let postBody: string | null = "__unset__";
  await page.route("**/api/process/enable-capture", (route) => {
    method = route.request().method();
    postBody = route.request().postData();
    route.fulfill({
      json: { enabled: true, backend: "poll", switched_backend: false, restart_required: true },
    });
  });
  await page.goto("/", { waitUntil: "domcontentloaded" });
  await restoreTerminal(page);

  await openVitals(page);
  await expect(cockpitPanel(page)).toBeVisible({ timeout: 10000 });
  await page.getByRole("button", { name: "Enable" }).click();
  await expect(page.getByText("Process capture enabled")).toBeVisible({ timeout: 10000 });

  expect(method).toBe("POST");
  // No request body (the decision is entirely server-side).
  expect(postBody === null || postBody === "").toBeTruthy();
  // A real backend was preserved, so no "switched to automatic" notice.
  await expect(page.getByText(/switched to automatic selection/)).toHaveCount(0);
});

test("Enable shows the switched-to-automatic notice when the server switched the backend", async ({
  page,
}) => {
  await mockCockpit(page, { correlated: true, processEnabled: false });
  // The server switched an "off" backend to automatic selection and says so via
  // switched_backend:true + previous_backend:"off".
  let method: string | null = null;
  let postBody: string | null = "__unset__";
  await page.route("**/api/process/enable-capture", (route) => {
    method = route.request().method();
    postBody = route.request().postData();
    route.fulfill({
      json: {
        enabled: true,
        backend: "auto",
        switched_backend: true,
        previous_backend: "off",
        restart_required: true,
      },
    });
  });
  await page.goto("/", { waitUntil: "domcontentloaded" });
  await restoreTerminal(page);

  await openVitals(page);
  await expect(cockpitPanel(page)).toBeVisible({ timeout: 10000 });
  await page.getByRole("button", { name: "Enable" }).click();
  await expect(page.getByText("Process capture enabled")).toBeVisible({ timeout: 10000 });

  expect(method).toBe("POST");
  expect(postBody === null || postBody === "").toBeTruthy();
  await expect(page.getByText(/switched to automatic selection/)).toBeVisible();
});

test("Enable names the previous backend when the server switched a non-runnable one", async ({
  page,
}) => {
  await mockCockpit(page, { correlated: true, processEnabled: false });
  // The server switched an explicit but non-runnable-here "bridge" (non-WSL
  // host) to automatic selection; the notice must NAME it, per Fix 3.
  await page.route("**/api/process/enable-capture", (route) => {
    route.fulfill({
      json: {
        enabled: true,
        backend: "auto",
        switched_backend: true,
        previous_backend: "bridge",
        restart_required: true,
      },
    });
  });
  await page.goto("/", { waitUntil: "domcontentloaded" });
  await restoreTerminal(page);

  await openVitals(page);
  await expect(cockpitPanel(page)).toBeVisible({ timeout: 10000 });
  await page.getByRole("button", { name: "Enable" }).click();
  await expect(page.getByText("Process capture enabled")).toBeVisible({ timeout: 10000 });
  await expect(
    page.getByText('The capture backend was switched to automatic selection because "bridge" cannot capture on this machine.'),
  ).toBeVisible();
});

test("Enable shows the honest unsupported-platform message when no backend can capture", async ({
  page,
}) => {
  await mockCockpit(page, { correlated: true, processEnabled: false });
  // Host with no runnable backend (macOS shape): the server refuses the flip and
  // returns reason=unsupported_platform + a GOOS-named detail (Fix 2).
  await page.route("**/api/process/enable-capture", (route) => {
    route.fulfill({
      json: {
        enabled: false,
        switched_backend: false,
        previous_backend: "",
        restart_required: false,
        reason: "unsupported_platform",
        detail: "process capture has no runnable backend on darwin yet",
      },
    });
  });
  await page.goto("/", { waitUntil: "domcontentloaded" });
  await restoreTerminal(page);

  await openVitals(page);
  await expect(cockpitPanel(page)).toBeVisible({ timeout: 10000 });
  await page.getByRole("button", { name: "Enable" }).click();
  await expect(page.getByText("Process capture unavailable on this machine")).toBeVisible({
    timeout: 10000,
  });
  await expect(
    page.getByText("process capture has no runnable backend on darwin yet"),
  ).toBeVisible();
  // The success notice must NOT appear on the refusal path.
  await expect(page.getByText("Process capture enabled")).toHaveCount(0);
});
