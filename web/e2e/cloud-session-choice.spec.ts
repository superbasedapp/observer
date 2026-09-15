import { expect, test, type Page } from "@playwright/test";

// Every API call is intercepted; no account, consent or real quota is used.
async function openSessions(page: Page, options: { automatic?: boolean; state?: string; excluded?: boolean; previousResult?: boolean } = {}) {
  const fixture = { state: options.state ?? "idle", syncRunning: false, syncOK: true, nextState: "sent", failStatus: false, holdStatus: false, mutations: [] as { path: string; body: unknown }[] };
  await page.addInitScript(() => localStorage.setItem("sb_tour_completed", "1"));
  const updatedAt = new Date(Date.now() - 120000).toISOString();
  const progress = () => ({ state: fixture.state, updated_at: updatedAt, last_error: fixture.state === "failed_retryable" ? "http_429" : undefined });
  const result = () => fixture.state === "complete" || options.previousResult ? { received_at: "2026-09-14T10:05:00Z", result: { title: "Checkout layout fixed", taxonomy_tags: ["frontend"] } } : null;
  await page.route("**/api/**", async (route) => {
    const req = route.request();
    const path = new URL(req.url()).pathname;
    if (req.method() === "POST") fixture.mutations.push({ path, body: req.postDataJSON() });
    let json: unknown;
    switch (path) {
      case "/api/sessions": json = { rows: [{
        id: "chosen", title: "Fix checkout layout", tool: "codex", project: "/demo/shop",
        started_at: "2026-09-10T12:00:00Z", duration_seconds: 90, total_actions: 3,
        sidechain_action_count: 0, input_tokens: 40, output_tokens: 20,
        cache_read_tokens: 0, cache_creation_tokens: 0, cache_creation_1h_tokens: 0,
        total_tokens: 60, cost_usd: 0, ai_cost_usd: 0, tool_cost_usd: 0, models: [],
        cloud_enrichment: progress(), cloud_enriched: !!result(),
      }], total: 1, page: 1, limit: 50, scored_count: 0 }; break;
      case "/api/cloud/status": json = {
        active: true, receipts_total: 0, receipts_live: 0, outbox_by_state: {}, outbox_total: 0,
        sendable_count: 0, results_total: 0, has_synced: false, allowance_known: false,
        sign_in: { known: true, signed_in: true, api_token_present: true, actions_available: true },
        policy: options.automatic ? { level: "titles", background: true, since: "2026-09-01T00:00:00Z" } : null,
        plan: { name: "free", label: "Signed-in Free", daily_cap: 5, monthly_cap: 100 },
        provider_state: "unknown", last_sync: null,
      }; break;
      case "/api/cloud/events": json = { results: [], now: "2026-09-14T00:00:00Z" }; break;
      case "/api/cloud/session/chosen":
        if (fixture.failStatus) return route.fulfill({ status: 503, json: { error: "status temporarily unavailable" } });
        while (fixture.holdStatus) await new Promise((resolve) => setTimeout(resolve, 50));
        json = {
        session_id: "chosen", authority: options.excluded ? "org" : "personal", eligible: !options.excluded, excluded: !!options.excluded,
        excluded_reason: options.excluded ? "Organization-owned session" : "", receipts: [],
        progress: progress(), result: result(),
        outbox: fixture.state === "idle" ? [] : [{ id: "queued", state: fixture.state === "complete" ? "sent" : fixture.state, retry_count: 0, receipt_id: "receipt", updated_at: "2026-09-14T10:00:00Z" }],
      }; break;
      case "/api/cloud/preview": json = { ok: true, output: "Preview for chosen session", upload_digest: "fixture-digest", truncated: false }; break;
      case "/api/cloud/consent": fixture.state = "pending"; json = { ok: true, output: "Consent recorded" }; break;
      case "/api/cloud/sync": if (fixture.state !== "sent") fixture.state = "sending"; json = { session_id: "chosen", running: true }; break;
      case "/api/cloud/sync/state":
        if (!fixture.syncRunning) fixture.state = fixture.nextState;
        json = { session_id: "chosen", running: fixture.syncRunning, ok: fixture.syncOK, tail: fixture.syncOK ? "Outbox: 1 sent" : "Upload needs retry" }; break;
      default: return route.fulfill({ status: 503, json: { error: "not mocked" } });
    }
    await route.fulfill({ json });
  });
  await page.goto("/sessions");
  return fixture;
}

const panel = (page: Page) => page.getByRole("region", { name: "Session enrichment progress" });
const progressMessage = (page: Page, message: string) => panel(page).getByRole("status").getByText(message, { exact: true });

for (const width of [1280, 390]) {
  test(`manual flow stays disabled through upload and awaiting-result at ${width}px`, async ({ page }, testInfo) => {
    await page.setViewportSize({ width, height: 900 });
    const f = await openSessions(page);
    f.syncRunning = true;
    await page.getByRole("button", { name: "Enrich session", exact: true }).click();
    expect(f.mutations).toEqual([]);
    await expect(page.getByRole("button", { name: "Confirm and enrich", exact: true })).toBeDisabled();
    await page.getByRole("button", { name: "Preview session", exact: true }).click();
    await expect(page.getByText("Preview for chosen session", { exact: true })).toBeVisible();
    await page.getByRole("button", { name: "Confirm and enrich", exact: true }).click();
    await expect(progressMessage(page, "Uploading session")).toBeVisible();
    await expect(panel(page).getByRole("button", { name: "Uploading session", exact: true })).toBeDisabled();
    expect(f.mutations.filter((m) => m.path === "/api/cloud/consent")).toHaveLength(1);
    expect(f.mutations.find((m) => m.path === "/api/cloud/consent")?.body).toEqual({ session_id: "chosen", purpose: "structural_activity_insights", expected_upload_digest: "fixture-digest" });
    await expect.poll(() => f.mutations.find((m) => m.path === "/api/cloud/sync")?.body).toEqual({ session_id: "chosen" });
    f.syncRunning = false;
    await expect(progressMessage(page, "Awaiting enrichment result")).toBeVisible({ timeout: 15000 });
    await expect(panel(page).getByRole("button", { name: "Awaiting enrichment result", exact: true })).toBeDisabled();
    await expect(page.getByRole("button", { name: "Check for result", exact: true })).toBeEnabled();
    expect((await panel(page).boundingBox())?.y).toBeLessThan(150);
    await page.screenshot({ path: testInfo.outputPath(`awaiting-${width}.png`), fullPage: true });
    await page.reload();
    await page.getByRole("button", { name: "Awaiting result · view status", exact: true }).click();
    await expect(progressMessage(page, "Awaiting enrichment result")).toBeVisible();
    expect(f.mutations.filter((m) => m.path === "/api/cloud/consent")).toHaveLength(1);
    f.state = "complete";
    await expect(progressMessage(page, "Enrichment ready")).toBeVisible({ timeout: 15000 });
    await expect(page.getByRole("button", { name: "Re-enrich this session", exact: true })).toBeEnabled();
    await expect(page.getByText("Checkout layout fixed", { exact: true })).toBeVisible();
  });
}

test("quick enrichment disables all submission paths immediately", async ({ page }) => {
  const f = await openSessions(page, { automatic: true });
  f.syncRunning = true;
  await page.getByRole("button", { name: "Enrich session", exact: true }).click();
  await page.getByRole("button", { name: "Enrich now", exact: true }).click();
  await expect(progressMessage(page, "Uploading session")).toBeVisible();
  await expect(page.getByRole("button", { name: "Enrich now", exact: true })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Confirm and enrich", exact: true })).toHaveCount(0);
  expect(f.mutations.filter((m) => m.path === "/api/cloud/consent")).toHaveLength(1);
  f.syncRunning = false;
});

for (const [state, rowLabel, label] of [
  ["pending", "Queued · view status", "Queued for enrichment"],
  ["sending", "Uploading · view status", "Uploading session"],
  ["sent", "Awaiting result · view status", "Awaiting enrichment result"],
]) {
  test(`existing ${state} request survives panel open without resubmission`, async ({ page }) => {
    const f = await openSessions(page, { automatic: true, state });
    await page.getByRole("button", { name: rowLabel, exact: true }).click();
    await expect(progressMessage(page, label)).toBeVisible();
    await expect(panel(page).getByRole("button", { name: label, exact: true })).toBeDisabled();
    await expect(page.getByRole("button", { name: "Enrich now", exact: true })).toHaveCount(0);
    expect(f.mutations).toEqual([]);
  });
}

test("retry sends the saved request without another consent", async ({ page }) => {
  const f = await openSessions(page, { automatic: true, state: "failed_retryable" });
  await page.getByRole("button", { name: "Retry needed · view status", exact: true }).click();
  await expect(progressMessage(page, "Waiting for allowance or capacity")).toBeVisible();
  await page.getByRole("button", { name: "Retry upload", exact: true }).click();
  await expect(progressMessage(page, "Awaiting enrichment result")).toBeVisible({ timeout: 15000 });
  expect(f.mutations.map((m) => m.path)).toEqual(["/api/cloud/sync"]);
});

test("review requires a fresh preview even with an enabled policy", async ({ page }) => {
  const f = await openSessions(page, { automatic: true, state: "reconfirmation_required" });
  await page.getByRole("button", { name: "Review enrichment", exact: true }).click();
  await expect(progressMessage(page, "Review needed")).toBeVisible();
  await expect(page.getByRole("button", { name: "Enrich now", exact: true })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Confirm and enrich", exact: true })).toBeDisabled();
  await page.getByRole("button", { name: "Preview session", exact: true }).click();
  await expect(page.getByRole("button", { name: "Confirm and enrich", exact: true })).toBeEnabled();
  expect(f.mutations.map((m) => m.path)).toEqual(["/api/cloud/preview"]);
});

test("a previous result does not hide a pending re-enrichment", async ({ page }) => {
  await openSessions(page, { automatic: true, state: "sent", previousResult: true });
  await page.getByRole("button", { name: "Awaiting result · view status", exact: true }).click();
  await expect(progressMessage(page, "Awaiting enrichment result")).toBeVisible();
  await expect(page.getByText("Previous enrichment — the new request is shown above.")).toBeVisible();
  await expect(page.getByRole("button", { name: "Re-enrich this session", exact: true })).toHaveCount(0);
});

test("excluded sessions offer no upload action", async ({ page }) => {
  const f = await openSessions(page, { excluded: true });
  await page.getByRole("button", { name: "Enrich session", exact: true }).click();
  await expect(page.getByText("Excluded from personal cloud enrichment:", { exact: false })).toBeVisible();
  await expect(page.getByRole("button", { name: "Preview session", exact: true })).toHaveCount(0);
  expect(f.mutations).toEqual([]);
});

test("a failed upload keeps the saved request and exposes retry", async ({ page }) => {
  const f = await openSessions(page, { automatic: true });
  f.syncOK = false; f.nextState = "failed_retryable";
  await page.getByRole("button", { name: "Enrich session", exact: true }).click();
  await page.getByRole("button", { name: "Enrich now", exact: true }).click();
  await expect(panel(page).getByRole("alert")).toBeVisible();
  await expect(progressMessage(page, "Waiting for allowance or capacity")).toBeVisible();
  await expect(page.getByRole("button", { name: "Retry upload", exact: true })).toBeEnabled();
  await expect(page.getByRole("button", { name: "Enrich now", exact: true })).toHaveCount(0);
  expect(f.mutations.filter((m) => m.path === "/api/cloud/consent")).toHaveLength(1);
});

test("unknown progress blocks submission and offers status refresh", async ({ page }) => {
  const f = await openSessions(page, { automatic: true, state: "unknown" });
  await page.getByRole("button", { name: "View enrichment status", exact: true }).click();
  await expect(page.getByRole("button", { name: "Status unavailable", exact: true })).toBeDisabled();
  await expect(page.getByRole("button", { name: "Refresh status", exact: true })).toBeEnabled();
  await expect(page.getByRole("button", { name: "Enrich now", exact: true })).toHaveCount(0);
  expect(f.mutations).toEqual([]);
});

test("starting a refresh cannot re-enable submission after a failed status read", async ({ page }) => {
  const f = await openSessions(page, { automatic: true });
  await page.getByRole("button", { name: "Enrich session", exact: true }).click();
  await expect(page.getByRole("button", { name: "Enrich now", exact: true })).toBeEnabled();
  f.failStatus = true;
  await expect(panel(page).getByRole("alert")).toBeVisible({ timeout: 10000 });
  await expect(page.getByRole("button", { name: "Enrich now", exact: true })).toHaveCount(0);
  f.failStatus = false; f.holdStatus = true;
  try {
    await page.getByRole("button", { name: "Refresh status", exact: true }).click();
    await expect(panel(page).getByRole("alert")).toBeVisible();
    await expect(page.getByRole("button", { name: "Enrich now", exact: true })).toHaveCount(0);
  } finally { f.holdStatus = false; }
  await expect(page.getByRole("button", { name: "Enrich now", exact: true })).toBeEnabled({ timeout: 10000 });
  expect(f.mutations).toEqual([]);
});
