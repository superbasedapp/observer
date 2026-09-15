import { test, expect, type Page } from "@playwright/test";

// SessionDetailPanel tab state — regression pin for the "tab flips back to
// Overview" defect (2026-08-28).
//
// THE DEFECT. The panel's active tab lived in the route's `?tab=` query param,
// for EVERY host. But `?tab=` is a single slot per route, and each list page
// (Sessions / Live / Actions / Cache) keeps a SessionDetailPanel mounted at all
// times with `open={selected != null}` plus a cleanup effect that deletes
// `?tab=` whenever that panel is closed. The terminal workspace's session modal
// (LaunchDock → TerminalSessionModal → SessionDetailPanel) is a SECOND panel
// that floats over whatever page the operator is on. Clicking Messages there
// wrote `?tab=messages`; the page's own closed panel deleted it on the next
// commit; the modal's tab derived straight back to Overview. Measured before
// the fix, `?tab=messages` placed on a bare URL survived indefinitely on "/"
// (no panel in the tree) and was stripped within 0.4-3s on /sessions, /live,
// /actions and /cache.
//
// THE FIX. Only the panel a route ADDRESSES (`?session=`) owns `?tab=`; the
// terminal modal passes urlTabState={false} and keeps its tab in local state.
// The cleanup effect is gated on the same flag, so a non-owning instance can
// never delete a param another panel wrote.
//
// WHAT THIS PIN COVERS. The route-owning half, end to end on the real Sessions
// page: the chosen tab survives poll ticks, `?tab=` is still cleaned up on
// close, and the URL slot is still route-owned (a stray `?tab=` with no panel
// open is cleared). The terminal-modal half is NOT driven here, but no longer
// because the cockpit harness is broken: session-cockpit.spec.ts was repaired
// on 2026-08-29 (its SessionDetail fixture omitted the REQUIRED `resume` block,
// so ResumeButton threw on `resume.kind` and, with no error boundary above the
// panel, React unwound the whole root about a second after the modal opened)
// and now runs 12/12. It stays there rather than moving here because that spec
// owns the dock/terminal harness. NOTE THE TARGETS DIFFER: this spec drives a
// REAL session id and needs a live daemon, while session-cockpit.spec.ts mocks
// every endpoint and needs an ISOLATED instance — pointed at a busy daemon its
// modal never mounts, because a dozen slow /api queries saturate the browser's
// six-connections-per-origin limit and the lazy chunk fetch simply queues.

test.use({ viewport: { width: 1360, height: 940 } });

// The panel reads a dozen per-session endpoints (detail, messages, predict,
// resume, processes, cache …) and several of its blocks assume a REAL row, so
// this spec drives a real session id from the daemon rather than a fabricated
// one: a stubbed detail with unstubbed siblings crashes the subtree on the
// first missing field, which pins nothing. Nothing here asserts on the
// session's content — only on which tab is selected.
async function suppressTour(page: Page): Promise<void> {
  await page.addInitScript(() => {
    try {
      localStorage.setItem("sb_tour_completed", "1"); // suppress first-run tour
    } catch {
      /* private mode — ignore */
    }
  });
}

async function firstSessionId(request: {
  get: (u: string) => Promise<{ json: () => Promise<unknown> }>;
}): Promise<string> {
  const res = await request.get("/api/sessions?limit=1&page=1");
  const body = (await res.json()) as { rows?: Array<{ id: string }> };
  const id = body.rows?.[0]?.id;
  if (!id) throw new Error("no captured session to open the detail panel for");
  return id;
}

function tab(page: Page, name: string) {
  return page.getByRole("tab", { name: new RegExp(`^${name}`) });
}

test("the chosen tab survives the panel's refresh polls", async ({ page, request }) => {
  const id = await firstSessionId(request);
  await suppressTour(page);
  await page.goto(`/sessions?session=${id}`, { waitUntil: "domcontentloaded" });
  await expect(tab(page, "Overview")).toBeVisible({ timeout: 30000 });

  await tab(page, "Messages").click();
  await expect(tab(page, "Messages")).toHaveAttribute("aria-selected", "true");

  // Hold across several render + poll ticks. The detail rollup and the message
  // stream both poll at 8s; the defect reverted within one commit, but a slow
  // revert has to fail here too.
  await page.waitForTimeout(9000);
  await expect(tab(page, "Messages")).toHaveAttribute("aria-selected", "true");
  await expect(tab(page, "Overview")).toHaveAttribute("aria-selected", "false");

  // A second switch sticks too (Cache mounts its own 5s-polling card).
  await tab(page, "Cache").click();
  await page.waitForTimeout(6000);
  await expect(tab(page, "Cache")).toHaveAttribute("aria-selected", "true");
});

test("the route-addressed panel still deep-links and cleans up its tab", async ({
  page,
  request,
}) => {
  const id = await firstSessionId(request);
  await suppressTour(page);
  // Deep link straight to a tab: the URL is the source of truth for the panel
  // the route addresses, so ?tab= must win over the derived default.
  await page.goto(`/sessions?session=${id}&tab=cache`, { waitUntil: "domcontentloaded" });
  await expect(tab(page, "Cache")).toHaveAttribute("aria-selected", "true", { timeout: 30000 });

  await tab(page, "Messages").click();
  await expect(page).toHaveURL(/[?&]tab=messages/);

  // Closing drops ?tab=, so the next session opened lands on Overview rather
  // than silently inheriting this one's tab.
  await page.getByRole("button", { name: "Close", exact: true }).click();
  await expect(page).not.toHaveURL(/[?&]tab=/, { timeout: 15000 });
});

// The ownership rule the fix rests on: `?tab=` belongs to the route's own
// panel. With no panel open the list page clears it — which is exactly why a
// panel that is NOT route-addressable (the terminal modal) must keep its tab
// out of the URL. "/" has no SessionDetailPanel in its tree and leaves the
// param alone; that contrast is what localised the defect.
test("a stray tab param is route-owned, not global", async ({ page }) => {
  await suppressTour(page);

  await page.goto("/sessions?tab=messages", { waitUntil: "domcontentloaded" });
  await expect(page).not.toHaveURL(/[?&]tab=/, { timeout: 15000 });

  await page.goto("/?tab=messages", { waitUntil: "domcontentloaded" });
  await page.waitForTimeout(4000);
  await expect(page).toHaveURL(/[?&]tab=messages/);
});
