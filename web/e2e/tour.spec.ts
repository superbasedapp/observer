import { test, expect } from "@playwright/test";

// First-run guided tour (shipped 45379283). The tour is owned by
// <TourProvider> (src/components/tour/TourProvider.tsx): it auto-starts once
// per browser, ~600ms after load, when localStorage `sb_tour_completed` is
// absent AND the desktop rail is present (window.innerWidth >= 1024). The
// coach-mark bubble is a role="dialog" rendered by TourStepView; it anchors to
// nav elements carrying data-tour="nav-<id>" (Sidebar) and to the global
// filter (FilterBar data-tour="global-filter"). Finishing/skipping writes
// `sb_tour_completed = "1"`. Replay entry points: the Help drawer's "Take the
// product tour" button and the command palette's "Start product tour".
//
// Drives the demo dashboard (BASE_URL). Every test uses a FRESH context (no
// shared localStorage) so the auto-start gate is deterministic.
test.use({ viewport: { width: 1360, height: 940 } });

const STORAGE_KEY = "sb_tour_completed";

// The tour dialog is the coach-mark bubble. It always carries the progress
// counter "N / 10" and the primary Next/Finish control.
function tourDialog(page: import("@playwright/test").Page) {
  return page.getByRole("dialog").filter({ hasText: /\/\s*10/ });
}

test("auto-starts on a fresh context (no sb_tour_completed)", async ({ page }) => {
  await page.goto("/", { waitUntil: "domcontentloaded" });
  // Auto-start fires ~600ms after mount; the first step is the centered
  // "Welcome to superbased" card.
  await expect(page.getByText("Welcome to superbased")).toBeVisible({
    timeout: 5000,
  });
  const dlg = tourDialog(page);
  await expect(dlg).toBeVisible();
  // Progress starts at step 1 of 10.
  await expect(dlg.getByText("1 / 10")).toBeVisible();
  // Not yet persisted — the user hasn't finished or skipped.
  expect(await page.evaluate((k) => localStorage.getItem(k), STORAGE_KEY)).toBeNull();
});

test("Next advances steps and anchors coach-marks to visible nav elements", async ({
  page,
}) => {
  await page.goto("/", { waitUntil: "domcontentloaded" });
  const dlg = tourDialog(page);
  await expect(page.getByText("Welcome to superbased")).toBeVisible({
    timeout: 5000,
  });

  // Step 2 anchors to the Overview nav item and navigates to "/".
  await dlg.getByRole("button", { name: "Next" }).click();
  await expect(dlg.getByText("2 / 10")).toBeVisible();
  await expect(page.getByText("Overview — your home base")).toBeVisible();
  // The anchor the coach-mark points at is a real, visible element.
  await expect(page.locator('[data-tour="nav-overview"]')).toBeVisible();

  // Step 3 → Live: navigation follows the step's path, anchor is visible.
  await dlg.getByRole("button", { name: "Next" }).click();
  await expect(dlg.getByText("3 / 10")).toBeVisible();
  await expect(page.locator('[data-tour="nav-live"]')).toBeVisible();
  await expect(page).toHaveURL(/\/live$/);

  // Back returns to the previous step (Overview).
  await dlg.getByRole("button", { name: "Back" }).click();
  await expect(dlg.getByText("2 / 10")).toBeVisible();
  await expect(page.getByText("Overview — your home base")).toBeVisible();
});

test("Finish sets sb_tour_completed and no tour on reload", async ({ page }) => {
  await page.goto("/", { waitUntil: "domcontentloaded" });
  const dlg = tourDialog(page);
  await expect(page.getByText("Welcome to superbased")).toBeVisible({
    timeout: 5000,
  });

  // Walk to the last step: Next until the primary reads "Finish".
  const primary = dlg.getByRole("button", { name: /^(Next|Finish)$/ });
  for (let i = 0; i < 12; i++) {
    const label = (await primary.textContent())?.trim();
    if (label === "Finish") break;
    await primary.click();
  }
  await expect(dlg.getByText("10 / 10")).toBeVisible();
  await dlg.getByRole("button", { name: "Finish" }).click();

  // Dialog closes and the completion flag is persisted.
  await expect(tourDialog(page)).toHaveCount(0);
  await expect
    .poll(() => page.evaluate((k) => localStorage.getItem(k), STORAGE_KEY))
    .toBe("1");

  // Reload: the flag suppresses the auto-start. Give it well past the 600ms
  // auto-start delay, then assert the tour never appeared.
  await page.reload({ waitUntil: "domcontentloaded" });
  await page.waitForTimeout(1500);
  await expect(page.getByText("Welcome to superbased")).toHaveCount(0);
  await expect(tourDialog(page)).toHaveCount(0);
});

test("Skip tour persists completion (no re-auto-start)", async ({ page }) => {
  await page.goto("/", { waitUntil: "domcontentloaded" });
  const dlg = tourDialog(page);
  await expect(page.getByText("Welcome to superbased")).toBeVisible({
    timeout: 5000,
  });
  await dlg.getByRole("button", { name: "Skip tour" }).click();
  await expect(tourDialog(page)).toHaveCount(0);
  await expect
    .poll(() => page.evaluate((k) => localStorage.getItem(k), STORAGE_KEY))
    .toBe("1");
});

test("replay from the Help drawer relaunches the tour", async ({ page }) => {
  // Pre-mark completion so the tour does NOT auto-start — the only way it can
  // appear in this test is via the explicit replay entry point.
  await page.addInitScript((k) => {
    try {
      localStorage.setItem(k, "1");
    } catch {
      /* private mode — ignore */
    }
  }, STORAGE_KEY);
  await page.goto("/", { waitUntil: "domcontentloaded" });
  // Confirm no auto-start.
  await page.waitForTimeout(1200);
  await expect(tourDialog(page)).toHaveCount(0);

  // Open the Help drawer from the top-bar Help button, then click the replay
  // control. The Help button is wrapped with data-tour="topbar-help".
  await page.locator('[data-tour="topbar-help"] button').click();
  const replay = page.getByRole("button", { name: /Take the product tour/i });
  await expect(replay).toBeVisible({ timeout: 5000 });
  await replay.click();

  // The tour opens at step 1 even though completion was already recorded.
  await expect(page.getByText("Welcome to superbased")).toBeVisible({
    timeout: 5000,
  });
  await expect(tourDialog(page).getByText("1 / 10")).toBeVisible();
});
