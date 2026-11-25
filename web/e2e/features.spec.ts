import { test, expect } from "@playwright/test";

// Visual + interaction verification for the three follow-up features:
// restart button (Settings → Health), draggable terminal dock, remote
// add-device / rotate-warning. Drives the demo dashboard (BASE_URL).
test.use({ viewport: { width: 1280, height: 900 } });

test("Settings → Health shows a Restart daemon button", async ({ page }) => {
  await page.goto("/settings", { waitUntil: "domcontentloaded" });
  // The section-nav button's accessible name carries a badge (e.g. "Health
  // SOFT"), so match loosely. click() waits for the button to render.
  await page.getByRole("button", { name: /Health/ }).first().click();
  await page.waitForTimeout(600);
  await expect(
    page.getByRole("button", { name: /Restart daemon/i }),
  ).toBeVisible();
  await page.screenshot({ path: "e2e/shots/features/health-restart.png", fullPage: true });
});

test("Remote page shows Add a device + Rotate secret", async ({ page }) => {
  await page.goto("/remote", { waitUntil: "domcontentloaded" });
  await page.waitForTimeout(800);
  await expect(page.getByRole("button", { name: /Add a device/i })).toBeVisible();
  await expect(page.getByRole("button", { name: /Rotate secret/i })).toBeVisible();
  await page.screenshot({ path: "e2e/shots/features/remote-actions.png", fullPage: true });
});

test("terminal dock grip drags and persists", async ({ page }) => {
  await page.goto("/", { waitUntil: "domcontentloaded" });
  await page.waitForTimeout(600);
  const grip = page.getByRole("button", { name: /Drag to move the terminal dock/i });
  await expect(grip).toBeVisible();
  const before = await grip.boundingBox();
  if (!before) throw new Error("grip has no box");
  // Drag the grip up-left by ~200px.
  await page.mouse.move(before.x + before.width / 2, before.y + before.height / 2);
  await page.mouse.down();
  await page.mouse.move(before.x - 200, before.y - 200, { steps: 8 });
  await page.mouse.up();
  await expect.poll(() => page.evaluate(() => localStorage.getItem("sb_dock_pos"))).toBeTruthy();
  const stored = await page.evaluate(() => localStorage.getItem("sb_dock_pos"));
  expect(stored).toBeTruthy();
  const pos = JSON.parse(stored as string);
  expect(pos.dx).toBeLessThan(0);
  expect(pos.dy).toBeLessThan(0);
  await page.screenshot({ path: "e2e/shots/features/dock-moved.png" });
  // Reload → position persists (grip is left of its original spot).
  await page.reload({ waitUntil: "domcontentloaded" });
  await expect
    .poll(async () => (await grip.boundingBox())?.x ?? Number.POSITIVE_INFINITY)
    .toBeLessThan(before.x);
});
