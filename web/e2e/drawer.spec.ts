import { test, expect } from "@playwright/test";

// Nav-drawer interaction check at a phone viewport: hamburger opens the
// slide-in Sidebar, backdrop tap closes it, a nav tap navigates + closes,
// and the shell never scrolls sideways in any state.
test.use({ viewport: { width: 390, height: 844 } });

async function docOverflow(page: import("@playwright/test").Page) {
  return page.evaluate(
    () =>
      document.documentElement.scrollWidth -
      document.documentElement.clientWidth,
  );
}

test("mobile nav drawer opens, closes on backdrop, navigates on tap", async ({
  page,
}) => {
  await page.goto("/", { waitUntil: "domcontentloaded" });
  await page.waitForTimeout(800);

  // Closed: no shell horizontal scroll.
  expect(await docOverflow(page)).toBeLessThanOrEqual(1);

  // Sidebar off-canvas when closed (translated out).
  const aside = page.locator("aside").first();

  // Open via hamburger (aria-label on the menu button).
  await page.getByRole("button", { name: /open navigation|menu/i }).click();
  await page.waitForTimeout(400);
  await page.screenshot({ path: "e2e/shots/drawer/open.png" });
  await expect(aside).toBeInViewport();
  // Still no sideways shell scroll with the drawer open.
  expect(await docOverflow(page)).toBeLessThanOrEqual(1);

  // Backdrop closes it. Click the right side (x=360) — the drawer covers
  // the left ~220px, so the backdrop's center would be intercepted by it.
  await page.mouse.click(360, 400);
  await page.waitForTimeout(400);
  await expect(aside).not.toBeInViewport();
  await page.screenshot({ path: "e2e/shots/drawer/closed.png" });

  // Re-open and tap a nav item → navigates and closes.
  await page.getByRole("button", { name: /open navigation|menu/i }).click();
  // click() waits for the link to stop moving (the drawer's slide-in).
  // Nav links carry a count badge, so the accessible name is e.g.
  // "Sessions 8" — match loosely, scoped to the sidebar.
  await page.locator("aside").getByRole("link", { name: /Sessions/ }).click();
  await page.waitForTimeout(500);
  await expect(page).toHaveURL(/\/sessions$/);
  expect(await docOverflow(page)).toBeLessThanOrEqual(1);
  await page.screenshot({ path: "e2e/shots/drawer/after-nav.png" });
});
