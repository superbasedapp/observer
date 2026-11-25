import { test, expect } from "@playwright/test";

// Verifies the clarified Remote-page language + that "Pair a device" actually
// reveals a QR (the "pair a device does nothing" fix). Runs against an ISOLATED
// temp-config dashboard (BASE_URL=:8093) so arming/pairing never touch the real
// remote secret.
test.use({ viewport: { width: 1280, height: 1000 } });

test("turn on remote access → Pair a device reveals a QR", async ({ page }) => {
  // The pairKnownUnreachable gate disables "Pair a device" whenever Tailscale
  // is absent / logged-out / serve-unconfigured — which is the clean-env
  // default here. Mock the status endpoint to a fully-reachable tailnet so the
  // pairing controls stay enabled; field names/shape match the TailscaleStatus
  // type in web/src/pages/Remote.tsx.
  await page.route("**/api/remote/tailscale/status", (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        present: true,
        logged_in: true,
        host: "test.tailnet.ts.net",
        state: "Running",
        install_url: "https://tailscale.com/download",
        daemon_runs_serve: false,
        armed: true,
        backend_addr: "127.0.0.1:8099",
        serve_command: "tailscale serve --bg 8099",
        serve_configured: true,
        serve_detectable: true,
      }),
    }),
  );

  // Suppress the first-run tour: its full-viewport overlay would otherwise
  // intercept the "Turn on remote access" / "Pair a device" clicks (see
  // tour.spec.ts and the sibling e2e specs that do the same).
  await page.addInitScript(() => {
    try {
      localStorage.setItem("sb_tour_completed", "1");
    } catch {
      /* private mode — ignore */
    }
  });

  await page.goto("/remote", { waitUntil: "domcontentloaded" });
  await page.waitForTimeout(600);

  // Off state: turn it on with a host.
  const hostInput = page.locator('input[placeholder*="tailnet"]').first();
  await hostInput.fill("box.tailnet-name.ts.net");
  await page.getByRole("button", { name: /Turn on remote access/i }).click();

  // Enable reveals the one-time pairing panel + QR.
  await expect(
    page.getByRole("heading", { name: /Scan to pair this device/i }),
  ).toBeVisible({ timeout: 15000 });
  await expect(page.getByAltText("Pairing QR code")).toBeVisible();
  await page.screenshot({ path: "e2e/shots/remote/armed.png", fullPage: true });

  // Dismiss the reveal, then prove "Pair a device" brings a FRESH one back
  // (this is the button that used to just scroll = "does nothing").
  await page.getByRole("button", { name: /^Done$/ }).click();
  await expect(
    page.getByRole("heading", { name: /Scan to pair this device/i }),
  ).toHaveCount(0);

  await page.getByRole("button", { name: /^Pair a device$/ }).click();
  await expect(
    page.getByRole("heading", { name: /Scan to pair this device/i }),
  ).toBeVisible({ timeout: 15000 });
  await expect(page.getByAltText("Pairing QR code")).toBeVisible();

  // The reset control is present + clearly labelled.
  await expect(
    page.getByRole("button", { name: /Reset & unpair all devices/i }),
  ).toBeVisible();
  await page.screenshot({ path: "e2e/shots/remote/paired-again.png", fullPage: true });
});
