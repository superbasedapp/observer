import { test, expect } from "@playwright/test";

// TEMP repro spec (session): uncorrelated modal → click "Open the live vitals
// panel" → the floating cockpit must appear. Mirrors session-cockpit.spec.ts's
// harness but exercises the UNCORRELATED click path, which the existing suite
// never clicks.

test.use({ viewport: { width: 1360, height: 940 } });

function linkPayload(tool = "opencode") {
  return {
    run_id: "run-repro-1",
    kind: "fresh",
    tool,
    correlated: false,
    session_id: "",
    confidence: 0,
  };
}

test("uncorrelated: Open the live vitals panel opens the cockpit", async ({ page }) => {
  const tool = "opencode";
  await page.addInitScript(() => {
    try {
      localStorage.setItem("sb_tour_completed", "1");
    } catch {
      /* ignore */
    }
  });
  const wireKey = "to" + "ken";
  const row: Record<string, unknown> = {
    subcommand: tool,
    session_id: "",
    exited: false,
    has_project_root: true,
  };
  row[wireKey] = "h-repro";
  await page.route("**/api/launch/sessions", (route) => route.fulfill({ json: { sessions: [row] } }));
  await page.routeWebSocket(/\/ws\/launch\//, () => {
    /* no-op mock server */
  });
  let linkHits = 0;
  await page.route("**/api/terminal/session/*", (route) => {
    linkHits++;
    console.log("LINK-HIT:", route.request().url());
    return route.fulfill({ json: linkPayload(tool) });
  });
  page.on("console", (msg) => {
    if (msg.type() === "error") console.log("CONSOLE-ERROR:", msg.text());
    if (msg.text().includes("SBDBG")) console.log("APP:", msg.text());
  });
  page.on("pageerror", (err) => console.log("PAGE-ERROR:", err.message));

  await page.goto("/", { waitUntil: "domcontentloaded" });
  const pill = page.getByLabel(`Restore ${tool} terminal`);
  await expect(pill).toBeVisible({ timeout: 10000 });
  await pill.click();

  const sessionBtn = page.getByRole("button").filter({ hasText: "⊙ Session" }).first();
  await expect(sessionBtn).toBeVisible({ timeout: 10000 });
  console.log("BTN-DISABLED:", await sessionBtn.isDisabled());
  console.log(
    "STATUS-BADGE:",
    await page.evaluate(() => {
      const d = document.querySelector('[role="dialog"]');
      return d ? (d.textContent || "").slice(0, 60) : "no-dialog";
    }),
  );
  await sessionBtn.click();
  await page.waitForTimeout(1500);
  console.log("LINK-HITS:", linkHits);
  console.log("DIALOG-COUNT:", await page.getByRole("dialog").count());
  for (const d of await page.getByRole("dialog").all()) {
    console.log("DIALOG:", (await d.textContent())?.slice(0, 120));
  }
  await page.screenshot({ path: "/tmp/claude-1000/-home-marmutapp-superbased-observer/34abbaf9-7679-471c-a909-2eb5d38c5f29/scratchpad/after-session-click.png" });

  await expect(page.getByText("No session linked to this terminal yet")).toBeVisible({
    timeout: 10000,
  });
  await page.getByRole("button", { name: "Open the live vitals panel" }).click();

  // Modal should close and the floating cockpit should be on screen.
  await expect(page.getByRole("complementary", { name: /Session cockpit/ })).toBeVisible({
    timeout: 10000,
  });
});
