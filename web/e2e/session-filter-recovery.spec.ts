import { test, expect } from "@playwright/test";

// Runs against the isolated demo dashboard, like the other e2e specs.
test.use({ viewport: { width: 1440, height: 1000 } });

test.beforeEach(async ({ page }) => {
  await page.addInitScript(() => {
    localStorage.setItem("sb_tour_completed", "1");
    sessionStorage.setItem("sb_firstrun_closed_this_visit", "1");
  });
});

test("clear all removes both search and classification filters", async ({ page }) => {
  await page.goto("/sessions");
  const search = page.getByRole("searchbox", { name: /Filter sessions by id or project/ });
  await search.fill("no-such-session-ux");
  await page.getByRole("button", { name: "Favorites", exact: true }).click();
  await page.getByRole("button", { name: "clear all", exact: true }).click();
  await expect(search).toHaveValue("");
  await expect(page.getByRole("row").filter({ has: page.getByRole("cell") }).first()).toBeVisible();
  await expect(page.getByRole("button", { name: "clear all", exact: true })).toHaveCount(0);
});

test("global search can be removed without a hidden query resurfacing", async ({ page }) => {
  await page.goto("/sessions?search=no-such-global-session-ux");
  const search = page.getByRole("searchbox", { name: /Filter sessions by id or project/ });
  await search.fill("no-such-local-session-ux");
  await page.getByRole("button", { name: "search: no-such-local-session-ux", exact: true }).click();
  await expect(search).toHaveValue("");
  await expect(page).not.toHaveURL(/[?&]search=/);
  await expect(page.getByRole("row").filter({ has: page.getByRole("cell") }).first()).toBeVisible();
});

test("empty filtered results explain how to recover, not how to set up tools", async ({ page }) => {
  await page.goto("/sessions");
  await page.getByRole("combobox", { name: "Filter sessions by client" }).selectOption("web");
  await expect(page.getByRole("heading", { name: "No sessions match the active filters. Clear filters or widen the time window." })).toBeVisible();
  await page.getByRole("button", { name: "clear all", exact: true }).click();
  await expect(page.getByRole("row").filter({ has: page.getByRole("cell") }).first()).toBeVisible();
});

test("global filters also get a recovery hint", async ({ page }) => {
  await page.goto("/sessions?proj=no-such-project-ux");
  await page.getByRole("searchbox", { name: "Filter sessions by id or project" }).waitFor();
  await expect(page.getByRole("heading", { name: "No sessions match the active filters. Clear filters or widen the time window." })).toBeVisible();
});
