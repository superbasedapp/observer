import { test, expect, type Locator, type Page } from "@playwright/test";
import { FIXTURE_PT_EVIDENCE, FIXTURE_PT_RETESTED as ARC_PT_RETESTED, FIXTURE_TM, fixtureBigThreatModel } from "../src/lib/secAssessModelFixture.ts";
import type { AssessModelResponse } from "../src/lib/secAssessModel.ts";
import { CVSS_CRITICAL, ID, KINDS, PROJECT_ALPHA, PROJECT_LEDGER, RED_TEAM_OBJECTIVE, fixturePtCvss, mockAll, newWire, openOverview, planFor, run, runsEveryState, runsWithRetests, type Json, type Wire } from "./secassess-workflow-fixtures.ts";
import { readFileSync } from "node:fs";
import { clearanceRegExp, parseClearanceList } from "../src/lib/secAssessBanned.ts";

// Code security > Overview > Security assessments, walked end to end as a
// person does it (the UX workflow review of 2026-11-15, report
// docs/audits/security-assessments-e2e-review-2026-11-15.md): the card and its
// six kinds, a plan dialog for each kind, the project picker, the target and its
// consent, the guardrail wording, the run list in every state, the report, Validate, the
// model view with its comparison, the phone and the keyboard. Like the sibling
// spec it drives an already-running ISOLATED dashboard on BASE_URL (a throwaway
// `observer dashboard` with its own HOME, or the Vite dev server in front of
// one; never the live daemon) and stubs only the assessment routes, the Code
// security status and the terminal launch routes, so the shell, the navigation,
// the theme and the components are the real ones. Every datum is synthetic
// (secassess-workflow-fixtures.ts).
//
// The three defects the review pinned here as expected failures (UX-6, UX-7,
// UX-9) were fixed in the third fix round and are ordinary tests now; the
// findings table (UX-15) belongs to the findings-contract work and is not
// pinned.

// The fixtures state their times in UTC and some assertions print them ("Nov 15, 2026, 09:00"), so the page runs on a UTC clock wherever the spec is run.
test.use({ viewport: { width: 1280, height: 1000 }, timezoneId: "UTC" });

const PHONE = { width: 375, height: 812 };

async function mount(page: Page, wire: Wire = newWire()): Promise<Wire> {
  await mockAll(page, wire);
  await openOverview(page);
  return wire;
}

function kindRow(page: Page, title: string): Locator {
  return page.getByTestId("assess-kind").filter({ hasText: title });
}

async function openPlan(page: Page, title: string): Promise<Locator> {
  await kindRow(page, title).getByRole("button", { name: "Start" }).click();
  const plan = page.getByTestId("assess-plan");
  await expect(plan).toBeVisible();
  return plan;
}

function runRow(page: Page, id: string): Locator {
  // A run row names its run in the report path of its own buttons only through the model route; the rows are found by their position in the fixture instead.
  return page.getByTestId("assess-run").nth(runsEveryState().findIndex((r) => r.id === id));
}

/** dialogBodyOverflow is how far the model view's dialog can be panned sideways: the scrolling body around the view and the dialog itself, each wider than its box (0: no horizontal scroll). A table inside the view has its own scroller and is not counted. */
async function dialogBodyOverflow(page: Page): Promise<number> {
  return page.getByTestId("assess-model").evaluate((el) => {
    const body = el.parentElement!;
    const dialog = el.closest('[role="dialog"]') as HTMLElement;
    return Math.max(body.scrollWidth - body.clientWidth, dialog.scrollWidth - dialog.clientWidth);
  });
}

const SNAKE = /\b[a-z]+_[a-z_]+\b/;

// ---------------------------------------------------------------- the card

test("the card lists the six kinds in order: five start, and the sixth explains in plain words why it does not", async ({ page }) => {
  await mount(page);
  const kinds = page.getByTestId("assess-kind");
  await expect(kinds).toHaveCount(6);
  const titles = await kinds.evaluateAll((els) => els.map((e) => e.querySelector("span.font-medium")?.textContent));
  expect(titles).toEqual(KINDS.map((k) => k.title));
  // Each launchable kind has Start; the sixth has Why not?.
  await expect(page.getByTestId("assess-kind").getByRole("button", { name: "Start" })).toHaveCount(5);
  const rasp = kindRow(page, "Runtime protection");
  await expect(rasp.getByRole("button", { name: "Start" })).toHaveCount(0);
  await rasp.getByRole("button", { name: "Why not?" }).click();
  const note = rasp.getByRole("note");
  await expect(note).toContainText("Nothing to launch");
  await expect(note).toContainText("not application self-protection");
  // The words of a person's page: no package path, no plane name, no config key.
  const words = await rasp.innerText();
  expect(words).not.toMatch(/internal\/|Plane [AB]\b|\.toml|security\.assessments\./);
});

test("the run list names every state in words, never a raw enum, and each row names its kind, project, tool and sandbox", async ({ page }) => {
  await mount(page);
  const rows = page.getByTestId("assess-run");
  await expect(rows).toHaveCount(runsEveryState().length);
  for (let i = 0; i < (await rows.count()); i++) {
    const text = await rows.nth(i).innerText();
    expect(text, `row ${i}`).not.toMatch(SNAKE);
    expect(text, `row ${i}`).not.toMatch(/undefined|NaN|\bnull\b|\[object/);
  }
  const live = rows.nth(0);
  await expect(live).toContainText("running");
  await expect(live.getByRole("button", { name: "Stop" })).toBeVisible();
  await expect(rows.nth(1)).toContainText("ended without a result");
  await expect(rows.nth(1)).toContainText("nothing to read or check");
  await expect(rows.nth(2)).toContainText("model written");
  await expect(rows.nth(2).getByRole("button", { name: "Validate" })).toBeVisible();
  // A pen test names its sandbox backend; every row names the tool and where it ran.
  await expect(rows.nth(3)).toContainText("Claude Code · http://localhost:3000/ · in a sandbox (bwrap)");
  await expect(rows.nth(4)).toContainText("Claude Code · not sandboxed");
  await expect(rows.nth(7)).toContainText("Cloud posture review");
});

test("the card fits a phone, in light and dark, with every state on it: no horizontal scroll in the page", async ({ page }) => {
  await page.setViewportSize(PHONE);
  await mount(page);
  for (const scheme of ["light", "dark"] as const) {
    await page.emulateMedia({ colorScheme: scheme });
    const over = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
    expect(over, `${scheme}: page overflow`).toBe(0);
    await expect(page.getByTestId("assess-card")).toBeVisible();
  }
});

// ---------------------------------------------------------------- the plan dialogs

test("each launchable kind opens its own plan: the threat model has a scope and a comparison, the pen test and red team a target, the cloud and instrumented kinds neither", async ({ page }) => {
  await mount(page);
  let plan = await openPlan(page, "Threat model");
  await expect(page.getByTestId("assess-scope")).toBeVisible();
  await expect(page.getByTestId("assess-target")).toHaveCount(0);
  await expect(plan.getByText("Your choice of sandbox in the next step")).toBeVisible();
  await page.keyboard.press("Escape");
  for (const title of ["Penetration test", "Red team"]) {
    plan = await openPlan(page, title);
    await expect(page.getByTestId("assess-target")).toBeVisible();
    await expect(plan.getByText("Runs in a sandbox that Observer chooses; it refuses to start without one")).toBeVisible();
    await expect(page.getByRole("button", { name: "Choose agent" })).toBeDisabled();
    await page.keyboard.press("Escape");
  }
  for (const title of ["Cloud posture", "Instrumented tests"]) {
    plan = await openPlan(page, title);
    await expect(page.getByTestId("assess-target")).toHaveCount(0);
    await expect(page.getByTestId("assess-scope")).toHaveCount(0);
    await expect(page.getByRole("button", { name: "Choose agent" })).toBeEnabled();
    await page.keyboard.press("Escape");
  }
  await expect(page.getByRole("dialog")).toHaveCount(0);
});

test("the plan dialog starts on the project assessed last, not on the first project in the list", async ({ page }) => {
  // alpha-probe is listed first; the newest run is on ledger.
  const wire = await mount(page);
  await openPlan(page, "Threat model");
  const select = page.getByTestId("assess-project");
  await expect(select).toHaveValue(PROJECT_LEDGER.project_root_hash);
  await expect(page.getByRole("dialog")).toContainText("In ledger");
  expect(wire.plans.at(-1)?.searchParams.get("project")).toBe(PROJECT_LEDGER.project_root_hash);
});

test("with no run yet the plan dialog starts on the first active project, and choosing another project reads the plan again for it", async ({ page }) => {
  const wire = newWire([]);
  await mount(page, wire);
  await openPlan(page, "Threat model");
  const select = page.getByTestId("assess-project");
  await expect(select).toHaveValue(PROJECT_ALPHA.project_root_hash);
  await select.selectOption(PROJECT_LEDGER.project_root_hash);
  await expect(page.getByRole("dialog")).toContainText("In ledger");
  await expect.poll(() => wire.plans.at(-1)?.searchParams.get("project")).toBe(PROJECT_LEDGER.project_root_hash);
  // The comparison of the other project appears with it: its earlier threat models are offered, the newest chosen.
  await expect(page.getByTestId("assess-previous-select")).toHaveValue(ID.tmNew);
});

test("a threat model launches with the project the picker shows and the plan's run id, after the comparison default was read", async ({ page }) => {
  const wire = await mount(page);
  await openPlan(page, "Threat model");
  await expect(page.getByTestId("assess-previous-select")).toHaveValue(ID.tmNew);
  await page.getByRole("button", { name: "Choose agent" }).click();
  await expect(page.getByTestId("new-terminal-task")).toBeVisible();
  await page.getByRole("button", { name: "Start", exact: true }).last().click();
  await expect.poll(() => wire.launches.length).toBe(1);
  expect(wire.launches[0]).toMatchObject({ assessment: "threat_model", project_root_hash: PROJECT_LEDGER.project_root_hash, run_id: "00000000000000f1" });
});

test("a pen test cannot start until its target is chosen and confirmed: the button says why, the consent names the exact target, and the launch carries both", async ({ page }) => {
  const wire = await mount(page);
  await openPlan(page, "Penetration test");
  const choose = page.getByRole("button", { name: "Choose agent" });
  await expect(choose).toBeDisabled();
  // The reason sits on the span around the disabled button: it is in the tab order (tabindex 0) and shows on hover.
  const why = choose.locator("xpath=..");
  await expect(why).toHaveAttribute("tabindex", "0");
  await why.hover();
  await expect(page.getByRole("tooltip").first()).toContainText("Choose the target first");
  await page.getByTestId("assess-target").getByRole("radio").first().click();
  await expect(page.getByTestId("assess-confirm")).toContainText("http://localhost:3000/ is the only thing the agent may test");
  await expect(choose).toBeDisabled();
  await page.getByTestId("assess-confirm").getByRole("checkbox").check();
  await expect(choose).toBeEnabled();
  await choose.click();
  await expect(page.getByTestId("new-terminal-task")).toBeVisible();
  await page.getByRole("button", { name: "Start", exact: true }).last().click();
  await expect.poll(() => wire.launches.length).toBe(1);
  expect(wire.launches[0]).toMatchObject({ assessment: "pentest_local", project_root_hash: PROJECT_LEDGER.project_root_hash, target: "http://localhost:3000/", confirm_target: "http://localhost:3000/" });
});

test("a target that is not on this machine is refused in the server's words, keeps the button off and offers no task", async ({ page }) => {
  await mount(page);
  await openPlan(page, "Penetration test");
  await page.getByTestId("assess-target-input").fill("http://example.com:3000/");
  await page.getByRole("button", { name: "Use this address" }).click();
  await expect(page.getByRole("dialog")).toContainText("This cannot start here");
  await expect(page.getByRole("dialog")).toContainText("The target must be localhost, 127.0.0.1 or [::1] with a port.");
  await expect(page.getByRole("button", { name: "Choose agent" })).toBeDisabled();
  await expect(page.getByTestId("assess-confirm")).toHaveCount(0);
  await expect(page.getByTestId("assess-prompt-text")).toHaveCount(0);
});

test("the guardrails section names the kind it is for, and a tick is a consent that says whose it is", async ({ page }) => {
  await mount(page);
  await openPlan(page, "Red team");
  const relax = page.getByTestId("assess-relax");
  await expect(relax).toContainText("A red team exercise can need one lifted for this run only.");
  await expect(relax).not.toContainText("A pen test can need");
  await expect(relax).toContainText("Your tick is the consent.");
  await page.keyboard.press("Escape");
  await openPlan(page, "Penetration test");
  await expect(page.getByTestId("assess-relax")).toContainText("A pen test can need one lifted for this run only.");
  await page.getByTestId("assess-relax-R-179").getByRole("checkbox").check();
  // The plan is read again with the rule ticked; the section then says what is lifted and how far it reaches.
  await expect(page.getByTestId("assess-relax-scope")).toBeVisible();
  await expect(page.getByTestId("assess-relax-report")).toContainText("not reported to your organization");
});

// ---------------------------------------------------------------- results

test("Read report opens the report as plain text, says how many places were hidden, and closes on Escape with focus back on the button", async ({ page }) => {
  await mount(page);
  const row = runRow(page, ID.ptChecked);
  const button = row.getByRole("button", { name: "Read report" });
  await button.click();
  await expect(page.getByTestId("assess-report-text")).toContainText("The agent's report, as plain text.");
  await expect(page.getByTestId("assess-report-redaction")).toContainText("2");
  await expect(page.getByRole("dialog")).toContainText(`.observer/assessments/${ID.ptChecked}/report.md`);
  await page.keyboard.press("Escape");
  await expect(page.getByRole("dialog")).toHaveCount(0);
  await expect(button).toBeFocused();
});

test("Validate checks a written model on one click and the row says what was checked, in the grammar of its counts", async ({ page }) => {
  const wire = await mount(page);
  const row = runRow(page, ID.ptWritten);
  await row.getByRole("button", { name: "Validate" }).click();
  await expect.poll(() => wire.posts.length).toBe(1);
  expect(wire.posts[0]).toMatchObject({ path: "validate", body: { run: ID.ptWritten } });
  const line = row.getByTestId("assess-run-validation");
  // One reference that exists reads "1 exists", never "1 exist".
  await expect(line).toContainText("References: 27 found near the cited line, 1 exists with nothing matched near the cited line.");
  await expect(row.getByRole("button", { name: "Open model" })).toBeVisible();
});

// ---------------------------------------------------------------- the model view

test("the model view of a threat model launched with an earlier run opens on that comparison, reads it, and titles itself by project and start time, not by the run's token", async ({ page }) => {
  const wire = await mount(page);
  await runRow(page, ID.tmNew).getByRole("button", { name: "Open model" }).click();
  const model = page.getByTestId("assess-model");
  await expect(model).toBeVisible();
  const select = page.getByTestId("assess-since-select");
  await expect(select).toHaveValue(ID.tmOld);
  // The comparison was read for that run, and its counts and its honest sentence are on screen.
  await expect.poll(() => wire.modelReads).toContain(`${ID.tmNew}+${ID.tmOld}`);
  await expect(page.getByTestId("assess-since-counts")).toBeVisible();
  await expect(page.getByTestId("assess-since-note")).toContainText("This compares what two runs reported; it does not say which is right.");
  // The title and the subtitle: no token that looks like a digest.
  const dialog = page.getByRole("dialog");
  await expect(dialog).toContainText("Threat model: ledger");
  await expect(dialog).toContainText(/Started .+ · Validated /);
  const head = (await dialog.innerText()).slice(0, 200);
  expect(head).not.toMatch(/\bRun [A-Za-z0-9_-]{20,}/);
  expect(head).not.toContain("x".repeat(20));
  // Choosing None drops the comparison; the model stays.
  await select.selectOption("");
  await expect(page.getByTestId("assess-since")).toHaveCount(0);
  await expect(model).toBeVisible();
});

test("a threat model launched without a comparison opens on None", async ({ page }) => {
  const wire = newWire(runsEveryState().map((r) => (r.id === ID.tmNew ? run({ ...r, previous_run: undefined, compare_state: undefined }) : r)));
  await mount(page, wire);
  await runRow(page, ID.tmNew).getByRole("button", { name: "Open model" }).click();
  await expect(page.getByTestId("assess-since-select")).toHaveValue("");
  expect(wire.modelReads.every((r) => !r.includes("+"))).toBe(true);
});

test("the threats filter lists each element once, and two routes of one service are told apart by their ids", async ({ page }) => {
  // Every entry point of a service is named "<kind> on <component>": a model with several routes made the filter list one name many times.
  const answer = JSON.parse(JSON.stringify(FIXTURE_TM)) as AssessModelResponse;
  const tm = answer.record.result.tm!;
  const comp = tm.system!.components![0];
  tm.system!.entry_points = [
    { id: "ep-search", component: comp.id, kind: "http_route" },
    { id: "ep-login", component: comp.id, kind: "http_route" },
  ];
  const base = tm.threats![0];
  tm.threats = [
    ...tm.threats!,
    { ...base, id: "T-91", element: { kind: "entry_point", id: "ep-search" } },
    { ...base, id: "T-92", element: { kind: "entry_point", id: "ep-login" } },
  ];
  const wire = newWire(runsEveryState());
  wire.models = { [ID.tmNew]: answer };
  await mount(page, wire);
  await runRow(page, ID.tmNew).getByRole("button", { name: "Open model" }).click();
  await page.getByRole("tab", { name: /^Threats/ }).click();
  const labels = await page.getByLabel("Filter by element").locator("option").allTextContents();
  expect(new Set(labels).size, `the element filter repeats a name: ${labels.join(" | ")}`).toBe(labels.length);
  expect(labels.some((l) => l.includes("ep-search"))).toBe(true);
  expect(labels.some((l) => l.includes("ep-login"))).toBe(true);
});

test("a large matrix at phone width does not make the dialog scroll sideways", async ({ page }) => {
  await page.setViewportSize(PHONE);
  const wire = newWire(runsEveryState());
  wire.models = { [ID.tmNew]: fixtureBigThreatModel(60) };
  await mount(page, wire);
  await runRow(page, ID.tmNew).getByRole("button", { name: "Open model" }).click();
  await page.getByRole("tab", { name: /^Matrix/ }).click();
  await expect(page.getByTestId("assess-matrix")).toBeVisible();
  expect(await dialogBodyOverflow(page)).toBeLessThanOrEqual(1);
});

test("the model view shows some of the model when it opens on a phone, not only its preamble and its footer", async ({ page }) => {
  await page.setViewportSize(PHONE);
  await mount(page);
  await runRow(page, ID.tmNew).getByRole("button", { name: "Open model" }).click();
  await expect(page.getByTestId("assess-model")).toBeVisible();
  const dialog = page.getByRole("dialog").last();
  const panel = await dialog.getByRole("tabpanel").first().boundingBox();
  const footer = await dialog.getByRole("button", { name: "Close" }).locator("xpath=ancestor::div[contains(@class,'justify-between')][1]").boundingBox();
  // How many pixels of the first tab's content sit between its top and the footer's top.
  expect(footer!.y - panel!.y).toBeGreaterThanOrEqual(120);
});

// ---------------------------------------------------------------- the keyboard

test("the plan dialog opens on a control, Tab stays inside it, the first Escape may close a help note and the next closes it with focus back on Start", async ({ page }) => {
  await mount(page);
  const start = kindRow(page, "Threat model").getByRole("button", { name: "Start" });
  await start.focus();
  await page.keyboard.press("Enter");
  await expect(page.getByTestId("assess-plan")).toBeVisible();
  for (let i = 0; i < 30; i++) {
    await page.keyboard.press("Tab");
    expect(await page.evaluate(() => !!document.activeElement?.closest('[role="dialog"]')), `Tab ${i + 1} left the dialog`).toBe(true);
  }
  for (let i = 0; i < 2 && (await page.getByRole("dialog").count()) > 0; i++) await page.keyboard.press("Escape");
  await expect(page.getByRole("dialog")).toHaveCount(0);
  await expect(start).toBeFocused();
});

// ---------------------------------------------------------------- the settings card (read only)

test("the Settings card labels a count of one in the singular", async ({ page }) => {
  await page.addInitScript(() => {
    try {
      localStorage.setItem("sb_tour_completed", "1");
      sessionStorage.setItem("sb_firstrun_closed_this_visit", "1");
    } catch {
      /* private mode: ignore */
    }
  });
  await page.goto("/settings?section=guard", { waitUntil: "domcontentloaded" });
  const window = page.getByTestId("code-security-setting-security.assessments.ref_match_window_lines");
  await expect(window).toBeVisible({ timeout: 20000 });
  const options = await window.locator("option").allTextContents();
  expect(options[0]).toBe("1 line");
  expect(options).toContain("3 lines");
  const pace = page.getByTestId("code-security-setting-security.assessments.pentest_pace_rps");
  const paces = await pace.locator("option").allTextContents();
  expect(paces[0]).toBe("1 request per second");
});

// ---------------------------------------------------------------- defects the review found and the third fix round fixed

test("the coverage tab says the log is a file the agent can write once, not on every row", async ({ page }) => {
  // A pen test whose request helper logged a request for every category the agent marked tested: each reads "Tested (logged request)".
  const answer = JSON.parse(JSON.stringify(FIXTURE_PT_EVIDENCE)) as AssessModelResponse;
  const pt = answer.record.result.report!.pt!;
  pt.rows = pt.rows.map((r) => (r.effective === "tested_claimed" ? { ...r, effective: "tested_logged" } : r));
  const wire = newWire(runsEveryState());
  wire.models = { [ID.ptChecked]: answer };
  await mount(page, wire);
  await runRow(page, ID.ptChecked).getByRole("button", { name: "Open model" }).click();
  await page.getByRole("dialog").getByRole("tab", { name: /^Coverage/ }).click();
  const text = await page.getByRole("dialog").getByRole("tabpanel").first().innerText();
  const repeats = text.split("The log is a file the agent can write, so this is not a trace.").length - 1;
  expect(repeats).toBeLessThanOrEqual(1);
});

test("a run row says which earlier run it was compared with by what it is, not by a 16-character id", async ({ page }) => {
  await mount(page);
  const text = await runRow(page, ID.tmNew).innerText();
  expect(text).not.toMatch(/Compared with run [0-9a-f]{16}/);
  // The row, the plan's picker and the model view's select name a run the same way: the kind, then the date and time.
  const label = /^Threat model, [A-Z][a-z]{2} \d+, 20\d\d, \d\d:\d\d/;
  expect(text).toMatch(/Compared with the earlier run \(Threat model, [A-Z][a-z]{2} \d+, 20\d\d, \d\d:\d\d\)/);
  await openPlan(page, "Threat model");
  const options = await page.getByTestId("assess-previous-select").locator("option").allTextContents();
  for (const o of options.filter((x) => x !== "No comparison")) {
    expect(o).toMatch(label);
    expect(o).not.toMatch(/[0-9a-f]{16}/);
  }
  await page.keyboard.press("Escape");
  await expect(page.getByRole("dialog")).toHaveCount(0);
  await runRow(page, ID.tmNew).getByRole("button", { name: "Open model" }).click();
  const since = page.getByTestId("assess-since-select");
  await expect(since).toBeVisible();
  const runs = (await since.locator("option").allTextContents()).filter((x) => x.trim() !== "" && x !== "None");
  expect(runs.length).toBeGreaterThan(0);
  for (const o of runs) {
    expect(o).toMatch(label);
    expect(o).not.toMatch(/\bago\b/);
  }
});

test("the pen test plan puts the consent directly under the target and prints why the button waits", async ({ page }) => {
  await mount(page);
  await openPlan(page, "Penetration test");
  const reason = page.getByTestId("assess-choose-reason");
  await expect(reason).toHaveText("Choose the target first");
  await page.getByTestId("assess-target").getByRole("radio").first().click();
  // The consent is inside the target's own section, so it is where the target was just chosen.
  const consent = page.getByTestId("assess-target").getByTestId("assess-confirm");
  await expect(consent).toBeVisible();
  await expect(reason).toHaveText("Confirm the target first");
  const target = await page.getByTestId("assess-target").boundingBox();
  const box = await consent.boundingBox();
  expect(box!.y - target!.y).toBeLessThan(500);
  await consent.getByRole("checkbox").check();
  await expect(reason).toHaveCount(0);
});

test("a pen test plan with no start command says so once, and no field leads with an Or that follows nothing", async ({ page }) => {
  await mount(page);
  await openPlan(page, "Penetration test");
  const text = await page.getByTestId("assess-plan").innerText();
  expect((text.match(/No start command/g) ?? []).length).toBeLessThanOrEqual(1);
  // An Or leads something only when a list of choices stands above the field.
  for (const [section, what] of [["assess-target", "the address"], ["assess-start", "the command"]] as const) {
    const box = page.getByTestId(section);
    if ((await box.count()) === 0) continue;
    const listed = (await box.locator("input[type=radio]").count()) > 0;
    await expect(box.getByText(new RegExp(`^${listed ? "Or type" : "Type"} ${what}`))).toBeVisible();
  }
});

// ---------------------------------------------------------------- the retest and the red team's exercise (depth plan W7.2, W7.3)
//
// A retest sends the stored requests of an earlier run's findings again and
// gives each finding a label; it closes nothing and changes no finding. A red
// team run's model has an Exercise tab built from its structured chain. The
// routes are the stubbed ones (secassess-workflow-fixtures.ts): the plan stub
// answers the retest and objective blocks in the server's shape, the launch
// route only records the body, and nothing here reaches a real server.

/** The words no sentence Observer writes may use because they read as a clearance: one shared list, read by the Go test and the unit tests too. */
const BANNED = clearanceRegExp(parseClearanceList(readFileSync(new URL("../../internal/secassess/testdata/clearance_words.json", import.meta.url), "utf8")));

/** retestRunRow is the row of a run of runsWithRetests (the arc's rows follow the ones the other tests index). */
function retestRunRow(page: Page, id: string): Locator {
  return page.getByTestId("assess-run").nth(runsWithRetests().findIndex((r) => r.id === id));
}

async function openModelOf(page: Page, id: string): Promise<void> {
  await retestRunRow(page, id).getByRole("button", { name: "Open model" }).click();
  await expect(page.getByTestId("assess-model")).toBeVisible();
}

/** modelTab is one tab of the model view on top (the page behind it has a Findings tab of its own). */
function modelTab(page: Page, name: string | RegExp): Locator {
  return page.getByRole("dialog").last().getByRole("tab", { name });
}

async function mountArc(page: Page): Promise<Wire> {
  return mount(page, newWire(runsWithRetests()));
}

/** topDialogOverflow is how far the topmost dialog can be panned sideways (0: no horizontal scroll). */
async function topDialogOverflow(page: Page): Promise<number> {
  return page.locator('[role="dialog"]').last().evaluate((el) => {
    const body = el.querySelector<HTMLElement>("[data-testid], div") ?? el;
    return Math.max((el as HTMLElement).scrollWidth - (el as HTMLElement).clientWidth, body.scrollWidth - body.clientWidth);
  });
}

/** noRawWords is the page rule for every new view: no raw code, no placeholder text and no word that reads as a clearance. */
function noRawWords(text: string, where: string) {
  expect(text.match(SNAKE)?.[0], `${where}: a raw code`).toBeUndefined();
  expect(text.match(/undefined|NaN|\bnull\b|\[object/)?.[0], `${where}: a placeholder`).toBeUndefined();
  expect(text.match(BANNED)?.[0], `${where}: a word that reads as a clearance`).toBeUndefined();
}

test("the card's grid leaves out the retest, which is reached only from a run's model view", async ({ page }) => {
  await mountArc(page);
  // The server lists the retest among the kinds; the card shows the six that start from nothing.
  await expect(page.getByTestId("assess-kind")).toHaveCount(6);
  await expect(page.getByTestId("assess-kind").filter({ hasText: "Retest of earlier findings" })).toHaveCount(0);
  // The retest runs are in the list of runs, each naming the earlier run it replayed and how many findings.
  const row = retestRunRow(page, ID.retestNew);
  await expect(row).toContainText("Retest of earlier findings");
  await expect(row.getByTestId("assess-run-retest-of")).toContainText("5 findings chosen");
  await expect(retestRunRow(page, ID.retestOld).getByTestId("assess-run-retest-of")).toContainText("2 findings chosen");
  // A red team run's row carries its objective as text.
  await expect(retestRunRow(page, ID.redTeam).getByTestId("assess-run-objective")).toContainText(`Objective: ${RED_TEAM_OBJECTIVE}`);
  for (const id of [ID.retestNew, ID.redTeam]) noRawWords(await retestRunRow(page, id).innerText(), id);
});

test("from a pen test's findings the picker lists what has a stored request, the choice is bounded and moves by keyboard, and it opens the retest plan on the same project", async ({ page }) => {
  const wire = await mountArc(page);
  await openModelOf(page, ID.ptRetested);
  await modelTab(page, /^Findings/).click();
  const action = page.getByTestId("assess-retest-action");
  await expect(action).toContainText("5 findings have a stored request to replay.");
  await action.getByRole("button", { name: "Retest findings" }).click();
  const picker = page.getByTestId("assess-retest-picker");
  await expect(picker).toBeVisible();
  // Five of the six findings have a request a retest can send; the sixth is code or text only and is not offered. The four the replay can send in full start chosen, counted against the bound of eight; F-2 has a hidden value and is listed after them, not chosen (N-21).
  await expect(picker.getByRole("checkbox")).toHaveCount(5);
  await expect(picker.getByRole("checkbox", { checked: true })).toHaveCount(4);
  await expect(page.getByTestId("assess-retest-choose-F-2")).not.toBeChecked();
  await expect(page.getByTestId("assess-retest-count")).toHaveText("4 of 8 findings chosen");
  await expect(page.getByTestId("assess-retest-offer")).toContainText("4 can be sent again in full and are chosen. 1 has a value that was hidden when the finding was kept; it is listed after and is not chosen for you.");
  await expect(picker.locator('[data-finding-id="F-4"]')).toHaveCount(0);
  // What was stored for each: its requests, whether a condition was stored, and the warning for a hidden value.
  await expect(picker.locator('[data-finding-id="F-1"]')).toContainText("2 stored requests");
  await expect(picker.locator('[data-finding-id="F-3"]')).toContainText(/no stored condition \(a label cannot be backed by the log\)/i);
  await expect(picker.locator('[data-finding-id="F-2"]')).toContainText("A stored value was hidden when the finding was kept");
  await expect(picker).toContainText("It closes nothing and changes no finding.");
  noRawWords(await picker.innerText(), "picker");
  // The keyboard: Space toggles the focused checkbox, Tab moves to the next finding.
  await page.getByTestId("assess-retest-choose-F-1").focus();
  await page.keyboard.press("Space");
  await expect(page.getByTestId("assess-retest-choose-F-1")).not.toBeChecked();
  await expect(page.getByTestId("assess-retest-count")).toHaveText("3 of 8 findings chosen");
  await page.keyboard.press("Tab");
  await expect(page.getByTestId("assess-retest-choose-F-3")).toBeFocused();
  // Tab stays inside the picker.
  for (let i = 0; i < 12; i++) {
    await page.keyboard.press("Tab");
    expect(await page.evaluate(() => !!document.activeElement?.closest('[role="dialog"]')), `Tab ${i + 1} left the picker`).toBe(true);
  }
  // Escape closes the picker and nothing under it.
  await page.keyboard.press("Escape");
  await expect(picker).toHaveCount(0);
  await expect(page.getByTestId("assess-model")).toBeVisible();
  await action.getByRole("button", { name: "Retest findings" }).click();
  await expect(page.getByTestId("assess-retest-picker").getByRole("checkbox", { checked: true })).toHaveCount(4);
  await page.getByTestId("assess-retest-choose-F-1").focus();
  await page.keyboard.press("Space");
  // Enter on the open button opens the plan: nothing is started by it.
  await page.getByTestId("assess-retest-open-plan").focus();
  await page.keyboard.press("Enter");
  const plan = page.getByTestId("assess-plan");
  await expect(plan).toBeVisible();
  await expect(page.getByTestId("assess-retest-picker")).toHaveCount(0);
  await expect.poll(() => wire.plans.at(-1)?.searchParams.get("kind")).toBe("pentest_retest");
  const asked = wire.plans.at(-1)!.searchParams;
  expect(asked.get("project")).toBe(PROJECT_LEDGER.project_root_hash);
  expect(asked.get("of_run")).toBe(ID.ptRetested);
  expect(asked.getAll("finding")).toEqual(["F-3", "F-5", "F-6"]);
  expect(wire.launches).toHaveLength(0);
  // The plan names what it replays, the earlier run's address as a suggestion only, and the request helper.
  const block = page.getByTestId("assess-retest-plan");
  await expect(block).toContainText("The stored requests of findings from an earlier penetration test.");
  await expect(block).toContainText("3 of 8 findings chosen");
  await expect(block.getByTestId("assess-retest-plan-finding")).toHaveCount(3);
  await expect(block).toContainText("Stored condition: status 200 and the body holds db.internal");
  await expect(block).toContainText("Nothing was closed: this is one replay of the stored request, read against the stored condition.");
  await expect(page.getByTestId("assess-helper")).toContainText("Request helper");
  await expect(page.getByTestId("assess-project")).toBeDisabled();
  // The block this arc added to the plan, in plain words (the rest of the dialog is the existing plan's).
  noRawWords(await block.innerText(), "retest plan block");
  noRawWords(await page.getByTestId("assess-helper").innerText(), "request helper");
});

test("the retest plan fills the earlier run's address in as a suggestion, asks for the same consent, shows the replay task and sends what the picker chose", async ({ page }) => {
  const wire = await mountArc(page);
  await openModelOf(page, ID.ptRetested);
  await modelTab(page, /^Findings/).click();
  await page.getByTestId("assess-retest-action").getByRole("button", { name: "Retest findings" }).click();
  await page.getByTestId("assess-retest-choose-F-3").uncheck();
  await page.getByTestId("assess-retest-open-plan").click();
  await expect(page.getByTestId("assess-plan")).toBeVisible();
  // The suggestion is in the field and nothing is confirmed: no consent line, no task, no way to start.
  await expect(page.getByTestId("assess-target-input")).toHaveValue("http://localhost:3000/");
  await expect(page.getByTestId("assess-retest-target-note")).toContainText("It is filled in under Target as a suggestion");
  await expect(page.getByTestId("assess-confirm")).toHaveCount(0);
  await expect(page.getByTestId("assess-prompt-text")).toHaveCount(0);
  const choose = page.getByRole("button", { name: "Choose agent" });
  await expect(choose).toBeDisabled();
  await page.getByRole("button", { name: "Use this address" }).click();
  await expect(page.getByTestId("assess-confirm")).toContainText("http://localhost:3000/ is the only thing the agent may test");
  await expect(choose).toBeDisabled();
  // The replay task names the earlier run and the findings it sends again.
  await expect(page.getByTestId("assess-prompt-text")).toContainText(`RETEST of run ${ID.ptRetested}`);
  await expect(page.getByTestId("assess-prompt-text")).toContainText("F-1, F-5, F-6");
  await page.getByTestId("assess-confirm").getByRole("checkbox").check();
  await expect(choose).toBeEnabled();
  // Only the stubbed launch route is on the other end: it records the body the dialog sends.
  await choose.click();
  await expect(page.getByTestId("new-terminal-task")).toBeVisible();
  await page.getByRole("button", { name: "Start", exact: true }).last().click();
  await expect.poll(() => wire.launches.length).toBe(1);
  expect(wire.launches[0]).toMatchObject({
    assessment: "pentest_retest",
    project_root_hash: PROJECT_LEDGER.project_root_hash,
    target: "http://localhost:3000/",
    confirm_target: "http://localhost:3000/",
    of_run: ID.ptRetested,
    finding_ids: ["F-1", "F-5", "F-6"],
  });
  expect(Object.keys(wire.launches[0])).not.toContain("objective");
});

test("Escape on the retest plan closes the plan and leaves the model view under it", async ({ page }) => {
  await mountArc(page);
  await openModelOf(page, ID.ptRetested);
  await modelTab(page, /^Findings/).click();
  await page.getByTestId("assess-retest-action").getByRole("button", { name: "Retest findings" }).click();
  await page.getByTestId("assess-retest-open-plan").click();
  await expect(page.getByTestId("assess-plan")).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(page.getByTestId("assess-plan")).toHaveCount(0);
  await expect(page.getByTestId("assess-model")).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(page.getByTestId("assess-model")).toHaveCount(0);
});

test("the red team plan has an objective field: counted in characters, bounded, read into the plan when applied, with the cleaned text shown; a pen test has none", async ({ page }) => {
  const wire = await mount(page);
  await openPlan(page, "Penetration test");
  await expect(page.getByTestId("assess-objective")).toHaveCount(0);
  await page.keyboard.press("Escape");
  await openPlan(page, "Red team");
  const field = page.getByTestId("assess-objective");
  const input = page.getByTestId("assess-objective-input");
  await expect(field).toContainText("0 of 200 characters");
  await expect(field).toContainText("Objective (optional)");
  // One line: a text field, not a text area.
  expect(await input.evaluate((el) => el.tagName)).toBe("INPUT");
  const typed = "Read the entries of another account `quietly`";
  const before = wire.plans.length;
  await input.fill(typed);
  await expect(field).toContainText(`${[...typed].length} of 200 characters`);
  // Typing reads nothing again; Enter applies it.
  expect(wire.plans.length).toBe(before);
  await input.press("Enter");
  await expect.poll(() => wire.plans.at(-1)?.searchParams.get("objective")).toBe(typed);
  await expect(page.getByTestId("assess-objective-cleaned")).toContainText("The task carries it as: Read the entries of another account quietly");
  // Leaving the field applies it too.
  await input.fill("Reach the export route");
  await input.blur();
  await expect.poll(() => wire.plans.at(-1)?.searchParams.get("objective")).toBe("Reach the export route");
  await expect(page.getByTestId("assess-objective-cleaned")).toHaveCount(0);
  // The bound: more than 200 characters are cut at 200.
  await input.fill("a".repeat(250));
  await expect(input).toHaveValue("a".repeat(200));
  await expect(field).toContainText("200 of 200 characters");
  noRawWords(await field.innerText(), "objective field");
});

test("a red team run's model opens on its Exercise tab: whose objective it is, the steps in the agent's order, the opinion headed as the agent's, and what the exercise is not", async ({ page }) => {
  await mountArc(page);
  await openModelOf(page, ID.redTeam);
  const tabs = page.getByRole("dialog").last().getByRole("tab");
  await expect(tabs.first()).toHaveText(/^Exercise/);
  await expect(tabs.first()).toHaveAttribute("aria-selected", "true");
  const exercise = page.getByTestId("assess-exercise");
  await expect(exercise).toBeVisible();
  const objective = page.getByTestId("assess-exercise-objective");
  await expect(objective).toContainText("In your words");
  await expect(objective).toContainText(RED_TEAM_OBJECTIVE);
  const steps = page.getByTestId("assess-exercise-step");
  await expect(steps).toHaveCount(5);
  expect(await steps.evaluateAll((els) => els.map((e) => e.getAttribute("data-step")))).toEqual(["1", "2", "3", "4", "5"]);
  await expect(steps.nth(0)).toContainText("Read the front page and the error pages");
  await expect(steps.nth(0).getByTestId("assess-exercise-finding")).toContainText("no finding");
  await expect(steps.nth(2).getByTestId("assess-exercise-finding")).toContainText("F-1");
  await expect(steps.nth(2).getByTestId("assess-exercise-finding")).toContainText("Entry search is injectable");
  await expect(steps.nth(3).getByTestId("assess-exercise-result")).toContainText("Partly achieved");
  await expect(steps.nth(4).getByTestId("assess-exercise-result")).toContainText("Blocked");
  // A step the agent gave no opinion for says so, and the column says whose opinion the rest is.
  await expect(steps.nth(4).getByTestId("assess-exercise-stop")).toContainText("The agent gave no opinion.");
  await expect(page.getByTestId("assess-exercise-stop-heading")).toContainText("the agent's opinion");
  await expect(page.getByTestId("assess-exercise-stop-note")).toContainText("Observer did not test any of it.");
  await expect(page.getByTestId("assess-exercise-limit")).toContainText("one application in one box");
  const words = await exercise.innerText();
  noRawWords(words, "exercise");
  expect(words).not.toMatch(/ATT&CK|MITRE|technique/i);
  // The other tabs of the run are the pen test's own.
  await expect(tabs).toHaveText([/^Exercise/, /^Coverage/, /^Findings/, /^How checked/]);
});

test("a retest run's view leads with what a retest is, shows the three labels with the agent's notes as text, the counts, the limit and no export", async ({ page }) => {
  const wire = await mountArc(page);
  await openModelOf(page, ID.retestNew);
  const view = page.getByTestId("assess-retest-view");
  await expect(view).toBeVisible();
  await expect(page.getByRole("dialog").last()).toContainText("Retest of earlier findings (your own app, local): ledger");
  // N-12: what a retest is and that it closes nothing is said once, by the limit that opens the results; nothing says it again before the first label.
  await expect(page.getByTestId("assess-retest-limit")).toContainText("A retest repeats the stored requests of findings from an earlier run");
  await expect(page.getByTestId("assess-retest-limit")).toContainText("A retest closes nothing and changes no finding's status.");
  await expect(page.getByTestId("assess-retest-lead")).toContainText("The labels are shown on the findings of the run it replayed.");
  const beforeLabels = await page.getByRole("dialog").last().evaluate((el) => {
    const table = el.querySelector('[data-testid="assess-retest-table"]');
    const range = document.createRange();
    range.setStart(el, 0);
    range.setEndBefore(table!);
    return range.toString();
  });
  expect(beforeLabels.match(/closes nothing|Nothing was closed|nothing was closed/gi)?.length, "the fact is said once before the first label").toBe(1);
  await expect(page.getByTestId("assess-retest-view")).not.toContainText("Nothing was closed: this is one replay");
  // One count line, not a line and five tiles with the same five numbers.
  await expect(page.getByTestId("assess-retest-counts")).toHaveCount(0);
  await expect(page.getByTestId("assess-retest-summary-line")).toHaveText("5 findings chosen: 1 reproduced, 2 not reproduced, 1 inconclusive, 1 not labelled.");
  const labels = await page.getByTestId("assess-retest-result-label").allInnerTexts();
  expect(labels.map((l) => l.trim())).toEqual(["Reproduced", "Not reproduced", "Inconclusive", "Not reproduced"]);
  // The earlier finding's own title, and the evidence in the words findings use: a match, a log that does not back the label (with its reason as a sentence), and no reading for an inconclusive one.
  const results = page.getByTestId("assess-retest-result");
  await expect(results.nth(0)).toContainText("Entry search is injectable");
  await expect(results.nth(0).getByTestId("assess-retest-result-evidence")).toContainText("Helper log backs the label");
  await expect(results.nth(1).getByTestId("assess-retest-result-evidence")).toContainText("No log");
  await expect(results.nth(2).getByTestId("assess-retest-result-evidence")).toContainText("an inconclusive label claims nothing");
  await expect(results.nth(3)).toContainText("The health route no longer lists the address.");
  // The finding the agent gave no label is named, and nothing is said to be closed for it.
  await expect(page.getByTestId("assess-retest-missing")).toContainText("F-6");
  // A retest has no export, no copy and no import: the footer says why.
  await expect(page.getByTestId("assess-retest-no-export")).toContainText("A retest has no export of its own");
  await expect(page.getByRole("dialog").last().getByRole("button", { name: /Export|Copy/ })).toHaveCount(0);
  // The requests the labels cite are the helper's records, each tagged with the finding it replayed.
  await expect(page.getByTestId("assess-retest-probes")).toContainText("Replay of F-1");
  await expect(page.getByTestId("assess-retest-probes")).toContainText("The log is a file the agent can write.");
  noRawWords(await view.innerText(), "retest results");
  // The second tab lists what it was asked to replay; the third carries the limits of a pen test, the retest's own among them.
  await modelTab(page, "Replayed").click();
  await expect(page.getByTestId("assess-retest-asked")).toHaveCount(5);
  await expect(page.getByTestId("assess-retest-asked").nth(4)).toContainText("(no label was given)");
  noRawWords(await page.getByTestId("assess-retest-replayed").innerText(), "retest replayed");
  await modelTab(page, "How checked").click();
  await expect(page.getByRole("dialog").last()).toContainText("A retest closes nothing and changes no finding's status.");
  // N-19: the sentence that says where the labels are shown has a control under it, and it opens the run the retest replayed.
  await modelTab(page, /^Results/).click();
  await page.getByTestId("assess-retest-open-replayed").click();
  await expect(page.getByTestId("assess-retest-view")).toHaveCount(0);
  await expect(page.getByRole("dialog").last()).toContainText("Penetration test");
  await modelTab(page, /^Findings/).click();
  await expect(page.getByTestId("assess-retest-line").first()).toBeVisible();
  expect(wire.launches).toHaveLength(0);
});

test("a finding's row shows its newest retest label in words, with the evidence word, the date, a short Not closed tag and the older retests behind a disclosure; the sentence is printed once above the findings", async ({ page }) => {
  await mountArc(page);
  await openModelOf(page, ID.ptRetested);
  await modelTab(page, /^Findings/).click();
  const line = (id: string) => page.getByTestId("assess-retest-line").and(page.locator(`[data-finding-id="${id}"]`));
  const f1 = line("F-1");
  await expect(f1.getByTestId("assess-retest-label")).toContainText("Reproduced");
  await expect(f1.getByTestId("assess-retest-label")).toContainText("Helper log backs the label");
  await expect(f1.getByTestId("assess-retest-date")).toHaveText(/\d{4}/);
  // N-13: every labelled row carries the short tag; the full sentence is the tag's description and is printed once, in the Retest block over the table.
  const SENTENCE = "Nothing was closed: this is one replay of the stored request, read against the stored condition.";
  await expect(f1.getByTestId("assess-retest-closed")).toHaveText("Not closed");
  for (const id of ["F-1", "F-2", "F-3", "F-5"]) {
    await expect(line(id).getByTestId("assess-retest-closed")).toHaveText("Not closed");
    await expect(line(id)).not.toContainText(SENTENCE);
  }
  const note = page.getByTestId("assess-retest-closed-note");
  await expect(note).toHaveCount(1);
  await expect(note).toHaveText(SENTENCE);
  await expect(page.getByTestId("assess-retest-action").getByTestId("assess-retest-closed-note")).toHaveCount(1);
  const noteId = await note.getAttribute("id");
  expect(noteId).toBeTruthy();
  await expect(f1.getByTestId("assess-retest-closed")).toHaveAttribute("aria-describedby", noteId!);
  expect(await page.getByRole("dialog").last().innerText()).toContain(SENTENCE);
  expect(((await page.getByRole("dialog").last().innerText()).match(/Nothing was closed: this is one replay/g) ?? []).length, "the sentence is in the findings tab once").toBe(1);
  // Hovering the tag shows the sentence as its tooltip.
  await f1.getByTestId("assess-retest-closed").hover();
  await expect(page.getByRole("tooltip").first()).toContainText(SENTENCE);
  await expect(f1).toContainText("Older retests (1)");
  // The label of F-2 is the newer retest's: the log does not back it, and the reason is a sentence.
  const f2 = line("F-2");
  await expect(f2.getByTestId("assess-retest-label")).toContainText("Not reproduced");
  await expect(f2.getByTestId("assess-retest-label")).toContainText("No log");
  await expect(f2.getByTestId("assess-retest-reason")).not.toBeEmpty();
  // N-11: the older retest said reproduced, and it is behind a disclosure under a newer label that has no log: the row says so, with the older retest's date and what its log is.
  const standing = f2.getByTestId("assess-retest-standing");
  await expect(standing).toContainText("The newer label has no log behind it. An older retest (");
  await expect(standing).toContainText(") labelled this finding reproduced, with no log behind that label either.");
  await expect(standing).toContainText("2026");
  await expect(f2).toContainText("Older retests (1)");
  // F-1's newer label is reproduced and backed, F-3 and F-5 have one label each: nothing to add.
  for (const id of ["F-1", "F-3", "F-5"]) await expect(line(id).getByTestId("assess-retest-standing")).toHaveCount(0);
  await expect(line("F-3").getByTestId("assess-retest-label")).toContainText("Inconclusive");
  // A finding no retest labelled has no line; nothing marks any finding closed or fixed.
  await expect(line("F-4")).toHaveCount(0);
  await expect(line("F-6")).toHaveCount(0);
  const rows = await page.getByTestId("assess-retest-line").allInnerTexts();
  for (const t of rows) {
    noRawWords(t, "label line");
    expect(t).not.toMatch(/\b(fixed|resolved|passed|safe|secure)\b/i);
  }
  // The label's button opens the retest run's own view.
  await f1.getByRole("button", { name: "Open the retest that labelled F-1" }).click();
  await expect(page.getByTestId("assess-retest-view")).toBeVisible();
});

test("an open finding says what each retest found, with the agent's note as text", async ({ page }) => {
  await mountArc(page);
  await openModelOf(page, ID.ptRetested);
  await modelTab(page, /^Findings/).click();
  await page.getByRole("button", { name: "Details of F-1" }).click();
  const history = page.getByTestId("assess-retest-history").and(page.locator('[data-finding-id="F-1"]'));
  await expect(history).toBeVisible();
  await expect(history.getByTestId("assess-retest-entry")).toHaveCount(2);
  await expect(history).toContainText("The same search term returned every entry again.");
  await expect(history).toContainText("The search answered with the ordinary list.");
  noRawWords(await history.innerText(), "retest history");
});

for (const scheme of ["light", "dark"] as const) {
  test(`at phone width, in ${scheme}, the picker, the retest plan, the Exercise tab, the retest view and a finding's label fit without sideways scroll`, async ({ page }) => {
    await page.setViewportSize(PHONE);
    await page.emulateMedia({ colorScheme: scheme });
    await mountArc(page);
    const pageOverflow = () => page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
    // The Exercise tab of a red team run.
    await openModelOf(page, ID.redTeam);
    await expect(page.getByTestId("assess-exercise")).toBeVisible();
    expect(await dialogBodyOverflow(page), "exercise").toBeLessThanOrEqual(1);
    await modelTab(page, /^Findings/).click();
    expect(await dialogBodyOverflow(page), "red team findings").toBeLessThanOrEqual(1);
    await page.keyboard.press("Escape");
    // A pen test's findings with labels, the picker and the plan.
    await openModelOf(page, ID.ptRetested);
    await modelTab(page, /^Findings/).click();
    await expect(page.getByTestId("assess-retest-line").first()).toBeVisible();
    expect(await dialogBodyOverflow(page), "labelled findings").toBeLessThanOrEqual(1);
    await page.getByTestId("assess-retest-action").getByRole("button", { name: "Retest findings" }).click();
    await expect(page.getByTestId("assess-retest-picker")).toBeVisible();
    expect(await topDialogOverflow(page), "picker").toBeLessThanOrEqual(1);
    await page.getByTestId("assess-retest-open-plan").click();
    await expect(page.getByTestId("assess-retest-plan")).toBeVisible();
    expect(await topDialogOverflow(page), "retest plan").toBeLessThanOrEqual(1);
    await page.keyboard.press("Escape");
    await page.keyboard.press("Escape");
    await expect(page.getByRole("dialog")).toHaveCount(0);
    // The retest's own view, each tab.
    await openModelOf(page, ID.retestNew);
    await expect(page.getByTestId("assess-retest-view")).toBeVisible();
    expect(await dialogBodyOverflow(page), "retest results").toBeLessThanOrEqual(1);
    await modelTab(page, "Replayed").click();
    expect(await dialogBodyOverflow(page), "retest replayed").toBeLessThanOrEqual(1);
    await modelTab(page, "How checked").click();
    expect(await dialogBodyOverflow(page), "retest checked").toBeLessThanOrEqual(1);
    await page.keyboard.press("Escape");
    expect(await pageOverflow(), "page").toBe(0);
  });
}

// ---------------------------------------------------------------- the second review (2026-11-16)
//
// What was built after the first review: the CVSS 4.0 base score on pen test and
// red team findings (W7.1), the retest plan and its refusals (W7.2) and the red
// team's objective and chain (W7.3). Report: docs/audits/security-assessments-
// e2e-review-2026-11-16.md. Synthetic data only: fixturePtCvss and the plan
// overrides below carry the server's own sentences and shapes.

const SERVER_WORDS = {
  helper:
    "A retest needs the request helper: it sends the stored requests and logs them, and a label with no log behind it is not worth a run. The helper is off, or was left out because python3 was not found, so nothing was started. Turn on \"Request helper for penetration tests\" in Settings > Guard > Code security, and install python3 on this machine if it was left out.",
  noRequest: "The finding F-4 has no stored request to replay (its reproduction is code or text only). Leave it out. Nothing was started.",
};

/** mountCvss mounts the arc's runs with the pen test of ID.ptChecked answering with the CVSS fixture (F-1 critical both ways, F-2 rated medium with a 0.0 vector, F-3 rated low with a medium vector, F-4 whose vector was dropped). */
async function mountCvss(page: Page): Promise<Wire> {
  const wire = newWire(runsWithRetests());
  wire.models = { [ID.ptChecked]: fixturePtCvss() };
  await mount(page, wire);
  return wire;
}

/** openFindingDetails opens the model of ID.ptChecked on its Findings tab and the details of one finding. */
async function openFinding(page: Page, finding: string): Promise<Locator> {
  await page.getByRole("button", { name: `Details of ${finding}` }).click();
  const detail = page.getByTestId("assess-finding-detail").and(page.locator(`[data-finding-id="${finding}"]`));
  await expect(detail).toBeVisible();
  return detail;
}

async function openCvssFindings(page: Page): Promise<void> {
  await openModelOf(page, ID.ptChecked);
  await modelTab(page, /^Findings/).click();
  await expect(page.getByTestId("assess-findings")).toBeVisible();
}

/** insideViewport says an element's whole box is inside the viewport sideways (nothing to pan to). */
async function insideViewport(page: Page, el: Locator): Promise<boolean> {
  const box = await el.boundingBox();
  const width = page.viewportSize()!.width;
  return !!box && box.x >= 0 && box.x + box.width <= width + 1;
}

test("CVSS: an open finding shows the vector, Observer's base score and band, the note and a line saying it is apart from the table's Band, with no pill of its own", async ({ page }) => {
  await mountCvss(page);
  await openCvssFindings(page);
  // The table's Band column is still the agent's likelihood times impact, whatever the vectors score.
  const bandOf = (id: string) => page.locator("tr", { has: page.locator(`[data-testid="assess-finding"][data-finding-id="${id}"]`) }).first();
  await expect(bandOf("F-1")).toContainText("critical 20");
  await expect(bandOf("F-2")).toContainText("medium 9");
  await expect(bandOf("F-3")).toContainText("low 4");
  await expect(bandOf("F-4")).toContainText("high 12");
  // F-1: critical by both readings.
  const f1 = await openFinding(page, "F-1");
  const block = f1.getByTestId("assess-finding-cvss");
  await expect(block).toContainText("CVSS 4.0 base vector");
  await expect(block).toContainText(CVSS_CRITICAL);
  await expect(block).toContainText("Base score 9.3 (critical), computed by Observer from the vector.");
  await expect(block).toContainText("Base score of the weakness as logged in an in-box copy, not a production risk.");
  // The two readings are told apart where they meet: the sentence is in the block, once.
  await expect(block.getByTestId("assess-finding-cvss-apart")).toHaveText("This is a separate reading from the Band in the table, which is the agent's likelihood times impact. Neither changes the other.");
  // The score is text, not a second severity pill: nothing in the block wears a tone.
  await expect(block.locator('[class*="rounded-pill"]')).toHaveCount(0);
  noRawWords(await block.innerText(), "cvss block");
  // F-3 is rated low by the agent and medium by its vector: the table says low, the block says medium and that it is apart.
  await page.getByRole("button", { name: "Details of F-1" }).click();
  const f3 = await openFinding(page, "F-3");
  await expect(f3.getByTestId("assess-finding-cvss")).toContainText("Base score 6.9 (medium)");
  await expect(f3.getByTestId("assess-finding-cvss-apart")).toBeVisible();
  await expect(bandOf("F-3")).toContainText("low 4");
  // A finding that has no vector says nothing about CVSS in its row.
  await page.getByRole("button", { name: "Details of F-3" }).click();
  const f4 = await openFinding(page, "F-4");
  await expect(f4.getByTestId("assess-finding-cvss")).toHaveCount(0);
  await expect(f4.getByTestId("assess-finding-cvss-apart")).toHaveCount(0);
});

test("CVSS: a vector that scores 0.0 is a score with no band, shown with its vector and without a placeholder", async ({ page }) => {
  await mountCvss(page);
  await openCvssFindings(page);
  const f2 = await openFinding(page, "F-2");
  const block = f2.getByTestId("assess-finding-cvss");
  await expect(block).toContainText("Base score 0.0 (no band), computed by Observer from the vector.");
  await expect(block).toContainText("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N");
  const text = await block.innerText();
  expect(text).not.toMatch(/undefined|NaN|\bnull\b|\[object|\(critical\)|\(low\)|\(medium\)|\(high\)/);
  // The agent rated it medium and its vector has no impact: the two readings disagree in plain sight, and the block says they are separate.
  await expect(f2.getByTestId("assess-finding-cvss-apart")).toBeVisible();
});

test("CVSS: a vector Observer could not read is left out and named under How checked, in the server's words, with the check's code only behind Details", async ({ page }) => {
  await mountCvss(page);
  await openCvssFindings(page);
  await modelTab(page, "How checked").click();
  const issues = page.getByTestId("assess-issues");
  await expect(issues).toContainText("Left out (1)");
  const issue = issues.getByTestId("assess-issue");
  await expect(issue).toContainText("The CVSS vector of finding F-4 carries a threat, environmental or supplemental metric");
  await expect(issue).not.toContainText("this finding");
  await expect(issue).toContainText("so it was left out. The finding keeps its likelihood and impact rating.");
  // The check's row and code are technical details, never in the sentence.
  expect(await issue.locator("> div").first().innerText()).not.toMatch(/bad_cvss_dropped|\bV5\b/);
  await issue.getByRole("button", { name: "Details" }).click();
  await expect(issue.getByTestId("assess-issue-technical")).toContainText("bad_cvss_dropped");
});

// N-9 (second review, fixed in fix round 4): the sentence under How checked names the finding (F-4), and the finding's own row says its vector was left out, so a reader of the finding does not take it for one the agent never wrote.
test("CVSS: the finding whose vector was left out says so in its own row, not only under How checked", async ({ page }) => {
  await mountCvss(page);
  await openCvssFindings(page);
  const f4 = await openFinding(page, "F-4");
  const note = f4.getByTestId("assess-finding-cvss-left-out");
  await expect(note).toContainText("The agent wrote a CVSS vector for this finding that was left out, so there is no CVSS reading. How checked says why.");
  await expect(f4).toContainText(/CVSS .*left out/i);
  // No vector or score is shown for it, and the pinned separate-reading sentence belongs to a score that exists.
  await expect(f4.getByTestId("assess-finding-cvss")).toHaveCount(0);
  await expect(f4.getByTestId("assess-finding-cvss-apart")).toHaveCount(0);
  // A finding that kept its vector carries no such note.
  await page.getByRole("button", { name: "Details of F-4" }).click();
  const f1 = await openFinding(page, "F-1");
  await expect(f1.getByTestId("assess-finding-cvss-left-out")).toHaveCount(0);
});

for (const scheme of ["light", "dark"] as const) {
  test(`CVSS at phone width, in ${scheme}: the opened row's vector, score and notes are on screen without panning the table`, async ({ page }) => {
    await page.setViewportSize(PHONE);
    await page.emulateMedia({ colorScheme: scheme });
    await mountCvss(page);
    await openCvssFindings(page);
    expect(await dialogBodyOverflow(page), "findings").toBeLessThanOrEqual(1);
    for (const id of ["F-1", "F-2"]) {
      const detail = await openFinding(page, id);
      const block = detail.getByTestId("assess-finding-cvss");
      await block.scrollIntoViewIfNeeded();
      // The vector is one unbroken string: it must wrap inside what is on screen, as must the score line and both notes.
      for (const part of [block.locator("code"), block.locator("p").nth(0), block.getByTestId("assess-finding-cvss-apart")]) {
        expect(await insideViewport(page, part), `${id}: a line of the CVSS block runs off the screen`).toBe(true);
      }
      expect(await insideViewport(page, detail.getByTestId("assess-finding-evidence")), `${id}: the evidence boxes run off the screen`).toBe(true);
      await page.getByRole("button", { name: `Details of ${id}` }).click();
    }
    expect(await dialogBodyOverflow(page), "after opening").toBeLessThanOrEqual(1);
    expect(await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth), "page").toBe(0);
  });
}

test("the threat table's opened row also fits the screen at phone width", async ({ page }) => {
  await page.setViewportSize(PHONE);
  await mount(page);
  await runRow(page, ID.tmNew).getByRole("button", { name: "Open model" }).click();
  await expect(page.getByTestId("assess-model")).toBeVisible();
  await page.getByRole("tab", { name: /^Threats/ }).click();
  const first = page.getByRole("button", { name: /^Details of / }).first();
  await first.click();
  const detail = page.getByTestId("assess-threat-detail").first();
  await expect(detail).toBeVisible();
  expect(await insideViewport(page, detail), "the opened threat runs off the screen").toBe(true);
});

test("a retest plan the server refuses for a finding names that finding in words, keeps Choose agent off, says nothing was started and offers no task", async ({ page }) => {
  const wire = newWire(runsWithRetests());
  wire.planFor = (u) => {
    const p = planFor(u);
    if (u.searchParams.get("kind") !== "pentest_retest") return p;
    const retest = p.retest as Json;
    return { ...p, ok: false, code: "retest_findings", reason: SERVER_WORDS.noRequest, retest: { ...retest, refused: [{ finding: "F-4", code: "no_request" }], selected: ["F-1"] } };
  };
  await mount(page, wire);
  await openModelOf(page, ID.ptRetested);
  await modelTab(page, /^Findings/).click();
  await page.getByTestId("assess-retest-action").getByRole("button", { name: "Retest findings" }).click();
  await page.getByTestId("assess-retest-open-plan").click();
  const plan = page.getByTestId("assess-plan");
  await expect(plan).toBeVisible();
  // The refused finding is named once, in words, in the retest block; the notice that nothing can start points at that list and says nothing was started (N-10), and the footer points at the notice.
  await expect(page.getByTestId("assess-retest-refused")).toContainText("F-4 has no stored request to replay: its reproduction is code or text only.");
  await expect(plan).toContainText("This cannot start here");
  await expect(plan).toContainText("Nothing was started.");
  await expect(plan.getByText("has no stored request to replay")).toHaveCount(1);
  await expect(page.getByRole("button", { name: "Choose agent" })).toBeDisabled();
  await expect(page.getByTestId("assess-prompt-text")).toHaveCount(0);
  await expect(page.getByTestId("assess-choose-reason")).toHaveText("Nothing can start here. The reason is in the note above.");
  expect(wire.launches).toHaveLength(0);
  // The words this arc added to the plan, and the notice, carry no code (the rest of the dialog is the existing plan's and names node_modules and the like).
  noRawWords(await page.getByTestId("assess-retest-plan").innerText(), "refused retest block");
  noRawWords(await plan.getByRole("note").filter({ hasText: "This cannot start here" }).innerText(), "refused retest notice");
  expect(await plan.innerText()).not.toMatch(/retest_findings|no_request/);
});

test("a retest plan the server refuses because the request helper is off says what to do and that nothing was started, and the dialog still fits a phone", async ({ page }) => {
  await page.setViewportSize(PHONE);
  const wire = newWire(runsWithRetests());
  wire.planFor = (u) => {
    const p = planFor(u);
    if (u.searchParams.get("kind") !== "pentest_retest") return p;
    return { ...p, ok: false, code: "retest_helper", reason: SERVER_WORDS.helper, probe: { state: "off", files: [], dir: "", budget: 0, pace_rps: 0 } };
  };
  await mount(page, wire);
  await openModelOf(page, ID.ptRetested);
  await modelTab(page, /^Findings/).click();
  await page.getByTestId("assess-retest-action").getByRole("button", { name: "Retest findings" }).click();
  await page.getByTestId("assess-retest-open-plan").click();
  await expect(page.getByTestId("assess-plan")).toBeVisible();
  await expect(page.getByRole("dialog").last()).toContainText("This cannot start here");
  // The helper's refusal is four sentences: in the note once, and the footer next to the button points at it instead of printing it again.
  await expect(page.getByRole("dialog").last()).toContainText('Turn on "Request helper for penetration tests" in Settings > Guard > Code security, and install python3 on this machine if it was left out.');
  await expect(page.getByRole("dialog").last().getByText("install python3 on this machine")).toHaveCount(1);
  // N-10: the sentence has a control that takes the person to that switch, and so has the plan's own helper line, which says the same switch is off.
  const settingLinks = page.getByRole("dialog").last().getByTestId("assess-setting-link");
  await expect(settingLinks).toHaveCount(2);
  await expect(page.getByRole("note").getByTestId("assess-setting-link")).toHaveText('Open the setting "Request helper for penetration tests"');
  for (const link of await settingLinks.all()) {
    await expect(link).toHaveAttribute("href", "/settings?section=guard#security.assessments.probe_helper");
  }
  await expect(page.getByTestId("assess-choose-reason")).toHaveText("Nothing can start here. The reason is in the note above.");
  await expect(page.getByRole("button", { name: "Choose agent" })).toBeDisabled();
  expect(await topDialogOverflow(page), "refused retest plan").toBeLessThanOrEqual(1);
  expect(wire.launches).toHaveLength(0);
});

/** findingsTableFit is how far the findings table runs past the box that holds it (0: every column, the last included, is inside), and whether its box scrolls. */
async function findingsTableFit(page: Page): Promise<{ past: number; scrolls: boolean; headers: string[] }> {
  return page.getByTestId("assess-findings").evaluate((root) => {
    const table = root.querySelector("table")!;
    let box: HTMLElement = table.parentElement!;
    while (box !== root && !/(auto|scroll)/.test(getComputedStyle(box).overflowX)) box = box.parentElement!;
    const last = [...table.querySelectorAll("thead th")].pop()!.getBoundingClientRect().right;
    const edge = box.getBoundingClientRect().right;
    return { past: Math.max(0, Math.round(last - edge)), scrolls: box.scrollWidth > box.clientWidth + 1, headers: [...table.querySelectorAll("thead th")].map((h) => (h.textContent ?? "").trim()) };
  });
}

test("at 1280 the findings table fits the dialog with its last column on screen, with the status said once when every finding states the same one, and with its column when they differ (UX-15)", async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 900 });
  // A real run's findings all state "open": the column is one repeated word, so it is left out and said once.
  const wire = await mountArc(page);
  await openModelOf(page, ID.ptRetested);
  await modelTab(page, /^Findings/).click();
  await expect(page.getByTestId("assess-findings-status-note")).toHaveText(`The agent states every finding as "Open". The status is the agent's own claim.`);
  const same = await findingsTableFit(page);
  expect(same.headers).not.toContain("Status");
  expect(same.headers.at(-1)).toBe("Cited places");
  expect(same.scrolls, "the table scrolls sideways in a 1240 px dialog").toBe(false);
  expect(same.past, "the last column runs past the table's box").toBe(0);
  expect(wire.launches).toHaveLength(0);
  await page.keyboard.press("Escape");
  // Findings that state different statuses keep the column, the sort and the room.
  const model = JSON.parse(JSON.stringify(ARC_PT_RETESTED)) as AssessModelResponse;
  model.record.result.pt!.findings![0].status = "identified";
  const mixedWire = newWire(runsWithRetests());
  mixedWire.models = { [ID.ptRetested]: model };
  await mount(page, mixedWire);
  await openModelOf(page, ID.ptRetested);
  await modelTab(page, /^Findings/).click();
  await expect(page.getByTestId("assess-findings-status-note")).toHaveCount(0);
  const mixed = await findingsTableFit(page);
  expect(mixed.headers).toContain("Status");
  expect(mixed.headers.at(-1)).toBe("Cited places");
  expect(mixed.scrolls, "the table scrolls sideways in a 1240 px dialog").toBe(false);
  expect(mixed.past, "the last column runs past the table's box").toBe(0);
});

test("a retest of findings with a hidden value says what that means once, with a short note on each finding that has one, in the picker and in the plan", async ({ page }) => {
  // Most findings of a real run carry a session header, so most have a hidden value: four of the five here.
  const model = JSON.parse(JSON.stringify(ARC_PT_RETESTED)) as AssessModelResponse;
  for (const f of model.record.result.pt!.findings!) {
    if (["F-1", "F-5", "F-6"].includes(f.id)) f.reproduction = [{ step: "Ask as the second account", request: { method: "GET", path: `/api/${f.id}`, headers: [{ name: "Authorization", value: "[REDACTED]" }] } }];
  }
  const wire = newWire(runsWithRetests());
  wire.models = { [ID.ptRetested]: model };
  wire.planFor = (u) => {
    const p = planFor(u);
    if (u.searchParams.get("kind") !== "pentest_retest") return p;
    const retest = p.retest as Json;
    return { ...p, retest: { ...retest, findings: (retest.findings as Json[]).map((f) => ({ ...f, hidden: true })) } };
  };
  await mount(page, wire);
  await openModelOf(page, ID.ptRetested);
  await modelTab(page, /^Findings/).click();
  await page.getByTestId("assess-retest-action").getByRole("button", { name: "Retest findings" }).click();
  const picker = page.getByTestId("assess-retest-picker");
  const consequence = "For a finding with a hidden value the replay is not the original request, so a not reproduced label for it cannot be backed by the log.";
  const short = "A stored value was hidden when the finding was kept.";
  const count = (text: string, part: string) => text.split(part).length - 1;
  let text = await picker.innerText();
  expect(count(text, short), "a short note on each finding that has a hidden value").toBe(4);
  expect(count(text, consequence), "what it means, once").toBe(1);
  await expect(picker.getByTestId("assess-retest-hidden-once")).toHaveCount(1);
  // Only the one finding the replay can send in full is chosen; the four with a hidden value are listed after it and chosen by the person, knowing what it means.
  await expect(picker.getByRole("checkbox", { checked: true })).toHaveCount(1);
  await expect(page.getByTestId("assess-retest-choose-F-3")).toBeChecked();
  for (const id of ["F-1", "F-2", "F-5", "F-6"]) await page.getByTestId(`assess-retest-choose-${id}`).check();
  await expect(page.getByTestId("assess-retest-count")).toHaveText("5 of 8 findings chosen");
  await page.getByTestId("assess-retest-open-plan").click();
  const block = page.getByTestId("assess-retest-plan");
  await expect(block).toBeVisible();
  text = await block.innerText();
  expect(count(text, short)).toBeGreaterThanOrEqual(4);
  expect(count(text, consequence)).toBe(1);
  // Nothing was started by looking.
  expect(wire.launches).toHaveLength(0);
});

// N-21 (second review, fixed in fix round 4): on the live node 12 of 16 candidate findings carried a hidden value (a session header the replay cannot send), so the default eight were mostly findings a retest cannot back. The picker now starts with the ones the replay can send in full and lists the others after them with the reason.
test("a retest of a real run's findings, twelve of sixteen with a hidden session header, starts with the four the replay can send in full and lists the rest after them with the reason", async ({ page }) => {
  const model = JSON.parse(JSON.stringify(ARC_PT_RETESTED)) as AssessModelResponse;
  const base = model.record.result.pt!.findings![0];
  const hiddenIds: string[] = [];
  const findings = Array.from({ length: 16 }, (_, i) => {
    const id = `F-${i + 1}`;
    const hidden = i % 4 !== 0; // F-1, F-5, F-9 and F-13 carry nothing hidden
    if (hidden) hiddenIds.push(id);
    return {
      ...JSON.parse(JSON.stringify(base)),
      id,
      title: `Finding number ${i + 1}`,
      reproduction: [{ step: "Ask for the page", request: { method: "GET", path: `/api/${id}`, headers: hidden ? [{ name: "Cookie", value: "[REDACTED]" }] : [] } }],
    };
  });
  model.record.result.pt!.findings = findings;
  const wire = newWire(runsWithRetests());
  wire.models = { [ID.ptRetested]: model };
  // The plan answers for whatever the picker asked, with the hidden flag of each finding.
  wire.planFor = (u) => {
    const p = planFor(u);
    if (u.searchParams.get("kind") !== "pentest_retest") return p;
    const asked = u.searchParams.getAll("finding");
    const stored = findings.map((f) => ({ id: f.id, title: f.title, category: "ATHN", steps: 1, has_condition: false, ...(hiddenIds.includes(f.id) ? { hidden: true } : {}) }));
    return { ...p, retest: { ...(p.retest as Json), findings: stored, selected: asked } };
  };
  await mount(page, wire);
  await openModelOf(page, ID.ptRetested);
  await modelTab(page, /^Findings/).click();
  const action = page.getByTestId("assess-retest-action");
  await expect(action).toContainText("16 findings have a stored request to replay. 4 can be sent again in full and are chosen. 12 have a value that was hidden when the finding was kept; they are listed after and none of them is chosen for you. A retest replays at most 8: choose which.");
  await action.getByRole("button", { name: "Retest findings" }).click();
  const picker = page.getByTestId("assess-retest-picker");
  await expect(picker.getByRole("checkbox")).toHaveCount(16);
  // Not the first eight: the four that can be sent in full, and nothing else.
  await expect(picker.getByRole("checkbox", { checked: true })).toHaveCount(4);
  for (const id of ["F-1", "F-5", "F-9", "F-13"]) await expect(page.getByTestId(`assess-retest-choose-${id}`)).toBeChecked();
  await expect(page.getByTestId("assess-retest-count")).toHaveText("4 of 8 findings chosen");
  // Two groups, the findings that can be sent first, each with its count; the reason once, on the group that needs it.
  await expect(picker).toContainText("Can be sent again in full (4)");
  await expect(picker).toContainText("Had a value hidden (12)");
  const full = page.getByTestId("assess-retest-full");
  const hidden = page.getByTestId("assess-retest-hidden");
  await expect(full.getByTestId("assess-retest-choice")).toHaveCount(4);
  await expect(hidden.getByTestId("assess-retest-choice")).toHaveCount(12);
  await expect(full).not.toContainText("A stored value was hidden when the finding was kept.");
  const hiddenText = await hidden.innerText();
  expect(hiddenText.split("A stored value was hidden when the finding was kept.").length - 1).toBe(12);
  expect(hiddenText.split("so a not reproduced label for it cannot be backed by the log.").length - 1, "the consequence, once").toBe(1);
  expect(hiddenText).toContain("You can still choose one. A replay without that value can show a weakness is there, but it cannot show it is gone.");
  await expect(picker.getByTestId("assess-retest-hidden-once")).toHaveCount(1);
  // The four come before the twelve on the page.
  const order = await picker.getByTestId("assess-retest-choice").evaluateAll((els) => els.map((e) => e.getAttribute("data-finding-id")));
  expect(order.slice(0, 4)).toEqual(["F-1", "F-5", "F-9", "F-13"]);
  expect(order.slice(4)).toEqual(hiddenIds);
  noRawWords(await picker.innerText(), "picker over a real run");
  // A finding with a hidden value can still be chosen; the plan is asked for exactly the choice, in the order chosen.
  await page.getByTestId("assess-retest-choose-F-2").check();
  await expect(page.getByTestId("assess-retest-count")).toHaveText("5 of 8 findings chosen");
  await page.getByTestId("assess-retest-open-plan").click();
  await expect(page.getByTestId("assess-retest-plan")).toBeVisible();
  await expect.poll(() => wire.plans.at(-1)?.searchParams.getAll("finding")).toEqual(["F-1", "F-5", "F-9", "F-13", "F-2"]);
  expect(wire.launches).toHaveLength(0);
  expect(await topDialogOverflow(page), "retest plan over sixteen findings").toBeLessThanOrEqual(1);
});

test("a run whose every finding has a hidden value opens the picker with none chosen, the button off, and the findings still selectable", async ({ page }) => {
  const model = JSON.parse(JSON.stringify(ARC_PT_RETESTED)) as AssessModelResponse;
  for (const f of model.record.result.pt!.findings!) {
    f.reproduction = [{ step: "Ask as the second account", request: { method: "GET", path: `/api/${f.id}`, headers: [{ name: "Authorization", value: "[REDACTED]" }] } }];
  }
  const wire = newWire(runsWithRetests());
  wire.models = { [ID.ptRetested]: model };
  await mount(page, wire);
  await openModelOf(page, ID.ptRetested);
  await modelTab(page, /^Findings/).click();
  await page.getByTestId("assess-retest-action").getByRole("button", { name: "Retest findings" }).click();
  const picker = page.getByTestId("assess-retest-picker");
  await expect(picker.getByRole("checkbox", { checked: true })).toHaveCount(0);
  await expect(page.getByTestId("assess-retest-count")).toHaveText("0 of 8 findings chosen");
  await expect(page.getByTestId("assess-retest-offer")).toContainText("Every one has a value that was hidden when the finding was kept, so none is chosen for you.");
  await expect(page.getByTestId("assess-retest-open-plan")).toBeDisabled();
  // Still selectable: choosing one turns the button on.
  await page.getByTestId("assess-retest-choose-F-1").check();
  await expect(page.getByTestId("assess-retest-open-plan")).toBeEnabled();
  await expect(page.getByTestId("assess-retest-count")).toHaveText("1 of 8 findings chosen");
});

test("a retest run that ended with nothing never says its findings were replayed, and a run name does not nest parentheses", async ({ page }) => {
  const dead = run({
    id: "00000000000000f9",
    created_at: "2026-11-16T10:00:00Z",
    kind: "pentest_retest",
    kind_title: "Retest of earlier findings (your own app, local)",
    contract: "retest.v1",
    retest_of: ID.ptRetested,
    retest_findings: ["F-1", "F-2", "F-3"],
    state: "ended_empty",
    has_model: undefined,
    validation: undefined,
    files: { report: false, sarif: false, commands: false },
    report_bytes: 0,
  });
  await mount(page, newWire([...runsWithRetests(), dead]));
  const rows = page.getByTestId("assess-run");
  const row = rows.nth(runsWithRetests().length);
  await expect(row).toContainText("ended without a result");
  const line = await row.getByTestId("assess-run-retest-of").innerText();
  expect(line).toBe("Retest of the earlier run (Penetration test, Nov 15, 2026, 09:00): 3 findings chosen.");
  expect(line).not.toMatch(/replayed/);
  // Beside it, a retest that finished: the same words, and every row names its earlier run by what it is and when, without a parenthesis inside a parenthesis.
  for (const id of [ID.retestNew, ID.retestOld]) {
    const t = await retestRunRow(page, id).getByTestId("assess-run-retest-of").innerText();
    expect(t).toMatch(/^Retest of the earlier run \(Penetration test, [A-Z][a-z]{2} \d+, 20\d\d, \d\d:\d\d\): \d findings? chosen\.$/);
    expect(t).not.toMatch(/\([^()]*\([^()]*\)/);
  }
});

test("a retest label never wears the colour of a pass, and its evidence pill says the log backs the label rather than matches it", async ({ page }) => {
  await mountArc(page);
  await openModelOf(page, ID.ptRetested);
  await modelTab(page, /^Findings/).click();
  const line = (id: string) => page.getByTestId("assess-retest-line").and(page.locator(`[data-finding-id="${id}"]`));
  // F-5 is "Not reproduced" with a log that backs it: the pair that read as a contradiction when the second pill said "matches".
  const f5 = line("F-5").getByTestId("assess-retest-label");
  await expect(f5).toContainText("Not reproduced");
  await expect(f5).toContainText("Helper log backs the label");
  await expect(f5).not.toContainText("matches");
  for (const id of ["F-1", "F-2", "F-3", "F-5"]) {
    await expect(line(id).locator('[class*="success"]'), `${id}: a label in the colour of a pass`).toHaveCount(0);
  }
  // The finding keeps its status: still open in the table, whatever the label says.
  const row = page.locator("tr", { has: page.locator('[data-testid="assess-finding"][data-finding-id="F-5"]') }).first();
  await expect(row).toContainText("Open");
  // And the label sits on the finding's own row, next to its band, so it reads as a note on the finding and not as a replacement for its state.
  await expect(row).toContainText("medium 9");
});

test("the red team plan carries the objective into the launch, and a launch with none carries none", async ({ page }) => {
  const wire = await mount(page);
  await openPlan(page, "Red team");
  await page.getByTestId("assess-target").getByRole("radio").first().click();
  await page.getByTestId("assess-confirm").getByRole("checkbox").check();
  const input = page.getByTestId("assess-objective-input");
  await input.fill("Reach the export route without signing in");
  await input.press("Enter");
  await expect.poll(() => wire.plans.at(-1)?.searchParams.get("objective")).toBe("Reach the export route without signing in");
  await expect(page.getByTestId("assess-prompt-text")).toContainText("Objective: Reach the export route without signing in");
  await page.getByRole("button", { name: "Choose agent" }).click();
  await expect(page.getByTestId("new-terminal-task")).toBeVisible();
  await page.getByRole("button", { name: "Start", exact: true }).last().click();
  await expect.poll(() => wire.launches.length).toBe(1);
  expect(wire.launches[0]).toMatchObject({ assessment: "red_team_local", target: "http://localhost:3000/", confirm_target: "http://localhost:3000/", objective: "Reach the export route without signing in" });
  // No objective typed: the launch has no objective member, and the exercise says the agent states its own.
  await page.goto("/code-security?tab=overview", { waitUntil: "domcontentloaded" });
  await page.getByTestId("assess-card").waitFor();
  await openPlan(page, "Red team");
  await page.getByTestId("assess-target").getByRole("radio").first().click();
  await page.getByTestId("assess-confirm").getByRole("checkbox").check();
  await page.getByRole("button", { name: "Choose agent" }).click();
  await page.getByRole("button", { name: "Start", exact: true }).last().click();
  await expect.poll(() => wire.launches.length).toBe(2);
  expect(Object.keys(wire.launches[1])).not.toContain("objective");
});

// N-8 (second review, fixed in fix round 4): the objective is applied when the field loses focus, which reads the plan again. The button used to go off while the plan was read, so a press that began on it the moment after typing ended on a disabled button and did nothing. The press now waits for the read and then does what the button says. These tests use a server that takes a little time to answer, as a real one does, and one that mints a new run id for every read, as the real one does: the consent has to survive the read too.
async function slowPlans(page: Page, wire: Wire, ms = 400) {
  await page.route("**/api/security/assessments/plan*", async (route) => {
    const u = new URL(route.request().url());
    wire.plans.push(u);
    await new Promise((r) => setTimeout(r, ms));
    const body = (wire.planFor ?? planFor)(u);
    await route.fulfill({ json: wire.freshRunIds ? { ...body, run_id: String(wire.plans.length).padStart(16, "0") } : body });
  });
}

for (const fresh of [false, true]) {
  test(`typing an objective and pressing Choose agent at once starts the agent step on the first click (${fresh ? "a new run id for every read, as the server mints" : "one run id"})`, async ({ page }) => {
    const wire = newWire(runsWithRetests());
    wire.freshRunIds = fresh;
    await mockAll(page, wire);
    await slowPlans(page, wire);
    await openOverview(page);
    await openPlan(page, "Red team");
    await page.getByTestId("assess-target").getByRole("radio").first().click();
    await page.getByTestId("assess-confirm").getByRole("checkbox").check();
    await expect(page.getByRole("button", { name: "Choose agent" })).toBeEnabled();
    await page.getByTestId("assess-objective-input").fill("Read the entries of another account");
    // The press begins on the button, which takes focus from the field and so applies the objective, and ends 150 ms later while the plan is still being read.
    await page.getByRole("button", { name: "Choose agent" }).click({ delay: 150 });
    await expect(page.getByTestId("new-terminal-task")).toBeVisible({ timeout: 3000 });
    // What starts is the plan that carries the objective, not the one read before it was typed.
    await page.getByRole("button", { name: "Start", exact: true }).last().click();
    await expect.poll(() => wire.launches.length).toBe(1);
    expect(wire.launches[0]).toMatchObject({ objective: "Read the entries of another account", confirm_target: "http://localhost:3000/" });
    expect(wire.plans.at(-1)?.searchParams.get("objective")).toBe("Read the entries of another account");
  });
}

test("a consent given before a choice that reads the plan again is still given after it: the target did not change", async ({ page }) => {
  const wire = newWire(runsWithRetests());
  wire.freshRunIds = true;
  await mockAll(page, wire);
  await openOverview(page);
  await openPlan(page, "Red team");
  await page.getByTestId("assess-target").getByRole("radio").first().click();
  const consent = page.getByTestId("assess-confirm").getByRole("checkbox");
  await consent.check();
  const reads = wire.plans.length;
  // A guardrail tick and an objective each read the plan again, and each read mints a new run id.
  await page.getByTestId("assess-relax-R-179").getByRole("checkbox").check();
  await page.getByTestId("assess-objective-input").fill("Reach the export route");
  await page.getByTestId("assess-objective-input").press("Enter");
  await expect.poll(() => wire.plans.length).toBeGreaterThanOrEqual(reads + 2);
  await expect(consent).toBeChecked();
  await expect(page.getByRole("button", { name: "Choose agent" })).toBeEnabled();
  // A different target is a different consent.
  await page.getByTestId("assess-target-input").fill("http://localhost:3001/");
  await page.getByRole("button", { name: "Use this address" }).click();
  await expect(page.getByTestId("assess-confirm").getByRole("checkbox")).not.toBeChecked();
  await expect(page.getByRole("button", { name: "Choose agent" })).toBeDisabled();
});

test("a threat model's scope note applied by the press on Choose agent does not lose the press either", async ({ page }) => {
  const wire = newWire(runsWithRetests());
  await mockAll(page, wire);
  await slowPlans(page, wire);
  await openOverview(page);
  await openPlan(page, "Threat model");
  await expect(page.getByRole("button", { name: "Choose agent" })).toBeEnabled();
  await page.getByTestId("assess-scope-note").fill("The export route matters this week");
  await page.getByRole("button", { name: "Choose agent" }).click({ delay: 150 });
  await expect(page.getByTestId("new-terminal-task")).toBeVisible({ timeout: 3000 });
  expect(wire.plans.at(-1)?.searchParams.get("scope_note")).toBe("The export route matters this week");
});

test("a press that waited for a plan the server then refuses starts nothing, and says so once", async ({ page }) => {
  const wire = newWire(runsWithRetests());
  wire.planFor = (u) => {
    const p = planFor(u);
    if ((u.searchParams.get("objective") ?? "").includes("elsewhere")) return { ...p, ok: false, code: "target_required", reason: "The task could not be built with that objective." };
    return p;
  };
  await mockAll(page, wire);
  await slowPlans(page, wire);
  await openOverview(page);
  await openPlan(page, "Red team");
  await page.getByTestId("assess-target").getByRole("radio").first().click();
  await page.getByTestId("assess-confirm").getByRole("checkbox").check();
  await page.getByTestId("assess-objective-input").fill("Try elsewhere");
  await page.getByRole("button", { name: "Choose agent" }).click({ delay: 150 });
  const plan = page.getByTestId("assess-plan");
  await expect(plan).toContainText("This cannot start here", { timeout: 3000 });
  await expect(page.getByTestId("new-terminal-task")).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Choose agent" })).toBeDisabled();
  // The reason is in the note once; the footer points at it and does not print it again.
  await expect(plan.getByText("The task could not be built with that objective.")).toHaveCount(1);
  await expect(page.getByTestId("assess-choose-reason")).toHaveText("Nothing can start here. The reason is in the note above.");
  expect(wire.launches).toHaveLength(0);
});

for (const scheme of ["light", "dark"] as const) {
  test(`at phone width, in ${scheme}, the red team plan's objective field fits, counts a full 200 characters and keeps the consent in the target section`, async ({ page }) => {
    await page.setViewportSize(PHONE);
    await page.emulateMedia({ colorScheme: scheme });
    await mount(page);
    await openPlan(page, "Red team");
    await page.getByTestId("assess-target").getByRole("radio").first().click();
    const consent = page.getByTestId("assess-target").getByTestId("assess-confirm");
    await expect(consent).toBeVisible();
    await consent.getByRole("checkbox").check();
    const input = page.getByTestId("assess-objective-input");
    await input.scrollIntoViewIfNeeded();
    await input.fill("o".repeat(230));
    await expect(page.getByTestId("assess-objective")).toContainText("200 of 200 characters");
    expect(await insideViewport(page, page.getByTestId("assess-objective")), "the objective field runs off the screen").toBe(true);
    expect(await topDialogOverflow(page), "red team plan").toBeLessThanOrEqual(1);
    await expect(page.getByRole("button", { name: "Choose agent" })).toBeEnabled();
  });
}

test("on a phone the red team chain's attribution is on screen: the note under the table says the opinion is the agent's, and the objective says whose it is", async ({ page }) => {
  await page.setViewportSize(PHONE);
  await mountArc(page);
  await openModelOf(page, ID.redTeam);
  const note = page.getByTestId("assess-exercise-stop-note");
  await note.scrollIntoViewIfNeeded();
  await expect(note).toHaveText("What would have detected or stopped a step is the agent's opinion. Observer did not test any of it.");
  expect(await insideViewport(page, note), "the attribution runs off the screen").toBe(true);
  const objective = page.getByTestId("assess-exercise-objective");
  await expect(objective).toContainText("In your words");
  expect(await insideViewport(page, objective)).toBe(true);
  await expect(page.getByTestId("assess-exercise-limit")).toContainText("one application in one box");
  expect(await dialogBodyOverflow(page)).toBeLessThanOrEqual(1);
});

test("on a phone the Exercise chain is one block per step: no table to pan, and each step's result and the agent's opinion are on screen under their own headings (N-18)", async ({ page }) => {
  await page.setViewportSize(PHONE);
  await mountArc(page);
  await openModelOf(page, ID.redTeam);
  await expect(page.getByTestId("assess-exercise-table")).toHaveCount(0);
  await expect(page.getByTestId("assess-exercise-blocks")).toBeVisible();
  const steps = page.getByTestId("assess-exercise-step");
  await expect(steps).toHaveCount(5);
  for (let i = 0; i < 5; i++) {
    const step = steps.nth(i);
    await step.scrollIntoViewIfNeeded();
    for (const part of ["assess-exercise-finding", "assess-exercise-result", "assess-exercise-stop"]) {
      const el = step.getByTestId(part);
      await el.scrollIntoViewIfNeeded();
      expect(await insideViewport(page, el), `step ${i + 1}: ${part} runs off the screen`).toBe(true);
    }
    await expect(step.getByTestId("assess-exercise-result")).toContainText("Result, as the agent says");
    await expect(step.getByTestId("assess-exercise-stop")).toContainText("the agent's opinion");
  }
  await expect(steps.nth(3).getByTestId("assess-exercise-result")).toContainText("Partly achieved");
  await expect(steps.nth(4).getByTestId("assess-exercise-result")).toContainText("Blocked");
  await expect(steps.nth(4).getByTestId("assess-exercise-stop")).toContainText("The agent gave no opinion.");
  expect(await dialogBodyOverflow(page)).toBeLessThanOrEqual(1);
  // The chain's own box does not scroll sideways: nothing in it is wider than the dialog body.
  const wide = await page.getByTestId("assess-exercise-chain").evaluate((el) => [...el.querySelectorAll<HTMLElement>("*")].filter((n) => n.scrollWidth > n.clientWidth + 1 && getComputedStyle(n).overflowX !== "visible").length);
  expect(wide, "a box in the chain scrolls sideways").toBe(0);
});

test("a validation line prints the conditions its reference counts were made under: the match window and how many quotes hiding secrets changed", async ({ page }) => {
  const checked = (extra: Json) => run({ id: ID.ptChecked, created_at: "2026-11-15T10:00:00Z", validation: { state: "valid", at: "2026-11-15T10:35:00Z", refused: 0, refs: { found: 192, exists: 0, claimed_not_found: 7, missing: 0, invalid: 0, unchecked: 0 }, ...extra } });
  const rows = (extra: Json) => runsEveryState().map((r) => (r.id === ID.ptChecked ? checked(extra) : r));
  // A check that kept its conditions prints them, in the grammar of their counts.
  await mount(page, newWire(rows({ ref_window_lines: 5, ref_text_hidden: 2 })));
  let line = await runRow(page, ID.ptChecked).getByTestId("assess-run-validation").innerText();
  expect(line).toContain("References: 192 found near the cited line");
  expect(line).toContain("A reference is found when its text is on a code line within 5 lines of the first cited line.");
  expect(line).toContain("2 references quote text that hiding secrets changed, so they could not be found in the file.");
  noRawWords(line, "validation line");
  // A window of one reads in the singular; one quote reads "1 reference quotes ... it".
  await mount(page, newWire(rows({ ref_window_lines: 1, ref_text_hidden: 1 })));
  line = await runRow(page, ID.ptChecked).getByTestId("assess-run-validation").innerText();
  expect(line).toContain("A reference is found only when its text is on the first cited line itself.");
  expect(line).toContain("1 reference quotes text that hiding secrets changed, so it could not be found in the file.");
  // A check made before the conditions were kept says nothing about them (the live node's six runs).
  await mount(page, newWire(rows({})));
  line = await runRow(page, ID.ptChecked).getByTestId("assess-run-validation").innerText();
  expect(line).toContain("References: 192 found near the cited line");
  expect(line).not.toMatch(/A reference is found/);
});

// ---------------------------------------------------------------- the polish round (N-10, N-16, N-17, N-20, UX-8)

test("the findings legend names the CVSS base score only on a run where some finding has one (N-16)", async ({ page }) => {
  await mount(page);
  await openModelOf(page, ID.ptChecked);
  await modelTab(page, /^Findings/).click();
  await expect(page.getByTestId("assess-findings-legend")).toHaveText("The text, the basis and the rating are what the agent wrote. The band, the evidence and the words about each cited place are Observer's.");
  await mountCvss(page);
  await openCvssFindings(page);
  await expect(page.getByTestId("assess-findings-legend")).toHaveText("The text, the basis and the rating are what the agent wrote. The band, the CVSS base score, the evidence and the words about each cited place are Observer's.");
});

test("the red team plan names its objective once and helps in one short sentence (N-17)", async ({ page }) => {
  await mount(page);
  await openPlan(page, "Red team");
  await page.getByTestId("assess-target").getByRole("radio").first().click();
  const field = page.getByTestId("assess-objective");
  await expect(field).toBeVisible();
  // One visible name: the heading. The field has no second label, and its accessible name is the same words.
  const text = await field.innerText();
  expect(text.match(/Objective/g)?.length, text).toBe(1);
  await expect(field.getByRole("heading", { name: /^Objective \(optional\)/ })).toBeVisible();
  await expect(page.getByRole("textbox", { name: "Objective (optional)" })).toBeVisible();
  // The help is the counter and one short sentence.
  expect(text.replace(/\s+/g, " ").trim()).toMatch(/^Objective \(optional\) 0 of 200 characters\. Leave it empty and the agent states an objective of its own\.$/);
});

test("a run recorded before the backend and the check conditions were kept says that, where the record lacks them (N-20)", async ({ page }) => {
  const checked = (over: Json, validation: Json) => run({ id: ID.ptChecked, created_at: "2026-11-15T10:00:00Z", ...over, validation: { state: "valid", at: "2026-11-15T10:35:00Z", refused: 0, refs: { found: 192, exists: 0, claimed_not_found: 7, missing: 0, invalid: 0, unchecked: 0 }, ...validation } });
  const rows = (r: Json) => runsEveryState().map((x) => (x.id === ID.ptChecked ? r : x));
  // An old record: sandboxed, no backend, a check with no window.
  await mount(page, newWire(rows(checked({ backend: undefined }, {}))));
  let row = runRow(page, ID.ptChecked);
  await expect(row).toContainText("in a sandbox (backend not recorded for this run)");
  let line = await row.getByTestId("assess-run-validation").innerText();
  expect(line).toContain("References: 192 found near the cited line");
  expect(line).toContain("How many lines from the cited line a reference could match was not recorded for this check.");
  // A new record names both and says nothing of the kind.
  await mount(page, newWire(rows(checked({}, { ref_window_lines: 5 }))));
  row = runRow(page, ID.ptChecked);
  await expect(row).toContainText("in a sandbox (bwrap)");
  await expect(row).not.toContainText("not recorded");
  line = await row.getByTestId("assess-run-validation").innerText();
  expect(line).not.toContain("not recorded");
  // A run that was never sandboxed says that and does not say its backend was not recorded.
  await expect(runRow(page, ID.tmOld)).toContainText("not sandboxed");
  await expect(runRow(page, ID.tmOld)).not.toContainText("backend not recorded");
});

test("the sentences of a pen test plan name no config key, rule id or tier value (UX-8)", async ({ page }) => {
  await mount(page);
  const plan = await openPlan(page, "Penetration test");
  await page.getByTestId("assess-target").getByRole("radio").first().click();
  await expect(page.getByTestId("assess-relax-R-179")).toBeVisible();
  const text = await plan.innerText();
  expect(text, "a rule id").not.toMatch(/\bR-\d{3}\b/);
  expect(text, "a config key").not.toMatch(/security\.assessments|terminal\.sandbox|egress_allow|\[terminal|\[proxy/);
  expect(text, "a tier value").not.toMatch(/proxy_only/);
  expect(text).toContain("Allow network and vulnerability scanners");
  // The settings the plan sends a reader to are named by screen.
  expect(text).toContain("Settings > Guard > Code security");
});

test("the link in a helper-off refusal opens Settings > Guard on the helper's own switch (N-10)", async ({ page }) => {
  const wire = newWire(runsWithRetests());
  wire.planFor = (u) => {
    const p = planFor(u);
    if (u.searchParams.get("kind") !== "pentest_retest") return p;
    return { ...p, ok: false, code: "retest_helper", reason: SERVER_WORDS.helper, probe: { state: "off", files: [], dir: "", budget: 0, pace_rps: 0 } };
  };
  await mount(page, wire);
  await openModelOf(page, ID.ptRetested);
  await modelTab(page, /^Findings/).click();
  await page.getByTestId("assess-retest-action").getByRole("button", { name: "Retest findings" }).click();
  await page.getByTestId("assess-retest-open-plan").click();
  const link = page.getByRole("dialog").last().getByTestId("assess-setting-link").first();
  await expect(link).toBeVisible();
  await link.click();
  await expect(page).toHaveURL(/\/settings\?section=guard#security\.assessments\.probe_helper$/);
  // The Code security card scrolls the row into view and puts focus on its picker once the config is read.
  const row = page.getByTestId("code-security-setting-security.assessments.probe_helper");
  await expect(row).toBeVisible({ timeout: 20000 });
  await expect(row).toBeFocused();
  expect(await insideViewport(page, row)).toBe(true);
});
