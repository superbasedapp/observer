import { readFileSync } from "node:fs";
import { test, expect, type Locator, type Page, type Route } from "@playwright/test";
import {
  FIXTURE_BIG_PT_RUN,
  FIXTURE_BIG_TM_RUN,
  FIXTURE_PT,
  FIXTURE_PT_EMPTY,
  FIXTURE_PT_EVIDENCE,
  FIXTURE_PT_NOT_STARTED,
  FIXTURE_PT_PARTIAL,
  FIXTURE_PT_REFUSED_ALL,
  FIXTURE_SINCE_RUN,
  FIXTURE_TM,
  FIXTURE_TM_PARTIAL,
  FIXTURE_TM_REFUSED_ALL,
  FIXTURE_TM_SINCE,
  fixtureBigPentest,
  fixtureBigThreatModel,
  fixtureFindings,
  fixtureThreats,
} from "../src/lib/secAssessModelFixture.ts";
import type { AssessModelResponse } from "../src/lib/secAssessModel.ts";
import { clearanceRegExp, parseClearanceList } from "../src/lib/secAssessBanned.ts";

// Code security > Overview > Security assessments, end to end in the browser
// (docs/plans/security-assessments-depth-plan-2026-11-14.md W0): the settings
// in force on the plan dialog, a live run past its time box with Stop, an
// ended run with its git check and Delete evidence, and the unreadable run
// history. Like the sibling specs it drives an already-running ISOLATED
// dashboard on BASE_URL (see e2e/README.md: a throwaway `observer dashboard`
// with its own config, database and HOME, never the live daemon): the shell
// (navigation, component state, theme) is the real one. Only the assessment
// routes and the Code security status are stubbed by route interception, so
// the runs and plans the spec needs exist without launching an agent. The
// stubs are registered after the pass-through, and Playwright matches the
// newest route first.
//
// Every assertion here is about what a person reads and clicks: the words,
// the two-step confirm on a destructive action, the request each click sends
// and the row that comes back. The words are never "verified", "confirmed" or
// "clean": the git check is a comparison and says what it cannot see.
//
// The depth plan's W3 and W4 sections of the plan dialog (the threat model's
// scope and comparison, a pen test's start command, what Observer noticed
// before it starts, the tools and what holds each rule) are driven the same
// way: the plan route is a function of its query (wire.planFor), so each click
// that changes a choice reads the plan again, and the test asserts the address
// of that read and, for a launch, the body that reaches the launch route. The
// Settings card's four new rows run against the isolated dashboard's own
// config (a real dry run and write), and an optional screenshot directory
// (E2E_SHOTS_DIR) keeps what the dialog looked like.

test.use({ viewport: { width: 1280, height: 1000 } });

const KINDS = [
  {
    id: "threat_model",
    title: "Threat model",
    summary: "A structured threat model of one project, read from its repository.",
    mode: "Read-only",
    launchable: true,
    sandbox: "optional",
    target: "none",
    files: ["report.md", "assessment.json"],
    note: "Read-only. The agent reads the repository.",
  },
  {
    id: "pentest_local",
    title: "Penetration test (your own app, local)",
    summary: "A time-boxed test of one development server, in a sandbox.",
    mode: "Sandboxed",
    launchable: true,
    sandbox: "required",
    target: "required",
    files: ["report.md", "assessment.json"],
  },
];

const PROJECT = { project_root_hash: "h1", name: "api", root_path: "/home/u/api", active: true, state: "ready", reason: "", blocking: 0, open: 0, counts: [], runs: [] };

type MockRun = Record<string, unknown>;

function liveRun(): MockRun {
  return {
    id: "00000000000000a1",
    created_at: "2026-11-14T10:00:00Z",
    kind: "pentest_local",
    kind_title: "Penetration test (your own app, local)",
    tool: "claude-code",
    project_root_hash: "h1",
    project_name: "api",
    handle: "H1",
    seeded: true,
    sandboxed: true,
    backend: "bwrap",
    target: "http://localhost:3000/",
    state: "started",
    phase: "started",
    files: { report: false, sarif: false, commands: false },
    report_bytes: 0,
    time_box_minutes: 45,
    time_box_action: "stop_button",
    deadline: "2026-11-14T10:45:00Z",
    over_time_box: true,
    can_stop: true,
    audit: "pending",
    audit_words: "Checked when the run ends",
    audit_limits: "Files git ignores (.env, local databases, caches, node_modules) are not covered, and a change made by you in the same window is counted too.",
    has_data: true,
  };
}

function endedRun(): MockRun {
  return {
    id: "00000000000000b2",
    created_at: "2026-11-14T08:00:00Z",
    kind: "threat_model",
    kind_title: "Threat model",
    tool: "claude-code",
    project_root_hash: "h1",
    project_name: "api",
    seeded: true,
    sandboxed: false,
    state: "report_ready",
    phase: "started",
    files: { report: true, sarif: false, commands: false },
    report_bytes: 1200,
    ended_at: "2026-11-14T08:40:00Z",
    end_why: "terminal_gone",
    time_box_minutes: 60,
    time_box_action: "stop_button",
    deadline: "2026-11-14T09:00:00Z",
    over_time_box: false,
    audit: "changed",
    audit_words: "Git state changed during the run window",
    audit_at: "2026-11-14T08:41:00Z",
    audit_limits: "Files git ignores are not covered.",
    has_data: true,
  };
}

type Wire = {
  runs: MockRun[];
  unreadable: boolean;
  posts: { path: string; body: unknown }[];
  /** The plan reads made, in order (the address each choice reads the plan with). */
  plans?: URL[];
  /** Answers the plan route from its query; absent: the one fixed pen test plan. */
  planFor?: (u: URL) => Record<string, unknown>;
  /** The bodies that reached the launch route. */
  launches?: Record<string, unknown>[];
};

async function mockWire(page: Page, wire: Wire) {
  await page.route("**/api/**", (route) => route.continue());
  await page.route("**/api/jobs*", (route) => route.fulfill({ json: { confirm_token: "tok", jobs: [] } }));
  await page.route("**/api/security/status", (route) => route.fulfill({ json: { module: "code-security", projects: [PROJECT] } }));
  await page.route("**/api/security/assessments", (route) =>
    route.fulfill({
      json: { kinds: KINDS, runs: wire.runs, import_available: true, launch: true, ...(wire.unreadable ? { runs_unreadable: true, runs_error: "run_record_unreadable" } : {}) },
    }),
  );
  await page.route("**/api/security/assessments/plan*", (route) => {
    const u = new URL(route.request().url());
    (wire.plans ??= []).push(u);
    return route.fulfill({
      json: wire.planFor
        ? wire.planFor(u)
        : {
            confirm_token: "tok",
            run_id: "00000000000000c3",
            kind: KINDS[1],
            project: { project_root_hash: "h1", name: "api", root_path: "/home/u/api", on_disk: true },
            ok: true,
            target_typed: false,
            candidates: [{ url: "http://localhost:3000/", name: "dev" }],
            boundary: ["The only target is the address you confirm."],
            backend: "bwrap",
            tier: "proxy_only",
            allowed_tools: ["claude-code"],
            seeds: {},
            limits: {
              time_box_minutes: 45,
              time_box_action: "stop_button",
              boundary_audit: true,
              audit_policy: "untracked_reported",
              audit_limits: "Files git ignores (.env, local databases, caches, node_modules) are not covered, and a change made by you in the same window is counted too.",
            },
          },
    });
  });
  const post = (path: string, apply: (body: { run: string }) => void) =>
    page.route(`**/api/security/assessments/${path}`, async (route: Route) => {
      const body = route.request().postDataJSON() as { run: string };
      wire.posts.push({ path, body });
      apply(body);
      const run = wire.runs.find((r) => r.id === body.run);
      await route.fulfill({ json: { run } });
    });
  await post("stop", (b) => {
    const i = wire.runs.findIndex((r) => r.id === b.run);
    wire.runs[i] = { ...wire.runs[i], can_stop: false, ended_at: "2026-11-14T10:50:00Z", end_why: "stopped", audit: "no_change", audit_words: "No git change seen", audit_at: "2026-11-14T10:50:30Z" };
  });
  await post("delete-data", (b) => {
    const i = wire.runs.findIndex((r) => r.id === b.run);
    wire.runs[i] = { ...wire.runs[i], has_data: false };
  });
  await post("validate", (b) => {
    const i = wire.runs.findIndex((r) => r.id === b.run);
    wire.runs[i] = {
      ...wire.runs[i],
      state: "validated",
      validation: { state: "partial", at: "2026-11-14T09:30:00Z", refused: 1, refs: { found: 4, exists: 1, claimed_not_found: 0, missing: 1, invalid: 0, unchecked: 0 } },
    };
  });
  await page.addInitScript(() => {
    try {
      localStorage.setItem("sb_tour_completed", "1");
      // The first-run capture dialog opens by itself on a fresh isolated
      // instance and would cover the page; closing it for this visit is what
      // its own Close button records.
      sessionStorage.setItem("sb_firstrun_closed_this_visit", "1");
    } catch {
      /* private mode: ignore */
    }
  });
}

async function openOverview(page: Page) {
  await page.goto("/code-security?tab=overview", { waitUntil: "domcontentloaded" });
  await expect(page.getByTestId("assess-card")).toBeVisible({ timeout: 15000 });
}

test("the plan dialog lists the settings in force before a run starts", async ({ page }) => {
  const wire: Wire = { runs: [], unreadable: false, posts: [] };
  await mockWire(page, wire);
  await openOverview(page);
  await expect(page.getByTestId("assess-empty")).toBeVisible();

  const pentest = page.getByTestId("assess-kind").filter({ hasText: "Penetration test" });
  await pentest.getByRole("button", { name: "Start" }).click();

  const limits = page.getByTestId("assess-limits");
  await expect(limits).toBeVisible();
  await expect(limits).toContainText("Settings in force for this run");
  await expect(limits).toContainText("Time box: 45 minutes");
  await expect(limits).toContainText("Nothing closes the terminal for you; use Stop when you are ready");
  await expect(limits).toContainText("Git check: Observer compares the project's git state before and after the run");
  await expect(limits).toContainText("Files git ignores (.env, local databases, caches, node_modules) are not covered");
  await expect(limits).toContainText("It does not check that the agent's reasoning is right");
  // Honest wording: nothing here is called verified, confirmed or clean.
  await expect(limits).not.toContainText(/verified|confirmed|clean/i);
});

test("a live run past its time box offers Stop, which asks first and then records the end", async ({ page }) => {
  const wire: Wire = { runs: [liveRun()], unreadable: false, posts: [] };
  await mockWire(page, wire);
  await openOverview(page);

  const row = page.getByTestId("assess-run");
  await expect(row.getByTestId("assess-run-timebox")).toContainText("Over its 45-minute time box. Nothing closes the terminal for you; use Stop when you are ready.");
  await expect(row.getByTestId("assess-run-audit")).toContainText("Git check: Checked when the run ends.");
  // A live run keeps its launch snapshot: there is no Delete yet.
  await expect(row.getByRole("button", { name: /^Delete the stored evidence/ })).toHaveCount(0);

  // The first click only arms the button; nothing is sent.
  await row.getByRole("button", { name: /^Stop the .* run/ }).click();
  expect(wire.posts).toHaveLength(0);
  await expect(page.getByText("Closes the run's terminal.")).toBeVisible();

  await row.getByRole("button", { name: /^Stop the .* run/ }).click();
  await expect.poll(() => wire.posts.length).toBe(1);
  expect(wire.posts[0]).toEqual({ path: "stop", body: { run: "00000000000000a1" } });
  // The list is read again: the row says how the run ended and what the git
  // check found, and Stop is gone.
  await expect(row.getByTestId("assess-run-timebox")).toContainText("stopped from this page", { timeout: 15000 });
  await expect(row.getByTestId("assess-run-audit")).toContainText("Git check: No git change seen");
  await expect(row.getByRole("button", { name: /^Stop the .* run/ })).toHaveCount(0);
  await expect(row.getByRole("button", { name: /^Delete the stored evidence/ })).toBeVisible();
});

test("an ended run says what the git check found and deletes its stored evidence on a confirmed click", async ({ page }) => {
  const wire: Wire = { runs: [endedRun()], unreadable: false, posts: [] };
  await mockWire(page, wire);
  await openOverview(page);

  const row = page.getByTestId("assess-run");
  await expect(row.getByTestId("assess-run-timebox")).toContainText("Within its 60-minute time box; ended when the terminal closed.");
  const audit = row.getByTestId("assess-run-audit");
  await expect(audit).toContainText("Git check: Git state changed during the run window");
  await expect(audit).not.toContainText(/verified|confirmed|clean|boundary crossed/i);
  await expect(row.getByRole("button", { name: /^Stop the .* run/ })).toHaveCount(0);

  await row.getByRole("button", { name: /^Delete the stored evidence/ }).click();
  expect(wire.posts).toHaveLength(0);
  await expect(page.getByText("The run, its report and its findings stay.")).toBeVisible();
  await row.getByRole("button", { name: /^Delete the stored evidence/ }).click();
  await expect.poll(() => wire.posts.length).toBe(1);
  expect(wire.posts[0]).toEqual({ path: "delete-data", body: { run: "00000000000000b2" } });
  await expect(row.getByRole("button", { name: /^Delete the stored evidence/ })).toHaveCount(0, { timeout: 15000 });
  // The run, its report and its git check stay.
  await expect(row.getByRole("button", { name: "Read report" })).toBeVisible();
  await expect(row.getByTestId("assess-run-audit")).toContainText("Git state changed");
});

test("an unreadable run history is said plainly and is never shown as no assessments", async ({ page }) => {
  const wire: Wire = { runs: [], unreadable: true, posts: [] };
  await mockWire(page, wire);
  await openOverview(page);
  await expect(page.getByTestId("assess-runs-unreadable")).toContainText(
    "The run record (secassess-runs.json) cannot be read, so runs may be missing from this list. Nothing was deleted.",
  );
  await expect(page.getByTestId("assess-empty")).toHaveCount(0);
});

test("the card fits a phone: no horizontal scroll with a live run and its buttons", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  const wire: Wire = { runs: [liveRun(), endedRun()], unreadable: false, posts: [] };
  await mockWire(page, wire);
  await openOverview(page);
  await expect(page.getByTestId("assess-run")).toHaveCount(2);
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  expect(overflow).toBeLessThanOrEqual(1);
});

function modelRun(): MockRun {
  return {
    ...endedRun(),
    id: "00000000000000d4",
    state: "model_ready",
    contract: "threatmodel.v1",
    files: { report: true, sarif: false, commands: false, model: true },
    audit: "no_change",
    audit_words: "No git change seen",
    has_data: false,
  };
}

test("a written model is validated on a click and the row says what was checked", async ({ page }) => {
  const wire: Wire = { runs: [modelRun()], unreadable: false, posts: [] };
  await mockWire(page, wire);
  await openOverview(page);

  const row = page.getByTestId("assess-run");
  await expect(row).toContainText("model written");
  await expect(row.getByTestId("assess-run-validation")).toHaveCount(0);
  await row.getByRole("button", { name: "Validate" }).click();
  await expect.poll(() => wire.posts.length).toBe(1);
  expect(wire.posts[0]).toEqual({ path: "validate", body: { run: "00000000000000d4" } });

  // The list is read again: the row is validated, says how much was refused and
  // how the references fared, and never calls anything verified or confirmed.
  const line = row.getByTestId("assess-run-validation");
  await expect(line).toContainText("Model checked: 1 item was refused.", { timeout: 15000 });
  await expect(line).toContainText("References: 4 found near the cited line, 1 exists with nothing matched near the cited line, 1 missing.");
  await expect(line).not.toContainText(/verified|confirmed|clean/i);
  await expect(row).toContainText("validated");
  await expect(row.getByRole("button", { name: "Validate" })).toHaveCount(0);
});

// --- The model contract: the plan's settings in force and the derived import ---

function tmPlan() {
  return {
    confirm_token: "tok",
    run_id: "00000000000000e5",
    kind: KINDS[0],
    project: { project_root_hash: "h1", name: "api", root_path: "/home/u/api", on_disk: true },
    ok: true,
    target_typed: false,
    candidates: [],
    boundary: ["This is a read-only assessment."],
    prompt: "SECURITY ASSESSMENT: Threat model of api.\nPrompt version: tm.2.",
    prompt_sha256: "ab".repeat(32),
    allowed_tools: null,
    seeds: {},
    limits: {
      time_box_minutes: 60,
      time_box_action: "stop_button",
      boundary_audit: true,
      audit_policy: "strict",
      audit_limits: "Files git ignores are not covered.",
    },
    model: {
      prompt_version: "tm.2",
      frameworks: "stride_ai",
      method_extras: "attack_trees",
      self_check: true,
      import_min_band: "medium",
      findings_cap: 100,
      rerun_dedup: true,
    },
  };
}

function validatedModelRun(): MockRun {
  return {
    ...modelRun(),
    state: "validated",
    validation: { state: "valid", at: "2026-11-14T09:30:00Z", refs: { found: 5, exists: 0, claimed_not_found: 0, missing: 0, invalid: 0, unchecked: 0 } },
  };
}

test("the plan dialog of a threat model lists what the task asks for and what Import will do", async ({ page }) => {
  const wire: Wire = { runs: [], unreadable: false, posts: [] };
  await mockWire(page, wire);
  await page.route("**/api/security/assessments/plan*", (route) => route.fulfill({ json: tmPlan() }));
  await openOverview(page);
  const card = page.getByTestId("assess-kind").filter({ hasText: "Threat model" });
  await card.getByRole("button", { name: "Start" }).click();

  const limits = page.getByTestId("assess-limits");
  await expect(limits).toBeVisible();
  await expect(limits).toContainText("Time box: 60 minutes");
  await expect(limits).toContainText("structured assessment.json (task version tm.2)");
  await expect(limits).toContainText("Frameworks asked for: STRIDE and the AI frameworks.");
  await expect(limits).toContainText("Abuse cases and attack trees: Attack trees only.");
  await expect(limits).toContainText("told to check its own file with Observer before it finishes");
  await expect(limits).toContainText("On import: findings at medium risk and above, at most 100, highest risk first");
  await expect(limits).not.toContainText(/verified|confirmed|clean/i);
  // The task the developer reads names its own version.
  await expect(page.getByTestId("assess-prompt-text")).toContainText("Prompt version: tm.2.");
});

test("a validated model is imported on a click and the row says how many were not, and why", async ({ page }) => {
  const wire: Wire = { runs: [validatedModelRun()], unreadable: false, posts: [] };
  await mockWire(page, wire);
  await page.route("**/api/security/assessments/import", async (route) => {
    wire.posts.push({ path: "import", body: route.request().postDataJSON() });
    wire.runs[0] = {
      ...wire.runs[0],
      state: "imported",
      import: {
        at: "2026-11-14T10:00:00Z",
        outcome: "imported",
        prepared: 2,
        findings: 2,
        new: 2,
        with_lineage: 0,
        derived: { considered: 9, kept: 2, no_location: 3, under_min_band: 2, over_cap: 2, min_band: "high", cap: 2, dedup: true },
      },
    };
    await route.fulfill({ json: { run: wire.runs[0] } });
  });
  await openOverview(page);
  const row = page.getByTestId("assess-run");
  await expect(row).toContainText("validated");
  await expect(row.getByRole("button", { name: "Validate" })).toHaveCount(0);
  await row.getByRole("button", { name: "Import findings" }).click();
  await expect.poll(() => wire.posts.length).toBe(1);
  expect(wire.posts[0]).toEqual({ path: "import", body: { run: "00000000000000d4" } });

  await expect(row).toContainText("2 findings imported (2 new). 7 of 9 not imported:", { timeout: 15000 });
  await expect(row).toContainText("3 with no location in the code");
  await expect(row).toContainText("2 under your minimum band (high)");
  await expect(row).toContainText("2 past your cap of 2");
  await expect(row.getByRole("link", { name: "See these findings" })).toBeVisible();
  await expect(row.getByRole("button", { name: /Import/ })).toHaveCount(0);
  await expect(row).not.toContainText(/verified|confirmed|clean/i);
});

test("an import of a model that was not validated says what to do, in plain words", async ({ page }) => {
  const run = validatedModelRun();
  const wire: Wire = { runs: [run], unreadable: false, posts: [] };
  await mockWire(page, wire);
  await page.route("**/api/security/assessments/import", (route) =>
    route.fulfill({ status: 409, json: { error: "check the model first", code: "not_validated" } }),
  );
  await openOverview(page);
  const row = page.getByTestId("assess-run");
  await row.getByRole("button", { name: "Import findings" }).click();
  await expect(row).toContainText("Check the model first: use Validate, then import.");
  // Nothing in the row changed: the run is still validated and still importable.
  await expect(row).toContainText("validated");
  await expect(row.getByRole("button", { name: "Import findings" })).toBeVisible();
});

test("an import that derived nothing reads as nothing to import and can be tried again", async ({ page }) => {
  const run = {
    ...validatedModelRun(),
    state: "no_findings",
    import: { at: "t", outcome: "no_findings", prepared: 0, findings: 0, new: 0, with_lineage: 0, derived: { considered: 2, kept: 0, no_location: 2 } },
  };
  const wire: Wire = { runs: [run], unreadable: false, posts: [] };
  await mockWire(page, wire);
  await openOverview(page);
  const row = page.getByTestId("assess-run");
  await expect(row).toContainText("nothing to import");
  await expect(row).toContainText("Nothing was derived to import from 2 candidates. 2 of 2 not imported: 2 with no location in the code.");
  await expect(row.getByRole("button", { name: "Import again" })).toBeVisible();
  await expect(row).not.toContainText(/verified|confirmed|\bclean\b|no weaknesses/i);
});

test("the model-contract rows fit a phone: no horizontal scroll", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  const none = { ...validatedModelRun(), id: "00000000000000f6", state: "no_findings", import: { at: "t", outcome: "no_findings", prepared: 0, findings: 0, new: 0, with_lineage: 0, derived: { considered: 2, kept: 0, no_location: 2 } } };
  const wire: Wire = { runs: [validatedModelRun(), none], unreadable: false, posts: [] };
  await mockWire(page, wire);
  await openOverview(page);
  await expect(page.getByTestId("assess-run")).toHaveCount(2);
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  expect(overflow).toBeLessThanOrEqual(1);
});

// --- The depth plan's W3 and W4 on the plan dialog ---------------------------

const HONEST = /confirmed|verified|vulnerable|\bclean\b|\bsecure\b|authentic/i;

// shot keeps what the dialog looked like when E2E_SHOTS_DIR is set (a tall
// viewport so the whole dialog is in the picture); it does nothing otherwise.
async function shot(page: Page, name: string) {
  const dir = process.env.E2E_SHOTS_DIR;
  if (!dir) return;
  const was = page.viewportSize();
  await page.setViewportSize({ width: was?.width ?? 1280, height: Math.max(was?.height ?? 1000, 2400) });
  await page.waitForTimeout(300);
  await page.screenshot({ path: `${dir}/${name}.png` });
  if (was) await page.setViewportSize(was);
}

const lastPlan = (wire: Wire): URL => (wire.plans ?? [])[(wire.plans ?? []).length - 1];

// mockLaunch makes the New terminal dialog (task mode) startable on the
// isolated dashboard and records the body that reaches the launch route.
async function mockLaunch(page: Page, wire: Wire) {
  wire.launches ??= [];
  await page.route("**/api/terminal/sessions*", (route) =>
    route.fulfill({
      json: {
        sessions: [],
        launchable_tools: ["claude-code"],
        launchable_tool_info: [{ tool: "claude-code", allowed: true, watched: true }],
        allowed_project_roots: ["/home/u/api"],
        fresh_enabled: true,
        shell_enabled: false,
      },
    }),
  );
  await page.route("**/api/terminal/launch/preflight*", (route) =>
    route.fulfill({ json: { tool: "claude-code", verdict: "ok", bin: "/usr/bin/claude", can_install: false } }),
  );
  await page.route("**/api/terminal/launch/models*", (route) => route.fulfill({ json: { tool: "claude-code", supported: false, models: [] } }));
  await page.route("**/api/security/assessments/launch", async (route) => {
    wire.launches!.push(route.request().postDataJSON() as Record<string, unknown>);
    await route.fulfill({ json: { handle: "H9", tool: "claude-code", command: "claude" } });
  });
}

// launchFromPlan presses Choose agent, then Start in the New terminal dialog,
// and returns the body the launch route received.
async function launchFromPlan(page: Page, wire: Wire): Promise<Record<string, unknown>> {
  const before = wire.launches?.length ?? 0;
  await page.getByRole("button", { name: "Choose agent" }).click();
  await expect(page.getByTestId("new-terminal-task")).toBeVisible();
  const start = page.getByRole("button", { name: "Start", exact: true }).last();
  await expect(start).toBeEnabled({ timeout: 15000 });
  await start.click();
  await expect.poll(() => wire.launches?.length ?? 0).toBe(before + 1);
  return wire.launches![before];
}

const PLAN_PROJECT = { project_root_hash: "h1", name: "api", root_path: "/home/u/api", on_disk: true };
const PLAN_LIMITS = {
  time_box_minutes: 60,
  time_box_action: "stop_button",
  boundary_audit: true,
  audit_policy: "strict",
  audit_limits: "Files git ignores are not covered.",
};

// tmPlanFor is a threat model plan that answers its own query: the places the
// server accepts, the one it refuses (anything that climbs out of the project),
// the note, and the earlier run.
function tmPlanFor(u: URL): Record<string, unknown> {
  const asked = u.searchParams.getAll("scope_path");
  const refused = asked.filter((p) => p.startsWith(".."));
  const accepted = asked.filter((p) => !p.startsWith(".."));
  const note = u.searchParams.get("scope_note") ?? "";
  const prev = u.searchParams.get("previous_run");
  const selected = prev === null ? "00000000000000a1" : prev === "none" ? "" : prev;
  return {
    confirm_token: "tok",
    run_id: "00000000000000e5",
    kind: KINDS[0],
    project: PLAN_PROJECT,
    ok: true,
    target_typed: false,
    candidates: [],
    boundary: ["This is a read-only assessment."],
    prompt: `SECURITY ASSESSMENT: Threat model of api.\n${accepted.length ? `Model only: ${accepted.join(", ")}.` : "Model the whole project."}${note ? `\nThe developer says: ${note}` : ""}`,
    prompt_sha256: "ab".repeat(32),
    allowed_tools: null,
    seeds: { "claude-code": "leading_positional" },
    limits: PLAN_LIMITS,
    model: {
      prompt_version: "tm.2",
      frameworks: "all",
      method_extras: "both",
      self_check: true,
      import_min_band: "low",
      findings_cap: 0,
      rerun_dedup: true,
      grounding: "full",
    },
    grounding: { mode: "full", sections: ["languages", "manifests", "infra", "spec", "dependencies", "findings"], bytes: 3174, dropped: 0, ai_app: false },
    scope: {
      dirs: ["cmd", "internal", "web", "docs"],
      paths: accepted,
      note,
      refused: refused.map((path) => ({ path, reason: "It is outside the project." })),
      max_paths: 8,
      max_note: 200,
    },
    previous: {
      options: [
        { id: "00000000000000a1", created_at: "2026-11-13T09:00:00Z", scope: ["cmd/api"] },
        { id: "00000000000000a0", created_at: "2026-11-12T09:00:00Z" },
      ],
      selected,
      default_run: "00000000000000a1",
      note: "Observer gives the agent nothing from the earlier run and asks it not to open other runs' folders. That is a request, not a barrier.",
    },
  };
}

const START_PLANS: { command: string; choice?: string; cwd?: string; port: number; source: string; prepare?: string[]; needs?: string[] }[] = [
  { command: "npm run dev", port: 3000, source: "package.json scripts" },
  { command: "python manage.py runserver 8000", port: 8000, source: "manage.py", prepare: ["python manage.py migrate"], needs: ["db"] },
  // The same command in a subfolder is its own plan, picked by its choice string.
  { command: "npm run dev", choice: "web::npm run dev", cwd: "web", port: 5173, source: ".claude/launch.json" },
];

// ptPlanFor is a pen test plan that answers its own query: the target, the start
// command (a command with a pipe, a quote or a variable is refused with a reason),
// and the facts Observer noticed before the run starts.
function ptPlanFor(u: URL): Record<string, unknown> {
  const target = u.searchParams.get("target") ?? "";
  const startQ = u.searchParams.get("start");
  const bad = startQ !== null && /[|;&$`<>"']/.test(startQ);
  let selected = START_PLANS[0].command;
  let edited = false;
  if (startQ === "none") {
    selected = "";
    edited = true;
  } else if (startQ !== null) {
    selected = bad ? "" : startQ;
    edited = !START_PLANS.some((p) => (p.choice ?? p.command) === startQ);
  }
  // The preparation steps run only when the developer opted in (prepare=yes); absent is no.
  const prepare = u.searchParams.get("prepare") === "yes";
  const error = bad ? "The start command has a character that is not accepted: no quotes, pipes or variables." : undefined;
  return {
    confirm_token: "tok",
    run_id: "00000000000000c4",
    kind: KINDS[1],
    project: PLAN_PROJECT,
    ok: !error,
    ...(error ? { code: "start_invalid", reason: error } : {}),
    target,
    target_typed: target !== "",
    candidates: [{ url: "http://localhost:3000/", name: "dev", source: ".claude/launch.json" }],
    boundary: ["The only target is the address you confirm."],
    ...(!error && target
      ? {
          prompt: `SECURITY ASSESSMENT: Penetration test of ${target}.\nThe start command: ${selected || "none"}.${prepare ? "\nRun first: python manage.py migrate" : ""}`,
          prompt_sha256: "cd".repeat(32),
        }
      : {}),
    backend: "bwrap",
    tier: "proxy_only",
    allowed_tools: ["claude-code"],
    seeds: { "claude-code": "leading_positional" },
    limits: { ...PLAN_LIMITS, time_box_minutes: 45, audit_policy: "untracked_reported", request_budget: 600, pace_rps: 5 },
    model: {
      prompt_version: "pt.2",
      categories: "all",
      self_check: true,
      import_min_band: "low",
      findings_cap: 0,
      rerun_dedup: true,
      grounding: "without_findings",
      secret_mode: "mask",
      secret_mode_effective: "warn",
      request_budget: 600,
      pace_rps: 5,
    },
    grounding: { mode: "without_findings", sections: ["languages", "manifests", "infra", "start"], bytes: 1900, dropped: 2, ai_app: false },
    start: {
      plans: START_PLANS,
      selected_command: selected,
      edit: START_PLANS.find((p) => (p.choice ?? p.command) === selected)?.command ?? selected,
      edited,
      prepare,
      ...(error ? { error } : {}),
      none_found: false,
    },
    preflight: [
      { id: "spec", level: "info", text: "An API spec was found at openapi.json." },
      { id: "env", level: "warn", text: "2 environment files are in this folder." },
      { id: "deps", level: "likely_fails", text: "No node_modules folder: the sandbox cannot install packages, so install them outside it first." },
    ],
    env: { files: [".env", ".env.local"], count: 2, configured: "mask", effective: "warn", line: "2 .env files are in this folder and are readable inside the sandbox." },
    tools: [
      { id: "curl", purpose: "Send HTTP requests", command: "curl", present: true, guarded: false, fallback: "" },
      { id: "nmap", purpose: "Scan ports", command: "nmap", present: false, guarded: true, fallback: "The agent sends the requests itself." },
      { id: "python3", purpose: "Run the request helper", command: "python3", present: null, guarded: false, fallback: "" },
    ],
    safety: [
      { id: "target", rule: "Only the target you named is tested", prompt: true, helper: "-", observer: "The sandbox's network", observer_kind: "prevents", prompt_only: false },
      { id: "pace", rule: "At most 5 requests a second", prompt: true, helper: "-", observer: "-", observer_kind: "", prompt_only: true },
      { id: "git", rule: "Do not destroy tracked files", prompt: true, helper: "-", observer: "A git check afterwards sees tracked-file edits only", observer_kind: "detects", prompt_only: false },
      { id: "time", rule: "Stay inside the time box", prompt: true, helper: "-", observer: "The deadline and the Stop button", observer_kind: "stops", prompt_only: false },
    ],
  };
}

async function openThreatModelPlan(page: Page) {
  await openOverview(page);
  await page.getByTestId("assess-kind").filter({ hasText: "Threat model" }).getByRole("button", { name: "Start" }).click();
  await expect(page.getByTestId("assess-scope")).toBeVisible();
}

async function openPentestPlan(page: Page) {
  await openOverview(page);
  await page.getByTestId("assess-kind").filter({ hasText: "Penetration test" }).getByRole("button", { name: "Start" }).click();
  await expect(page.getByTestId("assess-start")).toBeVisible();
}

test("a threat model's scope is chosen on the plan: a ticked folder, a typed place, a refused place and a note, each read again and sent to the launch", async ({ page }) => {
  const wire: Wire = { runs: [], unreadable: false, posts: [], planFor: tmPlanFor };
  await mockWire(page, wire);
  await mockLaunch(page, wire);
  await openThreatModelPlan(page);

  const scope = page.getByTestId("assess-scope");
  const choose = page.getByRole("button", { name: "Choose agent" });
  await expect(scope).toContainText("By default the whole project is covered.");
  await expect(scope.getByTestId("assess-scope-dirs").getByRole("checkbox")).toHaveCount(4);
  // The first read carries none of the choices: an untouched dialog reads what it always did.
  const first = wire.plans![0].searchParams;
  for (const k of ["scope_path", "scope_note", "previous_run", "start"]) expect(first.has(k), k).toBe(false);
  await expect(page.getByTestId("assess-prompt-text")).toContainText("Model the whole project.");

  // Tick a folder: the plan is read again with it, the chip and the line say so, and so does the task.
  await page.getByTestId("assess-scope-dir-cmd").check();
  await expect.poll(() => lastPlan(wire).searchParams.getAll("scope_path")).toEqual(["cmd"]);
  await expect(page.getByTestId("assess-scope-chip-cmd")).toBeVisible();
  await expect(page.getByTestId("assess-scope-line")).toContainText("The task asks the agent to model only cmd.");
  await expect(scope).toContainText("the agent is not stopped from reading anything");
  await expect(page.getByTestId("assess-prompt-text")).toContainText("Model only: cmd.");

  // Type a place: until it is added the button waits (the place is not in the task yet); Enter adds it.
  const typed = page.getByTestId("assess-scope-input");
  await typed.fill("internal/db");
  await expect(choose).toBeDisabled();
  await typed.press("Enter");
  await expect.poll(() => lastPlan(wire).searchParams.getAll("scope_path")).toEqual(["cmd", "internal/db"]);
  await expect(typed).toHaveValue("");
  await expect(page.getByTestId("assess-scope-chip-internal/db")).toBeVisible();
  await expect(scope).toContainText("2 of 8 places chosen.");

  // A place the server refuses is listed with its reason and is not part of the scope it describes.
  await typed.fill("../etc");
  await scope.getByRole("button", { name: "Add", exact: true }).click();
  await expect(page.getByTestId("assess-scope-refused")).toContainText("../etc: It is outside the project.", { timeout: 15000 });
  await expect(page.getByTestId("assess-scope-line")).toContainText("model only cmd, internal/db.");
  await expect(page.getByTestId("assess-scope-chip-../etc")).toBeVisible();
  await shot(page, "threat-model-scope-refused");

  // Remove it with its chip's button: the refusal and the chip are gone. (The plan for the two places was read
  // a moment ago, so this one is served from what the dialog already holds and sends no request.)
  const reads = wire.plans!.length;
  await page.getByRole("button", { name: "Remove ../etc from the scope" }).click();
  await expect(page.getByTestId("assess-scope-chip-../etc")).toHaveCount(0);
  await expect(page.getByTestId("assess-scope-refused")).toHaveCount(0);
  await expect(page.getByTestId("assess-scope-line")).toContainText("model only cmd, internal/db.");
  expect(wire.plans!.length).toBe(reads);

  // The note applies on Enter, with its count shown; the task carries it as the developer's own words.
  const note = page.getByTestId("assess-scope-note");
  await note.fill("the payment flow");
  await expect(scope).toContainText("16 of 200 characters.");
  await note.press("Enter");
  await expect.poll(() => lastPlan(wire).searchParams.get("scope_note")).toBe("the payment flow");
  await expect(page.getByTestId("assess-prompt-text")).toContainText("The developer says: the payment flow");

  // The earlier run to compare with: the server's pick is selected, No comparison is a choice, and nothing is given to the agent.
  const prev = page.getByTestId("assess-previous");
  const sel = page.getByTestId("assess-previous-select");
  await expect(sel).toHaveValue("00000000000000a1");
  await expect(prev).toContainText("Compared with the earlier run (Threat model, ");
  await expect(prev).not.toContainText("00000000000000a1");
  await expect(prev).toContainText("once the new model is checked.");
  await expect(prev).toContainText("Observer gives the agent nothing from the earlier run and asks it not to open other runs' folders. That is a request, not a barrier.");
  await expect(prev).not.toContainText("Nothing from the earlier run is given to the agent");
  await expect(sel.locator("option")).toHaveText(["No comparison", /^Threat model, [A-Z][a-z]{2} \d+, 20\d\d, .*scope cmd\/api$/, /^Threat model, [A-Z][a-z]{2} \d+, 20\d\d, \d\d:\d\d$/]);
  await sel.selectOption("none");
  await expect.poll(() => lastPlan(wire).searchParams.get("previous_run")).toBe("none");
  await expect(prev).toContainText("No comparison: nothing is compared once the new model is checked.");
  await sel.selectOption("00000000000000a0");
  await expect.poll(() => lastPlan(wire).searchParams.get("previous_run")).toBe("00000000000000a0");
  await expect(prev).toContainText("Compared with the earlier run (Threat model, ");
  await expect(prev).not.toContainText("00000000000000a0");

  // The project facts the task carries, in the settings in force, with its help entry.
  const limits = page.getByTestId("assess-limits");
  await expect(limits).toContainText("The task carries a digest of facts from the project: 6 sections, 3.1 KiB.");
  await expect(limits.locator('[data-help-id="card.code_security_assess_grounding"]')).toBeVisible();
  for (const id of ["assess-scope", "assess-previous", "assess-limits"]) await expect(page.getByTestId(id)).not.toContainText(HONEST);
  await shot(page, "threat-model-plan");

  // The launch carries exactly the choices the plan was read with: the accepted places, the note, the comparison.
  const body = await launchFromPlan(page, wire);
  expect(body).toMatchObject({
    assessment: "threat_model",
    run_id: "00000000000000e5",
    scope_paths: ["cmd", "internal/db"],
    scope_note: "the payment flow",
    previous_run: "00000000000000a0",
    prompt_sha256: "ab".repeat(32),
    tool: "claude-code",
  });
  expect(body).not.toHaveProperty("start");
  expect(JSON.stringify(body)).not.toContain("../etc");
  // And it is what the last plan read asked for.
  const read = lastPlan(wire).searchParams;
  expect(read.getAll("scope_path")).toEqual(body.scope_paths);
  expect(read.get("scope_note")).toBe(body.scope_note);
  expect(read.get("previous_run")).toBe(body.previous_run);
});

test("a threat model plan that was not touched launches with the body it always had", async ({ page }) => {
  const wire: Wire = { runs: [], unreadable: false, posts: [], planFor: tmPlanFor };
  await mockWire(page, wire);
  await mockLaunch(page, wire);
  await openThreatModelPlan(page);
  await expect(page.getByTestId("assess-prompt-text")).toBeVisible();
  const body = await launchFromPlan(page, wire);
  expect(body).toEqual({
    assessment: "threat_model",
    project_root_hash: "h1",
    run_id: "00000000000000e5",
    prompt_sha256: "ab".repeat(32),
    tool: "claude-code",
  });
});

test("a pen test's start command is read from the project: the offered commands, one chosen, one typed, one refused with its reason, and what is launched", async ({ page }) => {
  const wire: Wire = { runs: [], unreadable: false, posts: [], planFor: ptPlanFor };
  await mockWire(page, wire);
  await mockLaunch(page, wire);
  await openPentestPlan(page);

  const start = page.getByTestId("assess-start");
  const choose = page.getByRole("button", { name: "Choose agent" });
  // The offered commands, most likely first, with where each was read from; the server's pick is checked.
  await expect(start).toContainText("How the application starts");
  await expect(page.getByTestId("assess-start-plan-0")).toBeChecked();
  await expect(page.getByTestId("assess-start-plan-1")).not.toBeChecked();
  await expect(start).toContainText("npm run dev");
  await expect(start).toContainText("Port 3000");
  await expect(start).toContainText("Read from package.json scripts");
  await expect(start).toContainText("Preparation steps, not run unless you choose to: python manage.py migrate");
  // The same command in a subfolder is a plan of its own, with its folder said.
  await expect(page.getByTestId("assess-start-plan-2")).not.toBeChecked();
  await expect(start).toContainText("In the folder web/");
  // The server's pick has no preparation steps, so there is no opt-in yet.
  await expect(page.getByTestId("assess-prepare")).toHaveCount(0);
  await expect(start).toContainText("Needs: db. The sandbox has no container engine.");
  await expect(start).toContainText("No declared command: the agent looks for one itself");
  await expect(page.getByTestId("assess-start-line")).toContainText("The agent is told to start the application with: npm run dev.");
  await expect(page.getByTestId("assess-start-input")).toHaveValue("npm run dev");
  // The address candidates say where they were read from.
  await expect(page.getByTestId("assess-target")).toContainText("from .claude/launch.json");
  const first = wire.plans![0].searchParams;
  expect(first.has("start"), "an untouched dialog sends no start").toBe(false);

  // Choose the second offered command: the plan is read with it.
  await page.getByTestId("assess-start-plan-1").check();
  await expect.poll(() => lastPlan(wire).searchParams.get("start")).toBe("python manage.py runserver 8000");
  await expect(page.getByTestId("assess-start-line")).toContainText("start the application with: python manage.py runserver 8000.");
  await expect(page.getByTestId("assess-start-input")).toHaveValue("python manage.py runserver 8000");

  // Its preparation steps are an opt-in under it: unticked, listed, and why. Ticking reads the plan again with prepare=yes.
  const prepare = page.getByTestId("assess-prepare");
  await expect(prepare).toContainText("Run the preparation steps first");
  await expect(prepare).toContainText("python manage.py migrate");
  await expect(prepare).toContainText("Preparation steps can change local data in the project, for example its database file.");
  await expect(page.getByTestId("assess-prepare-check")).not.toBeChecked();
  expect(lastPlan(wire).searchParams.get("prepare"), "unticked sends nothing").toBe(null);
  await page.getByTestId("assess-prepare-check").check();
  await expect.poll(() => lastPlan(wire).searchParams.get("prepare")).toBe("yes");
  await expect(page.getByTestId("assess-start-line")).toContainText("It is told to run the preparation steps first.");
  await expect(page.getByTestId("assess-prepare-check")).toBeChecked();
  await shot(page, "pentest-prepare-optin");
  // Picking another plan clears it: the steps belong to one plan. The folder plan is picked by its choice, and the field shows the command.
  await page.getByTestId("assess-start-plan-2").check();
  await expect.poll(() => lastPlan(wire).searchParams.get("start")).toBe("web::npm run dev");
  await expect.poll(() => lastPlan(wire).searchParams.get("prepare")).toBe(null);
  await expect(page.getByTestId("assess-start-plan-2")).toBeChecked();
  await expect(page.getByTestId("assess-start-plan-0")).not.toBeChecked();
  await expect(page.getByTestId("assess-start-input")).toHaveValue("npm run dev");
  await expect(page.getByTestId("assess-start-line")).toContainText("start the application with: npm run dev (in web/).");
  await expect(page.getByTestId("assess-prepare")).toHaveCount(0);
  // Back to the Python plan: unticked again. That address was read before, so the page may answer from its cache and make no new read.
  await page.getByTestId("assess-start-plan-1").check();
  await expect(page.getByTestId("assess-start-plan-1")).toBeChecked();
  await expect(page.getByTestId("assess-prepare-check")).not.toBeChecked();
  expect(lastPlan(wire).searchParams.get("prepare")).toBe(null);

  // Type one: Use this command waits for a change, the launch button waits for it, and using it reads the plan.
  const input = page.getByTestId("assess-start-input");
  const use = start.getByRole("button", { name: "Use this command" });
  await expect(use).toBeDisabled();
  await input.fill("make dev");
  await expect(use).toBeEnabled();
  await expect(choose).toBeDisabled();
  await use.click();
  await expect.poll(() => lastPlan(wire).searchParams.get("start")).toBe("make dev");
  await expect(page.getByTestId("assess-start-line")).toContainText("start the application with: make dev (typed by you).");
  await expect(page.getByTestId("assess-start-plan-0")).not.toBeChecked();
  await expect(page.getByTestId("assess-start-plan-1")).not.toBeChecked();

  // One that cannot be expressed is refused with the server's reason, and nothing can start.
  await input.fill("npm run dev | tee log");
  await use.click();
  await expect(page.getByTestId("assess-start-error")).toContainText("The start command has a character that is not accepted", { timeout: 15000 });
  await expect(page.getByText("This cannot start here")).toBeVisible();
  await expect(choose).toBeDisabled();
  await shot(page, "pentest-start-refused");

  // No declared command is a choice too, said as such.
  await page.getByTestId("assess-start-none").check();
  await expect.poll(() => lastPlan(wire).searchParams.get("start")).toBe("none");
  await expect(page.getByTestId("assess-start-line")).toContainText("No start command is declared, so the agent is told to find one itself.");
  await expect(page.getByTestId("assess-start-input")).toHaveValue("");

  // Back to the first offered command, then the target, its confirmation and the launch.
  await page.getByTestId("assess-start-plan-0").check();
  await expect.poll(() => lastPlan(wire).searchParams.get("start")).toBe("npm run dev");
  await page.getByTestId("assess-target-input").fill("http://localhost:3000/");
  await page.getByRole("button", { name: "Use this address" }).click();
  await expect.poll(() => lastPlan(wire).searchParams.get("target")).toBe("http://localhost:3000/");
  await expect(page.getByTestId("assess-prompt-text")).toContainText("The start command: npm run dev.");
  await page.getByTestId("assess-confirm").getByRole("checkbox").check();
  await expect(start).not.toContainText(HONEST);
  const body = await launchFromPlan(page, wire);
  expect(body).toMatchObject({
    assessment: "pentest_local",
    run_id: "00000000000000c4",
    target: "http://localhost:3000/",
    confirm_target: "http://localhost:3000/",
    start: "npm run dev",
    prompt_sha256: "cd".repeat(32),
  });
  expect(body).not.toHaveProperty("scope_paths");
  expect(body).not.toHaveProperty("previous_run");
  // The route chooses the sandbox for a pen test: the dialog hides its Isolation and
  // Workspace controls and sends none of their members (the first live run was refused
  // at E6 when the route read a sandbox flag this body never carries).
  for (const m of ["sandbox", "backend", "workspace_source", "workspace_remote", "workspace_branch", "sign_in_seed", "sign_in_ask"]) {
    expect(body).not.toHaveProperty(m);
  }
  expect(lastPlan(wire).searchParams.get("start")).toBe(body.start);
});

test("a pen test plan lists what Observer noticed, the environment files, the tools and what holds each rule, and says where the limits are held", async ({ page }) => {
  const wire: Wire = { runs: [], unreadable: false, posts: [], planFor: ptPlanFor };
  await mockWire(page, wire);
  await openPentestPlan(page);

  // The notes read likely-to-fail first, then worth knowing, then notes: advice, never a refusal.
  const before = page.getByTestId("assess-before");
  await expect(before).toContainText("Before it starts");
  const notes = page.getByTestId("assess-preflight").locator("li");
  await expect(notes).toHaveCount(3);
  await expect(notes.nth(0)).toContainText("Likely to fail");
  await expect(notes.nth(0)).toContainText("No node_modules folder: the sandbox cannot install packages, so install them outside it first.");
  await expect(notes.nth(1)).toContainText("Worth knowing");
  await expect(notes.nth(1)).toContainText("2 environment files are in this folder.");
  await expect(notes.nth(2)).toContainText("Note");
  await expect(notes.nth(2)).toContainText("An API spec was found at openapi.json.");
  // The environment files: the sentence, and the names only.
  const env = page.getByTestId("assess-env");
  await expect(env).toContainText("2 .env files are in this folder and are readable inside the sandbox.");
  await expect(env).toContainText("Named: .env, .env.local.");
  // Only the top level is counted, and the dialog says so beside the server's sentence.
  await expect(page.getByTestId("assess-env-top-level")).toContainText("Only environment files at the top level of this folder are counted.");
  await expect(page.getByTestId("assess-env-top-level")).toContainText("Those in subfolders are not");

  // The tools: folded, then opened. Found, not found with the fallback and the scanner's answer, not known.
  const tools = page.getByTestId("assess-tools");
  await expect(tools.getByText("Send HTTP requests")).toBeHidden();
  await tools.getByText("Tools in the sandbox").click();
  await expect(tools).toContainText("Send HTTP requests. Found in the sandbox's standard folders.");
  await expect(tools).toContainText("Scan ports. Not found in the sandbox's standard folders. The agent sends the requests itself. It may need your answer: Observer's guard can ask before it runs.");
  await expect(tools).toContainText("Run the request helper. Observer could not tell whether it is there; the agent checks for itself.");

  // What holds each rule: folded, then opened; a rule only the task holds says so.
  const safety = page.getByTestId("assess-safety");
  await expect(safety.getByText("At most 5 requests a second")).toBeHidden();
  await safety.getByText("What holds each rule").click();
  await expect(page.getByTestId("assess-safety-pace")).toContainText("Held by the task only");
  // Only a check that prevents reads as held outside the task; a check afterwards and a Stop button say what they are.
  await expect(page.getByTestId("assess-safety-target")).toContainText("Held outside the task");
  await expect(page.getByTestId("assess-safety-target")).not.toContainText("Also held outside the task");
  await expect(page.getByTestId("assess-safety-git")).toContainText("Checked afterwards, not prevented");
  await expect(page.getByTestId("assess-safety-git")).not.toContainText("Held outside the task");
  await expect(page.getByTestId("assess-safety-time")).toContainText("You can stop the run; the limit is advisory");
  await expect(page.getByTestId("assess-safety-time")).not.toContainText("Held outside the task");
  await expect(page.getByTestId("assess-safety-target")).toContainText("Observer: The sandbox's network");
  await shot(page, "pentest-before-it-starts");

  // The settings in force name the request limits, the project facts and what happens to environment files.
  const limits = page.getByTestId("assess-limits");
  await expect(limits).toContainText("Request budget 600, at most 5 a second. Held by the task only: nothing between the agent and the target counts them.");
  await expect(limits).toContainText("The task carries a digest of facts from the project, without the open findings: 4 sections, 1.9 KiB.");
  await expect(limits).toContainText("2 strings were left out");
  await expect(limits).toContainText("Environment files: Hide in the sandbox is chosen, but the sandbox this run will use cannot hide files, so it acts as a warning.");
  for (const id of ["assess-before", "assess-limits"]) await expect(page.getByTestId(id)).not.toContainText(HONEST);
  // Advice is not a refusal: nothing here stopped the plan, and a threat model's sections are not here.
  await expect(page.getByText("This cannot start here")).toHaveCount(0);
  await expect(page.getByTestId("assess-scope")).toHaveCount(0);
  await expect(page.getByTestId("assess-previous")).toHaveCount(0);
});

test("a run row says what a threat model was scoped to and what it is compared with", async ({ page }) => {
  const scoped = { ...endedRun(), id: "00000000000000f7", scope: { paths: ["cmd/api", "internal/db"], note: "the payment flow" }, previous_run: "00000000000000a1" };
  const wire: Wire = { runs: [scoped, { ...endedRun(), id: "00000000000000f8" }], unreadable: false, posts: [] };
  await mockWire(page, wire);
  await openOverview(page);
  await expect(page.getByTestId("assess-run")).toHaveCount(2);
  const lines = page.getByTestId("assess-run-scope");
  await expect(lines).toHaveCount(1);
  await expect(lines).toContainText("Scope: cmd/api, internal/db. Note: the payment flow. Compared with an earlier run that is no longer in the list: shown once the model is checked");
  await expect(lines).not.toContainText("00000000000000a1");
  await expect(lines).not.toContainText(HONEST);
});

test("a run row says its comparison was not made when the earlier run's copy is gone, and keeps a note given without any place", async ({ page }) => {
  const gone = { ...endedRun(), id: "00000000000000f9", scope: { paths: [], note: "only the payment flow" }, previous_run: "00000000000000a1", compare_state: "previous_missing" };
  const wire: Wire = { runs: [gone], unreadable: false, posts: [] };
  await mockWire(page, wire);
  await openOverview(page);
  const lines = page.getByTestId("assess-run-scope");
  await expect(lines).toHaveCount(1);
  await expect(lines).toContainText("Note: only the payment flow. Not compared with an earlier run that is no longer in the list: Observer no longer has a usable checked copy of it");
  await expect(lines).not.toContainText("00000000000000a1");
  await expect(lines).not.toContainText("shown once the model is checked");
  await expect(lines).not.toContainText(HONEST);
});

test("the Settings card's four new rows change the config: project facts, environment files, request budget and pace", async ({ page }) => {
  const puts: { patches: { key: string; value: unknown; was: unknown }[]; dry: boolean }[] = [];
  await page.route("**/api/config/keys", async (route) => {
    const b = route.request().postDataJSON() as { patches: { key: string; value: unknown; was: unknown }[]; dry_run?: boolean };
    puts.push({ patches: b.patches, dry: b.dry_run === true });
    await route.continue();
  });
  await page.addInitScript(() => {
    try {
      localStorage.setItem("sb_tour_completed", "1");
      sessionStorage.setItem("sb_firstrun_closed_this_visit", "1");
    } catch {
      /* private mode: ignore */
    }
  });
  await page.goto("/settings?section=guard", { waitUntil: "domcontentloaded" });
  const rows: { key: string; label: RegExp; to: string; asValue: unknown }[] = [
    { key: "grounding", label: /Project facts in the task/, to: "without_findings", asValue: "without_findings" },
    { key: "workspace_secret_mode", label: /Environment files in a penetration test/, to: "refuse", asValue: "refuse" },
    { key: "pentest_request_budget", label: /Most requests a penetration test sends/, to: "1200", asValue: 1200 },
    { key: "pentest_pace_rps", label: /Fastest a penetration test sends requests/, to: "2", asValue: 2 },
  ];
  for (const r of rows) {
    const sel = page.getByTestId(`code-security-setting-security.assessments.${r.key}`);
    await expect(sel, r.key).toBeVisible({ timeout: 20000 });
    await expect(sel.locator("xpath=ancestor::div[1]").getByText(r.label)).toBeVisible();
    const was = await sel.inputValue();
    // Pick a value the row does not hold now, so a rerun against the same config still changes it.
    const to = was === r.to ? (await sel.locator("option").evaluateAll((os) => os.map((o) => (o as HTMLOptionElement).value))).find((v) => v !== was)! : r.to;
    const before = puts.length;
    await sel.selectOption(to);
    // A dry run first, then the write, each with the key, the value as its own type, and what it was.
    await expect.poll(() => puts.length, { timeout: 15000 }).toBe(before + 2);
    const [dry, write] = puts.slice(before);
    const numeric = typeof r.asValue === "number";
    const want = { key: `security.assessments.${r.key}`, value: numeric ? Number(to) : to, was: numeric ? Number(was) : was };
    expect(dry).toEqual({ patches: [want], dry: true });
    expect(write).toEqual({ patches: [want], dry: false });
    // The row holds the new value once the config is read again.
    await expect(sel).toHaveValue(to, { timeout: 15000 });
  }
  await page.getByTestId("code-security-setting-security.assessments.grounding").scrollIntoViewIfNeeded();
  await shot(page, "settings-assessments-rows");
  // Put the four back to their defaults, so the isolated config is as a new one reads.
  const defaults: Record<string, string> = { grounding: "full", workspace_secret_mode: "mask", pentest_request_budget: "600", pentest_pace_rps: "5" };
  for (const r of rows) {
    const sel = page.getByTestId(`code-security-setting-security.assessments.${r.key}`);
    const before = puts.length;
    await sel.selectOption(defaults[r.key]);
    await expect.poll(() => puts.length, { timeout: 15000 }).toBe(before + 2);
    await expect(sel).toHaveValue(defaults[r.key], { timeout: 15000 });
  }
});

test("the plan dialog fits a phone: no horizontal scroll with the scope, the start command and every fact", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  const longPath = "services/payments/internal/ledger/reconciliation/adapters/postgres/migrations";
  const longCommand = "python manage.py runserver 0.0.0.0:8000 --settings=config.settings.development --noreload";
  const wire: Wire = {
    runs: [],
    unreadable: false,
    posts: [],
    planFor: (u) => {
      if (u.searchParams.get("kind") === "threat_model") {
        const p = tmPlanFor(u) as { scope: Record<string, unknown> };
        return { ...(p as object), scope: { ...p.scope, dirs: ["cmd", "internal", "web", longPath] } };
      }
      const p = ptPlanFor(u) as { start: { plans: Record<string, unknown>[] } };
      return { ...(p as object), start: { ...p.start, plans: [{ command: longCommand, port: 8000, source: "manage.py", prepare: ["python manage.py migrate"], needs: ["db", "redis"] }, ...p.start.plans] } };
    },
  };
  await mockWire(page, wire);
  // overflowOf is how far each named part of the dialog (and the dialog and the page) reaches past
  // its own width, and the elements of the plan whose content is wider than they are.
  const overflowOf = (ids: string[]) =>
    page.evaluate((testIds) => {
      const out: Record<string, number> = { document: document.documentElement.scrollWidth - document.documentElement.clientWidth };
      for (const id of testIds) {
        const el = document.querySelector(`[data-testid="${id}"]`);
        if (el) out[id] = el.scrollWidth - el.clientWidth;
      }
      const modal = document.querySelector('[data-testid="assess-plan"]')?.closest('[role="dialog"]');
      if (modal) out.dialog = modal.scrollWidth - modal.clientWidth;
      // An element whose content is wider than it is (a long unbroken word, say) or that ends past the
      // phone's right edge. The task text and native controls scroll or clip by design.
      const past = [...document.querySelectorAll('[data-testid="assess-plan"] *')]
        .filter((e) => !e.closest("pre, select, input, textarea, svg"))
        .filter((e) => e.scrollWidth > e.clientWidth + 1 || e.getBoundingClientRect().right > window.innerWidth + 1)
        .map((e) => `${e.tagName.toLowerCase()}.${String(e.className).slice(0, 40)}:${(e.textContent ?? "").slice(0, 30)}`);
      return { out, past };
    }, ids);

  // A threat model: a long folder name among the choices, a long place typed and ticked.
  await openOverview(page);
  await page.getByTestId("assess-kind").filter({ hasText: "Threat model" }).getByRole("button", { name: "Start" }).click();
  await expect(page.getByTestId("assess-scope")).toBeVisible();
  await page.getByTestId(`assess-scope-dir-${longPath}`).check();
  await expect(page.getByTestId(`assess-scope-chip-${longPath}`)).toBeVisible();
  await expect(page.getByTestId("assess-previous")).toBeVisible();
  await shot(page, "threat-model-plan-390");
  const tm = await overflowOf(["assess-plan", "assess-scope", "assess-previous", "assess-limits"]);
  for (const [k, v] of Object.entries(tm.out)) expect(v, `threat model ${k}; past the edge: ${tm.past.join(" | ")}`).toBeLessThanOrEqual(1);
  expect(tm.past, "nothing of the threat model plan sticks out past the phone").toEqual([]);
  await page.getByRole("button", { name: "Cancel" }).click();

  // A pen test: a long command with its steps and services, the notes, and both folded lists opened.
  await page.getByTestId("assess-kind").filter({ hasText: "Penetration test" }).getByRole("button", { name: "Start" }).click();
  await expect(page.getByTestId("assess-start")).toBeVisible();
  await page.getByTestId("assess-tools").getByText("Tools in the sandbox").click();
  await page.getByTestId("assess-safety").getByText("What holds each rule").click();
  // The long plan, picked, with its preparation opt-in ticked and the safety rows' longer words showing.
  await page.getByTestId("assess-start-plan-0").check();
  await expect(page.getByTestId("assess-prepare")).toBeVisible();
  await page.getByTestId("assess-prepare-check").check();
  await expect(page.getByTestId("assess-prepare-check")).toBeChecked();
  await page.getByTestId("assess-start-input").fill(longCommand);
  await shot(page, "pentest-plan-390");
  const pt = await overflowOf(["assess-plan", "assess-start", "assess-before", "assess-limits", "assess-tools", "assess-safety", "assess-env"]);
  for (const [k, v] of Object.entries(pt.out)) expect(v, `pen test ${k}; past the edge: ${pt.past.join(" | ")}`).toBeLessThanOrEqual(1);
  expect(pt.past, "nothing of the pen test plan sticks out past the phone").toEqual([]);
});

// --- W5a and W6a: the model view, end to end ---
//
// The review workflow of a developer who opens a checked model: the run row's
// Open model, both kinds of view and their tabs, the threat filters, sort and
// detail, the matrix with its empty and waived cells, the flow table and the
// diagram source that is copied, the coverage rows of a pen test and the agent's
// claim beside Observer's "No log", the "how this was checked" strip with every
// limit, the comparison with an earlier run, the refusals in words, and the
// layout at phone width and in both themes. The answers of the model route are
// the fixtures the lib and component tests also read
// (src/lib/secAssessModelFixture.ts); the page, the shell, the modal, the
// controls and the clipboard are real.

const TM_ID = FIXTURE_TM.record.run_id;
const PT_ID = FIXTURE_PT.record.run_id;
const PT_EMPTY_ID = FIXTURE_PT_EMPTY.record.run_id;

// The Windows clipboard turns line breaks into CRLF; the text is otherwise as it was.
const CRLF = /\r\n/g;

// The words no sentence Observer writes may use because they read as a clearance:
// one shared list (internal/secassess/testdata/clearance_words.json) read by the Go
// test, the lib and component tests and this spec.
const CLEARANCE = parseClearanceList(readFileSync(new URL("../../internal/secassess/testdata/clearance_words.json", import.meta.url), "utf8"));
const BANNED = clearanceRegExp(CLEARANCE);

test("the clearance list this spec reads catches every sample it names as caught and lets every allowed one through", () => {
  expect(CLEARANCE.words.length).toBeGreaterThan(5);
  for (const sample of CLEARANCE.caught ?? []) expect(sample, `${sample} should be caught`).toMatch(BANNED);
  for (const sample of CLEARANCE.allowed ?? []) expect(sample, `${sample} should be allowed`).not.toMatch(BANNED);
});

function checkedRun(id: string, kind: string, title: string, contract: string, extra: MockRun = {}): MockRun {
  return {
    ...endedRun(),
    id,
    kind,
    kind_title: title,
    state: "validated",
    contract,
    files: { report: true, sarif: false, commands: false, model: true },
    // The server sends has_model true only while the checked copy is stored; a row without it offers no Open model.
    has_model: true,
    audit: "no_change",
    audit_words: "No git change seen",
    has_data: true,
    validation: { state: "partial", at: "2026-11-14T09:30:00Z", refused: 0, refs: { found: 2, exists: 1, claimed_not_found: 1, missing: 1, invalid: 0, unchecked: 1 } },
    ...extra,
  };
}

const TM_RUN = checkedRun(TM_ID, "threat_model", "Threat model", "threatmodel.v1", { created_at: "2026-11-14T08:00:00Z" });
const TM_EARLIER = checkedRun(FIXTURE_SINCE_RUN, "threat_model", "Threat model", "threatmodel.v1", { created_at: "2026-11-13T08:00:00Z" });
const PT_RUN = checkedRun(PT_ID, "pentest_local", "Penetration test (your own app, local)", "pentest.v1", { created_at: "2026-11-14T10:00:00Z", target: "http://localhost:3000/" });
const PT_EMPTY_RUN = checkedRun(PT_EMPTY_ID, "pentest_local", "Penetration test (your own app, local)", "pentest.v1", { created_at: "2026-11-14T11:00:00Z", target: "http://localhost:3000/" });

const TM_LATER = checkedRun("00000000000000c9", "threat_model", "Threat model", "threatmodel.v1", { created_at: "2026-11-15T08:00:00Z" });
// A threat model of the same project and kind with no stored checked copy (the server leaves has_model out).
const TM_NO_COPY = checkedRun("00000000000000c8", "threat_model", "Threat model", "threatmodel.v1", { created_at: "2026-11-12T08:00:00Z", has_model: undefined });
const TM_REFUSED_ID = FIXTURE_TM_REFUSED_ALL.record.run_id;
const PT_REFUSED_ID = FIXTURE_PT_REFUSED_ALL.record.run_id;
const TM_REFUSED_RUN = checkedRun(TM_REFUSED_ID, "threat_model", "Threat model", "threatmodel.v1", { created_at: "2026-11-14T12:00:00Z" });
const PT_REFUSED_RUN = checkedRun(PT_REFUSED_ID, "pentest_local", "Penetration test (your own app, local)", "pentest.v1", { created_at: "2026-11-14T12:30:00Z", target: "http://localhost:3000/" });
const BIG_TM_RUN = checkedRun(FIXTURE_BIG_TM_RUN, "threat_model", "Threat model", "threatmodel.v1", { created_at: "2026-11-14T13:00:00Z" });
const BIG_PT_RUN = checkedRun(FIXTURE_BIG_PT_RUN, "pentest_local", "Penetration test (your own app, local)", "pentest.v1", { created_at: "2026-11-14T13:30:00Z", target: "http://localhost:3000/" });

type ModelWire = Wire & {
  modelReads: string[];
  sinceRefusal?: { code: string; error: string };
  missing?: boolean;
  /** Answers by run id, in place of the fixed ones. */
  answers?: Record<string, AssessModelResponse>;
};

function newWire(runs: MockRun[]): ModelWire {
  return { runs, unreadable: false, posts: [], modelReads: [] };
}

async function mockModels(page: Page, wire: ModelWire) {
  await page.route("**/api/security/assessments/model*", async (route: Route) => {
    const u = new URL(route.request().url());
    const run = u.searchParams.get("run") ?? "";
    const since = u.searchParams.get("since");
    wire.modelReads.push(since ? `${run}+${since}` : run);
    if (wire.missing) {
      await route.fulfill({ status: 404, json: { error: "no stored model for this run", code: "no_stored_model" } });
      return;
    }
    if (since && wire.sinceRefusal) {
      await route.fulfill({ status: 409, json: wire.sinceRefusal });
      return;
    }
    const fixed = run === TM_ID ? (since ? FIXTURE_TM_SINCE : FIXTURE_TM) : run === PT_ID ? FIXTURE_PT : run === PT_EMPTY_ID ? FIXTURE_PT_EMPTY : null;
    const body = wire.answers?.[run] ?? fixed;
    if (!body) {
      await route.fulfill({ status: 404, body: "unknown run", contentType: "text/plain" });
      return;
    }
    await route.fulfill({ json: body });
  });
}

/** openRun mocks the wire and opens the model of the first run row whose text holds `title`. */
async function openRun(page: Page, wire: ModelWire, title: string) {
  await mockWire(page, wire);
  await mockModels(page, wire);
  await openOverview(page);
  await page.getByTestId("assess-run").filter({ hasText: title }).first().getByTestId("assess-open-model").click();
  return page.getByTestId("assess-model");
}

/** clipboardText reads the clipboard; the Windows clipboard turns line breaks into CRLF, the text is otherwise as it was. */
async function clipboardText(page: Page): Promise<string> {
  return (await page.evaluate(() => navigator.clipboard.readText())).replace(CRLF, "\n");
}

/** tabTo presses Tab until `target` has focus and fails the moment focus is outside the dialog. It returns how many presses it took. */
async function tabTo(page: Page, target: Locator, limit = 80): Promise<number> {
  for (let i = 0; i <= limit; i++) {
    if (await target.evaluate((el) => el === document.activeElement)) return i;
    await page.keyboard.press("Tab");
    const inside = await page.evaluate(() => !!document.activeElement?.closest('[role="dialog"]'));
    expect(inside, `focus is still inside the dialog after ${i + 1} Tab presses`).toBe(true);
  }
  throw new Error(`Tab did not reach the button within ${limit} presses`);
}

/** dialogNodes is how many elements the open dialog holds. */
async function dialogNodes(page: Page): Promise<number> {
  return page.getByRole("dialog").evaluate((el) => el.querySelectorAll("*").length);
}

/** paintMs presses the element the selector names, inside the page, and returns the milliseconds until the second frame after the press: how long a reader waits for the screen to change. */
async function paintMs(page: Page, selector: string): Promise<number> {
  return page.evaluate(async (sel) => {
    const el = document.querySelector<HTMLElement>(sel);
    if (!el) throw new Error(`nothing matches ${sel}`);
    const frame = () => new Promise<void>((resolve) => requestAnimationFrame(() => requestAnimationFrame(() => resolve())));
    const t0 = performance.now();
    el.click();
    await frame();
    return performance.now() - t0;
  }, selector);
}

function median(xs: number[]): number {
  const v = [...xs].sort((a, b) => a - b);
  return v[Math.floor(v.length / 2)];
}

/** pressShowMore presses Show more once. The table also draws its next batch by itself as its end nears the viewport, so under load a press can lose that race and find the button gone or moved; the row counts the test asserts afterwards are the check, not the press. */
async function pressShowMore(more: Locator): Promise<void> {
  await more.click({ timeout: 3_000 }).catch(() => undefined);
}

/** modalOverflow is how far the dialog's scrolling body is wider than its box. The body is the parent of the model view, and it is what a horizontal scroll bar would belong to: a block wider than the phone shows here and not in the page. */
async function modalOverflow(page: Page): Promise<number> {
  return page.getByTestId("assess-model").evaluate((el) => {
    const body = el.parentElement;
    if (!body) throw new Error("the model view has no parent");
    const y = getComputedStyle(body).overflowY;
    if (y !== "auto" && y !== "scroll") throw new Error(`the model view's parent is not the dialog's scrolling body (overflow-y is ${y})`);
    return body.scrollWidth - body.clientWidth;
  });
}

test("Open model is offered on a checked run and opens the threat model overview with its words", async ({ page }) => {
  const wire = newWire([TM_RUN, TM_EARLIER]);
  const view = await openRun(page, wire, "Threat model");
  await expect(view).toBeVisible();
  await expect(view.getByRole("tab")).toHaveText([/Overview/, /Threats/, /Matrix/, /System/, /Flows/, /Attack trees/, /How checked/]);
  // The summary is the agent's and is labelled so; the coverage line is Observer's count.
  await expect(view.getByTestId("assess-overview")).toContainText("The agent says");
  await expect(view.getByTestId("assess-model-coverage-line")).toContainText("Covered by the agent: 4 element and category pairs analysed, 2 waived with a reason and 41 with neither.");
  // Redaction is said by what it does, never by a setting's key, and it says what is not hidden.
  const redaction = view.getByTestId("assess-model-redaction");
  await expect(redaction).toContainText("only known shapes are recognised");
  await expect(redaction).toContainText("file paths are shown as the agent wrote them");
  await expect(redaction).toContainText("The files in your project are as the agent wrote them.");
  await expect(redaction).not.toContainText(/[a-z]+_[a-z]+/);
  await expect(view).not.toContainText(BANNED);
  expect(wire.modelReads).toEqual([TM_ID]);
  await page.screenshot({ path: "e2e/shots/model-overview.png" });
});

test("the threats table lists every threat, filters and sorts, and a threat opens to its mitigations", async ({ page }) => {
  const wire = newWire([TM_RUN, TM_EARLIER]);
  const view = await openRun(page, wire, "Threat model");
  await view.getByRole("tab", { name: "Threats" }).click();

  const rows = view.getByTestId("assess-threat");
  await expect(rows).toHaveCount(5);
  await expect(view.getByTestId("assess-threats-count")).toContainText("Showing 5 of 5 threats");
  // Sorted by band, highest first: the critical one leads.
  await expect(rows.first()).toHaveAttribute("data-threat-id", "T-1");

  // The row says how many references stand behind its mitigation word.
  const rowOf = (id: string) => view.locator("tr", { has: page.locator(`[data-testid="assess-threat"][data-threat-id="${id}"]`) });
  await expect(rowOf("T-1")).toContainText("Found near the cited line");
  await expect(rowOf("T-1")).toContainText("1 of 1 reference");
  await expect(rowOf("T-4")).toContainText("Claimed, not found");

  // A filter by band keeps the matching threats, says how many of how many, and can be cleared.
  await view.getByLabel("Filter by band").selectOption("critical");
  await expect(rows).toHaveCount(1);
  await expect(view.getByTestId("assess-threats-count")).toContainText("Showing 1 of 5 threats");
  await view.getByRole("button", { name: "Clear filters" }).click();
  await expect(rows).toHaveCount(5);

  // The mitigation filter reads the best reference state, in the check's own words.
  await view.getByLabel("Filter by mitigation state").selectOption("claimed_not_found");
  await expect(rows).toHaveCount(1);
  await expect(rows.first()).toHaveAttribute("data-threat-id", "T-4");
  await view.getByRole("button", { name: "Clear filters" }).click();

  // Framework, status and search.
  await view.getByLabel("Filter by framework").selectOption("linddun");
  await expect(rows).toHaveCount(1);
  await view.getByRole("button", { name: "Clear filters" }).click();
  await view.getByLabel("Filter by status").selectOption("partial");
  await expect(rows).toHaveCount(2);
  await view.getByRole("button", { name: "Clear filters" }).click();
  await view.getByLabel("Search threats").fill("session");
  await expect(rows).toHaveCount(1);
  await expect(rows.first()).toHaveAttribute("data-threat-id", "T-2");
  await view.getByLabel("Search threats").fill("no such threat anywhere");
  await expect(rows).toHaveCount(0);
  await expect(view.getByTestId("assess-threats-count")).toContainText("Showing 0 of 5 threats");
  await view.getByRole("button", { name: "Clear filters" }).click();
  await expect(rows).toHaveCount(5);

  // The sort buttons are real buttons: a keyboard sorts too, and the button says which way.
  await view.getByRole("button", { name: /^Sort by title/ }).focus();
  await page.keyboard.press("Enter");
  await expect(view.getByRole("button", { name: "Sort by title, sorted ascending" })).toBeVisible();
  // A sort restarts the table; the keyboard keeps its place on the button, so a second Enter reverses the sort.
  await expect(view.getByRole("button", { name: "Sort by title, sorted ascending" })).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(view.getByRole("button", { name: "Sort by title, sorted descending" })).toBeFocused();

  // Sort by id puts T-1 first; sorting by band twice puts the lowest band first.
  await view.getByRole("button", { name: /^Sort by id/ }).click();
  await expect(rows.first()).toHaveAttribute("data-threat-id", "T-1");
  await view.getByRole("button", { name: /^Sort by band/ }).click();
  await view.getByRole("button", { name: /^Sort by band/ }).click();
  await expect(rows.last()).toHaveAttribute("data-threat-id", "T-1");

  // A threat opens to the agent's description, mitigations with the check's words, and its abuse case.
  await view.getByRole("button", { name: "Details of T-1", exact: true }).click();
  const detail = view.getByTestId("assess-threat-detail");
  await expect(detail).toBeVisible();
  await expect(detail).toContainText("Found near the cited line");
  await expect(detail).toContainText("Location exists, nothing matched");
  await expect(detail).toContainText("Use the parameterised helper in the search route.");
  await expect(detail).toContainText("Read every account's entries.");
  await expect(detail).toContainText("src/api/db.ts");
  await expect(detail).not.toContainText(BANNED);
  await page.screenshot({ path: "e2e/shots/model-threats.png" });

  // One row is open at a time: opening another closes the first, and the same button closes it.
  await view.getByRole("button", { name: "Details of T-2", exact: true }).click();
  await expect(detail).toHaveCount(1);
  await expect(detail).toHaveAttribute("data-threat-id", "T-2");
  await expect(view.getByRole("button", { name: "Details of T-1", exact: true })).toHaveAttribute("aria-expanded", "false");
  await view.getByRole("button", { name: "Details of T-2", exact: true }).click();
  await expect(detail).toHaveCount(0);
});

test("the matrix shows analysed, waived and not-considered cells as three numbers, with every waiver listed", async ({ page }) => {
  const wire = newWire([TM_RUN, TM_EARLIER]);
  const view = await openRun(page, wire, "Threat model");
  await view.getByRole("tab", { name: "Matrix" }).click();
  await expect(view.getByTestId("assess-matrix-totals")).toContainText("4 analysed, 2 waived with a reason, 41 with neither");
  await expect(view.locator('[data-testid="assess-matrix-cell"][data-state="analysed"]')).toHaveCount(4);
  await expect(view.locator('[data-testid="assess-matrix-cell"][data-state="waived"]')).toHaveCount(2);
  await expect(view.locator('[data-testid="assess-matrix-cell"][data-state="empty"]')).toHaveCount(41);
  // A waiver is the agent's word, readable without a hover.
  const waivers = view.getByTestId("assess-waivers");
  await expect(waivers).toContainText("An anonymous visitor claims no identity, so there is nothing to spoof.");
  await expect(waivers).toContainText("The audit log is append-only and written by the API only.");
  // The AI framework's threats have no cells; they are counted.
  await expect(view.getByTestId("assess-matrix-ai")).toBeVisible();
  await expect(view).not.toContainText(/\d+%/);
  await page.screenshot({ path: "e2e/shots/model-matrix.png" });
});

test("the flow table flags a crossing without protection, and the diagram source is copied as it is", async ({ page, context }) => {
  await context.grantPermissions(["clipboard-read", "clipboard-write"]);
  const wire = newWire([TM_RUN, TM_EARLIER]);
  const view = await openRun(page, wire, "Threat model");
  await view.getByRole("tab", { name: "Flows" }).click();
  await expect(view.getByTestId("assess-flow")).toHaveCount(5);
  // Two flows cross a zone with no authentication or no encryption.
  await expect(view.locator('[data-testid="assess-flow"][data-weak="true"]')).toHaveCount(2);
  const source = view.getByTestId("assess-mermaid-source");
  await expect(source).toContainText("flowchart LR");
  await expect(source).toContainText("linkStyle");
  await view.getByRole("button", { name: "Copy diagram source" }).click();
  // The Windows clipboard turns line breaks into CRLF; the text is otherwise as it was.
  const copied = (await page.evaluate(() => navigator.clipboard.readText())).replace(CRLF, "\n");
  expect(copied).toBe(FIXTURE_TM.mermaid!.source);
  // Nothing is drawn and nothing is loaded to draw it.
  await expect(view.locator("svg[data-mermaid], .mermaid")).toHaveCount(0);
  await page.screenshot({ path: "e2e/shots/model-flows.png" });

  // The attack tree is a nested list.
  await view.getByRole("tab", { name: "Attack trees" }).click();
  const tree = view.getByTestId("assess-trees");
  await expect(tree).toContainText("Read another user's entries");
  await expect(tree).toContainText("Inject into the search query");
  await expect(tree.getByTestId("assess-tree-node").first()).toBeVisible();
});

test("how this was checked lists what Observer did and did not do, the issues, and every limit of a threat model", async ({ page }) => {
  const wire = newWire([TM_RUN, TM_EARLIER]);
  const view = await openRun(page, wire, "Threat model");
  await view.getByRole("tab", { name: "How checked" }).click();
  const strip = view.getByTestId("assess-limits");
  await expect(strip).toContainText("did not check that the reasoning is right");
  await expect(strip.getByTestId("assess-issue")).toHaveCount(2);
  await expect(strip.getByTestId("assess-limit")).toHaveCount(11);
  await expect(strip).toContainText("Nothing reported is not a clearance");
  await expect(strip).not.toContainText(BANNED);
  // An issue is a sentence; the check's row and code are behind its Details, never in the sentence.
  await expect(strip.getByTestId("assess-issues")).not.toContainText(/\bV\d+\b|ref_needle_not_found|coverage_empty_cells/);
  await expect(strip.getByTestId("assess-issue-technical")).toHaveCount(0);
  await strip.getByTestId("assess-issue").first().getByRole("button", { name: "Details" }).click();
  await expect(strip.getByTestId("assess-issue-technical")).toContainText("Raised by check V8, code ref_needle_not_found");
});

test("the penetration test view leads with coverage, says tested means claimed, and shows the agent's basis beside No log", async ({ page }) => {
  const wire = newWire([PT_RUN, PT_EMPTY_RUN]);
  await mockWire(page, wire);
  await mockModels(page, wire);
  await openOverview(page);
  // The rows are in the order the server sent them: this pen test, then the empty one.
  await page.getByTestId("assess-run").first().getByTestId("assess-open-model").click();
  const view = page.getByTestId("assess-model");
  await expect(view.getByRole("tab")).toHaveText([/Coverage/, /Findings/, /How checked/]);
  await expect(view.getByTestId("assess-coverage-row")).toHaveCount(8);
  await expect(view.getByTestId("assess-model-coverage-line")).toContainText("Covered by the agent: 5 of 8 categories claimed, 0 with a logged request, 1 skipped, 1 not applicable, 1 with a tool unavailable");
  await expect(view.locator('[data-testid="assess-coverage-row"][data-effective="tested_claimed"]')).toHaveCount(5);
  await expect(view.locator('[data-testid="assess-coverage-row"][data-effective="skipped"]')).toHaveCount(1);
  await expect(view.getByTestId("assess-coverage")).toContainText("Observer cannot see the agent's requests");
  await expect(view).not.toContainText(BANNED);
  await page.screenshot({ path: "e2e/shots/model-coverage.png" });

  await view.getByRole("tab", { name: "Findings" }).click();
  await expect(view.getByTestId("assess-finding")).toHaveCount(3);
  // Opening a finding shows the agent's basis beside Observer's evidence, then the steps, the impact and the fix.
  await view.getByRole("button", { name: "Details of F-1", exact: true }).click();
  const detail = view.getByTestId("assess-finding-detail");
  await expect(detail).toHaveAttribute("data-finding-id", "F-1");
  const ev = detail.getByTestId("assess-finding-evidence");
  await expect(ev).toContainText("The agent says: seen in a request");
  await expect(ev).toContainText("No log");
  await expect(detail).toContainText("GET /api/search?q=rent'--");
  // A finding with no cited place says so; opening it closes the first.
  await view.getByRole("button", { name: "Details of F-3", exact: true }).click();
  await expect(detail).toHaveCount(1);
  await expect(detail).toHaveAttribute("data-finding-id", "F-3");
  await expect(detail).toContainText("No place in the code is cited");
  await expect(view).not.toContainText(BANNED);
  await page.screenshot({ path: "e2e/shots/model-findings.png" });
});

test("a pen test that reported nothing reads as what was not covered, never as a clearance", async ({ page }) => {
  const wire = newWire([PT_EMPTY_RUN, PT_RUN]);
  await mockWire(page, wire);
  await mockModels(page, wire);
  await openOverview(page);
  // The empty one is the newest row.
  await page.getByTestId("assess-run").first().getByTestId("assess-open-model").click();
  const view = page.getByTestId("assess-model");
  const reading = view.getByTestId("assess-model-reading");
  await expect(reading).toContainText("The target was not started, so nothing was tested in a running application");
  await expect(reading).toContainText("this is not proof that none exists");
  await expect(view).not.toContainText(BANNED);
  await expect(view).not.toContainText(/no vulnerabilities|no weaknesses found/i);
  await expect(view.getByTestId("assess-coverage-not-started")).toBeVisible();
});

test("a threat model is compared with an earlier run, and a refused comparison keeps the model on screen", async ({ page }) => {
  const wire = newWire([TM_RUN, TM_EARLIER]);
  const view = await openRun(page, wire, "Threat model");
  await expect(view.getByTestId("assess-since")).toHaveCount(0);
  await view.getByLabel("Compare with an earlier run").selectOption(FIXTURE_SINCE_RUN);
  const diff = view.getByTestId("assess-since");
  await expect(diff).toBeVisible();
  await expect(diff).toContainText("T-1");
  await expect(diff).toContainText("Export route answers without a session");
  await expect(diff).toContainText("does not say which is right");
  await expect(view.getByTestId("assess-since-changed")).toContainText("critical");
  expect(wire.modelReads).toContain(`${TM_ID}+${FIXTURE_SINCE_RUN}`);
  await page.screenshot({ path: "e2e/shots/model-since.png" });
});

test("a refused comparison is said in the server's words and keeps the model on screen", async ({ page }) => {
  const wire = newWire([TM_RUN, TM_EARLIER]);
  wire.sinceRefusal = { code: "since_no_model", error: "the earlier run has no stored model to compare with (it was deleted, or its model was not kept)" };
  const view = await openRun(page, wire, "Threat model");
  await view.getByLabel("Compare with an earlier run").selectOption(FIXTURE_SINCE_RUN);
  await expect(view.getByTestId("assess-since-error")).toContainText("The earlier run has no stored model to compare with");
  await expect(view.getByTestId("assess-since")).toHaveCount(0);
  // The model is still there to read.
  await expect(view.getByRole("tab", { name: "Threats" })).toBeVisible();
  await expect(view.getByTestId("assess-overview")).toBeVisible();
});

test("a run whose checked copy is gone says so in words and offers nothing it cannot show", async ({ page }) => {
  const wire = newWire([TM_RUN]);
  wire.missing = true;
  await openRun(page, wire, "Threat model");
  await expect(page.getByTestId("assess-model-error")).toContainText("No checked copy of this model is stored");
  await expect(page.getByTestId("assess-model-error")).toContainText("Validate the run again");
});

test("export copies the diagram source and the checked model, and says the model is the display copy, not the agent's file", async ({ page, context }) => {
  await context.grantPermissions(["clipboard-read", "clipboard-write"]);
  const wire = newWire([TM_RUN]);
  await openRun(page, wire, "Threat model");
  // Both copies are plain buttons in the dialog's footer, in view at once, and there is no menu.
  const diagram = page.getByTestId("assess-export-diagram");
  const model = page.getByTestId("assess-export-model");
  await expect(diagram).toBeVisible();
  await expect(model).toBeVisible();
  await expect(page.getByRole("menuitem")).toHaveCount(0);
  const note = page.getByTestId("assess-export-note");
  await expect(note).toContainText("recognised secrets hidden while hiding is on");
  await expect(note).toContainText("It is not the agent's file as written.");
  await diagram.click();
  await expect(page.getByTestId("assess-export-copied")).toContainText("Copied");
  expect(await clipboardText(page)).toBe(FIXTURE_TM.mermaid!.source);
  await model.click();
  const json = JSON.parse(await clipboardText(page));
  expect(json.schema).toBe("observer.threatmodel.v1");
  expect(json.threats).toHaveLength(5);
});

test("the report says how many places were hidden, and that the files in the project are as the agent wrote them", async ({ page }) => {
  const wire = newWire([TM_RUN]);
  await mockWire(page, wire);
  await page.route("**/api/security/assessments/report*", (route) =>
    route.fulfill({
      status: 200,
      headers: { "content-type": "text/plain; charset=utf-8", "x-observer-redacted": "2" },
      body: "# Report\nThe key is [REDACTED:aws_access_key] and again [REDACTED:aws_access_key].\n",
    }),
  );
  await openOverview(page);
  await page.getByTestId("assess-run").getByRole("button", { name: "Read report" }).click();
  await expect(page.getByTestId("assess-report-text")).toContainText("[REDACTED:aws_access_key]");
  const note = page.getByTestId("assess-report-redaction");
  await expect(note).toContainText("2 places");
  await expect(note).toContainText("The files in your project are as the agent wrote them.");
});

test("the model view fits a phone, in both themes, with no horizontal scroll in the page or in the dialog on any tab", async ({ page }) => {
  // Fourteen tab visits with a screenshot each.
  test.setTimeout(180_000);
  await page.setViewportSize({ width: 390, height: 844 });
  const wire = newWire([TM_RUN, TM_EARLIER]);
  const view = await openRun(page, wire, "Threat model");
  for (const scheme of ["light", "dark"] as const) {
    await page.emulateMedia({ colorScheme: scheme });
    for (const tab of ["Overview", "Threats", "Matrix", "System", "Flows", "Attack trees", "How checked"]) {
      await view.getByRole("tab", { name: tab }).click();
      await expect(view.getByRole("tab", { name: tab })).toHaveAttribute("aria-selected", "true");
      if (tab === "Threats") {
        // An open row is measured too: its text is the widest thing on the tab.
        const open = view.getByRole("button", { name: "Details of T-1", exact: true });
        if ((await open.getAttribute("aria-expanded")) !== "true") await open.click();
        await expect(view.getByTestId("assess-threat-detail")).toBeVisible();
      }
      const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
      expect(overflow, `${scheme} ${tab} (page)`).toBeLessThanOrEqual(1);
      // The dialog's own scrolling body: the page can fit while the dialog scrolls sideways.
      expect(await modalOverflow(page), `${scheme} ${tab} (dialog body)`).toBeLessThanOrEqual(1);
      await page.screenshot({ path: `e2e/shots/model-phone-${scheme}-${tab.toLowerCase().replace(/[^a-z]+/g, "-")}.png` });
    }
  }
});

// --- W6a and W5a (fix round): the keyboard, big lists, what was not shown, filters, the phone ---

test("the two copy buttons are in the dialog's own tab order: Tab reaches each, Enter copies, and focus stays inside the dialog", async ({ page, context }) => {
  await context.grantPermissions(["clipboard-read", "clipboard-write"]);
  const wire = newWire([TM_RUN]);
  await openRun(page, wire, "Threat model");
  const diagram = page.getByTestId("assess-export-diagram");
  const model = page.getByTestId("assess-export-model");
  await expect(diagram).toBeVisible();

  // Tab from wherever focus starts to the first button; every press stays inside the dialog.
  await tabTo(page, diagram);
  await expect(diagram).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(page.getByTestId("assess-export-copied")).toContainText("Copied");
  expect(await clipboardText(page)).toBe(FIXTURE_TM.mermaid!.source);
  await expect(diagram).toBeFocused();

  // The next Tab is the second button, and Enter copies the checked model.
  await page.keyboard.press("Tab");
  await expect(model).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(page.getByTestId("assess-export-copied")).toContainText("Copied");
  const json = JSON.parse(await clipboardText(page));
  expect(json.schema).toBe("observer.threatmodel.v1");
  await expect(model).toBeFocused();

  // Shift+Tab goes back to the first, and more Tab presses never leave the dialog (the dialog keeps focus in).
  await page.keyboard.press("Shift+Tab");
  await expect(diagram).toBeFocused();
  for (let i = 0; i < 12; i++) {
    await page.keyboard.press("Tab");
    expect(await page.evaluate(() => !!document.activeElement?.closest('[role="dialog"]')), `Tab press ${i + 1} past the buttons`).toBe(true);
  }
});

test("a pen test offers only the checked model to copy, and a keyboard copies it", async ({ page, context }) => {
  await context.grantPermissions(["clipboard-read", "clipboard-write"]);
  const wire = newWire([PT_RUN, PT_EMPTY_RUN]);
  await openRun(page, wire, "Penetration test");
  await expect(page.getByTestId("assess-export-diagram")).toHaveCount(0);
  const model = page.getByTestId("assess-export-model");
  await tabTo(page, model);
  await page.keyboard.press("Enter");
  await expect(page.getByTestId("assess-export-copied")).toContainText("Copied");
  const json = JSON.parse(await clipboardText(page));
  expect(json.schema).toBe("observer.pentest.v1");
  expect(json.findings).toHaveLength(3);
});

test("what the view does not tell you is above the tabs on every tab, with a button to the full list", async ({ page }) => {
  const wire = newWire([TM_RUN, TM_EARLIER]);
  const view = await openRun(page, wire, "Threat model");
  const summary = view.getByTestId("assess-model-limits-summary");
  for (const tab of ["Overview", "Threats", "Matrix", "System", "Flows", "Attack trees", "How checked"]) {
    await view.getByRole("tab", { name: tab }).click();
    await expect(summary, tab).toBeVisible();
    await expect(summary, tab).toContainText("Nothing reported is not a clearance");
    await expect(summary, tab).toContainText("a part it leaves out is unknown, not ruled out");
  }
  await view.getByRole("tab", { name: "Overview" }).click();
  await summary.getByRole("button", { name: "All the limits" }).click();
  await expect(view.getByRole("tab", { name: "How checked" })).toHaveAttribute("aria-selected", "true");
  await expect(view.getByTestId("assess-limit")).toHaveCount(11);
  await expect(view).not.toContainText(BANNED);
});

test("the limits summary of a pen test says the target was a copy and the coverage is the agent's claim", async ({ page }) => {
  const wire = newWire([PT_RUN, PT_EMPTY_RUN]);
  const view = await openRun(page, wire, "Penetration test");
  const summary = view.getByTestId("assess-model-limits-summary");
  for (const tab of ["Coverage", "Findings", "How checked"]) {
    await view.getByRole("tab", { name: tab }).click();
    await expect(summary, tab).toContainText("Nothing reported is not a clearance");
    await expect(summary, tab).toContainText("a copy of your working tree in a box, not production");
  }
});

test("a run row offers Open model only while a checked copy is stored, and the comparison lists only earlier runs that have one", async ({ page }) => {
  const wire = newWire([TM_RUN, TM_EARLIER, TM_LATER, TM_NO_COPY]);
  await mockWire(page, wire);
  await mockModels(page, wire);
  await openOverview(page);
  await expect(page.getByTestId("assess-run")).toHaveCount(4);
  // The run with no stored copy offers none; the other three do.
  await expect(page.getByTestId("assess-open-model")).toHaveCount(3);
  await page.getByTestId("assess-run").first().getByTestId("assess-open-model").click();
  const view = page.getByTestId("assess-model");
  // None, and the one earlier run with a copy: not the run started later, not the run with no copy.
  await expect(view.getByLabel("Compare with an earlier run").locator("option")).toHaveCount(2);
});

test("a diagram that left nodes out or shortened labels says how many, by the names of the two settings", async ({ page }) => {
  const mermaid = { ...FIXTURE_TM.mermaid!, nodes: 5, total_nodes: 9, omitted_nodes: 4, omitted_edges: 2, max_nodes: 5, label_chars: 40, labels_cut: 3 };
  const wire = newWire([TM_RUN]);
  wire.answers = { [TM_ID]: { ...FIXTURE_TM, mermaid } };
  const view = await openRun(page, wire, "Threat model");
  await view.getByRole("tab", { name: "Flows" }).click();
  const counts = view.getByTestId("assess-diagram-counts");
  await expect(counts).toContainText("3 labels were shortened to 40 characters; the full names are in the tables.");
  await expect(counts).toContainText("Most nodes the data-flow diagram source draws");
  await expect(counts).toContainText("Longest label in the data-flow diagram source");
  await expect(counts).not.toContainText(/[a-z]+_[a-z]+/);
});

test("a partly checked threat model says how many threats the check did not list", async ({ page }) => {
  const wire = newWire([TM_RUN]);
  wire.answers = { [TM_ID]: FIXTURE_TM_PARTIAL };
  const view = await openRun(page, wire, "Threat model");
  await expect(view.getByTestId("assess-model-partial")).toContainText("Partly checked");
  await view.getByRole("tab", { name: "Threats" }).click();
  await expect(view.getByTestId("assess-threats-count")).toContainText("Showing 5 of 5 threats");
  await expect(view.getByTestId("assess-threats-unlisted")).toContainText("The agent wrote 6 threats; the check refused 1, so 1 is not listed here. The reasons are under How checked.");
  await view.getByRole("tab", { name: "How checked" }).click();
  await expect(view.getByTestId("assess-issue").first()).toContainText("Likelihood and impact must each be a whole number from 1 to 5.");
  await expect(view).not.toContainText(BANNED);
});

test("a threat model whose every threat the check refused is not read as one that reported none", async ({ page }) => {
  const wire = newWire([TM_REFUSED_RUN]);
  wire.answers = { [TM_REFUSED_ID]: FIXTURE_TM_REFUSED_ALL };
  const view = await openRun(page, wire, "Threat model");
  await expect(view.getByTestId("assess-model-reading")).toContainText("The agent wrote 3 threats, and none is shown here: the check refused 3.");
  await expect(view.getByTestId("assess-model-reading")).toContainText("This says nothing about whether a threat exists; the issues say why.");
  await view.getByRole("tab", { name: "Threats" }).click();
  const threats = view.getByTestId("assess-threats");
  await expect(threats).toContainText("No threat is shown");
  await expect(threats).toContainText("The agent wrote 3 threats; the check refused all 3, so none is shown here. The reasons are under How checked.");
  await expect(threats).not.toContainText("The model lists no threats");
  await expect(threats).not.toContainText("recorded no threat");
  await view.getByRole("tab", { name: "How checked" }).click();
  await expect(view.getByTestId("assess-issue")).toHaveCount(3);
  await expect(view).not.toContainText(BANNED);
});

test("a partly checked pen test says how many findings the check did not list", async ({ page }) => {
  const wire = newWire([PT_RUN]);
  wire.answers = { [PT_ID]: FIXTURE_PT_PARTIAL };
  const view = await openRun(page, wire, "Penetration test");
  await expect(view.getByTestId("assess-model-partial")).toContainText("Partly checked");
  await view.getByRole("tab", { name: "Findings" }).click();
  await expect(view.getByTestId("assess-findings-count")).toContainText("Showing 3 of 3 findings");
  await expect(view.getByTestId("assess-findings-unlisted")).toContainText("The agent wrote 4 findings; the check refused 1, so 1 is not listed here. The reasons are under How checked.");
  await expect(view).not.toContainText(BANNED);
});

test("a pen test whose every finding the check refused is not read as one that reported none", async ({ page }) => {
  const wire = newWire([PT_REFUSED_RUN]);
  wire.answers = { [PT_REFUSED_ID]: FIXTURE_PT_REFUSED_ALL };
  const view = await openRun(page, wire, "Penetration test");
  await expect(view.getByTestId("assess-model-reading")).toContainText("The agent wrote 2 findings, and none is shown here: the check refused 2.");
  await expect(view.getByTestId("assess-model-reading")).toContainText("This says nothing about whether a weakness exists; the issues say why.");
  await view.getByRole("tab", { name: "Findings" }).click();
  const findings = view.getByTestId("assess-findings");
  await expect(findings).toContainText("No finding is shown");
  await expect(findings).toContainText("The agent wrote 2 findings; the check refused all 2, so none is shown here. The reasons are under How checked.");
  await expect(findings).not.toContainText("The agent reported no findings");
  await expect(view).not.toContainText(BANNED);
});

test("the findings list filters by band, category and basis, searches, sorts, and says how many of how many", async ({ page }) => {
  const wire = newWire([PT_RUN, PT_EMPTY_RUN]);
  const view = await openRun(page, wire, "Penetration test");
  await view.getByRole("tab", { name: "Findings" }).click();
  const rows = view.getByTestId("assess-finding");
  const count = view.getByTestId("assess-findings-count");
  await expect(rows).toHaveCount(3);
  await expect(count).toContainText("Showing 3 of 3 findings");
  // The band, highest first.
  await expect(rows.first()).toHaveAttribute("data-finding-id", "F-1");
  await expect(rows.last()).toHaveAttribute("data-finding-id", "F-3");

  await view.getByLabel("Filter findings by band").selectOption("low");
  await expect(rows).toHaveCount(1);
  await expect(rows.first()).toHaveAttribute("data-finding-id", "F-3");
  await expect(count).toContainText("Showing 1 of 3 findings");
  await view.getByRole("button", { name: "Clear filters" }).click();
  await expect(rows).toHaveCount(3);

  await view.getByLabel("Filter findings by basis").selectOption("inferred");
  await expect(rows).toHaveCount(1);
  await expect(rows.first()).toHaveAttribute("data-finding-id", "F-2");
  await view.getByRole("button", { name: "Clear filters" }).click();

  await view.getByLabel("Filter findings by category").selectOption("ATHN");
  await expect(rows).toHaveCount(1);
  await expect(rows.first()).toHaveAttribute("data-finding-id", "F-2");
  await view.getByRole("button", { name: "Clear filters" }).click();

  await view.getByLabel("Search findings").fill("injectable");
  await expect(rows).toHaveCount(1);
  await expect(rows.first()).toHaveAttribute("data-finding-id", "F-1");
  await view.getByLabel("Search findings").fill("no such finding anywhere");
  await expect(rows).toHaveCount(0);
  await expect(count).toContainText("Showing 0 of 3 findings");
  await view.getByRole("button", { name: "Clear filters" }).click();
  await expect(rows).toHaveCount(3);

  // A keyboard sorts: id descending puts F-3 first.
  await view.getByRole("button", { name: /^Sort by id/ }).focus();
  await page.keyboard.press("Enter");
  await expect(rows.first()).toHaveAttribute("data-finding-id", "F-1");
  await page.keyboard.press("Enter");
  await expect(rows.first()).toHaveAttribute("data-finding-id", "F-3");
  await expect(view.getByRole("button", { name: "Sort by id, sorted descending" })).toBeVisible();
});

test("1,500 threats are all reachable in batches, and opening a row or changing the sort stays quick", async ({ page }) => {
  test.setTimeout(240_000);
  const n = 1500;
  const wire = newWire([BIG_TM_RUN]);
  wire.answers = { [FIXTURE_BIG_TM_RUN]: fixtureBigThreatModel(n) };
  const view = await openRun(page, wire, "Threat model");
  await view.getByRole("tab", { name: "Threats" }).click();
  const rows = view.getByTestId("assess-threat");
  await expect(view.getByTestId("assess-threats-count")).toContainText(`Showing ${n} of ${n} threats`);

  // Only the first batch is drawn.
  await expect(rows).toHaveCount(75);
  const first = await dialogNodes(page);
  expect(first, "elements in the dialog with the first batch drawn").toBeLessThan(3500);
  const more = view.getByRole("button", { name: /^Show more/ });
  await expect(more).toContainText(/1,?425 remaining/);

  // With the first batch: open a row, then change the sort (id up, id down, back to the band, the default).
  const openFirst: number[] = [];
  for (const id of ["T-4", "T-8", "T-12"]) {
    openFirst.push(await paintMs(page, `[data-testid="assess-model"] button[aria-label="Details of ${id}"]`));
    await expect(view.getByTestId("assess-threat-detail")).toHaveAttribute("data-threat-id", id);
  }
  await view.getByRole("button", { name: "Details of T-12", exact: true }).click();
  const sortFirst: number[] = [];
  for (const key of ["id", "id", "band"]) sortFirst.push(await paintMs(page, `[data-testid="assess-model"] button[aria-label^="Sort by ${key}"]`));
  await expect(rows).toHaveCount(75);

  // Every threat is reachable: Show more until the last id is on the page, then until there is no more.
  const lastId = `T-${n}`;
  let clicks = 0;
  while ((await view.locator(`[data-testid="assess-threat"][data-threat-id="${lastId}"]`).count()) === 0) {
    await pressShowMore(more);
    clicks++;
    expect(clicks, "Show more presses before the last id appeared").toBeLessThan(40);
  }
  while ((await more.count()) > 0) {
    await pressShowMore(more);
    clicks++;
    expect(clicks, "Show more presses").toBeLessThan(40);
  }
  await expect(rows).toHaveCount(n);
  const ids = await rows.evaluateAll((els) => els.map((e) => (e as HTMLElement).dataset.threatId));
  expect(new Set(ids).size).toBe(n);
  for (let i = 1; i <= n; i++) if (!ids.includes(`T-${i}`)) throw new Error(`T-${i} is not reachable`);
  // The band, highest first, then the agent's order: the last row is the last low one.
  expect(ids.at(-1)).toBe(fixtureThreats(n).filter((t) => t.band === "low").at(-1)!.id);
  const all = await dialogNodes(page);

  // With every row drawn (the worst case): open a row and change the sort.
  const openAll = [await paintMs(page, `[data-testid="assess-model"] button[aria-label="Details of T-4"]`)];
  await expect(view.getByTestId("assess-threat-detail")).toHaveAttribute("data-threat-id", "T-4");
  const sortAll = [await paintMs(page, `[data-testid="assess-model"] button[aria-label^="Sort by id"]`)];
  await expect(rows).toHaveCount(75);

  const report = `threats ${n}: elements in the dialog ${first} (first batch) and ${all} (every row drawn); ${clicks} Show more presses; open a row ${Math.round(median(openFirst))} ms (first batch) and ${Math.round(openAll[0])} ms (every row drawn); change the sort ${Math.round(median(sortFirst))} ms (first batch) and ${Math.round(sortAll[0])} ms (after every row was drawn)`;
  console.log(report);
  test.info().annotations.push({ type: "timing", description: report });
  expect(median(openFirst), "open a row, first batch").toBeLessThan(1500);
  expect(median(sortFirst), "change the sort, first batch").toBeLessThan(1500);
  expect(openAll[0], "open a row, every row drawn").toBeLessThan(4000);
  expect(sortAll[0], "change the sort after every row was drawn").toBeLessThan(4000);
});

test("1,200 findings are all reachable in batches, and opening a row or changing the sort stays quick", async ({ page }) => {
  test.setTimeout(240_000);
  const n = 1200;
  const wire = newWire([BIG_PT_RUN]);
  wire.answers = { [FIXTURE_BIG_PT_RUN]: fixtureBigPentest(n) };
  const view = await openRun(page, wire, "Penetration test");
  await view.getByRole("tab", { name: "Findings" }).click();
  const rows = view.getByTestId("assess-finding");
  await expect(view.getByTestId("assess-findings-count")).toContainText(`Showing ${n} of ${n} findings`);

  await expect(rows).toHaveCount(75);
  const first = await dialogNodes(page);
  expect(first, "elements in the dialog with the first batch drawn").toBeLessThan(3500);
  const more = view.getByRole("button", { name: /^Show more/ });
  await expect(more).toContainText(/1,?125 remaining/);

  const openFirst: number[] = [];
  for (const id of ["F-4", "F-8", "F-12"]) {
    openFirst.push(await paintMs(page, `[data-testid="assess-model"] button[aria-label="Details of ${id}"]`));
    await expect(view.getByTestId("assess-finding-detail")).toHaveAttribute("data-finding-id", id);
  }
  await view.getByRole("button", { name: "Details of F-12", exact: true }).click();
  const sortFirst: number[] = [];
  for (const key of ["id", "id", "band"]) sortFirst.push(await paintMs(page, `[data-testid="assess-model"] button[aria-label^="Sort by ${key}"]`));
  await expect(rows).toHaveCount(75);

  const lastId = `F-${n}`;
  let clicks = 0;
  while ((await view.locator(`[data-testid="assess-finding"][data-finding-id="${lastId}"]`).count()) === 0) {
    await pressShowMore(more);
    clicks++;
    expect(clicks, "Show more presses before the last id appeared").toBeLessThan(40);
  }
  while ((await more.count()) > 0) {
    await pressShowMore(more);
    clicks++;
    expect(clicks, "Show more presses").toBeLessThan(40);
  }
  await expect(rows).toHaveCount(n);
  const ids = await rows.evaluateAll((els) => els.map((e) => (e as HTMLElement).dataset.findingId));
  expect(new Set(ids).size).toBe(n);
  for (let i = 1; i <= n; i++) if (!ids.includes(`F-${i}`)) throw new Error(`F-${i} is not reachable`);
  expect(ids.at(-1)).toBe(fixtureFindings(n).filter((f) => f.band === "low").at(-1)!.id);
  const all = await dialogNodes(page);

  const openAll = [await paintMs(page, `[data-testid="assess-model"] button[aria-label="Details of F-4"]`)];
  await expect(view.getByTestId("assess-finding-detail")).toHaveAttribute("data-finding-id", "F-4");
  const sortAll = [await paintMs(page, `[data-testid="assess-model"] button[aria-label^="Sort by id"]`)];
  await expect(rows).toHaveCount(75);

  const report = `findings ${n}: elements in the dialog ${first} (first batch) and ${all} (every row drawn); ${clicks} Show more presses; open a row ${Math.round(median(openFirst))} ms (first batch) and ${Math.round(openAll[0])} ms (every row drawn); change the sort ${Math.round(median(sortFirst))} ms (first batch) and ${Math.round(sortAll[0])} ms (after every row was drawn)`;
  console.log(report);
  test.info().annotations.push({ type: "timing", description: report });
  expect(median(openFirst), "open a row, first batch").toBeLessThan(1500);
  expect(median(sortFirst), "change the sort, first batch").toBeLessThan(1500);
  expect(openAll[0], "open a row, every row drawn").toBeLessThan(4000);
  expect(sortAll[0], "change the sort after every row was drawn").toBeLessThan(4000);
});

test("the pen test view fits a phone, in both themes, with no horizontal scroll in the page or in the dialog on any tab", async ({ page }) => {
  test.setTimeout(180_000);
  await page.setViewportSize({ width: 390, height: 844 });
  const wire = newWire([PT_RUN, PT_EMPTY_RUN]);
  const view = await openRun(page, wire, "Penetration test");
  for (const scheme of ["light", "dark"] as const) {
    await page.emulateMedia({ colorScheme: scheme });
    for (const tab of ["Coverage", "Findings", "How checked"]) {
      await view.getByRole("tab", { name: tab }).click();
      await expect(view.getByRole("tab", { name: tab })).toHaveAttribute("aria-selected", "true");
      if (tab === "Findings") {
        const open = view.getByRole("button", { name: "Details of F-1", exact: true });
        if ((await open.getAttribute("aria-expanded")) !== "true") await open.click();
        await expect(view.getByTestId("assess-finding-detail")).toBeVisible();
      }
      const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
      expect(overflow, `${scheme} ${tab} (page)`).toBeLessThanOrEqual(1);
      expect(await modalOverflow(page), `${scheme} ${tab} (dialog body)`).toBeLessThanOrEqual(1);
      await page.screenshot({ path: `e2e/shots/model-phone-pt-${scheme}-${tab.toLowerCase().replace(/[^a-z]+/g, "-")}.png` });
    }
  }
});

test("the dialog overflow measurement is not blind: a block 1,200px wide inside the view makes it report overflow, and removing it clears it", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  const wire = newWire([TM_RUN]);
  const view = await openRun(page, wire, "Threat model");
  expect(await modalOverflow(page)).toBeLessThanOrEqual(1);
  await view.evaluate((el) => {
    const probe = document.createElement("div");
    probe.id = "wide-probe";
    probe.style.cssText = "width:1200px;height:8px";
    el.appendChild(probe);
  });
  expect(await modalOverflow(page), "a 1,200px block in a 390px dialog").toBeGreaterThan(500);
  // The page itself does not show it: the dialog's body scrolls sideways, which is why the page measure alone is not enough.
  await view.evaluate(() => document.getElementById("wide-probe")?.remove());
  expect(await modalOverflow(page)).toBeLessThanOrEqual(1);
});

// --- W6b: Fix with an agent on a threat or a finding, and the two downloads ---
//
// The fix and export routes are stubbed (the plan, the refusals, the file the
// server would send); the page, the dialogs, the New terminal dialog in task
// mode, the focus order and the downloads are real. The launch POST is
// intercepted and answered with a refusal, so nothing is started.

const FIX_PROMPT = [
  "You are fixing one threat in the project api.",
  "Read the code at each place below first and decide whether the weakness is real. If it is not, change nothing and say why.",
  "Add a regression test that fails before the fix and succeeds after it. If this place has no test setup, say so instead of inventing a new test framework.",
  "Do not commit or push unless the developer asks you to.",
  "  src/api/search.ts:22 (Found near the cited line)",
].join("\n");

function fixPlanBody(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    confirm_token: "fixtok",
    run: TM_ID,
    item: "T-1",
    item_kind: "threat",
    band: "high",
    project: { name: "api", root_path: "/home/u/api", on_disk: true },
    prompt: FIX_PROMPT,
    prompt_sha256: "cd".repeat(32),
    places: [
      { path: "src/api/search.ts", line: 22, state: "exists" },
      { path: "src/api/db.ts", line: 6, end_line: 6, state: "found" },
    ],
    places_omitted: 0,
    notes: ["The agent's model file changed after this check. The task is built from the checked copy."],
    seeds: { "claude-code": "leading_positional" },
    ...over,
  };
}

type FixWire = ModelWire & {
  /** The plan reads made, in order. */
  fixGets: URL[];
  /** The bodies, and the confirm header, that reached the launch route. */
  fixPosts: { body: Record<string, unknown>; confirm: string | undefined }[];
  /** Answers a plan read; absent: the fixed plan. */
  fixGet?: (u: URL, n: number) => { status: number; json?: unknown; body?: string };
  /** What the launch route answers; absent: the task changed (nothing starts). */
  fixPost?: { status: number; json: unknown };
};

function newFixWire(runs: MockRun[]): FixWire {
  return { ...newWire(runs), fixGets: [], fixPosts: [] };
}

async function mockFix(page: Page, wire: FixWire) {
  await mockLaunch(page, wire);
  await page.route("**/api/security/assessments/fix*", async (route: Route) => {
    const req = route.request();
    if (req.method() === "POST") {
      wire.fixPosts.push({ body: req.postDataJSON() as Record<string, unknown>, confirm: req.headers()["x-observer-confirm"] });
      const a = wire.fixPost ?? { status: 409, json: { error: "The task changed after you read it.", code: "plan_changed", prompt: FIX_PROMPT, prompt_sha256: "ef".repeat(32) } };
      await route.fulfill(a);
      return;
    }
    const u = new URL(req.url());
    wire.fixGets.push(u);
    const a = wire.fixGet?.(u, wire.fixGets.length) ?? { status: 200, json: fixPlanBody({ run: u.searchParams.get("run"), item: u.searchParams.get("item") }) };
    await route.fulfill(a.body !== undefined ? { status: a.status, body: a.body, contentType: "text/plain" } : { status: a.status, json: a.json });
  });
}

/** openRunFix is openRun with the fix and export routes stubbed too. They are registered after the shell's pass-through, which is how the newest route wins. */
async function openRunFix(page: Page, wire: FixWire, title: string) {
  await mockWire(page, wire);
  await mockModels(page, wire);
  await mockFix(page, wire);
  if ("exportGets" in wire) await mockExport(page, wire as ExportWire);
  await openOverview(page);
  await page.getByTestId("assess-run").filter({ hasText: title }).first().getByTestId("assess-open-model").click();
  return page.getByTestId("assess-model");
}

/** openThreat opens the model of the threat model run, the Threats tab and the detail of one threat. */
async function openThreat(page: Page, wire: FixWire, id: string) {
  const view = await openRunFix(page, wire, "Threat model");
  await view.getByRole("tab", { name: "Threats" }).click();
  await view.getByRole("button", { name: `Details of ${id}`, exact: true }).click();
  await expect(view.getByTestId("assess-threat-detail")).toHaveAttribute("data-threat-id", id);
  return view;
}

/** focusInFixDialog is whether focus is inside the fix dialog (the dialog that holds the plan). */
function focusInFixDialog(page: Page): Promise<boolean> {
  return page.evaluate(() => {
    const d = document.querySelector('[data-testid="assess-fix-plan"]')?.closest('[role="dialog"]');
    return !!d && d.contains(document.activeElement);
  });
}

test("a threat that cites a located place offers Fix with an agent, and one that does not offers nothing", async ({ page }) => {
  const wire = newFixWire([TM_RUN]);
  const view = await openThreat(page, wire, "T-1");
  // T-1 names a place in a missing mitigation.
  const button = view.getByTestId("assess-fix-open");
  await expect(button).toBeVisible();
  await expect(button).toHaveText("Fix with an agent");
  await expect(view.getByTestId("assess-fix")).toContainText("Starts a coding agent that edits this project");
  // Opening another row closes this one: T-2 cites only an existing mitigation, T-4 and T-5 name nothing to fix.
  for (const id of ["T-2", "T-4", "T-5"]) {
    await view.getByRole("button", { name: `Details of ${id}`, exact: true }).click();
    await expect(view.getByTestId("assess-threat-detail")).toHaveAttribute("data-threat-id", id);
    await expect(view.getByTestId("assess-fix-open"), id).toHaveCount(0);
  }
  await view.getByRole("button", { name: "Details of T-3", exact: true }).click();
  await expect(view.getByTestId("assess-fix-open")).toBeVisible();
  // Nothing is read until the button is pressed.
  expect(wire.fixGets).toHaveLength(0);
});

test("the fix dialog shows the project, the places, the notes and the exact task, then Choose agent opens New terminal in task mode and the launch posts the item, the digest and the agent", async ({ page }) => {
  const wire = newFixWire([TM_RUN]);
  const view = await openThreat(page, wire, "T-1");
  await view.getByTestId("assess-fix-open").click();

  const dialog = page.getByTestId("assess-fix-plan");
  await expect(dialog).toBeVisible();
  expect(wire.fixGets.map((u) => `${u.pathname}?${u.searchParams.toString()}`)).toEqual([`/api/security/assessments/fix?run=${TM_ID}&item=T-1`]);
  await expect(dialog.getByTestId("assess-fix-headline")).toHaveText("Threat T-1 (band high). The task points the agent at 2 places in the project.");
  await expect(dialog.getByTestId("assess-fix-project")).toContainText("api");
  await expect(dialog).toContainText("/home/u/api");
  const places = dialog.getByTestId("assess-fix-places").locator("li");
  await expect(places).toHaveCount(2);
  await expect(places.nth(0)).toContainText("src/api/search.ts:22");
  await expect(places.nth(0)).toContainText("Location exists, nothing matched");
  await expect(places.nth(1)).toContainText("src/api/db.ts:6");
  await expect(places.nth(1)).toContainText("Found near the cited line");
  await expect(dialog.getByTestId("assess-fix-notes")).toContainText("The agent's model file changed after this check.");
  // The exact task, as the server built it.
  expect(await dialog.getByTestId("assess-fix-prompt").locator("pre").innerText()).toBe(FIX_PROMPT);
  const next = dialog.getByTestId("assess-fix-next");
  await expect(next).toContainText("edits files in this project's live folder");
  await expect(next).toContainText("sandbox");
  await expect(next).toContainText("With no sandbox chosen the agent runs on this machine with your access");
  await expect(dialog).not.toContainText(BANNED);
  await expect(page.getByTestId("assess-fix-choose")).toBeEnabled({ timeout: 15000 });
  await page.screenshot({ path: "e2e/shots/model-fix-dialog.png" });

  // Choose agent closes the plan and opens the New terminal dialog in task mode.
  await page.getByTestId("assess-fix-choose").click();
  await expect(page.getByTestId("assess-fix-plan")).toHaveCount(0);
  const task = page.getByTestId("new-terminal-task");
  await expect(task).toBeVisible();
  await expect(task).toContainText("Fix this threat");
  await expect(task).toContainText("The task points the agent at 2 places");
  await expect(page.getByTestId("new-terminal-task-folder")).toContainText("/home/u/api");
  // The task chooses no sandbox itself: the dialog's own controls are there, not a sentence saying the server decides.
  await expect(page.getByTestId("new-terminal-task-sandbox")).toHaveCount(0);

  // Start posts to the fix route with the item, the digest the developer read and the agent; the server refuses, so nothing starts.
  const start = page.getByRole("button", { name: "Start", exact: true }).last();
  await expect(start).toBeEnabled({ timeout: 15000 });
  await start.click();
  await expect.poll(() => wire.fixPosts.length).toBe(1);
  expect(wire.fixPosts[0].body).toMatchObject({ run: TM_ID, item: "T-1", prompt_sha256: "cd".repeat(32), tool: "claude-code" });
  expect(wire.fixPosts[0].body).not.toHaveProperty("project_root");
  // The dialog sends its confirm header with the task (the real server checks it against the cookie the plan read set).
  expect(wire.fixPosts[0].confirm).toBeTruthy();
  // The refusal is said in the fix's own words, in the dialog.
  await expect(page.getByText("open Fix with an agent again to read the new task")).toBeVisible();
  expect(wire.launches ?? []).toHaveLength(0);
});

test("a finding of a pen test offers the fix when it cites a place, and not when it cites none", async ({ page }) => {
  const wire = newFixWire([PT_RUN, PT_EMPTY_RUN]);
  wire.fixGet = (u) => ({ status: 200, json: fixPlanBody({ run: u.searchParams.get("run"), item: u.searchParams.get("item"), item_kind: "finding" }) });
  const view = await openRunFix(page, wire, "Penetration test");
  await view.getByRole("tab", { name: "Findings" }).click();
  await view.getByRole("button", { name: "Details of F-1", exact: true }).click();
  await expect(view.getByTestId("assess-finding-detail")).toHaveAttribute("data-finding-id", "F-1");
  await expect(view.getByTestId("assess-fix-open")).toBeVisible();
  await view.getByRole("button", { name: "Details of F-3", exact: true }).click();
  await expect(view.getByTestId("assess-finding-detail")).toHaveAttribute("data-finding-id", "F-3");
  await expect(view.getByTestId("assess-fix-open")).toHaveCount(0);
  await view.getByRole("button", { name: "Details of F-2", exact: true }).click();
  await view.getByTestId("assess-fix-open").click();
  await expect(page.getByTestId("assess-fix-headline")).toContainText("Finding F-2");
  expect(wire.fixGets.map((u) => u.searchParams.get("item"))).toEqual(["F-2"]);
});

test("every refusal of the plan is said in words, with Retry only where reading again can help", async ({ page }) => {
  const wire = newFixWire([TM_RUN]);
  const refusals: Record<string, { status: number; json: unknown }> = {
    no_location: { status: 409, json: { error: "this item cites no place that Observer found in the project, so there is nothing to point a fix at", code: "no_location" } },
    unknown_item: { status: 404, json: { error: "the stored model holds no such threat or finding", code: "unknown_item" } },
    project_gone: { status: 409, json: { error: "the project's folder is no longer on this machine", code: "project_gone" } },
    run_running: { status: 409, json: { error: "the run has not ended", code: "run_running" } },
  };
  // The nth read gets the nth answer, so each open of the dialog reads again.
  const order = ["no_location", "unknown_item", "project_gone", "run_running"];
  wire.fixGet = (_u, n) => refusals[order[Math.min(n, order.length) - 1]];
  const view = await openThreat(page, wire, "T-1");
  const error = page.getByTestId("assess-fix-error");
  const rows: Array<[RegExp, boolean]> = [
    [/nothing to point a fix at\. Nothing was started\./, false],
    [/no threat or finding with that id/, false],
    [/no longer on this machine, so there is nothing to fix there\. Nothing was started\./, false],
    [/Wait for the run to end, or stop it, then try again\./, true],
  ];
  for (let i = 0; i < rows.length; i++) {
    if (i > 0) {
      await page.getByTestId("assess-fix-cancel").click();
      await expect(page.getByTestId("assess-fix-plan")).toHaveCount(0);
    }
    await view.getByTestId("assess-fix-open").click();
    await expect(error, order[i]).toContainText(rows[i][0]);
    await expect(page.getByTestId("assess-fix-retry"), order[i]).toHaveCount(rows[i][1] ? 1 : 0);
    await expect(page.getByTestId("assess-fix-choose"), order[i]).toHaveCount(0);
    // Words only: never the code, the status or the raw body.
    await expect(error, order[i]).not.toContainText(/\bcode\b|\{|40\d|no_location|unknown_item|project_gone|run_running/);
    await expect(error, order[i]).not.toContainText(BANNED);
  }
  // The last refusal has Retry: reading again changes the dialog to the plan.
  const before = wire.fixGets.length;
  wire.fixGet = (u) => ({ status: 200, json: fixPlanBody({ run: u.searchParams.get("run"), item: u.searchParams.get("item") }) });
  await page.getByTestId("assess-fix-retry").click();
  await expect(page.getByTestId("assess-fix-headline")).toBeVisible();
  expect(wire.fixGets.length).toBeGreaterThan(before);
  await expect(page.getByTestId("assess-fix-error")).toHaveCount(0);
});

test("a project whose folder is gone is shown, and Choose agent is off", async ({ page }) => {
  const wire = newFixWire([TM_RUN]);
  wire.fixGet = () => ({ status: 200, json: fixPlanBody({ project: { name: "api", root_path: "/gone/api", on_disk: false } }) });
  const view = await openThreat(page, wire, "T-1");
  await view.getByTestId("assess-fix-open").click();
  const dialog = page.getByTestId("assess-fix-plan");
  await expect(dialog).toContainText("Not on this machine");
  await expect(dialog).toContainText("an agent cannot be started on it from here");
  await expect(page.getByTestId("assess-fix-choose")).toBeDisabled();
});

test("a run that has not ended offers no fix and says why on the threats tab", async ({ page }) => {
  const wire = newFixWire([{ ...TM_RUN, ended_at: undefined, can_stop: true }]);
  const view = await openThreat(page, wire, "T-1");
  await expect(view.getByTestId("assess-fix-after-end")).toContainText("Fix with an agent is offered once the run has ended");
  await expect(view.getByTestId("assess-fix-open")).toHaveCount(0);
  await view.getByRole("tab", { name: "Matrix" }).click();
  await expect(view.getByTestId("assess-fix-after-end")).toHaveCount(0);
});

test("Escape closes the fix dialog and leaves the model view open; a second Escape closes the model view", async ({ page }) => {
  const wire = newFixWire([TM_RUN]);
  const view = await openThreat(page, wire, "T-1");
  await view.getByTestId("assess-fix-open").click();
  await expect(page.getByTestId("assess-fix-headline")).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(page.getByTestId("assess-fix-plan")).toHaveCount(0);
  await expect(page.getByTestId("assess-model")).toBeVisible();
  // Focus is back on the button that opened it, so the keyboard carries on from there.
  await expect(page.getByTestId("assess-fix-open")).toBeFocused();
  await page.keyboard.press("Escape");
  await expect(page.getByTestId("assess-model")).toHaveCount(0);
});

test("inside the fix dialog Tab never leaves it, and the Cancel and Choose agent buttons are reached", async ({ page }) => {
  const wire = newFixWire([TM_RUN]);
  const view = await openThreat(page, wire, "T-1");
  await view.getByTestId("assess-fix-open").click();
  const choose = page.getByTestId("assess-fix-choose");
  await expect(choose).toBeEnabled({ timeout: 15000 });
  const reached = new Set<string>();
  for (let i = 0; i < 16; i++) {
    await page.keyboard.press("Tab");
    expect(await focusInFixDialog(page), `Tab press ${i + 1} stays in the fix dialog`).toBe(true);
    const id = await page.evaluate(() => (document.activeElement as HTMLElement | null)?.dataset.testid ?? "");
    if (id) reached.add(id);
  }
  expect(reached.has("assess-fix-cancel")).toBe(true);
  expect(reached.has("assess-fix-choose")).toBe(true);
});

// ---- the downloads ----

type ExportWire = FixWire & { exportGets: URL[]; exportAnswer?: { status: number; body: string; contentType?: string } };

const EXPORT_MD = "# Threat model: api\n\nA report rendered by Observer from the checked copy.\n";
const EXPORT_JSON = '{"schema":"observer.assessment.export.v1","run":"x"}\n';

async function mockExport(page: Page, wire: ExportWire) {
  await page.route("**/api/security/assessments/export*", async (route: Route) => {
    const u = new URL(route.request().url());
    wire.exportGets.push(u);
    if (wire.exportAnswer) {
      await route.fulfill({ status: wire.exportAnswer.status, body: wire.exportAnswer.body, contentType: wire.exportAnswer.contentType ?? "text/plain" });
      return;
    }
    const md = u.searchParams.get("format") === "md";
    await route.fulfill({
      status: 200,
      body: md ? EXPORT_MD : EXPORT_JSON,
      headers: {
        "content-type": md ? "text/plain; charset=utf-8" : "application/json",
        "content-disposition": `attachment; filename="observer-assessment-${u.searchParams.get("run")}.${md ? "md" : "json"}"`,
        "x-content-type-options": "nosniff",
      },
    });
  });
}

function newExportWire(runs: MockRun[]): ExportWire {
  return { ...newFixWire(runs), exportGets: [] };
}

test("the Markdown report and the checked model download as files named by the server, from the export route", async ({ page }) => {
  const wire = newExportWire([TM_RUN]);
  await openRunFix(page, wire, "Threat model");
  const note = page.getByTestId("assess-export-download-note");
  await expect(note).toContainText("rendered by Observer from the checked copy");
  await expect(note).toContainText("not the agent's own report");
  await expect(note).toContainText("recognised secrets are hidden in them while hiding is on");

  const md = page.waitForEvent("download");
  await page.getByTestId("assess-export-download-md").click();
  const mdFile = await md;
  expect(mdFile.suggestedFilename()).toBe(`observer-assessment-${TM_ID}.md`);
  expect(readFileSync((await mdFile.path()) as string, "utf8")).toBe(EXPORT_MD);

  const json = page.waitForEvent("download");
  await page.getByTestId("assess-export-download-json").click();
  const jsonFile = await json;
  expect(jsonFile.suggestedFilename()).toBe(`observer-assessment-${TM_ID}.json`);
  expect(readFileSync((await jsonFile.path()) as string, "utf8")).toBe(EXPORT_JSON);

  expect(wire.exportGets.map((u) => `${u.pathname}?${u.searchParams.toString()}`)).toEqual([
    `/api/security/assessments/export?run=${TM_ID}&format=md`,
    `/api/security/assessments/export?run=${TM_ID}&format=json`,
  ]);
  // No error is shown and the buttons are ready for the next one.
  await expect(page.getByTestId("assess-export-download-error")).toHaveCount(0);
  await expect(page.getByTestId("assess-export-download-md")).toHaveAttribute("aria-busy", "false");
});

test("a refused download says why in words next to the buttons and is never saved as a file", async ({ page }) => {
  const wire = newExportWire([TM_RUN]);
  await openRunFix(page, wire, "Threat model");
  let downloads = 0;
  page.on("download", () => downloads++);
  const error = page.getByTestId("assess-export-download-error");

  wire.exportAnswer = { status: 404, body: JSON.stringify({ error: "no stored model for this run", code: "no_stored_model" }), contentType: "application/json" };
  await page.getByTestId("assess-export-download-md").click();
  await expect(error).toContainText("No checked copy of this run's model is stored. Check the model again. Nothing was saved.");

  wire.exportAnswer = { status: 404, body: "unknown run\n" };
  await page.getByTestId("assess-export-download-json").click();
  await expect(error).toContainText("This run is no longer listed. Nothing was saved.");

  wire.exportAnswer = { status: 500, body: "boom" };
  await page.getByTestId("assess-export-download-md").click();
  await expect(error).toContainText("The download could not be made. Nothing was saved.");
  await expect(error).not.toContainText(BANNED);
  await page.waitForTimeout(400);
  expect(downloads, "a refusal is not a download").toBe(0);

  // The next good answer clears the words.
  wire.exportAnswer = undefined;
  const ok = page.waitForEvent("download");
  await page.getByTestId("assess-export-download-md").click();
  await ok;
  await expect(error).toHaveCount(0);
});

test("a run with no stored model has its model copy and both downloads off, with the reason on hover", async ({ page }) => {
  const wire = newExportWire([TM_RUN]);
  wire.missing = true;
  await openRunFix(page, wire, "Threat model");
  for (const id of ["assess-export-model", "assess-export-download-md", "assess-export-download-json"]) await expect(page.getByTestId(id), id).toBeDisabled();
  await page.getByTestId("assess-export-download-md").locator("xpath=..").hover();
  await expect(page.getByText("There is no model to download from this run.")).toBeVisible();
  expect(wire.exportGets).toHaveLength(0);
});

test("the four export buttons are in the dialog's tab order: Tab reaches each, Enter downloads, and focus stays inside the dialog", async ({ page }) => {
  const wire = newExportWire([TM_RUN]);
  await openRunFix(page, wire, "Threat model");
  // The footer holds exactly the four, in this order, and no menu.
  const labels = await page.getByTestId("assess-export").locator("button[data-testid^='assess-export-']").allInnerTexts();
  expect(labels.map((l) => l.trim())).toEqual(["Copy diagram source", "Copy checked model", "Download report (Markdown)", "Download checked model (JSON)"]);
  await expect(page.getByTestId("assess-export").getByRole("menuitem")).toHaveCount(0);

  const order = ["assess-export-diagram", "assess-export-model", "assess-export-download-md", "assess-export-download-json"];
  await tabTo(page, page.getByTestId(order[0]));
  for (const id of order) {
    await expect(page.getByTestId(id), id).toBeFocused();
    expect(await page.evaluate(() => !!document.activeElement?.closest('[role="dialog"]'))).toBe(true);
    if (id !== order[order.length - 1]) await page.keyboard.press("Tab");
  }
  // Enter on a download button downloads, and focus stays on it.
  const json = page.waitForEvent("download");
  await page.keyboard.press("Enter");
  expect((await json).suggestedFilename()).toBe(`observer-assessment-${TM_ID}.json`);
  await expect(page.getByTestId("assess-export-download-json")).toBeFocused();
  // Further Tab presses never leave the dialog.
  for (let i = 0; i < 12; i++) {
    await page.keyboard.press("Tab");
    expect(await page.evaluate(() => !!document.activeElement?.closest('[role="dialog"]')), `Tab press ${i + 1} past the buttons`).toBe(true);
  }
  // Space downloads the Markdown report from the keyboard too.
  await page.getByTestId("assess-export-download-md").focus();
  const md = page.waitForEvent("download");
  await page.keyboard.press("Space");
  expect((await md).suggestedFilename()).toBe(`observer-assessment-${TM_ID}.md`);
});

test("a pen test has the model copy and both downloads in its footer, and a keyboard downloads the report", async ({ page }) => {
  const wire = newExportWire([PT_RUN, PT_EMPTY_RUN]);
  await openRunFix(page, wire, "Penetration test");
  await expect(page.getByTestId("assess-export-diagram")).toHaveCount(0);
  const md = page.getByTestId("assess-export-download-md");
  await tabTo(page, md);
  const file = page.waitForEvent("download");
  await page.keyboard.press("Enter");
  expect((await file).suggestedFilename()).toBe(`observer-assessment-${PT_ID}.md`);
});

// ---- the phone ----

/** dialogOverflowOf is how far the scrolling body of the dialog that holds the test id is wider than its box. */
async function dialogOverflowOf(page: Page, testId: string): Promise<number> {
  return page.getByTestId(testId).evaluate((el) => {
    const body = el.parentElement;
    if (!body) throw new Error("no parent");
    return body.scrollWidth - body.clientWidth;
  });
}

test("on a short phone the opened Copy and download box is capped and scrolls inside itself, so the model keeps its room and the last button is one Tab away (N-15)", async ({ page }) => {
  await page.setViewportSize({ width: 375, height: 600 });
  const wire = newExportWire([TM_RUN]);
  await openThreat(page, wire, "T-1");
  const room = () =>
    page.getByTestId("assess-model").evaluate((el) => {
      const body = el.parentElement!;
      const footer = document.querySelector("footer")!;
      const box = document.querySelector<HTMLElement>("[data-testid='assess-export-body']");
      return { model: Math.round(body.clientHeight), footer: Math.round(footer.getBoundingClientRect().height), box: box ? Math.round(box.clientHeight) : 0, boxScrolls: box ? box.scrollHeight > box.clientHeight + 1 : false, screen: window.innerHeight };
    });
  const closed = await room();
  await page.getByTestId("assess-export-toggle").click();
  const open = await room();
  expect(open.model, `the model keeps room with the box open: ${JSON.stringify({ closed, open })}`).toBeGreaterThanOrEqual(Math.round(closed.model * 0.5));
  await page.getByTestId("assess-export-download-json").focus();
  await expect(page.getByTestId("assess-export-download-json"), "the last button, focused").toBeInViewport();
  expect(await modalOverflow(page), "dialog body").toBeLessThanOrEqual(1);
});

test("the fix dialog and the export footer fit a phone, in both themes, with no horizontal scroll in the page or in a dialog", async ({ page }) => {
  test.setTimeout(120_000);
  await page.setViewportSize({ width: 390, height: 844 });
  const wire = newExportWire([TM_RUN]);
  // A long path, long notes and a long task are the widest things the dialog holds.
  wire.fixGet = (u) => ({
    status: 200,
    json: fixPlanBody({
      run: u.searchParams.get("run"),
      item: u.searchParams.get("item"),
      project: { name: "api-with-a-rather-long-project-name-for-a-phone", root_path: "/home/u/work/clients/a-deeply/nested/folder/api-with-a-rather-long-project-name-for-a-phone", on_disk: true },
      places: [{ path: "src/very/long/path/to/a/file/that/keeps/going/and/going/searchHandlerImplementation.ts", line: 120, end_line: 188, state: "found" }],
      notes: ["The agent's model file changed after this check. The task is built from the checked copy, which may not match the file now, so read the places before you start."],
      prompt: `${FIX_PROMPT}\n${"x".repeat(180)}`,
    }),
  });
  const view = await openThreat(page, wire, "T-1");
  for (const scheme of ["light", "dark"] as const) {
    await page.emulateMedia({ colorScheme: scheme });
    // The model view's footer: on a phone the four export buttons sit behind one disclosure button (UX-9), collapsed when the view opens.
    const toggle = page.getByTestId("assess-export-toggle");
    if (scheme === "light") {
      await expect(toggle).toHaveAttribute("aria-expanded", "false");
      await expect(page.getByTestId("assess-export-body")).toHaveCount(0);
    }
    if ((await toggle.getAttribute("aria-expanded")) === "false") await toggle.click();
    expect(await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth), `${scheme} model view (page)`).toBeLessThanOrEqual(1);
    expect(await modalOverflow(page), `${scheme} model view (dialog body)`).toBeLessThanOrEqual(1);
    const footer = await page.getByTestId("assess-export").evaluate((el) => {
      const box = el.closest("footer")!;
      const rights = [...el.querySelectorAll<HTMLButtonElement>("button[data-testid^='assess-export-']")].map((b) => Math.round(b.getBoundingClientRect().right));
      return { scroll: box.scrollWidth - box.clientWidth, rights };
    });
    expect(footer.rights).toHaveLength(5);
    expect(footer.scroll, `${scheme} footer`).toBeLessThanOrEqual(1);
    for (const right of footer.rights) expect(right, `${scheme} a footer button's right edge`).toBeLessThanOrEqual(390);
    await page.screenshot({ path: `e2e/shots/model-footer-phone-${scheme}.png` });

    await view.getByTestId("assess-fix-open").click();
    await expect(page.getByTestId("assess-fix-headline")).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth), `${scheme} fix dialog (page)`).toBeLessThanOrEqual(1);
    expect(await dialogOverflowOf(page, "assess-fix-plan"), `${scheme} fix dialog (dialog body)`).toBeLessThanOrEqual(1);
    const box = await page.getByTestId("assess-fix-plan").evaluate((el) => {
      const card = el.closest('[role="dialog"]')!.getBoundingClientRect();
      return { left: Math.round(card.left), right: Math.round(card.right) };
    });
    expect(box.left, `${scheme} dialog left edge`).toBeGreaterThanOrEqual(0);
    expect(box.right, `${scheme} dialog right edge`).toBeLessThanOrEqual(390);
    await page.screenshot({ path: `e2e/shots/model-fix-phone-${scheme}.png` });
    await page.keyboard.press("Escape");
    await expect(page.getByTestId("assess-fix-plan")).toHaveCount(0);
  }
});

// --- The request helper (depth plan W5b): the evidence on the findings, the plan's block and the Settings row ---

const PT_EVIDENCE_ID = FIXTURE_PT_EVIDENCE.record.run_id;
const PT_NOT_STARTED_ID = FIXTURE_PT_NOT_STARTED.record.run_id;
const PT_EVIDENCE_RUN = checkedRun(PT_EVIDENCE_ID, "pentest_local", "Penetration test (your own app, local)", "pentest.v1", { created_at: "2026-11-14T14:00:00Z", target: "http://localhost:3000/" });
const PT_NOT_STARTED_RUN = checkedRun(PT_NOT_STARTED_ID, "pentest_local", "Penetration test (your own app, local)", "pentest.v1", { created_at: "2026-11-14T14:30:00Z", target: "http://localhost:3000/" });

/** openFindings opens the findings tab of the pen test run whose answer is the one given. */
async function openEvidenceFindings(page: Page, run: MockRun, answer: AssessModelResponse) {
  const wire = newWire([run]);
  wire.answers = { [String(run.id)]: answer };
  const view = await openRun(page, wire, "Penetration test");
  await view.getByRole("tab", { name: "Findings" }).click();
  await expect(view.getByRole("tab", { name: "Findings" })).toHaveAttribute("aria-selected", "true");
  return view;
}

/** row is the table row of one finding. */
const findingRow = (view: Locator, id: string) => view.locator("tr", { has: view.page().locator(`[data-testid="assess-finding"][data-finding-id="${id}"]`) });

test("a pen test with the request helper reads Helper log matches, No log with its reason and Not started, and says the log is a file the agent can write", async ({ page }) => {
  const view = await openEvidenceFindings(page, PT_EVIDENCE_RUN, FIXTURE_PT_EVIDENCE);
  // The run's request log in one line above the findings, and the reasons behind it.
  await expect(view.getByTestId("assess-evidence-summary")).toHaveText("Request log: 4 requests sent, 1 refused; 1 finding with a matching log, 3 without, helper unchanged");
  await view.getByTestId("assess-evidence-reasons").getByText("Why findings are not logged").click();
  await expect(view.getByTestId("assess-evidence-reasons")).toContainText("1 finding: The finding cites no logged request (a request made another way, or read from code, is not logged).");
  await expect(view.getByTestId("assess-evidence-reasons")).toContainText("1 finding: A request the finding cites is not in the helper log.");
  await expect(view.getByTestId("assess-evidence-reasons")).toContainText("1 finding: A request the finding cites was refused by the helper, so it never reached the target.");
  // One word per state, and only a match carries the agent-writable line under it.
  await expect(findingRow(view, "F-1")).toContainText("Helper log matches");
  await expect(findingRow(view, "F-1")).toContainText("The log is a file the agent can write.");
  for (const id of ["F-2", "F-3", "F-4"]) {
    await expect(findingRow(view, id)).toContainText("No log");
    await expect(findingRow(view, id)).not.toContainText("Helper log matches");
    await expect(findingRow(view, id)).not.toContainText("The log is a file the agent can write.");
  }
  await expect(view).not.toContainText(BANNED);
  await expect(view).not.toContainText(/\bobserved\b|\bauthentic\b|\bexploitable\b/i);
  await expect(view.locator('[aria-label="Filter findings by evidence"] option')).toHaveText(["All", "Helper log matches (1)", "No log (3)"]);
  await shot(page, "pentest-evidence-findings");
});

test("a finding that matches opens to its attack and control requests as text, with the redacted excerpt and what the agent says differs", async ({ page }) => {
  const view = await openEvidenceFindings(page, PT_EVIDENCE_RUN, FIXTURE_PT_EVIDENCE);
  await view.getByRole("button", { name: "Details of F-1", exact: true }).click();
  const detail = view.getByTestId("assess-finding-detail");
  await expect(detail).toHaveAttribute("data-finding-id", "F-1");
  const ev = detail.getByTestId("assess-finding-evidence");
  await expect(ev).toContainText("Helper log matches");
  await expect(ev).toContainText("not proof of impact");
  await expect(ev.getByTestId("assess-finding-evidence-detail")).toHaveText(/The log is a file the agent can write, so this is not proof\.$/);
  // The agent's condition, in a plain sentence, as the agent's.
  await expect(detail.getByTestId("assess-finding-condition")).toContainText('status 200; the body contains "412"; the header X-Request-Id is absent.');
  // The attack, then the control, as cards.
  const cards = detail.getByTestId("assess-probe");
  await expect(cards).toHaveCount(2);
  await expect(cards.nth(0)).toHaveAttribute("data-probe-id", "p3");
  await expect(cards.nth(1)).toHaveAttribute("data-probe-id", "p4");
  await expect(cards.nth(0)).toContainText("Attack request");
  await expect(cards.nth(0)).toContainText("GET /api/search?q=rent'--");
  await expect(cards.nth(0)).toContainText("Response 200, 63 ms, 65536 bytes of body.");
  await expect(cards.nth(0)).toContainText("Category: Input validation");
  await expect(cards.nth(0)).toContainText("Account: user-a");
  await expect(cards.nth(0)).toContainText("The agent's note: term that closes the quote");
  await expect(cards.nth(0)).toContainText("Authorization: [REDACTED]");
  await expect(cards.nth(1)).toContainText("Control request");
  // The excerpt is a text block with the caption under it.
  const excerpt = cards.nth(0).getByLabel("Response excerpt of p3");
  await expect(excerpt).toHaveText('{"total":412,"items":[{"id":1,"title":"Rent, March"},{"id":2,"title":"An entry of another account"}]}');
  expect(await excerpt.evaluate((el) => el.tagName)).toBe("PRE");
  await expect(cards.nth(0).getByTestId("assess-probe-caption")).toContainText("first 1 KiB of the response, secrets Observer recognised hidden");
  // The reproduction carries the structured request: its line, its headers and its body.
  const steps = detail.locator("ol > li");
  await expect(steps).toHaveCount(3);
  await expect(steps.nth(1)).toContainText("GET /api/search?q=rent'--");
  await expect(steps.nth(1).getByLabel("Headers of step 2")).toHaveText("Accept: application/json");
  await expect(steps.nth(2)).toContainText("POST /api/export");
  await expect(steps.nth(2).getByLabel("Body of step 3")).toHaveText('{"format":"csv"}');
  // Nothing of the log became markup.
  expect(await detail.locator("script, img").count()).toBe(0);
  await expect(view).not.toContainText(BANNED);
  await shot(page, "pentest-evidence-detail");
});

test("a finding with no log opens to the reason in words: no request cited, a request not in the log, a request the helper refused", async ({ page }) => {
  const view = await openEvidenceFindings(page, PT_EVIDENCE_RUN, FIXTURE_PT_EVIDENCE);
  const open = async (id: string) => {
    await view.getByRole("button", { name: `Details of ${id}`, exact: true }).click();
    const d = view.getByTestId("assess-finding-detail");
    await expect(d).toHaveAttribute("data-finding-id", id);
    return d;
  };
  const f2 = await open("F-2");
  await expect(f2.getByTestId("assess-finding-evidence")).toContainText("No log");
  await expect(f2.getByTestId("assess-finding-evidence")).toContainText("The finding cites no logged request (a request made another way, or read from code, is not logged).");
  await expect(f2.getByTestId("assess-finding-evidence")).toContainText("the agent can write any file in the run folder");
  await expect(f2.getByTestId("assess-finding-probes")).toHaveCount(0);
  const f3 = await open("F-3");
  await expect(f3.getByTestId("assess-finding-evidence")).toContainText("A request the finding cites is not in the helper log.");
  await expect(f3.getByTestId("assess-probe-missing")).toContainText("p9");
  await expect(f3.getByTestId("assess-probe-missing")).toContainText("not in the log.");
  const f4 = await open("F-4");
  await expect(f4.getByTestId("assess-finding-evidence")).toContainText("A request the finding cites was refused by the helper, so it never reached the target.");
  const refused = f4.locator('[data-testid="assess-probe"][data-probe-id="p5"]');
  await expect(refused).toContainText("Refused");
  await expect(refused).toContainText("The address was not the target's host and port, and the helper sends to the target only. The request never reached the target.");
  await expect(view).not.toContainText(BANNED);
});

test("the evidence filter narrows the findings to a state and Clear filters brings them back", async ({ page }) => {
  const view = await openEvidenceFindings(page, PT_EVIDENCE_RUN, FIXTURE_PT_EVIDENCE);
  await expect(view.getByTestId("assess-finding")).toHaveCount(4);
  await view.getByLabel("Filter findings by evidence").selectOption("logged");
  await expect(view.getByTestId("assess-finding")).toHaveCount(1);
  await expect(view.getByTestId("assess-findings-count")).toHaveText("Showing 1 of 4 findings");
  await expect(findingRow(view, "F-1")).toContainText("Helper log matches");
  await view.getByLabel("Filter findings by evidence").selectOption("unlogged");
  await expect(view.getByTestId("assess-finding")).toHaveCount(3);
  await view.getByRole("button", { name: "Clear filters" }).click();
  await expect(view.getByTestId("assess-finding")).toHaveCount(4);
});

test("a run whose target did not start reads Not started, with the reason, and never Helper log matches", async ({ page }) => {
  const view = await openEvidenceFindings(page, PT_NOT_STARTED_RUN, FIXTURE_PT_NOT_STARTED);
  await expect(findingRow(view, "F-1")).toContainText("Not started");
  await expect(findingRow(view, "F-1")).not.toContainText("Helper log matches");
  await expect(findingRow(view, "F-1")).not.toContainText("The log is a file the agent can write.");
  await expect(view.getByTestId("assess-evidence-summary")).toContainText("Request log: the helper log holds no request; 0 findings with a matching log, 0 without, 1 not started, helper unchanged");
  await view.getByRole("button", { name: "Details of F-1", exact: true }).click();
  await expect(view.getByTestId("assess-finding-evidence")).toContainText("The application did not start, so nothing was tested in a running application.");
  await expect(view.getByTestId("assess-finding-probes")).toHaveCount(0);
  await expect(view).not.toContainText(BANNED);
  await shot(page, "pentest-evidence-not-started");
});

test("a copy stored before the helper existed reads No log for every finding and has no request log line", async ({ page }) => {
  const view = await openEvidenceFindings(page, PT_RUN, FIXTURE_PT);
  await expect(view.getByTestId("assess-finding")).toHaveCount(3);
  await expect(view.getByTestId("assess-evidence-summary")).toHaveCount(0);
  for (const id of ["F-1", "F-2", "F-3"]) await expect(findingRow(view, id)).toContainText("No log");
  // The reproduction request is the structured object the fixture now carries.
  await view.getByRole("button", { name: "Details of F-1", exact: true }).click();
  await expect(view.getByTestId("assess-finding-detail")).toContainText("GET /api/search?q=rent'--");
  await expect(view.getByTestId("assess-finding-probes")).toHaveCount(0);
});

test("the evidence view fits a phone, in both themes, with the requests of a finding open", async ({ page }) => {
  test.setTimeout(120_000);
  await page.setViewportSize({ width: 390, height: 844 });
  const view = await openEvidenceFindings(page, PT_EVIDENCE_RUN, FIXTURE_PT_EVIDENCE);
  await view.getByRole("button", { name: "Details of F-1", exact: true }).click();
  await expect(view.getByTestId("assess-probe")).toHaveCount(2);
  for (const scheme of ["light", "dark"] as const) {
    await page.emulateMedia({ colorScheme: scheme });
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
    expect(overflow, `${scheme} (page)`).toBeLessThanOrEqual(1);
    expect(await modalOverflow(page), `${scheme} (dialog body)`).toBeLessThanOrEqual(1);
    await page.screenshot({ path: `e2e/shots/model-phone-pt-evidence-${scheme}.png` });
  }
});

/** The plan route's answer with the request helper in the state a test names. */
function helperPlanFor(probe: Record<string, unknown> | undefined) {
  return (u: URL) => ({ ...ptPlanFor(u), ...(probe ? { probe } : {}) });
}

test("the plan lists probe.py and probe.json when the helper is on, with the folder, the budget, the pace and what the log is", async ({ page }) => {
  const wire: Wire = {
    runs: [],
    unreadable: false,
    posts: [],
    planFor: helperPlanFor({ state: "on", files: ["probe.py", "probe.json"], dir: ".observer/assessments/00000000000000c4", budget: 600, pace_rps: 5 }),
  };
  await mockWire(page, wire);
  await openPentestPlan(page);
  const block = page.getByTestId("assess-helper");
  await expect(block).toBeVisible();
  await expect(block).toContainText("Request helper");
  await expect(block.getByTestId("assess-helper-files").locator("li")).toHaveText(["probe.py", "probe.json"]);
  await expect(block.getByTestId("assess-helper-lead")).toHaveText(
    "Observer writes these two files into the run folder before the agent starts; the helper sends requests to the target address only, applies the pace and the request budget, and logs each request to probes.jsonl. The log is a file the agent can write.",
  );
  await expect(block.getByTestId("assess-helper-dir")).toContainText(".observer/assessments/00000000000000c4");
  await expect(block).toContainText("Request budget: 600 requests.");
  await expect(block).toContainText("Pace: at most 5 requests a second.");
  await expect(block).toContainText("A request the agent makes another way, with curl or its own code, is not logged, and a finding that rests on it reads No log.");
  await expect(block.locator('[data-help-id="card.code_security_assess_probe"]')).toBeVisible();
  // The request limits are no longer said to be held by the task only.
  await expect(page.getByTestId("assess-limits")).toContainText("Request budget 600, at most 5 a second. Held by the task, and by the request helper for the requests that go through it.");
  await expect(page.getByTestId("assess-limits")).not.toContainText("Held by the task only: nothing between the agent and the target counts them.");
  await expect(block).not.toContainText(HONEST);
  await shot(page, "pentest-request-helper-on");
});

test("the plan says nothing is written when the helper is off, and why it is left out when python3 is not there", async ({ page }) => {
  const wire: Wire = { runs: [], unreadable: false, posts: [], planFor: helperPlanFor({ state: "off", dir: ".observer/assessments/00000000000000c4", budget: 600, pace_rps: 5 }) };
  await mockWire(page, wire);
  await openPentestPlan(page);
  const block = page.getByTestId("assess-helper");
  await expect(block).toHaveAttribute("data-helper-state", "off");
  await expect(block.getByTestId("assess-helper-lead")).toHaveText("The request helper is off (a setting): nothing is written, and every finding's evidence reads No log.");
  await expect(block).toContainText('The setting is "Request helper for penetration tests" (Settings > Guard > Code security).');
  await expect(block.getByTestId("assess-helper-files")).toHaveCount(0);
  await expect(block).not.toContainText("probe.py");
  await expect(page.getByTestId("assess-limits")).toContainText("Held by the task only: nothing between the agent and the target counts them.");

  // Left out: the server's reason, then the consequence.
  const held: Wire = {
    runs: [],
    unreadable: false,
    posts: [],
    planFor: helperPlanFor({ state: "withheld", withheld_reason: "python3 was not seen in the sandbox's standard folders, so the request helper is left out.", dir: ".observer/assessments/00000000000000c4", budget: 600, pace_rps: 5 }),
  };
  await page.unroute("**/api/security/assessments/plan*");
  await mockWire(page, held);
  await page.reload({ waitUntil: "domcontentloaded" });
  await page.getByTestId("assess-kind").filter({ hasText: "Penetration test" }).getByRole("button", { name: "Start" }).click();
  const heldBlock = page.getByTestId("assess-helper");
  await expect(heldBlock).toHaveAttribute("data-helper-state", "withheld");
  await expect(heldBlock.getByTestId("assess-helper-lead")).toHaveText("python3 was not seen in the sandbox's standard folders, so the request helper is left out. Every finding's evidence reads No log.");
  await expect(heldBlock.getByTestId("assess-helper-files")).toHaveCount(0);
  await shot(page, "pentest-request-helper-withheld");
});

test("the plan with no request helper member has no block, and the helper block fits a phone", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  const wire: Wire = {
    runs: [],
    unreadable: false,
    posts: [],
    planFor: helperPlanFor({ state: "on", files: ["probe.py", "probe.json"], dir: ".observer/assessments/00000000000000c4", budget: 600, pace_rps: 5 }),
  };
  await mockWire(page, wire);
  await openPentestPlan(page);
  await expect(page.getByTestId("assess-helper")).toBeVisible();
  for (const scheme of ["light", "dark"] as const) {
    await page.emulateMedia({ colorScheme: scheme });
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
    expect(overflow, `${scheme} (page)`).toBeLessThanOrEqual(1);
    const body = await page.getByTestId("assess-plan").evaluate((el) => {
      const b = el.parentElement!;
      return b.scrollWidth - b.clientWidth;
    });
    expect(body, `${scheme} (dialog body)`).toBeLessThanOrEqual(1);
  }
  // A plan that carries no probe member (a kind that sends no requests, or an older server) has no block.
  await page.getByRole("button", { name: "Cancel" }).click();
  await page.unroute("**/api/security/assessments/plan*");
  const none: Wire = { runs: [], unreadable: false, posts: [], planFor: helperPlanFor(undefined) };
  await mockWire(page, none);
  await page.reload({ waitUntil: "domcontentloaded" });
  await page.getByTestId("assess-kind").filter({ hasText: "Penetration test" }).getByRole("button", { name: "Start" }).click();
  await expect(page.getByTestId("assess-start")).toBeVisible();
  await expect(page.getByTestId("assess-helper")).toHaveCount(0);
});

test("the Settings card offers the request helper as an on or off row, and a change is written as a boolean with the value it was", async ({ page }) => {
  // The daemon under test may be older than this page: the row's value and the write are answered here, so what is
  // tested is the row, its words and the request it sends. Everything else on the page is the real shell.
  const state = { value: true };
  const puts: { patches: { key: string; value: unknown; was: unknown }[]; dry: boolean }[] = [];
  await page.route("**/api/config*", async (route) => {
    if (new URL(route.request().url()).pathname !== "/api/config") return route.fallback();
    const res = await route.fetch();
    const body = await res.json();
    body.config.Security ??= {};
    body.config.Security.Assessments ??= {};
    body.config.Security.Assessments.ProbeHelper = state.value;
    return route.fulfill({ response: res, json: body });
  });
  await page.route("**/api/config/keys", async (route) => {
    const b = route.request().postDataJSON() as { patches: { key: string; value: unknown; was: unknown }[]; dry_run?: boolean };
    puts.push({ patches: b.patches, dry: b.dry_run === true });
    if (b.dry_run !== true) state.value = b.patches[0].value as boolean;
    const common = {
      changed_keys: b.patches.map((p) => p.key),
      restart_required: false,
      restart_required_keys: [],
      applied_live_keys: b.patches.map((p) => p.key),
      next_spawn_keys: [],
      comments_preserved: true,
      write_mode: "surgical",
      config_path: "config.toml",
      config_etag: "etag-after",
    };
    await route.fulfill({
      json: b.dry_run === true
        ? { ...common, dry_run: true, would_write: true, diff: "", diff_stats: { added: 1, removed: 1 }, needs_confirm: false, secret_warnings: [] }
        : { ...common, saved: true, backup_path: "" },
    });
  });
  await page.addInitScript(() => {
    try {
      localStorage.setItem("sb_tour_completed", "1");
      sessionStorage.setItem("sb_firstrun_closed_this_visit", "1");
    } catch {
      /* private mode: ignore */
    }
  });
  await page.goto("/settings?section=guard", { waitUntil: "domcontentloaded" });
  const sel = page.getByTestId("code-security-setting-security.assessments.probe_helper");
  await expect(sel).toBeVisible({ timeout: 20000 });
  await expect(sel.locator("xpath=ancestor::div[1]").getByText("Request helper for penetration tests")).toBeVisible();
  await expect(sel.locator("option")).toHaveText(["On (default)", "Off"]);
  await expect(sel).toHaveValue("true");
  // It sits with the request limits it applies.
  const order = await page.locator('[data-testid^="code-security-setting-security.assessments."]').evaluateAll((els) => els.map((e) => (e as HTMLElement).dataset.testid ?? ""));
  const at = order.indexOf("code-security-setting-security.assessments.probe_helper");
  expect(order[at - 1]).toBe("code-security-setting-security.assessments.pentest_pace_rps");
  expect(order[at - 2]).toBe("code-security-setting-security.assessments.pentest_request_budget");
  await sel.scrollIntoViewIfNeeded();
  await shot(page, "settings-request-helper-row");
  // Off: a dry run, then the write, each with the key, the boolean and what it was.
  await sel.selectOption("false");
  await expect.poll(() => puts.length, { timeout: 15000 }).toBe(2);
  const want = { key: "security.assessments.probe_helper", value: false, was: true };
  expect(puts[0]).toEqual({ patches: [want], dry: true });
  expect(puts[1]).toEqual({ patches: [want], dry: false });
  await expect(sel).toHaveValue("false", { timeout: 15000 });
  // And back on.
  await sel.selectOption("true");
  await expect.poll(() => puts.length, { timeout: 15000 }).toBe(4);
  expect(puts[3]).toEqual({ patches: [{ key: "security.assessments.probe_helper", value: true, was: false }], dry: false });
  await expect(sel).toHaveValue("true", { timeout: 15000 });
});
