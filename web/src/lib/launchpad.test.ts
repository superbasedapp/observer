// Pins the launchpad's rule tables (lib/launchpad.ts): one case per row of
// every table, plus the copy the consent shows.
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  CONSENT_RULES,
  METER_RULES,
  SPLIT_RULES,
  STEP_RULES,
  CONTINUE_RULES,
  consentChanges,
  continueAction,
  consentHeading,
  consentLines,
  consentSettings,
  consentTriggers,
  firstLaunchFolder,
  homeShortPath,
  isInstalledVerdict,
  launchpadSteps,
  meterPhase,
  meterReading,
  meterShowsNumbers,
  splitForLaunch,
  suggestedFirstAgents,
  type ConsentState,
  type ContinueInput,
  type MeterInput,
} from "./launchpad.ts";

test("suggestedFirstAgents keeps the operator's order and only guided-installable, launchable agents", () => {
  const launchable = ["opencode", "codex", "claude-code", "gemini-cli", "aider"];
  const probes = {
    "claude-code": { install_command: "npm i -g @anthropic-ai/claude-code" },
    codex: { install_command: "" },
    "gemini-cli": { install_command: "npm i -g @google/gemini-cli" },
    opencode: { install_command: "curl ... | bash" },
    aider: { install_command: "pipx install aider-chat" },
  };
  assert.deepEqual(suggestedFirstAgents(launchable, probes), ["claude-code", "gemini-cli", "opencode"]);
  assert.deepEqual(suggestedFirstAgents(["codex"], { codex: { install_command: "x" } }), ["codex"]);
  assert.deepEqual(suggestedFirstAgents(["claude-code"], {}), [], "no preflight answer: not suggested");
});

test("firstLaunchFolder row recent_project: the most recent project from history", () => {
  const f = firstLaunchFolder(
    [
      { root_path: "/home/u/old", last_seen: "2026-10-01T00:00:00Z" },
      { root_path: "/home/u/app", last_seen: "2026-11-17T00:00:00Z" },
      { root_path: "relative/skip", last_seen: "2026-11-18T00:00:00Z" },
    ],
    "/home/u/observer-playground",
  );
  assert.deepEqual(f, { path: "/home/u/app", source: "recent_project" });
});

test("firstLaunchFolder row playground: no history", () => {
  assert.deepEqual(firstLaunchFolder([], "/home/u/observer-playground"), {
    path: "/home/u/observer-playground",
    source: "playground",
  });
});

test("firstLaunchFolder: neither (no history and no home) is none", () => {
  assert.deepEqual(firstLaunchFolder([], ""), { path: "", source: "none" });
});

const ready: ConsentState = {
  toolAllowed: true,
  freshOn: true,
  folder: "/home/u/app",
  folderPermitted: true,
  folderMissing: false,
};

test("CONSENT_RULES: one case per row", () => {
  const cases: [string, Partial<ConsentState>, string[]][] = [
    ["allow_tool", { toolAllowed: false }, ["allow_tool"]],
    ["allow_fresh", { freshOn: false }, ["allow_fresh"]],
    ["allow_folder", { folderPermitted: false }, ["allow_folder"]],
    ["allow_folder: the default directory needs no root", { folder: "", folderPermitted: false }, []],
    ["create_folder", { folderPermitted: false, folderMissing: true }, ["allow_folder", "create_folder"]],
  ];
  assert.equal(cases.length - 1, CONSENT_RULES.length, "a case per row (plus the default-directory case)");
  for (const [name, edit, want] of cases) {
    assert.deepEqual(consentChanges({ ...ready, ...edit }), want, name);
  }
  assert.deepEqual(consentChanges(ready), []);
});

test("consentTriggers: the tool or fresh launch, never a folder alone", () => {
  assert.equal(consentTriggers(["allow_tool"]), true);
  assert.equal(consentTriggers(["allow_fresh", "allow_folder"]), true);
  assert.equal(consentTriggers(["allow_folder", "create_folder"]), false);
  assert.equal(consentTriggers([]), false);
});

test("consent copy: heading, one line per change, the settings it writes", () => {
  const all = consentChanges({ toolAllowed: false, freshOn: false, folder: "~/observer-playground", folderPermitted: false, folderMissing: true });
  assert.equal(consentHeading("Claude Code"), "To start Claude Code here, Observer will:");
  assert.deepEqual(consentLines("Claude Code", all, "~/observer-playground"), [
    "allow Claude Code to launch from the dashboard",
    "allow fresh launches",
    "allow the folder ~/observer-playground (created now)",
  ]);
  assert.deepEqual(consentLines("Codex", ["allow_tool", "allow_folder"], "/home/u/app"), [
    "allow Codex to launch from the dashboard",
    "allow the folder /home/u/app",
  ]);
  assert.deepEqual(consentLines("Codex", ["create_folder"], "/home/u/observer-playground"), [
    "create the folder /home/u/observer-playground",
  ]);
  assert.deepEqual(consentSettings(all), ["allowed_tools", "allow_fresh_agent", "allowed_project_roots"]);
});

test("STEP_RULES: one case per row", () => {
  const cases: [string, Parameters<typeof launchpadSteps>[0], string[]][] = [
    ["consent first", { consent: ["allow_tool"], installed: false }, ["consent", "install", "launch"]],
    ["install when missing", { consent: [], installed: false }, ["install", "launch"]],
    ["launch always last", { consent: [], installed: true }, ["launch"]],
  ];
  assert.equal(cases.length, STEP_RULES.length);
  for (const [name, s, want] of cases) assert.deepEqual(launchpadSteps(s), want, name);
  assert.deepEqual(launchpadSteps({ consent: ["allow_folder"], installed: null }), ["launch"], "a folder alone is not the consent; unknown install is not an install");
});

test("isInstalledVerdict", () => {
  assert.equal(isInstalledVerdict("ok"), true);
  assert.equal(isInstalledVerdict("ok_off_path"), true);
  assert.equal(isInstalledVerdict("not_found"), false);
  assert.equal(isInstalledVerdict(undefined), null);
});

test("SPLIT_RULES: one case per row", () => {
  const cases: [string, Parameters<typeof splitForLaunch>[0], string | null][] = [
    ["a plain New terminal never docks", { launchpad: false, label: "claude-code", resumes: false }, null],
    ["the launchpad's guided install", { launchpad: true, label: "claude-code install", resumes: true }, "install"],
    ["an uninstall or sandbox setup step", { launchpad: true, label: "claude-code uninstall", resumes: true }, null],
    ["an SSH shell has no session to meter", { launchpad: true, label: "ssh · box", resumes: false }, null],
    ["the launchpad's agent", { launchpad: true, label: "claude-code", resumes: false }, "agent"],
  ];
  assert.equal(cases.length, SPLIT_RULES.length);
  for (const [name, l, want] of cases) assert.equal(splitForLaunch(l), want, name);
});

test("METER_RULES: one case per row", () => {
  const base: MeterInput = { kind: "agent", status: "open", correlated: true, hasActivity: true };
  const cases: [string, Partial<MeterInput>, string][] = [
    ["installed", { kind: "install", status: "exited" }, "installed"],
    ["installing", { kind: "install", correlated: false }, "installing"],
    ["ended", { status: "error" }, "ended"],
    ["starting", { status: "connecting", correlated: false, hasActivity: false }, "starting"],
    ["waiting", { hasActivity: false }, "waiting"],
    ["live", {}, "live"],
  ];
  assert.equal(cases.length, METER_RULES.length);
  for (const [name, edit, want] of cases) assert.equal(meterPhase({ ...base, ...edit }), want, name);
});

test("meterShowsNumbers: real numbers only", () => {
  assert.equal(meterShowsNumbers("installing", false), false);
  assert.equal(meterShowsNumbers("starting", false), false);
  assert.equal(meterShowsNumbers("waiting", false), false);
  assert.equal(meterShowsNumbers("live", true), true);
  assert.equal(meterShowsNumbers("ended", true), true);
  assert.equal(meterShowsNumbers("ended", false), false);
});

test("meterReading: tokens, cost basis, model, actions", () => {
  const r = meterReading({
    tokens: { input: 1000, output: 200, cache_read: 5000, cache_creation: 300 },
    per_model: [{ model: "claude-sonnet-4-5" }, { model: "claude-haiku-4-5" }],
    cost_usd: 0.06,
    total_actions: 8,
    turn_count: 3,
    proxy_turn_count: 0,
  });
  assert.deepEqual(r, {
    tokens: 6500,
    costUSD: 0.06,
    costBasis: "transcript",
    model: "claude-sonnet-4-5",
    extraModels: 1,
    actions: 8,
    hasActivity: true,
  });
  assert.equal(meterReading({ turn_count: 2, proxy_turn_count: 2 }).costBasis, "proxy");
  assert.equal(meterReading({ turn_count: 2, proxy_turn_count: 1 }).costBasis, "mixed");
  const empty = meterReading(null);
  assert.equal(empty.hasActivity, false);
  assert.equal(empty.costBasis, "none");
});

test("CONTINUE_RULES: one case per row", () => {
  const base: ContinueInput = {
    mode: "after_consent",
    allowed: true,
    otherBlock: false,
    installed: true,
    verdictBlocks: false,
    canInstall: true,
  };
  const cases: [string, Partial<ContinueInput>, string][] = [
    ["wait for the allow-list re-read", { allowed: false }, "wait"],
    ["stop on another block", { otherBlock: true }, "stop"],
    ["wait for the preflight", { installed: null }, "wait"],
    ["launch an installed tool", {}, "launch"],
    ["stop when the verdict still blocks", { verdictBlocks: true }, "stop"],
    ["install a missing tool after the consent", { installed: false }, "install"],
    ["never install after an install", { installed: false, mode: "after_install" }, "stop"],
  ];
  assert.equal(cases.length, CONTINUE_RULES.length);
  for (const [name, edit, want] of cases) assert.equal(continueAction({ ...base, ...edit }), want, name);
});

test("homeShortPath writes home as ~ only when the playground names it", () => {
  const pg = "/home/u/observer-playground";
  assert.equal(homeShortPath(pg, pg), "~/observer-playground");
  assert.equal(homeShortPath("/home/u/code/app", pg), "~/code/app");
  assert.equal(homeShortPath("/home/u2/app", pg), "/home/u2/app");
  assert.equal(homeShortPath("/srv/app", ""), "/srv/app");
  assert.equal(homeShortPath("C:\\Users\\u\\code", "C:\\Users\\u\\observer-playground"), "~/code");
});
