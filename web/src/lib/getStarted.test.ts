import assert from "node:assert/strict";
import test from "node:test";

import type { FirstRunTool } from "./firstRun.ts";
import {
  GET_STARTED_RULES,
  TOP_BAR_RULES,
  accountOf,
  connectActive,
  connectFinished,
  connectLine,
  connectStartInit,
  getStartedMode,
  safeOpenURL,
  shareLevelOf,
  signInStep,
  snoozeRequestInit,
  toolCaptureLabel,
  topBarAccountView,
  wiringPlan,
  wiringResultLine,
  type Account,
  type AccountStatusInput,
  type ConnectProgress,
} from "./getStarted.ts";

const local: AccountStatusInput = { kind: "local", signed_in: false, identity_known: true, locked: false };

const account = (over: Partial<Account> = {}): Account => ({
  signedIn: false,
  identityKnown: true,
  connected: false,
  locked: false,
  displayName: "your dashboard",
  onlineUrl: null,
  ...over,
});

const NOW = Date.parse("2026-11-17T12:00:00Z");
const daysAgo = (d: number) => new Date(NOW - d * 86_400_000).toISOString();

test("the panel's mode: one case per rule, in order", () => {
  const cases: [string, Parameters<typeof getStartedMode>[0], string][] = [
    ["unknown", { account: null, connecting: false, now: NOW }, "loading"],
    ["connected", { account: account({ connected: true }), snoozedAt: daysAgo(1), connecting: false, now: NOW }, "connected"],
    ["connecting", { account: account(), snoozedAt: daysAgo(1), connecting: true, now: NOW }, "panel"],
    ["never_put_away", { account: account(), connecting: false, now: NOW }, "panel"],
    ["put_away_this_week", { account: account(), snoozedAt: daysAgo(6.9), connecting: false, now: NOW }, "hidden"],
    ["back_after_a_week", { account: account(), snoozedAt: daysAgo(7), connecting: false, now: NOW }, "strip"],
  ];
  assert.deepEqual(
    cases.map((c) => c[0]),
    GET_STARTED_RULES.map((r) => r.name),
    "one case per rule, in the table's order",
  );
  for (const [name, input, want] of cases) {
    assert.equal(getStartedMode(input), want, name);
  }
  assert.equal(
    getStartedMode({ account: account({ signedIn: true }), snoozedAt: "not a time", connecting: false, now: NOW }),
    "panel",
    "an unreadable snooze time is never put away",
  );
});

test("accountOf folds status, enrolment and the connect flow", () => {
  assert.equal(accountOf(null, null, null), null);

  const signedOut = accountOf(local, { enrolled: false }, null)!;
  assert.equal(signedOut.connected, false);
  assert.equal(signedOut.signedIn, false);
  assert.equal(signedOut.onlineUrl, null);

  const enrolled = accountOf(
    { ...local, kind: "individual", signed_in: true, destination: "Acme" },
    {
      enrolled: true,
      org_display: "Acme Dev",
      org_server_url: "https://acme-dev.superbased.app",
      user_email: "sam@acme.example",
      last_push: { pushed_at: "2026-11-17T11:00:00Z" },
    },
    null,
  )!;
  assert.equal(enrolled.connected, true);
  assert.equal(enrolled.displayName, "Acme Dev");
  assert.equal(enrolled.email, "sam@acme.example");
  assert.equal(enrolled.lastSentAt, "2026-11-17T11:00:00Z");
  assert.equal(enrolled.onlineUrl, "https://acme-dev.superbased.app/");

  const managed = accountOf({ ...local, kind: "managed" }, { enrolled: true, tenancy: "managed" }, null)!;
  assert.equal(managed.kind, "team");

  // The flow's own report wins: it is newer than the status polls.
  const justConnected = accountOf(local, { enrolled: false }, {
    state: "connected",
    running: false,
    display_name: "Personal dashboard",
    kind: "personal",
    online_url: "https://u-abc.superbased.app/",
  })!;
  assert.equal(justConnected.connected, true);
  assert.equal(justConnected.signedIn, true);
  assert.equal(justConnected.kind, "personal");
  assert.equal(justConnected.displayName, "Personal dashboard");
  assert.equal(justConnected.onlineUrl, "https://u-abc.superbased.app/");

  // After a daemon restart the status's recorded connection facts win over
  // the enrolment's org name and server address (lane 8 job 2).
  const restarted = accountOf(
    {
      ...local,
      kind: "individual",
      destination: "Your personal dashboard",
      display_name: "your personal dashboard",
      online_url: "https://u-abc.superbased.app/",
    },
    { enrolled: true, org_display: "u-abc", org_server_url: "https://u-abc.superbased.app" },
    null,
  )!;
  assert.equal(restarted.displayName, "your personal dashboard");
  assert.equal(restarted.onlineUrl, "https://u-abc.superbased.app/");
  // An unsafe recorded address falls back to the enrolment's.
  const unsafe = accountOf(
    { ...local, kind: "individual", online_url: "javascript:alert(1)" },
    { enrolled: true, org_server_url: "https://acme.superbased.app" },
    null,
  )!;
  assert.equal(unsafe.onlineUrl, "https://acme.superbased.app/");

  const notNow = accountOf(local, { enrolled: false }, { state: "signed_in_only", running: false })!;
  assert.equal(notNow.signedIn, true);
  assert.equal(notNow.connected, false);
});

test("step 1: sign in, connect, skipped or unavailable", () => {
  const cases: [string, Account, boolean, string][] = [
    ["signed out", account(), false, "sign_in"],
    ["signed in, not connected", account({ signedIn: true }), false, "connect"],
    ["continued without an account", account(), true, "skipped"],
    ["locked wins over everything", account({ locked: true }), true, "unavailable"],
    ["a build that cannot sign in", account({ identityKnown: false }), false, "unavailable"],
  ];
  for (const [name, a, skipped, want] of cases) {
    assert.equal(signInStep(a, skipped).kind, want, name);
  }
});

test("connect lines say each state in plain words", () => {
  const p = (state: ConnectProgress["state"], extra: Partial<ConnectProgress> = {}): ConnectProgress => ({
    state,
    running: true,
    ...extra,
  });
  assert.equal(connectLine(p("waiting_approval")).showCode, true);
  assert.match(connectLine(p("waiting_approval")).text, /Waiting for approval in your browser/);
  assert.equal(connectLine(p("connected", { display_name: "Acme Dev" })).text, "Connected to Acme Dev.");
  assert.equal(connectLine(p("connected", { kind: "personal" })).text, "Connected to your personal dashboard.");
  assert.equal(connectLine(p("error", { message: "Declined." })).tone, "danger");
  assert.equal(connectLine(null).text, "");
  for (const s of ["connected", "signed_in_only", "error", "canceled", "expired"] as const) {
    assert.equal(connectFinished(p(s)), true, s);
    assert.equal(connectActive(p(s)), false, s);
  }
  for (const s of ["starting", "waiting_approval", "approved", "attaching"] as const) {
    assert.equal(connectActive(p(s)), true, s);
  }
  assert.equal(connectActive(p("waiting_approval", { running: false })), false);
  // No line ever prints an address.
  const connected = connectLine(p("connected", { kind: "personal", online_url: "https://u-abc.superbased.app/" }));
  assert.doesNotMatch(connected.text, /u-abc|superbased\.app/);
});

test("only https or a loopback http address is opened", () => {
  assert.equal(safeOpenURL("https://cloud.superbased.app/connect/r1"), "https://cloud.superbased.app/connect/r1");
  assert.equal(safeOpenURL("http://127.0.0.1:9800/x"), "http://127.0.0.1:9800/x");
  assert.equal(safeOpenURL("http://cloud.superbased.app/connect/r1"), null);
  assert.equal(safeOpenURL("javascript:alert(1)"), null);
  assert.equal(safeOpenURL("https://a:b@cloud.superbased.app/"), null);
  assert.equal(safeOpenURL(""), null);
  assert.equal(safeOpenURL(undefined), null);
});

test("share levels in two words", () => {
  assert.equal(shareLevelOf("metadata_only"), "summary");
  assert.equal(shareLevelOf("full_content"), "full");
  assert.equal(shareLevelOf("admin_managed"), "full");
  assert.equal(shareLevelOf("enterprise_grant"), "full");
  assert.equal(shareLevelOf("summary"), "summary");
  assert.equal(shareLevelOf("full"), "full");
  assert.equal(shareLevelOf("mystery"), null);
  assert.equal(shareLevelOf(undefined), null);
});

const tool = (over: Partial<FirstRunTool>): FirstRunTool => ({
  tool: "t",
  name: "T",
  detected: true,
  enabled: true,
  watcher_active: true,
  history: { state: "done", files_found: 1, files_processed: 1, files_failed: 0 },
  sessions: 0,
  projects: 0,
  ...over,
});

const wiring = (over: { hooks?: boolean; route?: boolean; tradeoff?: string } = {}) => ({
  hooks: { register: over.hooks ?? true, remove: false },
  mcp: { register: true, remove: false },
  route: { register: over.route ?? true, remove: false, tradeoff: over.tradeoff },
  route_endpoint: "/api/setup/claude",
});

test("Turn on for all: hooks and routes not on yet, routes with a trade-off left to Settings", () => {
  const plan = wiringPlan([
    tool({ tool: "claude-code", name: "Claude Code", wiring: wiring(), hooks: { registered: false }, proxy: { registered: false } }),
    tool({ tool: "codex", name: "Codex", wiring: wiring({ tradeoff: "turns off its own login" }), hooks: { registered: true }, proxy: { registered: false } }),
    tool({ tool: "cursor", name: "Cursor", wiring: wiring({ route: false }), hooks: { registered: true }, proxy: { registered: false } }),
    tool({ tool: "gone", name: "Gone", detected: false, wiring: wiring() }),
    tool({ tool: "nohooks", name: "No hooks", wiring: wiring({ route: false }), hooks: { registered: false, no_hooks: true } }),
  ]);
  assert.deepEqual(
    plan.tools.map((t) => [t.tool, t.actions.map((a) => a.step)]),
    [["claude-code", ["hooks", "route"]]],
  );
  assert.deepEqual(plan.routeLeftToSettings, ["Codex"]);
  assert.equal(plan.alreadyOn, 3, "codex, cursor and the hookless tool have nothing to write in bulk");
  const hooks = plan.tools[0].actions[0];
  assert.equal(hooks.endpoint, "/api/setup/hooks");
  assert.deepEqual(hooks.body, { tool: "claude-code", force: false, dry_run: false });
  const route = plan.tools[0].actions[1];
  assert.equal(route.endpoint, "/api/setup/claude");
  assert.deepEqual(route.body, { force: false, dry_run: false });
});

test("the bulk result in one sentence", () => {
  assert.deepEqual(
    wiringResultLine([
      { tool: "a", step: "hooks", kind: "plan" },
      { tool: "a", step: "route", kind: "plan" },
      { tool: "b", step: "hooks", kind: "plan" },
    ]),
    { text: "Turned on for 2 tools.", tone: "success" },
  );
  assert.deepEqual(
    wiringResultLine([
      { tool: "a", step: "hooks", kind: "plan" },
      { tool: "b", step: "hooks", kind: "conflict" },
    ]),
    { text: "Turned on for 1 tool. 1 tool needs a look in Settings > Connected tools.", tone: "warn" },
  );
  assert.equal(wiringResultLine([{ tool: "b", step: "route", kind: "error" }]).text.startsWith("Nothing changed."), true);
});

test("a tool's capture state in plain words", () => {
  assert.equal(toolCaptureLabel(tool({ watcher_active: false })).text, "Not captured yet");
  assert.equal(toolCaptureLabel(tool({})).text, "Reading session files");
  assert.equal(toolCaptureLabel(tool({ hooks: { registered: true } })).text, "On");
  assert.equal(toolCaptureLabel(tool({ hooks: { registered: true }, proxy: { registered: true } })).text, "Fully on");
});

test("request bodies", () => {
  const start = connectStartInit(" acme ", { "X-Observer-Confirm": "t" });
  assert.equal(start.method, "POST");
  assert.equal(start.body, JSON.stringify({ team: "acme" }));
  const snooze = snoozeRequestInit("tok");
  assert.equal(snooze.body, JSON.stringify({ snooze: "get_started" }));
  assert.equal((snooze.headers as Record<string, string>)["X-Observer-Confirm"], "tok");
});

test("the top bar's account control: one case per rule, in order", () => {
  const waiting: ConnectProgress = { state: "waiting_approval", running: true, user_code: "KTRW-4821" };
  const cases: [string, Parameters<typeof topBarAccountView>[0], string][] = [
    ["unknown", { account: null, available: true, progress: null, managed: false }, "hidden"],
    ["connected", { account: account({ connected: true, displayName: "Acme Dev" }), available: false, progress: null, managed: false }, "connected"],
    ["connecting", { account: account(), available: true, progress: waiting, managed: false }, "connecting"],
    ["cannot_start_here", { account: account(), available: false, progress: null, managed: false }, "hidden"],
    ["signed_in", { account: account({ signedIn: true }), available: true, progress: null, managed: false }, "connect"],
    ["signed_out", { account: account(), available: true, progress: null, managed: false }, "sign_in"],
  ];
  assert.deepEqual(
    cases.map((c) => c[0]),
    TOP_BAR_RULES.map((r) => r.name),
  );
  for (const [name, input, want] of cases) {
    assert.equal(topBarAccountView(input).kind, want, name);
  }
  const managed = topBarAccountView({
    account: account({ connected: true, displayName: "Acme", email: "sam@acme.example", onlineUrl: "https://acme.superbased.app/" }),
    available: true,
    progress: null,
    managed: true,
  });
  assert.equal(managed.kind, "connected");
  if (managed.kind === "connected") {
    assert.equal(managed.label, "Managed by Acme");
    assert.equal(managed.managed, true);
    assert.equal(managed.onlineUrl, "https://acme.superbased.app/");
    assert.match(managed.tooltip, /sam@acme\.example/);
  }
  const code = topBarAccountView({ account: account(), available: true, progress: waiting, managed: false });
  assert.match(code.kind === "connecting" ? code.tooltip : "", /KTRW-4821/);
  assert.equal(
    topBarAccountView({ account: account({ locked: true }), available: true, progress: null, managed: false }).kind,
    "hidden",
    "a locked, unconnected machine offers nothing to start",
  );
});
