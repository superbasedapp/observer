import { test } from "node:test";
import assert from "node:assert/strict";
import type { ConnectChoice, ConnectHome } from "../api.ts";
import {
  CONNECT_FIRST,
  CONNECT_PAGE_TEXT,
  INSTALL_TABS,
  PURPOSE_TEXT,
  SDK_KEY_PAGE_TEXT,
  ageLabel,
  choiceAvailable,
  choiceLabel,
  connectPurpose,
  pickChoice,
  sdkClientLabel,
  sdkKeyAfter,
  connectPageState,
  connectedDashboards,
  PORTAL_HOME,
  homeMachineState,
  homeMachineView,
  installCommand,
  networkLine,
  osLabel,
  routerPath,
  safeReturnTo,
  tabForUserAgent,
  teamMembersLabel,
} from "./connectModel.ts";

// connectModel.test.ts pins the console's connect-flow rules (Getting
// started v2): the install commands and the tab a browser opens on, the
// account home's machine card, the approval page's states and wordings,
// and the sign-in return path.

test("the install tabs carry the four commands, in order", () => {
  assert.deepEqual(
    INSTALL_TABS.map((t) => t.id),
    ["unix", "windows", "npm", "pip"],
  );
  assert.equal(installCommand("unix"), "curl -fsSL https://superbased.app/connect.sh | sh");
  assert.equal(installCommand("windows"), "irm https://superbased.app/connect.ps1 | iex");
  assert.equal(installCommand("npm"), "npm install -g @superbased/observer && observer connect");
  assert.equal(installCommand("pip"), "pip install superbased-observer && observer connect");
});

test("a Windows browser opens on the Windows tab, every other one on macOS / Linux", () => {
  const cases: [string, string][] = [
    ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/130", "windows"],
    ["Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) Safari/605", "unix"],
    ["Mozilla/5.0 (X11; Linux x86_64) Firefox/131", "unix"],
    ["", "unix"],
  ];
  for (const [ua, want] of cases) assert.equal(tabForUserAgent(ua), want, ua);
});

const home = (over: Partial<ConnectHome> = {}): ConnectHome => ({ devices: 0, recent: [], ...over });
const machine = (name: string, url?: string) => ({
  request_id: "r-" + name,
  machine_name: name,
  os: "darwin",
  approved_at: "2026-11-17T10:00:00Z",
  target: null,
  open_url: url,
});

test("home machine state table: one case per row", () => {
  assert.equal(homeMachineState(null), "loading");
  assert.equal(homeMachineState(home({ recent: [machine("studio")] })), "connected");
  assert.equal(homeMachineState(home({ devices: 2 })), "signed_in");
  assert.equal(homeMachineState(home()), "waiting");
});

test("waiting shows the commands and polls; a connected machine flips it with an Open target", () => {
  const waiting = homeMachineView(home(), null);
  assert.equal(waiting.showInstall, true);
  assert.equal(waiting.poll, true);
  assert.equal(waiting.headline, CONNECT_FIRST.waiting);

  const connected = homeMachineView(home({ devices: 1, recent: [machine("studio", "https://u-x.superbased.app/"), machine("old")] }), null);
  assert.equal(connected.headline, "Connected: studio");
  assert.equal(connected.openUrl, "https://u-x.superbased.app/");
  assert.equal(connected.showInstall, false);
  assert.equal(connected.poll, false);

  // "Not now" left no dashboard: Open goes to the personal dashboard.
  const notNow = homeMachineView(home({ devices: 1, recent: [machine("laptop")] }), "https://u-p.superbased.app/");
  assert.equal(notNow.openUrl, "https://u-p.superbased.app/");

  assert.equal(homeMachineView(home({ devices: 1 }), null).headline, "1 machine is signed in.");
  assert.equal(homeMachineView(home({ devices: 3 }), null).headline, "3 machines are signed in.");
});

test("team member counts are worded, and absent before the first report", () => {
  assert.equal(teamMembersLabel({ members: 1 }), "1 member");
  assert.equal(teamMembersLabel({ members: 9 }), "9 members");
  assert.match(teamMembersLabel({}), /first day/);
});

test("the approval page wordings", () => {
  assert.equal(osLabel("darwin"), "macOS");
  assert.equal(osLabel("plan9"), "plan9");
  assert.equal(ageLabel(5), "just now");
  assert.equal(ageLabel(61), "1 minute ago");
  assert.equal(ageLabel(600), "10 minutes ago");
  assert.equal(ageLabel(7200), "2 hours ago");
  assert.deepEqual(networkLine({ prefix: "203.0.113.0/24", same_as_you: true }), {
    text: "Same network as this browser (203.0.113.0/24).",
    warn: false,
  });
  assert.equal(networkLine({ prefix: "203.0.113.0/24", same_as_you: false }).warn, true);
  assert.equal(networkLine({ prefix: "", same_as_you: false }).warn, true);
  assert.equal(choiceLabel({ kind: "personal", display_name: "Personal" }), "Your personal dashboard");
  assert.equal(choiceLabel({ kind: "team", display_name: "Acme" }), "Acme");
  // Mid-sentence ("... is connected to your personal dashboard.") the
  // personal name is lower case; a team keeps its own name.
  assert.equal(choiceLabel({ kind: "personal", display_name: "Personal" }, "inline"), "your personal dashboard");
  assert.equal(choiceLabel({ kind: "team", display_name: "Acme" }, "inline"), "Acme");
});

test("approval page state per status", () => {
  const target = { org_id: "o", slug: "acme", kind: "team" as const, display_name: "Acme", share_level: "full" as const };
  assert.equal(connectPageState({ status: "pending", target: null }), "choose");
  assert.equal(connectPageState({ status: "approved", target }), "connected");
  assert.equal(connectPageState({ status: "approved", target: null }), "signed_in_only");
  assert.equal(connectPageState({ status: "declined", target: null }), "declined");
  assert.equal(connectPageState({ status: "expired", target: null }), "expired");
  // The em and en dash by code point, so this test adds none to the source
  // (the T-546 dash ratchet counts webcloud/src).
  const dashes = new RegExp(`[${String.fromCharCode(0x2013)}${String.fromCharCode(0x2014)}]`);
  for (const t of Object.values(CONNECT_PAGE_TEXT)) {
    assert.doesNotMatch(t.title + t.line, dashes, "no dashes in copy");
  }
});

test("the sign-in return path stays under /portal/", () => {
  assert.equal(safeReturnTo("/portal/connect/6f1c"), "/portal/connect/6f1c");
  assert.equal(safeReturnTo("/portal/home"), "/portal/home");
  for (const bad of [null, "", "/connect/x", "https://evil.test/portal/", "/portal//evil", "/portal/../x", "/portal/a?b=1", "/portal\\x"]) {
    assert.equal(safeReturnTo(bad), null, String(bad));
  }
  assert.equal(routerPath("/portal/connect/abc"), "/connect/abc");
  assert.equal(routerPath("/portal/"), "/");
});

test("after approval the page shows both dashboards, each with its role", () => {
  const personal = { org_id: "p", slug: "u-abc", kind: "personal" as const, display_name: "Sam", share_level: "summary" as const };
  const team = { org_id: "o", slug: "acme", kind: "team" as const, display_name: "Acme", share_level: "full" as const };

  const p = connectedDashboards({ status: "approved", target: personal, open_url: "https://u-abc.superbased.app/dashboard" });
  assert.ok(p);
  assert.deepEqual(p.map((d) => d.id), ["local", "online"]);
  const [local, online] = p;
  assert.equal(local.title, "Local dashboard");
  assert.equal(local.role, "Everything Observer records on this computer, in full; it stays here.");
  assert.equal(local.button, "Open the local dashboard");
  assert.equal(local.href, "http://127.0.0.1:8081");
  assert.equal(local.opens, "external");
  assert.equal(local.note, "On the computer you just connected.");
  // The personal dashboard opens its own address (what "Open your dashboard"
  // opened before), in a new tab.
  assert.equal(online.title, "Online dashboard");
  assert.equal(online.role, "A summary from each machine you connect.");
  assert.equal(online.button, "Open your online dashboard");
  assert.equal(online.href, "https://u-abc.superbased.app/dashboard");
  assert.equal(online.opens, "external");
  // ... and this portal's home when the server sent no usable address.
  const pNone = connectedDashboards({ status: "approved", target: personal });
  assert.equal(pNone?.[1].href, PORTAL_HOME);
  assert.equal(pNone?.[1].opens, "portal");

  const t = connectedDashboards({ status: "approved", target: team, open_url: "https://acme.superbased.app/dashboard" });
  assert.ok(t);
  assert.equal(t[1].title, "Team dashboard: Acme");
  assert.equal(t[1].role, "Full detail (prompts, responses, file paths); the team's admins can read it.");
  assert.equal(t[1].button, "Open the team dashboard");
  assert.equal(t[1].href, "https://acme.superbased.app/dashboard");
  assert.equal(t[1].opens, "external");

  // No usable address (a team here) falls back to this portal's home.
  for (const bad of [undefined, "http://acme.superbased.app/", "javascript:alert(1)", "https://u:p@acme.superbased.app/"]) {
    const d = connectedDashboards({ status: "approved", target: team, open_url: bad });
    assert.equal(d?.[1].href, PORTAL_HOME, String(bad));
    assert.equal(d?.[1].opens, "portal", String(bad));
  }
  // A team with no display name is named by its slug.
  assert.equal(connectedDashboards({ status: "approved", target: { ...team, display_name: "" } })?.[1].title, "Team dashboard: acme");

  // Nothing to open before approval, after Not now, or when declined.
  assert.equal(connectedDashboards({ status: "pending", target: null }), null);
  assert.equal(connectedDashboards({ status: "approved", target: null }), null);
  assert.equal(connectedDashboards({ status: "declined", target: null }), null);
});

test("the connected line still lets the person close the page", () => {
  assert.match(CONNECT_PAGE_TEXT.connected.line, /close this page\.$/);
  assert.match(CONNECT_PAGE_TEXT.connected.line, /finishes connecting by itself/);
});

// ---------------------------------------------------------------------------
// An SDK key request (the AI Apps SDK quickstart, purpose "sdk_key")
// ---------------------------------------------------------------------------

test("an older server's view (no purpose) is a machine; an SDK key has its own words and no Not now", () => {
  assert.equal(connectPurpose({}), "machine");
  assert.equal(connectPurpose({ purpose: "sdk_key" }), "sdk_key");
  assert.equal(PURPOSE_TEXT.machine.notNow, true);
  assert.equal(PURPOSE_TEXT.sdk_key.notNow, false);
  assert.equal(PURPOSE_TEXT.machine.approve, "Connect");
  assert.equal(PURPOSE_TEXT.sdk_key.approve, "Approve");
  // The hosted AI gateway ships dark: the SDK key page never names it.
  for (const t of [...Object.values(PURPOSE_TEXT.sdk_key).map(String), ...Object.values(SDK_KEY_PAGE_TEXT).flatMap((x) => [x.title, x.line])]) {
    assert.equal(/gateway/i.test(t), false, t);
  }
});

test("the SDK that asks is named by its package", () => {
  assert.equal(sdkClientLabel("superbased-sdk-python", "0.3.0"), "Python SDK 0.3.0");
  assert.equal(sdkClientLabel("superbased-sdk-typescript", "0.3.0"), "TypeScript SDK 0.3.0");
  assert.equal(sdkClientLabel("something-else", ""), "something-else");
  assert.equal(sdkClientLabel(undefined, undefined), "SDK");
  assert.equal(osLabel("win32"), "Windows");
});

const choice = (org_id: string, extra: Partial<ConnectChoice> = {}): ConnectChoice => ({
  org_id,
  kind: "team",
  display_name: org_id,
  status: "active",
  share_level: "full",
  disclosure: { share_level: "full", title: "t", text: "x", disclosure_version: "v", disclosure_sha256: "s" },
  preselected: false,
  ...extra,
});

test("a dashboard without AI Apps is never the selected one", () => {
  const personal = choice("p", { kind: "personal", preselected: true });
  const noApps = choice("t", { available: false, refusal: { code: "plan_required", message: "no", upgrade_url: "https://x" } });
  const older = choice("o"); // an older server sends no available flag
  assert.equal(choiceAvailable(older), true);
  assert.equal(choiceAvailable(noApps), false);
  assert.equal(pickChoice([personal, noApps], null)?.org_id, "p");
  assert.equal(pickChoice([personal, noApps], "t")?.org_id, "p", "picking an unavailable one keeps the preselected");
  assert.equal(pickChoice([noApps, older], null)?.org_id, "o", "no preselected: the first available");
  assert.equal(pickChoice([noApps], null), undefined);
});

test("after Approve: go to the AI apps page, wait while the dashboard is set up, else nothing", () => {
  const target = { org_id: "o", slug: "acme", kind: "team" as const, display_name: "Acme", share_level: "full" as const };
  const href = "https://acme.superbased.app/trajectories?from=connect";
  const cases: { name: string; v: Parameters<typeof sdkKeyAfter>[0]; want: ReturnType<typeof sdkKeyAfter> }[] = [
    { name: "pending", v: { status: "pending", target: null, open_url: href }, want: { state: "none" } },
    { name: "declined", v: { status: "declined", target: null }, want: { state: "none" } },
    { name: "approved, not ready", v: { status: "approved", target, target_ready: false, open_url: href }, want: { state: "wait" } },
    { name: "approved, ready", v: { status: "approved", target, target_ready: true, open_url: href }, want: { state: "go", href } },
    { name: "an older server (no ready flag)", v: { status: "approved", target, open_url: href }, want: { state: "go", href } },
    { name: "not https", v: { status: "approved", target, target_ready: true, open_url: "http://acme.superbased.app/" }, want: { state: "none" } },
    { name: "no address", v: { status: "approved", target, target_ready: true }, want: { state: "none" } },
  ];
  for (const c of cases) {
    assert.deepEqual(sdkKeyAfter(c.v), c.want, c.name);
  }
});
