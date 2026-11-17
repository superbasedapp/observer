import { test } from "node:test";
import assert from "node:assert/strict";
import type { ConnectHome } from "../api.ts";
import {
  CONNECT_FIRST,
  CONNECT_PAGE_TEXT,
  INSTALL_TABS,
  ageLabel,
  choiceLabel,
  connectPageState,
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
  online_url: url,
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
