import assert from "node:assert/strict";
import test from "node:test";

import {
  browserBadge,
  changedSites,
  errorText,
  extensionIdProblem,
  isInAppLink,
  loginStartBadge,
  loginStartButtons,
  loginStartNote,
  siteDraft,
  statuslineBadge,
  statuslineButtons,
  teardownLinkText,
  validExtensionId,
  type BrowserSiteRow,
  type LoginStartStatus,
  type StatuslineStatus,
} from "./setupExtras.ts";

const sl = (state: StatuslineStatus["state"], supported = true): StatuslineStatus => ({ supported, state });

test("status line buttons follow the state and never remove a line the user wrote", () => {
  const cases: [StatuslineStatus["state"], string[]][] = [
    ["absent", ["install"]],
    ["installed", ["remove"]],
    ["stale", ["install", "remove"]],
    ["foreign", ["install"]],
  ];
  for (const [state, want] of cases) {
    assert.deepEqual(
      statuslineButtons(sl(state)).map((b) => b.action),
      want,
      state,
    );
  }
  const foreign = statuslineButtons(sl("foreign"));
  assert.equal(foreign[0].force, true);
  assert.deepEqual(statuslineButtons(sl("absent", false)), []);
});

test("status line badge tones", () => {
  assert.deepEqual(statuslineBadge(sl("installed")), { text: "on", tone: "success" });
  assert.equal(statuslineBadge(sl("absent")).tone, "neutral");
  assert.equal(statuslineBadge(sl("stale")).tone, "warn");
  assert.equal(statuslineBadge(sl("foreign")).tone, "info");
  assert.equal(statuslineBadge(sl("absent", false)).text, "unavailable");
});

const ls = (over: Partial<LoginStartStatus>): LoginStartStatus => ({
  supported: true,
  installed: false,
  enabled: false,
  running: false,
  ...over,
});

test("start at login offers install or remove, never both", () => {
  assert.deepEqual(
    loginStartButtons(ls({})).map((b) => b.action),
    ["install"],
  );
  assert.deepEqual(
    loginStartButtons(ls({ installed: true })).map((b) => b.action),
    ["remove"],
  );
  assert.deepEqual(loginStartButtons(ls({ supported: false })), []);
});

test("start at login badge and note", () => {
  assert.equal(loginStartBadge(ls({})).text, "off");
  assert.equal(loginStartBadge(ls({ installed: true, enabled: true })).tone, "success");
  assert.equal(loginStartBadge(ls({ installed: true })).tone, "warn");
  assert.match(loginStartNote(ls({ installed: true, enabled: true, running: true })), /does not stop it/);
  assert.match(loginStartNote(ls({})), /does not start the daemon now/);
  assert.equal(loginStartNote(ls({ supported: false, reason: "no systemd" })), "no systemd");
});

test("extension id validation", () => {
  const ok = "abcdefghijklmnopabcdefghijklmnop";
  assert.equal(validExtensionId(ok), true);
  assert.equal(validExtensionId(` ${ok} `), true);
  for (const bad of ["", "abc", ok + "a", ok.toUpperCase(), "qrstuvwxyzqrstuvwxyzqrstuvwxyzqr"]) {
    assert.equal(validExtensionId(bad), false, bad);
  }
  assert.equal(extensionIdProblem(""), "");
  assert.equal(extensionIdProblem(ok), "");
  assert.notEqual(extensionIdProblem("nope"), "");
});

test("browser badge", () => {
  assert.equal(browserBadge({ supported: true, installed: true, host_files: ["x"], candidates: [] }).tone, "success");
  assert.equal(
    browserBadge({ supported: true, installed: false, host_files: [], candidates: [] }).text,
    "host not installed",
  );
  assert.equal(browserBadge({ supported: false, installed: false, host_files: [], candidates: [] }).text, "unavailable");
});

const rows: BrowserSiteRow[] = [
  { site: "chatgpt-web", label: "ChatGPT", enabled: true, explicit: false },
  { site: "claude-web", label: "Claude.ai", enabled: false, explicit: true },
  { site: "gemini-web", label: "Gemini", enabled: true, explicit: false },
];

test("changedSites sends only the toggles that moved", () => {
  const draft = siteDraft(rows);
  assert.deepEqual(changedSites(rows, draft), {});
  draft["chatgpt-web"] = false;
  draft["claude-web"] = true;
  assert.deepEqual(changedSites(rows, draft), { "chatgpt-web": false, "claude-web": true });
  assert.deepEqual(changedSites(rows, { "unknown-web": false }), {});
});

test("errorText reads the server message, falling back to the raw body", () => {
  assert.equal(errorText({ body: '{"message":"config changed"}' }), "config changed");
  assert.equal(errorText({ body: '{"error":"invalid_config"}' }), "invalid_config");
  assert.equal(errorText({ body: 'unknown site "x"\n' }), 'unknown site "x"');
  assert.equal(errorText(new Error("boom")), "boom");
  assert.equal(errorText("plain"), "plain");
});

test("teardown links render only for in-app paths", () => {
  assert.equal(isInAppLink("/settings?section=terminal"), true);
  for (const bad of [undefined, "", "https://evil.example/x", "//evil.example/x", "settings"]) {
    assert.equal(isInAppLink(bad), false, String(bad));
  }
  assert.equal(teardownLinkText("Routing"), "Open Routing");
  assert.equal(teardownLinkText(undefined), "Open in the dashboard");
});
