import assert from "node:assert/strict";
import test from "node:test";

import {
  bodyText,
  errorNote,
  errorText,
  fixOf,
  orgActionLabel,
  orgAskText,
  orgSettingsLinkOfBody,
  isInAppPath,
  needsSettingOf,
  noteOf,
  noteWithText,
  parseErrorBody,
  settingsActionLabel,
  stripApiPrefix,
} from "./needsSetting.ts";
import { ORG_PLACES, PLACES, orgDashboardBase, orgDashboardURL, orgPlaceLink, placeLink } from "./settingsPlaces.ts";

// FakeApiError mirrors web/src/lib/api.ts ApiError: a numeric status, the
// full body, and the message that keeps only a 200-char excerpt.
class FakeApiError extends Error {
  readonly status: number;
  readonly body: string;
  constructor(status: number, path: string, body: string) {
    super(`api ${status} ${path}: ${body.slice(0, 200)}`);
    this.status = status;
    this.body = body;
  }
}

// The operator's report (2026-11-18): the New Terminal popover's install
// showed this body raw and cut off at 200 characters.
const REMOTE_BODY = JSON.stringify({
  error: "component_not_installed",
  component: "remote",
  state: "available",
  reason: "not_selected",
  message:
    "Remote dashboard (remote) is installed but inactive on this machine. Turn it on in Settings > Components or with `observer components add remote --yes`.",
  settings: "/settings/components?component=remote",
  settings_label: "Settings > Components",
  command: "observer components add remote --yes",
});

test("a component_not_installed refusal reads as its sentence and its link", () => {
  const e = new FakeApiError(404, "/api/remote/config", REMOTE_BODY);
  assert.ok(e.message.length < REMOTE_BODY.length + 40, "the excerpt is cut, so the full body must be read");
  const note = errorNote(e);
  assert.match(note.text, /^Remote dashboard \(remote\) is installed but inactive/);
  assert.ok(note.text.endsWith("`observer components add remote --yes`."), "never cut mid-word");
  assert.ok(!note.text.includes("{"), "never raw JSON");
  assert.deepEqual(note.settings, {
    href: "/settings/components?component=remote",
    label: "Settings > Components",
    command: "observer components add remote --yes",
    component: "remote",
    componentState: "available",
  });
  assert.equal(settingsActionLabel(note.settings!, "Remote dashboard"), "Turn on Remote dashboard");
  assert.equal(settingsActionLabel(note.settings!), "Turn on remote");
});

// One row per body shape the daemon answers.
const CASES: { name: string; status: number; body: string; text: string; href: string | null; action: string | null }[] = [
  {
    name: "a settings place (guided install off)",
    status: 403,
    body: JSON.stringify({
      error: "guided install is off: turn on ...",
      message: "Guided install is off on this machine.",
      settings: "/terminals?tab=settings#launch-policy",
      settings_label: "Terminals > Settings > Fresh-agent launch policy",
    }),
    text: "Guided install is off on this machine.",
    href: "/terminals?tab=settings#launch-policy",
    action: "Open Terminals > Settings > Fresh-agent launch policy",
  },
  {
    name: "a component not in this build: open, never turn on",
    status: 404,
    body: JSON.stringify({
      error: "component_not_installed",
      component: "obs",
      state: "absent",
      message: "Observability is not in this build.",
      settings: "/settings/components?component=obs",
      settings_label: "Settings > Components",
    }),
    text: "Observability is not in this build.",
    href: "/settings/components?component=obs",
    action: "Open Settings > Components",
  },
  {
    name: "a code-only error with a message and no link",
    status: 409,
    body: JSON.stringify({ error: "not_open", message: "the request is no longer open" }),
    text: "the request is no longer open",
    href: null,
    action: null,
  },
  {
    name: "an error that is itself a sentence",
    status: 400,
    body: JSON.stringify({ error: "missing tool" }),
    text: "missing tool",
    href: null,
    action: null,
  },
  {
    name: "a plain-text body",
    status: 403,
    body: "forbidden: missing or mismatched confirm token - reload the panel\n",
    text: "forbidden: missing or mismatched confirm token - reload the panel",
    href: null,
    action: null,
  },
  {
    name: "an off-origin link is ignored",
    status: 409,
    body: JSON.stringify({ error: "x_off", message: "X is off.", settings: "https://evil.example/settings" }),
    text: "X is off.",
    href: null,
    action: null,
  },
];

for (const c of CASES) {
  test(`errorNote: ${c.name}`, () => {
    const note = errorNote(new FakeApiError(c.status, "/api/x", c.body));
    assert.equal(note.text, c.text);
    assert.equal(note.settings?.href ?? null, c.href);
    assert.equal(note.settings ? settingsActionLabel(note.settings) : null, c.action);
  });
}

test("errorNote: a link wins over the surface's own status wording; without one the wording applies", () => {
  const linked = new FakeApiError(
    403,
    "/api/terminal/install",
    JSON.stringify({ error: "e", message: "Server words.", settings: "/settings?section=terminal", settings_label: "Settings > Session attach" }),
  );
  assert.equal(errorNote(linked, () => "Surface words.").text, "Server words.");
  const plain = new FakeApiError(400, "/api/terminal/install", JSON.stringify({ error: "no grounded install command for x" }));
  assert.equal(errorNote(plain, () => "Surface words.").text, "Surface words.");
  assert.equal(errorNote(plain, () => null).text, "no grounded install command for x");
});

test("errorText and stripApiPrefix never show fetchJSON's prefix", () => {
  assert.equal(stripApiPrefix("api 500 /api/x?y=1: boom"), "boom");
  assert.equal(errorText(new Error("api 503 /api/terminal/launch: launch unavailable")), "launch unavailable");
  assert.equal(errorText("plain"), "plain");
  assert.equal(errorText(new Error("network down")), "network down");
});

test("isInAppPath accepts only same-origin paths", () => {
  for (const ok of ["/settings", "/settings?section=otel", "/terminals?tab=settings#launch-policy", "/remote"]) {
    assert.ok(isInAppPath(ok), ok);
  }
  for (const bad of ["", "settings", "//evil.example", "https://x", "/\\evil", "javascript:alert(1)", "/javascript:x", 42, null]) {
    assert.ok(!isInAppPath(bad), String(bad));
  }
});

test("parseErrorBody and bodyText", () => {
  assert.equal(parseErrorBody("not json"), null);
  assert.equal(parseErrorBody("[1]"), null);
  assert.equal(parseErrorBody(undefined), null);
  assert.equal(bodyText({ error: "not_enrolled" }), null, "a bare code is not shown to a person");
  assert.equal(bodyText({ error: "install_refused", detail: "engine missing" }), "engine missing");
});

test("needsSettingOf reads only a thrown value with a body", () => {
  assert.equal(needsSettingOf(new Error("x")), null);
  assert.equal(needsSettingOf(null), null);
  assert.equal(needsSettingOf(new FakeApiError(404, "/api/remote/config", REMOTE_BODY))?.component, "remote");
});

test("noteOf takes a surface's own string or a note", () => {
  assert.equal(noteOf(null), null);
  assert.equal(noteOf(""), null);
  assert.deepEqual(noteOf("choose a tool"), { text: "choose a tool", settings: null });
  const n = { text: "t", settings: null };
  assert.equal(noteOf(n), n);
});

test("noteWithText keeps the surface's sentence and adds the server's link", () => {
  const e = new FakeApiError(
    403,
    "/api/terminal/sandbox/setup/x/run",
    JSON.stringify({ error: "elevated steps are off", code: "elevation_disabled", settings: "/terminals?tab=settings#sandbox-backends", settings_label: "Terminals > Settings > Sandbox isolation" }),
  );
  const n = noteWithText(e, "Our words.");
  assert.equal(n.text, "Our words.");
  assert.equal(n.settings?.href, "/terminals?tab=settings#sandbox-backends");
  assert.equal(noteWithText(new Error("x"), "Our words.").settings, null);
});

// The "ask your organization" form (dead-end sweep, 2026-11-18): a body
// names the team-dashboard place; the URL survives only when a button may
// open it.
test("orgSettingsLinkOfBody keeps a safe team-dashboard URL and the place name", () => {
  const cases: Array<[Record<string, unknown>, { href: string | null; label: string; personal?: boolean } | null]> = [
    [
      { org_settings: "https://org.example/intelligence?tab=session-enrichment", org_settings_label: "Intelligence > Session enrichment" },
      { href: "https://org.example/intelligence?tab=session-enrichment", label: "Intelligence > Session enrichment", personal: false },
    ],
    [{ org_settings_label: "Intelligence > Session enrichment" }, { href: null, label: "Intelligence > Session enrichment", personal: false }],
    [{ org_settings_label: "X", org_dashboard_kind: "personal" }, { href: null, label: "X", personal: true }],
    [{ org_settings: "javascript:alert(1)", org_settings_label: "X" }, { href: null, label: "X", personal: false }],
    [{ org_settings: "http://org.example/x", org_settings_label: "X" }, { href: null, label: "X", personal: false }],
    [{ org_settings: "https://u:p@org.example/x", org_settings_label: "X" }, { href: null, label: "X", personal: false }],
    [{ org_settings: "https://org.example/x" }, null],
    [{}, null],
  ];
  for (const [body, want] of cases) assert.deepEqual(orgSettingsLinkOfBody(body), want, JSON.stringify(body));
  assert.equal(orgSettingsLinkOfBody(null), null);
});

test("fixOf reads both forms off a status view", () => {
  const f = fixOf({
    reason: "purpose_not_allowed",
    reason_text: "Your organization does not allow a purpose your consent covers.",
    settings: "/settings?section=intel",
    settings_label: "Settings > Team AI summaries",
    org_settings_label: "Intelligence > Session enrichment",
  });
  assert.equal(f.settings?.href, "/settings?section=intel");
  assert.equal(f.settings?.label, "Settings > Team AI summaries");
  assert.deepEqual(f.org, { href: null, label: "Intelligence > Session enrichment", personal: false });
  assert.deepEqual(fixOf(undefined), { settings: null, org: null });
  assert.deepEqual(fixOf([]), { settings: null, org: null });
});

test("errorNote carries an org-only refusal", () => {
  const body = JSON.stringify({
    error: "org_off",
    message: "Your organization has not turned on session enrichment.",
    org_settings: "https://org.example/intelligence?tab=session-enrichment",
    org_settings_label: "Intelligence > Session enrichment",
  });
  const n = errorNote(new FakeApiError(409, "/api/intel/enrich", body));
  assert.equal(n.text, "Your organization has not turned on session enrichment.");
  assert.equal(n.settings, null);
  assert.equal(n.org?.href, "https://org.example/intelligence?tab=session-enrichment");
  assert.ok(noteOf({ text: "", settings: null, org: { href: null, label: "X" } }));
});

test("orgAskText names who and where: the person on a personal dashboard, the admins on a team", () => {
  assert.equal(
    orgAskText({ href: null, label: "Intelligence > Session enrichment" }),
    "The team's admins can turn it on in the team dashboard: Intelligence > Session enrichment.",
  );
  assert.equal(
    orgAskText({ href: null, label: "Intelligence > Session enrichment", personal: true }),
    "Turn it on in your personal dashboard: Intelligence > Session enrichment.",
  );
  assert.equal(orgActionLabel({ href: "https://x", label: "Intelligence > Session enrichment" }), "Open session enrichment");
});

test("settingsPlaces: every row is an in-app path with a plain label", () => {
  for (const [id, r] of Object.entries(PLACES)) {
    assert.ok(isInAppPath(r.href), id);
    assert.ok(r.label && !/[–—]/.test(r.label), id);
    assert.equal(placeLink(id as keyof typeof PLACES).href, r.href);
  }
  for (const [id, r] of Object.entries(ORG_PLACES)) {
    assert.ok(r.href.startsWith("/") && !r.href.startsWith("//"), id);
    assert.equal(orgPlaceLink("https://org.example/", id as keyof typeof ORG_PLACES).href, "https://org.example" + r.href);
  }
});

test("orgDashboardBase opens https, or http on loopback, never credentials", () => {
  const cases: Array<[string | undefined, string | null]> = [
    ["https://org.example", "https://org.example"],
    ["https://org.example:8443/some/path?q=1", "https://org.example:8443"],
    ["http://127.0.0.1:8443", "http://127.0.0.1:8443"],
    ["http://localhost:9000/", "http://localhost:9000"],
    ["http://[::1]:9000", "http://[::1]:9000"],
    ["http://org.example", null],
    ["https://user:pw@org.example", null],
    ["javascript:alert(1)", null],
    ["", null],
    [undefined, null],
    ["not a url", null],
  ];
  for (const [inp, want] of cases) assert.equal(orgDashboardBase(inp), want, String(inp));
  assert.equal(orgDashboardURL("https://org.example/a?b=1#c"), "https://org.example/a?b=1#c");
  assert.equal(orgDashboardURL("http://org.example/a"), null);
  assert.deepEqual(orgPlaceLink(undefined, "org_session_enrichment"), { href: null, label: "Intelligence > Session enrichment", personal: false });
  assert.equal(orgPlaceLink("https://u-abc.superbased.app/", "org_session_enrichment", "personal").personal, true);
});
