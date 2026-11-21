// Pins the AI tool settings page's pure helpers (src/lib/agentConfig.ts).
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  blocking,
  commonScope,
  countNoun,
  diagnosticsFor,
  editorLanguage,
  effectiveText,
  errorBody,
  filterSettings,
  inputText,
  keyPath,
  layerLabel,
  parseInput,
  severityTone,
  sortFindings,
  writableFiles,
  LAYER_LABEL,
  orgNotice,
  orgStatusOf,
  type Finding,
  type FileView,
  type SettingView,
  type ToolView,
} from "./agentConfig.ts";

const f = (severity: Finding["severity"], step: number, extra: Partial<Finding> = {}): Finding => ({
  step,
  code: "x",
  severity,
  message: `${severity}-${step}`,
  ...extra,
});

test("findings sort blocking first, then by step, stable", () => {
  const got = sortFindings([f("warning", 1), f("confirm", 4), f("error", 2), f("refuse", 5), f("warning", 0)]);
  assert.deepEqual(
    got.map((x) => x.message),
    ["error-2", "refuse-5", "confirm-4", "warning-0", "warning-1"],
  );
  assert.deepEqual(sortFindings(null), []);
});

test("only error and refuse block a save", () => {
  assert.equal(blocking([f("warning", 1), f("confirm", 2)]).length, 0);
  assert.equal(blocking([f("error", 1), f("refuse", 2), f("confirm", 3)]).length, 2);
  assert.equal(severityTone("refuse"), "danger");
  assert.equal(severityTone("confirm"), "warn");
  assert.equal(severityTone("warning"), "neutral");
});

const languages: [Parameters<typeof editorLanguage>[0], string][] = [
  ["json", "json"],
  ["jsonc", "jsonc"],
  ["crushrc", "jsonc"],
  ["vscode_settings", "jsonc"],
  ["toml", "toml"],
  ["yaml", "yaml"],
  ["markdown", "markdown"],
  ["mdc", "markdown"],
  ["script", "text"],
];
for (const [format, want] of languages) {
  test(`editor language for ${format} is ${want}`, () => assert.equal(editorLanguage(format), want));
}

test("effective text never shows a hidden value", () => {
  assert.equal(effectiveText({ set: false }), "Not set");
  assert.equal(effectiveText({ set: true, secret_present: true, value: "leak" }), "Set (hidden)");
  assert.equal(effectiveText({ set: true, value: ["a", "b"] }), '["a","b"]');
  assert.equal(effectiveText({ set: true, value: false }), "false");
});

const parseRows: [Parameters<typeof parseInput>[0], string, unknown][] = [
  ["bool", "true", true],
  ["bool", "false", false],
  ["int", "42", 42],
  ["int", "-3", -3],
  ["float", "0.5", 0.5],
  ["string", "  keep spaces ", "  keep spaces "],
  ["enum", "plan", "plan"],
  ["string_list", "a\n b \n\nc", ["a", "b", "c"]],
  ["rule_list", '["Bash(ls)"]', ["Bash(ls)"]],
  ["object", '{"a":1}', { a: 1 }],
];
for (const [t, text, want] of parseRows) {
  test(`parseInput ${t} ${JSON.stringify(text)}`, () => {
    const got = parseInput(t, text);
    assert.equal(got.ok, true);
    if (got.ok) assert.deepEqual(got.value, want);
  });
}

const parseBad: [Parameters<typeof parseInput>[0], string][] = [
  ["bool", "yes"],
  ["int", "1.5"],
  ["float", "abc"],
  ["object", "{bad"],
];
for (const [t, text] of parseBad) {
  test(`parseInput rejects ${t} ${JSON.stringify(text)}`, () => assert.equal(parseInput(t, text).ok, false));
}

test("inputText is parseInput's inverse for lists and objects", () => {
  assert.equal(inputText("string_list", ["a", "b"]), "a\nb");
  const obj = { a: [1, 2] };
  const back = parseInput("object", inputText("object", obj));
  assert.ok(back.ok && JSON.stringify(back.value) === JSON.stringify(obj));
  assert.equal(inputText("int", undefined), "");
});

test("keyPath splits dotted paths", () => {
  assert.deepEqual(keyPath("permissions.defaultMode"), ["permissions", "defaultMode"]);
  assert.deepEqual(keyPath(""), []);
});

const file = (id: string, scope: FileView["scope"], precedence: number, editable = true, shape = "s"): FileView => ({
  id,
  shape,
  kind: "settings",
  scope,
  format: "json",
  path_status: "resolved",
  state: "present",
  precedence,
  write_needs: "user",
  editable,
  etag: "",
  size: 0,
});

const setting = (over: Partial<SettingView> = {}): SettingView => ({
  id: "x",
  path: "a.b",
  shape: "s",
  type: "string",
  verified: "doc",
  owner: "user",
  writable: true,
  effective: { set: false },
  ...over,
});

test("writable files are same-shape, editable, allowed scope, by precedence", () => {
  const view: ToolView = {
    tool: "t",
    coverage: {
      tool: "t",
      status: "authored",
      rows: 0,
      verified: 0,
      writable: 0,
      secret: 0,
      dangerous: 0,
      deprecated: 0,
    },
    access: { read_only: false, secrets_posture: "warn" },
    settings: [],
    files: [
      file("local", "project_local", 30),
      file("user", "user", 10),
      file("managed", "managed", 90, false),
      file("other", "user", 5, true, "other"),
      file("shared", "project_shared", 20),
    ],
  };
  assert.deepEqual(
    writableFiles(view, setting()).map((x) => x.id),
    ["user", "shared", "local"],
  );
  assert.deepEqual(
    writableFiles(view, setting({ scopes: ["user"] })).map((x) => x.id),
    ["user"],
  );
});

test("filterSettings applies search and facets together", () => {
  const rows = [
    setting({ id: "1", path: "model", effective: { set: true, value: "m" }, common: ["model"] }),
    setting({ id: "2", path: "permissions.defaultMode", danger: "confirm", desc: "Approval" }),
    setting({ id: "3", path: "theme" }),
  ];
  const base = { q: "", onlySet: false, onlyCommon: false, onlyDanger: false };
  assert.equal(filterSettings(rows, base).length, 3);
  assert.deepEqual(filterSettings(rows, { ...base, onlySet: true }).map((r) => r.id), ["1"]);
  assert.deepEqual(filterSettings(rows, { ...base, onlyDanger: true }).map((r) => r.id), ["2"]);
  assert.deepEqual(filterSettings(rows, { ...base, onlyCommon: true }).map((r) => r.id), ["1"]);
  assert.deepEqual(filterSettings(rows, { ...base, q: "approval" }).map((r) => r.id), ["2"]);
});

test("diagnostics come only from positioned findings", () => {
  const ds = diagnosticsFor([f("error", 1, { line: 3, column: 2 }), f("warning", 2), f("warning", 3, { line: 1 })]);
  assert.equal(ds.length, 2);
  assert.equal(ds[0].severity, "error");
  assert.equal(ds[1].severity, "warning");
});

test("errorBody parses a structured error and ignores anything else", () => {
  assert.equal(errorBody('{"error":"stale","message":"m"}')?.error, "stale");
  assert.equal(errorBody("not json"), null);
});

test("layer labels carry no em dashes", () => {
  for (const v of Object.values(LAYER_LABEL)) assert.doesNotMatch(v, /—/);
});

test("countNoun puts the noun in the right number", () => {
  assert.equal(countNoun(1, "file"), "1 file");
  assert.equal(countNoun(0, "file"), "0 files");
  assert.equal(countNoun(3, "unknown key"), "3 unknown keys");
  assert.equal(countNoun(2, "entry", "entries"), "2 entries");
});

test("layerLabel words the org layers and never renders undefined", () => {
  assert.equal(layerLabel("o2_team"), "Your organization (team)");
  assert.equal(layerLabel("o1_org"), "Your organization");
  assert.equal(layerLabel("l2_adapter"), "This tool");
  assert.equal(layerLabel("o9_future"), "o9 future");
});

// T-429: a common value can be set at the project level, in each tool's
// personal project file by default or its shared one on request.
test("commonScope: user, project personal, project shared", () => {
  assert.deepEqual(commonScope("", "shared").fields, {});
  assert.equal(commonScope("", "local_only").tracked, false);
  const local = commonScope("/w/app", "local_only");
  assert.deepEqual(local.fields, { project: "/w/app", placement: "local_only" });
  assert.match(local.where, /personal project file/);
  const shared = commonScope("/w/app", "shared");
  assert.equal(shared.tracked, true);
  assert.match(shared.where, /committed with the repo/);
  for (const s of [local, shared, commonScope("", "local_only")]) assert.doesNotMatch(s.where, /[–—]/);
});

// The Organization tab's states (operator report 2026-11-02: an enrolled,
// individual-tenancy node read "Not managed by an organization" and was told
// to enrol).
test("orgNotice: not enrolled points at enrolment", () => {
  const n = orgNotice({ managed: false, status: "not_enrolled", has_policy: false });
  assert.equal(n?.title, "Not enrolled with an organization");
  assert.match(n!.body, /enrol this machine in Settings > Enrolment/);
  assert.equal(n?.to, "/settings?section=enrolment");
});

test("orgNotice: an individual enrolment names its org and how management turns on", () => {
  const n = orgNotice({ managed: false, status: "unmanaged", org_name: "localhost:8443", has_policy: false });
  assert.equal(n?.title, "Enrolled with localhost:8443, not managed");
  assert.match(n!.body, /enrolled with localhost:8443 with an individual \(teams\) enrolment/);
  assert.match(n!.body, /switches the organization to enterprise/);
  assert.match(n!.body, /managed enrolment code/);
  assert.doesNotMatch(n!.body, /not enrolled/);
});

test("orgNotice: an unnamed org reads as your organization", () => {
  assert.equal(orgNotice({ managed: false, status: "unmanaged", has_policy: false })?.title, "Enrolled with your organization, not managed");
});

test("orgNotice: managed with the grant not in force says why", () => {
  const n = orgNotice({ managed: false, status: "managed_inactive", org_name: "Acme", grant_state: "grant_expired", has_policy: false });
  assert.equal(n?.title, "Managed by Acme, not in force");
  assert.match(n!.body, /its management grant has expired/);
  const unknown = orgNotice({ managed: false, status: "managed_inactive", grant_state: "something_new", has_policy: false });
  assert.match(unknown!.body, /its management grant is not in force/);
});

test("orgNotice: managed with no policy yet, and nothing once a policy is in force", () => {
  const n = orgNotice({ managed: true, status: "managed", org_name: "Acme", has_policy: false });
  assert.equal(n?.title, "No AI tool policy yet");
  assert.match(n!.body, /^Acme manages this machine/);
  assert.match(orgNotice({ managed: true, status: "managed", has_policy: false })!.body, /^Your organization manages/);
  assert.equal(orgNotice({ managed: true, status: "managed", has_policy: true }), null);
});

test("orgStatusOf: an older daemon without status falls back on managed", () => {
  assert.equal(orgStatusOf({ managed: true }), "managed");
  assert.equal(orgStatusOf({ managed: false }), "not_enrolled");
  assert.equal(orgStatusOf({ managed: false, status: "unmanaged" }), "unmanaged");
});
