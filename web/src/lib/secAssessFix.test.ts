import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { ASSESS_REFUSALS, assessRefusalWords } from "./secAssess.ts";
import { HELP_REGISTRY } from "./help.ts";
import { clearanceRegExp, parseClearanceList } from "./secAssessBanned.ts";
import { MIT_STATE_WORDS } from "./secAssessModel.ts";
import { FIXTURE_PT, FIXTURE_TM, fixtureFindings, fixtureThreats } from "./secAssessModelFixture.ts";
import { taskLaunchBody } from "./terminalTask.ts";
import {
  ASSESS_EXPORT_PATH,
  ASSESS_FIX_PATH,
  EXPORT_DOWNLOADS,
  EXPORT_DOWNLOAD_NONE,
  EXPORT_DOWNLOAD_NOTE,
  FIX_AFTER_END_WORDS,
  FIX_BUTTON_NOTE,
  FIX_NEXT_WORDS,
  FIX_PLACE_WORDS,
  FIX_TASK_WORDS,
  assessExportPath,
  assessFixEnabled,
  assessFixPlanPath,
  exportErrorWords,
  exportFileName,
  fixChooseBlock,
  fixErrorWords,
  fixItemWord,
  fixPlaceText,
  fixPlaceWords,
  fixPlanHeadline,
  fixPlanNotes,
  fixRefusalText,
  fixRetryHelps,
  fixTaskFor,
  fixableItem,
  type AssessFixPlan,
} from "./secAssessFix.ts";

// ---- helpers ----

const CLEARANCE = parseClearanceList(readFileSync(new URL("../../../internal/secassess/testdata/clearance_words.json", import.meta.url), "utf8"));
const BANNED = clearanceRegExp(CLEARANCE);

function plan(over: Partial<AssessFixPlan> = {}): AssessFixPlan {
  return {
    confirm_token: "tok",
    run: "00000000000000b2",
    item: "T-1",
    item_kind: "threat",
    band: "high",
    project: { name: "ledger", root_path: "/home/u/ledger", on_disk: true },
    prompt: "Fix the weakness at the places below.",
    prompt_sha256: "ab".repeat(32),
    places: [
      { path: "src/api/search.ts", line: 22, end_line: 26, state: "found" },
      { path: "src/api/db.ts", state: "exists" },
    ],
    places_omitted: 0,
    seeds: { "claude-code": "leading_positional", cursor: "none" },
    ...over,
  };
}

const err = (status: number, body: unknown) => ({ status, body: typeof body === "string" ? body : JSON.stringify(body) });

// ---- the paths ----

test("the fix and export paths are the routes the server registers", () => {
  assert.equal(ASSESS_FIX_PATH, "/api/security/assessments/fix");
  assert.equal(ASSESS_EXPORT_PATH, "/api/security/assessments/export");
  const go = readFileSync(new URL("../../../internal/intelligence/dashboard/dashboard.go", import.meta.url), "utf8");
  assert.match(go, new RegExp(`reg\\("${ASSESS_FIX_PATH}"`));
  assert.match(go, new RegExp(`reg\\("${ASSESS_EXPORT_PATH}"`));
});

test("assessFixPlanPath and assessExportPath carry the run, the item and the format, escaped", () => {
  const cases: Array<[string, string]> = [
    [assessFixPlanPath("00000000000000b2", "T-1"), "/api/security/assessments/fix?run=00000000000000b2&item=T-1"],
    [assessFixPlanPath("r", "a b&c=d"), "/api/security/assessments/fix?run=r&item=a+b%26c%3Dd"],
    [assessFixPlanPath("r?x", "F/1"), "/api/security/assessments/fix?run=r%3Fx&item=F%2F1"],
    [assessExportPath("00000000000000b2", "md"), "/api/security/assessments/export?run=00000000000000b2&format=md"],
    [assessExportPath("00000000000000b2", "json"), "/api/security/assessments/export?run=00000000000000b2&format=json"],
  ];
  for (const [got, want] of cases) assert.equal(got, want);
});

// ---- which items offer a fix ----

test("fixableItem is true only for an item that cites a place Observer found or saw exist", () => {
  const rows: Array<[string, Parameters<typeof fixableItem>[0], boolean]> = [
    ["no refs at all", undefined, false],
    ["null refs", null, false],
    ["an empty list", [], false],
    ["found", [{ path: "a.ts", state: "found" }], true],
    ["exists", [{ path: "a.ts", state: "exists" }], true],
    ["claimed, not found", [{ path: "a.ts", state: "claimed_not_found" }], false],
    ["missing", [{ path: "a.ts", state: "missing" }], false],
    ["malformed", [{ path: "a.ts", state: "invalid" }], false],
    ["not checked", [{ path: "a.ts", state: "unchecked" }], false],
    ["no state", [{ path: "a.ts" }], false],
    ["a state this view does not know", [{ path: "a.ts", state: "newer" }], false],
    ["a located state with no path", [{ path: "", state: "found" }], false],
    ["a located state with no path key", [{ state: "exists" }], false],
    ["one located among the rest", [{ path: "a", state: "missing" }, { path: "b", state: "unchecked" }, { path: "c", state: "exists" }], true],
    ["a null reference among located ones", [null, { path: "c", state: "found" }], true],
  ];
  for (const [name, refs, want] of rows) assert.equal(fixableItem(refs), want, name);
});

test("fixableItem agrees with the fixture: a threat is judged by its missing mitigations' references, a finding by where it points", () => {
  const tm = FIXTURE_TM.record.result.tm!;
  const byId = new Map(tm.threats!.map((t) => [t.id, t]));
  const missingRefs = (id: string) => (byId.get(id)!.missing ?? []).flatMap((m) => m.refs ?? []);
  // T-1 and T-3 name a place in a missing mitigation; T-2 only has an existing mitigation, T-4 and T-5 name nothing to fix.
  assert.deepEqual(["T-1", "T-2", "T-3", "T-4", "T-5"].map((id) => fixableItem(missingRefs(id))), [true, false, true, false, false]);
  const pt = FIXTURE_PT.record.result.pt!;
  assert.deepEqual(
    pt.findings!.map((f) => fixableItem(f.where?.refs)),
    [true, true, false],
    "F-1 found, F-2 exists, F-3 cites nothing",
  );
  // The big generated lists: every state is judged, none is capped.
  assert.equal(fixtureThreats(30).filter((t) => fixableItem((t.missing ?? []).flatMap((m) => m.refs ?? []))).length > 0, true);
  assert.equal(fixtureFindings(30).length, 30);
});

// ---- the words ----

test("a place is told in the model view's own words, and a state this view does not know reads as the weaker one", () => {
  assert.equal(FIX_PLACE_WORDS.found.label, "Found near the cited line");
  assert.equal(FIX_PLACE_WORDS.exists.label, "Location exists, nothing matched");
  assert.equal(FIX_PLACE_WORDS.found.label, MIT_STATE_WORDS.found.label);
  assert.equal(FIX_PLACE_WORDS.exists.label, MIT_STATE_WORDS.exists.label);
  assert.equal(fixPlaceWords("found"), FIX_PLACE_WORDS.found);
  assert.equal(fixPlaceWords("exists"), FIX_PLACE_WORDS.exists);
  assert.equal(fixPlaceWords("newer"), FIX_PLACE_WORDS.exists);
  assert.equal(fixPlaceWords(undefined), FIX_PLACE_WORDS.exists);
});

test("fixPlaceText is path:line, path:line-end, or the bare path", () => {
  const rows: Array<[Parameters<typeof fixPlaceText>[0], string]> = [
    [{ path: "src/a.ts", line: 22, end_line: 26 }, "src/a.ts:22-26"],
    [{ path: "src/a.ts", line: 22 }, "src/a.ts:22"],
    [{ path: "src/a.ts", line: 22, end_line: 22 }, "src/a.ts:22"],
    [{ path: "src/a.ts", line: 22, end_line: 10 }, "src/a.ts:22"],
    [{ path: "src/a.ts" }, "src/a.ts"],
    [{ path: "src/a.ts", line: 0 }, "src/a.ts"],
    [{ path: "", line: 3 }, ":3"],
  ];
  for (const [p, want] of rows) assert.equal(fixPlaceText(p), want);
});

test("fixItemWord names the kind, and a kind it does not know reads as a threat", () => {
  assert.equal(fixItemWord("threat"), "Threat");
  assert.equal(fixItemWord("finding"), "Finding");
  assert.equal(fixItemWord("other"), "Threat");
  assert.equal(fixItemWord(undefined), "Threat");
});

test("the headline names the item, Observer's band, how many places the task lists and how many it does not", () => {
  const rows: Array<[Partial<AssessFixPlan>, string]> = [
    [{}, "Threat T-1 (band high). The task points the agent at 2 places in the project."],
    [{ item_kind: "finding", item: "F-2", band: "" }, "Finding F-2. The task points the agent at 2 places in the project."],
    [{ places: [{ path: "a.ts", state: "found" }] }, "Threat T-1 (band high). The task points the agent at 1 place in the project."],
    [{ places_omitted: 1 }, "Threat T-1 (band high). The task points the agent at 2 places in the project. 1 more place that Observer located is not listed in the task."],
    [{ places_omitted: 7 }, "Threat T-1 (band high). The task points the agent at 2 places in the project. 7 more places that Observer located are not listed in the task."],
  ];
  for (const [over, want] of rows) assert.equal(fixPlanHeadline(plan(over)), want);
});

test("the notes are the plan's sentences, with anything that is not text left out", () => {
  assert.deepEqual(fixPlanNotes(plan({ notes: ["The agent's model file changed after this check.", "  ", ""] })), ["The agent's model file changed after this check."]);
  assert.deepEqual(fixPlanNotes(plan({ notes: undefined })), []);
  assert.deepEqual(fixPlanNotes({ notes: [3 as unknown as string, "kept"] }), ["kept"]);
});

test("Choose agent is disabled with a reason for a missing folder, a missing dock or a read still in flight, in that order", () => {
  const ok = plan();
  const gone = plan({ project: { name: "ledger", root_path: "/gone", on_disk: false } });
  const rows: Array<[AssessFixPlan | null, boolean, boolean, string | null]> = [
    [null, true, false, "The task has not been read yet"],
    [ok, true, false, null],
    [gone, true, false, "This project's folder is not on this machine"],
    [gone, false, true, "This project's folder is not on this machine"],
    [ok, false, false, "The terminal dock is not available on this page"],
    [ok, false, true, "The terminal dock is not available on this page"],
    [ok, true, true, "The task is being read again"],
  ];
  for (const [p, dock, refreshing, want] of rows) assert.equal(fixChooseBlock(p, dock, refreshing), want);
});

// ---- the task ----

test("fixTaskFor opens the New terminal dialog in task mode on the fix route, with the item and the digest the developer read", () => {
  const started: unknown[] = [];
  const t = fixTaskFor(plan(), (r) => started.push(r));
  assert.equal(t.title, "Fix this threat");
  assert.equal(t.launchPath, "/api/security/assessments/fix");
  assert.deepEqual(t.launchBody, { run: "00000000000000b2", item: "T-1", prompt_sha256: "ab".repeat(32) });
  assert.equal(t.projectRoot, "/home/u/ledger");
  assert.equal(t.confirmToken, "tok");
  assert.deepEqual(t.seeds, { "claude-code": "leading_positional", cursor: "none" });
  // No sandbox is chosen by the task, and no agent is excluded: the dialog's own controls apply.
  assert.equal(t.serverSandbox, undefined);
  assert.equal(t.allowedTools, undefined);
  assert.equal(typeof t.refusalText, "function");
  assert.match(t.summary, /^In ledger\./);
  assert.match(t.summary, /2 places/);
  assert.match(t.summary, /edits the project/);
  assert.match(t.summary, /nothing here changes the model/);
  t.onStarted?.({ token: "t", tool: "claude-code" });
  assert.equal(started.length, 1);
  assert.equal(fixTaskFor(plan({ item_kind: "finding", item: "F-1" })).title, "Fix this finding");
  // A project with no name is named by its folder; a plan with no seeds reads as an empty table.
  assert.match(fixTaskFor(plan({ project: { name: "", root_path: "/x/y", on_disk: true } })).summary, /^In \/x\/y\./);
  assert.deepEqual(fixTaskFor({ ...plan(), seeds: undefined as unknown as Record<string, string> }).seeds, {});
  // The dialog adds the agent choice; the folder it sends never overrides the task's.
  assert.deepEqual(taskLaunchBody(t, { tool: "claude-code", project_root: "/elsewhere", model: undefined, sandbox: false }), {
    run: "00000000000000b2",
    item: "T-1",
    prompt_sha256: "ab".repeat(32),
    tool: "claude-code",
    sandbox: false,
  });
});

// ---- refusals ----

test("every refusal code the fix and export routes send has words, the three new ones in the shared table", () => {
  for (const code of ["unknown_item", "no_location", "bad_format"]) {
    assert.ok(Object.prototype.hasOwnProperty.call(ASSESS_REFUSALS, code), code);
    const w = ASSESS_REFUSALS[code].words;
    assert.match(w, /^[A-Z][\s\S]*\.$/, code);
    assert.doesNotMatch(w, BANNED, code);
  }
  assert.match(ASSESS_REFUSALS.no_location.words, /nothing to point a fix at/);
  assert.match(ASSESS_REFUSALS.no_location.words, /Nothing was started/);
  assert.match(ASSESS_REFUSALS.unknown_item.words, /Nothing was started/);
  assert.match(ASSESS_REFUSALS.bad_format.words, /Nothing was saved/);
  // The Go sources send exactly these codes from the two new files.
  const dir = new URL("../../../internal/intelligence/dashboard/", import.meta.url);
  const fixGo = readFileSync(new URL("security_assess_fix.go", dir), "utf8");
  const exportGo = readFileSync(new URL("security_assess_export.go", dir), "utf8");
  assert.match(fixGo, /codeUnknownItem\s*=\s*"unknown_item"/);
  assert.match(fixGo, /codeNoLocation\s*=\s*"no_location"/);
  assert.match(exportGo, /codeBadFormat\s*=\s*"bad_format"/);
});

test("a refused read of the plan says what happened in the fix route's words, for every code the route sends", () => {
  const rows: Array<[string, unknown, RegExp]> = [
    ["no location", err(409, { error: "this item cites no place that Observer found in the project, so there is nothing to point a fix at", code: "no_location" }), /nothing to point a fix at\. Nothing was started\./],
    ["unknown item", err(404, { error: "the stored model holds no such threat or finding", code: "unknown_item" }), /no threat or finding with that id/],
    ["no stored model", err(404, { error: "no stored model for this run", code: "no_stored_model" }), /No checked copy of this run's model is stored/],
    ["project gone", err(409, { error: "the project's folder is no longer on this machine", code: "project_gone" }), /folder is no longer on this machine, so there is nothing to fix there\. Nothing was started\./],
    ["run running", err(409, { error: "the run has not ended", code: "run_running" }), /a fix would change files that its git check is watching\. Nothing was started\. Wait for the run to end, or stop it, then try again\./],
    ["plan changed", err(409, { error: "x", code: "plan_changed", prompt: "p", prompt_sha256: "d" }), /Close this window, open Fix with an agent again to read the new task, then choose an agent\./],
    ["record busy", err(409, { error: "x", code: "run_record_busy" }), /Another Observer process is writing the run record/],
    ["unknown run", err(404, "unknown run\n"), /^This run is no longer listed\.$/],
  ];
  for (const [name, e, re] of rows) assert.match(fixErrorWords(e) ?? "", re, name);
  // Neither the validate button's words nor the assessment launch's reach the fix dialog.
  assert.doesNotMatch(fixErrorWords(err(409, { code: "run_running" })) ?? "", /Validate/);
  assert.doesNotMatch(fixErrorWords(err(409, { code: "project_gone" })) ?? "", /checked against the model/);
  assert.doesNotMatch(fixErrorWords(err(409, { code: "plan_changed" })) ?? "", /open the assessment again/);
  // A code with no row reads as the server's sentence; an error with nothing to say is left to the caller.
  assert.equal(fixErrorWords(err(409, { error: "the run is in a state this page does not know", code: "newer_code" })), "The run is in a state this page does not know.");
  assert.equal(fixErrorWords(new Error("offline")), null);
  assert.equal(fixErrorWords(err(500, "boom")), null);
  assert.equal(fixErrorWords(undefined), null);
});

test("retrying helps for a busy record, a run that has not ended and a failed read, and not for something that is not there", () => {
  const no = ["no_location", "unknown_item", "no_stored_model", "project_gone"];
  const yes = ["run_running", "run_record_busy", "run_record_unreadable", "plan_changed", "newer_code"];
  for (const c of no) assert.equal(fixRetryHelps(err(409, { code: c })), false, c);
  for (const c of yes) assert.equal(fixRetryHelps(err(409, { code: c })), true, c);
  assert.equal(fixRetryHelps(err(404, "unknown run")), false);
  assert.equal(fixRetryHelps(err(500, "boom")), true);
  assert.equal(fixRetryHelps(new Error("offline")), true);
  assert.equal(fixRetryHelps(err(409, "not json")), true);
});

test("the launch's own refusal words cover a task that changed, a run that has not ended and a missing folder, and leave other failures to the dialog", () => {
  assert.match(fixRefusalText(err(409, { code: "plan_changed", error: "x" })) ?? "", /open Fix with an agent again/);
  assert.match(fixRefusalText(err(409, { code: "run_running" })) ?? "", /Wait for the run to end/);
  assert.match(fixRefusalText(err(409, { code: "no_location" })) ?? "", /nothing to point a fix at/);
  assert.match(fixRefusalText(err(404, { code: "unknown_item" })) ?? "", /no threat or finding with that id/);
  assert.match(fixRefusalText(err(404, { code: "no_stored_model" })) ?? "", /No checked copy/);
  assert.equal(fixRefusalText(err(404, "unknown run")), "This run is no longer listed.");
  // The server's other statuses keep their text: the org terminal gate's 403, a launch that is unavailable, a bad request.
  assert.equal(fixRefusalText(err(403, "the organization does not allow this")), null);
  assert.equal(fixRefusalText(err(503, "launch unavailable")), null);
  assert.equal(fixRefusalText(err(400, "tool x is not launchable")), null);
  assert.equal(fixRefusalText(new Error("offline")), null);
  assert.equal(fixRefusalText(undefined), null);
  // A plain-text 409 reads as the server's sentence, as for the other assess routes.
  assert.equal(fixRefusalText(err(409, "the run is already over")), "The run is already over.");
});

// ---- the downloads ----

test("the two downloads are the Markdown report and the checked model as JSON, in that order, each with its own test id", () => {
  assert.deepEqual(
    EXPORT_DOWNLOADS.map((d) => [d.format, d.label, d.testId, d.ext]),
    [
      ["md", "Download report (Markdown)", "assess-export-download-md", "md"],
      ["json", "Download checked model (JSON)", "assess-export-download-json", "json"],
    ],
  );
  const go = readFileSync(new URL("../../../internal/intelligence/dashboard/security_assess_export.go", import.meta.url), "utf8");
  for (const d of EXPORT_DOWNLOADS) assert.match(go, new RegExp(`\\{"${d.format}", "[^"]+", "${d.ext}"\\}`), `${d.format} is a format the route serves`);
  assert.match(EXPORT_DOWNLOAD_NOTE, /rendered by Observer from the checked copy/);
  assert.match(EXPORT_DOWNLOAD_NOTE, /not the agent's own report/);
  assert.match(EXPORT_DOWNLOAD_NOTE, /recognised secrets are hidden in them while hiding is on/);
});

test("the file name is the server's when it is a plain name of this export, else one built from the run and format", () => {
  const run = "00000000000000b2";
  const rows: Array<[string | null | undefined, "md" | "json", string]> = [
    [`attachment; filename="observer-assessment-${run}.md"`, "md", `observer-assessment-${run}.md`],
    [`attachment; filename="observer-assessment-${run}.json"`, "json", `observer-assessment-${run}.json`],
    [`attachment; filename=observer-assessment-${run}.json`, "json", `observer-assessment-${run}.json`],
    // The server's name for a run id it does not know is "run".
    [`attachment; filename="observer-assessment-run.md"`, "md", "observer-assessment-run.md"],
    // No header, an empty header and a header with no name fall back to the built name.
    [null, "md", `observer-assessment-${run}.md`],
    [undefined, "json", `observer-assessment-${run}.json`],
    ["attachment", "json", `observer-assessment-${run}.json`],
    // A name that is not this export's (another extension, a path, a traversal) is never used.
    [`attachment; filename="observer-assessment-${run}.md"`, "json", `observer-assessment-${run}.json`],
    [`attachment; filename="../../etc/passwd"`, "md", `observer-assessment-${run}.md`],
    [`attachment; filename="..\\\\evil.md"`, "md", `observer-assessment-${run}.md`],
    [`attachment; filename="other.json"`, "json", `observer-assessment-${run}.json`],
    [`attachment; filename="observer-assessment-.json"`, "json", `observer-assessment-${run}.json`],
  ];
  for (const [d, f, want] of rows) assert.equal(exportFileName(d, run, f), want, String(d));
  // A run id that is not plain characters reads as "run" in the built name.
  assert.equal(exportFileName(null, "../x", "md"), "observer-assessment-run.md");
  assert.equal(exportFileName(null, "", "json"), "observer-assessment-run.json");
});

test("a refused download says why and that nothing was saved, and never reads as a file", () => {
  const rows: Array<[number, string, RegExp]> = [
    [404, "unknown run\n", /^This run is no longer listed\. Nothing was saved\.$/],
    [404, JSON.stringify({ error: "no stored model for this run", code: "no_stored_model" }), /No checked copy of this run's model is stored\. Check the model again\. Nothing was saved\.$/],
    [400, JSON.stringify({ error: "the format is json or md", code: "bad_format" }), /Nothing was saved\./],
    [409, JSON.stringify({ error: "x", code: "run_record_busy" }), /Another Observer process is writing the run record\. Try again in a moment\. Nothing was saved\.$/],
    [500, "boom", /^The download could not be made\. Nothing was saved\.$/],
    [502, "", /^The download could not be made\. Nothing was saved\.$/],
  ];
  for (const [status, body, re] of rows) assert.match(exportErrorWords(status, body), re, `${status} ${body}`);
  // A row that already says nothing was saved is not told twice.
  assert.equal(exportErrorWords(400, JSON.stringify({ code: "bad_format" })).match(/Nothing was saved/g)?.length, 1);
});

// ---- no sentence reads as a clearance, and the help says what it must ----

test("no sentence this view builds uses a word or phrase of the shared clearance list", () => {
  const all: string[] = [FIX_NEXT_WORDS, FIX_TASK_WORDS, FIX_BUTTON_NOTE, FIX_AFTER_END_WORDS, EXPORT_DOWNLOAD_NOTE, EXPORT_DOWNLOAD_NONE];
  for (const d of EXPORT_DOWNLOADS) all.push(d.label);
  for (const w of Object.values(FIX_PLACE_WORDS)) all.push(w.label);
  for (const kind of ["threat", "finding", "x"]) all.push(fixItemWord(kind));
  for (const over of [{}, { band: "" as const }, { places_omitted: 1 }, { places_omitted: 9, item_kind: "finding" as const, item: "F-9" }]) {
    all.push(fixPlanHeadline(plan(over)));
    all.push(fixTaskFor(plan(over)).summary, fixTaskFor(plan(over)).title);
  }
  for (const b of [fixChooseBlock(null, true, false), fixChooseBlock(plan({ project: { name: "", root_path: "", on_disk: false } }), true, false), fixChooseBlock(plan(), false, false), fixChooseBlock(plan(), true, true)]) all.push(b ?? "");
  for (const code of ["no_location", "unknown_item", "no_stored_model", "project_gone", "run_running", "plan_changed", "run_record_busy", "bad_format"]) {
    all.push(fixErrorWords(err(409, { code })) ?? "", fixRefusalText(err(409, { code })) ?? "", exportErrorWords(409, JSON.stringify({ code })));
  }
  all.push(fixErrorWords(err(404, "unknown run")) ?? "", exportErrorWords(404, "unknown run"), exportErrorWords(500, "x"));
  for (const code of ["unknown_item", "no_location", "bad_format"]) all.push(ASSESS_REFUSALS[code].words);
  assert.ok(all.length > 40, "the sweep reached the strings");
  assert.deepEqual(
    all.filter((s) => BANNED.test(s)),
    [],
    "banned words in Observer's own wording",
  );
});

test("the fix and export help entries exist, read as no clearance, and say what each does and does not do", () => {
  const byId = (id: string) => HELP_REGISTRY.find((e) => e.id === id);
  const fix = byId("card.code_security_assess_fix");
  const exp = byId("card.code_security_assess_export");
  assert.ok(fix, "card.code_security_assess_fix is in the help registry");
  assert.ok(exp, "card.code_security_assess_export is in the help registry");
  for (const e of [fix!, exp!]) {
    for (const [field, text] of [["title", e.title], ["oneLiner", e.oneLiner], ["detail", e.detail ?? ""]] as const) {
      assert.doesNotMatch(text, BANNED, `${e.id} ${field}: ${text.match(BANNED)?.[0]}`);
    }
    assert.doesNotMatch(e.detail ?? "", /github\.com|https?:\/\//i, `${e.id} links out`);
    for (const rel of e.related ?? []) assert.ok(byId(rel), `${e.id} relates to ${rel}, which exists`);
  }
  const fd = fix!.detail ?? "";
  assert.match(fd, /edits files in your live project folder/);
  assert.match(fd, /Observer's own words/);
  assert.match(fd, /never the agent's prose|not the agent's prose|no prose/);
  assert.match(fd, /sandbox/);
  assert.match(fd, /regression test/);
  assert.match(fd, /does not change the model|changes no finding|no finding/);
  const ed = exp!.detail ?? "";
  assert.match(ed, /Markdown/);
  assert.match(ed, /JSON/);
  assert.match(ed, /not the agent's own report/);
  assert.match(ed, /recognised secrets/i);
});

test("assessRefusalWords still reads the new codes the way every other assess route's refusal reads", () => {
  assert.match(assessRefusalWords(err(409, { code: "no_location", error: "x" })) ?? "", /nothing to point a fix at/);
  assert.match(assessRefusalWords(err(404, { code: "unknown_item", error: "x" })) ?? "", /no threat or finding with that id/);
  assert.match(assessRefusalWords(err(400, { code: "bad_format", error: "x" })) ?? "", /Nothing was saved/);
});

test("assessFixEnabled offers a fix only from a stored model whose run has ended", () => {
  const rows: Array<[boolean, string | null | undefined, boolean]> = [
    [true, "2026-11-14T08:40:00Z", true],
    [true, undefined, false],
    [true, null, false],
    [true, "", false],
    [false, "2026-11-14T08:40:00Z", false],
    [false, undefined, false],
  ];
  for (const [hasModel, ended, want] of rows) assert.equal(assessFixEnabled(hasModel, ended), want, `${hasModel} ${ended}`);
});
