// Component tests of the assessment model view (docs/plans/security-
// assessments-depth-plan-2026-11-14.md wave 6): the threat model and pen test
// tabs, the threat table, the matrix, the flow table, the attack trees, the
// coverage matrix, the findings, the limits strip, the export menu and the
// comparison with an earlier run, rendered with react-dom/server under node's
// test runner (scripts/test-components.mjs, no DOM). A click cannot be
// simulated; what a click does is pinned in src/lib/secAssessModel.test.ts (the
// pure helpers each handler calls) and in the Playwright spec (the clicks and
// the keyboard), and these prove the components render what those build. The fixtures are the
// exact shape of the server's answer (src/lib/secAssessModelFixture.ts).

import { test } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import type { ReactElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router-dom";
import { AssessModelView, modelErrorWords, modelTabs, NO_STORED_MODEL_WORDS, type ModelTabId } from "@/components/secassess/AssessModelView";
import { AssessRunsList } from "@/components/secassess/AssessRunsList";
import { reportRedactionNote } from "@/components/secassess/AssessReportDialog";
import { CoverageMatrix } from "@/components/secassess/CoverageMatrix";
import { ElementMatrix } from "@/components/secassess/ElementMatrix";
import { ExportMenu, exportItems } from "@/components/secassess/ExportMenu";
import { fmtDateTime } from "@/lib/format";
import { FINDING_BATCH, FINDING_COLUMN_WIDTHS, FindingBody, FindingEvidence, FindingList, ProbeCard } from "@/components/secassess/FindingEvidence";
import { FlowTable } from "@/components/secassess/FlowTable";
import { LimitsStrip } from "@/components/secassess/LimitsStrip";
import { SecAssessCard } from "@/components/secassess/SecAssessCard";
import { SystemView } from "@/components/secassess/SystemView";
import { THREAT_BATCH, ThreatTable } from "@/components/secassess/ThreatTable";
import { TreeList } from "@/components/secassess/TreeList";
import { ApiError } from "@/lib/api";
import { apiCache } from "@/lib/useApi";
import type { SecurityProject } from "@/lib/codeSecurity";
import { ASSESS_LIST_PATH, assessRefusalWords, type AssessList, type AssessRun } from "@/lib/secAssess";
import { clearanceRegExp, parseClearanceList } from "@/lib/secAssessBanned";
import { CVSS_APART, CVSS_LEFT_OUT_NOTE, assessModelPath, limitsFor, probeIndex, redactionNote, type AssessModelResponse, type EvidenceReport, type ModelIssue, type ModelThreat, type PentestDoc, type ThreatModelDoc } from "@/lib/secAssessModel";
import {
  FIXTURE_PT,
  FIXTURE_PT_EMPTY,
  FIXTURE_PT_EVIDENCE,
  FIXTURE_PT_NOT_STARTED,
  FIXTURE_PT_PARTIAL,
  FIXTURE_PT_REFUSED_ALL,
  FIXTURE_PT_RETESTED,
  FIXTURE_RED_TEAM,
  FIXTURE_RED_TEAM_AGENT,
  FIXTURE_RETEST,
  FIXTURE_SINCE,
  FIXTURE_SINCE_RUN,
  FIXTURE_SINCE_SIMILAR,
  FIXTURE_TM,
  FIXTURE_TM_PARTIAL,
  FIXTURE_TM_REFUSED_ALL,
  FIXTURE_TM_SINCE,
  FIXTURE_VOCAB,
  fixtureBigPentest,
  fixtureBigThreatModel,
} from "@/lib/secAssessModelFixture";

const consoleError = console.error;
console.error = (...args: unknown[]) => {
  if (typeof args[0] === "string" && args[0].includes("useLayoutEffect does nothing on the server")) return;
  consoleError(...args);
};

// ---- helpers ----

const TM = FIXTURE_TM.record.result.tm as ThreatModelDoc;
const PT = FIXTURE_PT.record.result.pt as PentestDoc;
const HOSTILE_SCRIPT = "<script>alert(1)</script>";
const HOSTILE_IMG = '"><img src=x onerror=1>';

function run(over: Partial<AssessRun> = {}): AssessRun {
  return {
    id: "20261114-tm0001",
    created_at: "2026-11-14T00:00:00Z",
    kind: "threat_model",
    kind_title: "Threat model",
    tool: "claude-code",
    project_root_hash: "h1",
    project_name: "ledger",
    seeded: true,
    sandboxed: false,
    state: "validated",
    files: { report: true, sarif: false, commands: false, model: true },
    contract: "threatmodel.v1",
    validation: { state: "partial", at: "2026-11-14T08:45:00Z", refs: { found: 2, exists: 1, claimed_not_found: 1, missing: 1, invalid: 0, unchecked: 1 } },
    // The server sends has_model while a checked copy is stored.
    has_model: true,
    report_bytes: 10,
    ...over,
  };
}

/** seed puts an answer in the query cache where the view reads it. */
async function seed(id: string, data: AssessModelResponse, since?: string): Promise<void> {
  await apiCache.fetch(assessModelPath(id, since), async () => data);
}

async function seedError(id: string, err: ApiError, since?: string): Promise<void> {
  await apiCache.fetch(assessModelPath(id, since), async () => {
    throw err;
  });
}

function view(r: AssessRun, extra: { runs?: AssessRun[]; initialTab?: ModelTabId; initialSince?: string } = {}): string {
  return renderToStaticMarkup(
    <MemoryRouter>
      <AssessModelView run={r} runs={extra.runs ?? [r]} onClose={() => {}} initialTab={extra.initialTab} initialSince={extra.initialSince} />
    </MemoryRouter>,
  );
}

function render(el: ReactElement): string {
  return renderToStaticMarkup(<MemoryRouter>{el}</MemoryRouter>);
}

function count(html: string, re: RegExp): number {
  return (html.match(re) ?? []).length;
}

function testIds(html: string, id: string): number {
  return count(html, new RegExp(`data-testid="${id}"`, "g"));
}

/** text strips the tags and decodes the five entities React writes, so a test reads what a person reads. */
function text(html: string): string {
  return html
    .replace(/<[^>]*>/g, " ")
    .replace(/&quot;/g, '"')
    .replace(/&#x27;/g, "'")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&amp;/g, "&")
    .replace(/\s+/g, " ");
}

/** tabNames lists the accessible names of the tabs, in order. */
function tabNames(html: string): string[] {
  const out: string[] = [];
  for (const m of html.matchAll(/<button[^>]*role="tab"[^>]*>([\s\S]*?)<\/button>/g)) {
    const label = m[0].match(/aria-label="([^"]*)"/);
    out.push(label ? label[1] : text(m[1]).trim());
  }
  return out;
}

/** The text of a block of markup that starts at a test id, up to the next one of the same kind. */
function between(html: string, from: string, to: string): string {
  const a = html.indexOf(from);
  const b = html.indexOf(to, a + from.length);
  assert.ok(a >= 0, `${from} is in the markup`);
  return html.slice(a, b >= 0 ? b : undefined);
}

const TM_TABS: ModelTabId[] = ["overview", "threats", "matrix", "system", "flows", "trees", "checked"];
const PT_TABS: ModelTabId[] = ["coverage", "findings", "checked"];

// ---- the pins: nothing builds markup from a string ----

/** secassessDir is the folder of the module's sources, whether the tests run from web/ or from the repository root. */
function secassessDir(): string {
  const candidates = [path.resolve(process.cwd(), "src/components/secassess"), path.resolve(process.cwd(), "web/src/components/secassess")];
  const dir = candidates.find((d) => {
    try {
      return readdirSync(d).length > 0;
    } catch {
      return false;
    }
  });
  assert.ok(dir, "the component directory is found");
  return dir;
}

/** repoFile is a file of the repository, whether the tests run from web/ or from the repository root. */
function repoFile(rel: string): string {
  const candidates = [path.resolve(process.cwd(), "..", rel), path.resolve(process.cwd(), rel)];
  const found = candidates.find((f) => {
    try {
      readFileSync(f);
      return true;
    } catch {
      return false;
    }
  });
  assert.ok(found, `${rel} is found`);
  return found;
}

/** The one list of words and phrases no sentence Observer builds may use: the file the Go test reads too. */
const CLEARANCE = parseClearanceList(readFileSync(repoFile("internal/secassess/testdata/clearance_words.json"), "utf8"));
const BANNED = clearanceRegExp(CLEARANCE);

test("the shared clearance list catches what it must and lets through what it must", () => {
  for (const c of CLEARANCE.caught ?? []) assert.match(c, BANNED, `caught: ${c}`);
  for (const a of CLEARANCE.allowed ?? []) assert.doesNotMatch(a, BANNED, `allowed: ${a}`);
  assert.ok((CLEARANCE.caught ?? []).length >= 10 && (CLEARANCE.allowed ?? []).length >= 10);
});

test("no component of the module builds markup, SVG or code from a string", () => {
  const dir = secassessDir();
  const files = readdirSync(dir).filter((f) => /\.(ts|tsx)$/.test(f) && !/\.test\.tsx?$/.test(f));
  // The nine components of the plan, the two this view added, and the three that already stood.
  for (const f of ["AssessModelView", "ThreatTable", "ElementMatrix", "FlowTable", "TreeList", "CoverageMatrix", "FindingEvidence", "LimitsStrip", "ExportMenu", "AssessRunsList", "SecAssessCard", "AssessReportDialog", "AssessExercise", "AssessRetestLabel", "AssessRetestPicker", "AssessRetestPlan", "AssessRetestView", "AssessObjectiveField", "AssessRunExtras"]) {
    assert.ok(files.includes(`${f}.tsx`), `${f}.tsx is swept`);
  }
  const banned = ["dangerouslySetInnerHTML", "innerHTML", "outerHTML", "insertAdjacentHTML", "createElementNS", "<svg", "eval("];
  for (const f of files) {
    const src = readFileSync(path.join(dir, f), "utf8");
    for (const b of banned) assert.equal(src.includes(b), false, `${f} contains ${b}`);
  }
});

test("the module's sources name no setting key, make no raw value readable by replacing underscores, and print no muted text in the fourth grey", () => {
  const dir = secassessDir();
  const files = readdirSync(dir).filter((f) => /\.(ts|tsx)$/.test(f) && !/\.test\.tsx?$/.test(f));
  for (const f of files) {
    const src = readFileSync(path.join(dir, f), "utf8");
    // A setting is named by its label, never by its key (docs/app-design-system.md "Never in UI text").
    assert.doesNotMatch(src, /display_redaction|diagram_max_nodes|diagram_label_chars/, `${f} names a setting key`);
    // A closed value reaches the page through a table of words, not through .replace(/_/g, " ").
    assert.doesNotMatch(src, /\.replace\(\/_\/g/, `${f} makes a raw value readable by replacing underscores`);
    // text-fg-4 is for glyphs: it does not reach 4.5:1 on the page's surfaces, so no line of words uses it.
    for (const line of src.split("\n")) {
      if (line.includes("text-fg-4")) assert.ok(/<Icon\b/.test(line), `${f}: text-fg-4 on something that is not a glyph: ${line.trim()}`);
    }
    // The export is two plain buttons in the dialog's own tab order: no popover, no menu role.
    assert.doesNotMatch(src, /AnchoredPopover|role="menu"|role="menuitem"|aria-haspopup/, `${f} builds a menu`);
  }
});

// ---- the view: tabs, states and notices ----

test("a threat model has seven tabs, in order, each with an honest name", async () => {
  const r = run({ id: "tm-tabs" });
  await seed(r.id, FIXTURE_TM);
  const html = view(r);
  assert.deepEqual(tabNames(html), ["Overview", "Threats", "Matrix", "System", "Flows", "Attack trees", "How checked"]);
  assert.match(html, /data-testid="assess-model"/);
  // The title is the kind and the project: the word model is not said twice.
  assert.match(text(html), /Threat model: ledger/);
  assert.doesNotMatch(text(html), /Threat model: model/);
  assert.match(text(html), /Validated /);
  // No tab label is longer than the design system's tab guide of about 14 characters.
  for (const name of tabNames(html)) assert.ok(name.length <= 14, `tab label ${name} is ${name.length} characters`);
  assert.match(html, /data-help-id="card\.code_security_assess_model"/);
  // The counts ride beside the tabs that have a number.
  assert.match(html, /aria-label="Threats"[^>]*>[^<]*(<[^>]*>)*[^<]*Threats(<[^>]*>)*[^<]*<span[^>]*>5</);
});

test("a pen test has Coverage first, then Findings and How checked", async () => {
  const r = run({ id: "pt-tabs", kind: "pentest_local", kind_title: "Penetration test (your own app, local)", contract: "pentest.v1" });
  await seed(r.id, FIXTURE_PT);
  const html = view(r);
  assert.deepEqual(tabNames(html), ["Coverage", "Findings", "How checked"]);
  assert.match(text(html), /Penetration test \(your own app, local\): ledger/);
});

test("the title names the project, else the run's id, and the handle token is never shown", async () => {
  const a = run({ id: "tm-title-handle", project_name: "", handle: "5GlyQD7F2QcTK82lkokY1X6LCJ8vFBmLK4sDeXT39gk" });
  await seed(a.id, FIXTURE_TM);
  const ta = text(view(a));
  assert.match(ta, /Threat model: tm-title-handle/);
  // The handle is a token the launch hands out, not a name: it is neither the title nor the subtitle.
  assert.doesNotMatch(ta, /5GlyQD7F2QcTK82lkokY1X6LCJ8vFBmLK4sDeXT39gk/);
  const b = run({ id: "tm-title-id", project_name: "" });
  await seed(b.id, FIXTURE_TM);
  assert.match(text(view(b)), /Threat model: tm-title-id/);
});

test("the subtitle says when the run started and when its model was checked, and no run token", async () => {
  const r = run({ id: "tm-subtitle", created_at: "2026-11-14T10:00:00Z", handle: "GPdOTMMholbW-NGur1OXzB3_MLkZ7cnOUmAEiE-VUdg" });
  await seed(r.id, FIXTURE_TM);
  const t = text(view(r));
  assert.ok(t.includes(`Started ${fmtDateTime("2026-11-14T10:00:00Z")}`), t.slice(0, 300));
  assert.match(t, /Started [^·]+ · Validated /);
  assert.doesNotMatch(t, /GPdOTMMholbW/);
  assert.doesNotMatch(t, /\bRun [A-Za-z0-9_-]{20,}/);
});

test("the comparison opens on the earlier run the run was launched with, when it can still be compared with", async () => {
  const r = run({ id: "tm-since-default", created_at: "2026-11-14T00:00:00Z", previous_run: "earlier-a" });
  await seed(r.id, FIXTURE_TM);
  const other = run({ id: "earlier-b", created_at: "2026-11-13T00:00:00Z" });
  const chosen = run({ id: "earlier-a", created_at: "2026-11-10T00:00:00Z" });
  const html = view(r, { runs: [r, other, chosen], initialTab: "overview" });
  // The older run was the one launched with; it is selected although a newer one is offered first.
  assert.match(html, /<option value="earlier-a" selected=""/);
  assert.doesNotMatch(html, /<option value="earlier-b" selected=""/);
  assert.doesNotMatch(html, /<option value="" selected=""/);
  // A caller that names a run (a deep link, a test) wins over the launch's own.
  const named = view(r, { runs: [r, other, chosen], initialTab: "overview", initialSince: "earlier-b" });
  assert.match(named, /<option value="earlier-b" selected=""/);
});

test("the comparison opens on none when the run was launched without one, or its earlier run has no checked copy left", async () => {
  const none = run({ id: "tm-since-none-chosen", created_at: "2026-11-14T00:00:00Z" });
  await seed(none.id, FIXTURE_TM);
  const earlier = run({ id: "earlier-ok", created_at: "2026-11-10T00:00:00Z" });
  const a = view(none, { runs: [none, earlier], initialTab: "overview" });
  assert.match(a, /<option value="" selected=""/);
  const gone = run({ id: "tm-since-gone", created_at: "2026-11-14T00:00:00Z", previous_run: "earlier-gone" });
  await seed(gone.id, FIXTURE_TM);
  const noCopy = run({ id: "earlier-gone", created_at: "2026-11-09T00:00:00Z", has_model: false });
  const b = view(gone, { runs: [gone, earlier, noCopy], initialTab: "overview" });
  assert.match(b, /<option value="" selected=""/);
});

test("modelTabs: every tab of a kind is listed, and a record with no model keeps only How this was checked", () => {
  assert.deepEqual(modelTabs(FIXTURE_TM.record).map((t) => t.id), TM_TABS);
  assert.deepEqual(modelTabs(FIXTURE_PT.record).map((t) => t.id), PT_TABS);
  assert.deepEqual(modelTabs({ ...FIXTURE_TM.record, truncated: true, result: { report: FIXTURE_TM.record.result.report } }).map((t) => t.id), ["checked"]);
  // A contract that carries no model has only the check, whatever the record holds.
  assert.deepEqual(modelTabs({ ...FIXTURE_TM.record, contract: "sarif" }).map((t) => t.id), ["checked"]);
  // A tab with nothing to show is still there: the empty threat model lists the same seven.
  const empty: AssessModelResponse = { ...FIXTURE_TM, record: { ...FIXTURE_TM.record, result: { ...FIXTURE_TM.record.result, tm: { ...TM, threats: [], attack_trees: [], system: {} } } } };
  assert.deepEqual(modelTabs(empty.record).map((t) => t.id), TM_TABS);
});

test("while the model is read the view shows a loading line, and a failed read says why in words", async () => {
  const loading = view(run({ id: "tm-never-read" }));
  assert.match(loading, /role="status"[^>]*aria-label="Loading the model"/);
  assert.doesNotMatch(loading, /data-testid="assess-model-error"/);

  const r404 = run({ id: "tm-404" });
  await seedError(r404.id, new ApiError(404, assessModelPath(r404.id), JSON.stringify({ error: "no stored model for this run", code: "no_stored_model" })));
  const html = view(r404);
  assert.match(html, /data-testid="assess-model-error"/);
  assert.match(text(html), /No checked copy of this model is stored \(it was deleted, or the run was never checked\)\. Validate the run again\./);
});

test("modelErrorWords: 404 the missing copy, 409 the server's words, anything else the reason", () => {
  const p = assessModelPath("x");
  assert.equal(modelErrorWords(new ApiError(404, p, JSON.stringify({ code: "no_stored_model", error: "no stored model for this run" }))), NO_STORED_MODEL_WORDS);
  assert.equal(modelErrorWords(new ApiError(404, p, "unknown run")), "This run is no longer listed.");
  const conflict = new ApiError(409, p, JSON.stringify({ code: "project_gone", error: "the project's folder is no longer on this machine" }));
  assert.equal(modelErrorWords(conflict), assessRefusalWords(conflict));
  assert.match(modelErrorWords(conflict), /folder is no longer on this machine/);
  assert.match(modelErrorWords(new ApiError(500, p, "boom")), /boom/);
  assert.equal(modelErrorWords(new Error("offline")), "offline");
});

test("notices: a stale check, drifted files, only the report kept, and the redaction note", async () => {
  const r = run({ id: "tm-notices" });
  await seed(r.id, { ...FIXTURE_TM, stale: true, drift: ["src/api/db.ts", "src/api/search.ts"], redaction: { on: true, hidden: 3 } });
  const html = view(r);
  assert.match(html, /data-testid="assess-model-stale"/);
  assert.match(text(html), /The agent's model file changed after this check/);
  assert.match(text(html), /Check the run again to read the new one/);
  assert.match(html, /data-testid="assess-model-drift"/);
  assert.match(text(html), /2 project files read differently/);
  assert.match(html, /data-testid="assess-model-redaction"/);
  assert.match(text(html), /In this answer, 3 places were hidden\./);
  assert.match(text(html), /Secrets Observer recognises are hidden in the text shown here, and only known shapes are recognised\./);
  assert.match(text(html), /Names that link parts of the model together and file paths are shown as the agent wrote them\./);
  assert.match(text(html), /The files in your project are as the agent wrote them\./);
  assert.doesNotMatch(html, /data-testid="assess-model-truncated"/);

  // Nothing stale, nothing drifted: none of the three notices.
  const quiet = run({ id: "tm-quiet" });
  await seed(quiet.id, FIXTURE_TM);
  const q = view(quiet);
  for (const id of ["assess-model-stale", "assess-model-drift", "assess-model-truncated", "assess-model-none"]) assert.doesNotMatch(q, new RegExp(`data-testid="${id}"`), id);
  // Hiding turned off says so too, and names the setting by its label, never by its key.
  const off = run({ id: "tm-off" });
  await seed(off.id, { ...FIXTURE_TM, redaction: { on: false, hidden: 0 } });
  const offText = text(view(off));
  assert.ok(offText.includes(redactionNote({ on: false, hidden: 0 })));
  assert.match(offText, /"Hide recognised secrets when showing a report or model"/);
  assert.doesNotMatch(offText, /display_redaction/);
});

test("the partly checked state is said above the tabs, on every tab, with what was refused and what was not looked at", async () => {
  // FIXTURE_TM is a partial result: one reference could not be looked at.
  const r = run({ id: "tm-partial-notice" });
  await seed(r.id, FIXTURE_TM_PARTIAL);
  for (const tab of TM_TABS) {
    const html = view(r, { initialTab: tab });
    const note = text(between(html, 'data-testid="assess-model-partial"', 'data-testid="assess-model-limits-summary"'));
    assert.match(note, /Partly checked/, tab);
    assert.match(note, /1 item was refused, 1 reference could not be looked at within the check's budget\./, tab);
    assert.match(note, /How checked/, tab);
  }
  // A result with nothing refused and nothing left unlooked-at has no such notice.
  const clean = run({ id: "tm-no-partial-notice" });
  await seed(clean.id, { ...FIXTURE_TM, record: { ...FIXTURE_TM.record, result: { ...FIXTURE_TM.record.result, report: { ...FIXTURE_TM.record.result.report, state: "valid", refs: { ...FIXTURE_TM.record.result.report.refs, unchecked: 0 } } } } });
  assert.doesNotMatch(view(clean), /data-testid="assess-model-partial"/);
  // The pen test's too.
  const pt = run({ id: "pt-partial-notice", ...PT_RUN });
  await seed(pt.id, FIXTURE_PT_PARTIAL);
  for (const tab of PT_TABS) assert.match(text(between(view(pt, { initialTab: tab }), 'data-testid="assess-model-partial"', 'data-testid="assess-model-limits-summary"')), /1 item was refused\./, tab);
});

test("what this does not tell you is above the tabs on every tab of both kinds, and in every state of the result", async () => {
  const cases: [string, AssessModelResponse, Partial<AssessRun>, ModelTabId[]][] = [
    ["tm", FIXTURE_TM, {}, TM_TABS],
    ["pt", FIXTURE_PT, PT_RUN, PT_TABS],
    ["pt-empty", FIXTURE_PT_EMPTY, PT_RUN, PT_TABS],
    ["tm-refused-all", FIXTURE_TM_REFUSED_ALL, {}, TM_TABS],
    ["pt-refused-all", FIXTURE_PT_REFUSED_ALL, PT_RUN, PT_TABS],
    ["tm-truncated", { ...FIXTURE_TM, record: { ...FIXTURE_TM.record, truncated: true, result: { report: FIXTURE_TM.record.result.report } } }, {}, ["checked"]],
  ];
  for (const [id, data, over, tabs] of cases) {
    const r = run({ id: `summary-${id}`, ...over });
    await seed(r.id, data);
    for (const tab of tabs) {
      const html = view(r, { initialTab: tab });
      const sum = between(html, 'data-testid="assess-model-limits-summary"', 'role="tablist"');
      const t = text(sum);
      assert.match(t, /What this does not tell you/, `${id} ${tab}`);
      assert.match(t, /Observer checked only its structure and the files it cites/, `${id} ${tab}`);
      assert.match(t, /Nothing reported is not a clearance, and this is not compliance evidence\./, `${id} ${tab}`);
      assert.match(t, /All the limits/, `${id} ${tab}`);
      assert.match(sum, /<button[^>]*>All the limits<\/button>/, `${id} ${tab}: a button to the last tab`);
    }
  }
  // The second line is the kind's own.
  const tm = run({ id: "summary-tm-line" });
  await seed(tm.id, FIXTURE_TM);
  assert.match(text(view(tm)), /unknown, not ruled out/);
  const pt = run({ id: "summary-pt-line", ...PT_RUN });
  await seed(pt.id, FIXTURE_PT);
  assert.match(text(view(pt)), /not production/);
  // The full strip stays on the last tab.
  assert.match(view(pt, { initialTab: "checked" }), /data-testid="assess-limits"/);
});

test("a truncated record shows only the report: a notice, no model tabs", async () => {
  const r = run({ id: "tm-truncated" });
  await seed(r.id, { ...FIXTURE_TM, record: { ...FIXTURE_TM.record, truncated: true, result: { report: FIXTURE_TM.record.result.report } }, mermaid: undefined });
  const html = view(r);
  assert.match(html, /data-testid="assess-model-truncated"/);
  assert.match(text(html), /Only the report is kept/);
  assert.deepEqual(tabNames(html), ["How checked"]);
  assert.match(html, /data-testid="assess-limits"/);
  // The truncation callout is the one explanation: there is not a second one for the same fact.
  assert.doesNotMatch(html, /data-testid="assess-model-none"/);
});

test("a refused file has no model: a callout says so and the issues are on How checked", async () => {
  const r = run({ id: "tm-refused", validation: { state: "invalid", at: "2026-11-14T08:45:00Z", fatal: "bad_shape", refs: { found: 0, exists: 0, claimed_not_found: 0, missing: 0, invalid: 0, unchecked: 0 } } });
  const report = { ...FIXTURE_TM.record.result.report, state: "invalid", fatal: "bad_shape", tm: undefined, issues: [{ row: "V2", code: "bad_shape", severity: "refused" as const, message: "The file's shape does not match the schema." }] };
  await seed(r.id, { ...FIXTURE_TM, record: { ...FIXTURE_TM.record, result: { report } }, mermaid: undefined });
  const html = view(r);
  assert.match(html, /data-testid="assess-model-none"/);
  assert.match(text(html), /No model was kept/);
  assert.deepEqual(tabNames(html), ["How checked"]);
  assert.match(text(html), /The file was refused: its shape does not match the schema\./);
  assert.match(text(html), /The file's shape does not match the schema\./);
  assert.match(html, /data-testid="assess-issue"/);
});

// ---- Overview and the comparison ----

test("Overview: the agent's summary, the band counts, the coverage line, scope, questions and limits", async () => {
  const r = run({ id: "tm-overview" });
  await seed(r.id, FIXTURE_TM);
  const html = view(r, { initialTab: "overview" });
  const t = text(html);
  assert.match(t, /The agent says/);
  assert.match(t, /Ledger is a small bookkeeping service/);
  const bands = between(html, 'data-testid="assess-model-bands"', "</div>");
  for (const want of ["critical 1", "high 1", "medium 2", "low 1"]) assert.match(text(bands), new RegExp(want), want);
  assert.match(text(between(html, 'data-testid="assess-model-coverage-line"', "</p>")), /Covered by the agent: 4 element and category pairs analysed, 2 waived with a reason and 41 with neither\./);
  assert.match(t, /In scope/);
  assert.match(t, /Out of scope/);
  assert.match(t, /The API runs behind a reverse proxy that ends TLS\./);
  assert.match(t, /Is the export route reachable without a session\?/);
  assert.match(t, /The agent did not read the deployment files\./);
  assert.match(t, /The file names claude-code \(model-x\) as its writer, prompt version tm\.2\./);
  assert.match(html, /aria-label="Compare with an earlier run"/);
  assert.match(html, /data-testid="assess-since-select"/);
  assert.doesNotMatch(html, /data-testid="assess-model-reading"/);
});

test("Overview: a model with nothing in it carries the reading sentence", async () => {
  const r = run({ id: "tm-reading" });
  const reading = "No threat was recorded. That says what the agent wrote; it is not proof that none exists.";
  await seed(r.id, { ...FIXTURE_TM, reading });
  const html = view(r, { initialTab: "overview" });
  assert.match(html, /data-testid="assess-model-reading"/);
  assert.match(text(between(html, 'data-testid="assess-model-reading"', 'data-testid="assess-model-coverage-line"')), /not proof that none exists/);
});

test("Overview: a threat model of which the check refused every threat says what happened, not that none was reported", async () => {
  const r = run({ id: "tm-refused-all-overview" });
  await seed(r.id, FIXTURE_TM_REFUSED_ALL);
  const html = view(r, { initialTab: "overview" });
  const reading = text(between(html, 'data-testid="assess-model-reading"', 'data-testid="assess-model-coverage-line"'));
  assert.match(reading, /The agent wrote 3 threats, and none is shown here: the check refused 3./);
  assert.doesNotMatch(reading, /lists no threats|reported no/i);
  assert.match(text(html), /0 element and category pairs analysed, 2 waived with a reason and 45 with neither/);
  assert.match(text(html), /Partly checked/);
});

test("the comparison offers the other checked runs of the same project and kind, newest first", async () => {
  const r = run({ id: "tm-since-opts" });
  await seed(r.id, FIXTURE_TM);
  const older = run({ id: "older", created_at: "2026-11-10T00:00:00Z" });
  const newer = run({ id: "newer", created_at: "2026-11-12T00:00:00Z", state: "model_ready" });
  const otherProject = run({ id: "elsewhere", project_root_hash: "h2" });
  const otherKind = run({ id: "pentest", kind: "pentest_local", contract: "pentest.v1" });
  const unchecked = run({ id: "unchecked", validation: undefined, has_model: undefined });
  // A run started after this one is refused by the server, and one whose stored copy was deleted has nothing to compare.
  const later = run({ id: "later", created_at: "2026-11-15T00:00:00Z" });
  const noCopy = run({ id: "no-copy", created_at: "2026-11-09T00:00:00Z", has_model: false });
  const html = view(r, { runs: [r, older, otherProject, newer, otherKind, unchecked, later, noCopy], initialTab: "overview" });
  const select = between(html, 'data-testid="assess-since-select"', "</select>");
  const values = [...select.matchAll(/<option value="([^"]*)"/g)].map((m) => m[1]);
  assert.deepEqual(values, ["", "newer", "older"]);
  assert.match(select, /, validated|, model ready/);
  // The same label as the run row and the plan's picker (UX-7): the kind, the date and time from the app's formatter, then the state. Not "2 hours ago", which two runs of one hour share.
  const labels = [...select.matchAll(/<option value="[^"]+">([^<]*)<\/option>/g)].map((m) => m[1]);
  assert.equal(labels.length, 2);
  for (const l of labels) assert.match(l, /^Threat model, [A-Z][a-z]{2} \d+, 2026, [^,]+, [a-z ]+$/);
  assert.doesNotMatch(select, /\bago\b/);
  assert.doesNotMatch(select, /disabled=""/);
  // With none to offer, the select is off and says why.
  const alone = run({ id: "tm-since-none" });
  await seed(alone.id, FIXTURE_TM);
  const a = view(alone, { initialTab: "overview" });
  assert.match(a, /<select[^>]*disabled=""[^>]*data-testid="assess-since-select"|<select[^>]*data-testid="assess-since-select"[^>]*disabled=""/);
  assert.match(text(a), /There is no earlier checked run of this project and kind to compare with\./);
});

test("the comparison shows every added, removed and changed threat, the band moves and the note", async () => {
  const r = run({ id: "tm-since" });
  await seed(r.id, FIXTURE_TM);
  await seed(r.id, FIXTURE_TM_SINCE, FIXTURE_SINCE_RUN);
  const earlier = run({ id: FIXTURE_SINCE_RUN, created_at: "2026-11-13T00:00:00Z" });
  const html = view(r, { runs: [r, earlier], initialTab: "overview", initialSince: FIXTURE_SINCE_RUN });
  const block = between(html, 'data-testid="assess-since"', 'data-testid="assess-since-system"');
  const t = text(block);
  assert.match(html, /data-testid="assess-since"/);
  assert.match(t, /Threats are matched by element, category and title first \(an element by its name/);
  assert.match(t, /This compares what two runs reported; it does not say which is right\./);
  assert.match(text(between(html, 'data-testid="assess-since-counts"', "</p>")), /1 added, 1 removed, 1 changed, 2 read the same/);
  assert.match(text(between(html, 'data-testid="assess-since-added"', 'data-testid="assess-since-removed"')), /T-5 Prompt text in an entry note steers the summary assistant medium 9/);
  assert.match(text(between(html, 'data-testid="assess-since-removed"', 'data-testid="assess-since-changed"')), /T-9 Export route answers without a session high 15/);
  const changed = text(between(html, 'data-testid="assess-since-changed"', 'data-testid="assess-since-system"'));
  assert.match(changed, /T-1 SQL injection through the entry search high 15 to critical 20/);
  assert.match(changed, /Matched by id\./);
  assert.match(changed, /status partly mitigated to identified, as the agent says/);
  assert.match(changed, /missing mitigations 2 to 1/);
  const sys = text(between(html, 'data-testid="assess-since-system"', "</ul>"));
  assert.match(sys, /Components: added Audit log/);
  assert.match(sys, /Flows: removed web to cache/);
  assert.doesNotMatch(sys, /Trust zones/);
  // The select shows the chosen run.
  assert.match(html, new RegExp(`<option value="${FIXTURE_SINCE_RUN}" selected=""`));
});

test("pairs made by the place a threat cites are listed apart as probably the same, never as unchanged", async () => {
  const r = run({ id: "tm-since-similar" });
  await seed(r.id, FIXTURE_TM);
  await seed(r.id, { ...FIXTURE_TM, since: FIXTURE_SINCE_SIMILAR }, FIXTURE_SINCE_RUN);
  const html = view(r, { runs: [r, run({ id: FIXTURE_SINCE_RUN, created_at: "2026-11-13T00:00:00Z" })], initialTab: "overview", initialSince: FIXTURE_SINCE_RUN });
  assert.match(text(between(html, 'data-testid="assess-since-counts"', "</p>")), /2 added, 12 removed, 0 changed, 0 read the same, 3 probably the same/);
  const block = text(between(html, 'data-testid="assess-since-similar"', "</ul>"));
  assert.match(block, /Probably the same \(3\)/);
  assert.match(block, /T-1 SQL injection through the entry search high 15 to critical 20/);
  assert.match(block, /Earlier run, E-40: The search term is concatenated into the notes query/);
  // The earlier category is shown when it differs, and only then.
  assert.match(block, /Tampering \(earlier: Information disclosure\)\. Probably the same, matched by the place in the code it cites, a weakness id \(CWE\) in common, similar words in the title and the same element\./);
  assert.match(block, /Spoofing\. Probably the same, matched by the place in the code it cites and the same category\./);
  assert.doesNotMatch(block, /Spoofing \(earlier/);
  assert.match(block, /matched by a weakness id \(CWE\) in common, similar words in the title and the same category\./);
  // No pair is offered as one that reads the same, and none is a change.
  assert.doesNotMatch(html, /data-testid="assess-since-changed"/);
  assert.equal(count(html, /data-testid="assess-since-similar"/g), 1);
});

test("a sign of a pair the vocabulary does not name is left out, never printed raw", async () => {
  const r = run({ id: "tm-since-odd-sign" });
  const since = { ...FIXTURE_SINCE_SIMILAR, similar: [{ ...FIXTURE_SINCE_SIMILAR.similar![2], basis: ["cwe", "zzsign"] }] };
  await seed(r.id, FIXTURE_TM);
  await seed(r.id, { ...FIXTURE_TM, since }, FIXTURE_SINCE_RUN);
  const html = view(r, { runs: [r, run({ id: FIXTURE_SINCE_RUN, created_at: "2026-11-13T00:00:00Z" })], initialTab: "overview", initialSince: FIXTURE_SINCE_RUN });
  assert.match(text(between(html, 'data-testid="assess-since-similar"', "</ul>")), /matched by a weakness id \(CWE\) in common\./);
  assert.doesNotMatch(html, /zzsign/);
});

test("a comparison that could pair few threats says so", async () => {
  const r = run({ id: "tm-since-pairing" });
  await seed(r.id, FIXTURE_TM);
  await seed(r.id, { ...FIXTURE_TM, since: FIXTURE_SINCE_SIMILAR }, FIXTURE_SINCE_RUN);
  const html = view(r, { runs: [r, run({ id: FIXTURE_SINCE_RUN, created_at: "2026-11-13T00:00:00Z" })], initialTab: "overview", initialSince: FIXTURE_SINCE_RUN });
  assert.match(text(between(html, 'data-testid="assess-since-pairing"', "</p>")), /Only 3 of the earlier run's 15 threats and 3 of this run's 5 could be paired\. The two runs word things differently, so the added and removed lists overstate what changed\./);
  // The ordinary comparison has no such note.
  const ok = run({ id: "tm-since-pairing-ok" });
  await seed(ok.id, FIXTURE_TM);
  await seed(ok.id, FIXTURE_TM_SINCE, FIXTURE_SINCE_RUN);
  assert.doesNotMatch(view(ok, { runs: [ok, run({ id: FIXTURE_SINCE_RUN, created_at: "2026-11-13T00:00:00Z" })], initialTab: "overview", initialSince: FIXTURE_SINCE_RUN }), /assess-since-pairing/);
});

test("the comparison is never hidden when it is long: 40 added and 40 removed threats all list", async () => {
  const r = run({ id: "tm-since-many" });
  const item = (i: number, p: string) => ({ id: `${p}-${i}`, title: `Threat ${p} ${i}`, element: { kind: "component", id: "api" }, category: "tampering", band: "low" as const, score: 4 });
  const since = { ...FIXTURE_SINCE, added: Array.from({ length: 40 }, (_, i) => item(i, "A")), removed: Array.from({ length: 40 }, (_, i) => item(i, "R")), changed: [] };
  await seed(r.id, FIXTURE_TM);
  await seed(r.id, { ...FIXTURE_TM, since }, FIXTURE_SINCE_RUN);
  const html = view(r, { runs: [r, run({ id: FIXTURE_SINCE_RUN })], initialTab: "overview", initialSince: FIXTURE_SINCE_RUN });
  assert.equal(count(between(html, 'data-testid="assess-since-added"', 'data-testid="assess-since-removed"'), /data-threat-id=/g), 40);
  assert.equal(count(html.slice(html.indexOf('data-testid="assess-since-removed"')), /data-threat-id="R-/g), 40);
});

test("a comparison the server refuses shows its words and leaves the model on screen", async () => {
  const r = run({ id: "tm-since-refused" });
  await seed(r.id, FIXTURE_TM);
  const p = assessModelPath(r.id, "gone");
  await seedError(r.id, new ApiError(409, p, JSON.stringify({ code: "no_model", error: "the run has not written the model yet" })), "gone");
  const html = view(r, { runs: [r, run({ id: "gone" })], initialTab: "overview", initialSince: "gone" });
  assert.match(html, /data-testid="assess-since-error"/);
  assert.match(text(html), /The run has not written assessment\.json yet\./);
  assert.match(html, /data-testid="assess-overview"/);
  assert.doesNotMatch(html, /data-testid="assess-since"/);
});

// ---- Threats ----

const THREAT_ORDER = ["T-1", "T-3", "T-2", "T-5", "T-4"];

function rowIds(html: string): string[] {
  return [...html.matchAll(/data-testid="assess-threat" data-threat-id="([^"]*)"/g)].map((m) => m[1]);
}

test("Threats: every threat is a row, highest band first, with its band, mitigation words and located fixes", async () => {
  const html = render(<ThreatTable doc={TM} vocab={FIXTURE_VOCAB} />);
  assert.deepEqual(rowIds(html), THREAT_ORDER);
  assert.match(html, /data-testid="assess-threats-count"[^>]*>Showing 5 of 5 threats</);
  assert.doesNotMatch(html, /Clear filters/);
  // The band with its score, as Observer computed it.
  for (const want of ["critical 20", "high 15", "medium 12", "medium 9", "low 6"]) assert.match(text(html), new RegExp(want), want);
  // The three mitigation words, plus the two states of no credit and no reference.
  const t = text(html);
  for (const w of ["Found near the cited line", "Location exists, nothing matched", "Claimed, not found", "Not checked", "No reference cited"]) assert.match(t, new RegExp(w), w);
  // Categories by the vocabulary's names; the AI framework's category as its id, its framework by a short name.
  assert.match(t, /Tampering/);
  assert.match(t, /Information disclosure/);
  assert.match(t, /Linkability/);
  assert.match(t, /LLM01/);
  assert.match(t, /STRIDE/);
  assert.match(t, /OWASP LLM/);
  assert.doesNotMatch(t, /owasp_llm/);
  // Elements by the model's names, statuses in words.
  assert.match(t, /Ledger API to Ledger database/);
  assert.match(t, /Ledger API/);
  assert.match(t, /Accepted by design/);
  assert.match(t, /Partly mitigated/);
  // Fixes located: T-1 has one located of one, T-2's one is missing, T-4 lists none.
  const row = (id: string) => text(between(html, `data-threat-id="${id}"`, "</tr>"));
  assert.match(row("T-1"), /1 of 1/);
  assert.match(row("T-2"), /0 of 1/);
  assert.match(row("T-4"), /none listed/);
  // The row says how many references stand behind its mitigation word.
  assert.match(row("T-1"), /Found near the cited line \(1 of 1 reference\)/);
  assert.match(row("T-4"), /Claimed, not found \(1 of 1 reference\)/);
  assert.doesNotMatch(row("T-3"), /\(\d+ of \d+ reference/, "a threat that cites nothing says no count");
});

test("Threats: a mitigation word that is the best of several references says how many, and the filter says what it reads", () => {
  const t1 = TM.threats![0];
  const five: ModelThreat = {
    ...t1,
    id: "T-9",
    existing: [{ text: "five cited controls", refs: ["found", "claimed_not_found", "claimed_not_found", "claimed_not_found", "exists"].map((state) => ({ path: "src/a.ts", line: 1, needle: "x", state: state as "found" })) }],
  };
  const html = render(<ThreatTable doc={{ ...TM, threats: [five] }} vocab={FIXTURE_VOCAB} />);
  assert.match(text(between(html, 'data-threat-id="T-9"', "</tr>")), /Found near the cited line \(1 of 5 references\)/);
  const t = text(html);
  assert.match(t, /A threat's mitigation word is the best state among its references, and the filter reads the same word: Found near the cited line means at least one reference was found\./);
  assert.match(html, /aria-label="Filter by mitigation state"/);
  assert.match(t, /Best reference state/);
});

test("Threats: the filters are labelled and the sort headers are buttons that say which way they are sorted", () => {
  const html = render(<ThreatTable doc={TM} vocab={FIXTURE_VOCAB} />);
  for (const name of ["Filter by framework", "Filter by element", "Filter by status", "Filter by band", "Filter by mitigation state", "Search threats"]) {
    assert.match(html, new RegExp(`aria-label="${name}"`), name);
  }
  // The default sort is the band, highest first; the others are unsorted and offer to sort.
  for (const name of ["Sort by id", "Sort by title", "Sort by element", "Sort by status"]) assert.match(html, new RegExp(`<button[^>]*aria-label="${name}"`), name);
  assert.match(html, /<button[^>]*aria-label="Sort by band, sorted descending"/);
  assert.equal(count(html, /aria-label="Sort by [a-z]+, sorted/g), 1);
  // Each filter lists only what occurs, with counts.
  const framework = between(html, 'aria-label="Filter by framework"', "</select>");
  assert.match(framework, /STRIDE \(3\)/);
  assert.match(framework, /LINDDUN \(1\)/);
  assert.match(framework, /OWASP LLM \(1\)/);
  assert.doesNotMatch(framework, /owasp_agentic|OWASP agentic/);
  // The option reads by its short name, whatever value it carries.
  assert.doesNotMatch(text(framework), /owasp_llm/);
  const band = between(html, 'aria-label="Filter by band"', "</select>");
  assert.match(band, /critical \(1\)/);
  assert.doesNotMatch(band, /<option[^>]*>low \(0\)/);
  const mitigation = between(html, 'aria-label="Filter by mitigation state"', "</select>");
  assert.match(mitigation, /Found near the cited line \(1\)/);
  assert.match(mitigation, /No reference cited \(1\)/);
  assert.doesNotMatch(mitigation, /Cited place not found/);
});

test("Threats: a filter narrows the list, the count line says so, Clear filters brings it back", () => {
  const narrowed = render(<ThreatTable doc={TM} vocab={FIXTURE_VOCAB} initialFilter={{ band: "critical" }} />);
  assert.deepEqual(rowIds(narrowed), ["T-1"]);
  assert.match(narrowed, /data-testid="assess-threats-count"[^>]*>Showing 1 of 5 threats</);
  assert.match(narrowed, />Clear filters</);
  const none = render(<ThreatTable doc={TM} vocab={FIXTURE_VOCAB} initialFilter={{ q: "no such text anywhere" }} />);
  assert.deepEqual(rowIds(none), []);
  assert.match(none, /Showing 0 of 5 threats/);
  assert.match(text(none), /No threat matches these filters/);
  assert.match(none, />Clear filters</);
  // The search reads the id, the title, the element and the description.
  assert.deepEqual(rowIds(render(<ThreatTable doc={TM} vocab={FIXTURE_VOCAB} initialFilter={{ q: "union" }} />)), []);
  assert.deepEqual(rowIds(render(<ThreatTable doc={TM} vocab={FIXTURE_VOCAB} initialFilter={{ q: "closes the query" }} />)), []);
  assert.deepEqual(rowIds(render(<ThreatTable doc={TM} vocab={FIXTURE_VOCAB} initialFilter={{ q: "joining the request text" }} />)), ["T-1"]);
  assert.deepEqual(rowIds(render(<ThreatTable doc={TM} vocab={FIXTURE_VOCAB} initialFilter={{ mitigation: "claimed_not_found" }} />)), ["T-4"]);
  assert.deepEqual(rowIds(render(<ThreatTable doc={TM} vocab={FIXTURE_VOCAB} initialSort={{ key: "id", dir: "asc" }} />)), ["T-1", "T-2", "T-3", "T-4", "T-5"]);
  assert.match(render(<ThreatTable doc={TM} vocab={FIXTURE_VOCAB} initialSort={{ key: "title", dir: "asc" }} />), /<button[^>]*aria-label="Sort by title, sorted ascending"/);
});

test("Sorting: every sort button names its column, so a keyboard keeps its place when a sort restarts the table", () => {
  const threats = render(<ThreatTable doc={TM} vocab={FIXTURE_VOCAB} />);
  for (const key of ["id", "title", "band", "element", "status"]) assert.match(threats, new RegExp(`<button[^>]*data-sort-key="${key}"`), `threats ${key}`);
  // The status column is there when the statuses differ (when they are all the same it is said once instead: see the test below).
  const mixed = PT.findings!.map((f, i) => (i === 0 ? { ...f, status: "identified" } : f));
  const findings = render(<FindingList findings={mixed} vocab={FIXTURE_VOCAB} />);
  for (const key of ["id", "title", "band", "category", "status"]) assert.match(findings, new RegExp(`<button[^>]*data-sort-key="${key}"`), `findings ${key}`);
});

test("Findings: when every finding states the same status the column is left out and the status is said once, so the table fits the dialog (UX-15)", () => {
  const same = render(<FindingList findings={PT.findings} vocab={FIXTURE_VOCAB} />);
  assert.doesNotMatch(same, /data-sort-key="status"/);
  assert.equal(count(text(between(same, "<thead", "</thead>")), /Status/g), 0);
  assert.equal(text(between(same, 'data-testid="assess-findings-status-note"', "</p>")).replace(/^[^>]*>/, "").trim(), `The agent states every finding as "Open". The status is the agent's own claim.`);
  // Nothing else is left out: the other seven columns, and every row.
  assert.equal(count(between(same, "<thead", "</thead>"), /<th /g), 7);
  assert.deepEqual([...findingIds(same)].sort(), PT.findings!.map((f) => f.id as string).sort());
  // Mixed statuses: the column and its sort stay, and the sentence is not printed.
  const mixed = PT.findings!.map((f, i) => (i === 0 ? { ...f, status: "identified" } : f));
  const html = render(<FindingList findings={mixed} vocab={FIXTURE_VOCAB} />);
  assert.match(html, /data-sort-key="status"/);
  assert.equal(count(between(html, "<thead", "</thead>"), /<th /g), 8);
  assert.doesNotMatch(html, /assess-findings-status-note/);
  // The table's least width is the sum of its columns, with and without the status column, and it is less than the room the dialog leaves.
  const widths = Object.values(FINDING_COLUMN_WIDTHS);
  const all = widths.reduce((n, w) => n + w, 0);
  assert.equal(all, 1160);
  assert.ok(all <= 1180, "the table with every column fits the 1200 px the 1240 px dialog leaves at its padding, less a scrollbar");
  assert.ok(html.includes(`min-width:${all}px`), "the table with every column is as wide as its columns");
  assert.ok(same.includes(`min-width:${all - FINDING_COLUMN_WIDTHS.status}px`), "without the status column it is as wide as the rest");
});

test("Threats: the Fixes located words sit in a positioned cell, so the screen-reader span cannot stretch the dialog's body sideways", () => {
  const html = render(<ThreatTable doc={TM} vocab={FIXTURE_VOCAB} />);
  // An absolutely positioned screen-reader span is placed against its nearest positioned ancestor. The table's own scroller is not one,
  // so without a positioned cell the span sat outside the scroller and the dialog's body scrolled sideways at phone width (found by the e2e spec).
  assert.match(html, /<span class="relative tabular-nums text-fg-2"><span class="sr-only">Missing mitigations that name a place in the code that exists: <\/span>/);
  assert.doesNotMatch(html, /<span class="tabular-nums text-fg-2"><span class="sr-only">/);
});

test("Threats: a row opens to the agent's text, the rating, the mitigations with their places, standards and the abuse case", () => {
  const html = render(<ThreatTable doc={TM} vocab={FIXTURE_VOCAB} initialExpanded="T-1" />);
  assert.equal(testIds(html, "assess-threat-detail"), 1);
  assert.match(between(html, 'data-threat-id="T-1"', "</tr>"), /aria-expanded="true"/);
  assert.match(between(html, 'data-threat-id="T-3"', "</tr>"), /aria-expanded="false"/);
  const d = text(between(html, 'data-testid="assess-threat-detail"', "</td>"));
  assert.match(d, /Description the agent says/);
  assert.match(d, /The search route builds its query by joining the request text/);
  assert.match(d, /Actor: Anonymous visitor/);
  assert.match(d, /Likelihood 4 x impact 5 the agent's judgement/);
  assert.match(d, /Observer reads the two ratings as critical 20/);
  assert.match(d, /Existing mitigations the agent says/);
  assert.match(d, /Found near the cited line \(1 of 1 reference\)/);
  assert.match(d, /Entries are written through a parameterised helper\./);
  assert.match(d, /src\/api\/db\.ts:30-34 Found near the cited line at line 31/);
  assert.match(d, /The agent quoted db\.query\(\$1, \[id\]\)/);
  assert.match(d, /That shows the text is there; it does not show the control works\./);
  assert.match(d, /Missing mitigations the agent says/);
  assert.match(d, /A place in the code that exists is cited by 1 of 1 missing mitigation\./);
  assert.match(d, /control: parameterised queries/);
  assert.match(d, /effort: small/);
  assert.match(d, /src\/api\/search\.ts:22 Location exists, nothing matched/);
  for (const std of ["CWE-89", "V5.3.4"]) assert.match(d, new RegExp(std), std);
  assert.match(d, /Abuse case the agent says/);
  assert.match(d, /Anonymous visitor: Read every account's entries\./);
  const steps = between(html, "<ol", "</ol>");
  assert.equal(count(steps, /<li/g), 2);
  assert.match(text(steps), /Send a search term that closes the quote\./);
});

/** detailText is the text of one threat's opened detail. */
function detailText(id: string, doc: ThreatModelDoc = TM): string {
  const html = render(<ThreatTable doc={doc} vocab={FIXTURE_VOCAB} initialExpanded={id} />);
  return text(between(html, 'data-testid="assess-threat-detail"', "</td>"));
}

test("Threats: a missing place reads File or line not found, a quoted text not in the lines reads Claimed, not found", () => {
  const t2 = detailText("T-2");
  assert.match(t2, /src\/api\/missing\.ts:3 File or line not found/);
  assert.match(t2, /effort: medium/);
  const t4 = detailText("T-4");
  assert.match(t4, /src\/api\/export\.ts:51 Claimed, not found/);
  assert.match(t4, /The agent lists no missing mitigation\./);
  const t3 = detailText("T-3");
  assert.match(t3, /The agent lists no existing mitigation\./);
  assert.match(t3, /src\/api\/db\.ts:6 Found near the cited line at line 6/);
});

test("Threats: one row is open at a time, under its own row", () => {
  const html = render(<ThreatTable doc={TM} vocab={FIXTURE_VOCAB} initialExpanded="T-3" />);
  assert.equal(testIds(html, "assess-threat-detail"), 1);
  assert.match(between(html, 'data-threat-id="T-3"', "</tr>"), /aria-expanded="true"/);
  assert.equal(count(html, /aria-expanded="true"/g), 1);
  assert.equal(count(html, /aria-expanded="false"/g), 4);
  // The open row's detail follows its own row, before the next row.
  const at = (s: string) => html.indexOf(s);
  assert.ok(at('data-testid="assess-threat-detail"') > at('data-threat-id="T-3"'));
  assert.ok(at('data-testid="assess-threat-detail"') < at('data-threat-id="T-2"'));
  // The expander names the detail it opens.
  assert.match(html, /aria-controls="([^"]+-detail)"/);
  const id = html.match(/aria-controls="([^"]+-detail)"/)![1];
  assert.match(html, new RegExp(`id="${id}"`));
});

test("Threats: a threat model with no threats says so and is not a clearance", () => {
  const html = render(<ThreatTable doc={{ ...TM, threats: [] }} vocab={FIXTURE_VOCAB} />);
  assert.match(text(html), /The model lists no threats/);
  assert.match(text(html), /That is not a finding that none exists/);
  assert.equal(testIds(html, "assess-threat"), 0);
});

test("Threats: when the agent wrote threats the check refused, the list says what happened and never that none was recorded", async () => {
  // Refused all: the view names the counts and sends the reader to the issues.
  const none = render(<ThreatTable doc={{ ...TM, threats: [] }} vocab={FIXTURE_VOCAB} counts={{ read: 3, refused: 3, leftOut: 0, kept: 0 }} />);
  assert.match(text(none), /No threat is shown/);
  assert.match(text(none), /The agent wrote 3 threats; the check refused all 3, so none is shown here\. The reasons are under How checked\./);
  assert.doesNotMatch(text(none), /The model lists no threats|recorded no threat|none exists/);
  // Some kept: the table is there with every kept threat, and a line under the count says what was not listed.
  const r = run({ id: "tm-partial-threats" });
  await seed(r.id, FIXTURE_TM_PARTIAL);
  const v = view(r, { initialTab: "threats" });
  assert.equal(testIds(v, "assess-threat"), 5);
  assert.match(text(between(v, 'data-testid="assess-threats-unlisted"', "</p>")), /The agent wrote 6 threats; the check refused 1, so 1 is not listed here\./);
  assert.match(text(v), /Showing 5 of 5 threats/);
  // The same through the whole view when none is left.
  const all = run({ id: "tm-refused-all-threats" });
  await seed(all.id, FIXTURE_TM_REFUSED_ALL);
  const t = text(view(all, { initialTab: "threats" }));
  assert.match(t, /The agent wrote 3 threats; the check refused all 3/);
  assert.doesNotMatch(t, /The model lists no threats/);
  // A report that kept every threat has no such line.
  assert.doesNotMatch(render(<ThreatTable doc={TM} vocab={FIXTURE_VOCAB} counts={{ read: 5, refused: 0, leftOut: 0, kept: 5 }} />), /assess-threats-unlisted/);
});

function manyThreats(n: number): ThreatModelDoc {
  const bands = ["low", "medium", "high", "critical"] as const;
  const threats: ModelThreat[] = Array.from({ length: n }, (_, i) => ({
    id: `T-${i + 1}`,
    title: `Generated threat ${i + 1}`,
    framework: "stride",
    category: "tampering",
    element: { kind: "component", id: "api" },
    rating: { likelihood: (i % 5) + 1, impact: ((i * 3) % 5) + 1 },
    band: bands[i % 4],
    score: ((i % 5) + 1) * (((i * 3) % 5) + 1),
    status: "identified",
  }));
  return { ...TM, threats };
}

/** elements counts the opening tags of a piece of markup: what a browser would build as elements. */
function elements(html: string): number {
  return count(html, /<[a-zA-Z][^>]*>/g);
}

test("1,500 threats: the first render holds a batch of rows, not all of them, and still says how many there are", async () => {
  const doc = manyThreats(1500);
  const html = render(<ThreatTable doc={doc} vocab={FIXTURE_VOCAB} />);
  assert.equal(testIds(html, "assess-threat"), THREAT_BATCH);
  // The whole count is stated, in the count line and on the tab, and the way to the rest is a button.
  assert.match(html, /Showing 1500 of 1500 threats/);
  assert.match(text(html), /Show more \(1,425 remaining\)/);
  assert.match(html, /<button[^>]*>Show more \(1,425 remaining\)<\/button>/);
  // The first batch is the head of the whole list, in the order the whole list has.
  assert.deepEqual(rowIds(html).slice(0, 3), ["T-4", "T-24", "T-44"]);
  // The page holds a bounded number of elements however long the list is. Measured (this test run, element tags in the markup):
  // 1,751 for the first render of 1,500 threats (a batch of 75 rows and the filters), against 33,098 with every row drawn. The
  // bound is 3,000: room for the filters and a batch, and nowhere near the rows of the whole list.
  const first = elements(html);
  assert.ok(first <= 3000, `${first} elements in the first render`);
  const everyRow = elements(render(<ThreatTable doc={doc} vocab={FIXTURE_VOCAB} batchSize={100000} />));
  assert.ok(first * 8 < everyRow, `the first render (${first}) is under an eighth of every row drawn (${everyRow})`);
  // The tab carries the whole count too, and the view is no heavier.
  const r = run({ id: "tm-1500" });
  await seed(r.id, fixtureBigThreatModel(1500));
  const v = view(r, { initialTab: "threats" });
  assert.equal(testIds(v, "assess-threat"), THREAT_BATCH);
  assert.match(v, /aria-label="Threats"[^>]*>[^<]*(<[^>]*>)*[^<]*Threats(<[^>]*>)*[^<]*<span[^>]*>1500</);
  assert.match(text(v), /Showing 1500 of 1500 threats/);
  assert.ok(elements(v) <= 3500, `${elements(v)} elements in the whole threats tab (measured 1,976)`);
});

test("every threat is reachable: with the batch as large as the list all 1,500 rows are drawn, each once, in the sorted order", () => {
  const doc = manyThreats(1500);
  const all = render(<ThreatTable doc={doc} vocab={FIXTURE_VOCAB} batchSize={100000} />);
  assert.equal(testIds(all, "assess-threat"), 1500);
  assert.doesNotMatch(all, /Show more/);
  const ids = rowIds(all);
  assert.equal(new Set(ids).size, 1500);
  assert.ok(ids.includes("T-1") && ids.includes("T-1500"));
  // Sorting and filtering run over every threat before a batch is cut: the sort by id puts T-1500 last, and a filter finds a threat far past the first batch.
  const byId = rowIds(render(<ThreatTable doc={doc} vocab={FIXTURE_VOCAB} batchSize={100000} initialSort={{ key: "id", dir: "asc" }} />));
  assert.equal(byId[0], "T-1");
  assert.equal(byId[1499], "T-1500");
  const far = render(<ThreatTable doc={doc} vocab={FIXTURE_VOCAB} initialFilter={{ q: "generated threat 1499" }} />);
  assert.deepEqual(rowIds(far), ["T-1499"]);
  assert.match(far, /Showing 1 of 1500 threats/);
  // With the default batch and a sort by id descending, the first batch is the last threats of the list: the sort ran over all of them.
  const desc = rowIds(render(<ThreatTable doc={doc} vocab={FIXTURE_VOCAB} initialSort={{ key: "id", dir: "desc" }} />));
  assert.deepEqual(desc.slice(0, 2), ["T-1500", "T-1499"]);
  assert.equal(desc.length, THREAT_BATCH);
});

// ---- the matrix ----

test("the matrix: analysed, waived and empty cells, never by colour alone, and three totals", () => {
  const html = render(<ElementMatrix doc={TM} cov={FIXTURE_TM.record.result.report.tm} vocab={FIXTURE_VOCAB} />);
  assert.equal(count(html, /data-state="analysed"/g), 4);
  assert.equal(count(html, /data-state="waived"/g), 2);
  assert.equal(count(html, /data-state="empty"/g), 41);
  assert.equal(count(html, /data-testid="assess-matrix-cell"/g), 47);
  assert.match(text(between(html, 'data-testid="assess-matrix-totals"', "</p>")), /4 analysed, 2 waived with a reason, 41 with neither/);
  // Every cell has a label and a word.
  const cell = between(html, 'data-state="analysed"', "</div></td>");
  assert.match(cell, /aria-label="[^"]*, [^"]*: Analysed: T-\d"/);
  assert.match(html, /aria-label="Ledger database, Tampering: Not considered"/);
  assert.match(html, /aria-label="Audit log, Repudiation: Waived: The audit log is append-only and written by the API only."/);
  assert.match(text(html), /not considered/);
  assert.match(text(html), /waived/);
  // The analysed cell lists the threat ids it holds.
  assert.match(html, /aria-label="Ledger API to Ledger database, Tampering: Analysed: T-1"/);
  // A legend, the column names, the first column on its own.
  assert.match(html, /aria-label="How to read the matrix"/);
  assert.match(text(html), /blank: the category does not apply to this kind of element/);
  assert.match(html, /aria-label="Column names"/);
  assert.match(html, /<th[^>]*scope="row"/);
  // LINDDUN columns follow STRIDE's, under a group header of their own, with two-letter names that repeat none of STRIDE's.
  assert.match(text(between(html, 'aria-label="Column names"', "</ul>")), /Linkability/);
  const head = between(html, "<thead", "</thead>");
  assert.match(head, /<th[^>]*scope="colgroup"[^>]*colSpan="6"[^>]*>STRIDE<\/th>/);
  assert.match(head, /<th[^>]*scope="colgroup"[^>]*colSpan="7"[^>]*>LINDDUN<\/th>/);
  const letters = [...head.matchAll(/<span[^>]*aria-label="(?:STRIDE|LINDDUN), [^"]*"[^>]*>([^<]*)<\/span>/g)].map((m) => m[1]);
  assert.deepEqual(letters, ["S", "T", "R", "I", "D", "E", "Lk", "Id", "Nr", "Dt", "Di", "Ua", "Nc"]);
  assert.equal(new Set(letters).size, letters.length, "no two column headers read the same");
  assert.match(head, /aria-label="LINDDUN, Identifiability"/);
  // The element kind is in words, not as the raw value.
  assert.match(text(html), /Ledger API component/);
  assert.match(text(html), /Signed-in user to Web client flow/);
  assert.doesNotMatch(text(html), /entry_point/);
  // A blank cell is not a cell: 12 elements x 13 columns less the 47 cells drawn.
  assert.match(html, /does not apply to this kind of element<\/span>/);
});

test("the matrix names an entry point row by its kind in words", () => {
  const cov = {
    analysed: 0,
    waived: 0,
    empty: 1,
    rows: [{ kind: "entry_point", id: "e1", name: "Login", class: "data_flow", cells: [{ category: "spoofing", state: "empty" as const }] }],
  };
  const doc: ThreatModelDoc = { ...TM, system: { ...TM.system, entry_points: [{ id: "e1", component: "api", kind: "http_route", authn: "none" }] } };
  const t = text(render(<ElementMatrix doc={doc} cov={cov} vocab={FIXTURE_VOCAB} />));
  assert.match(t, /entry point/);
  assert.doesNotMatch(t, /entry_point/);
});

test("the matrix cells keep their words in the page's text colour and the tone on the glyph, so the words reach the contrast the design asks for", () => {
  const html = render(<ElementMatrix doc={TM} cov={FIXTURE_TM.record.result.report.tm} vocab={FIXTURE_VOCAB} />);
  const cells = [...html.matchAll(/data-testid="assess-matrix-cell"[^>]*class="([^"]*)"/g)].map((m) => m[1]);
  assert.equal(cells.length, 47);
  for (const c of cells) {
    assert.match(c, /\btext-fg-1\b/, c);
    assert.doesNotMatch(c, /\btext-(success|warn|danger)\b/, c);
  }
  // The word and the glyph name the state; the tone is on the glyph.
  assert.match(html, /<svg[^>]*class="[^"]*text-warn[^"]*"/);
  assert.match(html, /<svg[^>]*class="[^"]*text-success[^"]*"/);
});

test("the matrix lists every waiver with its reason as the agent's, and says what the AI frameworks leave out", () => {
  const html = render(<ElementMatrix doc={TM} cov={FIXTURE_TM.record.result.report.tm} vocab={FIXTURE_VOCAB} />);
  const w = text(between(html, 'data-testid="assess-waivers"', "</ul>"));
  assert.match(w, /Waived pairs \(2\) the agent says/);
  assert.match(w, /Anonymous visitor, Spoofing An anonymous visitor claims no identity, so there is nothing to spoof\./);
  assert.match(w, /Audit log, Repudiation The audit log is append-only and written by the API only\./);
  assert.match(text(between(html, 'data-testid="assess-matrix-ai"', "</p>")), /1 threat under OWASP Top 10 for LLM applications has no matrix cells\./);
});

test("the matrix with no elements, or no coverage, is an empty state and not a table", () => {
  assert.match(text(render(<ElementMatrix doc={TM} cov={undefined} vocab={FIXTURE_VOCAB} />)), /No elements to lay out/);
  const noRows = { ...FIXTURE_TM.record.result.report.tm!, rows: [] };
  const html = render(<ElementMatrix doc={TM} cov={noRows} vocab={FIXTURE_VOCAB} />);
  assert.match(text(html), /No elements to lay out/);
  assert.equal(testIds(html, "assess-matrix-cell"), 0);
});

// ---- flows ----

test("Flows: every flow is a row, the weak crossings are flagged in words, and the entry points are listed", () => {
  const html = render(<FlowTable doc={TM} mermaid={FIXTURE_TM.mermaid} />);
  assert.equal(testIds(html, "assess-flow"), 5);
  assert.equal(count(html, /data-weak="true"/g), 2);
  assert.equal(count(html, /data-weak="false"/g), 3);
  const anon = text(between(html, 'data-flow-id="f-anon-api"', "</tr>"));
  assert.match(anon, /Anonymous visitor Ledger API/);
  assert.match(anon, /Crosses a trust zone without authentication/);
  assert.match(anon, /Internet to Application/);
  const db = text(between(html, 'data-flow-id="f-api-db"', "</tr>"));
  assert.match(db, /Ledger API Ledger database Crosses a trust zone without encryption Application to Data Ledger entries postgres user and password no yes/);
  assert.match(db, /Crosses a trust zone without encryption/);
  const web = text(between(html, 'data-flow-id="f-web-api"', "</tr>"));
  assert.match(web, /Crosses a trust zone/);
  assert.doesNotMatch(web, /without/);
  assert.equal(testIds(html, "assess-entry-point"), 2);
  assert.match(text(between(html, 'data-testid="assess-entry-point"', "</tr>")), /Ledger API web route none internet src\/api\/login\.ts:8 Found near the cited line at line 8/);
});

test("Flows and System: a closed value is in words, never as the raw value", () => {
  const doc: ThreatModelDoc = {
    ...TM,
    system: {
      ...TM.system,
      flows: [{ id: "f1", from: "web", to: "api", authn: "api_key", encrypted: "unknown" }, { id: "f2", from: "api", to: "db", authn: "mtls", encrypted: "yes" }],
      entry_points: [
        { id: "e1", component: "api", kind: "http_route", authn: "api_key", exposure: "internal_network" },
        { id: "e2", component: "api", kind: "scheduled", authn: "mtls", exposure: "local_only" },
        { id: "e3", component: "api", kind: "rpc", authn: "unknown", exposure: "unknown" },
      ],
      assets: [{ id: "a1", name: "Tokens", sensitivity: "restricted" }],
      actors: [{ id: "u1", name: "The operator", kind: "third_party" }, { id: "u2", name: "A person", kind: "end_user" }],
    },
  };
  const flows = text(render(<FlowTable doc={doc} mermaid={FIXTURE_TM.mermaid} />));
  for (const raw of ["api_key", "mtls", "internal_network", "local_only", "http_route"]) assert.doesNotMatch(flows, new RegExp(raw), raw);
  assert.match(flows, /API key/);
  assert.match(flows, /client certificate/);
  assert.match(flows, /internal network/);
  assert.match(flows, /this machine only/);
  assert.match(flows, /scheduled job/);
  assert.match(flows, /remote call/);
  assert.match(flows, /not known/);
  const sys = text(render(<SystemView doc={doc} vocab={FIXTURE_VOCAB} />));
  assert.match(sys, /restricted/);
  assert.match(sys, /third party/);
  assert.match(sys, /end user/);
  assert.doesNotMatch(sys, /third_party|end_user/);
});

test("Flows: the Mermaid source is text in a block, with a copy button, a sentence on how to view it and no counts when nothing was left out", () => {
  const html = render(<FlowTable doc={TM} mermaid={FIXTURE_TM.mermaid} />);
  const block = between(html, 'data-testid="assess-mermaid-source"', "</pre>");
  const source = text(block).replace(/^[^>]*>\s?/, "");
  assert.match(source, /flowchart LR/);
  assert.match(source, /subgraph z1\["Internet"\]/);
  assert.match(source, /c2 -\.->\|"postgres, not encrypted"\| c3/);
  // The block is escaped text: React wrote the quotes and the arrows as entities.
  assert.match(block, /&quot;postgres, not encrypted&quot;/);
  assert.match(block, /-\.-&gt;/);
  assert.match(html, /<button[^>]*>[^<]*(<[^>]*>)*[^<]*Copy diagram source/);
  assert.match(text(html), /Paste this into any Mermaid viewer\. Observer does not render it or load anything to draw it\./);
  assert.doesNotMatch(html, /data-testid="assess-diagram-counts"/);
  // Nothing is drawn by the component: the only markup under the diagram block is the text block and the button.
  assert.doesNotMatch(between(html, 'data-testid="assess-diagram"', "</pre>"), /<canvas|<iframe|<object|<embed|<img/);
});

test("Flows: a diagram that left something out says how many and which setting caps it", () => {
  const mermaid = { ...FIXTURE_TM.mermaid!, nodes: 60, total_nodes: 75, omitted_nodes: 15, omitted_edges: 9, max_nodes: 60 };
  const html = render(<FlowTable doc={TM} mermaid={mermaid} />);
  assert.match(text(between(html, 'data-testid="assess-diagram-counts"', "</p>")), /60 of 75 nodes drawn, 9 flows not drawn: the cap is the diagram size setting \(60 nodes\)\./);
  assert.match(text(html), /Both limits are settings, "Most nodes the data-flow diagram source draws" and "Longest label in the data-flow diagram source"/);
  const none = render(<FlowTable doc={TM} />);
  assert.match(none, /data-testid="assess-diagram-none"/);
  assert.doesNotMatch(none, /assess-mermaid-source/);
});

test("Flows: shortened labels are counted and the full names are said to be in the tables", () => {
  const cut = render(<FlowTable doc={TM} mermaid={{ ...FIXTURE_TM.mermaid!, labels_cut: 3, label_chars: 40 }} />);
  const block = text(between(cut, 'data-testid="assess-diagram-counts"', "</div></div>"));
  assert.match(block, /3 labels were shortened to 40 characters; the full names are in the tables\./);
  assert.doesNotMatch(block, /nodes drawn/, "nothing was left out, only shortened");
  assert.match(block, /"Longest label in the data-flow diagram source"/);
  assert.match(text(render(<FlowTable doc={TM} mermaid={{ ...FIXTURE_TM.mermaid!, labels_cut: 1, label_chars: 20 }} />)), /1 label was shortened to 20 characters/);
  // Nothing cut and nothing left out: no line, and no pointer to settings.
  const none = render(<FlowTable doc={TM} mermaid={FIXTURE_TM.mermaid} />);
  assert.doesNotMatch(none, /assess-diagram-counts/);
  assert.doesNotMatch(text(none), /Longest label/);
  // Both at once: both lines.
  const both = text(render(<FlowTable doc={TM} mermaid={{ ...FIXTURE_TM.mermaid!, nodes: 60, total_nodes: 75, omitted_nodes: 15, omitted_edges: 9, labels_cut: 2 }} />));
  assert.match(both, /60 of 75 nodes drawn/);
  assert.match(both, /2 labels were shortened to 40 characters/);
});

test("Flows: a model with no flows says so, and the diagram still has its place", () => {
  const html = render(<FlowTable doc={{ ...TM, system: { ...TM.system, flows: [], entry_points: [] } }} mermaid={FIXTURE_TM.mermaid} />);
  assert.match(text(html), /The model records no flows/);
  assert.match(html, /data-testid="assess-entry-points-none"/);
  assert.match(html, /data-testid="assess-mermaid-source"/);
});

// ---- attack trees ----

test("Attack trees: a nested list with and/or and leaf markers, every node shown", () => {
  const html = render(<TreeList trees={TM.attack_trees} />);
  assert.equal(testIds(html, "assess-tree"), 1);
  assert.match(html, /<h4[^>]*>Read another user&#x27;s entries<\/h4>/);
  assert.equal(testIds(html, "assess-tree-node"), 6);
  // Children sit inside their parent's list.
  const n1 = between(html, 'data-node-id="n1"', 'data-node-id="n4"');
  assert.match(n1, /data-node-id="n2"/);
  assert.match(n1, /data-node-id="n3"/);
  assert.doesNotMatch(n1, /data-node-id="n5"/);
  const n4 = html.slice(html.indexOf('data-node-id="n4"'));
  for (const id of ["n5", "n6"]) assert.match(n4, new RegExp(`data-node-id="${id}"`), id);
  assert.equal(count(html, /data-leaf="true"/g), 4);
  assert.match(html, /<ul[^>]*>[^]*<ul/);
  const t = text(html);
  assert.match(t, /Inject into the search query or/);
  assert.match(t, /Steal a session token and/);
  assert.equal(count(t, / leaf/g), 4);
  // A branch can be folded, none is folded at first.
  assert.equal(count(html, /aria-expanded="true"/g), 2);
  assert.doesNotMatch(html, /aria-expanded="false"/);
});

test("Attack trees: none is an empty state that names the setting, and the tab keeps its count", async () => {
  const html = render(<TreeList trees={[]} />);
  assert.match(text(html), /The model has no attack trees/);
  assert.match(text(html), /Threat model abuse cases and attack trees/);
  const r = run({ id: "tm-no-trees" });
  await seed(r.id, { ...FIXTURE_TM, record: { ...FIXTURE_TM.record, result: { ...FIXTURE_TM.record.result, tm: { ...TM, attack_trees: [] } } } });
  const v = view(r, { initialTab: "trees" });
  assert.match(text(v), /The model has no attack trees/);
  assert.match(v, /aria-label="Attack trees"[^>]*>[^<]*(<[^>]*>)*[^<]*Attack trees(<[^>]*>)*[^<]*<span[^>]*>0</);
});

test("System: components, zones, actors and assets, with the places components cite", async () => {
  const r = run({ id: "tm-system" });
  await seed(r.id, FIXTURE_TM);
  const html = view(r, { initialTab: "system" });
  const t = text(html);
  assert.equal(testIds(html, "assess-component"), 5);
  assert.match(t, /Ledger API Service or process Application react|Ledger API/);
  assert.match(t, /Ledger database Data store Data postgres/);
  assert.match(t, /Trust zones \(3\)/);
  assert.match(t, /Anonymous visitor\s*: anonymous/);
  assert.match(t, /Ledger entries confidential financial Ledger database/);
  assert.match(t, /src\/api\/server\.ts:10-40 Found near the cited line at line 12/);
});

// ---- the limits and how this was checked ----

test("How this was checked: the check's sentences, the issues as sentences, and every limit of a threat model", async () => {
  const r = run({ id: "tm-checked" });
  await seed(r.id, FIXTURE_TM);
  const html = view(r, { initialTab: "checked" });
  assert.match(html, /data-testid="assess-limits"/);
  assert.match(html, /data-help-id="card\.code_security_assess_checked"/);
  const t = text(html);
  assert.match(t, /Observer checked the structure of the file, its closed word lists and the files the agent cited\./);
  assert.match(t, /Partly checked/);
  assert.match(t, /References: 2 found near the cited line/);
  assert.match(t, /Analysed means the model records a threat for the pair/);
  assert.equal(testIds(html, "assess-issue"), 2);
  // Each issue is a sentence; the check's row and code are under its details, not in the line.
  assert.match(t, /1 references name a text that is not in the cited lines; they earn no credit\./);
  assert.match(t, /9 element and category pairs have neither a threat nor a reason that none applies\./);
  assert.doesNotMatch(t, /V8|V11|ref_needle_not_found|coverage_empty_cells/);
  assert.equal(count(html, />Details</g), 2);
  assert.match(t, /Warnings \(2\)/);
  // l1 to l11 (the limits of both kinds, then the threat model's), none of the pen test's.
  const ids = [...html.matchAll(/data-limit-id="(l\d+)"/g)].map((m) => m[1]);
  assert.deepEqual(ids, Array.from({ length: 11 }, (_, i) => `l${i + 1}`));
  assert.deepEqual(ids, limitsFor("threatmodel.v1").map((l) => l.id));
  assert.match(t, /11 limits/);
  assert.match(t, /Found near the cited line does not mean a working control\./);
  // The disclosure is open at first.
  assert.match(html, /aria-expanded="true"[^>]*>[^<]*(<[^>]*>)*[^<]*11 limits/);
});

test("How this was checked, pen test: the limits of both kinds and the pen test's, and the run's git check line", async () => {
  const r = run({ id: "pt-checked", kind: "pentest_local", contract: "pentest.v1", audit: "no_change", audit_words: "No git change seen", ended_at: "2026-11-14T10:00:00Z", audit_at: "2026-11-14T10:00:30Z" });
  await seed(r.id, FIXTURE_PT);
  const html = view(r, { initialTab: "checked" });
  const ids = [...html.matchAll(/data-limit-id="(l\d+)"/g)].map((m) => m[1]);
  assert.deepEqual(ids, limitsFor("pentest.v1").map((l) => l.id));
  assert.deepEqual(ids, ["l1", "l2", "l3", "l4", "l5", "l6", "l7", "l12", "l13", "l14", "l15", "l16", "l17", "l18", "l19", "l20"]);
  assert.match(text(html), /The coverage matrix is the agent's own claim\./);
  assert.match(text(html), /Git check: No git change seen\./);
  assert.match(html, /data-testid="assess-checked-audit"/);
  // The text of every limit is on the page, in the plan's words.
  for (const l of limitsFor("pentest.v1")) assert.ok(text(html).includes(l.text.slice(0, 60)), l.id);
});

test("How this was checked: issues past the list's end are counted, and a refused file says why", () => {
  const rec = { ...FIXTURE_TM.record, result: { ...FIXTURE_TM.record.result, report: { ...FIXTURE_TM.record.result.report, issues_more: 3 } } };
  const html = render(<LimitsStrip record={rec} />);
  assert.match(text(between(html, 'data-testid="assess-issues-more"', "</p>")), /3 more issues are counted but not listed/);
  const invalid = { ...FIXTURE_TM.record, result: { report: { ...FIXTURE_TM.record.result.report, state: "invalid", fatal: "not_json", issues: [] } } };
  assert.match(text(render(<LimitsStrip record={invalid} />)), /The file was refused: it is not JSON\./);
  // Refused, left-out and warned issues group by severity, in that order.
  const mixed = {
    ...FIXTURE_TM.record,
    result: {
      ...FIXTURE_TM.record.result,
      report: {
        ...FIXTURE_TM.record.result.report,
        issues: [
          { row: "V9", code: "w", severity: "warn" as const, message: "warn one" },
          { row: "V3", code: "r", severity: "refused" as const, message: "refused one" },
          { row: "V5", code: "d", severity: "dropped" as const, message: "dropped one" },
        ],
      },
    },
  };
  const m = text(render(<LimitsStrip record={mixed} />));
  assert.ok(m.indexOf("Refused (1)") < m.indexOf("Left out (1)") && m.indexOf("Left out (1)") < m.indexOf("Warnings (1)"));
});

// ---- the pen test ----

const PT_RUN = { kind: "pentest_local", kind_title: "Penetration test (your own app, local)", contract: "pentest.v1" } as const;
const RT_RUN = { kind: "red_team_local", kind_title: "Red team (your own app, local)", contract: "pentest.v1" } as const;
const RETEST_RUN = { kind: "pentest_retest", kind_title: "Retest of earlier findings", contract: "retest.v1", retest_of: "00000000000000f4", retest_findings: ["F-1", "F-2", "F-3", "F-5", "F-6"] as string[] } as const;

test("Coverage: one row for each category, what the agent marked and what Observer reads, with the counts and the claim sentence", async () => {
  const r = run({ id: "pt-coverage", ...PT_RUN });
  await seed(r.id, FIXTURE_PT);
  const html = view(r, { initialTab: "coverage" });
  assert.equal(testIds(html, "assess-coverage-row"), 8);
  const eff = [...html.matchAll(/data-effective="([^"]*)"/g)].map((m) => m[1]);
  assert.deepEqual(eff, ["tested_claimed", "tested_claimed", "tested_claimed", "tested_claimed", "skipped", "tested_claimed", "not_applicable", "tool_unavailable"]);
  const t = text(html);
  assert.match(t, /This is the agent's claim\. Observer cannot see the agent's requests, so a category it marked tested reads as claimed until a request log backs it\./);
  // The counts are said once on the tab: the coverage line at the top, not a second sentence under the table.
  assert.doesNotMatch(html, /data-testid="assess-coverage-counts"/);
  assert.equal(count(t, /5 of 8 categories claimed/g), 1);
  assert.match(text(between(html, 'data-testid="assess-model-coverage-line"', "</p>")), /Covered by the agent: 5 of 8 categories claimed, 0 with a logged request, 1 skipped, 1 not applicable, 1 with a tool unavailable/);
  assert.match(t, /Tested \(claimed\)/);
  // What each word means is printed once for each word the table uses, above the table: not on every row, and not only in a hover.
  const legend = text(between(html, 'data-testid="assess-coverage-legend"', "</ul>"));
  assert.match(legend, /Tested \(claimed\) The agent says it tested this category; no request log backs it\./);
  assert.equal(testIds(html, "assess-coverage-detail"), 4, "four words are in use: claimed, skipped, not applicable, tool unavailable");
  assert.equal(count(t, /The agent says it tested this category; no request log backs it\./g), 1);
  assert.doesNotMatch(text(between(html, 'data-category="INFO"', "</tr>")), /The agent says it tested this category/);
  // A tested category has no reason to give, and does not read as a missing one.
  assert.doesNotMatch(t, /No reason given|The agent gave no reason/);
  assert.match(t, /No second account could be created in the box\./);
  assert.match(t, /The target serves no pages, only JSON\./);
  assert.match(t, /Probes the agent names: p3, p4/);
  assert.match(t, /Start command, as the agent wrote it: npm run dev \(from \.claude\/launch\.json\)\. It says the target started after 6 seconds\./);
  assert.doesNotMatch(html, /data-testid="assess-coverage-not-started"/);
  assert.match(html, /data-help-id="card\.code_security_assess_coverage"/);
  // The summary and the agent's own limits are the agent's.
  assert.match(t, /The agent says/);
  assert.match(t, /The agent started the development server and tested five of eight categories\./);
  assert.match(t, /Only one origin was tested\./);
});

test("Coverage: a sentence true of every row that carries a word is printed once, not on each of 12 rows", () => {
  const rows = Array.from({ length: 12 }, (_, i) => ({ category: `C${i}`, title: `Category ${i}`, agent: "tested", effective: "tested_logged" }));
  const pt = { started: true, rows, counts: { tested_logged: 12 } };
  const html = render(<CoverageMatrix pt={pt} vocab={FIXTURE_VOCAB} />);
  const t = text(html);
  assert.equal(count(t, /The log is a file the agent can write, so this is not a trace\./g), 1);
  assert.equal(testIds(html, "assess-coverage-detail"), 1);
  assert.equal(testIds(html, "assess-coverage-row"), 12);
  assert.equal(count(t, /None expected/g), 12, "each dash keeps a short word for a screen reader, not a sentence");
  assert.equal(count(t, /No reason is expected for this word/g), 0);
  // A table with no dash does not explain one.
  const withReason = render(
    <CoverageMatrix pt={{ started: true, rows: [{ category: "INFO", title: "Information gathering", agent: "skipped", effective: "skipped", reason: "No second account." }], counts: { skipped: 1 } }} vocab={FIXTURE_VOCAB} />,
  );
  assert.doesNotMatch(text(withReason), /A dash in the Reason column/);
});

test("Coverage: a target that did not start is said first, and every category reads as skipped", async () => {
  const r = run({ id: "pt-empty-cov", ...PT_RUN });
  await seed(r.id, FIXTURE_PT_EMPTY);
  const html = view(r, { initialTab: "coverage" });
  assert.match(html, /data-testid="assess-coverage-not-started"/);
  assert.match(text(html), /The agent says the target did not start/);
  assert.match(text(html), /Every category reads as skipped/);
  assert.equal(count(html, /data-effective="skipped_not_started"/g), 2);
  assert.match(text(html), /Skipped \(target not started\)/);
  assert.match(html, /data-testid="assess-model-reading"/);
  assert.match(text(html), /No weakness was reported; this is not proof that none exists\./);
  assert.match(text(between(html, 'data-testid="assess-model-coverage-line"', "</p>")), /0 of 2 categories claimed, 0 with a logged request, 2 skipped \(target not started\)/);
  assert.doesNotMatch(html, /data-testid="assess-coverage-counts"/);
  // Nothing was tested, so no row asks for a reason.
  assert.doesNotMatch(text(html), /No reason given|The agent gave no reason/);
});

test("Coverage: a category the agent gave no row for reads as such", () => {
  const pt = { started: true, rows: [{ category: "INFO", title: "Information gathering", effective: "missing" }], counts: { missing: 1 } };
  const html = render(<CoverageMatrix pt={pt} vocab={FIXTURE_VOCAB} />);
  assert.match(text(html), /No row from the agent/);
  assert.match(text(html), /no row/);
  // A category with no row has nothing to give a reason for: the cell is blank, not a missing reason.
  assert.doesNotMatch(text(html), /No reason given|The agent gave no reason/);
  assert.match(html, /<span class="sr-only">None expected<\/span>/);
  assert.match(text(html), /A dash in the Reason column means the word gives no reason to expect one\./);
  assert.match(text(render(<CoverageMatrix pt={undefined} />)), /No coverage rows/);
  // The counts sentence is the matrix's own, unless the page already carries the coverage line.
  assert.match(html, /data-testid="assess-coverage-counts"/);
  assert.doesNotMatch(render(<CoverageMatrix pt={pt} vocab={FIXTURE_VOCAB} showCounts={false} />), /data-testid="assess-coverage-counts"/);
});

test("Coverage: a skipped, not applicable or tool-unavailable category without a reason says the agent gave none", () => {
  const rows = ["skipped", "not_applicable", "tool_unavailable"].map((effective, i) => ({ category: ["INFO", "CONF", "ATHN"][i], title: `Row ${i}`, agent: effective, effective }));
  const html = render(<CoverageMatrix pt={{ started: true, rows, counts: { skipped: 1, not_applicable: 1, tool_unavailable: 1 } }} vocab={FIXTURE_VOCAB} />);
  assert.equal(count(text(html), /The agent gave no reason/g), 3);
  // A reason the agent wrote is its text, shown as text.
  const withReason = render(<CoverageMatrix pt={{ started: true, rows: [{ ...rows[0], reason: "No second account" }], counts: { skipped: 1 } }} vocab={FIXTURE_VOCAB} />);
  assert.match(text(withReason), /No second account/);
  assert.doesNotMatch(text(withReason), /The agent gave no reason/);
});

function findingIds(html: string): string[] {
  return [...html.matchAll(/data-testid="assess-finding" data-finding-id="([^"]*)"/g)].map((m) => m[1]);
}

test("Findings: every finding, the agent's basis beside Observer's evidence (No log), and a word about the places it cites", async () => {
  const r = run({ id: "pt-findings", ...PT_RUN });
  await seed(r.id, FIXTURE_PT);
  const html = view(r, { initialTab: "findings" });
  assert.equal(testIds(html, "assess-finding"), 3);
  // Highest band first.
  assert.deepEqual(findingIds(html), ["F-1", "F-2", "F-3"]);
  const t = text(html);
  // Each row says No log once; the evidence filter lists the same word with its count.
  assert.equal(count(text(html.slice(html.indexOf("<table"))), /No log/g), 3);
  assert.match(between(html, 'aria-label="Filter findings by evidence"', "</select>"), /No log \(3\)/);
  assert.doesNotMatch(between(html, 'aria-label="Filter findings by evidence"', "</select>"), /Helper log matches|Not started/);
  assert.equal(count(t, /The agent says: seen in a request/g), 2);
  assert.equal(count(t, /The agent says: read from code/g), 1);
  assert.match(t, /critical 20/);
  assert.match(t, /Input validation/);
  assert.match(t, /CWE-89/);
  assert.match(t, /Route: GET \/api\/search/);
  assert.match(t, /Open/);
  // The cited places read as one word with how many references stand behind it; a finding with none cited says so.
  const f1 = text(between(html, 'data-finding-id="F-1"', 'data-finding-id="F-2"'));
  assert.match(f1, /Found near the cited line \(1 of 1 reference\)/);
  assert.match(text(between(html, 'data-finding-id="F-2"', 'data-finding-id="F-3"')), /Location exists, nothing matched \(1 of 1 reference\)/);
  assert.match(text(html.slice(html.indexOf('data-finding-id="F-3"'))), /none cited/);
  // The evidence block, the places and the steps are not in the page until a row is opened.
  assert.equal(testIds(html, "assess-finding-evidence"), 0);
  assert.equal(testIds(html, "assess-finding-detail"), 0);
  assert.doesNotMatch(t, /Observer has no request log for this finding/);
  assert.match(html, /data-help-id="card\.code_security_assess_evidence"/);
  // Band counts over the list.
  const bands = text(between(html, 'data-testid="assess-model-bands"', "</div>"));
  for (const want of ["critical 1", "medium 1", "low 1", "high 0"]) assert.match(bands, new RegExp(want), want);
});

test("Findings: a row opens to the evidence, the places, the indicator, the steps, the impact and the fix", () => {
  const html = render(<FindingList findings={PT.findings} vocab={FIXTURE_VOCAB} initialExpanded="F-1" />);
  assert.equal(testIds(html, "assess-finding-detail"), 1);
  assert.match(between(html, 'data-finding-id="F-1"', "</tr>"), /aria-expanded="true"/);
  assert.equal(count(html, /aria-expanded="true"/g), 1);
  const d = text(between(html, 'data-testid="assess-finding-detail"', "</td>"));
  assert.match(d, /Where in the code src\/api\/search\.ts:22-26 Found near the cited line at line 22/);
  assert.match(d, /Basis The agent says: seen in a request Observer's evidence No log/);
  assert.match(d, /Observer has no request log for this finding\./);
  assert.equal(testIds(html, "assess-finding-evidence"), 1);
  assert.match(d, /Indicator the agent says/);
  assert.match(d, /Attack probe p3, control probe p4\. Probes cited: p3, p4\./);
  assert.match(d, /Reproduction the agent says/);
  assert.match(d, /Request a normal search term GET \/api\/search\?q=rent/);
  assert.match(d, /GET \/api\/search\?q=rent'--/);
  assert.match(d, /Impact the agent says A caller can read entries that are not theirs\./);
  assert.match(d, /Fix the agent says Use the parameterised helper in the search route\./);
  assert.match(d, /Rating, as the agent judged it: likelihood 4 x impact 5\./);
  assert.equal(count(between(html, "<ol", "</ol>"), /<li/g), 2);
  // A finding with no cited place says so once opened.
  const f3 = text(between(render(<FindingList findings={PT.findings} vocab={FIXTURE_VOCAB} initialExpanded="F-3" />), 'data-testid="assess-finding-detail"', "</td>"));
  assert.match(f3, /No place in the code is cited\./);
  assert.match(f3, /The agent gave no reproduction steps\./);
  // Collapsed rows keep the evidence word and omit the detail; FindingEvidence and FindingBody stand alone.
  const collapsed = render(<FindingList findings={PT.findings} vocab={FIXTURE_VOCAB} />);
  assert.equal(testIds(collapsed, "assess-finding-detail"), 0);
  assert.equal(count(collapsed, /aria-expanded="false"/g), 3);
  assert.match(text(render(<FindingEvidence finding={PT.findings![1]} />)), /The agent says: read from code Observer's evidence No log/);
  assert.match(text(render(<FindingBody f={PT.findings![0]} />)), /Reproduction the agent says/);
});

test("Findings: an opened row shows the CVSS vector and Observer's base score with the note, and only when there is a vector", () => {
  const V = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N";
  const withScore = { ...PT.findings![0], cvss: V, cvss_score: 9.3, cvss_band: "critical" as const };
  const d = between(render(<FindingList findings={[withScore]} vocab={FIXTURE_VOCAB} initialExpanded="F-1" />), 'data-testid="assess-finding-cvss"', "</div>");
  assert.ok(text(d).includes(`CVSS 4.0 base vector ${V} Base score 9.3 (critical), computed by Observer from the vector. Base score of the weakness as logged in an in-box copy, not a production risk.`), text(d));
  // The table's band is still likelihood times impact, whatever the vector scores.
  assert.match(text(between(render(<FindingList findings={[withScore]} vocab={FIXTURE_VOCAB} />), 'data-finding-id="F-1"', "</tr>")), /critical 20/);
  // A score of 0.0 keeps the vector and the number and says there is no band.
  const zero = { ...withScore, cvss_score: 0, cvss_band: undefined };
  assert.ok(text(between(render(<FindingList findings={[zero]} vocab={FIXTURE_VOCAB} initialExpanded="F-1" />), 'data-testid="assess-finding-cvss"', "</div>")).includes(`CVSS 4.0 base vector ${V} Base score 0.0 (no band), computed by Observer from the vector. Base score of the weakness as logged in an in-box copy, not a production risk.`));
  // No vector, no block; a collapsed row has none either.
  assert.equal(testIds(render(<FindingList findings={PT.findings} vocab={FIXTURE_VOCAB} initialExpanded="F-1" />), "assess-finding-cvss"), 0);
  assert.equal(testIds(render(<FindingList findings={[withScore]} vocab={FIXTURE_VOCAB} />), "assess-finding-cvss"), 0);
});

test("Findings: a CVSS line says once that it is a separate reading from the Band column, and a finding with no vector says nothing about it", () => {
  const V = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N";
  const withScore = { ...PT.findings![0], cvss: V, cvss_score: 9.3, cvss_band: "critical" as const };
  const open = render(<FindingList findings={[withScore]} vocab={FIXTURE_VOCAB} initialExpanded="F-1" />);
  assert.equal(text(open).split(CVSS_APART).length - 1, 1);
  assert.equal(testIds(open, "assess-finding-cvss-apart"), 1);
  // The sentence names the column it is apart from, so a "medium 9" beside a 9.3 reads as two measures.
  assert.match(CVSS_APART, /separate reading from the Band in the table/);
  assert.match(CVSS_APART, /likelihood times impact/);
  assert.equal(testIds(render(<FindingList findings={PT.findings} vocab={FIXTURE_VOCAB} initialExpanded="F-1" />), "assess-finding-cvss-apart"), 0);
});

test("Findings: the legend names the CVSS base score only on a run where some finding has one (N-16)", () => {
  const V = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N";
  const legend = (html: string) => text(between(html, 'data-testid="assess-findings-legend"', "</p>")).replace(/^[^>]*>\s*/, "");
  const bare = legend(render(<FindingList findings={PT.findings} vocab={FIXTURE_VOCAB} />));
  assert.equal(bare, "The text, the basis and the rating are what the agent wrote. The band, the evidence and the words about each cited place are Observer's.");
  assert.doesNotMatch(bare, /CVSS/);
  const scored = [{ ...PT.findings![0], cvss: V, cvss_score: 9.3, cvss_band: "critical" as const }, ...PT.findings!.slice(1)];
  const withScore = legend(render(<FindingList findings={scored} vocab={FIXTURE_VOCAB} />));
  assert.match(withScore, /The band, the CVSS base score, the evidence and the words about each cited place are Observer's\.$/);
  // A vector Observer could not score is no score: the legend does not name one.
  const unscored = [{ ...PT.findings![0], cvss: V }, ...PT.findings!.slice(1)];
  assert.doesNotMatch(legend(render(<FindingList findings={unscored} vocab={FIXTURE_VOCAB} />)), /CVSS/);
});

test("Findings: a finding whose CVSS vector was left out says so in its own row, and a finding that kept its vector or never had one does not (N-9)", () => {
  const V = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N";
  const kept = { ...PT.findings![0], cvss: V, cvss_score: 9.3, cvss_band: "critical" as const };
  const lost = PT.findings![1];
  const issue: ModelIssue = { row: "V5", code: "bad_cvss_dropped", severity: "dropped", path: "findings[1]", item: lost.id, message: "The CVSS vector of finding " + lost.id + " carries a threat metric, so it was left out." };
  const list = (initialExpanded: string, issues = [issue]) => render(<FindingList findings={[kept, lost]} vocab={FIXTURE_VOCAB} issues={issues} initialExpanded={initialExpanded} />);
  const open = list(lost.id);
  assert.equal(testIds(open, "assess-finding-cvss-left-out"), 1);
  const noteText = text(between(open, 'data-testid="assess-finding-cvss-left-out"', "</div>"));
  assert.ok(noteText.includes("CVSS 4.0 base vector " + CVSS_LEFT_OUT_NOTE), noteText);
  assert.equal(testIds(open, "assess-finding-cvss"), 0, "no vector and no score are shown for it");
  assert.equal(testIds(open, "assess-finding-cvss-apart"), 0);
  // The finding that kept its vector has the block and no note; a closed row has neither.
  const keptOpen = list(kept.id);
  assert.equal(testIds(keptOpen, "assess-finding-cvss-left-out"), 0);
  assert.equal(testIds(keptOpen, "assess-finding-cvss"), 1);
  assert.equal(testIds(list(lost.id, []), "assess-finding-cvss-left-out"), 0, "no issue, no note: a finding with no vector says nothing about CVSS");
  assert.equal(testIds(render(<FindingList findings={[kept, lost]} vocab={FIXTURE_VOCAB} issues={[issue]} />), "assess-finding-cvss-left-out"), 0);
  // An issue of another finding, or one with no item (a record kept before it was recorded), names nobody here.
  assert.equal(testIds(list(lost.id, [{ ...issue, item: "F-99" }]), "assess-finding-cvss-left-out"), 0);
  assert.equal(testIds(list(lost.id, [{ ...issue, item: undefined }]), "assess-finding-cvss-left-out"), 0);
  // The vector the agent wrote is never printed.
  assert.ok(!open.includes("CVSS:4.0/AV"));
});

test("Findings: the filters, the search, the sort and the count line", () => {
  const html = render(<FindingList findings={PT.findings} vocab={FIXTURE_VOCAB} />);
  for (const name of ["Filter findings by band", "Filter findings by category", "Filter findings by basis", "Search findings"]) assert.match(html, new RegExp(`aria-label="${name}"`), name);
  assert.match(html, /data-testid="assess-findings-count"[^>]*>Showing 3 of 3 findings</);
  assert.doesNotMatch(html, /Clear filters/);
  // Each filter lists only what occurs, with counts.
  assert.match(between(html, 'aria-label="Filter findings by band"', "</select>"), /critical \(1\)/);
  assert.doesNotMatch(between(html, 'aria-label="Filter findings by band"', "</select>"), /high/);
  assert.match(between(html, 'aria-label="Filter findings by category"', "</select>"), /Input validation \(1\)/);
  assert.match(between(html, 'aria-label="Filter findings by basis"', "</select>"), /seen in a request \(2\)/);
  // The default sort is the band, highest first, said in the button's name.
  assert.match(html, /<button[^>]*aria-label="Sort by band, sorted descending"/);
  // (These findings all state "open", so the status column is not shown and has no sort: the test of UX-15 covers it, and the sort by status is run in the lib tests.)
  for (const name of ["Sort by id", "Sort by title", "Sort by category"]) assert.match(html, new RegExp(`<button[^>]*aria-label="${name}"`), name);
  assert.doesNotMatch(html, /aria-label="Sort by status/);
  // A filter narrows the list and says how many of how many; Clear filters brings it back.
  const narrowed = render(<FindingList findings={PT.findings} vocab={FIXTURE_VOCAB} initialFilter={{ basis: "inferred" }} />);
  assert.deepEqual(findingIds(narrowed), ["F-2"]);
  assert.match(narrowed, /data-testid="assess-findings-count"[^>]*>Showing 1 of 3 findings</);
  assert.match(narrowed, />Clear filters</);
  assert.deepEqual(findingIds(render(<FindingList findings={PT.findings} vocab={FIXTURE_VOCAB} initialFilter={{ band: "low" }} />)), ["F-3"]);
  assert.deepEqual(findingIds(render(<FindingList findings={PT.findings} vocab={FIXTURE_VOCAB} initialFilter={{ category: "ATHN" }} />)), ["F-2"]);
  assert.deepEqual(findingIds(render(<FindingList findings={PT.findings} vocab={FIXTURE_VOCAB} initialFilter={{ q: "injectable" }} />)), ["F-1"]);
  assert.deepEqual(findingIds(render(<FindingList findings={PT.findings} vocab={FIXTURE_VOCAB} initialSort={{ key: "id", dir: "desc" }} />)), ["F-3", "F-2", "F-1"]);
  const none = render(<FindingList findings={PT.findings} vocab={FIXTURE_VOCAB} initialFilter={{ q: "no such text anywhere" }} />);
  assert.deepEqual(findingIds(none), []);
  assert.match(none, /Showing 0 of 3 findings/);
  assert.match(text(none), /No finding matches these filters/);
  assert.match(none, />Clear filters</);
});

test("Findings: the agent wrote findings the check refused, so the list says what happened and never that none was reported", async () => {
  const none = render(<FindingList findings={[]} vocab={FIXTURE_VOCAB} counts={{ read: 2, refused: 2, leftOut: 0, kept: 0 }} />);
  assert.match(text(none), /No finding is shown/);
  assert.match(text(none), /The agent wrote 2 findings; the check refused all 2, so none is shown here\. The reasons are under How checked\./);
  assert.doesNotMatch(text(none), /The agent reported no findings|has no weakness/);
  const r = run({ id: "pt-refused-all", ...PT_RUN });
  await seed(r.id, FIXTURE_PT_REFUSED_ALL);
  const html = view(r, { initialTab: "findings" });
  assert.match(text(html), /The agent wrote 2 findings; the check refused all 2/);
  assert.doesNotMatch(text(html), /The agent reported no findings/);
  const cov = view(r, { initialTab: "coverage" });
  assert.match(text(between(cov, 'data-testid="assess-model-reading"', 'data-testid="assess-model-coverage-line"')), /The agent wrote 2 findings, and none is shown here: the check refused 2\./);
  assert.match(text(cov), /Partly checked/);
  assert.match(text(cov), /2 items were refused/);
  // Some kept: the list is there, and a line under the count says what was not listed.
  const p = run({ id: "pt-partial-findings", ...PT_RUN });
  await seed(p.id, FIXTURE_PT_PARTIAL);
  const v = view(p, { initialTab: "findings" });
  assert.equal(testIds(v, "assess-finding"), 3);
  assert.match(text(between(v, 'data-testid="assess-findings-unlisted"', "</p>")), /The agent wrote 4 findings; the check refused 1, so 1 is not listed here\./);
  // An empty list the agent really left empty still says what it is not.
  const empty = render(<FindingList findings={[]} vocab={FIXTURE_VOCAB} counts={{ read: 0, refused: 0, leftOut: 0, kept: 0 }} />);
  assert.match(text(empty), /The agent reported no findings/);
  assert.match(text(empty), /It does not say the target has no weakness/);
});

test("1,200 findings: the first render holds a batch of rows, still says how many there are, and every finding is reachable", async () => {
  const many = fixtureBigPentest(1200).record.result.pt!.findings!;
  const html = render(<FindingList findings={many} vocab={FIXTURE_VOCAB} />);
  assert.equal(testIds(html, "assess-finding"), FINDING_BATCH);
  assert.match(html, /data-testid="assess-findings-count"[^>]*>Showing 1200 of 1200 findings</);
  assert.match(html, /<button[^>]*>Show more \(1,125 remaining\)<\/button>/);
  // Nothing is drawn beyond the batch, and the evidence block and the steps of a row are not drawn until it is opened.
  assert.equal(testIds(html, "assess-finding-evidence"), 0);
  // Measured: 1,979 elements for the first render of 1,200 findings, against 30,101 with every row drawn; the bound is 3,000.
  assert.ok(elements(html) <= 3000, `${elements(html)} elements in the first render`);
  assert.ok(elements(html) * 8 < elements(render(<FindingList findings={many} vocab={FIXTURE_VOCAB} batchSize={100000} />)), "the first render is under an eighth of every row drawn");
  // The whole list is reachable: with the batch as large as the list every finding is drawn once.
  const all = render(<FindingList findings={many} vocab={FIXTURE_VOCAB} batchSize={100000} />);
  assert.equal(testIds(all, "assess-finding"), 1200);
  assert.equal(new Set(findingIds(all)).size, 1200);
  assert.ok(findingIds(all).includes("F-1200") && findingIds(all).includes("F-1"));
  // A filter and a sort run over every finding before a batch is cut.
  assert.deepEqual(findingIds(render(<FindingList findings={many} vocab={FIXTURE_VOCAB} initialFilter={{ q: "generated finding 1199" }} />)), ["F-1199"]);
  assert.deepEqual(findingIds(render(<FindingList findings={many} vocab={FIXTURE_VOCAB} initialSort={{ key: "id", dir: "desc" }} />)).slice(0, 2), ["F-1200", "F-1199"]);
  // Through the whole view: the tab carries the whole count.
  const r = run({ id: "pt-1200", ...PT_RUN });
  await seed(r.id, fixtureBigPentest(1200));
  const v = view(r, { initialTab: "findings" });
  assert.equal(testIds(v, "assess-finding"), FINDING_BATCH);
  assert.match(v, /aria-label="Findings"[^>]*>[^<]*(<[^>]*>)*[^<]*Findings(<[^>]*>)*[^<]*<span[^>]*>1200</);
  assert.ok(elements(v) <= 3500, `${elements(v)} elements in the whole findings tab (measured 2,029)`);
  // An empty list is not a clearance.
  const none = render(<FindingList findings={[]} vocab={FIXTURE_VOCAB} />);
  assert.match(text(none), /The agent reported no findings/);
  assert.match(text(none), /It does not say the target has no weakness/);
  assert.equal(testIds(none, "assess-finding"), 0);
});

test("the empty pen test never reads as a clearance, on any tab", async () => {
  const r = run({ id: "pt-empty-words", ...PT_RUN });
  await seed(r.id, FIXTURE_PT_EMPTY);
  for (const tab of PT_TABS) {
    const t = text(view(r, { initialTab: tab }));
    assert.doesNotMatch(t, BANNED, `${tab}: ${t.match(BANNED)?.[0]}`);
  }
  const findings = text(view(r, { initialTab: "findings" }));
  assert.match(findings, /The agent reported no findings/);
  assert.match(text(view(r, { initialTab: "coverage" })), /not proof that none exists/);
});

test("no tab of any fixture uses a word or phrase that reads as a clearance (the shared list)", async () => {
  for (const [id, data, tabs, over] of [
    ["words-tm", FIXTURE_TM, TM_TABS, {}],
    ["words-pt", FIXTURE_PT, PT_TABS, PT_RUN],
  ] as const) {
    const r = run({ id, ...over });
    await seed(r.id, data);
    for (const tab of tabs) {
      const t = text(view(r, { initialTab: tab }));
      assert.doesNotMatch(t, BANNED, `${id} ${tab}: ${t.match(BANNED)?.[0]}`);
    }
  }
  // Every opened detail, the empty states, the refused-all and partial answers on every tab, and the lines above the tabs too.
  const all = [
    ...TM.threats!.map((t) => text(render(<ThreatTable doc={TM} vocab={FIXTURE_VOCAB} initialExpanded={t.id} />))),
    ...PT.findings!.map((f) => text(render(<FindingList findings={PT.findings} vocab={FIXTURE_VOCAB} initialExpanded={f.id} />))),
    text(render(<ThreatTable doc={{ ...TM, threats: [] }} vocab={FIXTURE_VOCAB} />)),
    text(render(<ThreatTable doc={{ ...TM, threats: [] }} vocab={FIXTURE_VOCAB} counts={{ read: 3, refused: 3, leftOut: 0, kept: 0 }} />)),
    text(render(<FindingList findings={[]} vocab={FIXTURE_VOCAB} counts={{ read: 2, refused: 2, leftOut: 0, kept: 0 }} />)),
    text(render(<FindingList findings={[]} vocab={FIXTURE_VOCAB} />)),
    text(render(<TreeList trees={[]} />)),
    text(render(<ElementMatrix doc={TM} cov={undefined} vocab={FIXTURE_VOCAB} />)),
    text(render(<ExportMenu data={FIXTURE_TM} run={run()} />)),
    text(render(<ExportMenu data={null} run={run()} />)),
  ];
  for (const t of all) assert.doesNotMatch(t, BANNED, String(t.match(BANNED)?.[0]));
  for (const [id, data, over, tabs] of [
    ["words-tm-partial", FIXTURE_TM_PARTIAL, {}, TM_TABS],
    ["words-tm-refused", FIXTURE_TM_REFUSED_ALL, {}, TM_TABS],
    ["words-pt-partial", FIXTURE_PT_PARTIAL, PT_RUN, PT_TABS],
    ["words-pt-refused", FIXTURE_PT_REFUSED_ALL, PT_RUN, PT_TABS],
    ["words-pt-empty", FIXTURE_PT_EMPTY, PT_RUN, PT_TABS],
    ["words-pt-evidence-fx", FIXTURE_PT_EVIDENCE, PT_RUN, PT_TABS],
    ["words-pt-not-started-fx", FIXTURE_PT_NOT_STARTED, PT_RUN, PT_TABS],
    // The red team's Exercise tab, a retest's own view and a pen test with retest labels on its findings (depth plan W7.2, W7.3).
    ["words-red-team-fx", FIXTURE_RED_TEAM, RT_RUN, ["exercise", ...PT_TABS]],
    ["words-red-team-agent-fx", FIXTURE_RED_TEAM_AGENT, RT_RUN, ["exercise", ...PT_TABS]],
    ["words-retest-fx", FIXTURE_RETEST, RETEST_RUN, ["results", "replayed", "checked"]],
    ["words-pt-retested-fx", FIXTURE_PT_RETESTED, PT_RUN, PT_TABS],
  ] as const) {
    const r = run({ id, ...over });
    await seed(r.id, data);
    for (const tab of tabs) {
      const t = text(view(r, { initialTab: tab }));
      assert.doesNotMatch(t, BANNED, `${id} ${tab}: ${t.match(BANNED)?.[0]}`);
    }
  }
  // The server's own refused-all sentences are held to the same list.
  for (const a of [FIXTURE_TM_REFUSED_ALL, FIXTURE_PT_REFUSED_ALL]) assert.doesNotMatch(`${a.reading} ${a.coverage_line}`, BANNED);
});

// ---- the agent's text is only ever text ----

/** The keys whose string values are text the agent wrote. */
const TEXT_KEYS = new Set([
  "title", "description", "text", "summary", "name", "label", "reason", "goal", "root", "needle", "control", "impact", "fix", "route", "request",
  "step", "path", "tool", "model", "prompt_version", "message", "notes", "source", "tech", "data_classes", "cwe", "capec", "asvs",
  "steps", "open_questions", "in_scope", "out_of_scope", "assumptions", "limits", "probes",
]);

function hostile<T>(v: T, key = ""): T {
  if (typeof v === "string") return (TEXT_KEYS.has(key) ? `${HOSTILE_SCRIPT}${HOSTILE_IMG}` : v) as T;
  if (Array.isArray(v)) return v.map((x) => hostile(x, key)) as T;
  if (v && typeof v === "object") return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, hostile(x, k)])) as T;
  return v;
}

function assertEscaped(html: string, where: string): void {
  assert.match(html, /&lt;script&gt;alert\(1\)&lt;\/script&gt;/, `${where}: the script text is shown as text`);
  assert.doesNotMatch(html, /<script/i, `${where}: no live script`);
  assert.doesNotMatch(html, /<img[\s>]/i, `${where}: no live image`);
  assert.doesNotMatch(html, /onerror=1>/, `${where}: no live handler`);
  assert.match(html, /&quot;&gt;&lt;img src=x onerror=1&gt;/, `${where}: the image text is shown as text`);
}

test("hostile agent text in every field of a threat model is shown escaped, on every tab", async () => {
  const tm = hostile(TM);
  const data: AssessModelResponse = {
    ...FIXTURE_TM,
    record: { ...FIXTURE_TM.record, result: { ...FIXTURE_TM.record.result, tm } },
    mermaid: { ...FIXTURE_TM.mermaid!, source: `flowchart LR\n  a["${HOSTILE_SCRIPT}${HOSTILE_IMG}"]` },
    reading: HOSTILE_SCRIPT,
  };
  const r = run({ id: "tm-hostile" });
  await seed(r.id, data);
  for (const tab of TM_TABS) {
    // A tab is judged on its own markup: the agent's text is in all of them but the last.
    const html = view(r, { initialTab: tab });
    assert.doesNotMatch(html, /<script/i, tab);
    assert.doesNotMatch(html, /<img[\s>]/i, tab);
    if (tab !== "checked" && tab !== "matrix") assertEscaped(html, tab);
  }
  for (const t of tm.threats!) assertEscaped(render(<ThreatTable doc={tm} vocab={FIXTURE_VOCAB} initialExpanded={t.id} />), `threat detail ${t.id}`);
  assertEscaped(render(<ElementMatrix doc={tm} cov={FIXTURE_TM.record.result.report.tm} vocab={FIXTURE_VOCAB} />), "matrix waivers");
  assertEscaped(render(<FlowTable doc={tm} mermaid={data.mermaid} />), "flows");
  assertEscaped(render(<TreeList trees={tm.attack_trees} />), "trees");
  // The Mermaid text itself, in the block, is entity-escaped text.
  assert.match(between(view(r, { initialTab: "flows" }), 'data-testid="assess-mermaid-source"', "</pre>"), /&lt;script&gt;/);
});

test("hostile agent text in every field of a pen test is shown escaped, on every tab", async () => {
  const pt = hostile(PT);
  const data: AssessModelResponse = { ...FIXTURE_PT, record: { ...FIXTURE_PT.record, result: { ...FIXTURE_PT.record.result, pt } }, reading: HOSTILE_SCRIPT };
  const r = run({ id: "pt-hostile", ...PT_RUN });
  await seed(r.id, data);
  for (const tab of ["coverage", "findings"] as const) assertEscaped(view(r, { initialTab: tab }), tab);
  for (const f of pt.findings!) assertEscaped(render(<FindingList findings={pt.findings} vocab={FIXTURE_VOCAB} initialExpanded={f.id} />), `finding detail ${f.id}`);
  assertEscaped(render(<CoverageMatrix pt={{ started: true, rows: [{ category: "INFO", title: HOSTILE_SCRIPT + HOSTILE_IMG, effective: "skipped", reason: HOSTILE_SCRIPT + HOSTILE_IMG }], counts: { skipped: 1 } }} />), "coverage");
});

// ---- export ----

test("export: the diagram source and the checked model as JSON, both from the answer already in memory", () => {
  const tmItems = exportItems(FIXTURE_TM);
  assert.deepEqual(tmItems.map((i) => i.id), ["diagram", "model"]);
  assert.deepEqual(tmItems.map((i) => i.label), ["Copy diagram source", "Copy checked model"]);
  assert.equal(tmItems[0].text(), FIXTURE_TM.mermaid!.source);
  const json = tmItems[1].text();
  assert.deepEqual(JSON.parse(json), TM);
  assert.match(json, /^\{\n {2}"schema"/);
  assert.match(tmItems[1].description, /recognised secrets hidden while hiding is on\. It is not the agent's file as written\./);
  // A pen test has no diagram.
  assert.deepEqual(exportItems(FIXTURE_PT).map((i) => i.id), ["model"]);
  assert.deepEqual(JSON.parse(exportItems(FIXTURE_PT)[0].text()), PT);
  // No model, nothing to export.
  assert.deepEqual(exportItems({ ...FIXTURE_TM, mermaid: undefined, record: { ...FIXTURE_TM.record, result: { report: FIXTURE_TM.record.result.report } } }), []);
});

test("the copies are plain buttons in the footer, one for the diagram and one for the model, with the note that the model is the display copy", () => {
  const html = render(<ExportMenu data={FIXTURE_TM} run={run()} />);
  assert.match(html, /<button[^>]*data-testid="assess-export-diagram"[^>]*>[^<]*(<[^>]*>)*[^<]*Copy diagram source/);
  assert.match(html, /<button[^>]*data-testid="assess-export-model"[^>]*>[^<]*(<[^>]*>)*[^<]*Copy checked model/);
  // Nothing opens: no menu, no menu item, no popup, and no download glyph on a copy.
  assert.doesNotMatch(html, /role="menu|role="menuitem|aria-haspopup|aria-expanded/);
  assert.doesNotMatch(html, /lucide-download/);
  assert.doesNotMatch(html, /<button[^>]*disabled/);
  assert.match(text(html), /The copy is the checked model as Observer shows it, with recognised secrets hidden while hiding is on\. It is not the agent's file as written\./);
  // A pen test has the one button.
  const pt = render(<ExportMenu data={FIXTURE_PT} run={run()} />);
  assert.doesNotMatch(pt, /assess-export-diagram/);
  assert.match(pt, /assess-export-model/);
  // With no model the button is off and says why.
  const bare = render(<ExportMenu data={null} run={run()} />);
  assert.match(bare, /<button[^>]*disabled=""[^>]*data-testid="assess-export-model"|<button[^>]*data-testid="assess-export-model"[^>]*disabled=""/);
  assert.doesNotMatch(bare, /assess-export-note/);
});

test("on a phone the export buttons and their notes sit behind one disclosure button; on a wide window they do not", () => {
  const wide = render(<ExportMenu data={FIXTURE_TM} run={run()} narrow={false} />);
  assert.doesNotMatch(wide, /assess-export-toggle|aria-expanded/);
  assert.equal(count(wide, /data-testid="assess-export-(diagram|model|download-md|download-json)"/g), 4);
  assert.equal(testIds(wide, "assess-export-note"), 1);
  assert.equal(testIds(wide, "assess-export-download-note"), 1);

  // Collapsed: the footer holds the one button, no copy or download button and no note.
  const closed = render(<ExportMenu data={FIXTURE_TM} run={run()} narrow />);
  assert.match(closed, /<button[^>]*aria-expanded="false"[^>]*data-testid="assess-export-toggle"|<button[^>]*data-testid="assess-export-toggle"[^>]*aria-expanded="false"/);
  assert.match(text(closed), /^\s*Copy and download\s*$/);
  assert.doesNotMatch(closed, /assess-export-(diagram|model|download-md|download-json|note|download-note|body)/);

  // Open: the same buttons and the two notes, controlled by the toggle.
  const open = render(<ExportMenu data={FIXTURE_TM} run={run()} narrow expanded />);
  assert.match(open, /aria-expanded="true"/);
  const controls = /aria-controls="([^"]+)"/.exec(open)?.[1];
  assert.ok(controls && open.includes(`id="${controls}"`), "the toggle names the block it opens");
  assert.equal(count(open, /data-testid="assess-export-(diagram|model|download-md|download-json)"/g), 4);
  assert.equal(testIds(open, "assess-export-note"), 1);
  assert.equal(testIds(open, "assess-export-download-note"), 1);
  // A disclosure is not a menu.
  assert.doesNotMatch(open, /role="menu|role="menuitem|aria-haspopup/);
  // With no model the disclosure still opens onto the disabled buttons and says why.
  assert.match(render(<ExportMenu data={null} run={run()} narrow expanded />), /assess-export-model/);
});

test("the model view carries the two copy buttons and Close in its footer, in the dialog's own tab order", async () => {
  const r = run({ id: "tm-footer" });
  await seed(r.id, FIXTURE_TM);
  const html = view(r);
  assert.match(html, /<footer[^>]*>[\s\S]*Copy diagram source[\s\S]*Copy checked model[\s\S]*Close[\s\S]*<\/footer>/);
  // Both buttons are inside the dialog (the footer is a child of the dialog card), none is portalled out of it.
  const dialog = between(html, 'role="dialog"', "</footer>");
  assert.match(dialog, /data-testid="assess-export-diagram"/);
  assert.match(dialog, /data-testid="assess-export-model"/);
});

// ---- the runs list, the card and the report dialog ----

const validated = () => run({ id: "row-validated" });

test("a run row offers Open model once its model is checked, beside Read report, and not before", () => {
  const rows = [
    validated(),
    run({ id: "row-unchecked", validation: undefined, state: "model_ready" }),
    run({ id: "row-sarif", contract: undefined }),
    run({ id: "row-held", phase: "held" }),
    run({ id: "row-cancelled", phase: "cancelled" }),
    run({ id: "row-refused", validation: { state: "invalid", at: "t", fatal: "not_json", refs: { found: 0, exists: 0, claimed_not_found: 0, missing: 0, invalid: 0, unchecked: 0 } } }),
    // Delete evidence takes the checked copy and leaves the validation on the row: nothing to open.
    run({ id: "row-deleted", has_model: false }),
    run({ id: "row-no-key", has_model: undefined }),
  ];
  const html = render(<AssessRunsList runs={rows} importAvailable onReport={() => {}} onModel={() => {}} />);
  const opens = [...html.matchAll(/<li[^>]*data-testid="assess-run"[\s\S]*?<\/li>/g)].map((m) => /data-testid="assess-open-model"/.test(m[0]));
  assert.deepEqual(opens, [true, false, false, false, false, true, false, false]);
  assert.equal(count(html, />Open model</g), 2);
  // Beside Read report: the report button comes first.
  const first = html.match(/<li[^>]*data-testid="assess-run"[\s\S]*?<\/li>/)![0];
  assert.ok(first.indexOf("Read report") < first.indexOf("Open model"));
  // No handler, no button: the list keeps working for a caller that has none.
  assert.doesNotMatch(render(<AssessRunsList runs={rows} importAvailable onReport={() => {}} />), /assess-open-model/);
});

const project = { project_root_hash: "h1", name: "ledger", root_path: "/home/u/ledger", active: true } as SecurityProject;

test("the card lists Open model on a validated run, and mounts the model view only when it is opened", async () => {
  const list: AssessList = {
    kinds: [{ id: "threat_model", title: "Threat model", summary: "s", mode: "Read-only", launchable: true, sandbox: "optional", target: "none", files: [], note: "n" }],
    runs: [validated()],
    import_available: true,
    launch: true,
  };
  await apiCache.fetch(ASSESS_LIST_PATH, async () => list);
  const html = render(<SecAssessCard projects={[project]} />);
  assert.match(html, /data-testid="assess-open-model"/);
  assert.doesNotMatch(html, /data-testid="assess-model"/);
});

test("the report dialog's note: hiding on with a count, on with none, and off when the header is absent", () => {
  assert.equal(reportRedactionNote(null), redactionNote({ on: false, hidden: 0 }));
  assert.equal(reportRedactionNote("3"), redactionNote({ on: true, hidden: 3 }));
  assert.match(reportRedactionNote("3"), /In this answer, 3 places were hidden\./);
  assert.equal(reportRedactionNote("0"), redactionNote({ on: true, hidden: 0 }));
  assert.equal(reportRedactionNote("garbage"), redactionNote({ on: true, hidden: 0 }));
  assert.match(reportRedactionNote(null), /Hiding recognised secrets is turned off/);
  const src = readFileSync(path.join(secassessDir(), "AssessReportDialog.tsx"), "utf8");
  assert.match(src, /data-testid="assess-report-redaction"/);
  assert.match(src, /X-Observer-Redacted/);
});

// ---- the request helper's evidence (depth plan W5b) ----

const EV_PT = FIXTURE_PT_EVIDENCE.record.result.pt as PentestDoc;
const EV_REPORT = FIXTURE_PT_EVIDENCE.record.result.report;
const EV_PROBES = probeIndex(FIXTURE_PT_EVIDENCE.probes);

/** rowText is the text of the table row of one finding. */
function rowText(html: string, id: string): string {
  const rows = html.split("<tr").filter((r) => r.includes(`data-testid="assess-finding" data-finding-id="${id}"`));
  assert.equal(rows.length, 1, `one row for ${id}`);
  return text(rows[0]);
}

test("Evidence: each row says Helper log matches, No log or Not started, and only a match says the log is a file the agent can write", async () => {
  const r = run({ id: "pt-evidence", ...PT_RUN });
  await seed(r.id, FIXTURE_PT_EVIDENCE);
  const html = view(r, { initialTab: "findings" });
  const table = html.slice(html.indexOf("<table"));
  assert.match(rowText(table, "F-1"), /Helper log matches The log is a file the agent can write\./);
  for (const id of ["F-2", "F-3", "F-4"]) {
    assert.match(rowText(table, id), /No log/, id);
    assert.doesNotMatch(rowText(table, id), /Helper log matches|The log is a file the agent can write/, id);
  }
  const ns = run({ id: "pt-not-started", ...PT_RUN });
  await seed(ns.id, FIXTURE_PT_NOT_STARTED);
  const nsHtml = view(ns, { initialTab: "findings" });
  assert.match(rowText(nsHtml.slice(nsHtml.indexOf("<table")), "F-1"), /Not started/);
  assert.doesNotMatch(text(nsHtml.slice(nsHtml.indexOf("<table"))), /Helper log matches|No log/);
  assert.match(between(nsHtml, 'aria-label="Filter findings by evidence"', "</select>"), /Not started \(1\)/);
});

test("Evidence: the line above the findings says what the request log held, and the reasons sit behind a disclosure", async () => {
  const r = run({ id: "pt-evidence-summary", ...PT_RUN });
  await seed(r.id, FIXTURE_PT_EVIDENCE);
  const html = view(r, { initialTab: "findings" });
  assert.equal(
    text(between(html, 'data-testid="assess-evidence-summary"', "</p>")).replace(/^[^R]*/, "").trim(),
    "Request log: 4 requests sent, 1 refused; 1 finding with a matching log, 3 without, helper unchanged",
  );
  const reasons = text(between(html, 'data-testid="assess-evidence-reasons"', "</details>"));
  assert.match(reasons, /Why findings are not logged/);
  assert.match(reasons, /1 finding: The finding cites no logged request/);
  assert.match(reasons, /1 finding: A request the finding cites is not in the helper log\./);
  assert.match(reasons, /1 finding: A request the finding cites was refused by the helper, so it never reached the target\./);
  // A copy stored before the helper has no line, and no disclosure.
  const old = render(<FindingList findings={PT.findings} vocab={FIXTURE_VOCAB} />);
  assert.doesNotMatch(old, /assess-evidence-summary|assess-evidence-reasons/);
  // A run whose helper was off says so in the line, and its findings carry the run's reason.
  const off: EvidenceReport = { mode: "off", helper: "not_checked", log: "not_read", records: 0, sent: 0, refused: 0, requests: 0, logged: 0, unlogged: 3, not_started: 0 };
  const offHtml = render(<FindingList findings={PT.findings} vocab={FIXTURE_VOCAB} evidence={off} initialExpanded="F-1" />);
  assert.match(text(offHtml), /Request log: the request helper was off for this run; 0 findings with a matching log, 3 without/);
  assert.match(text(between(offHtml, 'data-testid="assess-finding-detail"', "</td>")), /The request helper was off for this run \(a setting\), so no request was logged\./);
});

test("Evidence: a matching finding opens to its attack and control requests, as text, with the excerpt caption", () => {
  const html = render(<FindingList findings={EV_PT.findings} vocab={FIXTURE_VOCAB} probes={FIXTURE_PT_EVIDENCE.probes} probeLog={FIXTURE_PT_EVIDENCE.probe_log} evidence={EV_REPORT.evidence} initialExpanded="F-1" />);
  const d = between(html, 'data-testid="assess-finding-detail"', "</td>");
  const t = text(d);
  assert.match(t, /Observer's evidence Helper log matches/);
  assert.match(t, /returned the indicated response for the attack request and not for its control request\./);
  assert.match(t, /This is not proof of impact, and it says nothing about production\. The log is a file the agent can write, so this is not proof\./);
  assert.match(t, /Requests in the helper log/);
  assert.equal(testIds(d, "assess-probe"), 2);
  // The attack comes first, then the control.
  assert.ok(d.indexOf('data-probe-id="p3"') < d.indexOf('data-probe-id="p4"'));
  const p3 = text(between(d, 'data-probe-id="p3"', 'data-probe-id="p4"'));
  assert.match(p3, /Attack request p3 200/);
  assert.match(p3, /GET \/api\/search\?q=rent'--/);
  assert.match(p3, /Response 200, 63 ms, 65536 bytes of body\./);
  assert.ok(p3.includes(`Category: Input validation · Account: user-a · Logged ${fmtDateTime("2026-11-14T10:31:44Z")}`));
  assert.ok(!p3.includes("2026-11-14T10:31:44Z"), "the probe time is formatted, never a raw ISO string");
  assert.match(p3, /The agent's note: term that closes the quote/);
  assert.match(p3, /first 1 KiB of the response, secrets Observer recognised hidden \(65536 bytes read; the response was longer than the helper reads\)/);
  assert.match(p3, /Authorization: \[REDACTED\]/);
  assert.match(p3, /"total":412/);
  const p4 = text(between(d, 'data-probe-id="p4"', "Reproduction"));
  assert.match(p4, /Control request p4 200/);
  assert.match(p4, /"total":3/);
  // The indicator carries the agent's condition in a plain sentence, as the agent's.
  assert.match(text(between(d, 'data-testid="assess-finding-condition"', "</p>")), /The agent says the attack response meets this condition and the control response does not: status 200; the body contains "412"; the header X-Request-Id is absent\./);
  // The excerpt is a <pre> of text: no tag of the response is a tag of the page.
  assert.match(d, /<pre[^>]*aria-label="Response excerpt of p3"[^>]*>/);
});

test("Evidence: a condition the agent wrote inside a JSON string reads as the text it means, with no backslash before its quotes (N-14)", () => {
  const bs = String.fromCharCode(92);
  const f = { ...EV_PT.findings![0], indicator: { control: "p4", attack: "p3", when: { body_contains: [`${bs}"role${bs}": ${bs}"admin${bs}"`] } } };
  const d = render(<FindingBody f={f} />);
  const sentence = text(between(d, 'data-testid="assess-finding-condition"', "</p>"));
  assert.ok(sentence.includes('the body contains ""role": "admin""'), sentence);
  assert.ok(!sentence.includes(bs), `no backslash in what a person reads: ${sentence}`);
});

test("Evidence: the structured reproduction shows the request line, its headers and its body as text", () => {
  const html = render(<FindingBody f={EV_PT.findings![0]} />);
  const d = between(html, "<ol", "</ol>");
  assert.equal(count(d, /<li/g), 3);
  const t = text(d);
  assert.match(t, /Request a normal search term GET \/api\/search\?q=rent Accept: application\/json/);
  assert.match(t, /Request a term that closes the quote GET \/api\/search\?q=rent'-- Accept: application\/json/);
  assert.match(t, /Send a body to the export route POST \/api\/export \{"format":"csv"\}/);
  assert.match(d, /<code[^>]*>POST \/api\/export<\/code>/);
  assert.match(d, /<pre[^>]*aria-label="Body of step 3"[^>]*>\{&quot;format&quot;:&quot;csv&quot;\}<\/pre>/);
  assert.match(d, /<pre[^>]*aria-label="Headers of step 1"[^>]*>Accept: application\/json<\/pre>/);
  // A request an older stored copy holds as one string reads as that text.
  const old = { ...EV_PT.findings![0], reproduction: [{ step: "Old step", request: "GET /old?q=1" as never }] };
  const oldHtml = text(between(render(<FindingBody f={old} />), "<ol", "</ol>"));
  assert.match(oldHtml, /Old step GET \/old\?q=1/);
  // A step with no request, an empty method and a missing path read without a throw.
  const odd = { ...old, reproduction: [{ step: "No request" }, { step: "Half", request: { method: "", path: "/x" } }] };
  const oddText = text(between(render(<FindingBody f={odd} />), "<ol", "</ol>"));
  assert.match(oddText, /No request/);
  assert.match(oddText, /Half \/x/);
});

test("Evidence: a finding that cites a request not in the log says so, and one in a log the answer holds only part of says that instead", () => {
  const f3 = EV_PT.findings![2];
  const html = render(<FindingBody f={f3} probes={EV_PROBES} probeLog={FIXTURE_PT_EVIDENCE.probe_log} />);
  assert.match(text(between(html, 'data-testid="assess-probe-missing"', "</div>")), /Cited request p9 : not in the log\./);
  assert.match(text(html), /Observer's evidence No log A request the finding cites is not in the helper log\./);
  const part = render(<FindingBody f={f3} probes={EV_PROBES} probeLog={{ records: 400, shown: 4, truncated: true }} />);
  assert.match(text(between(part, 'data-testid="assess-probe-missing"', "</div>")), /Cited request p9 : not shown in this answer\./);
  assert.match(text(part), /This answer holds 4 of the log's 400 requests, so a request that is not shown here may still be in the log\./);
  // A refused request is its own card, with the refusal in words.
  const f4 = render(<FindingBody f={EV_PT.findings![3]} probes={EV_PROBES} probeLog={FIXTURE_PT_EVIDENCE.probe_log} />);
  const p5 = text(between(f4, 'data-probe-id="p5"', "Reproduction"));
  assert.match(p5, /Attack request p5 Refused/);
  assert.match(p5, /Refused by the helper\. The address was not the target's host and port, and the helper sends to the target only\. The request never reached the target\./);
  assert.match(text(f4), /A request the finding cites was refused by the helper, so it never reached the target\./);
});

test("Evidence: a run with no log, or no answer member for it, draws no request cards and no line of not in the log", () => {
  // The older fixture cites p3 and p4 and has no probes member: nothing to look up, nothing to repeat.
  const html = render(<FindingBody f={PT.findings![0]} />);
  assert.doesNotMatch(html, /assess-finding-probes|assess-probe-missing|assess-probe"/);
  assert.match(text(html), /Observer's evidence No log Observer has no request log for this finding\./);
  // A finding that names no request has nothing to show even with a log.
  const none = render(<FindingBody f={EV_PT.findings![1]} probes={EV_PROBES} probeLog={FIXTURE_PT_EVIDENCE.probe_log} />);
  assert.doesNotMatch(none, /assess-finding-probes/);
  assert.match(text(none), /The finding cites no logged request \(a request made another way, or read from code, is not logged\)\./);
});

test("Evidence: the card of a request is text only, whatever the log holds", () => {
  const hostile = {
    ...FIXTURE_PT_EVIDENCE.probes![1],
    id: "p3",
    path: `/x?q=${HOSTILE_SCRIPT}`,
    note: HOSTILE_IMG,
    account: HOSTILE_SCRIPT,
    body_excerpt: `${HOSTILE_SCRIPT}\n${HOSTILE_IMG}`,
    req_body_excerpt: HOSTILE_SCRIPT,
    req_headers: [{ n: "X-A", v: HOSTILE_IMG }],
    resp_headers: [{ n: "Set-Cookie", v: HOSTILE_SCRIPT }],
    error: "",
    redirect_to: HOSTILE_SCRIPT,
  };
  const html = render(<ProbeCard p={hostile} role="attack" vocab={FIXTURE_VOCAB} />);
  assert.doesNotMatch(html, /<script|<img/);
  assert.match(html, /&lt;script&gt;alert\(1\)&lt;\/script&gt;/);
  assert.match(text(html), new RegExp(HOSTILE_SCRIPT.replace(/[()/]/g, "\\$&")));
  // An error the helper recorded is text too, and a request with no response says so.
  const err = text(render(<ProbeCard p={{ ...hostile, status: 0, error: HOSTILE_SCRIPT, body_excerpt: "" }} role="control" />));
  assert.match(err, /Control request p3 No response/);
  assert.match(err, /The request was sent and got no response\. The helper recorded: <script>alert\(1\)<\/script>/);
  // The log marking it another role than the finding's says so.
  assert.match(text(render(<ProbeCard p={{ ...hostile, role: "control" }} role="attack" />)), /The log marks it as a control request/);
  assert.doesNotMatch(text(render(<ProbeCard p={{ ...hostile, role: "attack" }} role="attack" />)), /The log marks it as/);
});

test("Evidence: the evidence filter narrows the list by Observer's state, and Clear filters brings it back", () => {
  const f = EV_PT.findings;
  const logged = render(<FindingList findings={f} vocab={FIXTURE_VOCAB} initialFilter={{ evidence: "logged" }} />);
  assert.deepEqual(findingIds(logged), ["F-1"]);
  assert.match(logged, /data-testid="assess-findings-count"[^>]*>Showing 1 of 4 findings</);
  assert.match(logged, />Clear filters</);
  // The default sort is the band, highest first.
  assert.deepEqual(findingIds(render(<FindingList findings={f} vocab={FIXTURE_VOCAB} initialFilter={{ evidence: "unlogged" }} />)), ["F-2", "F-4", "F-3"]);
  assert.deepEqual(findingIds(render(<FindingList findings={f} vocab={FIXTURE_VOCAB} initialFilter={{ evidence: "not_started" }} />)), []);
  const picker = between(render(<FindingList findings={f} vocab={FIXTURE_VOCAB} />), 'aria-label="Filter findings by evidence"', "</select>");
  assert.match(picker, /Helper log matches \(1\)/);
  assert.match(picker, /No log \(3\)/);
  assert.doesNotMatch(picker, /Not started/);
});

test("Evidence: no word on the page reads as a clearance or a confirmation, in any state, on any tab", async () => {
  for (const [id, answer] of [["words-pt-evidence", FIXTURE_PT_EVIDENCE], ["words-pt-not-started", FIXTURE_PT_NOT_STARTED]] as const) {
    const r = run({ id, ...PT_RUN });
    await seed(r.id, answer);
    for (const tab of PT_TABS) {
      const t = text(view(r, { initialTab: tab }));
      assert.doesNotMatch(t, BANNED, `${id} ${tab}: ${t.match(BANNED)?.[0]}`);
      assert.doesNotMatch(t, /\b(observed|authentic|exploitable)\b/i, `${id} ${tab}`);
    }
    // Every finding opened, with its requests: the sentences around the log's text are Observer's.
    for (const f of answer.record.result.pt!.findings!) {
      const t = text(render(<FindingList findings={answer.record.result.pt!.findings} vocab={FIXTURE_VOCAB} probes={answer.probes} probeLog={answer.probe_log} evidence={answer.record.result.report.evidence} initialExpanded={f.id} />));
      assert.doesNotMatch(t, BANNED, `${id} ${f.id}: ${t.match(BANNED)?.[0]}`);
      assert.doesNotMatch(t, /\b(observed|authentic|exploitable)\b/i, `${id} ${f.id}`);
    }
  }
});

test("Evidence: nothing of the helper's evidence builds markup from a string, and the probe cards put the log's text in text nodes and pre blocks only", () => {
  const src = readFileSync(path.join(secassessDir(), "FindingEvidence.tsx"), "utf8");
  for (const b of ["dangerouslySetInnerHTML", "innerHTML", "outerHTML", "insertAdjacentHTML", "createElementNS", "<svg", "eval(", "href="]) assert.equal(src.includes(b), false, `FindingEvidence.tsx contains ${b}`);
  // The words of the states come from the lib's one table, not from a literal here.
  const code = src
    .split("\n")
    .filter((l) => !l.trim().startsWith("//"))
    .join("\n");
  assert.doesNotMatch(code, /"Helper log matches"|"No log"|"Not started"/);
});
