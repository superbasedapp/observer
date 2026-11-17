// Component tests of the model view's fix button, its dialog and the export
// buttons (docs/plans/security-assessments-depth-plan-2026-11-14.md wave W6b),
// rendered with react-dom/server under node's test runner
// (scripts/test-components.mjs, no DOM). A click cannot be simulated here; what
// a click builds is pinned in src/lib/secAssessFix.test.ts (the pure helpers
// each handler calls) and the clicks, the keyboard and the downloads are in the
// Playwright spec. These prove the components render what those build: the
// button only where a task can be built, the dialog's every state, the four
// footer buttons in tab order, and the download helper's path, name and refusals.

import { afterEach, test } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import type { ReactElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router-dom";
import { AssessFixButton, AssessFixContext } from "@/components/secassess/AssessFixButton";
import { AssessFixDialog } from "@/components/secassess/AssessFixDialog";
import { AssessModelView } from "@/components/secassess/AssessModelView";
import { ExportMenu, downloadExport, exportDownloadsAvailable } from "@/components/secassess/ExportMenu";
import { FindingBody } from "@/components/secassess/FindingEvidence";
import { ThreatDetail } from "@/components/secassess/ThreatTable";
import { ApiError } from "@/lib/api";
import { apiCache } from "@/lib/useApi";
import type { AssessRun } from "@/lib/secAssess";
import { clearanceRegExp, parseClearanceList } from "@/lib/secAssessBanned";
import {
  EXPORT_DOWNLOADS,
  EXPORT_DOWNLOAD_NONE,
  EXPORT_DOWNLOAD_NOTE,
  FIX_AFTER_END_WORDS,
  FIX_BUTTON_NOTE,
  FIX_NEXT_WORDS,
  assessFixPlanPath,
  type AssessFixPlan,
} from "@/lib/secAssessFix";
import { assessModelPath, type AssessModelResponse, type ModelRefState, type ModelThreat, type PTFinding, type ThreatModelDoc } from "@/lib/secAssessModel";
import { FIXTURE_PT, FIXTURE_TM, FIXTURE_VOCAB } from "@/lib/secAssessModelFixture";

const consoleError = console.error;
console.error = (...args: unknown[]) => {
  if (typeof args[0] === "string" && args[0].includes("useLayoutEffect does nothing on the server")) return;
  consoleError(...args);
};

// ---- helpers ----

const TM = FIXTURE_TM.record.result.tm as ThreatModelDoc;
const PT_FINDINGS = FIXTURE_PT.record.result.pt!.findings as PTFinding[];
const HOSTILE_SCRIPT = "<script>alert(1)</script>";
const HOSTILE_IMG = '"><img src=x onerror=1>';
const RUN_ID = "00000000000000b2";

function render(el: ReactElement): string {
  return renderToStaticMarkup(<MemoryRouter>{el}</MemoryRouter>);
}

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

function count(html: string, re: RegExp): number {
  return (html.match(re) ?? []).length;
}

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

const CLEARANCE = parseClearanceList(readFileSync(repoFile("internal/secassess/testdata/clearance_words.json"), "utf8"));
const BANNED = clearanceRegExp(CLEARANCE);

/** An ended threat model run, the shape the list sends. */
function run(over: Partial<AssessRun> = {}): AssessRun {
  return {
    id: RUN_ID,
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
    has_model: true,
    report_bytes: 10,
    ended_at: "2026-11-14T08:40:00Z",
    ...over,
  };
}

function plan(over: Partial<AssessFixPlan> = {}): AssessFixPlan {
  return {
    confirm_token: "tok",
    run: RUN_ID,
    item: "T-1",
    item_kind: "threat",
    band: "high",
    project: { name: "ledger", root_path: "/home/u/ledger", on_disk: true },
    prompt: [
      "You are fixing one threat in the project ledger.",
      "Read the code at each place below first and decide whether the weakness is real. If it is not, change nothing and say why.",
      "Add a regression test that fails before the fix and succeeds after it.",
      "Do not commit or push unless the developer asks you to.",
      "  src/api/search.ts:22-26 (found near the cited line)",
    ].join("\n"),
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

/** seedPlan puts a plan in the query cache where the dialog reads it. */
async function seedPlan(runId: string, item: string, data: AssessFixPlan): Promise<void> {
  await apiCache.fetch(assessFixPlanPath(runId, item), async () => data);
}

async function seedFailure(runId: string, item: string, status: number, body: unknown): Promise<void> {
  const raw = typeof body === "string" ? body : JSON.stringify(body);
  await apiCache.fetch(assessFixPlanPath(runId, item), async () => {
    throw new ApiError(status, assessFixPlanPath(runId, item), raw);
  });
}

function dialog(runId: string, item: string, kind: "threat" | "finding" = "threat"): string {
  return render(<AssessFixDialog open run={runId} item={item} itemKind={kind} onClose={() => {}} />);
}

function withFix(el: ReactElement, ctx = { runId: RUN_ID, enabled: true }): string {
  return render(<AssessFixContext.Provider value={ctx}>{el}</AssessFixContext.Provider>);
}

const threat = (id: string): ModelThreat => TM.threats!.find((t) => t.id === id)!;
const actors = new Map<string, string>();

// ---- the button ----

test("the button is offered for a ref that Observer located, in the state found or exists, and for nothing else", () => {
  const states: Array<[ModelRefState | undefined, boolean]> = [
    ["found", true],
    ["exists", true],
    ["claimed_not_found", false],
    ["missing", false],
    ["invalid", false],
    ["unchecked", false],
    [undefined, false],
  ];
  for (const [state, want] of states) {
    const html = withFix(<AssessFixButton itemId="T-9" itemKind="threat" refs={[{ path: "src/a.ts", state }]} />);
    assert.equal(/data-testid="assess-fix-open"/.test(html), want, String(state));
    assert.equal(html === "", !want, `${state}: renders nothing when it is not offered`);
  }
  // One located reference among the rest is enough; none cited at all is not.
  assert.match(withFix(<AssessFixButton itemId="T-9" itemKind="threat" refs={[{ path: "a", state: "missing" }, { path: "b", state: "exists" }]} />), /assess-fix-open/);
  assert.equal(withFix(<AssessFixButton itemId="T-9" itemKind="threat" refs={[]} />), "");
  assert.equal(withFix(<AssessFixButton itemId="T-9" itemKind="threat" refs={undefined} />), "");
  // A located state with no path names no place.
  assert.equal(withFix(<AssessFixButton itemId="T-9" itemKind="threat" refs={[{ path: "", state: "found" }]} />), "");
});

test("the button says what it does in plain words, names its item and its kind, and is a plain button", () => {
  const html = withFix(<AssessFixButton itemId="F-2" itemKind="finding" refs={[{ path: "src/a.ts", state: "exists" }]} />);
  assert.match(html, /<button[^>]*type="button"[^>]*data-testid="assess-fix-open"[^>]*>[\s\S]*Fix with an agent<\/button>/);
  assert.match(html, /data-testid="assess-fix"[^>]*data-item-id="F-2"[^>]*data-item-kind="finding"/);
  assert.ok(text(html).includes(FIX_BUTTON_NOTE));
  assert.doesNotMatch(html, /disabled/);
  // The same icon as the Findings tab's fix.
  assert.match(html, /lucide-wrench/);
  // The dialog is closed until the button is pressed: nothing of it is in the markup.
  assert.doesNotMatch(html, /role="dialog"/);
  assert.doesNotMatch(text(html), BANNED);
});

test("without a provider, or with one that offers nothing, no row has a fix button", () => {
  const located = [{ path: "src/a.ts", state: "found" as const }];
  assert.equal(render(<AssessFixButton itemId="T-1" itemKind="threat" refs={located} />), "");
  assert.equal(withFix(<AssessFixButton itemId="T-1" itemKind="threat" refs={located} />, { runId: RUN_ID, enabled: false }), "");
  assert.equal(withFix(<AssessFixButton itemId="T-1" itemKind="threat" refs={located} />, { runId: "", enabled: true }), "");
  assert.equal(withFix(<AssessFixButton itemId="" itemKind="threat" refs={located} />), "");
});

test("a hostile item id is text and an attribute value, never markup", () => {
  const html = withFix(<AssessFixButton itemId={HOSTILE_IMG} itemKind="threat" refs={[{ path: "a", state: "found" }]} />);
  assert.doesNotMatch(html, /<img/);
  assert.match(html, /data-item-id="&quot;&gt;&lt;img src=x onerror=1&gt;"/);
});

test("a threat offers the fix from its missing mitigations' references, never from an existing one", () => {
  const detail = (t: ModelThreat) => withFix(<ThreatDetail t={t} actors={actors} vocab={FIXTURE_VOCAB} detailId="d" />);
  // T-1 and T-3 name a place in a missing mitigation.
  assert.match(detail(threat("T-1")), /data-testid="assess-fix-open"/);
  assert.match(detail(threat("T-3")), /data-testid="assess-fix-open"/);
  // T-2 cites a place only in an existing mitigation; T-4 and T-5 cite no place to fix at all.
  for (const id of ["T-2", "T-4", "T-5"]) assert.doesNotMatch(detail(threat(id)), /assess-fix/, id);
  // Outside the model view's provider no threat has it.
  for (const t of TM.threats!) assert.doesNotMatch(render(<ThreatDetail t={t} actors={actors} vocab={FIXTURE_VOCAB} detailId="d" />), /assess-fix/, t.id);
  // The button names its threat.
  assert.match(detail(threat("T-1")), /data-item-id="T-1"[^>]*data-item-kind="threat"/);
  // An unlocated reference in a missing mitigation, beside a located one in another, still offers it once.
  const mixed: ModelThreat = { ...threat("T-4"), missing: [{ text: "x", refs: [{ path: "a", state: "missing" }] }, { text: "y", refs: [{ path: "b", state: "exists" }] }] };
  assert.equal(count(detail(mixed), /data-testid="assess-fix-open"/g), 1);
});

test("a finding offers the fix from the places it cites, found or exists, and not when it cites none", () => {
  const body = (f: PTFinding) => withFix(<FindingBody f={f} />);
  assert.match(body(PT_FINDINGS[0]), /data-testid="assess-fix-open"/);
  assert.match(body(PT_FINDINGS[0]), /data-item-id="F-1"[^>]*data-item-kind="finding"/);
  assert.match(body(PT_FINDINGS[1]), /data-testid="assess-fix-open"/);
  assert.doesNotMatch(body(PT_FINDINGS[2]), /assess-fix/);
  for (const f of PT_FINDINGS) assert.doesNotMatch(render(<FindingBody f={f} />), /assess-fix/, f.id);
});

// ---- the model view provides the run ----

function view(r: AssessRun, tab: "threats" | "findings" | "overview"): string {
  return render(<AssessModelView run={r} runs={[r]} onClose={() => {}} initialTab={tab} />);
}

async function seedModel(id: string, data: AssessModelResponse): Promise<void> {
  await apiCache.fetch(assessModelPath(id), async () => data);
}

test("a run that has not ended says why the fix is not offered, on the tabs that would hold the button, and an ended run says nothing", async () => {
  const ended = run({ id: "fix-view-ended" });
  const live = run({ id: "fix-view-live", ended_at: undefined });
  await seedModel(ended.id, FIXTURE_TM);
  await seedModel(live.id, FIXTURE_TM);
  assert.doesNotMatch(view(ended, "threats"), /assess-fix-after-end/);
  const html = view(live, "threats");
  assert.match(html, /data-testid="assess-fix-after-end"/);
  assert.ok(text(html).includes(FIX_AFTER_END_WORDS));
  assert.doesNotMatch(text(FIX_AFTER_END_WORDS), BANNED);
  // The overview has no button to hold, so it carries no line about one.
  assert.doesNotMatch(view(live, "overview"), /assess-fix-after-end/);
  // A pen test says the same on its findings tab.
  const pt = run({ id: "fix-view-pt-live", kind: "pentest_local", contract: "pentest.v1", ended_at: undefined });
  await seedModel(pt.id, FIXTURE_PT);
  assert.match(view(pt, "findings"), /assess-fix-after-end/);
});

// ---- the dialog ----

test("the dialog shows the project, the places in the model view's own words, the notes and the exact task, and says the agent edits the project", async () => {
  const p = plan({ notes: ["The agent's model file changed after this check. The task is built from the checked copy."] });
  await seedPlan(RUN_ID, "T-1", p);
  const html = dialog(RUN_ID, "T-1");
  assert.match(html, /role="dialog"/);
  assert.match(html, /data-help-id="card\.code_security_assess_fix"/);
  assert.match(html, /data-testid="assess-fix-plan"/);
  const t = text(html);
  assert.match(t, /Fix with an agent/);
  assert.match(t, /Threat T-1/);
  assert.ok(t.includes("Threat T-1 (band high). The task points the agent at 2 places in the project."));
  assert.match(t, /ledger/);
  assert.match(html, /\/home\/u\/ledger/);
  // The places, with the model view's own words for the two states.
  assert.match(html, /<code[^>]*>src\/api\/search\.ts:22-26<\/code>/);
  assert.match(html, /<code[^>]*>src\/api\/db\.ts<\/code>/);
  assert.equal(count(html, /data-place-state="/g), 2);
  assert.match(t, /Found near the cited line/);
  assert.match(t, /Location exists, nothing matched/);
  // Observer's notes ride beside the task, not in it.
  assert.match(html, /data-testid="assess-fix-notes"/);
  assert.ok(t.includes("The agent's model file changed after this check."));
  // The exact task, character for character, in the prompt block.
  assert.match(html, /data-testid="assess-fix-prompt"/);
  const pre = /<pre[^>]*>([\s\S]*?)<\/pre>/.exec(html);
  assert.ok(pre, "the task is in a pre block");
  assert.equal(text(pre![1]).trim(), text(p.prompt).trim());
  assert.ok(pre![1].includes("Add a regression test that fails before the fix and succeeds after it."));
  // What happens next, said before anything starts.
  assert.ok(t.includes(FIX_NEXT_WORDS));
  assert.match(t, /edits files in this project's live folder/);
  assert.match(t, /sandbox/);
  assert.match(t, /With no sandbox chosen the agent runs on this machine with your access/);
  assert.match(t, /Nothing here changes the model or any finding/);
  assert.doesNotMatch(t, BANNED);
  // The footer: Cancel, and Choose agent. With no terminal dock in this render the second is off, and its reason is text the button is described by (not a tooltip on a disabled button).
  assert.match(html, /<footer[\s\S]*data-testid="assess-fix-cancel"[\s\S]*data-testid="assess-fix-choose"[\s\S]*<\/footer>/);
  assert.match(html, /<button[^>]*disabled=""[^>]*data-testid="assess-fix-choose"|<button[^>]*data-testid="assess-fix-choose"[^>]*disabled=""/);
  assert.match(html, /<p[^>]*id="assess-fix-block"[^>]*>The terminal dock is not available on this page\.<\/p>/);
  assert.match(html, /<button[^>]*aria-describedby="assess-fix-block"[^>]*data-testid="assess-fix-choose"|<button[^>]*data-testid="assess-fix-choose"[^>]*aria-describedby="assess-fix-block"/);
});

test("a finding's dialog says finding, and a cited place beyond the listed twenty is counted, not dropped", async () => {
  const p = plan({ run: "fix-dlg-finding", item: "F-1", item_kind: "finding", band: "critical", places_omitted: 5 });
  await seedPlan("fix-dlg-finding", "F-1", p);
  const t = text(dialog("fix-dlg-finding", "F-1", "finding"));
  assert.match(t, /Finding F-1/);
  assert.ok(t.includes("Finding F-1 (band critical). The task points the agent at 2 places in the project. 5 more places that Observer located are not listed in the task."));
  assert.doesNotMatch(t, /Threat F-1/);
});

test("while the plan is read the dialog says so, and names the item by the kind it was opened with", () => {
  const html = dialog("fix-dlg-never-read", "F-7", "finding");
  assert.match(html, /role="status"[^>]*aria-label="Loading the task"/);
  assert.match(text(html), /Finding F-7/);
  assert.doesNotMatch(html, /data-testid="assess-fix-choose"/, "no Choose agent before there is a task");
  assert.doesNotMatch(html, /data-testid="assess-fix-error"/);
});

test("a project whose folder is not on this machine is said, and its Choose agent is off", async () => {
  const p = plan({ run: "fix-dlg-gone", project: { name: "ledger", root_path: "/gone/ledger", on_disk: false } });
  await seedPlan("fix-dlg-gone", "T-1", p);
  const html = dialog("fix-dlg-gone", "T-1");
  assert.match(text(html), /Not on this machine/);
  assert.match(text(html), /This project's folder is not on this machine, so an agent cannot be started on it from here\./);
  assert.match(html, /<button[^>]*disabled=""[^>]*data-testid="assess-fix-choose"|<button[^>]*data-testid="assess-fix-choose"[^>]*disabled=""/);
  // The body says it, so the footer does not say it a second time.
  assert.doesNotMatch(html, /id="assess-fix-block"/);
});

test("a project with no name is shown by its folder", async () => {
  await seedPlan("fix-dlg-noname", "T-1", plan({ run: "fix-dlg-noname", project: { name: "", root_path: "/x/proj", on_disk: true } }));
  assert.match(text(dialog("fix-dlg-noname", "T-1")), /\/x\/proj \/x\/proj/);
});

test("every refusal of the plan is said in words, with Retry only where reading again can help", async () => {
  const rows: Array<[string, number, unknown, RegExp, boolean]> = [
    ["fix-r-noloc", 409, { error: "this item cites no place that Observer found in the project, so there is nothing to point a fix at", code: "no_location" }, /nothing to point a fix at\. Nothing was started\./, false],
    ["fix-r-unknown-item", 404, { error: "the stored model holds no such threat or finding", code: "unknown_item" }, /no threat or finding with that id/, false],
    ["fix-r-nomodel", 404, { error: "no stored model for this run", code: "no_stored_model" }, /No checked copy of this run's model is stored/, false],
    ["fix-r-gone", 409, { error: "the project's folder is no longer on this machine", code: "project_gone" }, /no longer on this machine, so there is nothing to fix there\. Nothing was started\./, false],
    ["fix-r-running", 409, { error: "the run has not ended", code: "run_running" }, /Wait for the run to end, or stop it, then try again\./, true],
    ["fix-r-busy", 409, { error: "x", code: "run_record_busy" }, /Another Observer process is writing the run record/, true],
    ["fix-r-unreadable", 409, { error: "x", code: "run_record_unreadable" }, /The run record cannot be read/, true],
    ["fix-r-norun", 404, "unknown run\n", /^This run is no longer listed\.$/, false],
    ["fix-r-boom", 500, "boom", /The task could not be read: .*boom/, true],
  ];
  for (const [id, status, body, re, retry] of rows) {
    await seedFailure(id, "T-1", status, body);
    const html = dialog(id, "T-1");
    const m = /data-testid="assess-fix-error"[^>]*>([\s\S]*?)<\/p>/.exec(html);
    assert.ok(m, `${id}: the refusal is shown`);
    assert.match(text(m![1]).trim(), re, id);
    assert.match(html, /role="alert"/, id);
    assert.equal(/data-testid="assess-fix-retry"/.test(html), retry, `${id}: Retry ${retry ? "is" : "is not"} offered`);
    assert.doesNotMatch(html, /data-testid="assess-fix-choose"/, `${id}: nothing to choose an agent for`);
    assert.doesNotMatch(text(m![1]), BANNED, id);
    assert.doesNotMatch(text(m![1]), /\{|"code"|api 4|api 5/, `${id}: never the raw JSON or the error's own message`);
  }
});

test("hostile strings in the project, a place, a note and the task are text, never markup", async () => {
  const p = plan({
    run: "fix-dlg-hostile",
    project: { name: HOSTILE_SCRIPT, root_path: `/home/${HOSTILE_IMG}`, on_disk: true },
    places: [{ path: HOSTILE_SCRIPT, line: 3, state: "found" }],
    notes: [HOSTILE_IMG],
    prompt: `${HOSTILE_SCRIPT}\n${HOSTILE_IMG}`,
  });
  await seedPlan("fix-dlg-hostile", "T-1", p);
  const html = dialog("fix-dlg-hostile", "T-1");
  assert.doesNotMatch(html, /<script/);
  assert.doesNotMatch(html, /<img/);
  assert.doesNotMatch(html, /<[a-z][^>]*\sonerror=/i, "no element carries the handler");
  const t = text(html);
  assert.ok(t.includes(HOSTILE_SCRIPT));
  assert.ok(t.includes(HOSTILE_IMG));
});

test("a closed dialog renders nothing and reads nothing", () => {
  assert.equal(render(<AssessFixDialog open={false} run={RUN_ID} item="T-1" itemKind="threat" onClose={() => {}} />), "");
});

// ---- the export buttons ----

/** The buttons of a render of the export menu, in document order, as their visible labels. */
function buttonLabels(html: string): string[] {
  return [...html.matchAll(/<button[^>]*>([\s\S]*?)<\/button>/g)].map((m) => text(m[1]).trim()).filter((l) => !/^Show help$/.test(l) && l !== "");
}

test("on a phone the opened disclosure is capped and scrolls inside itself, so the footer cannot take the model's room (N-15)", () => {
  const narrow = render(<ExportMenu data={FIXTURE_TM} run={run()} narrow expanded />);
  const body = /<div[^>]*data-testid="assess-export-body"[^>]*>/.exec(narrow)?.[0] ?? "";
  assert.ok(body.includes("max-h-[24vh]") && body.includes("overflow-y-auto"), body);
  // Wide, the same buttons sit in the footer's own row, with no box of their own to cap.
  const wide = render(<ExportMenu data={FIXTURE_TM} run={run()} narrow={false} />);
  const wideBody = /<div[^>]*data-testid="assess-export-body"[^>]*>/.exec(wide)?.[0] ?? "";
  assert.ok(wideBody.includes("contents") && !wideBody.includes("max-h-"), wideBody);
  // Collapsed, the disclosure's box is not there at all.
  assert.doesNotMatch(render(<ExportMenu data={FIXTURE_TM} run={run()} narrow />), /assess-export-body/);
});

test("the footer has four plain buttons in this order: the two copies, then the two downloads, none a menu", async () => {
  const html = render(<ExportMenu data={FIXTURE_TM} run={run()} />);
  assert.deepEqual(buttonLabels(html), ["Copy diagram source", "Copy checked model", "Download report (Markdown)", "Download checked model (JSON)"]);
  const ids = [...html.matchAll(/data-testid="(assess-export-[a-z-]+)"/g)].map((m) => m[1]);
  assert.deepEqual(
    ids.filter((i) => /^assess-export-(diagram|model|download-md|download-json)$/.test(i)),
    ["assess-export-diagram", "assess-export-model", "assess-export-download-md", "assess-export-download-json"],
  );
  // Plain, focusable buttons: type button, not disabled, no negative tab index, no menu, popup or expander.
  for (const tag of html.match(/<button[^>]*>/g) ?? []) {
    if (/data-help-id/.test(tag)) continue;
    assert.match(tag, /type="button"/);
    assert.doesNotMatch(tag, /disabled|tabindex="-1"|aria-haspopup|aria-expanded|role=/);
  }
  assert.doesNotMatch(html, /role="menu|role="menuitem/);
  // The two notes: the copy's and the downloads'.
  const t = text(html);
  assert.ok(t.includes("The copy is the checked model as Observer shows it"));
  assert.ok(t.includes(EXPORT_DOWNLOAD_NOTE));
  assert.match(t, /rendered by Observer from the checked copy/);
  assert.match(t, /not the agent's own report/);
  assert.match(t, /recognised secrets are hidden in them while hiding is on/);
  assert.doesNotMatch(t, BANNED);
  assert.match(html, /data-help-id="card\.code_security_assess_export"/);
  // They are in the model dialog's own footer, before Close, inside the dialog card.
  const r = run({ id: "fix-footer" });
  await seedModel(r.id, FIXTURE_TM);
  const dlg = render(<AssessModelView run={r} runs={[r]} onClose={() => {}} />);
  assert.match(dlg, /<footer[^>]*>[\s\S]*Copy diagram source[\s\S]*Copy checked model[\s\S]*Download report \(Markdown\)[\s\S]*Download checked model \(JSON\)[\s\S]*Close[\s\S]*<\/footer>/);
});

test("a pen test has three export buttons, and a run with no model has four that are off, with the reason", () => {
  const pt = render(<ExportMenu data={FIXTURE_PT} run={run()} />);
  assert.deepEqual(buttonLabels(pt), ["Copy checked model", "Download report (Markdown)", "Download checked model (JSON)"]);
  assert.doesNotMatch(pt, /assess-export-diagram/);
  const bare = render(<ExportMenu data={null} run={run()} />);
  assert.deepEqual(buttonLabels(bare), ["Copy checked model", "Download report (Markdown)", "Download checked model (JSON)"]);
  for (const id of ["assess-export-model", "assess-export-download-md", "assess-export-download-json"]) {
    assert.match(bare, new RegExp(`<button[^>]*disabled=""[^>]*data-testid="${id}"|<button[^>]*data-testid="${id}"[^>]*disabled=""`), id);
  }
  assert.doesNotMatch(bare, /assess-export-download-note/);
  assert.doesNotMatch(bare, /assess-export-note/);
  // Records that hold no model (only the report was kept) cannot be downloaded either.
  const noModel: AssessModelResponse = { ...FIXTURE_TM, record: { ...FIXTURE_TM.record, truncated: true, result: { report: FIXTURE_TM.record.result.report } } };
  assert.equal(exportDownloadsAvailable(noModel), false);
  assert.equal(exportDownloadsAvailable(FIXTURE_TM), true);
  assert.equal(exportDownloadsAvailable(FIXTURE_PT), true);
  assert.equal(exportDownloadsAvailable(null), false);
  assert.equal(EXPORT_DOWNLOAD_NONE, "There is no model to download from this run.");
});

// ---- the download helper: its path, its file name and its refusals ----

type Saved = { href: string; download: string; clicked: boolean };

/** withBrowser stubs fetch and the document for one call of the helper, and gives back what was asked and what was saved. */
async function withBrowser<T>(res: () => Response | Promise<Response>, fn: (seen: { urls: string[]; saved: Saved[] }) => Promise<T>): Promise<T> {
  const g = globalThis as unknown as Record<string, unknown>;
  const was = { fetch: g.fetch, document: g.document, window: g.window };
  const seen = { urls: [] as string[], saved: [] as Saved[] };
  g.fetch = async (url: string) => {
    seen.urls.push(url);
    return res();
  };
  g.window = globalThis;
  g.document = {
    createElement: () => {
      const a: Saved & { remove: () => void; click: () => void } = {
        href: "",
        download: "",
        clicked: false,
        remove() {},
        click() {
          a.clicked = true;
          seen.saved.push({ href: a.href, download: a.download, clicked: true });
        },
      };
      return a;
    },
    body: { appendChild() {} },
  };
  try {
    return await fn(seen);
  } finally {
    g.fetch = was.fetch;
    g.document = was.document;
    g.window = was.window;
  }
}

afterEach(() => {
  // Nothing a test stubs outlives it.
  assert.equal(typeof (globalThis as { document?: unknown }).document, "undefined");
});

test("a download asks for the run's export in its format and saves the file under the server's name", async () => {
  const [md, json] = EXPORT_DOWNLOADS;
  await withBrowser(
    () => new Response("# Report\n", { status: 200, headers: { "content-type": "text/plain", "content-disposition": `attachment; filename="observer-assessment-${RUN_ID}.md"` } }),
    async (seen) => {
      assert.equal(await downloadExport(RUN_ID, md), "");
      assert.deepEqual(seen.urls, [`/api/security/assessments/export?run=${RUN_ID}&format=md`]);
      assert.equal(seen.saved.length, 1);
      assert.equal(seen.saved[0].download, `observer-assessment-${RUN_ID}.md`);
      assert.match(seen.saved[0].href, /^blob:/);
    },
  );
  // No Content-Disposition: the name is built from the run and the format.
  await withBrowser(
    () => new Response("{}", { status: 200, headers: { "content-type": "application/json" } }),
    async (seen) => {
      assert.equal(await downloadExport(RUN_ID, json), "");
      assert.deepEqual(seen.urls, [`/api/security/assessments/export?run=${RUN_ID}&format=json`]);
      assert.equal(seen.saved[0].download, `observer-assessment-${RUN_ID}.json`);
    },
  );
  // A server name that is not this export's is not used.
  await withBrowser(
    () => new Response("x", { status: 200, headers: { "content-disposition": 'attachment; filename="../../x.md"' } }),
    async (seen) => {
      assert.equal(await downloadExport(RUN_ID, md), "");
      assert.equal(seen.saved[0].download, `observer-assessment-${RUN_ID}.md`);
    },
  );
});

test("a refused download is said in words and is never saved as a file", async () => {
  const refusals: Array<[number, string, RegExp]> = [
    [404, "unknown run\n", /^This run is no longer listed\. Nothing was saved\.$/],
    [404, JSON.stringify({ error: "no stored model for this run", code: "no_stored_model" }), /No checked copy of this run's model is stored\. Check the model again\. Nothing was saved\./],
    [400, JSON.stringify({ error: "the format is json or md", code: "bad_format" }), /Nothing was saved\./],
    [500, "boom", /^The download could not be made\. Nothing was saved\.$/],
  ];
  for (const [status, body, re] of refusals) {
    await withBrowser(
      () => new Response(body, { status }),
      async (seen) => {
        const words = await downloadExport(RUN_ID, EXPORT_DOWNLOADS[0]);
        assert.match(words, re, `${status} ${body}`);
        assert.equal(seen.saved.length, 0, `${status}: nothing was saved`);
        assert.doesNotMatch(words, BANNED);
      },
    );
  }
  // A network failure is a refusal too.
  await withBrowser(
    () => {
      throw new Error("offline");
    },
    async (seen) => {
      assert.equal(await downloadExport(RUN_ID, EXPORT_DOWNLOADS[1]), "The download could not be made. Nothing was saved.");
      assert.equal(seen.saved.length, 0);
    },
  );
});

// ---- the module's pins reach the new files ----

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

test("the new components build no markup, SVG or code from a string, name no setting key and open no menu", () => {
  const dir = secassessDir();
  const files = readdirSync(dir).filter((f) => /\.(ts|tsx)$/.test(f) && !/\.test\.tsx?$/.test(f));
  const mine = ["AssessFixButton.tsx", "AssessFixDialog.tsx", "ExportMenu.tsx"];
  for (const f of mine) assert.ok(files.includes(f), `${f} is swept by the module's pins`);
  const banned = ["dangerouslySetInnerHTML", "innerHTML", "outerHTML", "insertAdjacentHTML", "createElementNS", "<svg", "eval("];
  for (const f of mine) {
    const src = readFileSync(path.join(dir, f), "utf8");
    for (const b of banned) assert.equal(src.includes(b), false, `${f} contains ${b}`);
    assert.doesNotMatch(src, /display_redaction|diagram_max_nodes|diagram_label_chars/, `${f} names a setting key`);
    assert.doesNotMatch(src, /\.replace\(\/_\/g/, `${f} makes a raw value readable by replacing underscores`);
    assert.doesNotMatch(src, /AnchoredPopover|role="menu"|role="menuitem"|aria-haspopup/, `${f} builds a menu`);
    for (const line of src.split("\n")) {
      if (line.includes("text-fg-4")) assert.ok(/<Icon\b/.test(line), `${f}: text-fg-4 on something that is not a glyph: ${line.trim()}`);
    }
    // No colour is written by hand: tokens only.
    assert.doesNotMatch(src, /#[0-9a-fA-F]{3,8}\b|rgb\(|rgba\(|hsl\(/, `${f} writes a colour`);
  }
  // The fix lives in the module's own files and reaches the rows through one context.
  assert.match(readFileSync(path.join(dir, "AssessModelView.tsx"), "utf8"), /AssessFixContext\.Provider/);
  assert.match(readFileSync(path.join(dir, "ThreatTable.tsx"), "utf8"), /<AssessFixButton itemId=\{t\.id\} itemKind="threat"/);
  assert.match(readFileSync(path.join(dir, "FindingEvidence.tsx"), "utf8"), /<AssessFixButton itemId=\{f\.id\} itemKind="finding"/);
});

test("the dialog opens the New terminal dialog in task mode through the dock and only after it closes itself", () => {
  const src = readFileSync(path.join(secassessDir(), "AssessFixDialog.tsx"), "utf8");
  // The dock's own hook, as the Findings tab's fix dialog does, with the dialog closed first.
  assert.match(src, /useOptionalLaunchDock\(\)/);
  assert.match(src, /onClose\(\);\s*dock\.openNewTerminalWithTask\(task\)/);
  assert.match(src, /fixTaskFor\(data\)/);
  // Escape closes this dialog and not the model view under it.
  assert.match(src, /addEventListener\("keydown", onKey, true\)/);
});
