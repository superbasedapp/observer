// Component tests of the retest of earlier findings and the red team's exercise
// (depth plan W7.2 and W7.3, decision D38: a retest gives labels and nothing
// else), rendered with react-dom/server under node's test runner
// (scripts/test-components.mjs, no DOM). A click cannot be simulated; what a
// click does is pinned in src/lib/secAssessRetest.test.ts (the pure helpers each
// handler calls) and in the Playwright spec (the clicks and the keyboard), and
// these prove the components render what those build. The fixtures are the exact
// shape of the server's answer (src/lib/secAssessModelFixture.ts).

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import type { ReactElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router-dom";
import { AssessExercise } from "@/components/secassess/AssessExercise";
import { AssessModelView, modelTabs, type ModelTabId } from "@/components/secassess/AssessModelView";
import { AssessObjectiveField } from "@/components/secassess/AssessObjectiveField";
import { AssessRetestContext, RETEST_CLOSED_TAG } from "@/components/secassess/AssessRetestLabel";
import { AssessRetestPicker, RETEST_OPEN_PLAN_LABEL, RETEST_PICKER_INTRO, RetestAction } from "@/components/secassess/AssessRetestPicker";
import { AssessPlanDialog } from "@/components/secassess/AssessPlanDialog";
import { AssessRetestPlanBlock } from "@/components/secassess/AssessRetestPlan";
import { RETEST_VIEW_LEAD } from "@/components/secassess/AssessRetestView";
import { AssessRunExtras } from "@/components/secassess/AssessRunExtras";
import { AssessRunsList } from "@/components/secassess/AssessRunsList";
import { FindingList } from "@/components/secassess/FindingEvidence";
import { SecAssessCard } from "@/components/secassess/SecAssessCard";
import { ApiError } from "@/lib/api";
import { apiCache } from "@/lib/useApi";
import type { SecurityProject } from "@/lib/codeSecurity";
import { ASSESS_LIST_PATH, ASSESS_REFUSALS, assessPlanPath, type AssessKind, type AssessList, type AssessPlan, type AssessRun } from "@/lib/secAssess";
import { clearanceRegExp, parseClearanceList } from "@/lib/secAssessBanned";
import { EXERCISE_STOP_NOTE, HONEST_LIMITS, RETEST_NOTHING_CLOSED, assessModelPath, type AssessModelResponse, type PentestDoc } from "@/lib/secAssessModel";
import {
  CHAIN_EMPTY_WORDS,
  CHAIN_NO_FINDING,
  CHAIN_STOP_HEADING,
  OBJECTIVE_HELP,
  OBJECTIVE_SOURCE_WORDS,
  RETEST_HIDDEN_CHOOSE,
  RETEST_HIDDEN_CONSEQUENCE,
  RETEST_MAX,
  retestCandidates,
  retestChoices,
  retestsByFinding,
  type RetestCandidate,
} from "@/lib/secAssessRetest";
import {
  FIXTURE_PT,
  FIXTURE_PT_RETESTABLE,
  FIXTURE_PT_RETESTED,
  FIXTURE_RED_TEAM,
  FIXTURE_RED_TEAM_AGENT,
  FIXTURE_RED_TEAM_AGENT_RUN,
  FIXTURE_RED_TEAM_RUN,
  FIXTURE_RETEST,
  FIXTURE_RETEST_OF_RUN,
  FIXTURE_RETEST_RUN_NEW,
  FIXTURE_RETEST_RUN_OLD,
  FIXTURE_VOCAB,
} from "@/lib/secAssessModelFixture";

const consoleError = console.error;
console.error = (...args: unknown[]) => {
  if (typeof args[0] === "string" && args[0].includes("useLayoutEffect does nothing on the server")) return;
  consoleError(...args);
};

// ---- helpers ----

const RETESTABLE = FIXTURE_PT_RETESTABLE.record.result.pt as PentestDoc;
const HOSTILE_SCRIPT = "<script>alert(1)</script>";
const HOSTILE_IMG = '"><img src=x onerror=1>';

function run(over: Partial<AssessRun> = {}): AssessRun {
  return {
    id: FIXTURE_RETEST_OF_RUN,
    created_at: "2026-11-15T10:00:00Z",
    kind: "pentest_local",
    kind_title: "Penetration test (your own app, local)",
    tool: "claude-code",
    project_root_hash: "h1",
    project_name: "ledger",
    seeded: true,
    sandboxed: true,
    state: "validated",
    files: { report: true, sarif: false, commands: false, model: true },
    contract: "pentest.v1",
    validation: { state: "valid", at: "2026-11-15T10:30:00Z", refs: { found: 0, exists: 0, claimed_not_found: 0, missing: 0, invalid: 0, unchecked: 0 } },
    has_model: true,
    report_bytes: 10,
    ended_at: "2026-11-15T10:40:00Z",
    ...over,
  };
}

function redTeamRun(id: string, over: Partial<AssessRun> = {}): AssessRun {
  return run({ id, kind: "red_team_local", kind_title: "Red team (your own app, local)", ...over });
}

function retestRun(id: string, over: Partial<AssessRun> = {}): AssessRun {
  return run({
    id,
    kind: "pentest_retest",
    kind_title: "Retest of earlier findings",
    contract: "retest.v1",
    retest_of: FIXTURE_RETEST_OF_RUN,
    retest_findings: ["F-1", "F-2", "F-3", "F-5", "F-6"],
    created_at: "2026-11-16T09:00:00Z",
    ...over,
  });
}

async function seed(id: string, data: AssessModelResponse): Promise<void> {
  await apiCache.fetch(assessModelPath(id), async () => data);
}

function view(r: AssessRun, extra: { runs?: AssessRun[]; initialTab?: ModelTabId; onRetest?: boolean; onOpenRun?: boolean } = {}): string {
  return renderToStaticMarkup(
    <MemoryRouter>
      <AssessModelView
        run={r}
        runs={extra.runs ?? [r]}
        onClose={() => {}}
        initialTab={extra.initialTab}
        onRetest={extra.onRetest ? () => {} : undefined}
        onOpenRun={extra.onOpenRun ? () => {} : undefined}
      />
    </MemoryRouter>,
  );
}

function render(el: ReactElement): string {
  return renderToStaticMarkup(<MemoryRouter>{el}</MemoryRouter>);
}

function count(html: string, re: RegExp): number {
  return (html.match(re) ?? []).length;
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

/** between is the markup from one marker to the next. */
function between(html: string, from: string, to: string): string {
  const a = html.indexOf(from);
  const b = html.indexOf(to, a + from.length);
  assert.ok(a >= 0, `${from} is in the markup`);
  return html.slice(a, b >= 0 ? b : undefined);
}

/** inner is the text of the element that carries a marker, up to the closing tag that follows it. */
function inner(html: string, marker: string, close = "</div>"): string {
  const a = html.indexOf(marker);
  assert.ok(a >= 0, `${marker} is in the markup`);
  const open = html.indexOf(">", a) + 1;
  const b = html.indexOf(close, open);
  return text(html.slice(open, b >= 0 ? b : undefined)).trim();
}

function repoFile(rel: string): string {
  for (const f of [path.resolve(process.cwd(), "..", rel), path.resolve(process.cwd(), rel)]) {
    try {
      return readFileSync(f, "utf8");
    } catch {
      // try the next place
    }
  }
  assert.fail(`${rel} is found`);
}

const BANNED = clearanceRegExp(parseClearanceList(repoFile("internal/secassess/testdata/clearance_words.json")));

/** limitText is the text of one honest limit. */
function limitText(id: string): string {
  return HONEST_LIMITS.find((l) => l.id === id)?.text ?? "";
}

// ---- the tabs ----

test("a red team's model has an Exercise tab first, a pen test's has none, and a retest has Results, Replayed and How checked", () => {
  assert.deepEqual(modelTabs(FIXTURE_RED_TEAM.record).map((t) => t.id), ["exercise", "coverage", "findings", "checked"]);
  assert.deepEqual(modelTabs(FIXTURE_RED_TEAM_AGENT.record).map((t) => t.id), ["exercise", "coverage", "findings", "checked"]);
  assert.deepEqual(modelTabs(FIXTURE_PT.record).map((t) => t.id), ["coverage", "findings", "checked"]);
  assert.deepEqual(modelTabs(FIXTURE_PT_RETESTED.record).map((t) => t.id), ["coverage", "findings", "checked"]);
  assert.deepEqual(modelTabs(FIXTURE_RETEST.record).map((t) => t.id), ["results", "replayed", "checked"]);
  const labels = modelTabs(FIXTURE_RETEST.record).map((t) => t.label);
  assert.deepEqual(labels, ["Results", "Replayed", "How checked"]);
  for (const l of labels) assert.ok(l.length <= 14, `the tab label ${l} is ${l.length} characters`);
  // The count rides on Results: the findings the agent labelled.
  assert.equal(modelTabs(FIXTURE_RETEST.record)[0].count, 4);
});

test("the Exercise tab is on a red team's view and on no other", async () => {
  const rt = redTeamRun(FIXTURE_RED_TEAM_RUN);
  await seed(rt.id, FIXTURE_RED_TEAM);
  const html = view(rt);
  assert.match(html, /data-testid="assess-exercise"/);
  assert.match(html, /role="tab"[^>]*>[^<]*Exercise/);
  const pt = run({ id: "pt-no-exercise" });
  await seed(pt.id, FIXTURE_PT);
  const plain = view(pt);
  assert.doesNotMatch(plain, /data-testid="assess-exercise"/);
  assert.doesNotMatch(text(plain), /Exercise/);
});

// ---- the Exercise tab ----

test("Exercise: the developer's objective, whose it is, and the steps in the agent's order", async () => {
  const r = redTeamRun(FIXTURE_RED_TEAM_RUN);
  await seed(r.id, FIXTURE_RED_TEAM);
  const html = view(r, { initialTab: "exercise" });
  const objective = between(html, 'data-testid="assess-exercise-objective"', 'data-testid="assess-exercise-chain"');
  assert.match(objective, /data-source="developer"/);
  assert.match(text(objective), new RegExp(OBJECTIVE_SOURCE_WORDS.developer));
  assert.match(text(objective), /Read another user's entries without signing in as them\./);
  // Five steps, numbered in the order the agent listed them.
  const steps = [...html.matchAll(/data-testid="assess-exercise-step" data-step="(\d+)"/g)].map((m) => Number(m[1]));
  assert.deepEqual(steps, [1, 2, 3, 4, 5]);
  const t = text(html);
  assert.ok(t.indexOf("Read the front page and the error pages") < t.indexOf("Looked up the framework version"), "the order of the chain is kept");
  assert.ok(t.indexOf("Searched with a term that closes the quote") < t.indexOf("Tried the admin pages"), "the order of the chain is kept");
  assert.match(t, /5 steps: 3 achieved, 1 partly achieved, 1 blocked\./);
});

test("Exercise: a step names the finding it used by id and title, or says it used none", async () => {
  const r = redTeamRun(FIXTURE_RED_TEAM_RUN);
  await seed(r.id, FIXTURE_RED_TEAM);
  const html = view(r, { initialTab: "exercise" });
  const rows = html.split('data-testid="assess-exercise-step"').slice(1);
  assert.equal(rows.length, 5);
  // Step 2 used F-3 and step 3 used F-1: the finding's own title is beside the id.
  assert.match(text(rows[1]), /F-3/);
  assert.match(text(rows[2]), /F-1/);
  assert.match(text(between(rows[2], 'data-testid="assess-exercise-finding"', 'data-testid="assess-exercise-result"')), /F-1 .+/);
  // Steps 1 and 5 used no finding.
  assert.match(text(between(rows[0], 'data-testid="assess-exercise-finding"', 'data-testid="assess-exercise-result"')), new RegExp(CHAIN_NO_FINDING));
  assert.match(text(between(rows[4], 'data-testid="assess-exercise-finding"', 'data-testid="assess-exercise-result"')), new RegExp(CHAIN_NO_FINDING));
  assert.equal(count(html, new RegExp(CHAIN_NO_FINDING, "g")) >= 2, true);
});

test("Exercise: the result of each step is a word, and the column of what would have stopped it is headed as the agent's opinion", async () => {
  const r = redTeamRun(FIXTURE_RED_TEAM_RUN);
  await seed(r.id, FIXTURE_RED_TEAM);
  const html = view(r, { initialTab: "exercise" });
  const results = [...html.matchAll(/data-testid="assess-exercise-result"[^>]*>(.*?)<\/td>/g)].map((m) => text(m[1]).trim());
  assert.deepEqual(results, ["Achieved", "Achieved", "Achieved", "Partly achieved", "Blocked"]);
  const heading = text(between(html, 'data-testid="assess-exercise-stop-heading"', "</th>"));
  assert.match(heading, /the agent's opinion/);
  assert.ok(heading.includes(CHAIN_STOP_HEADING), heading);
  // The sentence that Observer did not test any of it is printed with the chain.
  assert.ok(text(html).includes(EXERCISE_STOP_NOTE));
  // A step with no opinion says so rather than leaving a blank.
  assert.match(text(html), /The agent gave no opinion\./);
});

test("Exercise on a phone: one block per step in the same order, every heading says whose words follow it, and there is no table to scroll sideways (N-18)", () => {
  const pt = FIXTURE_RED_TEAM.record.result.pt!;
  const wide = render(<AssessExercise pt={pt} narrow={false} />);
  const narrow = render(<AssessExercise pt={pt} narrow />);
  assert.match(wide, /data-testid="assess-exercise-table"/);
  assert.doesNotMatch(narrow, /<table|data-testid="assess-exercise-table"|overflow-x-auto/);
  assert.match(narrow, /data-testid="assess-exercise-blocks"/);
  // The same five steps in the same order as the table.
  const steps = (html: string) => [...html.matchAll(/data-testid="assess-exercise-step" data-step="(\d+)"/g)].map((m) => Number(m[1]));
  assert.deepEqual(steps(narrow), steps(wide));
  assert.deepEqual(steps(narrow), [1, 2, 3, 4, 5]);
  const blocks = narrow.split('data-testid="assess-exercise-step"').slice(1);
  // Each step's block holds its result word, the finding it used (or that it used none) and the agent's opinion (or that it gave none).
  const results = ["Achieved", "Achieved", "Achieved", "Partly achieved", "Blocked"];
  blocks.forEach((b, i) => {
    const part = text(between(b, 'data-testid="assess-exercise-result"', 'data-testid="assess-exercise-stop"'));
    assert.ok(part.includes("Result, as the agent says"), `step ${i + 1} result heading`);
    assert.ok(part.includes(results[i]), `step ${i + 1} result ${results[i]}: ${part}`);
    for (const other of ["Blocked", "Partly achieved"].filter((w) => w !== results[i])) assert.ok(!part.includes(other), `step ${i + 1} result also reads ${other}`);
  });
  assert.match(text(between(blocks[2], 'data-testid="assess-exercise-finding"', 'data-testid="assess-exercise-result"')), /F-1 .+/);
  assert.match(text(between(blocks[0], 'data-testid="assess-exercise-finding"', 'data-testid="assess-exercise-result"')), new RegExp(CHAIN_NO_FINDING));
  // Every block carries each heading, so each part says whose words it is: the step and the result are "as the agent says", the opinion is headed as one.
  const t = text(narrow);
  assert.equal(count(t, /What was done, as the agent says/g), 5);
  assert.equal(count(t, /Result, as the agent says/g), 5);
  assert.equal(count(t, /Finding used/g), 5);
  assert.equal(t.split(CHAIN_STOP_HEADING).length - 1, 5);
  assert.match(CHAIN_STOP_HEADING, /the agent's opinion/);
  // The note that Observer did not test any of it, and a step with no opinion, are there as on the table.
  assert.ok(t.includes(EXERCISE_STOP_NOTE));
  assert.match(t, /The agent gave no opinion\./);
});

test("Exercise: the honest limit of a red team run is printed on the tab", async () => {
  const r = redTeamRun(FIXTURE_RED_TEAM_RUN);
  await seed(r.id, FIXTURE_RED_TEAM);
  const t = text(between(view(r, { initialTab: "exercise" }), 'data-testid="assess-exercise-limit"', "</section>"));
  assert.ok(limitText("l18").length > 40);
  assert.ok(text(view(r, { initialTab: "exercise" })).includes(limitText("l18")));
  assert.match(t, /one application in one box/);
});

test("Exercise: an objective the agent stated is said to be the agent's, and a chain it did not record says so", async () => {
  const r = redTeamRun(FIXTURE_RED_TEAM_AGENT_RUN);
  await seed(r.id, FIXTURE_RED_TEAM_AGENT);
  const html = view(r, { initialTab: "exercise" });
  const objective = between(html, 'data-testid="assess-exercise-objective"', 'data-testid="assess-exercise-chain"');
  assert.match(objective, /data-source="agent"/);
  assert.match(text(objective), new RegExp(OBJECTIVE_SOURCE_WORDS.agent));
  assert.match(text(objective), /Reach the entries of another account through the search route\./);
  assert.match(html, /data-testid="assess-exercise-empty"/);
  assert.match(text(html), new RegExp(CHAIN_EMPTY_WORDS));
  assert.doesNotMatch(html, /data-testid="assess-exercise-table"/);
  // The note about the opinion column is still there: it is about what the tab says, not about a row.
  assert.ok(text(html).includes(EXERCISE_STOP_NOTE));
});

test("Exercise: an exercise with no objective says none was recorded, and one whose source is unknown says so", () => {
  const none = text(render(<AssessExercise pt={{ findings: [], exercise: { chain: [] } }} />));
  assert.match(none, new RegExp(OBJECTIVE_SOURCE_WORDS.none));
  const odd = text(render(<AssessExercise pt={{ findings: [], exercise: { objective: "Look around", objective_by: "somebody" as never, chain: [] } }} />));
  assert.match(odd, new RegExp(OBJECTIVE_SOURCE_WORDS.unknown));
  assert.match(odd, /Look around/);
});

test("Exercise: nothing the agent wrote is markup, and no technique table or list of objectives is offered", async () => {
  const hostile: AssessModelResponse = {
    ...FIXTURE_RED_TEAM,
    record: {
      ...FIXTURE_RED_TEAM.record,
      result: {
        ...FIXTURE_RED_TEAM.record.result,
        pt: {
          ...FIXTURE_RED_TEAM.record.result.pt!,
          exercise: {
            objective: HOSTILE_SCRIPT,
            objective_by: "agent",
            chain: [{ step: HOSTILE_IMG, finding: "F-1", result: "achieved", stop: HOSTILE_SCRIPT }],
          },
        },
      },
    },
  };
  const r = redTeamRun("rt-hostile");
  await seed(r.id, hostile);
  const html = view(r, { initialTab: "exercise" });
  assert.doesNotMatch(html, /<script>alert/);
  assert.doesNotMatch(html, /<img src=x/);
  assert.match(html, /&lt;script&gt;alert\(1\)&lt;\/script&gt;/);
  const t = text(html);
  assert.doesNotMatch(t, /ATT&CK|MITRE|technique/i, "no technique naming");
  assert.doesNotMatch(t, /choose an objective|pick an objective|example objectives/i, "no objective library");
});

// ---- the retest picker ----

function candidates(n: number): RetestCandidate[] {
  return Array.from({ length: n }, (_, i) => ({
    id: `F-${i + 1}`,
    title: `Finding number ${i + 1}`,
    category: "INPV",
    requests: 1 + (i % 2),
    condition: i % 3 !== 2 ? "status 200" : "",
    hasCondition: i % 3 !== 2,
    hidden: i === 1,
  }));
}

test("RetestAction: names what a retest is and opens the picker from a button; nothing is offered when no finding has a stored request", () => {
  const html = render(<RetestAction run={run()} doc={RETESTABLE} vocab={FIXTURE_VOCAB} onRetest={() => {}} />);
  assert.match(html, /data-testid="assess-retest-action"/);
  assert.match(html, /<button[^>]*data-testid="assess-retest-open"[^>]*>(<[^>]*>)*[^<]*Retest findings/);
  assert.match(text(html), /5 findings have a stored request to replay\./);
  // The picker is closed until the button is pressed.
  assert.doesNotMatch(html, /data-testid="assess-retest-picker"/);
  const none = render(<RetestAction run={run()} doc={{ findings: [] } as unknown as PentestDoc} onRetest={() => {}} />);
  assert.doesNotMatch(none, /data-testid="assess-retest-open"/);
  assert.match(text(none), /No finding in this model has a stored request, so there is nothing to retest\./);
});

test("RetestAction: a project whose folder is gone cannot be retested, and the button is off with the reason", () => {
  const html = render(<RetestAction run={run({ project_gone: true })} doc={RETESTABLE} onRetest={() => {}} />);
  assert.match(html, /<button[^>]*disabled=""[^>]*data-testid="assess-retest-open"|<button[^>]*data-testid="assess-retest-open"[^>]*disabled=""/);
  assert.match(text(html), /This project's folder is no longer on this machine, so there is nothing to retest against\./);
});

/** offer is the picker's offer line, as text. */
function offer(html: string): string {
  return text(between(html, 'data-testid="assess-retest-offer"', "</p>")).replace(/^data-testid="assess-retest-offer">/, "");
}

/** boxOf is the checkbox tag of one finding in the picker, to read its checked and disabled state. */
function boxOf(html: string, id: string): string {
  const m = html.match(new RegExp("<input[^>]*data-testid=\"assess-retest-choose-" + id + "\"[^>]*>"));
  assert.ok(m, "no checkbox for " + id);
  return m[0];
}

test("the picker lists every finding with a stored request, a checkbox each, and what was stored for it", () => {
  const cands = retestCandidates(RETESTABLE);
  assert.deepEqual(cands.map((c) => c.id), ["F-1", "F-2", "F-3", "F-5", "F-6"]);
  const html = render(<AssessRetestPicker candidates={cands} vocab={FIXTURE_VOCAB} projectHash="h1" ofRun={FIXTURE_RETEST_OF_RUN} onClose={() => {}} onPlan={() => {}} />);
  assert.match(html, /data-testid="assess-retest-picker"/);
  assert.equal(count(html, /type="checkbox"/g), 5);
  // Every checkbox is labelled by its finding's row (the row is the label).
  assert.equal(count(html, /<label[^>]*>\s*<input type="checkbox"/g), 5);
  const t = text(html);
  assert.ok(t.includes(RETEST_PICKER_INTRO));
  assert.match(t, /Entry search is injectable/);
  assert.match(t, /2 stored requests/);
  assert.match(t, /has a stored condition/i);
  assert.match(t, /no stored condition \(a label cannot be backed by the log\)/i);
  // F-2's stored request had a value hidden: the warning is on that row only. Its row comes after the findings the replay sends in full (N-21).
  const f2 = between(html, 'data-finding-id="F-2"', "</li>");
  assert.match(text(f2), /A stored value was hidden when the finding was kept/);
  assert.doesNotMatch(text(between(html, 'data-finding-id="F-1"', "</li>")), /A stored value was hidden/);
  assert.ok(html.indexOf('data-finding-id="F-6"') < html.indexOf('data-finding-id="F-2"'), "the hidden-value finding is listed after the others");
  // What a hidden value means for a label is said once above the list, not on each row that has one.
  assert.equal(count(html, /data-testid="assess-retest-hidden-once"/g), 1);
  assert.ok(t.includes(RETEST_HIDDEN_CONSEQUENCE));
  assert.equal(t.split(RETEST_HIDDEN_CONSEQUENCE).length - 1, 1);
  assert.doesNotMatch(text(f2), /not reproduced label/);
  assert.ok(t.includes(RETEST_NOTHING_CLOSED));
  assert.match(t, new RegExp(RETEST_OPEN_PLAN_LABEL));
});

test("the picker starts with the findings the replay can send in full ticked, up to the bound, and the count says how many of the bound", () => {
  const few = render(<AssessRetestPicker candidates={retestCandidates(RETESTABLE)} projectHash="h1" ofRun="r" onClose={() => {}} onPlan={() => {}} />);
  // Five findings, one with a hidden value (F-2): four are chosen.
  assert.equal(count(few, /type="checkbox"[^>]*checked=""/g), 4);
  assert.match(text(between(few, 'data-testid="assess-retest-count"', "</p>")), /4 of 8 findings chosen/);
  for (const id of ["F-1", "F-3", "F-5", "F-6"]) assert.match(boxOf(few, id), /checked=""/, id);
  assert.doesNotMatch(boxOf(few, "F-2"), /checked=""/, "F-2 has a hidden value and is not chosen for the person");
  // More findings than the bound: only the first eight that can be sent in full are ticked, all are listed, and the offer line says the bound.
  const many = render(<AssessRetestPicker candidates={candidates(12)} projectHash="h1" ofRun="r" onClose={() => {}} onPlan={() => {}} />);
  assert.equal(count(many, /type="checkbox"/g), 12);
  assert.equal(count(many, /type="checkbox"[^>]*checked=""/g), RETEST_MAX);
  assert.match(text(many), /8 of 8 findings chosen/);
  assert.match(text(many), /12 findings have a stored request to replay\. 11 can be sent again in full, and the first 8 of them are chosen\. 1 has a value that was hidden when the finding was kept; it is listed after and is not chosen for you\. A retest replays at most 8: choose which\./);
  assert.match(many, new RegExp(`data-testid="assess-retest-choose-F-9"`));
  assert.doesNotMatch(boxOf(many, "F-2"), /checked=""/);
});

test("the picker lists the findings with a hidden value after the others, with the reason once, and keeps them selectable (N-21)", () => {
  const html = render(<AssessRetestPicker candidates={retestCandidates(RETESTABLE)} vocab={FIXTURE_VOCAB} projectHash="h1" ofRun="r" onClose={() => {}} onPlan={() => {}} />);
  const t = text(html);
  // Two groups to tell apart: both have a heading with their count.
  assert.match(t, /Can be sent again in full \(4\)/);
  assert.match(t, /Had a value hidden \(1\)/);
  assert.ok(html.indexOf("Can be sent again in full") < html.indexOf("Had a value hidden"));
  assert.match(html, /aria-label="Findings that can be sent again in full"/);
  assert.match(html, /aria-label="Findings with a hidden value"/);
  // The offer line says how many of the findings are chosen and why the others are not.
  assert.equal(offer(html), "5 findings have a stored request to replay. 4 can be sent again in full and are chosen. 1 has a value that was hidden when the finding was kept; it is listed after and is not chosen for you.");
  // The reason is in the hidden group, once, with what a person can still do.
  const hidden = between(html, 'data-testid="assess-retest-hidden"', "</section>");
  assert.ok(text(hidden).includes(RETEST_HIDDEN_CONSEQUENCE));
  assert.ok(text(hidden).includes(RETEST_HIDDEN_CHOOSE));
  assert.equal(t.split(RETEST_HIDDEN_CONSEQUENCE).length - 1, 1);
  assert.doesNotMatch(text(between(html, 'data-testid="assess-retest-full"', "</section>")), /A stored value was hidden|hidden when the finding/);
  // A finding with a hidden value can be chosen: its checkbox is an ordinary one.
  assert.doesNotMatch(boxOf(html, "F-2"), /disabled/);
  // No hidden value anywhere: one list, no headings, no reason.
  const plain = render(<AssessRetestPicker candidates={candidates(3).map((c) => ({ ...c, hidden: false }))} projectHash="h1" ofRun="r" onClose={() => {}} onPlan={() => {}} />);
  assert.doesNotMatch(text(plain), /Can be sent again in full|Had a value hidden/);
  assert.equal(count(plain, /data-testid="assess-retest-hidden-once"/g), 0);
  assert.equal(count(plain, /type="checkbox"[^>]*checked=""/g), 3);
  assert.match(plain, /aria-label="Findings with a stored request"/);
  assert.equal(offer(plain), "3 findings have a stored request to replay.");
});

test("every finding has a hidden value: none is chosen, the offer line says so, the button is off, and the findings can still be chosen (N-21)", () => {
  const all = candidates(4).map((c) => ({ ...c, hidden: true }));
  const html = render(<AssessRetestPicker candidates={all} projectHash="h1" ofRun="r" onClose={() => {}} onPlan={() => {}} />);
  assert.equal(count(html, /type="checkbox"/g), 4);
  assert.equal(count(html, /type="checkbox"[^>]*checked=""/g), 0);
  assert.match(text(between(html, 'data-testid="assess-retest-count"', "</p>")), /0 of 8 findings chosen/);
  assert.equal(offer(html), "4 findings have a stored request to replay. Every one has a value that was hidden when the finding was kept, so none is chosen for you.");
  assert.match(html, /<button[^>]*disabled=""[^>]*data-testid="assess-retest-open-plan"|<button[^>]*data-testid="assess-retest-open-plan"[^>]*disabled=""/);
  // One group: no headings to tell apart, and the reason is said once.
  assert.doesNotMatch(text(html), /Can be sent again in full|Had a value hidden/);
  assert.equal(count(html, /data-testid="assess-retest-hidden-once"/g), 1);
  assert.doesNotMatch(boxOf(html, "F-1"), /disabled/);
  // One finding alone.
  const one = render(<AssessRetestPicker candidates={all.slice(0, 1)} projectHash="h1" ofRun="r" onClose={() => {}} onPlan={() => {}} />);
  assert.equal(offer(one), "1 finding has a stored request to replay. It has a value that was hidden when the finding was kept, so none is chosen for you.");
});

test("the picker's button opens the plan and is the only action: it starts nothing", () => {
  const html = render(<AssessRetestPicker candidates={candidates(3)} projectHash="h1" ofRun="r" onClose={() => {}} onPlan={() => {}} />);
  const button = between(html, 'data-testid="assess-retest-open-plan"', "</button>");
  assert.match(text(button), /Open the retest plan/);
  assert.doesNotMatch(text(html), /\bStart\b/);
  assert.doesNotMatch(text(html), /close the finding|mark .* fixed|resolved/i);
  // With nothing chosen the button is off.
  const empty = render(<AssessRetestPicker candidates={[]} projectHash="h1" ofRun="r" onClose={() => {}} onPlan={() => {}} />);
  assert.match(empty, /<button[^>]*disabled=""[^>]*data-testid="assess-retest-open-plan"|<button[^>]*data-testid="assess-retest-open-plan"[^>]*disabled=""/);
});

// ---- the retest's plan ----

const retestKind: AssessKind = {
  id: "pentest_retest",
  title: "Retest of earlier findings",
  summary: "Sends the stored requests of earlier findings again and labels each one.",
  mode: "Sandboxed",
  launchable: true,
  sandbox: "required",
  target: "required",
  files: ["retest.md"],
  note: "Sandboxed. Labels only.",
  from_run: true,
};

const redTeamKind: AssessKind = {
  ...retestKind,
  id: "red_team_local",
  title: "Red team (your own app, local)",
  summary: "A goal-driven test of one development server.",
  from_run: undefined,
  exercise: true,
};

const project = { project_root_hash: "h1", name: "ledger", root_path: "/home/u/ledger", active: true } as SecurityProject;

const retestPlan: AssessPlan = {
  confirm_token: "tok",
  run_id: "20261116-ab12cd",
  kind: retestKind,
  project: { project_root_hash: "h1", name: "ledger", root_path: "/home/u/ledger", on_disk: true },
  ok: true,
  target: "",
  target_typed: false,
  candidates: [],
  boundary: ["The only target is the address given below."],
  prompt: "You are retesting findings of an earlier run.",
  backend: "bwrap",
  tier: "proxy_only",
  allowed_tools: ["claude-code"],
  seeds: { "claude-code": "leading_positional" },
  residual: "The sandbox's only route out is Observer's model proxy.",
  retest: {
    of_run: FIXTURE_RETEST_OF_RUN,
    of_kind: "pentest_local",
    of_target: "http://localhost:3000/",
    max: 8,
    selected: ["F-1", "F-2", "F-6"],
    findings: [
      { id: "F-1", title: "Entry search is injectable", category: "INPV", steps: 2, has_condition: true, condition: "status 200 and the body holds 412" },
      { id: "F-2", title: "An export can be read with another account's session", category: "ATHZ", steps: 1, has_condition: true, hidden: true },
      { id: "F-6", title: "The admin list answers without a session", category: "ATHN", steps: 1, has_condition: false },
    ],
    refused: [
      { finding: "F-4", code: "no_request" },
      { finding: "F-9", code: "unknown_finding" },
    ],
  },
};

test("the retest plan names the earlier run's findings, what was stored for each, the ones refused by name and the suggestion for the address", () => {
  const html = render(<AssessRetestPlanBlock retest={retestPlan.retest!} vocab={FIXTURE_VOCAB} />);
  assert.match(html, /data-testid="assess-retest-plan"/);
  const t = text(html);
  assert.match(t, /The stored requests of findings from an earlier penetration test/);
  assert.match(t, /3 of 8 findings chosen/);
  assert.equal(count(html, /data-testid="assess-retest-plan-finding"/g), 3);
  assert.match(t, /Stored condition: status 200 and the body holds 412/);
  assert.match(t, /A stored value was hidden when the finding was kept/);
  assert.match(t, /no stored condition \(a label cannot be backed by the log\)/i);
  assert.equal(count(html, /data-testid="assess-retest-hidden-once"/g), 1);
  assert.equal(t.split(RETEST_HIDDEN_CONSEQUENCE).length - 1, 1);
  // The refused ones are named, in words and not as codes.
  const refused = text(between(html, 'data-testid="assess-retest-refused"', "</ul>"));
  assert.match(refused, /F-4/);
  assert.match(refused, /F-9/);
  assert.doesNotMatch(refused, /no_request|unknown_finding/);
  // The earlier run's address is only a suggestion, and the developer still uses it and ticks that it is theirs.
  assert.match(text(between(html, 'data-testid="assess-retest-target-note"', "</p>")), /http:\/\/localhost:3000\/ .* as a suggestion/);
  assert.ok(t.includes(RETEST_NOTHING_CLOSED));
  assert.doesNotMatch(html, /<script/);
});

test("the plan dialog for a retest holds the project, names the retest and still asks for the confirmation of the target", async () => {
  const choices = retestChoices({ ofRun: FIXTURE_RETEST_OF_RUN, findings: ["F-1", "F-2", "F-6"] });
  await apiCache.fetch(`${assessPlanPath("pentest_retest", "h1", undefined, undefined, undefined, choices)}&n=t`, async () => retestPlan);
  const html = render(
    <AssessPlanDialog
      kind={retestKind}
      retest={{ ofRun: FIXTURE_RETEST_OF_RUN, findings: ["F-1", "F-2", "F-6"], projectHash: "h1", vocab: FIXTURE_VOCAB }}
      projects={[project]}
      launch
      onClose={() => {}}
      readKey="t"
    />,
  );
  assert.match(html, /data-testid="assess-retest-plan"/);
  assert.match(html, /data-testid="assess-target"/);
  // No address is chosen yet, so nothing can be confirmed: the earlier run's address is only a suggestion.
  assert.doesNotMatch(html, /data-testid="assess-confirm"/);
  assert.match(text(html), /The earlier run tested http:\/\/localhost:3000\/ ?\. It is filled in under Target as a suggestion/);
  // The project is the earlier run's: the picker of projects is off.
  const picker = html.match(/<select[^>]*id="assess-project"[^>]*>/);
  assert.ok(picker && /disabled=""/.test(picker[0]), String(picker?.[0]));
  // Nothing is started by opening the plan: Choose agent stays off until the target is confirmed.
  assert.match(html, /<button[^>]*disabled=""[^>]*>[^<]*(<[^>]*>)*[^<]*Choose agent/);
  const t = text(html);
  assert.doesNotMatch(t, /\b(fixed|resolved)\b/i, "nothing on the plan says a finding is fixed");
  assert.ok(t.includes(RETEST_NOTHING_CLOSED));
});

test("a retest the server will not plan is shown by the server's reason, in words", async () => {
  const choices = retestChoices({ ofRun: "00000000000000e9", findings: ["F-1"] });
  await apiCache.fetch(`${assessPlanPath("pentest_retest", "h1", undefined, undefined, undefined, choices)}&n=t`, async () => {
    throw new ApiError(409, "retest_run_unknown", ASSESS_REFUSALS.retest_run_unknown.words);
  });
  const html = render(
    <AssessPlanDialog kind={retestKind} retest={{ ofRun: "00000000000000e9", findings: ["F-1"], projectHash: "h1" }} projects={[project]} launch onClose={() => {}} readKey="t" />,
  );
  assert.ok(text(html).includes(ASSESS_REFUSALS.retest_run_unknown.words) || /could not|cannot/i.test(text(html)));
  assert.doesNotMatch(html, /retest_run_unknown/);
});

// ---- the objective on a red team's plan ----

test("the objective field is one line with a counter in characters, empty to begin with, and says it is optional", () => {
  const html = render(<AssessObjectiveField objective={{ text: "", max: 200 }} value="" locked={false} onApply={() => {}} />);
  assert.match(html, /data-testid="assess-objective"/);
  const input = between(html, "<input", ">");
  assert.match(input, /data-testid="assess-objective-input"/);
  assert.doesNotMatch(html, /<textarea/);
  const t = text(html);
  assert.match(t, /Objective \(optional\)/);
  assert.match(t, /0 of 200 characters/);
  // One name, once (N-17): the heading is the field's visible name, the field carries it as its accessible name, and the help is one short sentence.
  assert.equal(count(t, /Objective/g), 1);
  assert.match(input, /aria-label="Objective \(optional\)"/);
  const help = t.slice(t.indexOf("0 of 200 characters")).trim();
  assert.equal(help, `0 of 200 characters. ${OBJECTIVE_HELP}`);
  assert.equal(OBJECTIVE_HELP.split(".").filter((x) => x.trim() !== "").length, 1);
  assert.doesNotMatch(html, /data-testid="assess-objective-cleaned"/);
});

test("the objective field counts characters not bytes, keeps what is typed and shows the cleaned text when the server changed it", () => {
  const typed = "Read entries 日本語 `quoted`";
  const html = render(<AssessObjectiveField objective={{ text: "Read entries 日本語 quoted", max: 200 }} value={typed} locked={false} onApply={() => {}} />);
  const input = between(html, "<input", ">");
  assert.ok(input.includes('value="Read entries 日本語 `quoted`"'), input);
  assert.match(text(html), /25 of 200 characters/);
  assert.match(text(between(html, 'data-testid="assess-objective-cleaned"', "</p>")), /The task carries it as: Read entries 日本語 quoted/);
  // A held run keeps the objective it was filed with: the field is off.
  const locked = render(<AssessObjectiveField objective={{ text: typed, max: 200 }} value={typed} locked onApply={() => {}} />);
  assert.match(between(locked, "<input", ">"), /disabled=""/);
});

test("the plan dialog for a red team carries the objective field, and one for a pen test does not", async () => {
  const redPlan: AssessPlan = { ...retestPlan, kind: redTeamKind, retest: undefined, objective: { text: "", max: 200 } };
  await apiCache.fetch(`${assessPlanPath("red_team_local", "h1")}&n=t`, async () => redPlan);
  const html = render(<AssessPlanDialog kind={redTeamKind} projects={[project]} launch onClose={() => {}} readKey="t" />);
  assert.match(html, /data-testid="assess-objective-input"/);
  assert.doesNotMatch(html, /data-testid="assess-retest-plan"/);
  await apiCache.fetch(`${assessPlanPath("pentest_local", "h1")}&n=t`, async () => ({ ...retestPlan, kind: { ...redTeamKind, id: "pentest_local", exercise: undefined }, retest: undefined, objective: undefined }));
  const pen = render(<AssessPlanDialog kind={{ ...redTeamKind, id: "pentest_local", exercise: undefined }} projects={[project]} launch onClose={() => {}} readKey="t" />);
  assert.doesNotMatch(pen, /data-testid="assess-objective-input"/);
});

// ---- the label on a finding's row ----

const RUNS_WITH_RETESTS = [
  run(),
  retestRun(FIXTURE_RETEST_RUN_NEW),
  retestRun(FIXTURE_RETEST_RUN_OLD, { created_at: "2026-11-15T16:00:00Z", retest_findings: ["F-1", "F-2"] }),
];

test("a finding's row shows its newest retest label in words, with the evidence word and a short Not closed tag (N-13)", async () => {
  const r = run();
  await seed(r.id, FIXTURE_PT_RETESTED);
  const html = view(r, { initialTab: "findings", runs: RUNS_WITH_RETESTS, onOpenRun: true });
  const f1 = between(html, 'data-testid="assess-retest-line" data-finding-id="F-1"', 'data-testid="assess-retest-line" data-finding-id="F-2"');
  const label = text(between(f1, 'data-testid="assess-retest-label"', 'data-testid="assess-retest-date"'));
  assert.match(label, /Reproduced/);
  assert.match(label, /Helper log backs the label/);
  // The row carries the short tag, not the sentence; the sentence is printed once above the findings.
  assert.equal(inner(f1, 'data-testid="assess-retest-closed"', "</span></span>"), RETEST_CLOSED_TAG);
  assert.ok(!text(f1).includes(RETEST_NOTHING_CLOSED), "the full sentence is not repeated under the label");
  assert.match(f1, /data-testid="assess-retest-open"/);
  // F-2: not reproduced, the log does not back it, and the reason is a sentence, never a code.
  const f2 = between(html, 'data-testid="assess-retest-line" data-finding-id="F-2"', 'data-testid="assess-retest-line" data-finding-id="F-3"');
  assert.match(text(between(f2, 'data-testid="assess-retest-label"', 'data-testid="assess-retest-date"')), /Not reproduced.*No log/);
  assert.doesNotMatch(f2, /replay_incomplete/);
  assert.match(text(between(f2, 'data-testid="assess-retest-reason"', "</p>")), /\w+/);
  // F-3: inconclusive has no reading of the log.
  const f3 = between(html, 'data-testid="assess-retest-line" data-finding-id="F-3"', 'data-testid="assess-retest-line" data-finding-id="F-5"');
  assert.match(text(between(f3, 'data-testid="assess-retest-label"', 'data-testid="assess-retest-date"')), /Inconclusive.*No log reading/);
  // Findings no retest labelled show no label, and a retest never closes or marks one.
  assert.doesNotMatch(html, /data-testid="assess-retest-line" data-finding-id="F-4"/);
  assert.doesNotMatch(html, /data-testid="assess-retest-line" data-finding-id="F-6"/);
});

test("every labelled row carries the Not closed tag, which points at the one sentence above the findings (N-13)", async () => {
  const r = run({ id: "pt-tags" });
  await seed(r.id, FIXTURE_PT_RETESTED);
  for (const withRetestButton of [false, true]) {
    const html = view(r, { initialTab: "findings", runs: RUNS_WITH_RETESTS, onOpenRun: true, onRetest: withRetestButton });
    const labelled = ["F-1", "F-2", "F-3", "F-5"];
    // One tag per labelled finding, none for the findings no retest labelled.
    assert.equal(count(html, /data-testid="assess-retest-closed"/g), labelled.length);
    assert.equal(count(html, /data-testid="assess-retest-line"/g), labelled.length);
    for (const id of labelled) {
      const row = between(html, `data-testid="assess-retest-line" data-finding-id="${id}"`, "</div></td>");
      assert.match(row, /data-testid="assess-retest-closed"/, id);
      assert.equal(inner(row, 'data-testid="assess-retest-closed"', "</span></span>"), "Not closed", id);
    }
    // The sentence is in the document once, as the Retest block's note (or, with no retest button, a note over the findings), and each tag names it as its description.
    assert.equal(count(html, /data-testid="assess-retest-closed-note"/g), 1);
    assert.equal(text(html).split(RETEST_NOTHING_CLOSED).length - 1, 1, "the full sentence is printed once");
    const id = html.match(/<p id="([^"]+)"[^>]*data-testid="assess-retest-closed-note"/)?.[1];
    assert.ok(id, "the note has an id");
    assert.equal(count(html, new RegExp(`aria-describedby="${id!.replace(/[:]/g, "\\:")}"[^>]*data-testid="assess-retest-closed"`, "g")), labelled.length);
    assert.equal(inner(html, 'data-testid="assess-retest-closed-note"', "</p>"), RETEST_NOTHING_CLOSED);
    // With a retest button the note sits in the Retest block, above the table; without one it still sits above the table.
    const note = html.indexOf('data-testid="assess-retest-closed-note"');
    assert.ok(note > 0 && note < html.indexOf('data-testid="assess-retest-line"'));
    if (withRetestButton) assert.ok(between(html, 'data-testid="assess-retest-action"', 'data-testid="assess-model-bands"').includes("assess-retest-closed-note"), "the note is in the Retest block");
    else assert.doesNotMatch(html, /data-testid="assess-retest-action"/);
  }
  // A run no retest labelled prints no note and no tag.
  const bare = run({ id: "pt-no-labels" });
  await seed(bare.id, FIXTURE_PT_RETESTABLE);
  const none = view(bare, { initialTab: "findings", onRetest: true });
  assert.doesNotMatch(none, /assess-retest-closed/);
  assert.ok(!text(none).includes(RETEST_NOTHING_CLOSED));
});

test("a finding retested twice shows the newest label and lists the older one behind a disclosure", async () => {
  const r = run({ id: "pt-twice" });
  await seed(r.id, FIXTURE_PT_RETESTED);
  const html = view(r, { initialTab: "findings", runs: RUNS_WITH_RETESTS, onOpenRun: true });
  const f1 = between(html, 'data-testid="assess-retest-line" data-finding-id="F-1"', 'data-testid="assess-retest-line" data-finding-id="F-2"');
  assert.match(text(f1), /Older retests \(1\)/);
  // The older one is the one that did not reproduce it; it is not the one in the row's own label.
  const newest = inner(f1, 'data-testid="assess-retest-label"', 'data-testid="assess-retest-date"');
  assert.doesNotMatch(newest, /Not reproduced/);
  assert.match(newest, /Reproduced/);
  // F-5 was retested once: no disclosure.
  const f5 = between(html, 'data-testid="assess-retest-line" data-finding-id="F-5"', "</tr>");
  assert.doesNotMatch(f5, /Older retests/);
});

test("no label is worded or toned as a fix: Not reproduced is neutral, Reproduced draws attention, nothing is green", async () => {
  const r = run({ id: "pt-tone" });
  await seed(r.id, FIXTURE_PT_RETESTED);
  const html = view(r, { initialTab: "findings", runs: RUNS_WITH_RETESTS, onOpenRun: true });
  const lines = html.split('data-testid="assess-retest-line"').slice(1).join(" ");
  assert.doesNotMatch(lines, /success|ok\b|bg-ok|text-ok/);
  const t = text(lines);
  assert.doesNotMatch(t, /\b(fixed|resolved|closed the|passed|safe|secure|clean)\b/i);
  assert.match(t, /Not reproduced/);
  assert.doesNotMatch(text(html), /Mark .* (fixed|closed)/i);
});

test("the open button is offered only when the retest's own run can be opened here", async () => {
  const r = run({ id: "pt-open" });
  await seed(r.id, FIXTURE_PT_RETESTED);
  const none = view(r, { initialTab: "findings", runs: [r], onOpenRun: true });
  assert.doesNotMatch(none, /data-testid="assess-retest-open"[^>]*aria-label="Open the retest/);
  const without = view(r, { initialTab: "findings", runs: RUNS_WITH_RETESTS });
  assert.doesNotMatch(without, /aria-label="Open the retest/);
  const withBoth = view(r, { initialTab: "findings", runs: RUNS_WITH_RETESTS, onOpenRun: true });
  assert.match(withBoth, /aria-label="Open the retest that labelled F-1"/);
});

test("an open finding says what each retest found, the agent's note as text, and every sentence stays free of a clearance", () => {
  const byFinding = retestsByFinding(FIXTURE_PT_RETESTED.retests);
  const html = renderToStaticMarkup(
    <MemoryRouter>
      <AssessRetestContext.Provider value={{ byFinding, canOpen: () => false }}>
        <FindingList findings={RETESTABLE.findings} vocab={FIXTURE_VOCAB} initialExpanded="F-1" />
      </AssessRetestContext.Provider>
    </MemoryRouter>,
  );
  const history = between(html, 'data-testid="assess-retest-history"', "</ul>");
  assert.match(text(history), /Retests/);
  assert.equal(count(history, /data-testid="assess-retest-entry"/g), 2);
  assert.match(text(history), /The same search term returned every entry again\./);
  assert.match(text(history), /The search answered with the ordinary list\./);
  assert.doesNotMatch(text(history), BANNED);
  // Without a provider the same rows render no label at all.
  const bare = render(<FindingList findings={RETESTABLE.findings} vocab={FIXTURE_VOCAB} initialExpanded="F-1" />);
  assert.doesNotMatch(bare, /data-testid="assess-retest-line"|data-testid="assess-retest-history"/);
});

test("the agent's note on a label is text: markup in it is shown, not built", () => {
  const hostile = new Map(retestsByFinding(FIXTURE_PT_RETESTED.retests));
  const first = hostile.get("F-1")![0];
  hostile.set("F-1", [{ ...first, result: { ...first.result, note: `${HOSTILE_SCRIPT} ${HOSTILE_IMG}` } }]);
  const html = renderToStaticMarkup(
    <MemoryRouter>
      <AssessRetestContext.Provider value={{ byFinding: hostile, canOpen: () => false }}>
        <FindingList findings={RETESTABLE.findings} vocab={FIXTURE_VOCAB} initialExpanded="F-1" />
      </AssessRetestContext.Provider>
    </MemoryRouter>,
  );
  assert.doesNotMatch(html, /<script>alert/);
  assert.doesNotMatch(html, /<img src=x/);
  assert.match(html, /&lt;script&gt;/);
});

test("a finding's row says so when its newest label is not backed and an older retest reproduced it, and says nothing otherwise (N-11)", () => {
  const byFinding = retestsByFinding(FIXTURE_PT_RETESTED.retests);
  const html = renderToStaticMarkup(
    <MemoryRouter>
      <AssessRetestContext.Provider value={{ byFinding, canOpen: () => false }}>
        <FindingList findings={RETESTABLE.findings} vocab={FIXTURE_VOCAB} />
      </AssessRetestContext.Provider>
    </MemoryRouter>,
  );
  const line = (id: string) => between(html, `data-testid="assess-retest-line" data-finding-id="${id}"`, "</div></td>");
  // F-2: the newer retest says not reproduced with no log (the stored request had a hidden value); the older one said reproduced, with no log either.
  const f2 = text(between(line("F-2"), 'data-testid="assess-retest-standing"', "</p>"));
  assert.match(f2, /The newer label has no log behind it\. An older retest \(.+\) labelled this finding reproduced, with no log behind that label either\./);
  assert.doesNotMatch(f2, BANNED);
  // The tag sits with the label, the sentence under it, and the older retest is still listed behind its disclosure.
  assert.ok(line("F-2").indexOf("assess-retest-closed") < line("F-2").indexOf("assess-retest-standing"));
  assert.match(text(line("F-2")), /Older retests \(1\)/);
  // F-1: the newer label is reproduced and backed. F-3, F-5: one label. F-6: none.
  for (const id of ["F-1", "F-3", "F-5"]) assert.doesNotMatch(line(id), /assess-retest-standing/, id);
  assert.equal(count(html, /data-testid="assess-retest-standing"/g), 1);
});

// ---- the offer of a retest over the findings ----

test("the Findings tab offers a retest only where the view was given a way to open one", async () => {
  const r = run({ id: "pt-offer" });
  await seed(r.id, FIXTURE_PT_RETESTABLE);
  const offered = view(r, { initialTab: "findings", onRetest: true });
  assert.match(offered, /data-testid="assess-retest-action"/);
  assert.match(text(offered), /5 findings have a stored request to replay\./);
  const not = view(r, { initialTab: "findings" });
  assert.doesNotMatch(not, /data-testid="assess-retest-action"/);
  // A red team's findings can be retested the same way.
  const rt = redTeamRun("rt-offer");
  await seed(rt.id, FIXTURE_RED_TEAM);
  assert.match(view(rt, { initialTab: "findings", onRetest: true }), /data-testid="assess-retest-action"/);
});

test("a retest run's own view offers no retest of a retest", async () => {
  const r = retestRun(FIXTURE_RETEST_RUN_NEW);
  await seed(r.id, FIXTURE_RETEST);
  assert.doesNotMatch(view(r, { onRetest: true }), /data-testid="assess-retest-action"/);
});

// ---- the retest run's own view ----

test("a retest run's view has a button to the run it replayed when that run can be opened here, and no dead control otherwise (N-19)", async () => {
  const r = retestRun(FIXTURE_RETEST_RUN_NEW);
  await seed(r.id, FIXTURE_RETEST);
  const earlier = run({ id: FIXTURE_RETEST_OF_RUN });
  const offered = view(r, { runs: [earlier, r], onOpenRun: true });
  assert.match(offered, /data-testid="assess-retest-open-replayed"[^>]*>Open the run it replayed</);
  // The sentence that says where the labels are shown is still there, with the control under it.
  assert.ok(text(between(offered, 'data-testid="assess-retest-lead"', 'data-testid="assess-retest-open-replayed"')).includes("The labels are shown on the findings of the run it replayed."));
  // No way to open another run from here, the earlier run missing from the list, or its model gone: nothing to press.
  assert.doesNotMatch(view(r, { runs: [earlier, r] }), /assess-retest-open-replayed/);
  assert.doesNotMatch(view(r, { runs: [r], onOpenRun: true }), /assess-retest-open-replayed/);
  assert.doesNotMatch(view(r, { runs: [run({ id: FIXTURE_RETEST_OF_RUN, has_model: false }), r], onOpenRun: true }), /assess-retest-open-replayed/);
  // A pen test's own view is not a retest of anything: it carries none.
  const pt = run({ id: "pt-no-replayed" });
  await seed(pt.id, FIXTURE_PT);
  assert.doesNotMatch(view(pt, { runs: [pt, earlier], onOpenRun: true }), /assess-retest-open-replayed/);
});

test("a retest run's view says what a retest is and that it closes nothing once, then one count line and the results (N-12)", async () => {
  const r = retestRun(FIXTURE_RETEST_RUN_NEW);
  await seed(r.id, FIXTURE_RETEST);
  const html = view(r);
  assert.match(html, /data-testid="assess-retest-view"/);
  // The limit of a retest (l20) opens the results: it is where the view says what a retest is and that nothing was closed.
  const lead = text(between(html, 'data-testid="assess-retest-lead"', "</div>"));
  assert.ok(lead.includes(limitText("l20")));
  assert.ok(lead.includes(RETEST_VIEW_LEAD));
  assert.match(lead, /closes nothing and changes no finding's status/);
  // Nothing says it again before the first label: not the preamble, not the lead, not a second sentence.
  const beforeLabels = text(html.slice(0, html.indexOf('data-testid="assess-retest-table"')));
  assert.equal(beforeLabels.split(/closes nothing|Nothing was closed|nothing was closed/).length - 1, 1, beforeLabels);
  assert.ok(!text(html).includes(RETEST_NOTHING_CLOSED), "the per-label sentence is not printed in the retest's own view");
  // The five counts are one sentence, not a sentence and five tiles with the same numbers.
  assert.match(text(html), /5 findings chosen: 1 reproduced, 2 not reproduced, 1 inconclusive, 1 not labelled\./);
  assert.equal(count(html, /data-count="/g), 0);
  assert.doesNotMatch(html, /data-testid="assess-retest-counts"/);
});

test("the results table lists each finding's label, the reading of the helper's log and the agent's note, with the earlier finding's own title", async () => {
  const r = retestRun(FIXTURE_RETEST_RUN_NEW);
  await seed(r.id, FIXTURE_RETEST);
  const html = view(r);
  const rows = html.split('data-testid="assess-retest-result"').slice(1);
  assert.equal(rows.length, 4);
  const labels = rows.map((row) => inner(row, 'data-testid="assess-retest-result-label"', "</td>"));
  assert.deepEqual(labels, ["Reproduced", "Not reproduced", "Inconclusive", "Not reproduced"]);
  assert.match(text(rows[0]), /Entry search is injectable/);
  assert.match(text(rows[0]), /Helper log backs the label/);
  assert.match(text(rows[1]), /No log/);
  assert.match(text(rows[2]), /No log reading: an inconclusive label claims nothing\./);
  assert.match(text(rows[3]), /The health route no longer lists the address\./);
  // The code the validator set is never printed.
  assert.doesNotMatch(html, /replay_incomplete|evidence_state|not_replayed/);
  // A finding the agent gave no label is named, and nothing is said to be closed for it.
  assert.match(text(between(html, 'data-testid="assess-retest-missing"', "</p>")), /F-6/);
  assert.match(text(between(html, 'data-testid="assess-retest-missing"', "</p>")), /nothing was closed/);
});

test("the requests a label cites are the helper's records, each tagged with the finding it replayed", async () => {
  const r = retestRun(FIXTURE_RETEST_RUN_NEW);
  await seed(r.id, FIXTURE_RETEST);
  const html = view(r);
  const probes = between(html, 'data-testid="assess-retest-probes"', "</section>");
  assert.match(text(probes), /Replay of F-1/);
  assert.match(text(probes), /Replay of F-2/);
  assert.match(text(probes), /Replay of F-5/);
  assert.match(text(probes), /The log is a file the agent can write\./);
  assert.equal(count(html, /data-testid="assess-retest-probe-group"/g), 3);
});

test("a retest run has no export and no import: the footer says why", async () => {
  const r = retestRun(FIXTURE_RETEST_RUN_NEW);
  await seed(r.id, FIXTURE_RETEST);
  const html = view(r);
  assert.match(html, /data-testid="assess-retest-no-export"/);
  assert.ok(text(between(html, 'data-testid="assess-retest-no-export"', "</p>")).includes(ASSESS_REFUSALS.retest_no_export.words));
  assert.doesNotMatch(html, /data-testid="assess-export/);
  assert.doesNotMatch(text(html), /\bCopy\b|\bExport\b|Download|Import findings/);
});

test("the Replayed tab lists the findings it was asked to replay, the agent's own words as the agent's, and its own limits", async () => {
  const r = retestRun(FIXTURE_RETEST_RUN_NEW);
  await seed(r.id, FIXTURE_RETEST);
  const html = view(r, { initialTab: "replayed" });
  const asked = [...html.matchAll(/data-testid="assess-retest-asked" data-finding-id="([^"]+)"/g)].map((m) => m[1]);
  assert.deepEqual(asked, ["F-1", "F-2", "F-3", "F-5", "F-6"]);
  assert.match(text(between(html, 'data-finding-id="F-6"', "</li>")), /\(no label was given\)/);
  assert.match(text(html), /The agent started the development server and replayed the stored requests of five findings\./);
  assert.match(text(html), /Only the stored requests were sent\./);
  assert.match(text(html), /the agent's own limits/i);
});

test("How checked for a retest carries the limits of a pen test, l20 among them, and the honest limit of the retest", async () => {
  const r = retestRun(FIXTURE_RETEST_RUN_NEW);
  await seed(r.id, FIXTURE_RETEST);
  const html = view(r, { initialTab: "checked" });
  const t = text(html);
  assert.ok(t.includes(limitText("l20")));
  assert.ok(t.includes(limitText("l12")));
  assert.doesNotMatch(t, new RegExp(limitText("l8").slice(0, 40)), "a threat model's limit is not shown on a retest");
});

test("a retest's agent text is only text", async () => {
  const hostile: AssessModelResponse = {
    ...FIXTURE_RETEST,
    record: {
      ...FIXTURE_RETEST.record,
      result: {
        ...FIXTURE_RETEST.record.result,
        rt: {
          ...FIXTURE_RETEST.record.result.rt!,
          summary: HOSTILE_SCRIPT,
          limits: [HOSTILE_IMG],
          results: FIXTURE_RETEST.record.result.rt!.results!.map((x, i) => (i === 0 ? { ...x, note: `${HOSTILE_SCRIPT}${HOSTILE_IMG}`, title: HOSTILE_SCRIPT } : x)),
        },
      },
    },
  };
  const r = retestRun("rt-hostile-view");
  await seed(r.id, hostile);
  for (const tab of ["results", "replayed", "checked"] as const) {
    const html = view(r, { initialTab: tab });
    assert.doesNotMatch(html, /<script>alert/, tab);
    assert.doesNotMatch(html, /<img src=x/, tab);
  }
});

// ---- the run rows ----

function rows(runs: AssessRun[]): string {
  return render(<AssessRunsList importAvailable onReport={() => {}} onModel={() => {}} runs={runs} />);
}

test("a retest run's row names the earlier run it retested and how many findings it was asked to replay", () => {
  const earlier = run();
  const rt = retestRun(FIXTURE_RETEST_RUN_NEW);
  const html = rows([rt, earlier]);
  const line = inner(html, 'data-testid="assess-run-retest-of"');
  assert.match(line, /^Retest of the earlier run \(.+\): 5 findings chosen\.$/);
  assert.doesNotMatch(line, /0000000/, "the earlier run is named, never shown by its id");
  // When the earlier run is no longer in the list the line says so and shows no id.
  const orphan = text(rows([rt]));
  assert.match(orphan, /Retest of an earlier run that is no longer in the list: 5 findings chosen\./);
  assert.doesNotMatch(inner(rows([rt]), 'data-testid="assess-run-retest-of"'), /0000000/);
  assert.doesNotMatch(html, /data-testid="assess-run-objective"/);
});

test("a red team run's row carries its objective, clipped", () => {
  const long = `Read the entries of another account ${"through the search route and the export route ".repeat(5)}`.trim();
  const short = redTeamRun("rt-short", { objective: "Read another account's entries." });
  const clipped = redTeamRun("rt-long", { objective: long });
  assert.equal(inner(rows([short]), 'data-testid="assess-run-objective"'), "Objective: Read another account's entries.");
  const longHtml = rows([clipped]);
  assert.match(inner(longHtml, 'data-testid="assess-run-objective"'), /^Objective: .+…$/);
  assert.ok(longHtml.includes(`title="${long}"`), "the full text is on the row's title");
  // A run with neither shows neither.
  assert.equal(AssessRunExtras({ run: run(), runs: [] }), null);
});

test("a retest run's row offers the model view and no import or export of its own", () => {
  const rt = retestRun(FIXTURE_RETEST_RUN_NEW);
  const html = rows([rt, run()]);
  assert.match(text(html), /Retest of earlier findings/);
  assert.doesNotMatch(html, /data-testid="assess-run-import/);
});

// ---- the card ----

const gridKinds: AssessKind[] = [
  { ...redTeamKind, id: "pentest_local", title: "Penetration test (your own app, local)", exercise: undefined },
  redTeamKind,
  retestKind,
];

test("the card's grid lists the kinds started from nothing and leaves out the ones started from an earlier run", async () => {
  const data: AssessList = { kinds: gridKinds, runs: [], import_available: true, launch: true };
  await apiCache.fetch(ASSESS_LIST_PATH, async () => data);
  const html = render(<SecAssessCard projects={[project]} />);
  const grid = between(html, 'aria-label="Assessment kinds"', "</ul>");
  assert.match(grid, /Penetration test \(your own app, local\)/);
  assert.match(grid, /Red team \(your own app, local\)/);
  assert.doesNotMatch(grid, /Retest of earlier findings/);
});

// ---- the words ----

test("every new tab of every new fixture is free of a word that reads as a clearance, and of a raw code", async () => {
  const cases: [string, AssessRun, AssessModelResponse, ModelTabId[]][] = [
    ["red-team", redTeamRun(FIXTURE_RED_TEAM_RUN), FIXTURE_RED_TEAM, ["exercise", "coverage", "findings", "checked"]],
    ["red-team-agent", redTeamRun(FIXTURE_RED_TEAM_AGENT_RUN), FIXTURE_RED_TEAM_AGENT, ["exercise", "coverage", "findings", "checked"]],
    ["retest", retestRun(FIXTURE_RETEST_RUN_NEW), FIXTURE_RETEST, ["results", "replayed", "checked"]],
    ["retested", run({ id: "sweep-retested" }), FIXTURE_PT_RETESTED, ["coverage", "findings", "checked"]],
    ["retestable", run({ id: "sweep-retestable" }), FIXTURE_PT_RETESTABLE, ["coverage", "findings", "checked"]],
  ];
  for (const [name, r, data, tabs] of cases) {
    await seed(r.id, data);
    for (const tab of tabs) {
      const html = view(r, { initialTab: tab, runs: RUNS_WITH_RETESTS, onOpenRun: true, onRetest: true });
      const t = text(html);
      assert.doesNotMatch(t, BANNED, `${name} ${tab}: ${t.match(BANNED)?.[0]}`);
      assert.doesNotMatch(t, /\b(observed|authentic|exploitable)\b/i, `${name} ${tab}`);
      assert.doesNotMatch(t, /\b(not_reproduced|replay_incomplete|not_started|not_replayed|condition_still_holds|target_not_started|evidence_state|evidence_reason|objective_by|retest_findings|retest_of|retest_no_export)\b/, `${name} ${tab}: a code reaches the page`);
    }
  }
  // The pieces that are not a tab: the picker, the plan block, the objective field, the run rows.
  const pieces = [
    text(render(<AssessRetestPicker candidates={candidates(12)} projectHash="h1" ofRun="r" onClose={() => {}} onPlan={() => {}} />)),
    text(render(<AssessRetestPlanBlock retest={retestPlan.retest!} vocab={FIXTURE_VOCAB} />)),
    text(render(<AssessObjectiveField objective={{ text: "a b", max: 200 }} value="a`b" locked={false} onApply={() => {}} />)),
    text(rows([retestRun(FIXTURE_RETEST_RUN_NEW), redTeamRun("rt-row", { objective: "Reach the export" }), run()])),
  ];
  for (const t of pieces) assert.doesNotMatch(t, BANNED, String(t.match(BANNED)?.[0]));
});

test("the new components build no markup from a string and name no setting key", () => {
  const dir = ["src/components/secassess", "web/src/components/secassess"].map((d) => path.resolve(process.cwd(), d)).find((d) => {
    try {
      readFileSync(path.join(d, "AssessExercise.tsx"), "utf8");
      return true;
    } catch {
      return false;
    }
  });
  assert.ok(dir, "the component directory is found");
  for (const f of ["AssessExercise", "AssessRetestLabel", "AssessRetestPicker", "AssessRetestPlan", "AssessRetestView", "AssessObjectiveField", "AssessRunExtras"]) {
    const src: string = readFileSync(path.join(dir as string, `${f}.tsx`), "utf8");
    for (const b of ["dangerouslySetInnerHTML", "innerHTML", "outerHTML", "insertAdjacentHTML", "createElementNS", "<svg", "eval(", "href="]) assert.equal(src.includes(b), false, `${f}.tsx contains ${b}`);
    assert.doesNotMatch(src, /\.replace\(\/_\/g/, f);
    assert.doesNotMatch(src, /aria-haspopup|role="menu"/, f);
  }
});
