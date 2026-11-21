import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import type { AssessKind, AssessRetestPlan } from "./secAssess.ts";
import { clearanceRegExp, parseClearanceList } from "./secAssessBanned.ts";
import {
  CHAIN_RESULT_WORDS,
  EVIDENCE_REASON_WORDS,
  RETEST_NOTHING_CLOSED,
  RETEST_RESULT_WORDS,
  type PentestDoc,
  type PTFinding,
  type RetestResultView,
  type RetestView,
} from "./secAssessModel.ts";
import {
  CHAIN_EMPTY_WORDS,
  CHAIN_NO_FINDING,
  CHAIN_STOP_HEADING,
  HIDDEN_MARKER,
  OBJECTIVE_HELP,
  OBJECTIVE_MAX,
  OBJECTIVE_SOURCE_WORDS,
  RETEST_CONDITION_WORDS,
  RETEST_HIDDEN_NOTE,
  RETEST_MAX,
  RETEST_OF_KIND_WORDS,
  RETEST_REFUSED_WORDS,
  RETEST_SUMMARY_PARTS,
  cardKinds,
  chainCountsLine,
  chainRows,
  clipObjective,
  defaultRetestIds,
  retestGroups,
  retestHiddenCount,
  RETEST_HIDDEN_CHOOSE,
  objectiveCleanedNote,
  objectiveCounterLine,
  objectiveLength,
  objectiveReading,
  retestCandidateNotes,
  retestCandidates,
  retestChoices,
  retestChosenIds,
  retestCountLine,
  retestEvidenceWords,
  retestKindOf,
  retestLimitWords,
  retestNotLabelled,
  retestOfKindWords,
  retestOfferLine,
  retestPlanFindings,
  retestPlanLine,
  retestPlanNotes,
  retestReading,
  retestRefusedWords,
  retestRows,
  retestSummaryCounts,
  retestSummaryLine,
  retestTargetSuggestion,
  retestsByFinding,
  retestRanAt,
  retestStanding,
  runObjectiveLine,
  runRetestLine,
  toggleRetestId,
} from "./secAssessRetest.ts";
import { FIXTURE_PT_RETESTABLE, FIXTURE_PT_RETESTED, FIXTURE_RED_TEAM, FIXTURE_RED_TEAM_AGENT, FIXTURE_RETEST, FIXTURE_VOCAB } from "./secAssessModelFixture.ts";

// The pure side of the retest (W7.2) and the red team's objective and chain
// (W7.3): the picker's candidates and bounds, the finding-label join, the words
// of a label and of a log reading, the chain's rows and the plan's lines. One
// row per rule, table-driven.

const CLEARANCE = parseClearanceList(readFileSync(new URL("../../../internal/secassess/testdata/clearance_words.json", import.meta.url), "utf8"));
const BANNED = clearanceRegExp(CLEARANCE);

/** A finding with the stored requests and condition a case needs. */
function finding(id: string, over: Partial<PTFinding> = {}): PTFinding {
  return { id, title: `Finding ${id}`, category: "INPV", rating: { likelihood: 3, impact: 3 }, basis: "observed", where: {}, ...over };
}

function doc(findings: PTFinding[]): Pick<PentestDoc, "findings"> {
  return { findings };
}

const GET = (path: string) => ({ step: "s", request: { method: "GET", path } });

// ---- the picker's candidates ----

test("retestCandidates offers a finding only when a reproduction step carries a request with a method and a path", () => {
  const rows: [string, PTFinding, boolean][] = [
    ["a method and a path", finding("F-1", { reproduction: [GET("/a")] }), true],
    ["a request among text-only steps", finding("F-1", { reproduction: [{ step: "t" }, GET("/a")] }), true],
    ["text-only steps", finding("F-1", { reproduction: [{ step: "t" }] }), false],
    ["no steps", finding("F-1", { reproduction: [] }), false],
    ["no reproduction", finding("F-1"), false],
    ["an empty path", finding("F-1", { reproduction: [{ step: "s", request: { method: "GET", path: "" } }] }), false],
    ["an empty method", finding("F-1", { reproduction: [{ step: "s", request: { method: "", path: "/a" } }] }), false],
    ["a blank method", finding("F-1", { reproduction: [{ step: "s", request: { method: "  ", path: "/a" } }] }), false],
    // An older stored copy holds a plain string, which a retest cannot send.
    ["a request an older copy stores as a string", finding("F-1", { reproduction: [{ step: "s", request: "GET /a" as unknown as never }] }), false],
    ["a null request", finding("F-1", { reproduction: [{ step: "s", request: null as unknown as never }] }), false],
  ];
  for (const [name, f, offered] of rows) assert.equal(retestCandidates(doc([f])).length === 1, offered, name);
});

test("retestCandidates: the requests are counted, the condition is read, a hidden value is flagged, and the model's order is kept", () => {
  const c = retestCandidates(FIXTURE_PT_RETESTABLE.record.result.pt);
  assert.deepEqual(c.map((x) => x.id), ["F-1", "F-2", "F-3", "F-5", "F-6"], "F-4 has text steps only and is not offered");
  const by = new Map(c.map((x) => [x.id, x] as const));
  assert.equal(by.get("F-1")!.requests, 2);
  assert.equal(by.get("F-1")!.hasCondition, true);
  assert.match(by.get("F-1")!.condition, /status 200/);
  assert.equal(by.get("F-3")!.hasCondition, false, "no stored condition");
  assert.equal(by.get("F-3")!.condition, "");
  assert.deepEqual(c.filter((x) => x.hidden).map((x) => x.id), ["F-2"], "only the request with a hidden header value");
  assert.equal(by.get("F-1")!.category, "INPV");
  assert.equal(by.get("F-1")!.title, "Entry search is injectable");
});

test("retestCandidates reads a hidden value in the path, the body or any header value, and nothing else", () => {
  const hidden = (req: object) => retestCandidates(doc([finding("F-1", { reproduction: [{ step: "s", request: { method: "POST", path: "/a", ...req } as never }] })]))[0].hidden;
  assert.equal(hidden({}), false);
  assert.equal(hidden({ path: `/a?token=${HIDDEN_MARKER}` }), true);
  assert.equal(hidden({ body: `{"k":"${HIDDEN_MARKER}"}` }), true);
  assert.equal(hidden({ headers: [{ name: "Cookie", value: HIDDEN_MARKER }] }), true);
  assert.equal(hidden({ headers: [{ name: "[REDACTED]", value: "x" }] }), false, "a header name is not a value");
  assert.equal(hidden({ headers: [{ name: "Accept", value: "application/json" }] }), false);
  // A hidden value in a second stored request counts for the finding.
  assert.equal(
    retestCandidates(doc([finding("F-1", { reproduction: [GET("/a"), { step: "s", request: { method: "GET", path: `/b/${HIDDEN_MARKER}` } }] })]))[0].hidden,
    true,
  );
});

test("retestCandidates: a repeated id is left to the first, a missing id is skipped, and no document is no candidate", () => {
  const a = finding("F-1", { title: "first", reproduction: [GET("/a")] });
  const b = finding("F-1", { title: "second", reproduction: [GET("/b")] });
  assert.deepEqual(retestCandidates(doc([a, b])).map((c) => c.title), ["first"]);
  assert.deepEqual(retestCandidates(doc([finding("", { reproduction: [GET("/a")] })])), []);
  assert.deepEqual(retestCandidates(null), []);
  assert.deepEqual(retestCandidates(undefined), []);
  assert.deepEqual(retestCandidates({ findings: undefined }), []);
});

test("there is no cap on the candidates: only the choice is bounded", () => {
  const many = Array.from({ length: 40 }, (_, i) => finding(`F-${i + 1}`, { reproduction: [GET(`/p${i}`)] }));
  assert.equal(retestCandidates(doc(many)).length, 40);
});

// ---- the choice and its bound ----

test("defaultRetestIds takes the first findings in the model's order, at most the bound, when none has a hidden value", () => {
  const ids = Array.from({ length: 11 }, (_, i) => ({ id: `F-${i + 1}` }));
  assert.equal(RETEST_MAX, 8);
  const rows: [string, number, number][] = [
    ["none", 0, 0],
    ["fewer than the bound", 3, 3],
    ["exactly the bound", 8, 8],
    ["more than the bound", 11, 8],
  ];
  for (const [name, n, want] of rows) assert.deepEqual(defaultRetestIds(ids.slice(0, n)).length, want, name);
  assert.deepEqual(defaultRetestIds(ids), ["F-1", "F-2", "F-3", "F-4", "F-5", "F-6", "F-7", "F-8"]);
  assert.deepEqual(defaultRetestIds(ids, 2), ["F-1", "F-2"]);
  assert.deepEqual(defaultRetestIds(ids, 0), []);
});

test("defaultRetestIds chooses the findings the replay can send in full: a hidden value is listed but not chosen for the person (N-21)", () => {
  type C = { id: string; hidden?: boolean };
  const ok = (id: string): C => ({ id });
  const hid = (id: string): C => ({ id, hidden: true });
  const many = (prefix: string, n: number, hidden: boolean): C[] => Array.from({ length: n }, (_, i) => ({ id: `${prefix}-${i + 1}`, hidden }));
  const rows: [string, C[], number | undefined, string[]][] = [
    ["a hidden finding in front is skipped and not counted", [hid("F-1"), ok("F-2"), hid("F-3"), ok("F-4")], undefined, ["F-2", "F-4"]],
    ["the bound counts only the findings chosen", [...many("H", 5, true), ...many("P", 10, false)], undefined, ["P-1", "P-2", "P-3", "P-4", "P-5", "P-6", "P-7", "P-8"]],
    ["every finding hidden: none is chosen", many("H", 4, true), undefined, []],
    ["a real run: twelve of sixteen with a hidden value, the four that can be sent are the four chosen", [...many("H", 12, true), ...many("P", 4, false)], undefined, ["P-1", "P-2", "P-3", "P-4"]],
    ["a smaller bound", many("P", 5, false), 2, ["P-1", "P-2"]],
    ["a bound of zero", many("P", 3, false), 0, []],
    ["nothing hidden is the first ones, in order", [ok("A"), ok("B"), ok("C")], undefined, ["A", "B", "C"]],
  ];
  for (const [name, input, max, want] of rows) assert.deepEqual(defaultRetestIds(input, max), want, name);
  // The candidate list the picker builds from a model carries the flag, so the default reads it.
  const doc = {
    findings: [
      { id: "F-1", title: "a", category: "ATHN", reproduction: [{ step: "s", request: { method: "GET", path: "/a", headers: [{ name: "Authorization", value: "[REDACTED]" }] } }] },
      { id: "F-2", title: "b", category: "ATHN", reproduction: [{ step: "s", request: { method: "GET", path: "/b" } }] },
    ],
  } as unknown as Parameters<typeof retestCandidates>[0];
  assert.deepEqual(defaultRetestIds(retestCandidates(doc)), ["F-2"]);
});

test("retestGroups splits the findings by whether the replay sends them in full, each in the model's order", () => {
  const list = [{ id: "A", hidden: true }, { id: "B", hidden: false }, { id: "C", hidden: true }, { id: "D" }];
  const g = retestGroups(list);
  assert.deepEqual(g.full.map((c) => c.id), ["B", "D"]);
  assert.deepEqual(g.hidden.map((c) => c.id), ["A", "C"]);
  assert.deepEqual(retestGroups([]), { full: [], hidden: [] });
  assert.equal(retestHiddenCount(list), 2);
  assert.equal(retestHiddenCount([]), 0);
});

test("retestOfferLine says how many findings are chosen for the person and how many are listed after them with a hidden value (N-21)", () => {
  const rows: [string, [number, number, number?], string][] = [
    ["none offered", [0, 8, 3], "No finding in this model has a stored request, so there is nothing to retest."],
    ["no hidden value: the line is the old one", [5, 8, 0], "5 findings have a stored request to replay."],
    ["one finding, hidden", [1, 8, 1], "1 finding has a stored request to replay. It has a value that was hidden when the finding was kept, so none is chosen for you."],
    ["all hidden", [4, 8, 4], "4 findings have a stored request to replay. Every one has a value that was hidden when the finding was kept, so none is chosen for you."],
    ["all hidden past the bound", [12, 8, 12], "12 findings have a stored request to replay. Every one has a value that was hidden when the finding was kept, so none is chosen for you. A retest replays at most 8: choose which."],
    ["some hidden", [5, 8, 1], "5 findings have a stored request to replay. 4 can be sent again in full and are chosen. 1 has a value that was hidden when the finding was kept; it is listed after and is not chosen for you."],
    ["one that can be sent", [5, 8, 4], "5 findings have a stored request to replay. 1 can be sent again in full and is chosen. 4 have a value that was hidden when the finding was kept; they are listed after and none of them is chosen for you."],
    ["a real run: sixteen findings, twelve hidden", [16, 8, 12], "16 findings have a stored request to replay. 4 can be sent again in full and are chosen. 12 have a value that was hidden when the finding was kept; they are listed after and none of them is chosen for you. A retest replays at most 8: choose which."],
    ["more that can be sent than the bound", [12, 8, 1], "12 findings have a stored request to replay. 11 can be sent again in full, and the first 8 of them are chosen. 1 has a value that was hidden when the finding was kept; it is listed after and is not chosen for you. A retest replays at most 8: choose which."],
    ["a hidden count past the total is cut to it", [2, 8, 9], "2 findings have a stored request to replay. Every one has a value that was hidden when the finding was kept, so none is chosen for you."],
    ["a negative count is none", [2, 8, -1], "2 findings have a stored request to replay."],
  ];
  for (const [name, [total, max, hidden], want] of rows) assert.equal(retestOfferLine(total, max, hidden), want, name);
  assert.equal(retestOfferLine(5, 8), "5 findings have a stored request to replay.", "the third argument is optional");
  // Plain words: nothing of the check's own vocabulary.
  for (const [, [total, max, hidden]] of rows) assert.doesNotMatch(retestOfferLine(total, max, hidden), /_|redacted|E23|replay_incomplete/i);
  assert.match(RETEST_HIDDEN_CHOOSE, /can show a weakness is there, but it cannot show it is gone/);
});

test("toggleRetestId: adding keeps the order chosen, a repeat is not added, the bound refuses in words, removing always works", () => {
  const eight = ["F-1", "F-2", "F-3", "F-4", "F-5", "F-6", "F-7", "F-8"];
  const rows: [string, string[], string, boolean, { ids: string[]; error?: string }][] = [
    ["add to empty", [], "F-1", true, { ids: ["F-1"] }],
    ["add after others", ["F-3"], "F-1", true, { ids: ["F-3", "F-1"] }],
    ["a repeat is not added twice", ["F-1"], "F-1", true, { ids: ["F-1"] }],
    ["remove", ["F-1", "F-2"], "F-1", false, { ids: ["F-2"] }],
    ["remove one not chosen", ["F-1"], "F-9", false, { ids: ["F-1"] }],
    ["the eighth is added", eight.slice(0, 7), "F-8", true, { ids: eight }],
    ["the ninth is refused", eight, "F-9", true, { ids: eight, error: retestLimitWords(8) }],
    ["a repeat at the bound is not an error", eight, "F-8", true, { ids: eight }],
    ["remove at the bound", eight, "F-8", false, { ids: eight.slice(0, 7) }],
  ];
  for (const [name, cur, id, on, want] of rows) assert.deepEqual(toggleRetestId(cur, id, on), want, name);
  assert.deepEqual(toggleRetestId(["F-1"], "F-2", true, 1), { ids: ["F-1"], error: "A retest replays at most 1 findings. Leave one out to choose another." }, "the bound is a parameter");
});

test("retestChosenIds keeps only findings the picker offers, once each, in the order chosen", () => {
  const offered = [{ id: "F-1" }, { id: "F-2" }, { id: "F-3" }];
  assert.deepEqual(retestChosenIds(["F-3", "F-1"], offered), ["F-3", "F-1"]);
  assert.deepEqual(retestChosenIds(["F-9", "F-1"], offered), ["F-1"]);
  assert.deepEqual(retestChosenIds(["F-1", "F-1"], offered), ["F-1"]);
  assert.deepEqual(retestChosenIds([], offered), []);
});

test("the picker's lines: the count against the bound, what the run offers, and the notes under a finding", () => {
  assert.equal(retestCountLine(0, 8), "0 of 8 findings chosen");
  assert.equal(retestCountLine(3, 8), "3 of 8 findings chosen");
  assert.equal(retestOfferLine(0, 8), "No finding in this model has a stored request, so there is nothing to retest.");
  assert.equal(retestOfferLine(1, 8), "1 finding has a stored request to replay.");
  assert.equal(retestOfferLine(5, 8), "5 findings have a stored request to replay.");
  assert.equal(retestOfferLine(8, 8), "8 findings have a stored request to replay.");
  assert.equal(retestOfferLine(12, 8), "12 findings have a stored request to replay. A retest replays at most 8: choose which.");
  const notes = (requests: number, hasCondition: boolean, hidden: boolean) => retestCandidateNotes({ requests, hasCondition, hidden });
  assert.deepEqual(notes(1, true, false), ["1 stored request", RETEST_CONDITION_WORDS.has]);
  assert.deepEqual(notes(2, false, false), ["2 stored requests", RETEST_CONDITION_WORDS.none]);
  assert.deepEqual(notes(2, true, true), ["2 stored requests", RETEST_CONDITION_WORDS.has, RETEST_HIDDEN_NOTE]);
  assert.equal(RETEST_CONDITION_WORDS.has, "Has a stored condition");
  assert.equal(RETEST_CONDITION_WORDS.none, "No stored condition (a label cannot be backed by the log)");
  assert.match(RETEST_HIDDEN_NOTE, /^A stored value was hidden when the finding was kept\.$/);
});

// ---- the plan's lines ----

const planBlock = (over: Partial<AssessRetestPlan> = {}): AssessRetestPlan => ({
  of_run: "r1",
  findings: [
    { id: "F-1", title: "one", steps: 2, has_condition: true, condition: "status 200" },
    { id: "F-2", title: "two", steps: 1, has_condition: false, hidden: true },
    { id: "F-3", title: "three", steps: 1, has_condition: true },
  ],
  selected: ["F-2", "F-1"],
  max: 8,
  ...over,
});

test("retestPlanFindings lists what the plan replays in the order it chose, and leaves out an id its list does not hold", () => {
  assert.deepEqual(retestPlanFindings(planBlock()).map((f) => f.id), ["F-2", "F-1"]);
  assert.deepEqual(retestPlanFindings(planBlock({ selected: ["F-9", "F-3"] })).map((f) => f.id), ["F-3"]);
  assert.deepEqual(retestPlanFindings(planBlock({ selected: [] })), []);
});

test("retestPlanLine and retestPlanNotes say what the plan replays and what was stored for each finding", () => {
  assert.equal(retestPlanLine(planBlock()), "Replays 2 of the 3 findings of that run that have a stored request (at most 8).");
  assert.equal(retestPlanLine(planBlock({ selected: ["F-1"], findings: [planBlock().findings[0]] })), "Replays 1 of the 1 finding of that run that has a stored request (at most 8).");
  assert.equal(retestPlanLine(planBlock({ selected: [] })), "No finding is chosen to replay yet.");
  assert.equal(retestPlanLine(planBlock({ max: 0 })), "Replays 2 of the 3 findings of that run that have a stored request (at most 8).");
  const f = planBlock().findings;
  assert.deepEqual(retestPlanNotes(f[0]), ["2 stored requests", RETEST_CONDITION_WORDS.has]);
  assert.deepEqual(retestPlanNotes(f[1]), ["1 stored request", RETEST_CONDITION_WORDS.none, RETEST_HIDDEN_NOTE]);
});

test("retestTargetSuggestion is the earlier run's address trimmed, and nothing when there is none", () => {
  assert.equal(retestTargetSuggestion({ of_target: " http://localhost:3000/ " }), "http://localhost:3000/");
  assert.equal(retestTargetSuggestion({}), "");
  assert.equal(retestTargetSuggestion(undefined), "");
});

test("every refusal code of a finding the retest cannot replay has words that name the finding; an unknown code still does", () => {
  const src = readFileSync(new URL("../../../internal/secassess/retest.go", import.meta.url), "utf8");
  const codes = [...src.matchAll(/^\s*Retest(?:UnknownFinding|NoRequest|TooMany|Duplicate)\s*=\s*"([a-z_]+)"/gm)].map((m) => m[1]);
  assert.deepEqual(codes.sort(), ["duplicate", "no_request", "too_many", "unknown_finding"], "the Go codes were read");
  assert.deepEqual(Object.keys(RETEST_REFUSED_WORDS).sort(), codes, "one row per code");
  for (const code of codes) {
    const w = retestRefusedWords(code, "F-7", 8);
    assert.match(w, /F-7/, code);
    assert.match(w, /\.$/, code);
    assert.doesNotMatch(w, /_/, `${code}: the raw code is not shown`);
  }
  assert.match(retestRefusedWords("too_many", "F-9", 8), /at most 8/);
  assert.equal(retestRefusedWords("a_new_code", "F-7"), "F-7 cannot be replayed.");
  assert.equal(retestRefusedWords("constructor", "F-7"), "F-7 cannot be replayed.");
});

test("the earlier run's kind is named in words, and a kind this table lacks is an assessment", () => {
  assert.equal(retestOfKindWords("pentest_local"), "penetration test");
  assert.equal(retestOfKindWords("red_team_local"), "red team exercise");
  assert.equal(retestOfKindWords("threat_model"), "assessment");
  assert.equal(retestOfKindWords(undefined), "assessment");
  assert.equal(retestOfKindWords("constructor"), "assessment");
  for (const w of Object.values(RETEST_OF_KIND_WORDS)) assert.doesNotMatch(w, /_/);
});

test("retestChoices is what the plan is read with: the earlier run and the findings, in the order chosen", () => {
  const req = { ofRun: "r1", findings: ["F-3", "F-1"], projectHash: "h" };
  const c = retestChoices(req);
  assert.deepEqual(c, { ofRun: "r1", findings: ["F-3", "F-1"] });
  c.findings!.push("F-9");
  assert.deepEqual(req.findings, ["F-3", "F-1"], "the request is not changed");
});

// ---- the kinds ----

test("the retest kind is found by what the server says (from_run), never by its name, and the card's grid never lists it", () => {
  const kind = (id: string, over: Partial<AssessKind> = {}): AssessKind => ({ id, title: id, summary: "", mode: "", launchable: true, sandbox: "required", target: "required", files: [], ...over });
  const kinds = [kind("threat_model"), kind("pentest_local"), kind("a_retest_by_another_name", { from_run: true }), kind("red_team_local", { exercise: true })];
  assert.equal(retestKindOf(kinds)?.id, "a_retest_by_another_name");
  assert.deepEqual(cardKinds(kinds).map((k) => k.id), ["threat_model", "pentest_local", "red_team_local"]);
  assert.equal(retestKindOf([kind("pentest_retest")]), undefined, "a kind named like it but not marked is not the retest");
  assert.equal(retestKindOf(undefined), undefined);
  assert.deepEqual(cardKinds(undefined), []);
  assert.deepEqual(cardKinds([kind("pentest_retest", { from_run: false })]).map((k) => k.id), ["pentest_retest"]);
});

// ---- the label of a finding ----

const view = (run: string, at: string, results: RetestResultView[]): RetestView => ({ run, at, state: "valid", started: true, asked: results.map((r) => r.finding), results });
const res = (finding: string, result: string, over: Partial<RetestResultView> = {}): RetestResultView => ({ finding, result, ...over });

test("retestsByFinding: the newest retest's label is first, older ones follow, and a finding no retest labelled has none", () => {
  const m = retestsByFinding([
    view("new", "2026-11-16T09:00:00Z", [res("F-1", "reproduced"), res("F-3", "inconclusive")]),
    view("mid", "2026-11-15T09:00:00Z", [res("F-1", "not_reproduced"), res("F-2", "reproduced")]),
    view("old", "2026-11-14T09:00:00Z", [res("F-1", "inconclusive")]),
  ]);
  assert.deepEqual(m.get("F-1")!.map((x) => [x.run, x.result.result]), [["new", "reproduced"], ["mid", "not_reproduced"], ["old", "inconclusive"]]);
  assert.deepEqual(m.get("F-2")!.map((x) => x.run), ["mid"], "a label from an older retest stands when a newer one gave none");
  assert.deepEqual(m.get("F-3")!.map((x) => x.run), ["new"]);
  assert.equal(m.get("F-4"), undefined);
});

test("retestsByFinding carries what the label needs to be shown: the retest, its date and whether the target started", () => {
  const rt = { ...view("r", "2026-11-16T09:00:00Z", [res("F-1", "reproduced", { note: "n" })]), started: false, state: "partial" };
  const first = retestsByFinding([rt]).get("F-1")![0];
  assert.deepEqual({ run: first.run, at: first.at, state: first.state, started: first.started, note: first.result.note }, { run: "r", at: "2026-11-16T09:00:00Z", state: "partial", started: false, note: "n" });
});

test("retestsByFinding ignores what is not shaped like a retest", () => {
  assert.equal(retestsByFinding(undefined).size, 0);
  assert.equal(retestsByFinding(null).size, 0);
  assert.equal(retestsByFinding([{ run: "x", at: "t", state: "valid", started: true, asked: [], results: undefined as never }]).size, 0);
  assert.equal(retestsByFinding([view("x", "t", [res("", "reproduced")])]).size, 0, "a result with no finding id");
  assert.equal(retestsByFinding([null as never]).size, 0);
});

test("retestsByFinding orders the labels by the date each retest ran, newest first, and shows that date (N-11)", () => {
  const rt = (run: string, ranAt: string | undefined, checkedAt: string, result: string): RetestView => ({ ...view(run, checkedAt, [res("F-1", result)]), ...(ranAt === undefined ? {} : { launched_at: ranAt }) });
  const rows: [string, RetestView[], string[], string[]][] = [
    ["already newest first", [rt("new", "2026-11-16T09:00:00Z", "2026-11-16T09:30:00Z", "reproduced"), rt("old", "2026-11-14T09:00:00Z", "2026-11-14T09:30:00Z", "reproduced")], ["new", "old"], ["2026-11-16T09:00:00Z", "2026-11-14T09:00:00Z"]],
    ["listed oldest first: the dates decide", [rt("old", "2026-11-14T09:00:00Z", "2026-11-14T09:30:00Z", "reproduced"), rt("new", "2026-11-16T09:00:00Z", "2026-11-16T09:30:00Z", "reproduced")], ["new", "old"], ["2026-11-16T09:00:00Z", "2026-11-14T09:00:00Z"]],
    ["the older retest was checked again later: the run date decides, not the check date", [rt("old", "2026-11-14T09:00:00Z", "2026-11-18T09:00:00Z", "reproduced"), rt("new", "2026-11-16T09:00:00Z", "2026-11-16T09:30:00Z", "not_reproduced")], ["new", "old"], ["2026-11-16T09:00:00Z", "2026-11-14T09:00:00Z"]],
    ["an answer with no run date falls back to the check date", [rt("old", undefined, "2026-11-14T09:30:00Z", "reproduced"), rt("new", undefined, "2026-11-16T09:30:00Z", "reproduced")], ["new", "old"], ["2026-11-16T09:30:00Z", "2026-11-14T09:30:00Z"]],
    ["the same date keeps the server's order", [rt("a", "2026-11-16T09:00:00Z", "2026-11-16T09:30:00Z", "reproduced"), rt("b", "2026-11-16T09:00:00Z", "2026-11-16T09:31:00Z", "reproduced")], ["a", "b"], ["2026-11-16T09:00:00Z", "2026-11-16T09:00:00Z"]],
    ["a date that cannot be read goes last", [rt("bad", "yesterday", "also not a date", "reproduced"), rt("ok", "2026-11-16T09:00:00Z", "2026-11-16T09:30:00Z", "reproduced")], ["ok", "bad"], ["2026-11-16T09:00:00Z", "also not a date"]],
  ];
  for (const [name, input, runs, dates] of rows) {
    const got = retestsByFinding(input).get("F-1")!;
    assert.deepEqual(got.map((x) => x.run), runs, name);
    assert.deepEqual(got.map((x) => x.at), dates, name + ": the date shown is the one it is ordered by");
  }
  assert.equal(retestRanAt({ launched_at: "2026-11-16T09:00:00Z", at: "2026-11-17T00:00:00Z" }), "2026-11-16T09:00:00Z");
  assert.equal(retestRanAt({ launched_at: "", at: "2026-11-17T00:00:00Z" }), "2026-11-17T00:00:00Z");
  assert.equal(retestRanAt({ at: "2026-11-17T00:00:00Z" }), "2026-11-17T00:00:00Z");
});

test("retestStanding: a newest label that claims little does not leave an older reproduced label unmentioned, and says what each one's log is (N-11)", () => {
  const ran = (n: number) => `2026-11-${10 + n}T09:00:00Z`;
  const one = (n: number, result: string, over: Partial<RetestResultView> = {}) => ({ run: `r${n}`, at: ran(n), state: "valid", started: true, result: res("F-1", result, over) });
  const logged = { evidence_state: "logged" } as const;
  const unlogged = { evidence_state: "unlogged", evidence_reason: "replay_incomplete" } as const;
  const noLog = { evidence_state: "unlogged", evidence_reason: "not_replayed" } as const;
  const fmt = (iso: string) => `on ${iso.slice(0, 10)}`;
  const NEWER_UNBACKED = "The newer label has no log behind it.";
  const NEWER_INCONCLUSIVE = "The newer retest was inconclusive and claims nothing.";
  const rows: [string, ReturnType<typeof one>[], string | null][] = [
    ["a finding with one label", [one(3, "not_reproduced", unlogged)], null],
    ["newest reproduced: it already draws the eye", [one(3, "reproduced", logged), one(2, "not_reproduced", logged)], null],
    ["newest reproduced, an older reproduced too", [one(3, "reproduced", logged), one(2, "reproduced", logged)], null],
    ["newest not reproduced and backed by its log: the newer label stands", [one(3, "not_reproduced", logged), one(2, "reproduced", logged)], null],
    ["newest not reproduced with no log, older reproduced and backed", [one(3, "not_reproduced", unlogged), one(2, "reproduced", logged)], `${NEWER_UNBACKED} An older retest (on 2026-11-12) labelled this finding reproduced, and its log backs that label.`],
    ["newest not reproduced with no log, older reproduced with no log either", [one(3, "not_reproduced", unlogged), one(2, "reproduced", noLog)], `${NEWER_UNBACKED} An older retest (on 2026-11-12) labelled this finding reproduced, with no log behind that label either.`],
    ["newest not reproduced and its target did not start", [one(3, "not_reproduced", { evidence_state: "not_started" }), one(2, "reproduced", logged)], `${NEWER_UNBACKED} An older retest (on 2026-11-12) labelled this finding reproduced, and its log backs that label.`],
    ["newest not reproduced with no log, but no older retest reproduced it", [one(3, "not_reproduced", unlogged), one(2, "not_reproduced", logged), one(1, "inconclusive")], null],
    ["newest inconclusive, older reproduced and backed", [one(3, "inconclusive"), one(2, "reproduced", logged)], `${NEWER_INCONCLUSIVE} An older retest (on 2026-11-12) labelled this finding reproduced, and its log backs that label.`],
    ["newest inconclusive, older only not reproduced", [one(3, "inconclusive"), one(2, "not_reproduced", logged)], null],
    ["the most recent older reproduced label is the one named", [one(4, "not_reproduced", unlogged), one(3, "not_reproduced", logged), one(2, "reproduced", noLog), one(1, "reproduced", logged)], `${NEWER_UNBACKED} An older retest (on 2026-11-12) labelled this finding reproduced, with no log behind that label either.`],
    ["a label this view does not know says nothing", [one(3, "withdrawn"), one(2, "reproduced", logged)], null],
  ];
  for (const [name, list, want] of rows) assert.equal(retestStanding(list, fmt), want, name);
  assert.equal(retestStanding([], fmt), null);
  assert.equal(retestStanding([one(2, "not_reproduced", unlogged), one(1, "reproduced", logged)]), "The newer label has no log behind it. An older retest (2026-11-11T09:00:00Z) labelled this finding reproduced, and its log backs that label.", "the date is printed as given without a formatter");
  // Neither a fix nor a pass: the sentences carry no clearance words, and no code.
  for (const [, list] of rows) {
    const s = retestStanding(list, fmt);
    if (s) assert.doesNotMatch(s, /\b(fixed|resolved|closed|safe|secure|passed|verified)\b|_/i, s);
  }
});

test("the fixture's pen test with two retests gives F-1 the newer retest's label and F-2 the newer one's too", () => {
  const m = retestsByFinding(FIXTURE_PT_RETESTED.retests);
  assert.equal(m.get("F-1")![0].result.result, "reproduced");
  assert.equal(m.get("F-1")![1].result.result, "not_reproduced");
  assert.equal(m.get("F-2")![0].result.result, "not_reproduced");
  assert.equal(m.get("F-2")![1].result.result, "reproduced");
  assert.equal(m.get("F-3")!.length, 1);
  assert.equal(m.get("F-6"), undefined);
});

// ---- the words of a label and of a log reading ----

test("retestEvidenceWords: the findings' own words for the log, the reason's sentence and never the code", () => {
  const ev = (result: string, evidence_state?: string, evidence_reason?: string) => retestEvidenceWords({ result, evidence_state: evidence_state as never, evidence_reason });
  // An inconclusive label claims nothing, so it has no reading, whatever the server sent.
  assert.equal(ev("inconclusive"), null);
  assert.equal(ev("inconclusive", "logged"), null);
  const rep = ev("reproduced", "logged")!;
  assert.deepEqual([rep.state, rep.label, rep.tone], ["logged", "Helper log backs the label", "info"]);
  assert.match(rep.detail, /returned|meets the stored condition/);
  assert.match(rep.detail, /control request's response does not/);
  assert.match(rep.detail, /file the agent can write/);
  const not = ev("not_reproduced", "logged")!;
  assert.match(not.detail, /does not meet the stored condition/);
  assert.match(not.detail, /does not show the weakness is gone from your code or from production/);
  assert.notEqual(rep.detail, not.detail, "each label says what its own match is");
  const unlogged = ev("not_reproduced", "unlogged", "replay_incomplete")!;
  assert.deepEqual([unlogged.state, unlogged.label, unlogged.tone], ["unlogged", "No log", "neutral"]);
  assert.ok(unlogged.detail.startsWith(EVIDENCE_REASON_WORDS.replay_incomplete), unlogged.detail);
  assert.doesNotMatch(unlogged.detail, /replay_incomplete/);
  assert.match(unlogged.detail, /agent can write any file in the run folder/);
  assert.ok(ev("reproduced", "unlogged", "not_replayed")!.detail.startsWith(EVIDENCE_REASON_WORDS.not_replayed));
  assert.ok(ev("not_reproduced", "unlogged", "condition_still_holds")!.detail.startsWith(EVIDENCE_REASON_WORDS.condition_still_holds));
  // No reason, or a state the server never sends, reads as no log; a code this view has no words for is the generic sentence with its underscores out.
  assert.match(ev("reproduced", "unlogged")!.detail, /^Observer has no request log that backs this label\./);
  assert.equal(ev("reproduced")!.label, "No log");
  assert.match(ev("reproduced", "unlogged", "a_new_reason")!.detail, /^Observer has no request log that backs this finding \(a new reason\)\./);
  const ns = ev("reproduced", "not_started")!;
  assert.deepEqual([ns.state, ns.label, ns.tone], ["not_started", "Not started", "neutral"]);
  assert.equal(ns.detail, EVIDENCE_REASON_WORDS.target_not_started);
  assert.equal(ev("not_reproduced", "not_started", "probe_helper_off")!.detail, EVIDENCE_REASON_WORDS.probe_helper_off);
});

test("retestReading carries the label, the reading of the log and the sentence that nothing was closed", () => {
  const r = retestReading(res("F-1", "not_reproduced", { evidence_state: "logged" }));
  assert.equal(r.label, RETEST_RESULT_WORDS.not_reproduced);
  assert.equal(r.evidence?.label, "Helper log backs the label");
  assert.equal(r.nothingClosed, "Nothing was closed: this is one replay of the stored request, read against the stored condition.");
  assert.equal(r.nothingClosed, RETEST_NOTHING_CLOSED);
  assert.equal(retestReading(res("F-1", "inconclusive")).evidence, null);
});

test("a label is never worded or toned as a fix, whatever its log says", () => {
  const fixed = /\b(fixed|resolved|closed as|solved|patched|remediated|no longer vulnerable)\b/i;
  for (const result of ["reproduced", "not_reproduced", "inconclusive"]) {
    for (const [state, reason] of [["logged", ""], ["unlogged", "replay_incomplete"], ["unlogged", "condition_still_holds"], ["unlogged", ""], ["not_started", ""], ["", ""]]) {
      const w = retestReading(res("F-1", result, { evidence_state: state as never, evidence_reason: reason }));
      const text = `${w.label.label} ${w.label.detail} ${w.evidence?.label ?? ""} ${w.evidence?.detail ?? ""}`;
      assert.doesNotMatch(text, fixed, `${result} ${state} ${reason}`);
      assert.doesNotMatch(text, BANNED, `${result} ${state} ${reason}: ${text.match(BANNED)?.[0]}`);
      assert.notEqual(w.label.tone, "success", result);
      assert.notEqual(w.evidence?.tone, "success", `${result} ${state}`);
    }
  }
});

// ---- a retest's summary and its results ----

test("retestSummaryCounts and retestSummaryLine: the five counters in order, a missing one as 0, and no summary as nothing", () => {
  const s = { replayed: 5, reproduced: 1, not_reproduced: 2, inconclusive: 1, missing: 1 };
  assert.deepEqual(retestSummaryCounts(s).map((c) => [c.label, c.n]), [["Chosen", 5], ["Reproduced", 1], ["Not reproduced", 2], ["Inconclusive", 1], ["Not labelled", 1]]);
  assert.equal(retestSummaryLine(s), "5 findings chosen: 1 reproduced, 2 not reproduced, 1 inconclusive, 1 not labelled.");
  assert.equal(retestSummaryLine({ replayed: 1, reproduced: 0, not_reproduced: 1, inconclusive: 0, missing: 0 }), "1 finding chosen: 0 reproduced, 1 not reproduced, 0 inconclusive, 0 not labelled.");
  assert.deepEqual(retestSummaryCounts({ replayed: 3 }).map((c) => c.n), [3, 0, 0, 0, 0]);
  assert.deepEqual(retestSummaryCounts({ replayed: -2, reproduced: Number.NaN as never }).map((c) => c.n), [0, 0, 0, 0, 0]);
  assert.deepEqual(retestSummaryCounts(undefined), []);
  assert.deepEqual(retestSummaryCounts(null), []);
  assert.equal(retestSummaryLine(undefined), "");
  assert.deepEqual(RETEST_SUMMARY_PARTS.map((p) => p.key), ["replayed", "reproduced", "not_reproduced", "inconclusive", "missing"], "the Go summary's members");
  for (const p of RETEST_SUMMARY_PARTS) assert.doesNotMatch(p.label, /_/);
});

test("retestRows: one row for each result in the agent's order, with the earlier finding's own title, a category title and the requests the label cites", () => {
  const rows = retestRows(FIXTURE_RETEST.record.result.rt, FIXTURE_VOCAB);
  assert.deepEqual(rows.map((r) => [r.finding, r.result]), [["F-1", "reproduced"], ["F-2", "not_reproduced"], ["F-3", "inconclusive"], ["F-5", "not_reproduced"]]);
  assert.equal(rows[0].title, "Entry search is injectable");
  assert.equal(rows[0].categoryTitle, "Input validation");
  assert.equal(rows[0].label, RETEST_RESULT_WORDS.reproduced);
  assert.deepEqual(rows[0].cited, [{ id: "p1", role: "attack" }, { id: "p2", role: "control" }]);
  assert.equal(rows[0].evidence?.label, "Helper log backs the label");
  assert.equal(rows[1].evidence?.label, "No log");
  assert.deepEqual(rows[1].cited, [{ id: "p3", role: "attack" }]);
  assert.equal(rows[2].evidence, null, "an inconclusive label has no reading of the log");
  assert.deepEqual(rows[2].cited, []);
  assert.equal(rows[2].note, "The error page changed, so the stored condition could not be compared.");
});

test("retestRows: a result with no title reads as its finding id, a category the vocabulary lacks as its id, and no category as not stated", () => {
  const r = (over: object) => retestRows({ results: [{ finding: "F-9", result: "inconclusive", ...over }] })[0];
  assert.equal(r({}).title, "F-9");
  assert.equal(r({ title: "  " }).title, "F-9");
  assert.equal(r({ title: "T" }).title, "T");
  assert.equal(r({ category: "ZZZZ" }).categoryTitle, "ZZZZ");
  assert.equal(r({}).categoryTitle, "Not stated");
  assert.deepEqual(r({ attack: "p1", evidence: ["p1", "p7"] }).cited, [{ id: "p1", role: "attack" }, { id: "p7", role: "cited" }], "an id is named once");
  assert.deepEqual(retestRows(undefined), []);
  assert.deepEqual(retestRows({ results: undefined }), []);
});

test("retestNotLabelled lists what the retest was asked for and gave no label, in the order asked", () => {
  const d = FIXTURE_RETEST.record.result.rt;
  assert.deepEqual(retestNotLabelled(["F-1", "F-2", "F-3", "F-5", "F-6"], d), ["F-6"]);
  assert.deepEqual(retestNotLabelled(["F-6", "F-1", "F-7"], d), ["F-6", "F-7"]);
  assert.deepEqual(retestNotLabelled([], d), []);
  assert.deepEqual(retestNotLabelled(undefined, d), []);
  assert.deepEqual(retestNotLabelled(["F-1"], undefined), ["F-1"]);
});

// ---- the red team's objective ----

test("objectiveLength counts characters, not bytes or code units; clipObjective keeps whole characters", () => {
  const rows: [string, string, number][] = [
    ["empty", "", 0],
    ["ascii", "abc", 3],
    ["accented letters are one character each", "éàü", 3],
    ["an emoji is one character, however many bytes", "a😀b", 3],
    ["a letter outside the basic plane", "𝒳𝒴", 2],
    ["a joined sequence counts its code points", "👨‍👩", 3],
  ];
  for (const [name, s, n] of rows) assert.equal(objectiveLength(s), n, name);
  assert.ok(new TextEncoder().encode("a😀b").length > 3, "bytes would give another count");
  assert.equal(clipObjective("a😀b😀c", 3), "a😀b");
  assert.equal(clipObjective("abc", 3), "abc");
  assert.equal(clipObjective("abcd", 3), "abc");
  assert.equal(clipObjective("abc", 0), "");
  assert.equal(clipObjective("x".repeat(250)).length, OBJECTIVE_MAX);
  assert.equal(OBJECTIVE_MAX, 200);
  // A string cut at the bound is never cut inside a character: it stays valid text.
  assert.equal(clipObjective("😀".repeat(5), 2), "😀😀");
});

test("objectiveCounterLine and objectiveCleanedNote: the count against the bound, and what the task carries when the server cleaned it", () => {
  assert.equal(objectiveCounterLine("", 200), "0 of 200 characters");
  assert.equal(objectiveCounterLine("abc", 200), "3 of 200 characters");
  assert.equal(objectiveCounterLine("a😀", 50), "2 of 50 characters");
  const rows: [string, string, string | undefined, string][] = [
    ["nothing typed", "", "", ""],
    ["blank typed", "   ", "", ""],
    ["the task carries what was typed", "reach the export", "reach the export", ""],
    ["surrounding spaces are not a change", "  reach the export ", "reach the export", ""],
    ["the server took out backticks", "reach `the` export", "reach the export", "The task carries it as: reach the export"],
    ["the server left it all out", "```", "", "The task carries no objective: the server left out everything you typed."],
    ["the plan has no objective block yet", "reach", undefined, "The task carries no objective: the server left out everything you typed."],
  ];
  for (const [name, typed, inForce, want] of rows) assert.equal(objectiveCleanedNote(typed, inForce), want, name);
  // One short sentence (N-17): the placeholder shows what to type and the Exercise tab says whose the objective is.
  assert.match(OBJECTIVE_HELP, /^Leave it empty and the agent states an objective of its own\.$/);
  assert.equal(OBJECTIVE_HELP.split(/[.!?]/).filter((x) => x.trim() !== "").length, 1);
});

test("objectiveReading says whose the objective is, and never attributes an objective to the developer on the agent's say-so", () => {
  const rows: [string, Parameters<typeof objectiveReading>[0], string, string][] = [
    ["the developer's", { objective: "Reach X", objective_by: "developer" }, "developer", "In your words"],
    ["the agent's", { objective: "Reach X", objective_by: "agent" }, "agent", "Stated by the agent"],
    ["none recorded", { objective: "", objective_by: "developer" }, "none", "No objective was recorded"],
    ["blank text is none", { objective: "   ", objective_by: "agent" }, "none", "No objective was recorded"],
    ["no objective at all", {}, "none", "No objective was recorded"],
    ["no exercise", undefined, "none", "No objective was recorded"],
    ["a text with no source", { objective: "Reach X" }, "unknown", "Whose words these are is not stated"],
    ["a source this view does not know", { objective: "Reach X", objective_by: "operator" }, "unknown", "Whose words these are is not stated"],
  ];
  for (const [name, ex, source, label] of rows) {
    const r = objectiveReading(ex);
    assert.deepEqual([r.source, r.sourceLabel], [source, label], name);
    assert.equal(r.text, source === "none" ? "" : "Reach X", name);
  }
  assert.deepEqual(Object.keys(OBJECTIVE_SOURCE_WORDS).sort(), ["agent", "developer", "none", "unknown"]);
  assert.equal(objectiveReading(FIXTURE_RED_TEAM.record.result.pt!.exercise).source, "developer");
  assert.equal(objectiveReading(FIXTURE_RED_TEAM_AGENT.record.result.pt!.exercise).source, "agent");
});

// ---- the red team's chain ----

test("chainRows: the steps in the agent's order with the finding each used by title, a step with none as none, and the result in words", () => {
  const rows = chainRows(FIXTURE_RED_TEAM.record.result.pt);
  assert.deepEqual(rows.map((r) => r.n), [1, 2, 3, 4, 5]);
  assert.deepEqual(rows.map((r) => r.finding?.id ?? null), [null, "F-3", "F-1", "F-4", null]);
  assert.equal(rows[2].finding?.title, "Entry search is injectable");
  assert.deepEqual(rows.map((r) => r.result.label), ["Achieved", "Achieved", "Achieved", "Partly achieved", "Blocked"]);
  assert.deepEqual(rows.map((r) => r.result.code), ["achieved", "achieved", "achieved", "partly", "blocked"]);
  assert.equal(rows[0].step, "Read the front page and the error pages to learn what the app is built with.");
  assert.equal(rows[4].stop, "", "a step the agent gave no opinion for");
  assert.match(rows[2].stop, /parameterised query/);
  for (const r of rows) assert.doesNotMatch(r.result.label, /_/);
});

test("chainRows: a finding the model does not hold is not named, an unknown result reads as written, and no chain is no row", () => {
  const f = [finding("F-1", { title: "One" })];
  const row = (step: object) => chainRows({ findings: f, exercise: { chain: [{ step: "s", result: "achieved", ...step }] } })[0];
  assert.equal(row({ finding: "F-1" }).finding?.title, "One");
  assert.equal(row({ finding: "F-9" }).finding, null, "a citation the model does not hold");
  assert.equal(row({ finding: "" }).finding, null);
  assert.equal(row({}).finding, null);
  assert.equal(row({ result: "gone_wrong" }).result.label, "Gone wrong");
  assert.equal(row({ result: "gone_wrong" }).result.tone, "neutral");
  assert.equal(row({ stop: "  an opinion  " }).stop, "an opinion");
  assert.deepEqual(chainRows({ findings: f, exercise: {} }), []);
  assert.deepEqual(chainRows({ findings: f }), []);
  assert.deepEqual(chainRows(undefined), []);
  // The step's text is carried as the agent wrote it: nothing is cleaned or composed here.
  assert.equal(row({ step: "<b>a</b> `x`" }).step, "<b>a</b> `x`");
});

test("chainRows carries no word Observer made up: only the step, the stop and the labels of the result table", () => {
  const rows = chainRows(FIXTURE_RED_TEAM.record.result.pt);
  const labels = new Set(Object.values(CHAIN_RESULT_WORDS).map((w) => w.label));
  for (const r of rows) assert.ok(labels.has(r.result.label), r.result.label);
  assert.deepEqual(Object.keys(rows[0]).sort(), ["finding", "n", "result", "step", "stop"]);
});

test("chainCountsLine says how the steps went, by the result's words, and nothing for no step", () => {
  assert.equal(chainCountsLine(chainRows(FIXTURE_RED_TEAM.record.result.pt)), "5 steps: 3 achieved, 1 partly achieved, 1 blocked.");
  assert.equal(chainCountsLine(chainRows({ findings: [], exercise: { chain: [{ step: "s", result: "blocked" }] } })), "1 step: 1 blocked.");
  assert.equal(chainCountsLine([]), "");
});

test("the chain's constants: the heading says it is the agent's opinion, and an empty chain says the agent recorded no steps", () => {
  assert.equal(CHAIN_STOP_HEADING, "What would have detected or stopped it (the agent's opinion)");
  assert.match(CHAIN_STOP_HEADING, /agent's opinion/);
  assert.equal(CHAIN_NO_FINDING, "no finding");
  assert.equal(CHAIN_EMPTY_WORDS, "The agent recorded no steps.");
});

// ---- the run rows ----

test("runRetestLine names the earlier run when the list still has it and says how many findings were chosen, never that they were replayed", () => {
  const earlier = "Penetration test, 14 Nov, 10:00";
  const rows: [string, Parameters<typeof runRetestLine>[0], string | undefined, string][] = [
    ["a retest of a listed pen test", { retest_of: "0123456789abcdef", retest_findings: ["F-1", "F-2", "F-3"] }, earlier, "Retest of the earlier run (Penetration test, 14 Nov, 10:00): 3 findings chosen."],
    ["one finding", { retest_of: "0123456789abcdef", retest_findings: ["F-1"] }, earlier, "Retest of the earlier run (Penetration test, 14 Nov, 10:00): 1 finding chosen."],
    ["an earlier run no longer in the list", { retest_of: "0123456789abcdef", retest_findings: ["F-1", "F-2"] }, undefined, "Retest of an earlier run that is no longer in the list: 2 findings chosen."],
    ["an empty label is no label", { retest_of: "0123456789abcdef", retest_findings: ["F-1"] }, "  ", "Retest of an earlier run that is no longer in the list: 1 finding chosen."],
    ["no findings recorded", { retest_of: "0123456789abcdef" }, earlier, "Retest of the earlier run (Penetration test, 14 Nov, 10:00): no finding recorded."],
    ["not a retest", { retest_findings: ["F-1"] }, earlier, ""],
    ["a blank earlier run", { retest_of: "  " }, earlier, ""],
    ["nothing", {}, undefined, ""],
  ];
  for (const [name, run, e, want] of rows) {
    assert.equal(runRetestLine(run, e), want, name);
    // A run is named, never identified by its id (fix round 3, UX-7).
    assert.doesNotMatch(runRetestLine(run, e), /0123456789|01234567/, `${name}: an id`);
  }
});

test("runObjectiveLine shows a red team run's objective clipped, whole when it fits, and nothing without one", () => {
  assert.equal(runObjectiveLine({ objective: "Reach the export" }), "Objective: Reach the export");
  assert.equal(runObjectiveLine({ objective: "  Reach the export  " }), "Objective: Reach the export");
  assert.equal(runObjectiveLine({ objective: "" }), "");
  assert.equal(runObjectiveLine({}), "");
  const long = "x".repeat(150);
  const line = runObjectiveLine({ objective: long });
  assert.equal(line, `Objective: ${"x".repeat(89)}…`);
  assert.equal(objectiveLength(line.slice("Objective: ".length)), 90);
  assert.equal(runObjectiveLine({ objective: "😀".repeat(100) }, 10), `Objective: ${"😀".repeat(9)}…`, "cut by characters");
  assert.equal(runObjectiveLine({ objective: "x".repeat(90) }), `Objective: ${"x".repeat(90)}`, "exactly the bound is kept whole");
});

// ---- the module's words ----

/** Every string inside a value, however deep. */
function strings(v: unknown, out: string[] = []): string[] {
  if (typeof v === "string") out.push(v);
  else if (Array.isArray(v)) for (const x of v) strings(x, out);
  else if (v && typeof v === "object") for (const x of Object.values(v)) strings(x, out);
  return out;
}

test("no word this module says reads as a clearance (the shared list), and none is a raw code", () => {
  const all: string[] = [];
  const add = (label: string, v: unknown) => strings(v).forEach((s) => all.push(`${label}: ${s}`));
  add("kind words", [RETEST_OF_KIND_WORDS, RETEST_CONDITION_WORDS, RETEST_HIDDEN_NOTE, OBJECTIVE_SOURCE_WORDS, OBJECTIVE_HELP]);
  add("chain constants", [CHAIN_STOP_HEADING, CHAIN_NO_FINDING, CHAIN_EMPTY_WORDS]);
  for (const code of Object.keys(RETEST_REFUSED_WORDS)) add(`refused ${code}`, retestRefusedWords(code, "F-1", 8));
  add("lines", [retestCountLine(3, 8), retestLimitWords(8), retestOfferLine(0, 8), retestOfferLine(12, 8), retestPlanLine(planBlock()), retestSummaryLine({ replayed: 4, reproduced: 1, not_reproduced: 1, inconclusive: 1, missing: 1 })]);
  add("objective", [objectiveCounterLine("abc"), objectiveCleanedNote("a`b", "ab"), objectiveCleanedNote("```", "")]);
  for (const result of ["reproduced", "not_reproduced", "inconclusive"]) {
    for (const state of ["logged", "unlogged", "not_started", ""]) {
      for (const reason of [...Object.keys(EVIDENCE_REASON_WORDS), ""]) {
        const w = retestReading(res("F-1", result, { evidence_state: state as never, evidence_reason: reason }));
        add(`reading ${result} ${state} ${reason}`, [w.label.label, w.label.detail, w.evidence?.label, w.evidence?.detail, w.nothingClosed]);
      }
    }
  }
  add("chain", chainCountsLine(chainRows(FIXTURE_RED_TEAM.record.result.pt)));
  add("run lines", [runRetestLine({ retest_of: "abcdefgh12", retest_findings: ["F-1"] }, undefined), runRetestLine({ retest_of: "abcdefgh12", retest_findings: ["F-1"] }, "Penetration test, 14 Nov"), runObjectiveLine({ objective: "Reach the export" })]);
  assert.ok(all.length > 100, "the sweep reached the strings");
  assert.deepEqual(all.filter((s) => BANNED.test(s)), [], "banned words in Observer's own wording");
  // A label, a reading or a line a person reads never shows a snake_case code.
  assert.deepEqual(all.filter((s) => /\b[a-z]+_[a-z_]+\b/.test(s.replace(/^[^:]*: /, ""))), [], "a raw code reaches the page");
});

test("the module is pure: no fetch, no React, no DOM, no clock", () => {
  const src = readFileSync(new URL("./secAssessRetest.ts", import.meta.url), "utf8");
  for (const re of [/\bfetch\s*\(/, /from\s+["']react/, /\bdocument\./, /\bwindow\./, /\bDate\.now/, /new Date\(/, /Math\.random/, /localStorage/, /dangerouslySetInnerHTML/, /\beval\(/, /\bsetTimeout\(/]) {
    assert.doesNotMatch(src, re, String(re));
  }
  // It imports the model's words and types, and secAssess.ts's types only.
  assert.doesNotMatch(src, /import \{[^}]*\} from "\.\/secAssess\.ts"/, "secAssess.ts is imported for types only");
});
