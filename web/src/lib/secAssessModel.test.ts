import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { ASSESS_FATAL_WORDS, ASSESS_MODEL_PATH, ASSESS_WINDOW_UNRECORDED, assessRefTallyWords } from "./secAssess.ts";
import { HELP_REGISTRY } from "./help.ts";
import { clearanceRegExp, parseClearanceList } from "./secAssessBanned.ts";
import {
  ANSWER_FIXTURES,
  FIXTURE_PT,
  FIXTURE_PT_EMPTY,
  FIXTURE_PT_EVIDENCE,
  FIXTURE_PT_NOT_STARTED,
  FIXTURE_PT_PARTIAL,
  FIXTURE_PT_REFUSED_ALL,
  FIXTURE_SINCE_SIMILAR,
  FIXTURE_TM,
  FIXTURE_TM_PARTIAL,
  FIXTURE_TM_REFUSED_ALL,
  FIXTURE_VOCAB,
  fixtureBigPentest,
  fixtureBigThreatModel,
  fixtureFindings,
  fixtureThreats,
} from "./secAssessModelFixture.ts";
import {
  AGENT_COVERAGE_WORDS,
  BANDS,
  COVERAGE_WORDS,
  DEFAULT_FINDING_SORT,
  DIAGRAM_SETTING_LABELS,
  EFFORT_WORDS,
  ENUM_WORDS,
  EVIDENCE_AGENT_WRITABLE,
  EVIDENCE_LABELS,
  EVIDENCE_NOT_PROOF,
  EVIDENCE_REASON_WORDS,
  EVIDENCE_STATES,
  PROBE_EXCERPT_CAPTION,
  PROBE_ROLE_WORDS,
  REFUSED_WORDS,
  STATUS_WORDS,
  agentCoverageWords,
  categoryLabel,
  categoryName,
  citedProbes,
  coverageReasonExpected,
  effortWords,
  enumWords,
  evidenceReasonLines,
  evidenceReasonSentence,
  evidenceState,
  evidenceSummaryLine,
  filterFindings,
  findingStatusNote,
  findingFacets,
  frameworkLabel,
  frameworkTitle,
  itemCounts,
  conditionText,
  jsonUnescapeOnce,
  limitsSummary,
  matchWords,
  matrixAbbr,
  mermaidCountsLine,
  mermaidCutLine,
  mermaidSettingsLine,
  mitRefsWords,
  mitigationSummary,
  defaultSince,
  modelSubtitle,
  modelTitle,
  partialNotice,
  probeIndex,
  probeLogNote,
  probeOutcome,
  probeExcerptCaption,
  probeRedirectLine,
  probeRoleWords,
  refusedWords,
  requestBody,
  requestHeaderLines,
  requestLine,
  pairingCounts,
  pairingNote,
  similarBasisWords,
  sinceCandidates,
  sortFindings,
  statusWords,
  threatMitSummary,
  unlistedWords,
  validationLine,
  HONEST_LIMITS,
  MIT_STATES,
  MIT_STATE_WORDS,
  REDACTION_NOTE_OFF,
  REF_BUDGET_UNRECORDED,
  REDACTION_NOTE_ON,
  REDACTION_SETTING_LABEL,
  assessModelPath,
  basisWords,
  bandCounts,
  bandTone,
  cvssLeftOutIds,
  cvssReading,
  CVSS_APART,
  CVSS_LEFT_OUT_CODES,
  CVSS_LEFT_OUT_NOTE,
  CVSS_NOTE,
  buildElementMatrix,
  coverageCountsLine,
  coverageWords,
  elementKey,
  elementName,
  evidenceWords,
  filterThreats,
  flowRows,
  howCheckedLines,
  limitsFor,
  missingLocated,
  mitigationState,
  modelOpenable,
  naturalCompare,
  redactionNote,
  findingsLegend,
  hasCvssScore,
  sortThreats,
  threatFacets,
  threatMitState,
  treeItems,
  type MitState,
  type FindingFilter,
  type FindingSort,
  type FindingSortKey,
  type ModelBand,
  type ModelRecord,
  type ModelRef,
  type ModelReport,
  type ModelIssue,
  type ModelThreat,
  type ModelTree,
  type EvidenceReport,
  type PTCoverage,
  type PTFinding,
  type PTMatch,
  type ThreatFilter,
  type ThreatModelDoc,
  type ThreatSortKey,
  type TreeItem,
} from "./secAssessModel.ts";
import {
  CHAIN_RESULTS,
  CHAIN_RESULT_WORDS,
  EXERCISE_STOP_NOTE,
  RETEST_NOTHING_CLOSED,
  RETEST_RESULTS,
  RETEST_RESULT_WORDS,
  chainResultWords,
  retestResultWords,
} from "./secAssessModel.ts";
import { FIXTURE_PT_RETESTED, FIXTURE_RED_TEAM, FIXTURE_RED_TEAM_AGENT, FIXTURE_RETEST } from "./secAssessModelFixture.ts";

// ---- builders ----

const zeroRefs = { found: 0, exists: 0, claimed_not_found: 0, missing: 0, invalid: 0, unchecked: 0 };
const ptDoc = FIXTURE_PT.record.result.pt!;

function tdoc(over: Partial<ThreatModelDoc> = {}): ThreatModelDoc {
  return { schema: "observer.threatmodel.v1", run_id: "r", generator: {}, scope: {}, system: {}, ...over };
}

function thr(id: string, over: Partial<ModelThreat> = {}): ModelThreat {
  return {
    id,
    title: `Threat ${id}`,
    framework: "stride",
    category: "tampering",
    element: { kind: "component", id: "c1" },
    rating: { likelihood: 1, impact: 1 },
    ...over,
  };
}

function ref(state?: ModelRef["state"]): ModelRef {
  return state === undefined ? { path: "a.ts", line: 1 } : { path: "a.ts", line: 1, state };
}

function record(report: Partial<ModelReport>, over: Partial<ModelRecord> = {}): ModelRecord {
  return {
    schema: 1,
    run_id: "r",
    validated_at: "2026-11-14T00:00:00Z",
    contract: "threatmodel.v1",
    source_bytes: 1,
    result: { report: { state: "valid", contract: "threatmodel.v1", refs: zeroRefs, sets: {}, ...report } },
    ...over,
  };
}

const ids = (xs: { id: string }[]) => xs.map((x) => x.id);

// ---- mitigation state ----

/** The ref state that reads as each mitigation state; "none" is an empty list, not a ref. */
const REF_FOR: Record<Exclude<MitState, "none">, ModelRef["state"]> = {
  found: "found",
  exists: "exists",
  claimed_not_found: "claimed_not_found",
  unchecked: "unchecked",
  not_located: "missing",
};

test("mitigationState: one row per way a reference list reads", () => {
  const rows: [string, ModelRef[] | undefined, MitState][] = [
    ["no list", undefined, "none"],
    ["empty list", [], "none"],
    ["found", [ref("found")], "found"],
    ["exists", [ref("exists")], "exists"],
    ["claimed not found", [ref("claimed_not_found")], "claimed_not_found"],
    ["unchecked", [ref("unchecked")], "unchecked"],
    ["no state yet reads as unchecked", [ref()], "unchecked"],
    ["missing reads as not located", [ref("missing")], "not_located"],
    ["invalid reads as not located", [ref("invalid")], "not_located"],
    ["a state this view does not know reads as unchecked", [{ path: "a", state: "weird" as never }], "unchecked"],
    ["a null entry is a place that cannot be located", [null as never], "not_located"],
    ["found beats everything", [ref("missing"), ref("unchecked"), ref("claimed_not_found"), ref("exists"), ref("found")], "found"],
    ["exists beats claimed", [ref("claimed_not_found"), ref("exists")], "exists"],
    ["claimed beats unchecked and missing", [ref("missing"), ref("unchecked"), ref("claimed_not_found")], "claimed_not_found"],
    ["unchecked beats missing", [ref("missing"), ref("unchecked")], "unchecked"],
    ["missing and invalid together", [ref("invalid"), ref("missing")], "not_located"],
  ];
  for (const [name, refs, want] of rows) assert.equal(mitigationState(refs), want, name);
});

test("mitigationState: every pair of states resolves to the stronger one, whatever the order", () => {
  const withRefs = MIT_STATES.filter((s): s is Exclude<MitState, "none"> => s !== "none");
  for (let i = 0; i < withRefs.length; i++) {
    for (let j = i + 1; j < withRefs.length; j++) {
      const strong = withRefs[i];
      const weak = withRefs[j];
      assert.equal(mitigationState([ref(REF_FOR[strong]), ref(REF_FOR[weak])]), strong, `${strong} over ${weak}`);
      assert.equal(mitigationState([ref(REF_FOR[weak]), ref(REF_FOR[strong])]), strong, `${weak} then ${strong}`);
    }
  }
});

test("threatMitState reads every ref of every existing mitigation", () => {
  const fx = FIXTURE_TM.record.result.tm!.threats!;
  const want: Record<string, MitState> = { "T-1": "found", "T-2": "exists", "T-3": "none", "T-4": "claimed_not_found", "T-5": "unchecked" };
  for (const t of fx) assert.equal(threatMitState(t), want[t.id], t.id);
  const rows: [string, ModelThreat, MitState][] = [
    ["no existing", thr("a"), "none"],
    ["an existing item with no refs", thr("a", { existing: [{ text: "x" }] }), "none"],
    ["an existing item with an empty list", thr("a", { existing: [{ text: "x", refs: [] }] }), "none"],
    ["the best across two items", thr("a", { existing: [{ text: "x", refs: [ref("missing")] }, { text: "y", refs: [ref("exists")] }] }), "exists"],
    ["missing[] refs are not mitigations", thr("a", { missing: [{ text: "m", refs: [ref("found")] }] }), "none"],
  ];
  for (const [name, t, want2] of rows) assert.equal(threatMitState(t), want2, name);
});

test("missingLocated counts missing items that name a place that exists", () => {
  const fx = FIXTURE_TM.record.result.tm!.threats!;
  assert.deepEqual(missingLocated(fx[0]), { located: 1, total: 1 });
  assert.deepEqual(missingLocated(fx[1]), { located: 0, total: 1 });
  assert.deepEqual(missingLocated(fx[2]), { located: 1, total: 1 });
  assert.deepEqual(missingLocated(fx[3]), { located: 0, total: 0 });
  const mixed = thr("a", {
    missing: [
      { text: "1", refs: [ref("exists")] },
      { text: "2", refs: [ref("missing")] },
      { text: "3" },
      { text: "4", refs: [ref("claimed_not_found"), ref("unchecked")] },
      { text: "5", refs: [ref("invalid"), ref("found")] },
    ],
  });
  assert.deepEqual(missingLocated(mixed), { located: 2, total: 5 });
});

test("the mitigation words: the three labels are exactly the plan's, and each state says what it does not mean", () => {
  assert.equal(MIT_STATE_WORDS.found.label, "Found near the cited line");
  assert.equal(MIT_STATE_WORDS.exists.label, "Location exists, nothing matched");
  assert.equal(MIT_STATE_WORDS.claimed_not_found.label, "Claimed, not found");
  const rows: [MitState, string, string][] = [
    ["found", "Found near the cited line", "success"],
    ["exists", "Location exists, nothing matched", "neutral"],
    ["claimed_not_found", "Claimed, not found", "warn"],
    ["unchecked", "Not checked", "neutral"],
    ["not_located", "Cited place not found", "warn"],
    ["none", "No reference cited", "neutral"],
  ];
  assert.deepEqual(Object.keys(MIT_STATE_WORDS).sort(), [...MIT_STATES].sort());
  for (const [state, label, tone] of rows) {
    assert.equal(MIT_STATE_WORDS[state].label, label, state);
    assert.equal(MIT_STATE_WORDS[state].tone, tone, state);
    assert.match(MIT_STATE_WORDS[state].detail, /^[A-Z].*\.$/, `${state} detail is a sentence`);
  }
  assert.match(MIT_STATE_WORDS.found.detail, /does not show the control works/);
  assert.match(MIT_STATE_WORDS.found.detail, /match window/);
  // Only a found reference earns credit; no other state reads as success.
  for (const s of MIT_STATES) if (s !== "found") assert.notEqual(MIT_STATE_WORDS[s].tone, "success", s);
});

// ---- elements ----

test("elementKey and elementName", () => {
  const doc = FIXTURE_TM.record.result.tm!;
  assert.equal(elementKey({ kind: "flow", id: "f-api-db" }), "flow:f-api-db");
  const rows: [string, { kind: string; id: string }, string][] = [
    ["a component by name", { kind: "component", id: "api" }, "Ledger API"],
    ["an actor by name", { kind: "actor", id: "anon" }, "Anonymous visitor"],
    ["an asset by name", { kind: "asset", id: "entries" }, "Ledger entries"],
    ["a zone by name", { kind: "zone", id: "z-data" }, "Data"],
    ["a flow as from to to, in names", { kind: "flow", id: "f-api-db" }, "Ledger API to Ledger database"],
    ["a flow from an actor", { kind: "flow", id: "f-user-web" }, "Signed-in user to Web client"],
    ["an entry point by kind and component", { kind: "entry_point", id: "ep-login" }, "http_route on Ledger API"],
    ["a component the model does not have falls back to the id", { kind: "component", id: "ghost" }, "ghost"],
    ["a flow the model does not have falls back to the id", { kind: "flow", id: "ghost" }, "ghost"],
    ["an unknown kind falls back to the id", { kind: "satellite", id: "api" }, "api"],
    ["a kind named like an object property falls back to the id", { kind: "constructor", id: "api" }, "api"],
  ];
  for (const [name, e, want] of rows) assert.equal(elementName(doc, e), want, name);
  // A flow whose endpoints are not in the model reads in ids; a flow endpoint may be an actor or a component.
  const odd = tdoc({ system: { flows: [{ id: "f", from: "x", to: "y" }], entry_points: [{ id: "e", component: "gone", kind: "cli" }] } });
  assert.equal(elementName(odd, { kind: "flow", id: "f" }), "x to y");
  assert.equal(elementName(odd, { kind: "entry_point", id: "e" }), "cli on gone");
});

test("a name that is text passes through untouched, as data", () => {
  const nasty = "<script>alert(1)</script> 日本語 🔒 & \"quotes\"";
  const doc = tdoc({
    system: {
      components: [{ id: "c1", name: nasty, type: "service" }],
      actors: [{ id: "a1", name: "<img src=x onerror=1>", kind: "anonymous" }],
      flows: [{ id: "f1", from: "a1", to: "c1" }],
    },
    threats: [thr("T-1", { title: nasty, description: nasty })],
  });
  assert.equal(elementName(doc, { kind: "component", id: "c1" }), nasty);
  assert.equal(elementName(doc, { kind: "flow", id: "f1" }), `<img src=x onerror=1> to ${nasty}`);
  assert.deepEqual(ids(filterThreats(doc, doc.threats!, { q: "<script>" })), ["T-1"]);
  assert.deepEqual(ids(filterThreats(doc, doc.threats!, { q: "日本" })), ["T-1"]);
  assert.deepEqual(ids(filterThreats(doc, doc.threats!, { q: "🔒" })), ["T-1"]);
  assert.equal(flowRows(doc)[0].toName, nasty);
  assert.equal(treeItems({ root: "r", nodes: [{ id: "n", label: nasty }] })[0].label, nasty);
  assert.equal(basisWords(nasty.replace(/\s+/g, "")).startsWith("The agent says: <script>"), true);
});

// ---- filtering ----

/** An independent statement of the filters, for the property tests. */
function matches(doc: ThreatModelDoc, t: ModelThreat, f: ThreatFilter): boolean {
  const compName = doc.system.components?.find((c) => c.id === t.element.id)?.name ?? t.element.id;
  const q = (f.q ?? "").trim().toLowerCase();
  return (
    (!f.framework || t.framework === f.framework) &&
    (!f.element || `${t.element.kind}:${t.element.id}` === f.element) &&
    (!f.status || t.status === f.status) &&
    (!f.band || t.band === f.band) &&
    (!f.mitigation || threatMitState(t) === f.mitigation) &&
    (q === "" || [t.id, t.title, t.category, compName, t.description ?? ""].some((s) => s.toLowerCase().includes(q)))
  );
}

/** A model with n threats spread over the filter values, and five components. */
function bigDoc(n: number): ThreatModelDoc {
  const fw = ["stride", "linddun", "owasp_llm", "owasp_agentic"];
  const st = ["identified", "mitigated", "partial", "accepted_by_design"];
  const mit: (ModelRef["state"] | null)[] = ["found", "exists", "claimed_not_found", "unchecked", "missing", null];
  const threats: ModelThreat[] = [];
  for (let i = 0; i < n; i++) {
    const m = mit[i % mit.length];
    threats.push(
      thr(`T-${i + 1}`, {
        title: `Threat number ${i + 1} about ${i % 3 === 0 ? "Injection" : "Sessions"}`,
        framework: fw[i % fw.length],
        category: i % 2 === 0 ? "tampering" : "LLM01",
        element: { kind: "component", id: `c${i % 5}` },
        description: i % 4 === 0 ? "reads the SECRET value" : undefined,
        status: i % 7 === 6 ? undefined : st[i % st.length],
        band: BANDS[i % 4],
        score: ((i * 7) % 25) + 1,
        existing: m ? [{ text: "x", refs: [ref(m)] }] : undefined,
      }),
    );
  }
  return tdoc({
    system: { components: [0, 1, 2, 3, 4].map((i) => ({ id: `c${i}`, name: `Component ${["Alpha", "Beta", "Gamma", "Delta", "Epsilon"][i]}`, type: "service" })) },
    threats,
  });
}

test("filterThreats: one row per filter on the fixture", () => {
  const all = FIXTURE_TM.record.result.tm!.threats!;
  const rows: [string, ThreatFilter, string[]][] = [
    ["no filter", {}, ["T-1", "T-2", "T-3", "T-4", "T-5"]],
    ["framework stride", { framework: "stride" }, ["T-1", "T-2", "T-3"]],
    ["framework linddun", { framework: "linddun" }, ["T-4"]],
    ["framework owasp_llm", { framework: "owasp_llm" }, ["T-5"]],
    ["framework none present", { framework: "owasp_agentic" }, []],
    ["element flow", { element: "flow:f-api-db" }, ["T-1", "T-3", "T-4"]],
    ["element component", { element: "component:api" }, ["T-2", "T-5"]],
    ["status identified", { status: "identified" }, ["T-1", "T-3"]],
    ["status partial", { status: "partial" }, ["T-2", "T-5"]],
    ["band critical", { band: "critical" }, ["T-1"]],
    ["band medium", { band: "medium" }, ["T-2", "T-5"]],
    ["mitigation found", { mitigation: "found" }, ["T-1"]],
    ["mitigation exists", { mitigation: "exists" }, ["T-2"]],
    ["mitigation claimed_not_found", { mitigation: "claimed_not_found" }, ["T-4"]],
    ["mitigation unchecked", { mitigation: "unchecked" }, ["T-5"]],
    ["mitigation none", { mitigation: "none" }, ["T-3"]],
    ["mitigation not_located", { mitigation: "not_located" }, []],
    ["q by id, any case", { q: "t-2" }, ["T-2"]],
    ["q by title", { q: "SQL INJECTION" }, ["T-1"]],
    ["q by category", { q: "llm01" }, ["T-5"]],
    ["q by element name", { q: "ledger database" }, ["T-1", "T-3", "T-4"]],
    ["q by description", { q: "connection string" }, ["T-3"]],
    ["q in nothing", { q: "zzz" }, []],
    ["q of spaces is not set", { q: "   " }, ["T-1", "T-2", "T-3", "T-4", "T-5"]],
    ["q is trimmed", { q: "  t-3  " }, ["T-3"]],
    ["two filters both apply", { framework: "stride", band: "high" }, ["T-3"]],
    ["three filters", { framework: "stride", status: "identified", mitigation: "none" }, ["T-3"]],
    ["filters that cannot meet", { framework: "linddun", band: "critical" }, []],
  ];
  for (const [name, f, want] of rows) assert.deepEqual(ids(filterThreats(FIXTURE_TM.record.result.tm!, all, f)), want, name);
});

test("filterThreats returns a new list and never reads a filter that is not set as a filter", () => {
  const doc = FIXTURE_TM.record.result.tm!;
  const all = doc.threats!;
  const out = filterThreats(doc, all, {});
  assert.notEqual(out, all);
  assert.deepEqual(out, all);
  // Empty strings and undefined are "not set".
  assert.deepEqual(ids(filterThreats(doc, all, { framework: "", status: "", q: "", element: undefined })), ids(all));
});

test("filterThreats never drops a threat it should keep: no cap, and the count is the true match count", () => {
  const doc = bigDoc(600);
  const all = doc.threats!;
  const values: ThreatFilter[] = [{}];
  for (const framework of [undefined, "stride", "owasp_llm"]) {
    for (const band of [undefined, "low", "critical"] as (ModelBand | undefined)[]) {
      for (const status of [undefined, "identified", "partial"]) {
        for (const mitigation of [undefined, "found", "none"] as (MitState | undefined)[]) {
          for (const q of [undefined, "injection", "SECRET", "component beta", "t-12", "T-60"]) {
            values.push({ framework, band, status, mitigation, q });
          }
        }
      }
    }
  }
  assert.ok(values.length > 400);
  for (const f of values) {
    const want = all.filter((t) => matches(doc, t, f));
    const got = filterThreats(doc, all, f);
    assert.deepEqual(ids(got), ids(want), JSON.stringify(f));
    assert.ok(got.length >= want.length, "never below the true match count");
  }
  // No cap: 600 threats pass an empty filter, and a filter that matches them all keeps all.
  assert.equal(filterThreats(doc, all, {}).length, 600);
  assert.equal(filterThreats(doc, all, { q: "threat number" }).length, 600);
});

test("filterThreats copes with a threat that has no title, no description, no element", () => {
  const doc = tdoc({ threats: [{ id: "T-1", framework: "stride", category: "x", rating: { likelihood: 1, impact: 1 } } as never] });
  assert.deepEqual(ids(filterThreats(doc, doc.threats!, { q: "t-1" })), ["T-1"]);
  assert.deepEqual(ids(filterThreats(doc, doc.threats!, { q: "nothing" })), []);
  assert.deepEqual(ids(filterThreats(doc, doc.threats!, { element: "component:c1" })), []);
});

// ---- sorting ----

test("naturalCompare orders ids as people read them", () => {
  const sorted = ["T-10", "T-2", "T-1", "t-3", "T-02", "T-100", "A-1", "T-1a", "T-"].sort(naturalCompare);
  assert.deepEqual(sorted, ["A-1", "T-", "T-1", "T-1a", "T-02", "T-2", "t-3", "T-10", "T-100"]);
  assert.equal(naturalCompare("T-2", "T-10"), -1);
  assert.equal(naturalCompare("T-10", "T-2"), 1);
  assert.equal(naturalCompare("x", "x"), 0);
  // A digit run longer than a safe integer still compares as a number.
  assert.equal(naturalCompare("n99999999999999999999", "n100000000000000000000"), -1);
});

test("sortThreats: one row per key and direction", () => {
  const doc = FIXTURE_TM.record.result.tm!;
  const all = doc.threats!;
  const rows: [string, ThreatSortKey, "asc" | "desc", string[]][] = [
    ["band high to low", "band", "desc", ["T-1", "T-3", "T-2", "T-5", "T-4"]],
    ["band low to high", "band", "asc", ["T-4", "T-5", "T-2", "T-3", "T-1"]],
    ["id ascending", "id", "asc", ["T-1", "T-2", "T-3", "T-4", "T-5"]],
    ["id descending", "id", "desc", ["T-5", "T-4", "T-3", "T-2", "T-1"]],
    ["title ascending, any case", "title", "asc", ["T-4", "T-3", "T-5", "T-2", "T-1"]],
    ["title descending", "title", "desc", ["T-1", "T-2", "T-5", "T-3", "T-4"]],
    ["element ascending, by name", "element", "asc", ["T-2", "T-5", "T-1", "T-3", "T-4"]],
    ["element descending", "element", "desc", ["T-1", "T-3", "T-4", "T-2", "T-5"]],
    ["status ascending", "status", "asc", ["T-4", "T-1", "T-3", "T-2", "T-5"]],
    ["status descending", "status", "desc", ["T-2", "T-5", "T-1", "T-3", "T-4"]],
  ];
  for (const [name, key, dir, want] of rows) assert.deepEqual(ids(sortThreats(doc, all, { key, dir })), want, name);
});

test("sortThreats: an id sorts naturally, ties by id, the unscored last, whatever the direction", () => {
  const doc = tdoc();
  const t = [
    thr("T-10", { score: 9, band: "medium" }),
    thr("T-2", { score: 9, band: "medium" }),
    thr("T-1", { score: 20, band: "critical" }),
    thr("T-20"),
    thr("T-3", { score: 4, band: "low" }),
    thr("T-4", { band: "high" }),
  ];
  assert.deepEqual(ids(sortThreats(doc, t, { key: "id", dir: "asc" })), ["T-1", "T-2", "T-3", "T-4", "T-10", "T-20"]);
  assert.deepEqual(ids(sortThreats(doc, t, { key: "band", dir: "desc" })), ["T-1", "T-2", "T-10", "T-3", "T-4", "T-20"]);
  assert.deepEqual(ids(sortThreats(doc, t, { key: "band", dir: "asc" })), ["T-3", "T-2", "T-10", "T-1", "T-4", "T-20"]);
});

test("sortThreats returns a copy, leaves the input alone and is stable for equal keys", () => {
  const doc = tdoc();
  const a = thr("T-1", { title: "same", score: 5 });
  const b = thr("T-1", { title: "same", score: 5, description: "second" });
  const c = thr("T-1", { title: "same", score: 5, description: "third" });
  const input = [c, a, b];
  const before = input.map((x) => x);
  for (const key of ["band", "id", "title", "element", "status"] as ThreatSortKey[]) {
    for (const dir of ["asc", "desc"] as const) {
      const out = sortThreats(doc, input, { key, dir });
      assert.notEqual(out, input);
      assert.deepEqual(out, [c, a, b], `${key} ${dir} keeps input order for equal keys`);
    }
  }
  assert.deepEqual(input, before);
  assert.equal(sortThreats(doc, [], { key: "band", dir: "desc" }).length, 0);
});

test("sortThreats puts a threat with no rating, score or band last and does not throw", () => {
  const doc = tdoc();
  const bare = { id: "T-0", title: "no rating", framework: "stride", category: "x", element: { kind: "component", id: "c" } } as never as ModelThreat;
  const t = [bare, thr("T-1", { score: 3, band: "low" }), thr("T-2", { band: "high" })];
  assert.deepEqual(ids(sortThreats(doc, t, { key: "band", dir: "desc" })), ["T-1", "T-2", "T-0"]);
  assert.deepEqual(ids(sortThreats(doc, t, { key: "band", dir: "asc" })), ["T-1", "T-2", "T-0"]);
  // An unknown key falls back to the id order rather than failing.
  assert.deepEqual(ids(sortThreats(doc, t, { key: "nope" as never, dir: "asc" })), ["T-0", "T-1", "T-2"]);
});

// ---- facets and band counts ----

test("threatFacets on the fixture", () => {
  const f = threatFacets(FIXTURE_TM.record.result.tm!);
  assert.deepEqual(f.frameworks, [
    { value: "stride", n: 3 },
    { value: "linddun", n: 1 },
    { value: "owasp_llm", n: 1 },
  ]);
  assert.deepEqual(f.elements, [
    { value: "component:api", label: "Ledger API", n: 2 },
    { value: "flow:f-api-db", label: "Ledger API to Ledger database", n: 3 },
  ]);
  assert.deepEqual(f.statuses, [
    { value: "identified", n: 2 },
    { value: "partial", n: 2 },
    { value: "accepted_by_design", n: 1 },
  ]);
  assert.deepEqual(f.bands, [
    { value: "critical", n: 1 },
    { value: "high", n: 1 },
    { value: "medium", n: 2 },
    { value: "low", n: 1 },
  ]);
  assert.deepEqual(f.mitigations, [
    { value: "found", n: 1 },
    { value: "exists", n: 1 },
    { value: "claimed_not_found", n: 1 },
    { value: "unchecked", n: 1 },
    { value: "none", n: 1 },
  ]);
});

test("threatFacets: known frameworks and statuses in the published order, others after, counts add up", () => {
  const doc = tdoc({
    threats: [
      thr("1", { framework: "zeta", status: "weird" }),
      thr("2", { framework: "owasp_agentic", status: "accepted_by_design" }),
      thr("3", { framework: "stride", status: "identified" }),
      thr("4", { framework: "alpha", status: "partial" }),
      thr("5", { framework: "linddun", status: "mitigated" }),
      thr("6", { framework: "owasp_llm" }),
      thr("7", { framework: "stride", band: "medium" }),
    ],
  });
  const f = threatFacets(doc);
  assert.deepEqual(f.frameworks.map((x) => x.value), ["stride", "linddun", "owasp_llm", "owasp_agentic", "alpha", "zeta"]);
  assert.deepEqual(f.statuses.map((x) => x.value), ["identified", "mitigated", "partial", "accepted_by_design", "weird"]);
  assert.equal(f.frameworks.reduce((n, x) => n + x.n, 0), 7);
  // A band no threat has is not offered; a threat with no band is in no band facet.
  assert.deepEqual(f.bands, [{ value: "medium", n: 1 }]);
  assert.deepEqual(threatFacets(tdoc()), { frameworks: [], elements: [], statuses: [], bands: [], mitigations: [] });
});

test("bandCounts lists all four bands lowest to highest, zeros included", () => {
  assert.deepEqual(bandCounts(FIXTURE_TM.record.result.tm!.threats!), [
    { band: "low", n: 1 },
    { band: "medium", n: 2 },
    { band: "high", n: 1 },
    { band: "critical", n: 1 },
  ]);
  assert.deepEqual(bandCounts(FIXTURE_PT.record.result.pt!.findings!), [
    { band: "low", n: 1 },
    { band: "medium", n: 1 },
    { band: "high", n: 0 },
    { band: "critical", n: 1 },
  ]);
  const zeros = [
    { band: "low", n: 0 },
    { band: "medium", n: 0 },
    { band: "high", n: 0 },
    { band: "critical", n: 0 },
  ];
  assert.deepEqual(bandCounts([]), zeros);
  assert.deepEqual(bandCounts([{}, { band: "weird" as never }]), zeros);
});

test("bandTone: one table", () => {
  const rows: [string | undefined, string][] = [
    ["critical", "danger"],
    ["high", "danger"],
    ["medium", "warn"],
    ["low", "info"],
    [undefined, "neutral"],
    ["", "neutral"],
    ["severe", "neutral"],
    ["Critical", "neutral"],
    ["constructor", "neutral"],
    ["__proto__", "neutral"],
    ["toString", "neutral"],
  ];
  for (const [band, tone] of rows) assert.equal(bandTone(band), tone, String(band));
});

// ---- the matrix ----

const STATE_CODE = { analysed: "A", waived: "W", empty: "E", na: "-" } as const;

test("buildElementMatrix on the fixture: columns, cells, reasons, threat ids and totals", () => {
  const m = buildElementMatrix(FIXTURE_TM.record.result.tm!, tm_cov(), FIXTURE_VOCAB);
  assert.deepEqual(
    m.columns.map((c) => c.id),
    ["spoofing", "tampering", "repudiation", "information_disclosure", "denial_of_service", "elevation_of_privilege", "linkability", "identifiability", "non_repudiation", "detectability", "disclosure_of_information", "unawareness", "non_compliance"],
  );
  assert.deepEqual(m.columns.slice(0, 6).map((c) => [c.letter, c.label, c.framework]), [
    ["S", "Spoofing", "stride"],
    ["T", "Tampering", "stride"],
    ["R", "Repudiation", "stride"],
    ["I", "Information disclosure", "stride"],
    ["D", "Denial of service", "stride"],
    ["E", "Elevation of privilege", "stride"],
  ]);
  for (const c of m.columns.slice(6)) {
    assert.equal(c.framework, "linddun");
    assert.equal(c.letter, undefined);
  }
  assert.deepEqual(m.rows.map((r) => r.key), ["component:web", "component:api", "component:db", "component:audit", "component:idp", "actor:anon", "actor:user", "flow:f-user-web", "flow:f-web-api", "flow:f-anon-api", "flow:f-api-db", "flow:f-api-idp"]);
  const codes = Object.fromEntries(m.rows.map((r) => [r.key, r.cells.map((c) => STATE_CODE[c.state]).join("")]));
  assert.deepEqual(codes, {
    "component:web": "EEEEEE-------",
    "component:api": "AEEEEE-------",
    "component:db": "-E-EE--------",
    "component:audit": "-EWEE--------",
    "component:idp": "E-E----------",
    "actor:anon": "W-E----------",
    "actor:user": "E-E----------",
    "flow:f-user-web": "-E-EE--------",
    "flow:f-web-api": "-E-EE--------",
    "flow:f-anon-api": "-E-EE--------",
    "flow:f-api-db": "-A-AE-AEEEEEE",
    "flow:f-api-idp": "-E-EE--------",
  });
  const byKey = Object.fromEntries(m.rows.map((r) => [r.key, r]));
  // Each cell carries its own category, in column order.
  for (const r of m.rows) assert.deepEqual(r.cells.map((c) => c.category), m.columns.map((c) => c.id));
  assert.deepEqual(byKey["component:api"].cells[0], { category: "spoofing", state: "analysed", threats: ["T-2"] });
  assert.deepEqual(byKey["component:audit"].cells[2], {
    category: "repudiation",
    state: "waived",
    reason: "The audit log is append-only and written by the API only.",
    threats: [],
  });
  assert.equal(byKey["actor:anon"].cells[0].reason, "An anonymous visitor claims no identity, so there is nothing to spoof.");
  assert.deepEqual(byKey["flow:f-api-db"].cells[1].threats, ["T-1"]);
  assert.deepEqual(byKey["flow:f-api-db"].cells[3].threats, ["T-3"]);
  assert.deepEqual(byKey["flow:f-api-db"].cells[6].threats, ["T-4"]);
  // A cell that does not apply is "na", not an empty cell, and carries nothing.
  assert.deepEqual(byKey["component:db"].cells[0], { category: "spoofing", state: "na", threats: [] });
  // The flow row reads in the model's names, not the ids the report spells; the others as named.
  assert.equal(byKey["flow:f-api-db"].name, "Ledger API to Ledger database");
  assert.equal(byKey["component:api"].name, "Ledger API");
  assert.equal(byKey["flow:f-api-db"].class, "data_flow");
  // Totals are the report's three numbers, as given.
  assert.deepEqual(m.totals, { analysed: 4, waived: 2, empty: 41 });
});

function tm_cov() {
  return FIXTURE_TM.record.result.report.tm!;
}

test("buildElementMatrix: LINDDUN columns appear only when some row has a LINDDUN cell", () => {
  const stride = (state: "analysed" | "empty" = "empty") => ({ category: "tampering", state });
  const cov = { analysed: 0, waived: 0, empty: 1, rows: [{ kind: "component", id: "c1", name: "C", class: "process", cells: [stride()] }] };
  const doc = tdoc({ system: { components: [{ id: "c1", name: "C", type: "service" }] } });
  const m = buildElementMatrix(doc, cov, FIXTURE_VOCAB);
  assert.equal(m.columns.length, 6);
  assert.deepEqual(m.columns.map((c) => c.framework), Array(6).fill("stride"));
  assert.equal(m.rows[0].cells.length, 6);
  const withL = buildElementMatrix(doc, { ...cov, rows: [...cov.rows, { kind: "flow", id: "f", class: "data_flow", cells: [{ category: "linkability", state: "empty" as const }] }] }, FIXTURE_VOCAB);
  assert.equal(withL.columns.length, 13);
  assert.equal(withL.rows[0].cells.length, 13);
  assert.equal(withL.rows[0].cells[6].state, "na");
});

test("buildElementMatrix: hostile inputs are ignored, never an error", () => {
  const doc = tdoc({
    system: { components: [{ id: "c1", name: "C", type: "service" }] },
    threats: [
      thr("T-1", { element: { kind: "component", id: "ghost" }, category: "spoofing" }),
      thr("T-2", { element: { kind: "component", id: "c1" }, category: "spoofing" }),
      thr("T-3", { element: { kind: "component", id: "c1" }, category: "spoofing" }),
      thr("T-4", { element: { kind: "component", id: "c1" }, category: "tampering" }),
    ],
    no_threat: [
      { element: { kind: "flow", id: "ghost" }, category: "tampering", reason: "ghost flow" },
      { element: { kind: "component", id: "c1" }, category: "repudiation", reason: "no log here" },
      { element: { kind: "component", id: "c1" }, category: "tampering", reason: "also analysed" },
    ],
  });
  const cov = {
    analysed: 2,
    waived: 1,
    empty: 0,
    rows: [
      {
        kind: "component",
        id: "c1",
        name: "From the report",
        class: "process",
        cells: [
          { category: "spoofing", state: "analysed" as const },
          { category: "tampering", state: "analysed" as const },
          { category: "repudiation", state: "waived" as const },
          { category: "made_up_category", state: "empty" as const },
        ],
      },
      { kind: "component", id: "no_such_component", class: "process", cells: [{ category: "spoofing", state: "empty" as const }] },
    ],
  };
  const m = buildElementMatrix(doc, cov, FIXTURE_VOCAB);
  assert.equal(m.columns.length, 6, "a category outside the vocabulary is no column");
  assert.deepEqual(m.rows.map((r) => r.name), ["C", "no_such_component"]);
  const c1 = m.rows[0];
  assert.deepEqual(c1.cells[0].threats, ["T-2", "T-3"]);
  assert.equal(c1.cells[0].reason, undefined);
  // An analysed cell has no waiver reason even when the model lists one for it.
  assert.equal(c1.cells[1].state, "analysed");
  assert.equal(c1.cells[1].reason, undefined);
  assert.equal(c1.cells[2].reason, "no log here");
  // The row of an element the model does not have still draws, with the id as its name.
  assert.deepEqual(m.rows[1].cells.map((c) => c.state), ["empty", "na", "na", "na", "na", "na"]);
  // The row's own name is used when the model has no such element; with neither, the id.
  const named = buildElementMatrix(tdoc(), { analysed: 0, waived: 0, empty: 1, rows: [{ ...cov.rows[0], id: "x" }] }, FIXTURE_VOCAB);
  assert.equal(named.rows[0].name, "From the report");
  // A waived cell with no matching no_threat row has no reason.
  const noReason = buildElementMatrix(tdoc(), { analysed: 0, waived: 1, empty: 0, rows: [{ kind: "actor", id: "a", class: "external_entity", cells: [{ category: "spoofing", state: "waived" }] }] }, FIXTURE_VOCAB);
  assert.equal(noReason.rows[0].cells[0].state, "waived");
  assert.equal("reason" in noReason.rows[0].cells[0], false);
  // Nothing to lay out.
  assert.deepEqual(buildElementMatrix(tdoc(), { analysed: 0, waived: 0, empty: 0 }, FIXTURE_VOCAB).rows, []);
  assert.deepEqual(buildElementMatrix(tdoc(), { analysed: 0, waived: 0, empty: 0 }, FIXTURE_VOCAB).totals, { analysed: 0, waived: 0, empty: 0 });
});

// ---- flows ----

test("flowRows on the fixture", () => {
  const rows = flowRows(FIXTURE_TM.record.result.tm!);
  assert.equal(rows.length, 5);
  const brief = rows.map((r) => ({
    id: r.id,
    from: r.fromName,
    to: r.toName,
    data: r.data,
    protocol: r.protocol,
    authn: r.authn,
    encrypted: r.encrypted,
    personalData: r.personalData,
    crossing: r.crossing,
    zones: r.zones,
    weak: r.weakCrossing,
  }));
  assert.deepEqual(brief, [
    { id: "f-user-web", from: "Signed-in user", to: "Web client", data: ["Session tokens"], protocol: "https", authn: "session", encrypted: "yes", personalData: false, crossing: true, zones: ["Internet"], weak: false },
    { id: "f-web-api", from: "Web client", to: "Ledger API", data: ["Ledger entries"], protocol: "https", authn: "session", encrypted: "yes", personalData: false, crossing: true, zones: ["Internet", "Application"], weak: false },
    { id: "f-anon-api", from: "Anonymous visitor", to: "Ledger API", data: [], protocol: "https", authn: "none", encrypted: "unknown", personalData: false, crossing: true, zones: ["Internet", "Application"], weak: true },
    { id: "f-api-db", from: "Ledger API", to: "Ledger database", data: ["Ledger entries"], protocol: "postgres", authn: "basic", encrypted: "no", personalData: true, crossing: true, zones: ["Application", "Data"], weak: true },
    { id: "f-api-idp", from: "Ledger API", to: "Identity provider", data: [], protocol: "https", authn: "token", encrypted: "yes", personalData: false, crossing: true, zones: ["Application", "Internet"], weak: false },
  ]);
  assert.deepEqual([rows[0].from, rows[0].to], ["user", "web"], "the ids stay beside the names");
});

test("flowRows: crossing, weak crossing and the unknown display, one row per rule", () => {
  const doc = tdoc({
    system: {
      zones: [{ id: "za", name: "Zone A" }],
      components: [
        { id: "a1", name: "A1", type: "service", zone: "za" },
        { id: "a2", name: "A2", type: "service", zone: "za" },
        { id: "b1", name: "B1", type: "service", zone: "zb" },
        { id: "n1", name: "No zone", type: "service" },
        { id: "nameless", name: "", type: "service", zone: "zc" },
      ],
      actors: [{ id: "u", name: "User", kind: "end_user" }],
      assets: [{ id: "as", name: "The asset", sensitivity: "restricted" }],
      flows: [
        { id: "same", from: "a1", to: "a2" },
        { id: "differ", from: "a1", to: "b1" },
        { id: "differ-weak", from: "a1", to: "b1", authn: "none" },
        { id: "differ-unenc", from: "a1", to: "b1", encrypted: "no" },
        { id: "differ-both-ok", from: "a1", to: "b1", authn: "session", encrypted: "yes" },
        { id: "no-zone-one-side", from: "a1", to: "n1" },
        { id: "actor-end", from: "u", to: "a1" },
        { id: "stated", from: "u", to: "a1", crosses: ["za", "zq"] },
        { id: "stated-weak", from: "u", to: "a1", crosses: ["za"], authn: "none" },
        { id: "inside-weak", from: "a1", to: "a2", authn: "none", encrypted: "no" },
        { id: "data", from: "a1", to: "a2", data: ["as", "gone"], personal_data: true },
        { id: "empty-strings", from: "a1", to: "a2", protocol: "", authn: "", encrypted: "", crosses: [], data: [] },
        { id: "ghost-ends", from: "x", to: "y" },
        { id: "nameless-cross", from: "nameless", to: "a1" },
      ],
    },
  });
  const by = Object.fromEntries(flowRows(doc).map((r) => [r.id, r]));
  const rows: [string, boolean, boolean, string[]][] = [
    // id, crossing, weakCrossing, zones
    ["same", false, false, []],
    ["differ", true, false, []],
    ["differ-weak", true, true, []],
    ["differ-unenc", true, true, []],
    ["differ-both-ok", true, false, []],
    ["no-zone-one-side", false, false, []],
    ["actor-end", false, false, []],
    ["stated", true, false, ["Zone A", "zq"]],
    ["stated-weak", true, true, ["Zone A"]],
    ["inside-weak", false, false, []],
    ["data", false, false, []],
    ["empty-strings", false, false, []],
    ["ghost-ends", false, false, []],
    ["nameless-cross", true, false, []],
  ];
  for (const [id, crossing, weak, zones] of rows) {
    assert.equal(by[id].crossing, crossing, `${id} crossing`);
    assert.equal(by[id].weakCrossing, weak, `${id} weak`);
    assert.deepEqual(by[id].zones, zones, `${id} zones`);
  }
  assert.deepEqual(by.data.data, ["The asset", "gone"]);
  assert.equal(by.data.personalData, true);
  assert.equal(by.same.personalData, false);
  // An empty protocol, authn or encrypted reads "unknown" in the row; a missing field too.
  assert.deepEqual([by["empty-strings"].protocol, by["empty-strings"].authn, by["empty-strings"].encrypted], ["unknown", "unknown", "unknown"]);
  assert.deepEqual([by.same.protocol, by.same.authn, by.same.encrypted], ["unknown", "unknown", "unknown"]);
  // Endpoints the model does not have read as their ids.
  assert.deepEqual([by["ghost-ends"].fromName, by["ghost-ends"].toName], ["x", "y"]);
  assert.equal(by.differ.fromName, "A1");
  // A component with no name reads as its id, and still has its zone.
  assert.equal(by["nameless-cross"].fromName, "nameless");
});

test("flowRows leaves no flow out: 10,000 flows resolve to their own names", () => {
  const n = 10_000;
  const components = Array.from({ length: n }, (_, i) => ({ id: `c${i}`, name: `Component ${i}`, type: "service", zone: i % 2 === 0 ? "z-even" : "z-odd" }));
  const flows = Array.from({ length: n }, (_, i) => ({ id: `f${i}`, from: `c${i}`, to: `c${(i + 1) % n}`, data: [`as${i}`] }));
  const assets = Array.from({ length: n }, (_, i) => ({ id: `as${i}`, name: `Asset ${i}`, sensitivity: "internal" }));
  const doc = tdoc({ system: { components, flows, assets } });
  const t0 = performance.now();
  const rows = flowRows(doc);
  const ms = performance.now() - t0;
  assert.equal(rows.length, n);
  assert.deepEqual(rows.map((r) => r.id), flows.map((f) => f.id));
  assert.equal(rows[0].fromName, "Component 0");
  assert.equal(rows[n - 1].toName, "Component 0");
  assert.equal(rows[1234].data[0], "Asset 1234");
  // Even and odd components sit in different zones, so every flow crosses.
  assert.equal(rows.filter((r) => r.crossing).length, n);
  assert.ok(ms < 5_000, `flowRows took ${ms} ms`);
});

// ---- trees ----

/** Every node of a nested list, parents first, without recursion. */
function walkAll(items: TreeItem[]): TreeItem[] {
  const out: TreeItem[] = [];
  const stack = [...items].reverse();
  while (stack.length > 0) {
    const it = stack.pop()!;
    out.push(it);
    for (let i = it.children.length - 1; i >= 0; i--) stack.push(it.children[i]);
  }
  return out;
}

const brief = (items: TreeItem[]): unknown[] => items.map((i) => (i.children.length ? [i.id, brief(i.children)] : i.id));

test("treeItems: the fixture tree, depths, op and leaf", () => {
  const items = treeItems(FIXTURE_TM.record.result.tm!.attack_trees![0]);
  assert.deepEqual(brief(items), [["n1", ["n2", "n3"]], ["n4", ["n5", "n6"]]]);
  assert.deepEqual(items.map((i) => [i.depth, i.op, i.leaf]), [[0, "or", false], [0, "and", false]]);
  assert.deepEqual(items[0].children.map((i) => [i.depth, i.op, i.leaf]), [[1, undefined, true], [1, undefined, true]]);
  assert.equal(items[0].label, "Inject into the search query");
});

test("treeItems: one row per link shape", () => {
  const n = (id: string, parent?: string) => ({ id, label: id.toUpperCase(), ...(parent === undefined ? {} : { parent }) });
  const rows: [string, ModelTree, unknown[]][] = [
    ["no nodes", { root: "r" }, []],
    ["empty nodes", { root: "r", nodes: [] }, []],
    ["empty parent hangs from the root", { root: "r", nodes: [n("a", ""), n("b")] }, ["a", "b"]],
    ["a parent that is not in the tree hangs from the root", { root: "r", nodes: [n("a", "ghost"), n("b", "a")] }, [["a", ["b"]]]],
    ["the root's own text as a parent is not a node", { root: "r", nodes: [n("a", "r")] }, ["a"]],
    ["a child listed before its parent", { root: "r", nodes: [n("b", "a"), n("a")] }, [["a", ["b"]]]],
    ["siblings keep input order", { root: "r", nodes: [n("a"), n("c", "a"), n("b", "a"), n("d", "a"), n("e")] }, [["a", ["c", "b", "d"]], "e"]],
    ["a self parent hangs from the root", { root: "r", nodes: [n("a", "a"), n("b", "a")] }, [["a", ["b"]]]],
    ["a two-node cycle is cut at its first node", { root: "r", nodes: [n("a", "b"), n("b", "a")] }, [["a", ["b"]]]],
    ["a cycle's descendant stays under it", { root: "r", nodes: [n("c", "b"), n("a", "b"), n("b", "a")] }, [["a", [["b", ["c"]]]]]],
    ["a three-node cycle", { root: "r", nodes: [n("x"), n("a", "c"), n("b", "a"), n("c", "b")] }, ["x", ["a", [["b", ["c"]]]]]],
    ["a cycle beside a proper tree", { root: "r", nodes: [n("a", "b"), n("b", "a"), n("t"), n("u", "t")] }, [["t", ["u"]], ["a", ["b"]]]],
  ];
  for (const [name, tree, want] of rows) {
    const items = treeItems(tree);
    assert.deepEqual(brief(items), want, name);
    // Whatever the shape, each node appears exactly once.
    const all = walkAll(items).map((i) => i.id).sort();
    assert.deepEqual(all, (tree.nodes ?? []).map((x) => x.id).sort(), `${name}: every node once`);
  }
});

test("treeItems: a duplicate id still shows each node once", () => {
  const items = treeItems({ root: "r", nodes: [{ id: "a", label: "first" }, { id: "a", label: "second", parent: "a" }, { id: "b", label: "child", parent: "a" }] });
  const all = walkAll(items);
  assert.equal(all.length, 3);
  assert.deepEqual(all.map((i) => i.label).sort(), ["child", "first", "second"]);
});

test("treeItems: 10,000 nodes in a chain, a fan and a ring do not overflow the stack", () => {
  const n = 10_000;
  const chain = Array.from({ length: n }, (_, i) => ({ id: `n${i}`, label: `Node ${i}`, ...(i === 0 ? {} : { parent: `n${i - 1}` }) }));
  const items = treeItems({ root: "r", nodes: chain });
  assert.equal(items.length, 1);
  const all = walkAll(items);
  assert.equal(all.length, n);
  assert.equal(all[n - 1].depth, n - 1);

  const fan = Array.from({ length: n }, (_, i) => ({ id: `n${i}`, label: `Node ${i}`, ...(i === 0 ? {} : { parent: "n0" }) }));
  const fanItems = treeItems({ root: "r", nodes: fan });
  assert.equal(fanItems.length, 1);
  assert.equal(fanItems[0].children.length, n - 1);
  assert.equal(fanItems[0].children[0].id, "n1");
  assert.equal(fanItems[0].children[n - 2].id, `n${n - 1}`);

  const ring = Array.from({ length: n }, (_, i) => ({ id: `n${i}`, label: `Node ${i}`, parent: `n${(i + 1) % n}` }));
  const ringItems = treeItems({ root: "r", nodes: ring });
  assert.equal(ringItems.length, 1);
  assert.equal(ringItems[0].id, "n0", "cut at the first node in input order");
  assert.equal(walkAll(ringItems).length, n);

  const orphans = Array.from({ length: n }, (_, i) => ({ id: `n${i}`, label: `Node ${i}`, parent: `gone${i}` }));
  assert.equal(treeItems({ root: "r", nodes: orphans }).length, n);
});

// ---- pen test coverage ----

test("COVERAGE_WORDS: one row per effective word", () => {
  const rows: [string, string, string][] = [
    ["tested_claimed", "Tested (claimed)", "neutral"],
    ["tested_logged", "Tested (logged request)", "info"],
    ["skipped", "Skipped", "warn"],
    ["skipped_not_started", "Skipped (target not started)", "warn"],
    ["not_applicable", "Not applicable", "neutral"],
    ["tool_unavailable", "Tool unavailable", "warn"],
    ["missing", "No row from the agent", "warn"],
  ];
  assert.deepEqual(Object.keys(COVERAGE_WORDS).sort(), rows.map((r) => r[0]).sort());
  for (const [word, label, tone] of rows) {
    assert.equal(COVERAGE_WORDS[word].label, label, word);
    assert.equal(COVERAGE_WORDS[word].tone, tone, word);
    assert.match(COVERAGE_WORDS[word].detail, /^[A-Z].*\.$/, `${word} detail is a sentence`);
  }
  assert.equal(COVERAGE_WORDS.tested_claimed.detail, "The agent says it tested this category; no request log backs it.");
  // The claim is never worded as backed: the claimed word is neutral, never success.
  assert.notEqual(COVERAGE_WORDS.tested_claimed.tone, "success");
  // Every effective word the server sends is worded.
  for (const r of [...FIXTURE_PT.record.result.report.pt!.rows, ...FIXTURE_PT_EMPTY.record.result.report.pt!.rows]) {
    assert.ok(r.effective in COVERAGE_WORDS, r.effective);
  }
});

test("coverageWords: a word this view does not know reads neutral, as sent", () => {
  assert.equal(coverageWords("tested_claimed"), COVERAGE_WORDS.tested_claimed);
  for (const w of ["something_new", "constructor", "__proto__", ""]) {
    const x = coverageWords(w);
    assert.equal(x.tone, "neutral", w);
    assert.equal(typeof x.label, "string");
    assert.equal(typeof x.detail, "string");
  }
  assert.equal(coverageWords("something_new").label, "something new");
});

test("coverageCountsLine: the example, and one row per tail", () => {
  assert.equal(
    coverageCountsLine(FIXTURE_PT.record.result.report.pt!),
    "5 of 8 categories claimed, 0 with a logged request, 1 skipped, 1 not applicable, 1 with a tool unavailable",
  );
  assert.equal(coverageCountsLine(FIXTURE_PT_EMPTY.record.result.report.pt!), "0 of 2 categories claimed, 0 with a logged request, 2 skipped (target not started)");
  const rows = (n: number, effective: string) => Array.from({ length: n }, (_, i) => ({ category: `C${i}`, title: "t", effective }));
  const table: [string, PTCoverage, string][] = [
    ["claimed only", { started: true, rows: rows(3, "tested_claimed"), counts: { tested_claimed: 3 } }, "3 of 3 categories claimed, 0 with a logged request"],
    ["logged counts as claimed and as logged", { started: true, rows: [...rows(2, "tested_claimed"), ...rows(3, "tested_logged")], counts: { tested_claimed: 2, tested_logged: 3 } }, "5 of 5 categories claimed, 3 with a logged request"],
    ["skipped", { started: true, rows: rows(2, "skipped"), counts: { skipped: 2 } }, "0 of 2 categories claimed, 0 with a logged request, 2 skipped"],
    ["skipped, target not started", { started: false, rows: rows(4, "skipped_not_started"), counts: { skipped_not_started: 4 } }, "0 of 4 categories claimed, 0 with a logged request, 4 skipped (target not started)"],
    ["not applicable", { started: true, rows: rows(1, "not_applicable"), counts: { not_applicable: 1 } }, "0 of 1 categories claimed, 0 with a logged request, 1 not applicable"],
    ["tool unavailable", { started: true, rows: rows(1, "tool_unavailable"), counts: { tool_unavailable: 1 } }, "0 of 1 categories claimed, 0 with a logged request, 1 with a tool unavailable"],
    ["no row", { started: true, rows: rows(2, "missing"), counts: { missing: 2 } }, "0 of 2 categories claimed, 0 with a logged request, 2 with no row"],
    [
      "every tail, in order",
      { started: true, rows: [], counts: { missing: 6, tool_unavailable: 5, not_applicable: 4, skipped_not_started: 3, skipped: 2, tested_logged: 1, tested_claimed: 9 } },
      "10 of 0 categories claimed, 1 with a logged request, 2 skipped, 3 skipped (target not started), 4 not applicable, 5 with a tool unavailable, 6 with no row",
    ],
    ["a zero count adds nothing", { started: true, rows: rows(1, "tested_claimed"), counts: { tested_claimed: 1, skipped: 0, missing: 0 } }, "1 of 1 categories claimed, 0 with a logged request"],
    ["no rows at all", { started: true, rows: [], counts: {} }, "0 of 0 categories claimed, 0 with a logged request"],
    ["counts left out are tallied from the rows", { started: true, rows: [...rows(2, "tested_claimed"), ...rows(1, "skipped")], counts: {} }, "2 of 3 categories claimed, 0 with a logged request, 1 skipped"],
    ["an effective word this view does not know adds no tail", { started: true, rows: rows(1, "something_new"), counts: { something_new: 1 } }, "0 of 1 categories claimed, 0 with a logged request"],
  ];
  for (const [name, pt, want] of table) assert.equal(coverageCountsLine(pt), want, name);
});

// ---- evidence and basis ----

test("evidenceWords: a finding with no state of its own (a copy stored before the helper) reads No log", () => {
  for (const f of ptDoc.findings!) {
    const w = evidenceWords(f);
    assert.equal(w.label, "No log");
    assert.equal(w.state, "unlogged");
    assert.equal(w.tone, "neutral");
    assert.match(w.detail, /Observer has no request log for this finding/);
    assert.match(w.detail, /agent's own claim is shown beside it/);
    assert.match(w.detail, /agent can write any file in the run folder/);
    assert.doesNotMatch(`${w.label} ${w.detail}`, /\b(observed|confirmed|verified|logged)\b/i);
  }
});

const F = (over: Partial<PTFinding> = {}): PTFinding => ({
  id: "F-1",
  title: "t",
  category: "INPV",
  rating: { likelihood: 1, impact: 1 },
  basis: "observed",
  where: {},
  ...over,
});

test("evidenceWords: the three states, their exact labels, and an info tone (never success) for a match", () => {
  assert.deepEqual(EVIDENCE_STATES, ["logged", "unlogged", "not_started"]);
  assert.deepEqual(EVIDENCE_LABELS, { logged: "Helper log matches", unlogged: "No log", not_started: "Not started" });
  const logged = evidenceWords(F({ evidence_state: "logged" }));
  assert.equal(logged.label, "Helper log matches");
  assert.equal(logged.state, "logged");
  assert.equal(logged.tone, "info", "a record the agent could have written is not a green pass");
  assert.match(logged.detail, /not proof of impact/);
  assert.match(logged.detail, /says nothing about production/);
  assert.ok(logged.detail.endsWith(EVIDENCE_NOT_PROOF), "every logged detail ends with the agent-writable sentence");
  assert.equal(EVIDENCE_NOT_PROOF, "The log is a file the agent can write, so this is not proof.");
  assert.equal(EVIDENCE_AGENT_WRITABLE, "The log is a file the agent can write.");
  const unlogged = evidenceWords(F({ evidence_state: "unlogged", evidence_reason: "no_probe" }));
  assert.equal(unlogged.label, "No log");
  assert.equal(unlogged.tone, "neutral");
  const notStarted = evidenceWords(F({ evidence_state: "not_started", evidence_reason: "target_not_started" }));
  assert.equal(notStarted.label, "Not started");
  assert.equal(notStarted.tone, "neutral");
  assert.equal(notStarted.detail, "The application did not start, so nothing was tested in a running application.");
  // A state this view does not know reads as no log, never as a match.
  assert.equal(evidenceWords(F({ evidence_state: "authentic" as never })).label, "No log");
  assert.equal(evidenceState({ evidence_state: "logged" }), "logged");
  assert.equal(evidenceState({}), "unlogged");
  assert.equal(evidenceState(null), "unlogged");
  // A not-started finding with no reason says why it is not started in the table's words.
  assert.equal(evidenceWords(F({ evidence_state: "not_started" })).detail, EVIDENCE_REASON_WORDS.target_not_started);
});

test("EVIDENCE_REASON_WORDS: one sentence for each reason code, and each one is read through evidenceWords", () => {
  const codes: [string, string][] = [
    ["target_not_started", "The application did not start, so nothing was tested in a running application."],
    ["probe_helper_off", "The request helper was off for this run (a setting), so no request was logged."],
    ["helper_withheld", "The request helper was left out because python3 was not seen in the box's standard folders."],
    ["helper_changed", "The helper or its settings file was changed after Observer wrote it, so its log is not used."],
    ["helper_missing", "The helper's files could not be read when the run was checked, so the log cannot be compared."],
    ["log_absent", "The helper log holds no request."],
    ["log_unreadable", "The helper log could not be read."],
    ["log_too_large", "The helper log is over the size Observer reads."],
    ["log_inconsistent", "The helper log does not read like one the helper wrote (a line out of order, missing or malformed), so it is not used."],
    ["no_probe", "The finding cites no logged request (a request made another way, or read from code, is not logged)."],
    ["probe_not_in_log", "A request the finding cites is not in the helper log."],
    ["probe_not_sent", "A request the finding cites was refused by the helper, so it never reached the target."],
    ["probe_no_response", "A request the finding cites got no response."],
    ["no_indicator", "The finding names no attack request."],
    ["no_control", "The finding names no control request, or names the same request as the attack."],
    ["no_condition", "The finding does not say what differs between the attack and the control response."],
    ["condition_not_met", "The logged attack response does not meet the finding's condition. The log keeps a cookie or token value as [REDACTED], so a condition that names the value itself cannot be met."],
    ["not_differential", "The condition also holds for the control response, so it does not tell the two apart."],
    ["not_replayed", "The request named as the attack is not the helper's replay of this finding's stored request, so the label rests on nothing the retest sent."],
    ["condition_still_holds", "The stored condition still holds for the replayed request in the log, so the log does not back a label that says the weakness is gone."],
    ["replay_incomplete", "The stored request had values hidden when it was kept, so the replay was not the original request and the log does not back a label that says the weakness is gone."],
  ];
  assert.deepEqual(Object.keys(EVIDENCE_REASON_WORDS).sort(), codes.map(([c]) => c).sort(), "no code without a row and no row without a test row");
  for (const [code, sentence] of codes) {
    assert.equal(EVIDENCE_REASON_WORDS[code], sentence, code);
    assert.equal(evidenceReasonSentence(code), sentence, code);
    if (code !== "target_not_started") {
      const w = evidenceWords(F({ evidence_state: "unlogged", evidence_reason: code }));
      assert.equal(w.label, "No log", code);
      assert.ok(w.detail.startsWith(sentence), `${code}: ${w.detail}`);
      assert.match(w.detail, /agent can write any file in the run folder\.$/, code);
    }
  }
  // An unknown code: No log, the generic sentence and the code with its underscores taken out.
  const w = evidenceWords(F({ evidence_state: "unlogged", evidence_reason: "log_has_a_new_problem" }));
  assert.equal(w.label, "No log");
  assert.ok(w.detail.startsWith("Observer has no request log that backs this finding (log has a new problem)."), w.detail);
  assert.equal(evidenceReasonSentence("  "), "Observer has no request log that backs this finding.");
  // A hostile code is text; a name on the prototype is not a row.
  assert.equal(evidenceReasonSentence("constructor"), "Observer has no request log that backs this finding (constructor).");
  assert.equal(evidenceReasonSentence("<script>x</script>"), "Observer has no request log that backs this finding (<script>x</script>).");
});

test("evidenceWords: a finding with no reason of its own takes the one the run's evidence report explains", () => {
  const rep = (over: Partial<EvidenceReport>): EvidenceReport => ({
    mode: "on",
    helper: "intact",
    log: "ok",
    records: 0,
    sent: 0,
    refused: 0,
    requests: 0,
    logged: 0,
    unlogged: 1,
    not_started: 0,
    ...over,
  });
  const f = F({ evidence_state: "unlogged" });
  const rows: [string, EvidenceReport | undefined, string][] = [
    ["no report", undefined, "Observer has no request log for this finding."],
    ["a report that explains nothing", rep({}), "Observer has no request log for this finding."],
    ["off", rep({ mode: "off" }), EVIDENCE_REASON_WORDS.probe_helper_off],
    ["withheld", rep({ mode: "withheld" }), EVIDENCE_REASON_WORDS.helper_withheld],
    ["helper changed", rep({ helper: "changed" }), EVIDENCE_REASON_WORDS.helper_changed],
    ["helper missing", rep({ helper: "missing" }), EVIDENCE_REASON_WORDS.helper_missing],
    ["log absent", rep({ log: "absent" }), EVIDENCE_REASON_WORDS.log_absent],
    ["log unreadable", rep({ log: "unreadable" }), EVIDENCE_REASON_WORDS.log_unreadable],
    ["log too large", rep({ log: "too_large" }), EVIDENCE_REASON_WORDS.log_too_large],
    ["log inconsistent", rep({ log: "inconsistent" }), EVIDENCE_REASON_WORDS.log_inconsistent],
  ];
  for (const [name, r, want] of rows) assert.ok(evidenceWords(f, r).detail.startsWith(want), `${name}: ${evidenceWords(f, r).detail}`);
  // The finding's own reason wins, and a match is a match whatever the report says.
  assert.ok(evidenceWords(F({ evidence_state: "unlogged", evidence_reason: "no_probe" }), rep({ mode: "off" })).detail.startsWith(EVIDENCE_REASON_WORDS.no_probe));
  assert.equal(evidenceWords(F({ evidence_state: "logged" }), rep({ mode: "off" })).label, "Helper log matches");
});

test("evidenceSummaryLine: the request log in one line, by mode", () => {
  const base: EvidenceReport = { mode: "on", helper: "intact", log: "ok", records: 16, sent: 14, refused: 2, requests: 14, logged: 3, unlogged: 5, not_started: 0 };
  const rows: [string, Partial<EvidenceReport> | null, string][] = [
    ["the example", {}, "Request log: 14 requests sent, 2 refused; 3 findings with a matching log, 5 without, helper unchanged"],
    ["one of each", { sent: 1, refused: 1, logged: 1, unlogged: 1 }, "Request log: 1 request sent, 1 refused; 1 finding with a matching log, 1 without, helper unchanged"],
    ["not started findings", { not_started: 2 }, "Request log: 14 requests sent, 2 refused; 3 findings with a matching log, 5 without, 2 not started, helper unchanged"],
    ["helper changed", { helper: "changed", logged: 0, unlogged: 8 }, "Request log: 14 requests sent, 2 refused; 0 findings with a matching log, 8 without, helper changed, so its log is not used"],
    ["helper missing", { helper: "missing" }, "Request log: 14 requests sent, 2 refused; 3 findings with a matching log, 5 without, helper files not readable"],
    ["helper not checked", { helper: "not_checked" }, "Request log: 14 requests sent, 2 refused; 3 findings with a matching log, 5 without, helper not checked"],
    ["helper not said", { helper: "" }, "Request log: 14 requests sent, 2 refused; 3 findings with a matching log, 5 without"],
    ["log absent", { log: "absent", sent: 0, refused: 0, logged: 0, unlogged: 8 }, "Request log: the helper log holds no request; 0 findings with a matching log, 8 without, helper unchanged"],
    ["log unreadable", { log: "unreadable" }, "Request log: the helper log could not be read; 3 findings with a matching log, 5 without, helper unchanged"],
    ["log too large", { log: "too_large" }, "Request log: the helper log is over the size Observer reads; 3 findings with a matching log, 5 without, helper unchanged"],
    ["log inconsistent", { log: "inconsistent" }, "Request log: the helper log does not read like one the helper wrote, so it is not used; 3 findings with a matching log, 5 without, helper unchanged"],
    ["log not read", { log: "not_read" }, "Request log: the helper log was not read; 3 findings with a matching log, 5 without, helper unchanged"],
    ["off", { mode: "off", helper: "not_checked", log: "not_read", logged: 0, unlogged: 8 }, "Request log: the request helper was off for this run; 0 findings with a matching log, 8 without"],
    ["withheld", { mode: "withheld", helper: "not_checked", log: "not_read", logged: 0, unlogged: 8 }, "Request log: the request helper was left out (python3 was not seen in the box's standard folders); 0 findings with a matching log, 8 without"],
    ["no mode", { mode: "" }, ""],
    ["absent", null, ""],
  ];
  for (const [name, over, want] of rows) assert.equal(evidenceSummaryLine(over === null ? undefined : { ...base, ...over }), want, name);
  assert.equal(evidenceSummaryLine(null), "");
  assert.doesNotMatch(evidenceSummaryLine(base), /observed|confirm|verif|authentic/i);
});

test("evidenceReasonLines: the report's counts, most findings first, each in the reason's words", () => {
  const ev: EvidenceReport = {
    mode: "on",
    helper: "intact",
    log: "ok",
    records: 1,
    sent: 1,
    refused: 0,
    requests: 1,
    logged: 0,
    unlogged: 6,
    not_started: 0,
    by_reason: { probe_not_in_log: 1, no_probe: 3, not_differential: 3, zero: 0, brand_new: 2 },
  };
  assert.deepEqual(
    evidenceReasonLines(ev).map((r) => [r.code, r.n]),
    [
      ["no_probe", 3],
      ["not_differential", 3],
      ["brand_new", 2],
      ["probe_not_in_log", 1],
    ],
  );
  assert.equal(evidenceReasonLines(ev)[0].text, EVIDENCE_REASON_WORDS.no_probe);
  assert.equal(evidenceReasonLines(ev)[2].text, "Observer has no request log that backs this finding (brand new).");
  assert.deepEqual(evidenceReasonLines(undefined), []);
  assert.deepEqual(evidenceReasonLines({ ...ev, by_reason: undefined }), []);
});

test("requestLine and the request readers: an object, a plain string from an older stored copy, and anything else", () => {
  assert.equal(requestLine({ method: "GET", path: "/api/search?q=rent" }), "GET /api/search?q=rent");
  assert.equal(requestLine({ method: " POST ", path: "/api/x" }), "POST /api/x");
  assert.equal(requestLine({ method: "GET", path: "" }), "GET");
  assert.equal(requestLine({ method: "", path: "/only" }), "/only");
  assert.equal(requestLine("GET /old/string?q=1"), "GET /old/string?q=1");
  assert.equal(requestLine("  "), "");
  assert.equal(requestLine(undefined), "");
  assert.equal(requestLine(null), "");
  assert.equal(requestLine(42 as never), "");
  assert.equal(requestLine({ method: 7, path: ["x"] } as never), "");
  assert.deepEqual(
    requestHeaderLines({ method: "GET", path: "/", headers: [{ name: "Accept", value: "application/json" }, { name: "", value: "x" }, { name: "X-A", value: "" }] }),
    ["Accept: application/json", "X-A: "],
  );
  assert.deepEqual(requestHeaderLines("GET /"), []);
  assert.deepEqual(requestHeaderLines({ method: "GET", path: "/", headers: "no" as never }), []);
  assert.deepEqual(requestHeaderLines(undefined), []);
  assert.equal(requestBody({ method: "POST", path: "/", body: '{"a":1}' }), '{"a":1}');
  assert.equal(requestBody("GET /"), "");
  assert.equal(requestBody({ method: "POST", path: "/", body: 5 as never }), "");
  assert.equal(requestBody(undefined), "");
});

test("matchWords: a condition in a plain sentence, every member, quoting the agent's words", () => {
  const rows: [string, PTMatch | undefined | null, string][] = [
    ["status only", { status: 200 }, "status 200"],
    ["status zero is a status", { status: 0 }, "status 0"],
    ["body contains one", { body_contains: ["total"] }, 'the body contains "total"'],
    ["body contains two", { body_contains: ["a", "b"] }, 'the body contains "a" and "b"'],
    ["body contains three", { body_contains: ["a", "b", "c"] }, 'the body contains "a", "b" and "c"'],
    ["body does not contain", { body_not_contains: ["error"] }, 'the body does not contain "error"'],
    ["header present", { header_present: ["X-Powered-By"] }, "the header X-Powered-By is present"],
    ["headers present", { header_present: ["A", "B"] }, "the headers A and B are present"],
    ["header absent", { header_absent: ["X-Frame-Options"] }, "the header X-Frame-Options is absent"],
    ["headers absent", { header_absent: ["A", "B", "C"] }, "the headers A, B and C are absent"],
    ["header contains", { header_contains: [{ name: "Server", value: "nginx" }] }, 'the header Server contains "nginx"'],
    [
      "all of them, in the order of the shape",
      { status: 200, body_contains: ["x"], body_not_contains: ["y"], header_present: ["P"], header_absent: ["Q"], header_contains: [{ name: "S", value: "v" }] },
      'status 200; the body contains "x"; the body does not contain "y"; the header P is present; the header Q is absent; the header S contains "v"',
    ],
    ["empty", {}, ""],
    ["empty lists", { body_contains: [], header_present: [] }, ""],
    ["blank strings are no condition", { body_contains: [""], header_absent: ["  "] }, ""],
    ["a header with no name", { header_contains: [{ name: "", value: "x" }] }, ""],
    ["absent", undefined, ""],
    ["null", null, ""],
  ];
  for (const [name, m, want] of rows) assert.equal(matchWords(m), want, name);
  // Anything the wire holds is read without a throw, and the agent's markup stays text.
  assert.equal(matchWords({ status: "200" as never, body_contains: "x" as never, header_contains: "y" as never }), "");
  assert.equal(matchWords({ body_contains: ["<img src=x onerror=1>"] }), 'the body contains "<img src=x onerror=1>"');
});

test("jsonUnescapeOnce: the Go decoder's golden table, case for case (N-14)", () => {
  // The one table internal/secassess runs jsonUnescape against, so the text a person is shown and the text the evidence check reads cannot drift apart.
  const cases = JSON.parse(readFileSync(new URL("../../../internal/secassess/testdata/json_unescape_cases.json", import.meta.url), "utf8")) as { name: string; in: string; want: string }[];
  assert.ok(cases.length >= 15, "the whole table is read");
  for (const c of cases) assert.equal(jsonUnescapeOnce(c.in), c.want, c.name);
});

test("matchWords: a condition the agent wrote inside a JSON string is shown as the text, not its encoding (N-14)", () => {
  const bs = String.fromCharCode(92);
  const stored = `${bs}"role${bs}": ${bs}"admin${bs}"`;
  assert.equal(matchWords({ body_contains: [stored] }), 'the body contains ""role": "admin""');
  assert.equal(matchWords({ body_not_contains: [`${bs}"x${bs}"`, "y"] }), 'the body does not contain ""x"" and "y"');
  assert.equal(matchWords({ header_contains: [{ name: "Set-Cookie", value: `${bs}"x${bs}"` }] }), 'the header Set-Cookie contains ""x""');
  // A line break in a stored text reads on one line, and a backslash that starts no escape is kept as it was written.
  assert.equal(conditionText(`a${bs}nb${bs}tc`), "a b c");
  assert.equal(conditionText(`C:${bs}path`), `C:${bs}path`);
  // Decoded once: an escaped backslash before a quote is a backslash and a quote, not a quote.
  assert.equal(conditionText(`${bs}${bs}${bs}"`), `${bs}"`);
  // Nothing to decode, nothing changed.
  assert.equal(conditionText("plain text"), "plain text");
});

test("findingStatusNote: one sentence when every finding states the same status, nothing when they differ or there is none (UX-15)", () => {
  const some = (...statuses: (string | undefined)[]) => statuses.map((status) => ({ status }));
  const rows: [string, readonly { status?: string }[], string][] = [
    ["no finding", [], ""],
    ["every finding open", some("open", "open", "open"), `The agent states every finding as "Open". The status is the agent's own claim.`],
    ["one finding", some("open"), `The agent states this finding as "Open". The status is the agent's own claim.`],
    ["a status in its words", some("accepted_by_design", "accepted_by_design"), `The agent states every finding as "Accepted by design". The status is the agent's own claim.`],
    ["a status this view does not know, as cleaned", some("wont_fix", "wont_fix"), `The agent states every finding as "wont fix". The status is the agent's own claim.`],
    ["none states one", some(undefined, undefined), "The agent stated no status for any finding."],
    ["one finding with none", some(undefined), "The agent stated no status for this finding."],
    ["two statuses", some("open", "identified"), ""],
    ["one finding says none and the rest open", some("open", undefined, "open"), ""],
    ["a status written as not stated is its own word, not the missing one", some("not stated", undefined), ""],
  ];
  for (const [name, list, want] of rows) assert.equal(findingStatusNote(list), want, name);
});

test("refusedWords: one sentence per refusal code, each saying the request never reached the target", () => {
  assert.deepEqual(Object.keys(REFUSED_WORDS).sort(), ["bad_config", "bad_header", "bad_method", "bad_path", "body_too_large", "budget", "lockout", "off_target"]);
  for (const code of Object.keys(REFUSED_WORDS)) {
    const w = refusedWords(code);
    assert.ok(w.startsWith(REFUSED_WORDS[code]), code);
    assert.ok(w.endsWith("The request never reached the target."), code);
    assert.doesNotMatch(w, /_/, `${code}: no raw code in the words`);
  }
  assert.match(refusedWords("brand_new"), /^The helper gave a reason this view has no words for \(brand new\)\. The request never reached the target\.$/);
  assert.match(refusedWords("constructor"), /\(constructor\)/);
});

test("probe records: the index, the cited requests, the outcome and the redirect line", () => {
  const probes = FIXTURE_PT_EVIDENCE.probes!;
  const ix = probeIndex(probes);
  assert.deepEqual([...ix.keys()], ["p1", "p3", "p4", "p5"]);
  assert.equal(ix.get("p3")!.path, "/api/search?q=rent'--");
  // The first of two records with one id wins; a record with no id is not indexed.
  const dup = probeIndex([{ ...probes[0], id: "x", note: "first" }, { ...probes[0], id: "x", note: "second" }, { ...probes[0], id: "" }]);
  assert.equal(dup.size, 1);
  assert.equal(dup.get("x")!.note, "first");
  assert.equal(probeIndex(undefined).size, 0);
  // A finding's requests: its attack, its control, then the others it cites, each once.
  assert.deepEqual(citedProbes({ indicator: { control: "p4", attack: "p3" }, evidence: ["p3", "p4", "p9"] }), [
    { id: "p3", role: "attack" },
    { id: "p4", role: "control" },
    { id: "p9", role: "cited" },
  ]);
  assert.deepEqual(citedProbes({}), []);
  assert.deepEqual(citedProbes({ indicator: { attack: "p3", control: "p3" }, evidence: [""] }), [{ id: "p3", role: "attack" }]);
  assert.equal(probeRoleWords("attack"), "Attack request");
  assert.equal(probeRoleWords("control"), "Control request");
  assert.equal(probeRoleWords(""), "Cited request");
  assert.equal(probeRoleWords("constructor"), "Cited request");
  assert.deepEqual(Object.keys(PROBE_ROLE_WORDS), ["attack", "control"]);
  // What became of a request.
  const out = (id: string) => probeOutcome(ix.get(id)!);
  assert.deepEqual(out("p3"), { kind: "response", text: "Response 200, 63 ms, 65536 bytes of body.", tone: "neutral" });
  assert.deepEqual(out("p4"), { kind: "response", text: "Response 200, 41 ms, 96 bytes of body.", tone: "neutral" });
  assert.equal(out("p5").kind, "refused");
  assert.equal(out("p5").tone, "warn");
  assert.equal(out("p5").text, `Refused by the helper. ${refusedWords("off_target")}`);
  const base = ix.get("p4")!;
  assert.equal(probeOutcome({ ...base, error: "connection refused" }).text, "The request was sent and got no response. The helper recorded: connection refused");
  assert.equal(probeOutcome({ ...base, status: 0 }).kind, "none");
  assert.equal(probeOutcome({ ...base, sent: false, refused: "" }).kind, "refused");
  assert.equal(probeOutcome({ ...base, ms: 0, body_bytes: 1 }).text, "Response 200, 1 byte of body.");
  assert.equal(probeOutcome({ ...base, ms: 0, body_bytes: 0 }).text, "Response 200.");
  // A redirect the helper followed, one it did not, and none.
  assert.equal(probeRedirectLine(base), "");
  assert.equal(probeRedirectLine({ ...base, hops: 2 }), "2 redirects were followed.");
  assert.equal(probeRedirectLine({ ...base, hops: 1 }), "1 redirect was followed.");
  assert.equal(probeRedirectLine({ ...base, redirect_to: "/login" }), "The response pointed to /login.");
  assert.equal(probeRedirectLine({ ...base, redirect_to: "http://other.invalid/", redirect_blocked: true }), "The response pointed to http://other.invalid/, and the helper did not follow it.");
  // The answer holds part of the log.
  assert.equal(probeLogNote({ records: 40, shown: 25, truncated: false }), "");
  assert.equal(probeLogNote(undefined), "");
  assert.equal(probeLogNote({ records: 40, shown: 25, truncated: true }), "This answer holds 25 of the log's 40 requests, so a request that is not shown here may still be in the log.");
  assert.equal(PROBE_EXCERPT_CAPTION, "first 1 KiB of the response, secrets Observer recognised hidden");
  // The caption says what the helper read, and that the response was longer than the helper reads only then.
  assert.equal(probeExcerptCaption({ body_bytes: 0, body_truncated: false }), PROBE_EXCERPT_CAPTION);
  assert.equal(probeExcerptCaption({ body_bytes: 2, body_truncated: false }), `${PROBE_EXCERPT_CAPTION} (2 bytes read)`);
  assert.equal(probeExcerptCaption({ body_bytes: 1, body_truncated: false }), `${PROBE_EXCERPT_CAPTION} (1 byte read)`);
  assert.equal(probeExcerptCaption({ body_bytes: 65536, body_truncated: true }), `${PROBE_EXCERPT_CAPTION} (65536 bytes read; the response was longer than the helper reads)`);
  assert.equal(probeExcerptCaption({ body_bytes: 0, body_truncated: true }), `${PROBE_EXCERPT_CAPTION}; the response was longer than the helper reads`);
});

test("the evidence fixtures: one finding per state, the log records they cite, and the run's report adds up", () => {
  const f = FIXTURE_PT_EVIDENCE.record.result.pt!.findings!;
  assert.deepEqual(
    f.map((x) => [x.id, evidenceState(x), x.evidence_reason ?? ""]),
    [
      ["F-1", "logged", ""],
      ["F-2", "unlogged", "no_probe"],
      ["F-3", "unlogged", "probe_not_in_log"],
      ["F-4", "unlogged", "probe_not_sent"],
    ],
  );
  const ev = FIXTURE_PT_EVIDENCE.record.result.report.evidence!;
  assert.equal(ev.logged + ev.unlogged + ev.not_started, f.length);
  assert.equal(ev.logged, f.filter((x) => evidenceState(x) === "logged").length);
  assert.equal(Object.values(ev.by_reason ?? {}).reduce((n, c) => n + c, 0), ev.unlogged + ev.not_started);
  assert.equal(ev.sent + ev.refused, ev.records, "every line of the log is a request sent or refused");
  assert.equal(FIXTURE_PT_EVIDENCE.probes!.length, ev.records - 1, "the log holds one request no finding or coverage row cites");
  assert.deepEqual(
    FIXTURE_PT_EVIDENCE.record.result.report.pt!.rows.filter((r) => r.effective === "tested_logged").map((r) => r.category),
    ["INPV"],
  );
  assert.equal(FIXTURE_PT_EVIDENCE.probe_log!.shown, FIXTURE_PT_EVIDENCE.probes!.length);
  // The not-started run: its finding reads Not started and its report counts it.
  const ns = FIXTURE_PT_NOT_STARTED.record.result.pt!.findings!;
  assert.deepEqual(ns.map((x) => evidenceState(x)), ["not_started"]);
  assert.equal(FIXTURE_PT_NOT_STARTED.record.result.report.evidence!.not_started, 1);
  assert.equal(FIXTURE_PT_NOT_STARTED.record.result.report.pt!.started, false);
  assert.ok(ANSWER_FIXTURES.pentest_evidence && ANSWER_FIXTURES.pentest_not_started, "both answers are in the checked-in fixtures");
});

test("the evidence facet and filter: only states that occur, in their own order, over findings with no state too", () => {
  const f = FIXTURE_PT_EVIDENCE.record.result.pt!.findings!;
  assert.deepEqual(findingFacets(f, FIXTURE_VOCAB).evidence, [
    { value: "logged", label: "Helper log matches", n: 1 },
    { value: "unlogged", label: "No log", n: 3 },
  ]);
  assert.deepEqual(findingFacets(ptDoc.findings!, FIXTURE_VOCAB).evidence, [{ value: "unlogged", label: "No log", n: 3 }], "a copy with no state reads as No log throughout");
  assert.deepEqual(findingFacets(FIXTURE_PT_NOT_STARTED.record.result.pt!.findings!, FIXTURE_VOCAB).evidence, [{ value: "not_started", label: "Not started", n: 1 }]);
  const ids = (xs: PTFinding[]) => xs.map((x) => x.id);
  assert.deepEqual(ids(filterFindings(f, { evidence: "logged" }, FIXTURE_VOCAB)), ["F-1"]);
  assert.deepEqual(ids(filterFindings(f, { evidence: "unlogged" }, FIXTURE_VOCAB)), ["F-2", "F-3", "F-4"]);
  assert.deepEqual(ids(filterFindings(f, { evidence: "not_started" }, FIXTURE_VOCAB)), []);
  assert.deepEqual(ids(filterFindings(ptDoc.findings!, { evidence: "unlogged" }, FIXTURE_VOCAB)), ["F-1", "F-2", "F-3"], "an absent state is unlogged");
  assert.deepEqual(ids(filterFindings(f, { evidence: "logged", band: "low" }, FIXTURE_VOCAB)), [], "filters add up");
});

test("basisWords: said as the agent's", () => {
  const rows: [string, string][] = [
    ["observed", "The agent says: seen in a request"],
    ["inferred", "The agent says: read from code"],
    ["  observed  ", "The agent says: seen in a request"],
    ["from_a_guess", "The agent says: from a guess"],
    ["from   a\tguess", "The agent says: from a guess"],
    ["", "The agent gave no basis"],
    ["   ", "The agent gave no basis"],
    ["<script>alert(1)</script>", "The agent says: <script>alert(1)</script>"],
    ["日本語", "The agent says: 日本語"],
  ];
  for (const [basis, want] of rows) assert.equal(basisWords(basis), want, basis);
  assert.equal(basisWords(undefined as never), "The agent gave no basis");
  // Every basis is the agent's, never Observer's.
  for (const f of ptDoc.findings!) assert.match(basisWords(f.basis), /^The agent says: /);
});

// ---- the honest limits ----

test("HONEST_LIMITS: all 20 limits of plan section 13, in order, by who they apply to", () => {
  assert.equal(HONEST_LIMITS.length, 20);
  assert.deepEqual(HONEST_LIMITS.map((l) => l.id), Array.from({ length: 20 }, (_, i) => `l${i + 1}`));
  const applies = HONEST_LIMITS.map((l) => l.applies);
  assert.deepEqual(applies.slice(0, 7), Array(7).fill("both"));
  assert.deepEqual(applies.slice(7, 11), Array(4).fill("threatmodel"));
  assert.deepEqual(applies.slice(11), Array(9).fill("pentest"));
  for (const l of HONEST_LIMITS) {
    assert.ok(l.text.length > 40, `${l.id} is in words`);
    assert.match(l.text, /\.$/, `${l.id} ends as a sentence`);
  }
  // The meaning each limit has to keep, by a phrase it must still carry.
  const keeps: [string, RegExp][] = [
    ["l1", /Observer checked only its structure/],
    ["l2", /model and the prompt version/],
    ["l3", /Nothing reported is not a clearance/],
    ["l4", /not compliance evidence/],
    ["l5", /capped at medium/],
    ["l6", /text Observer has not checked/],
    ["l7", /It is not a trace/],
    ["l8", /code and docs only/],
    ["l9", /not a probability or a loss figure/],
    ["l10", /does not mean a working control/],
    ["l11", /Completeness is structural/],
    ["l12", /not production/],
    ["l13", /Helper log matches/],
    ["l14", /not a trace/],
    ["l15", /Scope holds by the sandbox, not by the prompt/],
    ["l16", /\.env files/],
    ["l17", /not a production risk, and it changes neither the band nor the severity/],
    ["l18", /one application in one box/],
    ["l19", /training data/],
    ["l20", /A retest closes nothing and changes no finding's status/],
  ];
  for (const [id, re] of keeps) assert.match(HONEST_LIMITS.find((l) => l.id === id)!.text, re, id);
  assert.match(HONEST_LIMITS[9].text, /Found near the cited line/);
  assert.match(HONEST_LIMITS[9].text, /Location exists, nothing matched earns no credit/);
});

test("limitsFor: both kinds' limits, then the contract's", () => {
  const idsOf = (c: string) => limitsFor(c).map((l) => l.id);
  const l = (from: number, to: number) => Array.from({ length: to - from + 1 }, (_, i) => `l${from + i}`);
  const rows: [string, string[]][] = [
    ["threatmodel.v1", [...l(1, 7), ...l(8, 11)]],
    ["pentest.v1", [...l(1, 7), ...l(12, 20)]],
    ["retest.v1", [...l(1, 7), ...l(12, 20)]],
    ["sarif", l(1, 7)],
    ["", l(1, 7)],
    ["something.v9", l(1, 7)],
    ["constructor", l(1, 7)],
  ];
  for (const [contract, want] of rows) assert.deepEqual(idsOf(contract), want, contract);
  // Every contract's strip carries the limits that apply to both kinds.
  for (const contract of ["threatmodel.v1", "pentest.v1", "sarif", "", "x"]) {
    const got = idsOf(contract);
    for (const id of l(1, 7)) assert.ok(got.includes(id), `${contract} has ${id}`);
  }
  assert.equal(limitsFor("pentest.v1").some((x) => x.applies === "threatmodel"), false);
  assert.equal(limitsFor("threatmodel.v1").some((x) => x.applies === "pentest"), false);
});

// ---- how this was checked ----

test("howCheckedLines: a partly checked threat model", () => {
  const lines = howCheckedLines(FIXTURE_TM.record);
  assert.deepEqual(lines.map((l) => l.tone), ["neutral", "warn", "warn", "neutral", "neutral", "neutral", "neutral"]);
  assert.match(lines[0].text, /^Observer checked the structure of the file, its closed word lists and the files the agent cited\./);
  assert.match(lines[0].text, /did not check that the reasoning is right/);
  assert.equal(lines[1].text, "Partly checked: 1 reference could not be looked at within the check's budget.");
  assert.equal(lines[2].text, assessRefTallyWords(FIXTURE_TM.record.result.report.refs));
  // The conditions of the reference counts follow them: the window, the quoted text hiding secrets changed, the budget.
  assert.equal(lines[3].text, "A reference is found when its text is on a code line within 5 lines of the first cited line.");
  assert.equal(lines[4].text, "1 reference quotes text that hiding secrets changed, so it could not be found in the file.");
  assert.equal(lines[5].text, 'References were read under a budget of 500 files, 128 MiB and 10 seconds; one the check ran out of budget for reads "not checked".');
  assert.match(lines[6].text, /4 analysed, 2 waived and 41 with neither/);
  assert.match(lines[6].text, /waived means it gives a reason that none applies/);
  assert.match(lines[6].text, /a pair with neither is not considered/);
});

test("howCheckedLines: the conditions of the reference counts, one row per case", () => {
  const rec = (check: { window_lines: number; text_hidden?: number } | undefined, budget: { files: number; mib: number; seconds: number } | undefined): ModelRecord => ({
    ...FIXTURE_TM.record,
    ref_budget: budget,
    result: { ...FIXTURE_TM.record.result, report: { ...FIXTURE_TM.record.result.report, ref_check: check } },
  });
  const tail = (r: ModelRecord) => howCheckedLines(r).slice(3, -1).map((l) => l.text);
  assert.deepEqual(tail(rec({ window_lines: 20 }, undefined)), ["A reference is found when its text is on a code line within 20 lines of the first cited line.", REF_BUDGET_UNRECORDED]);
  assert.deepEqual(tail(rec({ window_lines: 1 }, undefined)), ["A reference is found only when its text is on the first cited line itself.", REF_BUDGET_UNRECORDED]);
  assert.deepEqual(tail(rec({ window_lines: 5, text_hidden: 6 }, undefined)), [
    "A reference is found when its text is on a code line within 5 lines of the first cited line.",
    "6 references quote text that hiding secrets changed, so they could not be found in the file.",
    REF_BUDGET_UNRECORDED,
  ]);
  // A check that predates the record says its conditions were not recorded, in the window's line and the budget's (N-20): never a guess, never silence.
  assert.deepEqual(tail(rec(undefined, undefined)), [ASSESS_WINDOW_UNRECORDED, REF_BUDGET_UNRECORDED]);
  assert.deepEqual(tail(rec({ window_lines: 0 }, undefined)), [ASSESS_WINDOW_UNRECORDED, REF_BUDGET_UNRECORDED]);
  // The budget in singular units and with an unusable value read as not recorded.
  assert.deepEqual(tail(rec(undefined, { files: 1, mib: 1, seconds: 1 })), [ASSESS_WINDOW_UNRECORDED, 'References were read under a budget of 1 file, 1 MiB and 1 second; one the check ran out of budget for reads "not checked".']);
  assert.deepEqual(tail(rec(undefined, { files: 0, mib: 128, seconds: 10 })), [ASSESS_WINDOW_UNRECORDED, REF_BUDGET_UNRECORDED]);
  // A recorded window with a recorded budget has neither sentence.
  assert.deepEqual(tail(rec({ window_lines: 5 }, { files: 500, mib: 128, seconds: 10 })), [
    "A reference is found when its text is on a code line within 5 lines of the first cited line.",
    'References were read under a budget of 500 files, 128 MiB and 10 seconds; one the check ran out of budget for reads "not checked".',
  ]);
  assert.doesNotMatch(REF_BUDGET_UNRECORDED + ASSESS_WINDOW_UNRECORDED, /verified|confirmed|clean|secure|safe/i);
});

test("howCheckedLines: a valid pen test and one whose target did not start", () => {
  const valid = howCheckedLines(FIXTURE_PT.record);
  assert.equal(valid[1].text, "Nothing was refused.");
  assert.equal(valid[1].tone, "neutral");
  assert.equal(valid.some((l) => /^References:/.test(l.text)), true);
  assert.match(valid[valid.length - 1].text, /^The coverage matrix is the agent's own claim\. Observer sees only the requests that went through the request helper/);
  // No reference to count: no references line.
  const none = howCheckedLines(FIXTURE_PT_EMPTY.record);
  assert.equal(none.some((l) => /^References:/.test(l.text)), false);
  assert.equal(none[1].text, "Partly checked: some items were left out.");
});

test("howCheckedLines: one row per validation state", () => {
  const rows: [string, ModelRecord, string, string][] = [
    ["valid", record({ state: "valid" }), "Nothing was refused.", "neutral"],
    ["valid, checked before the run ended", record({ state: "valid" }, { anyway: true }), "Nothing was refused. It was checked before the run ended.", "neutral"],
    ["invalid, a known reason", record({ state: "invalid", fatal: "not_json" }), "The file was refused: it is not JSON.", "danger"],
    ["invalid, another reason", record({ state: "invalid", fatal: "too_large" }), "The file was refused: it is over the size cap.", "danger"],
    ["invalid, an unknown reason", record({ state: "invalid", fatal: "brand_new_reason" }), "The file was refused: brand new reason.", "danger"],
    ["invalid, a reason named like an object property", record({ state: "invalid", fatal: "constructor" }), "The file was refused: constructor.", "danger"],
    ["invalid, no reason", record({ state: "invalid" }), "The file was refused: it could not be read.", "danger"],
    [
      "partial, items refused and left out and references unchecked",
      record({
        state: "partial",
        counts: { threats: { read: 9, refused: 2, kept: 7 }, flows: { read: 4, left_out: 3, kept: 1 }, components: { read: 3, refused: 1, left_out: 1, kept: 1 } },
        refs: { ...zeroRefs, unchecked: 4 },
      }),
      "Partly checked: 3 items were refused, 4 items were left out, 4 references could not be looked at within the check's budget.",
      "warn",
    ],
    ["partial, one of each", record({ state: "partial", counts: { threats: { read: 3, refused: 1, left_out: 1, kept: 1 } }, refs: { ...zeroRefs, unchecked: 1 } }), "Partly checked: 1 item was refused, 1 item was left out, 1 reference could not be looked at within the check's budget.", "warn"],
    ["partial with nothing to count", record({ state: "partial" }), "Partly checked: some items were left out.", "warn"],
    ["a state this view does not know", record({ state: "odd" }), 'The validation state is "odd".', "neutral"],
  ];
  for (const [name, rec, text, tone] of rows) {
    const line = howCheckedLines(rec)[1];
    assert.equal(line.text, text, name);
    assert.equal(line.tone, tone, name);
  }
  // The refused-file words are the dashboard's own.
  for (const [code, why] of Object.entries(ASSESS_FATAL_WORDS)) {
    assert.equal(howCheckedLines(record({ state: "invalid", fatal: code }))[1].text, `The file was refused: ${why}.`);
  }
});

test("howCheckedLines: a line with nothing to say is left out, one with something is kept", () => {
  const base = howCheckedLines(record({ state: "valid" }));
  assert.equal(base.length, 3, "the checked line, the state line and the contract line");
  const withIgnored = howCheckedLines(record({ state: "valid", ignored_fields: 3, ignored_keys: ["risk", "band"] }));
  assert.equal(withIgnored.length, 4);
  assert.equal(withIgnored[2].text, "3 fields were not in the schema and were ignored (risk, band, and others).");
  const one = howCheckedLines(record({ state: "valid", ignored_fields: 1, ignored_keys: ["score"] }));
  assert.equal(one[2].text, "1 field was not in the schema and was ignored (score).");
  const all = howCheckedLines(record({ state: "valid", ignored_fields: 2, ignored_keys: ["a", "b"] }));
  assert.equal(all[2].text, "2 fields were not in the schema and were ignored (a, b).");
  const keyless = howCheckedLines(record({ state: "valid", ignored_fields: 2 }));
  assert.equal(keyless[2].text, "2 fields were not in the schema and were ignored.");
  assert.equal(howCheckedLines(record({ state: "valid", ignored_fields: 0, ignored_keys: [] })).length, 3);

  const more = howCheckedLines(record({ state: "valid", issues_more: 12 }));
  assert.equal(more[2].text, "12 more issues were found than the list keeps, so they are not shown.");
  assert.equal(more[2].tone, "warn");
  assert.equal(howCheckedLines(record({ state: "valid", issues_more: 1 }))[2].text, "1 more issue was found than the list keeps, so it is not shown.");
  assert.equal(howCheckedLines(record({ state: "valid", issues_more: 0 })).length, 3);

  const refs = howCheckedLines(record({ state: "valid", refs: { ...zeroRefs, found: 2 } }));
  assert.equal(refs[2].text, "References: 2 found near the cited line.");
  assert.equal(refs[2].tone, "neutral");
  const bad = howCheckedLines(record({ state: "valid", refs: { ...zeroRefs, found: 2, missing: 1 } }));
  assert.equal(bad[2].tone, "warn");

  const truncated = howCheckedLines(record({ state: "valid" }, { truncated: true }));
  assert.equal(truncated.length, 4);
  assert.match(truncated[3].text, /did not fit the stored copy, so only the report is kept/);
  assert.equal(truncated[3].tone, "warn");
});

test("howCheckedLines: the contract line is the contract's own, and an unknown contract has none", () => {
  const tmLine = howCheckedLines(record({ state: "valid", tm: { analysed: 1, waived: 0, empty: 0 } })).pop()!;
  assert.match(tmLine.text, /^Element and category pairs: 1 analysed, 0 waived and 0 with neither\. Analysed means/);
  const tmNoCov = howCheckedLines(record({ state: "valid" })).pop()!;
  assert.match(tmNoCov.text, /^Analysed means the model records a threat for the pair/);
  const pt = howCheckedLines(record({ state: "valid", contract: "pentest.v1" }, { contract: "pentest.v1" })).pop()!;
  assert.match(pt.text, /^The coverage matrix is the agent's own claim/);
  const odd = howCheckedLines(record({ state: "valid", contract: "sarif" }, { contract: "sarif" }));
  assert.equal(odd.length, 2);
});

test("howCheckedLines does not fail on a record with no report", () => {
  const lines = howCheckedLines({ ...record({}), result: {} as never });
  assert.equal(lines.length, 1);
});

// ---- redaction, paths and the run row ----

test("findingsLegend names the CVSS base score only when a finding has one (N-16)", () => {
  const plain = findingsLegend([{ id: "F-1" } as PTFinding, { id: "F-2", cvss: "CVSS:4.0/AV:N" } as PTFinding]);
  assert.equal(plain, "The text, the basis and the rating are what the agent wrote. The band, the evidence and the words about each cited place are Observer's.");
  assert.doesNotMatch(plain, /CVSS/);
  const scored = findingsLegend([{ id: "F-1" } as PTFinding, { id: "F-2", cvss: "CVSS:4.0/AV:N", cvss_score: 9.3, cvss_band: "critical" } as PTFinding]);
  assert.equal(scored, "The text, the basis and the rating are what the agent wrote. The band, the CVSS base score, the evidence and the words about each cited place are Observer's.");
  // A score of 0 is a score: it is Observer's number, shown as "no band".
  assert.match(findingsLegend([{ id: "F-1", cvss: "CVSS:4.0/AV:N", cvss_score: 0 } as PTFinding]), /the CVSS base score/);
  // Rows that carry nothing readable are no score.
  for (const none of [undefined, null, [], [{ id: "F-1", cvss_score: Number.NaN } as PTFinding], [{ id: "F-1", cvss_score: "9.3" } as unknown as PTFinding]]) {
    assert.equal(hasCvssScore(none), false);
    assert.doesNotMatch(findingsLegend(none), /CVSS/);
  }
});

test("redactionNote", () => {
  assert.equal(redactionNote(undefined), "");
  assert.equal(redactionNote({ on: false, hidden: 0 }), REDACTION_NOTE_OFF);
  assert.equal(redactionNote({ on: false, hidden: 5 }), REDACTION_NOTE_OFF);
  assert.equal(redactionNote({ on: true, hidden: 0 }), REDACTION_NOTE_ON);
  assert.equal(redactionNote({ on: true, hidden: -3 }), REDACTION_NOTE_ON);
  assert.equal(redactionNote({ on: true, hidden: Number.NaN }), REDACTION_NOTE_ON);
  assert.equal(redactionNote({ on: true, hidden: 1 }), `${REDACTION_NOTE_ON} In this answer, 1 place was hidden.`);
  assert.equal(redactionNote({ on: true, hidden: 2 }), `${REDACTION_NOTE_ON} In this answer, 2 places were hidden.`);
  // The sentence says what is hidden, what is shown as written, that only known shapes are recognised, and that the files are as written.
  assert.match(REDACTION_NOTE_ON, /Secrets Observer recognises are hidden in the text shown here/);
  assert.match(REDACTION_NOTE_ON, /only known shapes are recognised/);
  assert.match(REDACTION_NOTE_ON, /Names that link parts of the model together and file paths are shown as the agent wrote them\./);
  assert.match(REDACTION_NOTE_ON, /The files in your project are as the agent wrote them\./);
  // The off sentence names the setting by its label, never by its key.
  assert.ok(REDACTION_NOTE_OFF.includes(`"${REDACTION_SETTING_LABEL}"`));
  assert.equal(REDACTION_SETTING_LABEL, "Hide recognised secrets when showing a report or model");
  assert.match(REDACTION_NOTE_OFF, /\(Settings > Guard > Code security\)/);
  assert.doesNotMatch(REDACTION_NOTE_OFF, /display_redaction|[a-z]+_[a-z]+/);
  assert.doesNotMatch(REDACTION_NOTE_ON, /display_redaction|[a-z]+_[a-z]+/);
});

test("the settings the notes name are the ones the Settings rows carry, by label", () => {
  const src = readFileSync(new URL("./codeSecuritySettings.ts", import.meta.url), "utf8");
  assert.ok(src.includes(`label: "${REDACTION_SETTING_LABEL}"`), "the Settings row's label is the one the note names");
  for (const label of DIAGRAM_SETTING_LABELS) assert.ok(src.includes(`label: "${label}"`), `the Settings row labelled ${label}`);
});

test("assessModelPath carries the run, and the earlier run only when set", () => {
  assert.equal(assessModelPath("00000000000000b2"), `${ASSESS_MODEL_PATH}?run=00000000000000b2`);
  assert.equal(assessModelPath("b2", "a1"), `${ASSESS_MODEL_PATH}?run=b2&since=a1`);
  assert.equal(assessModelPath("b2", ""), `${ASSESS_MODEL_PATH}?run=b2`);
  assert.equal(assessModelPath("b2", undefined), `${ASSESS_MODEL_PATH}?run=b2`);
  assert.equal(assessModelPath("a b&c=d", "x/y?z"), `${ASSESS_MODEL_PATH}?run=a+b%26c%3Dd&since=x%2Fy%3Fz`);
  assert.equal(ASSESS_MODEL_PATH, "/api/security/assessments/model");
});

test("modelOpenable: one row per contract, phase, validation and stored copy", () => {
  const v = { state: "valid" };
  const rows: [string, Parameters<typeof modelOpenable>[0], boolean][] = [
    ["a threat model with a validation and a copy", { contract: "threatmodel.v1", validation: v, has_model: true }, true],
    ["a pen test with a validation and a copy", { contract: "pentest.v1", validation: v, has_model: true }, true],
    ["a partial validation", { contract: "pentest.v1", validation: { state: "partial" }, has_model: true }, true],
    ["a refused file still has its report to read", { contract: "threatmodel.v1", validation: { state: "invalid" }, has_model: true }, true],
    ["a started run", { contract: "threatmodel.v1", phase: "started", validation: v, has_model: true }, true],
    ["a held run", { contract: "threatmodel.v1", phase: "held", validation: v, has_model: true }, false],
    ["a cancelled run", { contract: "pentest.v1", phase: "cancelled", validation: v, has_model: true }, false],
    ["no validation yet", { contract: "threatmodel.v1", has_model: true }, false],
    ["a null validation", { contract: "threatmodel.v1", validation: null, has_model: true }, false],
    ["the SARIF contract", { contract: "sarif", validation: v, has_model: true }, false],
    ["no contract", { validation: v, has_model: true }, false],
    ["an empty contract", { contract: "", validation: v, has_model: true }, false],
    ["a contract named like an object property", { contract: "constructor", validation: v, has_model: true }, false],
    // Delete evidence leaves the validation on the row and takes the copy: the server sends has_model false, or leaves the key out.
    ["the evidence was deleted: the validation stays and the copy is gone", { contract: "threatmodel.v1", validation: v, has_model: false }, false],
    ["the key is left out when there is no copy", { contract: "threatmodel.v1", validation: v }, false],
  ];
  for (const [name, r, want] of rows) assert.equal(modelOpenable(r), want, name);
});

// ---- the wording ----

/** Every string inside a value, however deep. */
function strings(v: unknown, out: string[] = []): string[] {
  if (typeof v === "string") out.push(v);
  else if (Array.isArray(v)) for (const x of v) strings(x, out);
  else if (v && typeof v === "object") for (const x of Object.values(v)) strings(x, out);
  return out;
}

/** The one list of words and phrases no sentence Observer builds may use: the file the Go test reads too. */
const CLEARANCE = parseClearanceList(readFileSync(new URL("../../../internal/secassess/testdata/clearance_words.json", import.meta.url), "utf8"));
const BANNED = clearanceRegExp(CLEARANCE);

test("the shared clearance list: every sample it must catch is caught and every sample it must allow is allowed", () => {
  assert.ok(CLEARANCE.words.length >= 10, "the list has its words");
  assert.ok(CLEARANCE.phrases.length >= 10, "the list has its phrases");
  assert.ok((CLEARANCE.caught ?? []).length >= 10, "the list has samples it must catch");
  assert.ok((CLEARANCE.allowed ?? []).length >= 10, "the list has samples it must allow");
  for (const c of CLEARANCE.caught ?? []) assert.match(c, BANNED, `caught: ${c}`);
  for (const a of CLEARANCE.allowed ?? []) assert.doesNotMatch(a, BANNED, `allowed: ${a}`);
  // Every word is caught whole, in any case, and not inside a longer word; every phrase with any run of spaces between its words.
  for (const w of CLEARANCE.words) {
    assert.match(`it is ${w.toUpperCase()}.`, BANNED, w);
    assert.doesNotMatch(`un${w}ed`, BANNED, `${w} inside a longer word`);
  }
  for (const p of CLEARANCE.phrases) {
    assert.match(p, BANNED, p);
    assert.match(p.toUpperCase().replace(/ /g, "   "), BANNED, p);
  }
});

test("clearanceRegExp: an empty list matches nothing, a hostile word is taken literally, and a list that is not shaped right is refused", () => {
  assert.doesNotMatch("clean verified no issues", clearanceRegExp({ words: [], phrases: [] }));
  assert.doesNotMatch("anything", clearanceRegExp({ words: [".*", ""], phrases: [" "] }));
  assert.match("a (b) c", clearanceRegExp({ words: ["a (b) c"], phrases: [] }));
  assert.doesNotMatch("axxc", clearanceRegExp({ words: ["a.*c"], phrases: [] }));
  assert.throws(() => parseClearanceList("[]"), /not an object|not a list of strings/);
  assert.throws(() => parseClearanceList('{"words": [1], "phrases": []}'), /not a list of strings/);
  assert.throws(() => parseClearanceList("{"));
});

test("no word or phrase this module says reads as a clearance (the shared list)", () => {
  const all: string[] = [];
  const add = (label: string, v: unknown) => strings(v).forEach((s) => all.push(`${label}: ${s}`));
  add("MIT_STATE_WORDS", MIT_STATE_WORDS);
  add("COVERAGE_WORDS", COVERAGE_WORDS);
  add("coverageWords(unknown)", coverageWords("some_new_word"));
  add("HONEST_LIMITS", HONEST_LIMITS);
  for (const c of ["threatmodel.v1", "pentest.v1", "x"]) add(`limitsFor(${c})`, limitsFor(c));
  for (const f of ptDoc.findings!) add(`evidence ${f.id}`, evidenceWords(f));
  for (const state of EVIDENCE_STATES) {
    for (const code of [...Object.keys(EVIDENCE_REASON_WORDS), "", "something_new"]) add(`evidence ${state} ${code}`, evidenceWords(F({ evidence_state: state, evidence_reason: code })));
  }
  add("evidence labels", EVIDENCE_LABELS);
  add("evidence reasons", EVIDENCE_REASON_WORDS);
  add("refused", [...Object.keys(REFUSED_WORDS), "brand_new"].map(refusedWords));
  add("probe roles", PROBE_ROLE_WORDS);
  for (const p of FIXTURE_PT_EVIDENCE.probes!) add(`probe ${p.id}`, [probeOutcome(p).text, probeRedirectLine(p)]);
  add("probe log note", [probeLogNote({ records: 40, shown: 25, truncated: true }), PROBE_EXCERPT_CAPTION, EVIDENCE_AGENT_WRITABLE, EVIDENCE_NOT_PROOF]);
  for (const [name, a] of [["evidence", FIXTURE_PT_EVIDENCE], ["not started", FIXTURE_PT_NOT_STARTED]] as const) {
    const ev = a.record.result.report.evidence!;
    add(`summary ${name}`, evidenceSummaryLine(ev));
    add(`reasons ${name}`, evidenceReasonLines(ev).map((r) => r.text));
  }
  for (const mode of ["on", "off", "withheld"] as const) {
    for (const log of ["ok", "absent", "unreadable", "too_large", "inconsistent", "not_read"] as const) {
      for (const helper of ["intact", "changed", "missing", "not_checked"] as const) {
        add(`summary ${mode} ${log} ${helper}`, evidenceSummaryLine({ mode, helper, log, records: 3, sent: 2, refused: 1, requests: 2, logged: 1, unlogged: 2, not_started: 1 }));
      }
    }
  }
  for (const b of ["observed", "inferred", "weird_basis", "", "from code"]) add(`basis ${b}`, basisWords(b));
  add("redaction", [REDACTION_NOTE_ON, REDACTION_NOTE_OFF, redactionNote({ on: true, hidden: 1 }), redactionNote({ on: true, hidden: 7 }), redactionNote({ on: false, hidden: 0 }), redactionNote(undefined)]);
  for (const [name, r] of [["tm", FIXTURE_TM], ["pt", FIXTURE_PT], ["pt empty", FIXTURE_PT_EMPTY]] as const) {
    add(`howChecked ${name}`, howCheckedLines(r.record));
    const pt = r.record.result.report.pt;
    if (pt) add(`counts ${name}`, coverageCountsLine(pt));
  }
  // The refused-file words, partial and truncated records, ignored keys.
  for (const code of Object.keys(ASSESS_FATAL_WORDS)) add(`invalid ${code}`, howCheckedLines(record({ state: "invalid", fatal: code })));
  add("partial", howCheckedLines(record({ state: "partial", counts: { x: { read: 5, refused: 2, left_out: 1, kept: 2 } }, refs: { ...zeroRefs, unchecked: 3, found: 1, exists: 1, claimed_not_found: 1, missing: 1, invalid: 1 }, ignored_fields: 4, ignored_keys: ["a"], issues_more: 3 }, { anyway: true, truncated: true })));
  add("pt contract", howCheckedLines(record({ state: "valid", contract: "pentest.v1" }, { contract: "pentest.v1" })));
  // The closed-value words, the lines above the tabs, what was not shown and the diagram sentences.
  add("closed values", [ENUM_WORDS, STATUS_WORDS, EFFORT_WORDS, AGENT_COVERAGE_WORDS]);
  for (const c of ["threatmodel.v1", "pentest.v1", "sarif"]) add(`limitsSummary(${c})`, limitsSummary(c));
  for (const list of ["threats", "findings"] as const) {
    for (const counts of [{ read: 3, refused: 3, leftOut: 0, kept: 0 }, { read: 1, refused: 1, leftOut: 0, kept: 0 }, { read: 6, refused: 1, leftOut: 2, kept: 3 }, { read: 4, refused: 0, leftOut: 0, kept: 1 }]) add(`unlisted ${list}`, unlistedWords(list, counts));
  }
  for (const r of [FIXTURE_TM.record, FIXTURE_TM_PARTIAL.record, FIXTURE_TM_REFUSED_ALL.record, FIXTURE_PT_PARTIAL.record]) add("partialNotice", partialNotice(r));
  add("partialNotice, everything at once", partialNotice(record({ state: "partial", counts: { a: { read: 5, refused: 2, left_out: 3, kept: 0 } }, refs: { ...zeroRefs, unchecked: 4 } }, { anyway: true })));
  const omitted = { ...FIXTURE_TM.mermaid!, nodes: 60, total_nodes: 75, omitted_nodes: 15, omitted_edges: 9, labels_cut: 3 };
  add("diagram lines", [mermaidCountsLine(omitted), mermaidCutLine(omitted), mermaidSettingsLine(omitted), DIAGRAM_SETTING_LABELS]);
  add("framework words", ["stride", "linddun", "owasp_llm", "owasp_agentic", "new_one"].map(frameworkLabel));
  add("mitigation counts", [mitRefsWords({ state: "found", at: 1, total: 5 }), mitRefsWords({ state: "found", at: 1, total: 1 })]);
  // The sentences the server writes, as the fixtures carry them.
  for (const [name, a] of Object.entries(ANSWER_FIXTURES)) add(`fixture ${name}`, [a.reading, a.coverage_line]);
  assert.ok(all.length > 100, "the sweep reached the strings");
  const hits = all.filter((s) => BANNED.test(s));
  assert.deepEqual(hits, [], "banned words in Observer's own wording");
  // The agent's words ride through as data: the dashboard does not word them, so the sweep does not judge them.
  assert.equal(basisWords("verified_by_hand"), "The agent says: verified by hand");
});

test("the help entries of the assessment model view read as no clearance", () => {
  const ids = ["card.code_security_assess_model", "card.code_security_assess_coverage", "card.code_security_assess_evidence", "card.code_security_assess_checked", "card.code_security_assess_probe"];
  const entries = HELP_REGISTRY.filter((e) => ids.includes(e.id));
  assert.equal(entries.length, ids.length, "the five help entries of the model view are found");
  for (const e of entries) {
    for (const [field, text] of [["title", e.title], ["oneLiner", e.oneLiner], ["detail", e.detail ?? ""]] as const) {
      assert.doesNotMatch(text, BANNED, `${e.id} ${field}: ${text.match(BANNED)?.[0]}`);
    }
  }
});

test("Observer's evidence words never read as confirmation", () => {
  const confirms = /observed|confirm|verif|prov(?:en|ed)|exploitable|authentic|vulnerable/i;
  for (const f of ptDoc.findings!) {
    const w = evidenceWords(f);
    assert.doesNotMatch(`${w.label} ${w.detail}`, confirms);
  }
  for (const state of EVIDENCE_STATES) {
    for (const code of [...Object.keys(EVIDENCE_REASON_WORDS), ""]) {
      const w = evidenceWords(F({ evidence_state: state, evidence_reason: code }));
      assert.doesNotMatch(`${w.label} ${w.detail}`, confirms, `${state} ${code}`);
    }
  }
  for (const code of Object.keys(REFUSED_WORDS)) assert.doesNotMatch(refusedWords(code), confirms, code);
  // Every logged detail says the log is agent-writable and that a match is not proof of impact.
  const logged = evidenceWords(F({ evidence_state: "logged" }));
  assert.match(logged.detail, /file the agent can write/);
  assert.match(logged.detail, /not proof of impact/);
});

// ---- purity and the fixtures ----

test("the module is pure: no fetch, no React, no DOM, no clock, and secAssess.ts does not import it", () => {
  const src = readFileSync(new URL("./secAssessModel.ts", import.meta.url), "utf8");
  for (const re of [/\bfetch\s*\(/, /from\s+["']react/, /\bdocument\./, /\bwindow\./, /\bDate\.now/, /new Date\(/, /Math\.random/, /localStorage/, /dangerouslySetInnerHTML/, /\beval\(/, /\bsetTimeout\(/]) {
    assert.doesNotMatch(src, re, String(re));
  }
  assert.doesNotMatch(readFileSync(new URL("./secAssess.ts", import.meta.url), "utf8"), /secAssessModel/);
});

test("the helpers do not change the model they read", () => {
  const before = structuredClone([FIXTURE_TM, FIXTURE_PT, FIXTURE_PT_EMPTY]);
  const doc = FIXTURE_TM.record.result.tm!;
  filterThreats(doc, doc.threats!, { q: "a", band: "high" });
  sortThreats(doc, doc.threats!, { key: "band", dir: "desc" });
  threatFacets(doc);
  buildElementMatrix(doc, FIXTURE_TM.record.result.report.tm!, FIXTURE_VOCAB);
  flowRows(doc);
  treeItems(doc.attack_trees![0]);
  for (const r of [FIXTURE_TM, FIXTURE_PT, FIXTURE_PT_EMPTY]) {
    howCheckedLines(r.record);
    if (r.record.result.report.pt) coverageCountsLine(r.record.result.report.pt);
  }
  limitsFor("pentest.v1");
  assert.deepEqual([FIXTURE_TM, FIXTURE_PT, FIXTURE_PT_EMPTY], before);
});

test("a large model: 10,000 threats filter, sort and facet without a cap and in order", () => {
  const doc = bigDoc(10_000);
  const all = doc.threats!;
  const t0 = performance.now();
  const f = filterThreats(doc, all, { q: "injection", framework: "stride" });
  const want = all.filter((t) => matches(doc, t, { q: "injection", framework: "stride" }));
  assert.equal(f.length, want.length);
  assert.ok(f.length > 100);
  for (const key of ["band", "id", "title", "element", "status"] as ThreatSortKey[]) {
    const s = sortThreats(doc, all, { key, dir: "desc" });
    assert.equal(s.length, 10_000, key);
    assert.equal(new Set(s).size, 10_000, `${key} keeps every threat once`);
  }
  const byId = sortThreats(doc, all, { key: "id", dir: "asc" });
  assert.equal(byId[0].id, "T-1");
  assert.equal(byId[9].id, "T-10");
  assert.equal(byId[9_999].id, "T-10000");
  const facets = threatFacets(doc);
  assert.equal(facets.frameworks.reduce((n, x) => n + x.n, 0), 10_000);
  assert.equal(facets.elements.length, 5);
  assert.equal(bandCounts(all).reduce((n, x) => n + x.n, 0), 10_000);
  const ms = performance.now() - t0;
  assert.ok(ms < 10_000, `took ${ms} ms`);
});

// ---- words for closed values ----

/** goEnum reads one closed list of internal/secassess/vocab_enums.go, the list the validator accepts: the page must have words for each of its values. */
function goEnum(name: string): string[] {
  const src = readFileSync(new URL("../../../internal/secassess/vocab_enums.go", import.meta.url), "utf8");
  const m = src.match(new RegExp(`${name}\\s*=\\s*Enum\\{([^}]*)\\}`));
  assert.ok(m, `${name} is in vocab_enums.go`);
  return [...m[1].matchAll(/"([^"]+)"/g)].map((x) => x[1]);
}

test("every value of a closed list the validator accepts has words, and none reads as a raw value", () => {
  const tables: [string, Readonly<Record<string, string>>][] = [
    ["EnumSensitivity", ENUM_WORDS.sensitivity],
    ["EnumActorKind", ENUM_WORDS.actor_kind],
    ["EnumEntryKind", ENUM_WORDS.entry_kind],
    ["EnumAuthn", ENUM_WORDS.authn],
    ["EnumExposure", ENUM_WORDS.exposure],
    ["EnumEncrypted", ENUM_WORDS.encrypted],
    ["EnumElementKind", ENUM_WORDS.element_kind],
    ["EnumThreatState", STATUS_WORDS],
    ["EnumFindingState", STATUS_WORDS],
    ["EnumEffort", EFFORT_WORDS],
    ["EnumCoverageStatus", AGENT_COVERAGE_WORDS],
  ];
  for (const [name, table] of tables) {
    const values = goEnum(name);
    assert.ok(values.length >= 3, `${name} has values`);
    for (const v of values) {
      assert.ok(Object.prototype.hasOwnProperty.call(table, v), `${name}: "${v}" has no words`);
      assert.doesNotMatch(table[v], /_/, `${name}: the words for "${v}" are the raw value`);
      assert.notEqual(table[v].trim(), "", `${name}: "${v}" has empty words`);
    }
  }
  // The words of a basis are the agent's own: every value has a row too.
  for (const v of goEnum("EnumBasis")) assert.doesNotMatch(basisWords(v), /_/, `the words for the basis ${v}`);
  assert.equal(basisWords("observed"), "The agent says: seen in a request");
  assert.equal(basisWords("inferred"), "The agent says: read from code");
});

test("no table row names a value the validator would not accept (the one extra is the effort size xl)", () => {
  const pairs: [string, Readonly<Record<string, string>>, string[]][] = [
    ["EnumSensitivity", ENUM_WORDS.sensitivity, []],
    ["EnumActorKind", ENUM_WORDS.actor_kind, []],
    ["EnumEntryKind", ENUM_WORDS.entry_kind, []],
    ["EnumAuthn", ENUM_WORDS.authn, []],
    ["EnumExposure", ENUM_WORDS.exposure, []],
    ["EnumEncrypted", ENUM_WORDS.encrypted, []],
    ["EnumElementKind", ENUM_WORDS.element_kind, []],
    ["EnumEffort", EFFORT_WORDS, ["xl"]],
    ["EnumCoverageStatus", AGENT_COVERAGE_WORDS, []],
  ];
  for (const [name, table, extra] of pairs) {
    const go = new Set(goEnum(name));
    for (const k of Object.keys(table)) assert.ok(go.has(k) || extra.includes(k), `${name}: the table has a row for "${k}" the validator does not accept`);
  }
});

test("every closed value in the fixtures has a row in its table", () => {
  const tm = FIXTURE_TM.record.result.tm!;
  const sys = tm.system;
  const has = (name: keyof typeof ENUM_WORDS, v: string | undefined, where: string) => {
    if (v === undefined || v === "") return;
    assert.ok(Object.prototype.hasOwnProperty.call(ENUM_WORDS[name], v), `${where}: "${v}" has no row in ${name}`);
  };
  for (const a of sys.assets ?? []) has("sensitivity", a.sensitivity, `asset ${a.id}`);
  for (const a of sys.actors ?? []) has("actor_kind", a.kind, `actor ${a.id}`);
  for (const e of sys.entry_points ?? []) {
    has("entry_kind", e.kind, `entry point ${e.id}`);
    has("authn", e.authn, `entry point ${e.id}`);
    has("exposure", e.exposure, `entry point ${e.id}`);
  }
  for (const f of sys.flows ?? []) {
    has("authn", f.authn, `flow ${f.id}`);
    has("encrypted", f.encrypted, `flow ${f.id}`);
  }
  for (const r of FIXTURE_TM.record.result.report.tm?.rows ?? []) has("element_kind", r.kind, `matrix row ${r.id}`);
  for (const t of tm.threats ?? []) {
    has("element_kind", t.element.kind, `threat ${t.id}`);
    assert.ok(Object.prototype.hasOwnProperty.call(STATUS_WORDS, t.status ?? "identified"), `threat ${t.id}: status`);
    for (const m of t.missing ?? []) if (m.effort) assert.ok(Object.prototype.hasOwnProperty.call(EFFORT_WORDS, m.effort), `threat ${t.id}: effort`);
  }
  for (const f of FIXTURE_PT.record.result.pt!.findings ?? []) assert.ok(Object.prototype.hasOwnProperty.call(STATUS_WORDS, f.status ?? "open"), `finding ${f.id}: status`);
  for (const c of FIXTURE_PT.record.result.pt!.coverage ?? []) assert.ok(Object.prototype.hasOwnProperty.call(AGENT_COVERAGE_WORDS, c.status), `coverage ${c.category}`);
});

test("enumWords: a value no table knows reads as written with the underscores taken out, and an empty one reads as not stated", () => {
  assert.equal(enumWords("authn", "api_key"), "API key");
  assert.equal(enumWords("authn", "mtls"), "client certificate");
  assert.equal(enumWords("exposure", "internal_network"), "internal network");
  assert.equal(enumWords("exposure", "local_only"), "this machine only");
  assert.equal(enumWords("authn", "some_new_kind"), "some new kind");
  assert.equal(enumWords("authn", ""), "not stated");
  assert.equal(enumWords("authn", undefined), "not stated");
  // A key an agent could pick to reach the table's prototype is not a row.
  assert.equal(enumWords("authn", "constructor"), "constructor");
  assert.equal(enumWords("authn", "__proto__"), "proto");
  assert.equal(statusWords("accepted_by_design"), "Accepted by design");
  assert.equal(statusWords("brand_new"), "brand new");
  assert.equal(statusWords(undefined), "Not stated");
  assert.equal(effortWords("xl"), "very large");
  assert.equal(effortWords("huge_one"), "huge one");
  assert.equal(agentCoverageWords("tool_unavailable"), "tool unavailable");
  assert.equal(agentCoverageWords(undefined), "no row");
});

test("frameworks and categories have names: the AI frameworks read as short names, a category without a framework by its vocabulary name", () => {
  for (const f of FIXTURE_VOCAB.ai_frameworks) {
    assert.notEqual(frameworkLabel(f.id), f.id, `${f.id} has a short name`);
    assert.doesNotMatch(frameworkLabel(f.id), /_/);
    assert.equal(frameworkTitle(f.id, FIXTURE_VOCAB), f.name);
  }
  assert.equal(frameworkLabel("stride"), "STRIDE");
  assert.equal(frameworkLabel("linddun"), "LINDDUN");
  assert.equal(frameworkLabel("owasp_llm"), "OWASP LLM");
  assert.equal(frameworkLabel("owasp_agentic"), "OWASP agentic");
  assert.equal(frameworkLabel("new_framework"), "new framework");
  assert.equal(frameworkTitle("stride", FIXTURE_VOCAB), "STRIDE");
  assert.equal(categoryName("stride", "information_disclosure", FIXTURE_VOCAB), "Information disclosure");
  assert.equal(categoryName("linddun", "linkability", FIXTURE_VOCAB), "Linkability");
  assert.equal(categoryName("owasp_llm", "LLM01", FIXTURE_VOCAB), "LLM01");
  assert.equal(categoryLabel("information_disclosure", FIXTURE_VOCAB), "Information disclosure");
  assert.equal(categoryLabel("non_repudiation", FIXTURE_VOCAB), "Non-repudiation");
  assert.equal(categoryLabel("LLM01", FIXTURE_VOCAB), "LLM01");
  assert.equal(categoryLabel("some_other_one", undefined), "some other one");
});

test("matrixAbbr: STRIDE keeps its letters, LINDDUN has two letters each, and no header repeats another", () => {
  const cols = [
    ...FIXTURE_VOCAB.stride.map((c) => ({ id: c.id, label: c.name, letter: c.letter, framework: "stride" })),
    ...FIXTURE_VOCAB.linddun.map((c) => ({ id: c.id, label: c.name, framework: "linddun" })),
  ];
  const abbr = cols.map((c) => matrixAbbr(c));
  assert.deepEqual(abbr.slice(0, 6), ["S", "T", "R", "I", "D", "E"]);
  assert.deepEqual(abbr.slice(6), ["Lk", "Id", "Nr", "Dt", "Di", "Ua", "Nc"]);
  assert.equal(new Set(abbr).size, abbr.length, "no two columns share a header");
  assert.equal(matrixAbbr({ id: "new_one", label: "Newness", framework: "linddun" }), "Ne");
  assert.equal(matrixAbbr({ id: "x", label: "", framework: "linddun" }), "x");
});

// ---- a mitigation word and how many references stand behind it ----

test("threatMitSummary: the best state, how many references are in it and how many are cited", () => {
  const withRefs = (...states: (ModelRef["state"] | null)[]) =>
    thr("T-x", { existing: [{ text: "a", refs: states.map((s) => (s === null ? (null as unknown as ModelRef) : ref(s))) }] });
  const rows: [string, ModelThreat, { state: MitState; at: number; total: number }, string][] = [
    ["none cited", thr("T-x"), { state: "none", at: 0, total: 0 }, ""],
    ["one found", withRefs("found"), { state: "found", at: 1, total: 1 }, "1 of 1 reference"],
    ["one found among five", withRefs("found", "claimed_not_found", "claimed_not_found", "exists", "missing"), { state: "found", at: 1, total: 5 }, "1 of 5 references"],
    ["two found among three", withRefs("found", "found", "missing"), { state: "found", at: 2, total: 3 }, "2 of 3 references"],
    ["only existing", withRefs("exists", "claimed_not_found"), { state: "exists", at: 1, total: 2 }, "1 of 2 references"],
    ["all claimed, none found", withRefs("claimed_not_found", "claimed_not_found", "claimed_not_found"), { state: "claimed_not_found", at: 3, total: 3 }, "3 of 3 references"],
    ["all unlooked at", withRefs("unchecked", "unchecked"), { state: "unchecked", at: 2, total: 2 }, "2 of 2 references"],
    ["a reference with no state reads as unchecked", withRefs(undefined, "missing"), { state: "unchecked", at: 1, total: 2 }, "1 of 2 references"],
    ["a missing place and a malformed one", withRefs("missing", "invalid"), { state: "not_located", at: 2, total: 2 }, "2 of 2 references"],
    ["a hostile null reference reads as not located", withRefs(null), { state: "not_located", at: 1, total: 1 }, "1 of 1 reference"],
  ];
  for (const [name, t, want, words] of rows) {
    const got = threatMitSummary(t);
    assert.deepEqual(got, want, name);
    assert.equal(got.state, threatMitState(t), `${name}: the state is the threat's state`);
    assert.equal(mitRefsWords(got), words, name);
  }
  // The refs of several mitigations are counted together.
  const two = thr("T-y", { existing: [{ text: "a", refs: [ref("found")] }, { text: "b", refs: [ref("exists"), ref("exists")] }] });
  assert.deepEqual(threatMitSummary(two), { state: "found", at: 1, total: 3 });
  assert.deepEqual(mitigationSummary(undefined), { state: "none", at: 0, total: 0 });
  assert.deepEqual(mitigationSummary([ref("exists")]), { state: "exists", at: 1, total: 1 });
});

test("the mitigation filter reads the best state: Found means at least one reference was found", () => {
  const doc = tdoc({
    threats: [
      thr("T-1", { existing: [{ text: "a", refs: [ref("found"), ref("claimed_not_found"), ref("claimed_not_found")] }] }),
      thr("T-2", { existing: [{ text: "a", refs: [ref("claimed_not_found"), ref("claimed_not_found")] }] }),
      thr("T-3", { existing: [{ text: "a", refs: [ref("exists"), ref("claimed_not_found")] }] }),
    ],
  });
  assert.deepEqual(ids(filterThreats(doc, doc.threats!, { mitigation: "found" })), ["T-1"]);
  assert.deepEqual(ids(filterThreats(doc, doc.threats!, { mitigation: "claimed_not_found" })), ["T-2"]);
  assert.deepEqual(ids(filterThreats(doc, doc.threats!, { mitigation: "exists" })), ["T-3"]);
});

// ---- findings: filter, search, sort ----

function fnd(id: string, over: Partial<PTFinding> = {}): PTFinding {
  return { id, title: `Finding ${id}`, category: "INPV", rating: { likelihood: 2, impact: 2 }, basis: "observed", where: {}, ...over };
}

/** The findings the finding tests filter and sort, written in this order. */
const FS: PTFinding[] = [
  fnd("F-10", { title: "Entry search is injectable", category: "INPV", basis: "observed", band: "critical", score: 20, route: "GET /api/search", cwe: ["CWE-89"], status: "open", where: { refs: [{ path: "src/api/search.ts", line: 3 }] } }),
  fnd("F-2", { title: "Login does not slow failures", category: "ATHN", basis: "inferred", band: "medium", score: 9, status: "mitigated", impact: "A password can be guessed." }),
  fnd("F-1", { title: "Error pages name the framework", category: "INFO", basis: "observed", band: "low", score: 4, status: "open", fix: "Remove the Server header." }),
  fnd("F-3", { title: "Another medium", category: "ATHN", basis: "observed", band: "medium", score: 9, status: "open" }),
  fnd("F-4", { title: "No band at all", category: "CONF", basis: "inferred" }),
  fnd("F-5", { title: "A high one", category: "INPV", basis: "inferred", band: "high", score: 16, status: "accepted_by_design" }),
];

test("filterFindings: one row per filter", () => {
  const rows: [string, FindingFilter, string[]][] = [
    ["no filter keeps every finding", {}, ["F-10", "F-2", "F-1", "F-3", "F-4", "F-5"]],
    ["a band", { band: "medium" }, ["F-2", "F-3"]],
    ["the top band", { band: "critical" }, ["F-10"]],
    ["a band nothing has", { band: "high", category: "INFO" }, []],
    ["a category", { category: "ATHN" }, ["F-2", "F-3"]],
    ["a basis", { basis: "inferred" }, ["F-2", "F-4", "F-5"]],
    ["band and basis together", { band: "medium", basis: "observed" }, ["F-3"]],
    ["search: a word of the title", { q: "injectable" }, ["F-10"]],
    ["search: the id", { q: "f-4" }, ["F-4"]],
    ["search: the category's title from the vocabulary", { q: "authentication" }, ["F-2", "F-3"]],
    ["search: the route", { q: "/api/search" }, ["F-10"]],
    ["search: a CWE id", { q: "cwe-89" }, ["F-10"]],
    ["search: the impact", { q: "guessed" }, ["F-2"]],
    ["search: the fix", { q: "server header" }, ["F-1"]],
    ["search: a cited path", { q: "src/api/search.ts" }, ["F-10"]],
    ["search is trimmed and case-blind", { q: "  INJECTABLE " }, ["F-10"]],
    ["a search of only spaces is not set", { q: "   " }, ["F-10", "F-2", "F-1", "F-3", "F-4", "F-5"]],
    ["a search nothing matches", { q: "no such text anywhere" }, []],
  ];
  for (const [name, f, want] of rows) assert.deepEqual(ids(filterFindings(FS, f, FIXTURE_VOCAB)), want, name);
  // Without the vocabulary the category is searched by its id.
  assert.deepEqual(ids(filterFindings(FS, { q: "athn" })), ["F-2", "F-3"]);
  assert.deepEqual(ids(filterFindings(FS, { q: "authentication" })), []);
});

test("sortFindings: one row per key and direction, and equal rows keep the agent's order", () => {
  const rows: [string, FindingSort, string[]][] = [
    ["the default: band highest first, equal bands in the agent's order, no band last", DEFAULT_FINDING_SORT, ["F-10", "F-5", "F-2", "F-3", "F-1", "F-4"]],
    ["band lowest first: equal bands still in the agent's order, no band still last", { key: "band", dir: "asc" }, ["F-1", "F-2", "F-3", "F-5", "F-10", "F-4"]],
    ["id ascending reads numbers as numbers", { key: "id", dir: "asc" }, ["F-1", "F-2", "F-3", "F-4", "F-5", "F-10"]],
    ["id descending", { key: "id", dir: "desc" }, ["F-10", "F-5", "F-4", "F-3", "F-2", "F-1"]],
    ["title ascending", { key: "title", dir: "asc" }, ["F-5", "F-3", "F-10", "F-1", "F-2", "F-4"]],
    ["category by its title: Authentication, Configuration, Information gathering, Input validation", { key: "category", dir: "asc" }, ["F-2", "F-3", "F-4", "F-1", "F-10", "F-5"]],
    ["category descending keeps equal categories in the agent's order", { key: "category", dir: "desc" }, ["F-10", "F-5", "F-1", "F-4", "F-2", "F-3"]],
    ["status ascending, a finding with no status last", { key: "status", dir: "asc" }, ["F-5", "F-2", "F-10", "F-1", "F-3", "F-4"]],
    ["status descending, a finding with no status still last", { key: "status", dir: "desc" }, ["F-10", "F-1", "F-3", "F-2", "F-5", "F-4"]],
  ];
  for (const [name, s, want] of rows) assert.deepEqual(ids(sortFindings(FS, s, FIXTURE_VOCAB)), want, name);
  // A key this code does not know sorts like the default, and the input is left alone.
  const before = ids(FS);
  assert.deepEqual(ids(sortFindings(FS, { key: "nonsense" as FindingSortKey, dir: "asc" }, FIXTURE_VOCAB)), ids(sortFindings(FS, { key: "band", dir: "asc" }, FIXTURE_VOCAB)));
  assert.deepEqual(ids(FS), before);
});

test("findingFacets lists only what occurs, bands highest first, categories in the vocabulary's order, with counts that add up", () => {
  const f = findingFacets(FS, FIXTURE_VOCAB);
  assert.deepEqual(f.bands, [{ value: "critical", n: 1 }, { value: "high", n: 1 }, { value: "medium", n: 2 }, { value: "low", n: 1 }]);
  assert.deepEqual(f.categories.map((c) => c.value), ["INFO", "CONF", "ATHN", "INPV"]);
  assert.deepEqual(f.categories.map((c) => c.label), ["Information gathering", "Configuration and deployment", "Authentication", "Input validation"]);
  assert.equal(f.categories.reduce((n, c) => n + c.n, 0), FS.length);
  assert.deepEqual(f.bases, [{ value: "observed", n: 3 }, { value: "inferred", n: 3 }]);
  // A finding with no band is in no band's count, and the band facet says so by counting only the ones with one.
  assert.equal(f.bands.reduce((n, b) => n + b.n, 0), FS.length - 1);
});

test("filtering and sorting 10,000 findings keep every one: no cap", () => {
  const many = fixtureFindings(10_000);
  assert.equal(filterFindings(many, {}, FIXTURE_VOCAB).length, 10_000);
  const sorted = sortFindings(many, DEFAULT_FINDING_SORT, FIXTURE_VOCAB);
  assert.equal(sorted.length, 10_000);
  assert.equal(new Set(sorted).size, 10_000);
  // The band is the first key: every critical finding comes before every other.
  const firstNonCritical = sorted.findIndex((x) => x.band !== "critical");
  assert.equal(firstNonCritical, 2_500);
  assert.ok(sorted.slice(firstNonCritical).every((x) => x.band !== "critical"));
  // Equal bands keep the order the agent wrote them in.
  assert.deepEqual(ids(sorted.slice(0, 3)), ["F-4", "F-8", "F-12"]);
  const q = filterFindings(many, { q: "generated finding 77" }, FIXTURE_VOCAB);
  assert.deepEqual(ids(q).slice(0, 3), ["F-77", "F-770", "F-771"]);
  const f = findingFacets(many, FIXTURE_VOCAB);
  assert.equal(f.categories.reduce((n, c) => n + c.n, 0), 10_000);
});

// ---- the run list: which runs open and which compare ----

test("sinceCandidates: other runs of the same project and kind, not later than this one, with a stored copy, newest first", () => {
  const run = { id: "r5", created_at: "2026-11-12T00:00:00Z", project_root_hash: "h1", kind: "threat_model" };
  const base = { project_root_hash: "h1", kind: "threat_model", has_model: true };
  const runs = [
    { ...base, id: "r5", created_at: "2026-11-12T00:00:00Z" },
    { ...base, id: "r1", created_at: "2026-11-10T00:00:00Z" },
    { ...base, id: "r3", created_at: "2026-11-11T00:00:00Z" },
    { ...base, id: "r-later", created_at: "2026-11-13T00:00:00Z" },
    { ...base, id: "r-same-time", created_at: "2026-11-12T00:00:00Z" },
    { ...base, id: "r-no-copy", created_at: "2026-11-09T00:00:00Z", has_model: false },
    { ...base, id: "r-no-key", created_at: "2026-11-09T00:00:00Z", has_model: undefined },
    { ...base, id: "r-other-project", created_at: "2026-11-09T00:00:00Z", project_root_hash: "h2" },
    { ...base, id: "r-other-kind", created_at: "2026-11-09T00:00:00Z", kind: "pentest_local" },
  ];
  assert.deepEqual(ids(sinceCandidates(run, runs)), ["r-same-time", "r3", "r1"]);
  // A run that cannot be dated is left to the server to judge.
  assert.deepEqual(ids(sinceCandidates(run, [{ ...base, id: "r-undated", created_at: "not a date" }])), ["r-undated"]);
  // This run alone has nothing to compare with.
  assert.deepEqual(sinceCandidates(run, [runs[0]]), []);
  // Nothing about the list is changed.
  assert.equal(runs[0].id, "r5");
});

test("modelTitle names the project, else the run's id (never its handle token): never the word model twice", () => {
  assert.equal(modelTitle({ kind_title: "Threat model", project_name: "ledger", id: "r1" }), "Threat model: ledger");
  assert.equal(modelTitle({ kind_title: "Threat model", project_name: "", id: "r1" }), "Threat model: r1");
  assert.equal(modelTitle({ kind_title: "Penetration test (your own app, local)", project_name: "", id: "20261114-ab" }), "Penetration test (your own app, local): 20261114-ab");
  assert.doesNotMatch(modelTitle({ kind_title: "Threat model", project_name: "ledger", id: "r1" }), /model.*model/i);
});

test("modelSubtitle says when the run started and when it was checked, and leaves out what it cannot read", () => {
  const date = (iso: string) => `D(${iso})`;
  const ago = (iso: string) => `A(${iso})`;
  assert.equal(modelSubtitle("2026-11-14T10:00:00Z", "2026-11-14T11:00:00Z", date, ago), "Started D(2026-11-14T10:00:00Z) · Validated A(2026-11-14T11:00:00Z)");
  assert.equal(modelSubtitle("2026-11-14T10:00:00Z", undefined, date, ago), "Started D(2026-11-14T10:00:00Z)");
  assert.equal(modelSubtitle(undefined, "2026-11-14T11:00:00Z", date, ago), "Validated A(2026-11-14T11:00:00Z)");
  assert.equal(modelSubtitle("not a date", "", date, ago), "");
  assert.equal(modelSubtitle(undefined, undefined, date, ago), "");
});

test("defaultSince is the run's own previous run when the view can still compare with it, else none", () => {
  const cands = [{ id: "a" }, { id: "b" }];
  assert.equal(defaultSince({ previous_run: "b" }, cands), "b");
  assert.equal(defaultSince({ previous_run: " b " }, cands), "b");
  // Launched without a comparison, or the earlier run lost its copy: nothing is guessed.
  assert.equal(defaultSince({}, cands), "");
  assert.equal(defaultSince({ previous_run: "" }, cands), "");
  assert.equal(defaultSince({ previous_run: "gone" }, cands), "");
  assert.equal(defaultSince({ previous_run: "a" }, []), "");
});

/** The members a pair of the scored pass has on the wire. internal/secassess/diffsimilar_test.go (TestDiffSimilarWireMembers) pins the same list from the Go struct. */
const SIMILAR_WIRE_MEMBERS = ["basis", "category", "element", "from_band", "from_score", "id", "points", "prev_category", "prev_id", "prev_title", "title", "to_band", "to_score"];

test("a probably-the-same pair has only the members the Go side sends, and its required ones", () => {
  const pairs = FIXTURE_SINCE_SIMILAR.similar ?? [];
  assert.ok(pairs.length >= 3);
  for (const s of pairs) {
    for (const k of Object.keys(s)) assert.ok(SIMILAR_WIRE_MEMBERS.includes(k), `${k} is not a member of secassess.DiffSimilar`);
    for (const k of ["id", "prev_id", "title", "prev_title", "element", "category", "basis", "points"]) assert.ok(k in s, `${k} is always sent`);
  }
});

test("similarBasisWords lists what a probably-the-same pair has in common and never prints a raw value", () => {
  assert.equal(similarBasisWords(["location"]), "the place in the code it cites");
  assert.equal(similarBasisWords(["location", "cwe"]), "the place in the code it cites and a weakness id (CWE) in common");
  assert.equal(
    similarBasisWords(["location", "cwe", "words", "category", "element"]),
    "the place in the code it cites, a weakness id (CWE) in common, similar words in the title, the same category and the same element",
  );
  // A word the table does not know is left out; with none left the line still reads.
  assert.equal(similarBasisWords(["cwe", "mystery", "__proto__"]), "a weakness id (CWE) in common");
  assert.equal(similarBasisWords(["mystery"]), "signs the table does not name");
  assert.equal(similarBasisWords([]), "signs the table does not name");
  assert.equal(similarBasisWords(undefined), "signs the table does not name");
});

test("pairingNote says so when fewer than half of either run's threats could be paired, and stays quiet for small runs", () => {
  const since = (added: number, removed: number, changed: number, similar: number, unchanged: number): Parameters<typeof pairingCounts>[0] =>
    ({
      added: Array.from({ length: added }, (_, i) => ({ id: `A${i}`, title: "t", element: { kind: "component", id: "c" }, category: "tampering" })),
      removed: Array.from({ length: removed }, (_, i) => ({ id: `R${i}`, title: "t", element: { kind: "component", id: "c" }, category: "tampering" })),
      changed: Array.from({ length: changed }, (_, i) => ({ id: `C${i}`, prev_id: `C${i}`, title: "t", element: { kind: "component", id: "c" }, category: "tampering", match: "id" })),
      similar: Array.from({ length: similar }, (_, i) => ({ id: `S${i}`, prev_id: `S${i}`, title: "t", prev_title: "u", element: { kind: "component", id: "c" }, category: "tampering", basis: ["location"], points: 6 })),
      unchanged,
      matched_by_id: 0,
      matched_by_title: 0,
      system: { components: {}, zones: {}, flows: {} },
      note: "",
    });
  // The first live comparison: 122 earlier threats, 50 new, 0 paired.
  assert.deepEqual(pairingCounts(since(50, 122, 0, 0, 0)), { paired: 0, earlier: 122, later: 50 });
  assert.equal(
    pairingNote(since(50, 122, 0, 0, 0)),
    "Only 0 of the earlier run's 122 threats and 0 of this run's 50 could be paired. The two runs word things differently, so the added and removed lists overstate what changed.",
  );
  // Pairs of every kind count: changed, probably the same and unchanged.
  assert.deepEqual(pairingCounts(since(5, 77, 1, 44, 2)), { paired: 47, earlier: 124, later: 52 });
  assert.match(pairingNote(since(5, 77, 1, 44, 2)), /^Only 47 of the earlier run's 124 threats and 47 of this run's 52 could be paired./);
  // Half of each run paired: quiet. One short of half of the larger run: says so.
  assert.equal(pairingNote(since(10, 10, 5, 5, 0)), "");
  assert.notEqual(pairingNote(since(10, 11, 5, 4, 0)), "");
  // A small run that pairs little says it in its own counts.
  assert.equal(pairingNote(since(3, 3, 0, 0, 0)), "");
  assert.equal(pairingNote(since(0, 0, 0, 0, 0)), "");
  // An empty new run against a large earlier one: the earlier run's threats are the ones unpaired.
  assert.match(pairingNote(since(0, 12, 0, 0, 0)), /^Only 0 of the earlier run's 12 threats and 0 of this run's 0 could be paired./);
});

// ---- what was not shown, and what this does not tell you ----

test("itemCounts reads what the check did with one list, and a report with no count reads as nothing written", () => {
  assert.deepEqual(itemCounts(FIXTURE_TM.record, "threats"), { read: 5, refused: 0, leftOut: 0, kept: 5 });
  assert.deepEqual(itemCounts(FIXTURE_TM_REFUSED_ALL.record, "threats"), { read: 3, refused: 3, leftOut: 0, kept: 0 });
  assert.deepEqual(itemCounts(FIXTURE_PT_REFUSED_ALL.record, "findings"), { read: 2, refused: 2, leftOut: 0, kept: 0 });
  assert.deepEqual(itemCounts(FIXTURE_TM.record, "findings"), { read: 0, refused: 0, leftOut: 0, kept: 0 });
  assert.deepEqual(itemCounts(undefined, "threats"), { read: 0, refused: 0, leftOut: 0, kept: 0 });
  assert.deepEqual(itemCounts(record({ counts: { threats: { read: 4, left_out: 1, refused: 2, kept: 1 } } }), "threats"), { read: 4, refused: 2, leftOut: 1, kept: 1 });
  assert.deepEqual(itemCounts(record({}), "threats"), { read: 0, refused: 0, leftOut: 0, kept: 0 });
});

test("unlistedWords: one row per way items were not kept, and nothing when every one was", () => {
  const c = (read: number, refused: number, leftOut: number, kept: number) => ({ read, refused, leftOut, kept });
  const rows: [string, "threats" | "findings", ReturnType<typeof c>, string][] = [
    ["every one kept", "threats", c(5, 0, 0, 5), ""],
    ["nothing written", "threats", c(0, 0, 0, 0), ""],
    ["more kept than written is not an error", "threats", c(2, 0, 0, 3), ""],
    ["all refused", "threats", c(3, 3, 0, 0), "The agent wrote 3 threats; the check refused all 3, so none is shown here. The reasons are under How checked."],
    ["one written, refused", "threats", c(1, 1, 0, 0), "The agent wrote 1 threat; the check refused it, so it is not shown here. The reasons are under How checked."],
    ["all left out", "findings", c(2, 0, 2, 0), "The agent wrote 2 findings; the check left out all 2, so none is shown here. The reasons are under How checked."],
    ["some refused, some left out, none kept", "threats", c(3, 2, 1, 0), "The agent wrote 3 threats; the check refused 2 and left out 1, so none is shown here. The reasons are under How checked."],
    ["one refused of six", "threats", c(6, 1, 0, 5), "The agent wrote 6 threats; the check refused 1, so 1 is not listed here. The reasons are under How checked."],
    ["refused and left out, some kept", "findings", c(6, 1, 2, 3), "The agent wrote 6 findings; the check refused 1 and left out 2, so 3 are not listed here. The reasons are under How checked."],
    ["no breakdown", "threats", c(4, 0, 0, 1), "The agent wrote 4 threats; the check did not keep 3, so 3 are not listed here. The reasons are under How checked."],
  ];
  for (const [name, list, counts, want] of rows) assert.equal(unlistedWords(list, counts), want, name);
  // It never says none was reported when some were written.
  for (const [, list, counts] of rows.filter((r) => r[3] !== "")) assert.doesNotMatch(unlistedWords(list, counts), /reported no|lists no|none was reported/i);
});

test("the fixtures that the check only partly kept, or refused whole, carry counts that say so", () => {
  assert.deepEqual(itemCounts(FIXTURE_TM_PARTIAL.record, "threats"), { read: 6, refused: 1, leftOut: 0, kept: 5 });
  assert.equal(FIXTURE_TM_PARTIAL.record.result.tm!.threats!.length, 5);
  assert.equal(FIXTURE_TM_PARTIAL.record.result.report.state, "partial");
  assert.deepEqual(itemCounts(FIXTURE_PT_PARTIAL.record, "findings"), { read: 4, refused: 1, leftOut: 0, kept: 3 });
  assert.equal(FIXTURE_PT_PARTIAL.record.result.pt!.findings!.length, 3);
  // Refused whole: nothing to show, a reading that says what happened, and a matrix that has no analysed cell.
  assert.equal(FIXTURE_TM_REFUSED_ALL.record.result.tm!.threats!.length, 0);
  assert.equal(FIXTURE_PT_REFUSED_ALL.record.result.pt!.findings!.length, 0);
  assert.match(FIXTURE_TM_REFUSED_ALL.reading ?? "", /The agent wrote 3 threats, and none is shown here: the check refused 3./);
  assert.match(FIXTURE_PT_REFUSED_ALL.reading ?? "", /The agent wrote 2 findings, and none is shown here: the check refused 2./);
  const tm = FIXTURE_TM_REFUSED_ALL.record.result.report.tm!;
  assert.equal(tm.analysed, 0);
  assert.equal(tm.waived, 2);
  assert.equal(tm.empty, 45);
  assert.equal(tm.analysed + tm.waived + tm.empty, FIXTURE_TM.record.result.report.tm!.analysed + FIXTURE_TM.record.result.report.tm!.waived + FIXTURE_TM.record.result.report.tm!.empty);
  assert.equal(tm.by_framework!.reduce((n, f) => n + f.empty, 0), 45);
  assert.match(FIXTURE_TM_REFUSED_ALL.coverage_line ?? "", /0 element and category pairs analysed, 2 waived with a reason and 45 with neither/);
});

test("partialNotice: only a partly checked result says so, with what was refused, left out or not looked at", () => {
  assert.equal(partialNotice(undefined), null);
  assert.equal(partialNotice(record({ state: "valid" })), null);
  assert.equal(partialNotice(record({ state: "invalid", fatal: "not_json" })), null);
  assert.deepEqual(partialNotice(FIXTURE_TM.record), { title: "Partly checked", text: "1 reference could not be looked at within the check's budget." });
  assert.deepEqual(partialNotice(FIXTURE_TM_PARTIAL.record), { title: "Partly checked", text: "1 item was refused, 1 reference could not be looked at within the check's budget." });
  assert.deepEqual(partialNotice(FIXTURE_TM_REFUSED_ALL.record), { title: "Partly checked", text: "3 items were refused, 1 reference could not be looked at within the check's budget." });
  assert.deepEqual(partialNotice(FIXTURE_PT_PARTIAL.record), { title: "Partly checked", text: "1 item was refused." });
  assert.deepEqual(partialNotice(record({ state: "partial", counts: { a: { read: 5, refused: 2, left_out: 3, kept: 0 } }, refs: { ...zeroRefs, unchecked: 4 } }, { anyway: true })), {
    title: "Partly checked",
    text: "2 items were refused, 3 items were left out, 4 references could not be looked at within the check's budget. It was checked before the run ended.",
  });
  assert.deepEqual(partialNotice(record({ state: "partial" })), { title: "Partly checked", text: "Some items were left out." });
  // The notice is the first half of the How checked line, word for word.
  for (const r of [FIXTURE_TM.record, FIXTURE_TM_PARTIAL.record, FIXTURE_PT_PARTIAL.record]) {
    const line = validationLine(r, r.result.report).text.replace(/^Partly checked: /, "");
    assert.equal(partialNotice(r)!.text, line.charAt(0).toUpperCase() + line.slice(1));
  }
});

test("limitsSummary: the common line, then the one of the contract, and not a clearance", () => {
  const tm = limitsSummary("threatmodel.v1");
  const pt = limitsSummary("pentest.v1");
  assert.equal(tm.length, 2);
  assert.equal(pt.length, 2);
  assert.equal(tm[0], pt[0]);
  assert.match(tm[0], /Observer checked only its structure and the files it cites/);
  assert.match(tm[0], /Nothing reported is not a clearance, and this is not compliance evidence\./);
  assert.match(tm[1], /unknown, not ruled out/);
  assert.match(pt[1], /not production/);
  assert.match(pt[1], /coverage matrix is the agent's claim/);
  assert.equal(limitsSummary("sarif").length, 1);
  assert.equal(limitsSummary("constructor").length, 1);
  for (const l of [...tm, ...pt]) assert.ok(l.length <= 220, `a short line: ${l.length} characters`);
});

test("the diagram lines: what was left out, what was shortened, and the settings that bound them", () => {
  const m = FIXTURE_TM.mermaid!;
  assert.equal(mermaidCountsLine(m), "");
  assert.equal(mermaidCutLine(m), "");
  assert.equal(mermaidSettingsLine(m), "");
  const omitted = { ...m, nodes: 60, total_nodes: 75, omitted_nodes: 15, omitted_edges: 9 };
  assert.equal(mermaidCountsLine(omitted), "60 of 75 nodes drawn, 9 flows not drawn: the cap is the diagram size setting (60 nodes).");
  assert.equal(mermaidCountsLine({ ...omitted, omitted_edges: 1 }), "60 of 75 nodes drawn, 1 flow not drawn: the cap is the diagram size setting (60 nodes).");
  assert.equal(mermaidCutLine({ ...m, labels_cut: 3, label_chars: 40 }), "3 labels were shortened to 40 characters; the full names are in the tables.");
  assert.equal(mermaidCutLine({ ...m, labels_cut: 1, label_chars: 20 }), "1 label was shortened to 20 characters; the full names are in the tables.");
  assert.equal(mermaidCutLine({ ...m, labels_cut: 0, label_chars: 40 }), "");
  assert.equal(mermaidCutLine({ ...m, labels_cut: Number.NaN, label_chars: 40 }), "");
  // The pointer to the two settings appears when either limit was reached, and names them by their labels.
  for (const hit of [omitted, { ...m, labels_cut: 2 }]) {
    const line = mermaidSettingsLine(hit);
    for (const label of DIAGRAM_SETTING_LABELS) assert.ok(line.includes(`"${label}"`), label);
    assert.doesNotMatch(line, /diagram_max_nodes|diagram_label_chars|[a-z]+_[a-z]+/);
  }
  // The model's own sentence for the cap stays in the words the design system allows: the setting by its description, never by its key.
  assert.doesNotMatch(mermaidCountsLine(omitted), /diagram_max_nodes|_/);
});

test("coverageReasonExpected: a reason is expected only for a category the agent skipped, called not applicable or had no tool for", () => {
  const want: Record<string, boolean> = { tested_claimed: false, tested_logged: false, skipped: true, skipped_not_started: false, not_applicable: true, tool_unavailable: true, missing: false };
  assert.deepEqual(Object.keys(want).sort(), Object.keys(COVERAGE_WORDS).sort(), "one row per coverage word");
  for (const [w, expected] of Object.entries(want)) assert.equal(coverageReasonExpected(w), expected, w);
  assert.equal(coverageReasonExpected("something_new"), false);
});

// ---- the fixtures the Go tests decode ----

/** The checked-in copy of every fixed answer, which the Go tests decode into the real response struct with unknown fields refused. */
const ANSWER_FIXTURES_FILE = new URL("../../../internal/secassess/testdata/model_answer_fixtures.json", import.meta.url);

/** answerFixturesJSON is every fixed answer as the file holds it: an object by name, two-space indent, the names in the order ANSWER_FIXTURES lists them, a newline at the end. */
function answerFixturesJSON(): string {
  return `${JSON.stringify(ANSWER_FIXTURES, null, 2)}\n`;
}

test("the answer fixtures are the checked-in JSON the Go tests decode (UPDATE_FIXTURES=1 rewrites the file)", () => {
  const want = answerFixturesJSON();
  if (process.env.UPDATE_FIXTURES === "1") {
    writeFileSync(ANSWER_FIXTURES_FILE, want);
    return;
  }
  const got = readFileSync(ANSWER_FIXTURES_FILE, "utf8").replace(/\r\n/g, "\n");
  assert.equal(got, want, "internal/secassess/testdata/model_answer_fixtures.json is out of date: run the lib test with UPDATE_FIXTURES=1 and commit the file");
  assert.deepEqual(Object.keys(JSON.parse(got)), Object.keys(ANSWER_FIXTURES));
  // Every answer is a whole one: a record with a report, the vocabulary and the redaction state, as the server sends them.
  for (const [name, a] of Object.entries(ANSWER_FIXTURES)) {
    assert.ok(a.record?.result?.report, `${name}: a report`);
    assert.ok(a.vocab?.stride?.length, `${name}: the vocabulary`);
    assert.ok(a.redaction && typeof a.redaction.on === "boolean", `${name}: the redaction state`);
    if (a.record.contract === "threatmodel.v1") {
      assert.ok(a.mermaid, `${name}: a diagram`);
      assert.equal(typeof a.mermaid.label_chars, "number", `${name}: label_chars`);
      assert.equal(typeof a.mermaid.labels_cut, "number", `${name}: labels_cut`);
    }
  }
});

test("the big answers carry every threat and finding they are made with: no cap anywhere on the way", () => {
  const tm = fixtureBigThreatModel(1500);
  assert.equal(tm.record.result.tm!.threats!.length, 1500);
  assert.deepEqual(itemCounts(tm.record, "threats"), { read: 1500, refused: 0, leftOut: 0, kept: 1500 });
  const pt = fixtureBigPentest(1200);
  assert.equal(pt.record.result.pt!.findings!.length, 1200);
  assert.deepEqual(itemCounts(pt.record, "findings"), { read: 1200, refused: 0, leftOut: 0, kept: 1200 });
  // Every band, status and mitigation state occurs, so a row of each kind is drawn.
  const t = fixtureThreats(1500);
  assert.deepEqual(new Set(t.map((x) => x.band)), new Set(["low", "medium", "high", "critical"]));
  assert.deepEqual(new Set(t.map((x) => threatMitState(x))), new Set(["found", "exists", "claimed_not_found"]));
  assert.equal(new Set(t.map((x) => x.id)).size, 1500);
});

test("threatFacets tells elements that share a name apart by their id, and leaves a name that is alone as it is", () => {
  const doc = tdoc({
    system: {
      components: [{ id: "api", name: "Notes service", type: "service" }],
      entry_points: [
        { id: "ep-search", component: "api", kind: "http_route" },
        { id: "ep-login", component: "api", kind: "http_route" },
        { id: "ep-job", component: "api", kind: "scheduled" },
      ],
    },
    threats: [
      thr("1", { element: { kind: "entry_point", id: "ep-search" } }),
      thr("2", { element: { kind: "entry_point", id: "ep-login" } }),
      thr("3", { element: { kind: "entry_point", id: "ep-login" } }),
      thr("4", { element: { kind: "entry_point", id: "ep-job" } }),
      thr("5", { element: { kind: "component", id: "api" } }),
    ],
  });
  const labels = threatFacets(doc).elements.map((e) => `${e.label} (${e.n})`);
  // Two routes of one service read alike ("http_route on Notes service"): each is named with its own id.
  assert.ok(labels.includes("http_route on Notes service, ep-login (2)"), labels.join(" | "));
  assert.ok(labels.includes("http_route on Notes service, ep-search (1)"), labels.join(" | "));
  // A name that is alone is not changed, and no two options read the same.
  assert.ok(labels.includes("scheduled on Notes service (1)"), labels.join(" | "));
  assert.ok(labels.includes("Notes service (1)"), labels.join(" | "));
  const names = threatFacets(doc).elements.map((e) => e.label);
  assert.equal(new Set(names).size, names.length, "every option reads differently");
});

test("cvssReading: Observer's own score of the agent's vector, 0.0 included, and nothing without a vector", () => {
  const base = { id: "F-1", title: "t", category: "ATHN", rating: { likelihood: 3, impact: 3 }, basis: "observed", where: {} };
  const V = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N";
  assert.equal(cvssReading(base), null);
  assert.equal(cvssReading({ ...base, cvss: "  " }), null);
  assert.deepEqual(cvssReading({ ...base, cvss: V, cvss_score: 9.3, cvss_band: "critical" }), {
    vector: V,
    text: "Base score 9.3 (critical), computed by Observer from the vector.",
  });
  // A whole number keeps its decimal; a score of 0.0 is a score with no band, the vector still shown.
  assert.equal(cvssReading({ ...base, cvss: V, cvss_score: 5, cvss_band: "medium" })!.text, "Base score 5.0 (medium), computed by Observer from the vector.");
  assert.deepEqual(cvssReading({ ...base, cvss: V, cvss_score: 0 }), { vector: V, text: "Base score 0.0 (no band), computed by Observer from the vector." });
  // A vector with no computed score does not invent one.
  assert.equal(cvssReading({ ...base, cvss: V })!.text, "Observer has no score for this vector.");
  assert.equal(CVSS_NOTE, "Base score of the weakness as logged in an in-box copy, not a production risk.");
  // The sentence that keeps the score from reading as a second severity beside the table's band: it names the band's inputs and says neither changes the other.
  assert.equal(CVSS_APART, "This is a separate reading from the Band in the table, which is the agent's likelihood times impact. Neither changes the other.");
});

test("cvssLeftOutIds: a finding is named by the issue's item, never by the path, and only for the two codes that mean a vector was left out (N-9)", () => {
  const dropped: ModelIssue = { row: "V5", code: "bad_cvss_dropped", severity: "dropped", path: "findings[3]", item: "F-4", message: "The CVSS vector of finding F-4 carries a threat metric, so it was left out." };
  const rows: [string, readonly ModelIssue[] | undefined, string[]][] = [
    ["no issues", undefined, []],
    ["an empty list", [], []],
    ["a dropped vector names its finding", [dropped], ["F-4"]],
    ["a vector that did not score names its finding", [{ ...dropped, row: "V10", code: "cvss_not_scored", item: "F-9" }], ["F-9"]],
    ["both codes on two findings", [dropped, { ...dropped, code: "cvss_not_scored", item: "F-9" }], ["F-4", "F-9"]],
    ["a record kept before the item was recorded names nobody: the path is a place in the agent's file, not a kept finding", [{ ...dropped, item: undefined }], []],
    ["an empty item names nobody", [{ ...dropped, item: "" }], []],
    ["another code with an item is not a vector left out", [{ ...dropped, code: "bad_enum_dropped" }], []],
    ["the same finding twice is one", [dropped, dropped], ["F-4"]],
  ];
  for (const [name, issues, want] of rows) assert.deepEqual([...cvssLeftOutIds(issues)].sort(), want, name);
  assert.deepEqual([...CVSS_LEFT_OUT_CODES], ["bad_cvss_dropped", "cvss_not_scored"]);
  // The note is in Observer's words: it names no code, quotes no vector and points at the list that says why.
  assert.match(CVSS_LEFT_OUT_NOTE, /left out/);
  assert.match(CVSS_LEFT_OUT_NOTE, /How checked says why/);
  assert.doesNotMatch(CVSS_LEFT_OUT_NOTE, /CVSS:4|bad_cvss|V5/);
  // The Go validator's two codes are the ones this reads.
  const go = readFileSync(new URL("../../../internal/secassess/cvss.go", import.meta.url), "utf8") + readFileSync(new URL("../../../internal/secassess/validate_cover.go", import.meta.url), "utf8");
  for (const code of CVSS_LEFT_OUT_CODES) assert.ok(go.includes(`"${code}"`), code + " is raised by the validator");
});

// ---- the retest's labels and the red team's chain (depth plan W7.2, W7.3) ----

/** goConstValues reads the closed list `name = Enum{A, B}` of a Go file whose members are constants (`A = "a"`), as the words the validator accepts. */
function goConstEnum(file: string, name: string): string[] {
  const src = readFileSync(new URL(`../../../internal/secassess/${file}`, import.meta.url), "utf8");
  const list = src.match(new RegExp(`${name}\\s*=\\s*Enum\\{([^}]*)\\}`));
  assert.ok(list, `${name} is in ${file}`);
  const out: string[] = [];
  for (const id of list[1].split(",").map((x) => x.trim()).filter((x) => x !== "")) {
    const c = src.match(new RegExp(`\\b${id}\\s*=\\s*"([a-z_]+)"`));
    assert.ok(c, `${id} is a constant of ${file}`);
    out.push(c[1]);
  }
  return out;
}

test("every label a retest can give has words, and no row names a label the validator does not accept", () => {
  const go = goConstEnum("retest.go", "EnumRetestResult");
  assert.deepEqual(go, ["reproduced", "not_reproduced", "inconclusive"], "the Go list was read");
  assert.deepEqual([...RETEST_RESULTS], go, "the summary's order is the Go list's");
  assert.deepEqual(Object.keys(RETEST_RESULT_WORDS).sort(), [...go].sort(), "one row per label");
  for (const v of go) {
    const w = RETEST_RESULT_WORDS[v];
    assert.doesNotMatch(w.label, /_/, `the words for ${v} are the raw value`);
    assert.notEqual(w.label.trim(), "", v);
    assert.match(w.detail, /\.$/, `${v}: a sentence`);
    assert.equal(retestResultWords(v), w, v);
  }
});

test("the labels' tones never read as a fix: reproduced draws attention, the other two are neutral, none is green", () => {
  assert.equal(RETEST_RESULT_WORDS.reproduced.tone, "warn");
  assert.equal(RETEST_RESULT_WORDS.not_reproduced.tone, "neutral");
  assert.equal(RETEST_RESULT_WORDS.inconclusive.tone, "neutral");
  for (const w of Object.values(RETEST_RESULT_WORDS)) assert.notEqual(w.tone, "success");
  // "Not reproduced" says what one replay got and that it is not a statement about the code.
  assert.match(RETEST_RESULT_WORDS.not_reproduced.detail, /does not mean the weakness is gone from your code or from production/);
  assert.doesNotMatch(Object.values(RETEST_RESULT_WORDS).map((w) => `${w.label} ${w.detail}`).join(" "), /\b(fixed|resolved|closed|solved|patched|remediated)\b/i);
});

test("a label this table lacks reads as written, neutral, and an absent one as not stated", () => {
  assert.deepEqual(retestResultWords("brand_new"), { label: "Brand new", tone: "neutral", detail: "" });
  assert.deepEqual(retestResultWords(undefined), { label: "Not stated", tone: "neutral", detail: "" });
  assert.deepEqual(retestResultWords("constructor"), { label: "Constructor", tone: "neutral", detail: "" });
});

test("every result a chain step can have has words, and no row names a result the validator does not accept", () => {
  const go = goEnum("EnumChainResult");
  assert.deepEqual(go, ["achieved", "partly", "blocked"], "the Go list was read");
  assert.deepEqual([...CHAIN_RESULTS], go);
  assert.deepEqual(Object.keys(CHAIN_RESULT_WORDS).sort(), [...go].sort(), "one row per result");
  const goWords = readFileSync(new URL("../../../internal/secassess/exercise.go", import.meta.url), "utf8");
  for (const v of go) {
    const w = CHAIN_RESULT_WORDS[v];
    assert.doesNotMatch(w.label, /_/, `the words for ${v} are the raw value`);
    assert.notEqual(w.tone, "success", `${v}: a chain result is never a success`);
    assert.equal(chainResultWords(v), w);
    // The Go narrative's own words for the result are the same words in lower case.
    const m = goWords.match(new RegExp(`"${v}":\\s*"([^"]+)"`));
    assert.ok(m, `${v} has a row in the Go narrative`);
    assert.equal(w.label.toLowerCase(), m[1], `${v}: the page and the Go narrative agree`);
  }
  assert.deepEqual(chainResultWords("weird_value"), { label: "Weird value", tone: "neutral" });
  assert.deepEqual(chainResultWords(undefined), { label: "Not stated", tone: "neutral" });
});

test("EVIDENCE_REASON_WORDS lists the reasons in the order the Go side can raise them, and the retest's three are among them", () => {
  const src = readFileSync(new URL("../../../internal/secassess/evidence.go", import.meta.url), "utf8");
  const block = src.match(/var EvidenceReasons = \[\]string\{([^}]*)\}/);
  assert.ok(block, "the Go list was read");
  const consts = new Map([...src.matchAll(/^\s*(Reason[A-Za-z]+)\s*=\s*"([a-z_]+)"/gm)].map((m) => [m[1], m[2]] as const));
  const order = block[1].split(",").map((x) => x.trim()).filter((x) => x !== "").map((id) => {
    assert.ok(consts.has(id), `${id} is a constant`);
    return consts.get(id)!;
  });
  assert.deepEqual(Object.keys(EVIDENCE_REASON_WORDS), order, "the table's key order is the Go list's");
  for (const code of ["not_replayed", "condition_still_holds", "replay_incomplete"]) assert.ok(order.includes(code), code);
});

test("the sentence under the chain is the Go side's, the retest's limit is the Go side's, and no sentence of either reads as a clearance", () => {
  const ex = readFileSync(new URL("../../../internal/secassess/exercise.go", import.meta.url), "utf8");
  assert.equal(ex.match(/const ExerciseStopNote = "([^"]+)"/)?.[1], EXERCISE_STOP_NOTE);
  const limits = readFileSync(new URL("../../../internal/secassess/limits.go", import.meta.url), "utf8");
  for (const id of ["l18", "l20"]) {
    const m = limits.match(new RegExp(`\\{"${id}", LimitsPentest, "([^"]+)"\\}`));
    assert.ok(m, `${id} is in limits.go`);
    assert.equal(HONEST_LIMITS.find((l) => l.id === id)?.text, m[1], `${id}: the page and the Go list agree`);
  }
  const all: string[] = [];
  const add = (label: string, v: unknown) => strings(v).forEach((x) => all.push(`${label}: ${x}`));
  add("RETEST_RESULT_WORDS", RETEST_RESULT_WORDS);
  add("CHAIN_RESULT_WORDS", CHAIN_RESULT_WORDS);
  add("RETEST_NOTHING_CLOSED", RETEST_NOTHING_CLOSED);
  add("EXERCISE_STOP_NOTE", EXERCISE_STOP_NOTE);
  add("limitsFor(retest.v1)", limitsFor("retest.v1"));
  add("limitsSummary(retest.v1)", limitsSummary("retest.v1"));
  add("howChecked retest", howCheckedLines(FIXTURE_RETEST.record));
  for (const [name, a] of [["retest", FIXTURE_RETEST], ["red team", FIXTURE_RED_TEAM], ["pen test retested", FIXTURE_PT_RETESTED]] as const) add(`fixture ${name}`, [a.reading, a.coverage_line]);
  assert.ok(all.length > 10);
  assert.deepEqual(all.filter((x) => BANNED.test(x)), [], "banned words in Observer's own wording");
});

test("a retest run's contract has its own limits, summary and how-checked line, and its model opens", () => {
  const ids = (c: string) => limitsFor(c).map((l) => l.id);
  assert.deepEqual(ids("retest.v1"), ids("pentest.v1"), "a retest reads the pen test's limits, l20 among them");
  assert.ok(ids("retest.v1").includes("l20"));
  assert.equal(limitsSummary("retest.v1").length, 2);
  // The preamble no longer says that nothing was closed: the retest's own view says it once, in its limit (N-12).
  assert.match(limitsSummary("retest.v1")[1], /Not reproduced does not mean the weakness is gone\./);
  assert.doesNotMatch(limitsSummary("retest.v1")[1], /closed|closes nothing/);
  const lines = howCheckedLines(FIXTURE_RETEST.record).map((l) => l.text).join(" ");
  assert.match(lines, /closes nothing and changes no finding/);
  assert.equal(modelOpenable({ contract: "retest.v1", validation: { state: "valid" }, has_model: true }), true);
  assert.equal(modelOpenable({ contract: "retest.v1", validation: { state: "valid" } }), false);
});

test("the retest and red team fixtures hold only values the Go side can raise", () => {
  const reasons = new Set(Object.keys(EVIDENCE_REASON_WORDS));
  for (const r of FIXTURE_RETEST.record.result.rt!.results!) {
    assert.ok(RETEST_RESULTS.includes(r.result), `${r.finding}: ${r.result}`);
    if (r.evidence_reason) assert.ok(reasons.has(r.evidence_reason), `${r.finding}: ${r.evidence_reason}`);
    // An inconclusive label claims nothing, so it has no reading of the log.
    if (r.result === "inconclusive") assert.equal(r.evidence_state, undefined, r.finding);
  }
  for (const v of FIXTURE_PT_RETESTED.retests!) for (const r of v.results) assert.ok(RETEST_RESULTS.includes(r.result), `${v.run} ${r.finding}`);
  for (const a of [FIXTURE_RED_TEAM, FIXTURE_RED_TEAM_AGENT]) {
    const ex = a.record.result.pt!.exercise!;
    assert.ok(["developer", "agent"].includes(ex.objective_by ?? ""));
    for (const st of ex.chain ?? []) {
      assert.ok(CHAIN_RESULTS.includes(st.result), st.step);
      if (st.finding) assert.ok(a.record.result.pt!.findings!.some((f) => f.id === st.finding), `${st.finding} is a kept finding`);
    }
  }
  // A chain step with no finding is in the fixture, so the cell for it is drawn.
  assert.ok(FIXTURE_RED_TEAM.record.result.pt!.exercise!.chain!.some((s) => !s.finding));
});
