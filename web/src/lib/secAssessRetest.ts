// secAssessRetest is the pure side of two features of the assessment model view:
// the retest of earlier findings (docs/plans/security-assessments-depth-plan-
// 2026-11-14.md W7.2, decision D38) and the red team's objective and chain
// (W7.3). Pure: no fetch, no React, no clock, no DOM. The shapes it reads are
// in secAssessModel.ts (the model answer) and secAssess.ts (the plan).
//
// Both features say less than they could, on purpose:
//   - a retest is LABELS ONLY. Each finding it replays is labelled reproduced,
//     not reproduced or inconclusive, and the label is shown beside the
//     finding with the sentence that nothing was closed. No status changes and
//     nothing is written back to the earlier run. A label of "not reproduced"
//     is never worded or toned as a fix.
//   - the chain is the agent's account, shown from its structure. The
//     objective is the developer's words or the agent's, and says which. What
//     would have detected or stopped a step is the agent's opinion and is
//     labelled as one. There is no technique table and no objective list.

import type { Tone } from "../../../shared/lib/tone.ts";
import type { AssessChoices, AssessKind, AssessRetestFinding, AssessRetestPlan, AssessRun } from "./secAssess.ts";
import {
  EVIDENCE_LABELS,
  RETEST_NOTHING_CLOSED,
  chainResultWords,
  citedProbes,
  evidenceReasonSentence,
  matchWords,
  plural,
  retestResultWords,
  wstgTitle,
  type CitedProbe,
  type EvidenceState,
  type ModelVocab,
  type PentestDoc,
  type PTExercise,
  type PTFinding,
  type PTRequest,
  type RetestDoc,
  type RetestResultView,
  type RetestSummary,
  type RetestView,
  type RetestWord,
} from "./secAssessModel.ts";

// ---- the kinds ----

/** retestKindOf is the kind a retest starts from: the one the server marks as started from a run's findings. Absent when this server has none. */
export function retestKindOf(kinds: readonly AssessKind[] | undefined): AssessKind | undefined {
  return (kinds ?? []).find((k) => k.from_run === true);
}

/** cardKinds is the kinds the card's grid lists: every kind but the ones started from an earlier run, which are reached only from that run's model view. */
export function cardKinds(kinds: readonly AssessKind[] | undefined): AssessKind[] {
  return (kinds ?? []).filter((k) => k.from_run !== true);
}

// ---- the picker: which findings a retest can replay ----

/** The most findings one retest replays (secassess.MaxRetestFindings). The plan states the bound it holds; this is what the picker counts against before a plan is read. */
export const RETEST_MAX = 8;

/** The text a stored request holds where a value was hidden when the finding was kept (secassess hiddenMarker). */
export const HIDDEN_MARKER = "[REDACTED]";

/** The picker's two notes on a finding's stored condition. */
export const RETEST_CONDITION_WORDS = {
  has: "Has a stored condition",
  none: "No stored condition (a label cannot be backed by the log)",
} as const;

/** The short note on a finding whose stored request had a value hidden when it was kept: one line a row, because most findings of a real run carry a session header and so most rows have it. What it means is said once, above the list (RETEST_HIDDEN_CONSEQUENCE). */
export const RETEST_HIDDEN_NOTE = "A stored value was hidden when the finding was kept.";

/** What a hidden value means for a label, said once above a list of findings that has one (the picker, the plan's list): the replay is not the original request, so a not reproduced label cannot be backed by the log. */
export const RETEST_HIDDEN_CONSEQUENCE = "For a finding with a hidden value the replay is not the original request, so a not reproduced label for it cannot be backed by the log.";

/** What the picker says about the findings with a hidden value, where they can still be chosen: a replay without the value can show a weakness is there but cannot show it is gone, which is what the log can back (the hidden-value consequence above says it once for a not reproduced label). */
export const RETEST_HIDDEN_CHOOSE = "You can still choose one. A replay without that value can show a weakness is there, but it cannot show it is gone.";

/** One finding the picker offers: what the checked model stored for it. */
export type RetestCandidate = {
  id: string;
  title: string;
  /** A test category id, as the agent filed it. */
  category: string;
  /** How many stored requests the finding has. */
  requests: number;
  /** The stored response condition in words, "" when none was stored. */
  condition: string;
  hasCondition: boolean;
  /** A stored request carries a value that was hidden when the finding was kept. */
  hidden: boolean;
};

/** storedRequests is the reproduction steps of a finding that carry a request a retest can send again: an object with a method and a path (an older stored copy holds a plain string, which a retest cannot send). */
function storedRequests(f: Pick<PTFinding, "reproduction">): PTRequest[] {
  const out: PTRequest[] = [];
  for (const s of Array.isArray(f.reproduction) ? f.reproduction : []) {
    const r = s?.request as unknown;
    if (r === null || typeof r !== "object") continue;
    const req = r as PTRequest;
    if (typeof req.method === "string" && req.method.trim() !== "" && typeof req.path === "string" && req.path.trim() !== "") out.push(req);
  }
  return out;
}

/** hasHiddenValue says a stored request has a value that was hidden: in its path, its body or a header's value. */
function hasHiddenValue(reqs: readonly PTRequest[]): boolean {
  for (const r of reqs) {
    if (String(r.path ?? "").includes(HIDDEN_MARKER) || String(r.body ?? "").includes(HIDDEN_MARKER)) return true;
    for (const h of Array.isArray(r.headers) ? r.headers : []) if (String(h?.value ?? "").includes(HIDDEN_MARKER)) return true;
  }
  return false;
}

/** retestCandidates lists the findings of a stored pen test or red team model that have a request to replay, in the order the model holds them. A finding with no reproduction step that carries a method and a path is not offered, and a second finding with an id already seen is left to the first. */
export function retestCandidates(doc: Pick<PentestDoc, "findings"> | null | undefined): RetestCandidate[] {
  const out: RetestCandidate[] = [];
  const seen = new Set<string>();
  for (const f of Array.isArray(doc?.findings) ? doc!.findings! : []) {
    const id = typeof f?.id === "string" ? f.id : "";
    if (id === "" || seen.has(id)) continue;
    seen.add(id);
    const reqs = storedRequests(f);
    if (reqs.length === 0) continue;
    const condition = matchWords(f.indicator?.when);
    out.push({
      id,
      title: typeof f.title === "string" ? f.title : "",
      category: typeof f.category === "string" ? f.category : "",
      requests: reqs.length,
      condition,
      hasCondition: condition !== "",
      hidden: hasHiddenValue(reqs),
    });
  }
  return out;
}

/** defaultRetestIds is the findings the picker starts with: the ones the replay can send in full (no value hidden when the finding was kept), in the model's order, at most max. A finding with a hidden value is replayed without it (a hidden header is not sent), so most findings of a real run, which carry a session header, cannot be backed by the log when a retest says the weakness is gone; they are listed and can be chosen, but are not chosen for the person. When every finding has one, none is chosen. The server's default for a plan read that names no finding is the same rule (secassess.DefaultRetestIDs). */
export function defaultRetestIds(candidates: readonly (Pick<RetestCandidate, "id"> & { hidden?: boolean })[], max: number = RETEST_MAX): string[] {
  return candidates
    .filter((c) => c.hidden !== true)
    .slice(0, Math.max(0, max))
    .map((c) => c.id);
}

/** RetestGroups splits the findings the picker offers by whether the replay can send them in full, each in the model's order. */
export type RetestGroups<T> = { full: T[]; hidden: T[] };

/** retestGroups splits candidates into the ones the replay sends in full and the ones with a value hidden when the finding was kept. */
export function retestGroups<T extends { hidden?: boolean }>(candidates: readonly T[]): RetestGroups<T> {
  const out: RetestGroups<T> = { full: [], hidden: [] };
  for (const c of candidates) (c.hidden === true ? out.hidden : out.full).push(c);
  return out;
}

/** The words of a choice the bound refuses. */
export function retestLimitWords(max: number): string {
  return `A retest replays at most ${max} findings. Leave one out to choose another.`;
}

/** toggleRetestId adds or removes one finding from the choice. Adding is refused, with words, once max are chosen; a finding already chosen is not added twice; the order chosen is kept. */
export function toggleRetestId(current: readonly string[], id: string, on: boolean, max: number = RETEST_MAX): { ids: string[]; error?: string } {
  const has = current.includes(id);
  if (!on) return { ids: current.filter((x) => x !== id) };
  if (has) return { ids: [...current] };
  if (current.length >= max) return { ids: [...current], error: retestLimitWords(max) };
  return { ids: [...current, id] };
}

/** retestChosenIds is the choice kept to the findings the picker offers, in the order the model holds them: an id the model no longer offers never goes to the plan. */
export function retestChosenIds(chosen: readonly string[], candidates: readonly Pick<RetestCandidate, "id">[]): string[] {
  const offered = new Set(candidates.map((c) => c.id));
  return chosen.filter((id, i) => offered.has(id) && chosen.indexOf(id) === i);
}

/** retestCountLine is how many findings are chosen against the bound: "3 of 8 findings chosen". */
export function retestCountLine(n: number, max: number): string {
  return `${n} of ${max} ${plural(max, "finding", "findings")} chosen`;
}

/** retestOfferLine says how many findings the run has that a retest can replay, how many of them the replay can send in full (the ones chosen for the person) and how many had a value hidden when the finding was kept (listed, not chosen), and the bound when they are more than it replays. `hidden` is how many of the `total` have a hidden value. */
export function retestOfferLine(total: number, max: number, hidden = 0): string {
  if (total === 0) return "No finding in this model has a stored request, so there is nothing to retest.";
  const base = `${total} ${plural(total, "finding has", "findings have")} a stored request to replay.`;
  const bound = total > max ? ` A retest replays at most ${max}: choose which.` : "";
  const n = Math.min(Math.max(0, Math.floor(hidden)), total);
  if (n === 0) return `${base}${bound}`;
  const full = total - n;
  if (full === 0) {
    const all = total === 1 ? "It has" : "Every one has";
    return `${base} ${all} a value that was hidden when the finding was kept, so none is chosen for you.${bound}`;
  }
  const sent = full > max ? `${full} can be sent again in full, and the first ${max} of them are chosen.` : `${full} can be sent again in full and ${plural(full, "is", "are")} chosen.`;
  const kept = `${n} ${plural(n, "has", "have")} a value that was hidden when the finding was kept; ${n === 1 ? "it is listed after and is not chosen for you." : "they are listed after and none of them is chosen for you."}`;
  return `${base} ${sent} ${kept}${bound}`;
}

/** retestHiddenCount is how many of the findings have a value hidden when the finding was kept. */
export function retestHiddenCount(candidates: readonly { hidden?: boolean }[]): number {
  return candidates.filter((c) => c.hidden === true).length;
}

/** retestCandidateNotes is the notes under a finding of the picker: its stored requests, its condition and, when it has one, the hidden-value warning. */
export function retestCandidateNotes(c: Pick<RetestCandidate, "requests" | "hasCondition" | "hidden">): string[] {
  const notes = [`${c.requests} stored ${plural(c.requests, "request", "requests")}`, c.hasCondition ? RETEST_CONDITION_WORDS.has : RETEST_CONDITION_WORDS.none];
  if (c.hidden) notes.push(RETEST_HIDDEN_NOTE);
  return notes;
}

/** What the picker hands the plan: the run to retest, the chosen findings, the project and the vocabulary the model answer carried (the plan's words for a finding's category come from it). */
export type RetestRequest = { ofRun: string; findings: string[]; projectHash: string; vocab?: ModelVocab };

// ---- the retest's plan ----

/** retestChoices is what the plan is read with for a retest: the earlier run and the findings chosen, in the order chosen. The plan and the launch carry the same two. */
export function retestChoices(req: Pick<RetestRequest, "ofRun" | "findings">): AssessChoices {
  return { ofRun: req.ofRun, findings: [...req.findings] };
}

/** The words for the kind of an earlier run, by the kind's id. */
export const RETEST_OF_KIND_WORDS: Readonly<Record<string, string>> = {
  pentest_local: "penetration test",
  red_team_local: "red team exercise",
};

/** retestOfKindWords names the earlier run's kind; a kind this table lacks reads as "assessment". */
export function retestOfKindWords(kind: string | undefined): string {
  return kind !== undefined && Object.prototype.hasOwnProperty.call(RETEST_OF_KIND_WORDS, kind) ? RETEST_OF_KIND_WORDS[kind] : "assessment";
}

/** The refusal codes of one finding a retest cannot replay (secassess.RetestRefusal), each in a sentence that names the finding. */
export const RETEST_REFUSED_WORDS: Readonly<Record<string, (finding: string, max: number) => string>> = {
  unknown_finding: (f) => `${f} is not in the earlier run's checked model.`,
  no_request: (f) => `${f} has no stored request to replay: its reproduction is code or text only.`,
  too_many: (f, max) => `A retest replays at most ${max} findings, so ${f} was left out.`,
  duplicate: (f) => `${f} was chosen twice.`,
};

/** retestRefusedWords is why one finding is not in the retest, in words; a code this table lacks reads as a plain "cannot be replayed". */
export function retestRefusedWords(code: string, finding: string, max: number = RETEST_MAX): string {
  return Object.prototype.hasOwnProperty.call(RETEST_REFUSED_WORDS, code) ? RETEST_REFUSED_WORDS[code](finding, max) : `${finding} cannot be replayed.`;
}

/** retestPlanFindings is the findings the plan replays, in the order it chose them, each with what the earlier run stored for it. An id the plan names that its list does not hold is left out. */
export function retestPlanFindings(r: Pick<AssessRetestPlan, "findings" | "selected">): AssessRetestFinding[] {
  const byId = new Map((r.findings ?? []).map((f) => [f.id, f] as const));
  return (r.selected ?? []).map((id) => byId.get(id)).filter((f): f is AssessRetestFinding => f !== undefined);
}

/** retestPlanLine says what the retest replays: how many findings of how many the earlier run has with a stored request. */
export function retestPlanLine(r: Pick<AssessRetestPlan, "findings" | "selected" | "max">): string {
  const n = (r.selected ?? []).length;
  const total = (r.findings ?? []).length;
  if (n === 0) return "No finding is chosen to replay yet.";
  const head = `Replays ${n} of the ${total} ${plural(total, "finding", "findings")} of that run that ${plural(total, "has", "have")} a stored request`;
  return `${head} (at most ${r.max > 0 ? r.max : RETEST_MAX}).`;
}

/** retestPlanNotes is the notes under one finding of the plan: the same three the picker gives, from what the server read. */
export function retestPlanNotes(f: Pick<AssessRetestFinding, "steps" | "has_condition" | "hidden">): string[] {
  return retestCandidateNotes({ requests: f.steps, hasCondition: f.has_condition === true, hidden: f.hidden === true });
}

/** retestTargetSuggestion is the address the earlier run confirmed, offered as a suggestion for the target field, "" when it gave none. The developer still applies and confirms it. */
export function retestTargetSuggestion(r: Pick<AssessRetestPlan, "of_target"> | undefined): string {
  return (r?.of_target ?? "").trim();
}

// ---- the label of a finding ----

/** One retest's label for a finding, with the retest it came from. `at` is the date the retest ran (launched_at; the check time for an answer that has none): the label is dated by it and the list is ordered by it. */
export type FindingRetest = { run: string; at: string; state: string; started: boolean; result: RetestResultView };

/** retestRanAt is the date a retest's labels are shown under: when the retest was launched, else when its model was checked. */
export function retestRanAt(rt: Pick<RetestView, "launched_at" | "at">): string {
  const l = typeof rt.launched_at === "string" ? rt.launched_at : "";
  return l !== "" && !Number.isNaN(Date.parse(l)) ? l : rt.at;
}

/** retestsByFinding joins the retests of a run onto its findings: each finding id maps to its labels, the newest retest first. The order is the date each retest ran (retestRanAt), newest first, whatever order the server listed them in (a tie keeps the server's order, a date that cannot be read goes last), so the label a row shows is always the latest retest's, the date printed beside a label is the one it is ordered by, and the older ones are the ones behind the disclosure. A finding's label is the first of them that has a result for it. */
export function retestsByFinding(retests: readonly RetestView[] | null | undefined): Map<string, FindingRetest[]> {
  const out = new Map<string, FindingRetest[]>();
  const listed = (Array.isArray(retests) ? retests : [])
    .filter((rt): rt is RetestView => !!rt && typeof rt.run === "string")
    .map((rt, i) => ({ rt, i, t: Date.parse(retestRanAt(rt)) }))
    .sort((a, b) => {
      const an = Number.isNaN(a.t);
      const bn = Number.isNaN(b.t);
      if (an !== bn) return an ? 1 : -1;
      return an || a.t === b.t ? a.i - b.i : b.t - a.t;
    });
  for (const { rt } of listed) {
    for (const r of Array.isArray(rt.results) ? rt.results : []) {
      const id = typeof r?.finding === "string" ? r.finding : "";
      if (id === "") continue;
      const list = out.get(id) ?? [];
      list.push({ run: rt.run, at: retestRanAt(rt), state: rt.state, started: rt.started === true, result: r });
      out.set(id, list);
    }
  }
  return out;
}

/** retestBacked says a label has the helper's log behind it (Observer's reading is "logged"). A label with no log, or whose target did not start, is the agent's claim alone; an inconclusive label claims nothing. */
export function retestBacked(r: Pick<RetestResultView, "result" | "evidence_state" | "evidence_reason">): boolean {
  return retestEvidenceWords(r)?.state === "logged";
}

/** retestStanding is the sentence a finding's row adds when the label it shows (the newest) may hide an older one that said the weakness was there: the newest says not reproduced with no log behind it, or is inconclusive, and an older retest labelled the finding reproduced. Without it a neutral label on top reads as the end of the matter while the older, more alarming one is behind a disclosure. It names the older retest's date and whether its log backs it, and says what is wrong with the newer label. It is the one place the ordering is decided (newest first, a label is judged by its own log): a reproduced newest label, a newest not reproduced label that the log backs, and a finding no older retest reproduced all need no sentence. null then. `fmt` formats the older retest's date; the list is retestsByFinding's (newest first). */
export function retestStanding(list: readonly FindingRetest[], fmt: (iso: string) => string = (iso) => iso): string | null {
  if (list.length < 2) return null;
  const [newest, ...older] = list;
  const label = newest.result.result;
  if (label !== "not_reproduced" && label !== "inconclusive") return null;
  if (label === "not_reproduced" && retestBacked(newest.result)) return null;
  const prior = older.find((r) => r.result.result === "reproduced");
  if (!prior) return null;
  const lead = label === "inconclusive" ? "The newer retest was inconclusive and claims nothing." : "The newer label has no log behind it.";
  const tail = retestBacked(prior.result) ? "and its log backs that label" : "with no log behind that label either";
  return `${lead} An older retest (${fmt(prior.at)}) labelled this finding reproduced, ${tail}.`;
}

/** The sentence about a label's log that stands where an unlogged label's reason ends. */
const RETEST_UNLOGGED_TAIL = "The agent can write any file in the run folder, so the label stands as the agent's claim.";

/** What a logged label says, by the label. */
const RETEST_LOGGED_DETAIL: Readonly<Record<string, string>> = {
  reproduced:
    "In this copy of the project, the helper log holds the replay of the stored request, and its response meets the stored condition while the control request's response does not. This is not proof of impact, and it says nothing about production.",
  not_reproduced:
    "In this copy of the project, the helper log holds the replay of the stored request, and its response does not meet the stored condition. That is one replay: it does not show the weakness is gone from your code or from production.",
};

/** The pill for a label the helper's log backs. Findings call the same state "Helper log matches", but beside a "Not reproduced" label that reads as the log matching the weakness, the opposite of what it says; a label is backed, not matched. */
export const RETEST_LOG_BACKS = "Helper log backs the label";

/** RetestEvidenceWord is Observer's reading of the helper's log for one label. */
export type RetestEvidenceWord = { state: EvidenceState; label: string; tone: Tone; detail: string };

/** retestEvidenceWords is Observer's reading of the helper's log for a label, in the words findings use for theirs except that a backed label says so (Helper log backs the label): No log with the reason's sentence, or Not started. An inconclusive label claims nothing, so it has no reading (null). The tones are the findings' (info for a match, neutral for the rest): the log is a file the agent can write, so a match is never shown as a pass. */
export function retestEvidenceWords(r: Pick<RetestResultView, "result" | "evidence_state" | "evidence_reason">): RetestEvidenceWord | null {
  if (r.result === "inconclusive") return null;
  const reason = typeof r.evidence_reason === "string" ? r.evidence_reason.trim() : "";
  if (r.evidence_state === "logged") {
    const detail = Object.prototype.hasOwnProperty.call(RETEST_LOGGED_DETAIL, r.result) ? RETEST_LOGGED_DETAIL[r.result] : "The helper log backs this label.";
    return { state: "logged", label: RETEST_LOG_BACKS, tone: "info", detail: `${detail} The log is a file the agent can write.` };
  }
  if (r.evidence_state === "not_started") {
    return { state: "not_started", label: EVIDENCE_LABELS.not_started, tone: "neutral", detail: evidenceReasonSentence(reason === "" ? "target_not_started" : reason) };
  }
  const why = reason === "" ? "Observer has no request log that backs this label." : evidenceReasonSentence(reason);
  return { state: "unlogged", label: EVIDENCE_LABELS.unlogged, tone: "neutral", detail: `${why} ${RETEST_UNLOGGED_TAIL}` };
}

/** RetestReading is what a finding's row says about one retest label: the label, the reading of its log (null for an inconclusive one) and the sentence that nothing was closed. */
export type RetestReading = { label: RetestWord; evidence: RetestEvidenceWord | null; nothingClosed: string };

/** retestReading reads one label for a row. */
export function retestReading(r: RetestResultView): RetestReading {
  return { label: retestResultWords(r.result), evidence: retestEvidenceWords(r), nothingClosed: RETEST_NOTHING_CLOSED };
}

/** The counters of a retest's summary, in the order they are listed, with the words each carries. */
export const RETEST_SUMMARY_PARTS: readonly { key: keyof RetestSummary; label: string }[] = [
  { key: "replayed", label: "Chosen" },
  { key: "reproduced", label: "Reproduced" },
  { key: "not_reproduced", label: "Not reproduced" },
  { key: "inconclusive", label: "Inconclusive" },
  { key: "missing", label: "Not labelled" },
];

/** retestSummaryCounts lists a retest's counters; a count the answer lacks reads as 0. Empty when the answer has no summary. */
export function retestSummaryCounts(s: Partial<RetestSummary> | null | undefined): { key: keyof RetestSummary; label: string; n: number }[] {
  if (!s || typeof s !== "object") return [];
  return RETEST_SUMMARY_PARTS.map((p) => {
    const v = s[p.key];
    return { ...p, n: typeof v === "number" && Number.isFinite(v) && v > 0 ? v : 0 };
  });
}

/** retestSummaryLine is the counters in one sentence: "3 findings chosen: 1 reproduced, 1 not reproduced, 1 inconclusive, 0 not labelled." The first count is the findings the retest was started with, not the ones that were replayed: a finding the agent did not label may never have been sent, so the word is "chosen" (the file's own count is named replayed, which says more than it knows). */
export function retestSummaryLine(s: Partial<RetestSummary> | null | undefined): string {
  const c = retestSummaryCounts(s);
  if (c.length === 0) return "";
  const n = c[0].n;
  const rest = c.slice(1).map((p) => `${p.n} ${p.label.toLowerCase()}`);
  return `${n} ${plural(n, "finding", "findings")} chosen: ${rest.join(", ")}.`;
}

// ---- a retest run's own results ----

/** One row of a retest run's results table. */
export type RetestRow = {
  finding: string;
  /** The earlier finding's own title, else its id. */
  title: string;
  category: string;
  categoryTitle: string;
  result: string;
  label: RetestWord;
  evidence: RetestEvidenceWord | null;
  /** The agent's note, text only. */
  note: string;
  /** The requests the label cites, each once: the attack, the control, then the others. */
  cited: CitedProbe[];
};

/** retestRows turns a retest run's results into rows, in the order the agent listed them. */
export function retestRows(doc: Pick<RetestDoc, "results"> | null | undefined, vocab?: ModelVocab): RetestRow[] {
  return (Array.isArray(doc?.results) ? doc!.results! : []).map((r) => {
    const category = typeof r.category === "string" ? r.category : "";
    return {
      finding: r.finding,
      title: typeof r.title === "string" && r.title.trim() !== "" ? r.title : r.finding,
      category,
      categoryTitle: category === "" ? "Not stated" : wstgTitle(category, vocab),
      result: r.result,
      label: retestResultWords(r.result),
      evidence: retestEvidenceWords(r),
      note: typeof r.note === "string" ? r.note : "",
      cited: citedProbes({ indicator: { attack: r.attack, control: r.control }, evidence: r.evidence }),
    };
  });
}

/** retestNotLabelled lists the findings the retest was asked to replay and gave no label, in the order they were asked. */
export function retestNotLabelled(asked: readonly string[] | null | undefined, doc: Pick<RetestDoc, "results"> | null | undefined): string[] {
  const labelled = new Set((Array.isArray(doc?.results) ? doc!.results! : []).map((r) => r.finding));
  return (asked ?? []).filter((id) => !labelled.has(id));
}

// ---- the red team's objective ----

/** The longest objective, in characters (secassess.MaxObjective); the plan states the bound in force. */
export const OBJECTIVE_MAX = 200;

/** The help line under the objective field: one short sentence (N-17). The placeholder shows what to type, the help drawer holds the rest, and the Exercise tab says whose the objective is. */
export const OBJECTIVE_HELP = "Leave it empty and the agent states an objective of its own.";

/** objectiveLength counts an objective in characters, not bytes or code units. */
export function objectiveLength(s: string): number {
  return Array.from(s).length;
}

/** clipObjective keeps the first max characters of s: whole characters, never half of one. */
export function clipObjective(s: string, max: number = OBJECTIVE_MAX): string {
  const chars = Array.from(s);
  return chars.length <= max ? s : chars.slice(0, Math.max(0, max)).join("");
}

/** objectiveCounterLine is the counter under the field: "12 of 200 characters". */
export function objectiveCounterLine(text: string, max: number = OBJECTIVE_MAX): string {
  return `${objectiveLength(text)} of ${max} characters`;
}

/** objectiveCleanedNote says what the task carries when the server cleaned the objective (it takes out line breaks and backticks): "" when it carries what was typed. */
export function objectiveCleanedNote(typed: string, inForce: string | undefined): string {
  const t = typed.trim();
  const f = (inForce ?? "").trim();
  if (t === "" || f === t) return "";
  return f === "" ? "The task carries no objective: the server left out everything you typed." : `The task carries it as: ${f}`;
}

/** The words for whose objective it is, by the source Observer records. */
export const OBJECTIVE_SOURCE_WORDS: Readonly<Record<"developer" | "agent" | "none" | "unknown", string>> = {
  developer: "In your words",
  agent: "Stated by the agent",
  none: "No objective was recorded",
  unknown: "Whose words these are is not stated",
};

/** ObjectiveReading is the objective of an exercise with its source in words. */
export type ObjectiveReading = { source: "developer" | "agent" | "none" | "unknown"; sourceLabel: string; text: string };

/** objectiveReading reads an exercise's objective and whose it is. Observer records the source (objective_by); an objective with no source of a known kind is never attributed to the developer. */
export function objectiveReading(ex: Pick<PTExercise, "objective" | "objective_by"> | null | undefined): ObjectiveReading {
  const text = typeof ex?.objective === "string" ? ex.objective.trim() : "";
  if (text === "") return { source: "none", sourceLabel: OBJECTIVE_SOURCE_WORDS.none, text: "" };
  const by = ex?.objective_by === "developer" || ex?.objective_by === "agent" ? ex.objective_by : "unknown";
  return { source: by, sourceLabel: OBJECTIVE_SOURCE_WORDS[by], text: typeof ex?.objective === "string" ? ex.objective : "" };
}

// ---- the red team's chain ----

/** The heading of the opinion column: what would have detected or stopped a step is the agent's opinion, and the heading says so. */
export const CHAIN_STOP_HEADING = "What would have detected or stopped it (the agent's opinion)";

/** The cell of a step that names no finding. */
export const CHAIN_NO_FINDING = "no finding";

/** The cell of a step the agent gave no opinion for. */
export const CHAIN_NO_STOP = "The agent gave no opinion.";

/** What the tab says when the chain has no step. */
export const CHAIN_EMPTY_WORDS = "The agent recorded no steps.";

/** One step of the chain, ready to show. */
export type ChainRow = {
  n: number;
  /** The agent's words for the step. */
  step: string;
  /** The finding the step used, with its title; null for a step that names none. */
  finding: { id: string; title: string } | null;
  result: { code: string; label: string; tone: Tone };
  /** The agent's opinion of what would have detected or stopped it, "" when it gave none. */
  stop: string;
};

/** chainRows turns an exercise's chain into rows, in the order the agent listed the steps. A finding is named only when the model holds it; a step that cites none is a step with no finding. */
export function chainRows(pt: Pick<PentestDoc, "exercise" | "findings"> | null | undefined): ChainRow[] {
  const chain = Array.isArray(pt?.exercise?.chain) ? pt!.exercise!.chain! : [];
  const titles = new Map<string, string>();
  for (const f of Array.isArray(pt?.findings) ? pt!.findings! : []) if (typeof f?.id === "string" && !titles.has(f.id)) titles.set(f.id, typeof f.title === "string" ? f.title : "");
  return chain.map((s, i) => {
    const id = typeof s.finding === "string" ? s.finding : "";
    const w = chainResultWords(s.result);
    return {
      n: i + 1,
      step: typeof s.step === "string" ? s.step : "",
      finding: id !== "" && titles.has(id) ? { id, title: titles.get(id)! } : null,
      result: { code: typeof s.result === "string" ? s.result : "", label: w.label, tone: w.tone },
      stop: typeof s.stop === "string" ? s.stop.trim() : "",
    };
  });
}

/** chainCountsLine is how the steps went, in a sentence: "4 steps: 2 achieved, 1 partly achieved, 1 blocked." Empty for no steps; a result with no step is left out. */
export function chainCountsLine(rows: readonly Pick<ChainRow, "result">[]): string {
  if (rows.length === 0) return "";
  const tally = new Map<string, number>();
  for (const r of rows) tally.set(r.result.label, (tally.get(r.result.label) ?? 0) + 1);
  const parts = [...tally.entries()].map(([label, n]) => `${n} ${label.toLowerCase()}`);
  return `${rows.length} ${plural(rows.length, "step", "steps")}: ${parts.join(", ")}.`;
}

// ---- the run rows ----

/** runRetestLine is the line a retest run's row carries: which earlier run it retested and how many findings were chosen for it (a run that ended with nothing replayed nothing, so the line never says "replayed"). `earlier` is that run's label (assessRunLabel, the one name a run has wherever it is mentioned), found by the caller in the run list; "" when the list no longer holds it, and the line then says so and shows no id. "" for a run that is not a retest. */
export function runRetestLine(run: Pick<AssessRun, "retest_of" | "retest_findings">, earlier?: string): string {
  const of = (run.retest_of ?? "").trim();
  if (of === "") return "";
  const n = (run.retest_findings ?? []).length;
  const label = (earlier ?? "").trim();
  const what = label ? `the earlier run (${label})` : "an earlier run that is no longer in the list";
  const count = n > 0 ? `${n} ${plural(n, "finding", "findings")} chosen` : "no finding recorded";
  return `Retest of ${what}: ${count}.`;
}

/** runObjectiveLine is the line a red team run's row carries: its objective, clipped. "" when the run has none. The full text is on the model view's Exercise tab. */
export function runObjectiveLine(run: Pick<AssessRun, "objective">, max: number = 90): string {
  const t = (run.objective ?? "").trim();
  if (t === "") return "";
  return `Objective: ${objectiveLength(t) > max ? `${clipObjective(t, Math.max(1, max - 1))}…` : t}`;
}
