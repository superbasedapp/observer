// secAssessModel is the pure side of the assessment model view
// (docs/plans/security-assessments-depth-plan-2026-11-14.md W6a): the shapes of
// GET /api/security/assessments/model (the checked copy of a run's
// assessment.json, which Observer built, never the agent's file as written),
// and the helpers the model view's components read: filters and sorts over
// threats, the mitigation state words, the STRIDE-per-element matrix, the flow
// table, the attack tree list, the pen test coverage rows, the evidence words
// and the honest-limits strip. Pure: no fetch, no React.
//
// Words rule (plan section 13): every sentence here says what Observer checked,
// never more. "Found near the cited line" is not "a working control"; a
// coverage row the agent marked tested is "claimed" until a logged request
// backs it; nothing here says clean, verified, confirmed, secure or passed
// (secAssessModel.test.ts pins the words).
//
// The types mirror the Go JSON tags of internal/secassess (model.go,
// validate*.go) and internal/secassesssvc (model.go). A field tagged
// `computed:"true"` in Go (band, score, ref state, match line) is Observer's
// own computation and is what the view shows.

import type { Tone } from "../../../shared/lib/tone.ts";
import { ASSESS_FATAL_WORDS, ASSESS_MODEL_PATH, ASSESS_SETTINGS_WHERE, assessRefConditionWords, assessRefTallyWords } from "./secAssess.ts";

// ---- the wire shapes ----

/** What Observer found when it looked at a reference (secassess.RefState). */
export type ModelRefState = "found" | "exists" | "claimed_not_found" | "missing" | "invalid" | "unchecked";

/** The inherent band of a likelihood x impact rating (secassess.Band). */
export type ModelBand = "low" | "medium" | "high" | "critical";

export type ModelRef = {
  /** Project-relative, forward slashes. */
  path: string;
  line?: number;
  end_line?: number;
  /** The agent's quoted text; how a reference earns "found". */
  needle?: string;
  /** Observer's finding about the reference. */
  state?: ModelRefState;
  /** The line the needle was found on ("found" only). */
  match_line?: number;
};

export type ModelRating = { likelihood: number; impact: number };

export type ModelComponent = {
  id: string;
  name: string;
  type: string;
  description?: string;
  paths?: ModelRef[];
  tech?: string[];
  zone?: string;
};
export type ModelZone = { id: string; name: string; description?: string };
export type ModelActor = { id: string; name: string; kind: string };
export type ModelAsset = { id: string; name: string; sensitivity: string; data_classes?: string[]; stored_in?: string[] };
export type ModelEntryPoint = { id: string; component: string; kind: string; ref?: ModelRef; authn?: string; exposure?: string };
export type ModelFlow = {
  id: string;
  from: string;
  to: string;
  data?: string[];
  protocol?: string;
  crosses?: string[];
  authn?: string;
  /** yes | no | unknown. */
  encrypted?: string;
  personal_data?: boolean;
};

export type ModelSystem = {
  components?: ModelComponent[];
  zones?: ModelZone[];
  actors?: ModelActor[];
  assets?: ModelAsset[];
  entry_points?: ModelEntryPoint[];
  flows?: ModelFlow[];
};

/** The thing a threat is about: component | actor | flow | entry_point | asset. */
export type ModelElement = { kind: string; id: string };

export type ModelMitigation = { text: string; refs?: ModelRef[] };
export type ModelMissing = { text: string; control?: string; effort?: string; refs?: ModelRef[] };
export type ModelAbuseCase = { actor?: string; goal: string; steps?: string[] };

export type ModelThreat = {
  id: string;
  title: string;
  /** stride | linddun | owasp_llm | owasp_agentic. */
  framework: string;
  category: string;
  element: ModelElement;
  actor?: string;
  description?: string;
  rating: ModelRating;
  existing?: ModelMitigation[];
  missing?: ModelMissing[];
  cwe?: string[];
  capec?: string[];
  asvs?: string[];
  /** identified | mitigated | partial | accepted_by_design. */
  status?: string;
  abuse_case?: ModelAbuseCase;
  /** Computed by Observer from the rating. */
  band?: ModelBand;
  score?: number;
};

export type ModelNoThreat = { element: ModelElement; category: string; reason: string };
export type ModelTreeNode = { id: string; parent?: string; label: string; op?: string; leaf?: boolean };
export type ModelTree = { root: string; nodes?: ModelTreeNode[] };
export type ModelGenerator = { tool?: string; model?: string };

export type ThreatModelDoc = {
  schema: string;
  run_id: string;
  prompt_version?: string;
  generator: ModelGenerator;
  summary?: string;
  scope: { in_scope?: string[]; out_of_scope?: string[]; assumptions?: string[] };
  system: ModelSystem;
  threats?: ModelThreat[];
  no_threat?: ModelNoThreat[];
  attack_trees?: ModelTree[];
  open_questions?: string[];
  limits?: string[];
};

export type PTStart = {
  argv?: string[];
  source?: string;
  /** The agent's claim. */
  started: boolean;
  startup_seconds?: number;
  health: { path?: string; status?: number };
};
export type PTCoverageClaim = { category: string; status: string; reason?: string; probes?: string[]; notes?: string };
/** A header as the agent wrote it in a request or a condition. */
export type PTHeader = { name: string; value: string };
/** The condition on a response (secassess.PTMatch): what the attack response meets and the control response does not. Every member is the agent's. */
export type PTMatch = {
  status?: number;
  body_contains?: string[];
  body_not_contains?: string[];
  header_present?: string[];
  header_absent?: string[];
  header_contains?: PTHeader[];
};
/** One request a person can send again (secassess.PTRequest). An older stored copy holds a plain string here; requestLine and the readers below take both. */
export type PTRequest = { method: string; path: string; headers?: PTHeader[]; body?: string };
export type PTIndicator = { control?: string; attack?: string; when?: PTMatch };
export type PTRepro = { step: string; request?: PTRequest };
/** One step of a red team exercise's chain (secassess.PTChainStep). The step, the stop and the objective are the agent's words, shown as text; `finding` is only kept by Observer when it is a kept finding's id. */
export type PTChainStep = { step: string; finding?: string; result: string; stop?: string };
/** A red team run's exercise (secassess.PTExercise). `objective_by` is Observer's word for whose words the objective is, never the agent's. */
export type PTExercise = { objective?: string; objective_by?: "developer" | "agent" | string; chain?: PTChainStep[] };
/** Observer's evidence for a finding (secassess.Evidence*): logged | unlogged | not_started. Absent on a copy stored before the request helper existed, which reads as unlogged. */
export type EvidenceState = "logged" | "unlogged" | "not_started";
export type PTFinding = {
  id: string;
  title: string;
  /** A WSTG category id (INFO, CONF, ... APIT). */
  category: string;
  cwe?: string[];
  rating: ModelRating;
  /** The agent's optional CVSS 4.0 base vector, as Observer vetted it (V5); absent when the agent wrote none or it was left out. */
  cvss?: string;
  /** Observer's base score of that vector, computed from the vector alone (the agent's own number is never read). 0 is a valid score. */
  cvss_score?: number;
  /** The band of that score; absent for a score of 0.0 (no band). */
  cvss_band?: ModelBand;
  /** The agent's claim: observed | inferred. Observer's own check is the evidence state. */
  basis: string;
  where: { refs?: ModelRef[] };
  route?: string;
  indicator?: PTIndicator;
  /** Probe ids the agent cites. */
  evidence?: string[];
  /** Observer's own check against the helper log, computed (never the agent's word). Absent reads as unlogged. */
  evidence_state?: EvidenceState;
  /** Why the state is not logged: a closed code (EVIDENCE_REASON_WORDS), only with unlogged and not_started. */
  evidence_reason?: string;
  reproduction?: PTRepro[];
  impact?: string;
  fix?: string;
  status?: string;
  band?: ModelBand;
  score?: number;
};
export type PentestDoc = {
  schema: string;
  run_id: string;
  prompt_version?: string;
  generator: ModelGenerator;
  summary?: string;
  target: { url?: string; start: PTStart; accounts?: { label: string; role?: string }[] };
  method: { standard?: string };
  coverage?: PTCoverageClaim[];
  findings?: PTFinding[];
  /** A red team run's objective and chain (absent for a penetration test). */
  exercise?: PTExercise;
  limits?: string[];
};

/** What a retest gave one finding (secassess.RTResult): the label, the two requests it rests on, the agent's note and Observer's reading of the helper's log. `title` and `category` are the earlier finding's own. */
export type RTResult = {
  finding: string;
  /** reproduced | not_reproduced | inconclusive. */
  result: string;
  attack?: string;
  control?: string;
  evidence?: string[];
  note?: string;
  title?: string;
  category?: string;
  /** Empty for an inconclusive label, which claims nothing to back. */
  evidence_state?: EvidenceState;
  evidence_reason?: string;
};
/** A retest run's own result (secassess.RetestDoc). `of` is the earlier run, Observer's. */
export type RetestDoc = {
  schema: string;
  run_id: string;
  prompt_version?: string;
  generator: ModelGenerator;
  summary?: string;
  /** The agent's claim that the target started. */
  started: boolean;
  results?: RTResult[];
  limits?: string[];
  of?: string;
};
/** A retest's label counts (secassess.RetestSummary): `missing` are findings it was asked to replay and gave no label. */
export type RetestSummary = { replayed: number; reproduced: number; not_reproduced: number; inconclusive: number; missing: number };
/** One finding's label in a retest of an earlier run (secassesssvc.RetestResultView). */
export type RetestResultView = {
  finding: string;
  result: string;
  evidence_state?: EvidenceState;
  evidence_reason?: string;
  attack?: string;
  control?: string;
  note?: string;
};
/** One retest of a run, as the earlier run's model answer lists it (secassesssvc.RetestView): the run that did it, when it was launched, when its model was last checked, whether the agent says the target started, the findings it was asked for and the labels it gave. */
export type RetestView = {
  run: string;
  /** When the retest run started: the date its labels are shown under and the order they are listed in. Absent from an answer that predates it, which is then dated and ordered by `at`. */
  launched_at?: string;
  /** When the retest's model was last checked: it moves when the run is checked again. */
  at: string;
  /** valid | partial. */
  state: string;
  started: boolean;
  asked: string[];
  summary?: RetestSummary;
  results: RetestResultView[];
};

// ---- the validation report ----

export type ModelIssue = {
  row: string;
  code: string;
  severity: "refused" | "dropped" | "warn";
  /** The item in the agent's file (a place such as findings[3], an index into what the agent wrote, not into what was kept). */
  path?: string;
  /** The id of the item the issue is about, when the check names it (a finding whose CVSS vector was left out). Absent on a record kept before it was recorded. */
  item?: string;
  message: string;
};
export type ModelCount = { read: number; left_out?: number; refused?: number; kept: number };
export type ModelRefTally = {
  found: number;
  exists: number;
  claimed_not_found: number;
  missing: number;
  invalid: number;
  unchecked: number;
};
export type CellState = "analysed" | "waived" | "empty";
export type CoverageCell = { category: string; state: CellState };
export type CoverageRow = { kind: string; id: string; name?: string; class: string; cells: CoverageCell[] };
export type FrameworkCoverage = { framework: string; analysed: number; waived: number; empty: number };
export type TMCoverage = {
  analysed: number;
  waived: number;
  empty: number;
  by_framework?: FrameworkCoverage[];
  rows?: CoverageRow[];
  ai_threats?: Record<string, number>;
};
/** The effective coverage words (secassess.Cov*): tested_claimed | tested_logged | skipped |
 *  not_applicable | tool_unavailable | skipped_not_started | missing. */
export type PTCoverageRow = { category: string; title: string; agent?: string; effective: string; reason?: string };
export type PTCoverage = { started: boolean; rows: PTCoverageRow[]; counts: Record<string, number> };
export type ModelSets = { frameworks?: string[]; method_extras?: string[]; categories?: string[]; ai_app?: boolean };

/** What Observer found when it compared a pen test's findings with the request helper's log (secassess.EvidenceReport). Absent on a copy stored before the helper existed. */
export type EvidenceReport = {
  /** on | off | withheld: whether the helper was written into the run folder, and why not. "" when not stated. */
  mode: "on" | "off" | "withheld" | "";
  /** intact | changed | missing | not_checked: the helper's files against what Observer wrote. */
  helper: "intact" | "changed" | "missing" | "not_checked" | "";
  /** ok | absent | unreadable | too_large | inconsistent | not_read: the log file. */
  log: "ok" | "absent" | "unreadable" | "too_large" | "inconsistent" | "not_read" | "";
  /** Lines in the log. */
  records: number;
  /** Requests the helper sent, and refused. */
  sent: number;
  refused: number;
  /** Requests counted against the budget. */
  requests: number;
  /** Findings by evidence state. */
  logged: number;
  unlogged: number;
  not_started: number;
  /** Findings that are not logged, by reason code (EVIDENCE_REASON_WORDS). */
  by_reason?: Record<string, number>;
};

export type ModelReport = {
  /** valid | partial | invalid. */
  state: string;
  contract: string;
  fatal?: string;
  issues?: ModelIssue[];
  issues_more?: number;
  counts?: Record<string, ModelCount>;
  refs: ModelRefTally;
  ignored_fields?: number;
  ignored_keys?: string[];
  tm?: TMCoverage;
  pt?: PTCoverage;
  /** Pen test and red team: the request helper and its log against the findings. */
  evidence?: EvidenceReport;
  /** A retest run: how many labels of each kind it gave (contract retest.v1). */
  rt?: RetestSummary;
  sets: ModelSets;
  /** How the references were looked at (secassess.RefCheck); absent for a check that predates it or looked at no files. */
  ref_check?: { window_lines: number; text_hidden?: number };
};

export type ModelResult = { report: ModelReport; tm?: ThreatModelDoc; pt?: PentestDoc; rt?: RetestDoc };

export type ModelRecord = {
  schema: number;
  run_id: string;
  validated_at: string;
  /** threatmodel.v1 | pentest.v1. */
  contract: string;
  anyway?: boolean;
  source_sha?: string;
  source_bytes: number;
  files?: { path: string; sha: string; lines: number }[];
  /** The model did not fit the stored copy's cap: the report is kept, the model is not. */
  truncated?: boolean;
  /** The read budget the reference check ran under (settings ref_budget_*); absent for a copy that predates it. */
  ref_budget?: { files: number; mib: number; seconds: number };
  result: ModelResult;
};

// ---- the vocabulary the server sends (secassess.ModelVocab) ----

export type ModelVocab = {
  stride: { id: string; letter: string; name: string; question: string }[];
  linddun: { id: string; name: string; question: string }[];
  /** class: external_entity | process | data_store | data_flow. */
  component_types: { id: string; class: string; holds_logs?: boolean; name: string }[];
  wstg: { id: string; title: string; intent: string; applies_when: string }[];
  ai_frameworks: { id: string; name: string }[];
  /** Lowest to highest. */
  bands: string[];
};

/** The Mermaid source of the data-flow diagram (secassess.RenderMermaid). */
export type ModelMermaid = {
  source: string;
  /** Nodes drawn. */
  nodes: number;
  /** Nodes the model has: every component, and every actor that takes part in a flow. */
  total_nodes: number;
  omitted_nodes: number;
  edges: number;
  omitted_edges: number;
  /** The cap in force (setting diagram_max_nodes). */
  max_nodes: number;
  /** The most characters a label keeps in the source (setting diagram_label_chars). */
  label_chars: number;
  /** How many of the labels drawn were shortened to fit label_chars. */
  labels_cut: number;
};

/** A threat that is in only one of the two compared models (secassess.DiffItem). */
export type ModelDiffItem = { id: string; title: string; element: ModelElement; category: string; band?: ModelBand; score?: number };
/** A threat in both models that differs (secassess.DiffChange). id is the id in this run, prev_id the one in the earlier run. */
export type ModelDiffChange = {
  id: string;
  prev_id: string;
  title: string;
  element: ModelElement;
  category: string;
  /** id | title: how the pair was matched. */
  match: string;
  from_band?: ModelBand;
  to_band?: ModelBand;
  from_score?: number;
  to_score?: number;
  title_changed?: boolean;
  from_status?: string;
  to_status?: string;
  missing_from?: number;
  missing_to?: number;
  existing_from?: number;
  existing_to?: number;
};
/** A pair the scored pass made (secassess.DiffSimilar): a threat of this run and a threat of the earlier run that probably describe the same flaw, tied by the place they cite and other signs rather than by their words. It is a guess: it is never counted as unchanged, and basis says what the two have in common. */
export type ModelDiffSimilar = {
  /** The id in this run, and the one in the earlier run. */
  id: string;
  prev_id: string;
  /** The title in this run, and the one in the earlier run (the two read differently, which is why the pass exists). */
  title: string;
  prev_title: string;
  element: ModelElement;
  category: string;
  /** The earlier threat's category, present only when it differs. */
  prev_category?: string;
  from_band?: ModelBand;
  to_band?: ModelBand;
  from_score?: number;
  to_score?: number;
  /** What the pair has in common: location, cwe, words, category, element. */
  basis: string[];
  /** The pair's score in the matching table; shown to nobody, kept for the order. */
  points: number;
};
export type ModelNameDiff = { added?: string[]; removed?: string[] };
/** What changed between this run's threat model and an earlier run's (secassess.ModelDiff, computed by Observer from the two
 *  stored copies; nothing of the earlier model is given to an agent). Present only when the request named `since`. */
export type ModelSince = {
  /** The earlier run's id. */
  prev_run?: string;
  added?: ModelDiffItem[];
  removed?: ModelDiffItem[];
  changed?: ModelDiffChange[];
  /** Pairs the scored pass made: probably the same threat, matched by the place it cites and other signs. In none of the counts above. */
  similar?: ModelDiffSimilar[];
  /** Threats in both models that read the same. */
  unchanged: number;
  matched_by_id: number;
  matched_by_title: number;
  system: { components: ModelNameDiff; zones: ModelNameDiff; flows: ModelNameDiff };
  /** The sentence a view prints with a diff (secassess.DiffNote). */
  note: string;
};

/** A header of a logged request or response, as the helper wrote it (secrets Observer recognised hidden). */
export type ProbeHeader = { n: string; v: string };

/** One request in the helper's log, redacted (secassess.ProbeRecord). It is a line of a file the agent can write: every field is data to show as text, and none is Observer's word about the target. */
export type ProbeRecord = {
  id: string;
  ts: string;
  /** control | attack, or "" when the agent named none. */
  role: "" | "control" | "attack";
  /** A WSTG category id, or "". */
  wstg: string;
  account: string;
  note: string;
  method: string;
  path: string;
  req_headers: ProbeHeader[];
  req_body_bytes: number;
  req_body_excerpt: string;
  /** false: the helper refused the request (see `refused`) and it never reached the target. */
  sent: boolean;
  /** The refusal code (REFUSED_WORDS), "" when the request was not refused. */
  refused: string;
  error: string;
  /** 0 when there was no response. */
  status: number;
  resp_headers: ProbeHeader[];
  body_bytes: number;
  body_truncated: boolean;
  /** The first 1 KiB of the response body, secrets Observer recognised hidden. */
  body_excerpt: string;
  ms: number;
  hops: number;
  redirect_to: string;
  redirect_blocked: boolean;
  cost: number;
  /** The id of the finding this request is the helper's replay of (a retest run's log only). */
  replay?: string;
};

/** How much of the helper's log this answer carries: the records cited by findings or coverage rows are in `probes`; `truncated` says the answer holds only part of those. */
export type ProbeLogInfo = { records: number; shown: number; truncated: boolean };

/** GET /api/security/assessments/model?run=[&since=]. */
export type AssessModelResponse = {
  record: ModelRecord;
  /** assessment.json is not the file that was validated. */
  stale: boolean;
  /** Project files the references were checked against that read differently now. */
  drift?: string[];
  /** secassess.CleanReading: set only when the model holds no threat and no finding. */
  reading?: string;
  /** secassess.CoverageLine: what was covered, always set for a stored model. */
  coverage_line?: string;
  /** Threat model only. */
  mermaid?: ModelMermaid;
  vocab: ModelVocab;
  /** Display redaction (setting display_redaction): on, and how many places were hidden in this answer. */
  redaction: { on: boolean; hidden: number };
  since?: ModelSince;
  /** Pen test and red team, only for a run with a request log: the redacted log records the findings and coverage rows cite. */
  probes?: ProbeRecord[];
  probe_log?: ProbeLogInfo;
  /** Penetration test and red team: the labels the run's retests gave its findings, newest retest first. Nothing in them changes the findings above. */
  retests?: RetestView[];
};

// ---- helpers ----

/** The state of a threat's mitigations as a reader should take it. Order = strength:
 *  found > exists > claimed_not_found > unchecked > not_located > none.
 *  unchecked: every cited reference was left unlooked-at (the read budget); not_located: every one names
 *  a file or line that is not there or is malformed; none: no reference was cited. */
export type MitState = "found" | "exists" | "claimed_not_found" | "unchecked" | "not_located" | "none";

/** MIT_STATES lists the mitigation states strongest first: the order mitigationState picks the best of, and the order a picker shows them in. */
export const MIT_STATES: readonly MitState[] = ["found", "exists", "claimed_not_found", "unchecked", "not_located", "none"];

/** MIT_STATE_WORDS: found near the cited line / location exists, nothing matched / claimed, not found. */
export const MIT_STATE_WORDS: Readonly<Record<MitState, { label: string; tone: Tone; detail: string }>> = {
  found: {
    label: "Found near the cited line",
    tone: "success",
    detail:
      "The text the agent quoted is on a code line within the match window of the line it cited. That shows the text is there; it does not show the control works.",
  },
  exists: {
    label: "Location exists, nothing matched",
    tone: "neutral",
    detail: "The cited file and line are there, but the quoted text was not found on a code line near the cited line. It earns no credit.",
  },
  claimed_not_found: {
    label: "Claimed, not found",
    tone: "warn",
    detail: "The agent quoted text that is not in the cited lines. The claim has nothing behind it until someone looks.",
  },
  unchecked: {
    label: "Not checked",
    tone: "neutral",
    detail: "Observer ran out of its reference-check budget before it looked at this reference, so nothing is known about it.",
  },
  not_located: {
    label: "Cited place not found",
    tone: "warn",
    detail: "Every reference cited here names a file or line that is not there, or is malformed.",
  },
  none: {
    label: "No reference cited",
    tone: "neutral",
    detail: "The agent cited no file or line, so there was nothing for Observer to look at.",
  },
};

export type ThreatFilter = {
  framework?: string;
  /** "kind:id", as elementKey makes it. */
  element?: string;
  status?: string;
  band?: ModelBand;
  /** The state of the threat's existing mitigations (threatMitState). */
  mitigation?: MitState;
  /** Substring of id, title, category, element name or description (case-insensitive). */
  q?: string;
};
export type ThreatSortKey = "band" | "id" | "title" | "element" | "status";
export type ThreatSort = { key: ThreatSortKey; dir: "asc" | "desc" };

/** The sort a threat list opens with: the band, highest first. */
export const DEFAULT_THREAT_SORT: ThreatSort = { key: "band", dir: "desc" };

/** nextSort is the sort a header click gives: a column that is not the sort starts in its first direction (the band, highest first; any other column, ascending), and the column that is the sort flips. */
function nextSort<K extends string>(cur: { key: K; dir: "asc" | "desc" }, k: K): { key: K; dir: "asc" | "desc" } {
  if (cur.key === k) return { key: k, dir: cur.dir === "asc" ? "desc" : "asc" };
  return { key: k, dir: k === "band" ? "desc" : "asc" };
}

/** nextThreatSort is the threat sort after a click on a column header. */
export function nextThreatSort(cur: ThreatSort, k: ThreatSortKey): ThreatSort {
  return nextSort(cur, k);
}

/** toggleOpenKey is the row that is open after a click on a row's expander: that row, or none when it was the one open. One row is open at a time. */
export function toggleOpenKey(cur: string | null, key: string): string | null {
  return cur === key ? null : key;
}

/** BANDS lists the bands lowest to highest. */
export const BANDS: readonly ModelBand[] = ["low", "medium", "high", "critical"];

// ---- small pure utilities ----

/** hasOwn is a table lookup that an agent-supplied key such as "constructor" cannot reach through the prototype. */
function hasOwn(table: object, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(table, key);
}

/** plural picks the singular or the plural form for a count. */
export function plural(n: number, one: string, many: string): string {
  return n === 1 ? one : many;
}

/** count reads a number from a wire field: a finite number, else 0. */
function count(n: unknown): number {
  return typeof n === "number" && Number.isFinite(n) && n > 0 ? n : 0;
}

/** naturalCompare orders strings the way a person reads ids: "T-2" before "T-10", case ignored first. */
export function naturalCompare(a: string, b: string): number {
  const ta = a.match(/\d+|\D+/g) ?? [];
  const tb = b.match(/\d+|\D+/g) ?? [];
  const n = Math.min(ta.length, tb.length);
  for (let i = 0; i < n; i++) {
    const x = ta[i];
    const y = tb[i];
    if (x === y) continue;
    const dx = x.charCodeAt(0) >= 48 && x.charCodeAt(0) <= 57;
    const dy = y.charCodeAt(0) >= 48 && y.charCodeAt(0) <= 57;
    if (dx && dy) {
      // Compare as numbers without parsing them (no overflow on a long digit run).
      const nx = x.replace(/^0+/, "");
      const ny = y.replace(/^0+/, "");
      if (nx.length !== ny.length) return nx.length < ny.length ? -1 : 1;
      if (nx !== ny) return nx < ny ? -1 : 1;
      continue;
    }
    if (dx !== dy) return dx ? -1 : 1;
    const lx = x.toLowerCase();
    const ly = y.toLowerCase();
    if (lx !== ly) return lx < ly ? -1 : 1;
  }
  if (ta.length !== tb.length) return ta.length < tb.length ? -1 : 1;
  return a === b ? 0 : a < b ? -1 : 1;
}

/** textCompare is a case-insensitive comparison, the raw strings breaking a tie. */
function textCompare(a: string, b: string): number {
  const la = a.toLowerCase();
  const lb = b.toLowerCase();
  if (la !== lb) return la < lb ? -1 : 1;
  return a === b ? 0 : a < b ? -1 : 1;
}

// ---- words for closed values ----
//
// Every closed value the agent's file can hold (a status, an effort size, an
// authentication kind, an exposure, a sensitivity, an element kind, a
// framework) reaches the page through one of these tables, never as the raw
// word (docs/app-design-system.md "Never in UI text": a raw enum on screen is a
// bug). The tables are pinned against the Go lists (internal/secassess/
// vocab_enums.go) by secAssessModel.test.ts, which fails when a value has no
// words. A value no table knows reads as written with its underscores taken
// out, never as an empty cell.

/** cleaned is a value as written with its underscores and runs of white space made single spaces. */
function cleaned(v: string): string {
  return v.replace(/[_\s]+/g, " ").trim();
}

/** The words of a threat's or a finding's status. The status is the agent's own claim. */
export const STATUS_WORDS: Readonly<Record<string, string>> = {
  identified: "Identified",
  mitigated: "Mitigated",
  partial: "Partly mitigated",
  accepted_by_design: "Accepted by design",
  open: "Open",
};

/** statusWords is a status as a person reads it; a value this view does not know reads as written, cleaned. */
export function statusWords(status: string | undefined): string {
  if (!status) return "Not stated";
  if (hasOwn(STATUS_WORDS, status)) return STATUS_WORDS[status];
  return cleaned(status) || "Not stated";
}

/** The words of an effort size on a missing mitigation. */
export const EFFORT_WORDS: Readonly<Record<string, string>> = { s: "small", m: "medium", l: "large", xl: "very large" };

/** effortWords is an effort size in words. */
export function effortWords(effort: string): string {
  return hasOwn(EFFORT_WORDS, effort) ? EFFORT_WORDS[effort] : cleaned(effort) || effort;
}

/** The words of a pen test coverage claim, as the agent wrote it. */
export const AGENT_COVERAGE_WORDS: Readonly<Record<string, string>> = {
  tested: "tested",
  skipped: "skipped",
  not_applicable: "not applicable",
  tool_unavailable: "tool unavailable",
};

/** agentCoverageWords is what the agent marked a category as, in words. */
export function agentCoverageWords(agent: string | undefined): string {
  if (!agent) return "no row";
  if (hasOwn(AGENT_COVERAGE_WORDS, agent)) return AGENT_COVERAGE_WORDS[agent];
  return cleaned(agent) || "no row";
}

// ---- the retest's labels and the red team chain's results ----
//
// A retest labels each finding it replays reproduced, not reproduced or
// inconclusive (secassess.EnumRetestResult); a chain step's result is achieved,
// partly or blocked (secassess.EnumChainResult). Both reach the page through
// the tables below, never as the raw word, and the tests read the Go lists.
// The tones never read as an outcome of a fix: a label of "not reproduced" is a
// neutral one, because it says one replay got a response the stored condition
// does not match, in a copy of the project in a box, and nothing more.

/** The sentence every place that shows a retest label carries: what the label is, and that nothing was closed. */
export const RETEST_NOTHING_CLOSED = "Nothing was closed: this is one replay of the stored request, read against the stored condition.";

/** RetestWord is a retest label in words: the pill's label and tone, and a sentence on what it says and does not say. */
export type RetestWord = { label: string; tone: Tone; detail: string };

/** The retest labels, in the order a summary lists them. */
export const RETEST_RESULTS: readonly string[] = ["reproduced", "not_reproduced", "inconclusive"];

/** RETEST_RESULT_WORDS: one row per label of a retest. Reproduced draws attention because the stored request got the stored response again; the other two are neutral, since neither says the weakness is gone. */
export const RETEST_RESULT_WORDS: Readonly<Record<string, RetestWord>> = {
  reproduced: {
    label: "Reproduced",
    tone: "warn",
    detail: "The stored request got a response that meets the stored condition again, in a copy of the project in a box.",
  },
  not_reproduced: {
    label: "Not reproduced",
    tone: "neutral",
    detail: "The stored request got a response that does not meet the stored condition, in a copy of the project in a box. This does not mean the weakness is gone from your code or from production.",
  },
  inconclusive: {
    label: "Inconclusive",
    tone: "neutral",
    detail: "The agent could not tell, so this label claims nothing and no log reading backs it.",
  },
};

/** retestResultWords is a retest label in words; a label this table lacks reads as written, cleaned, with a neutral tone. */
export function retestResultWords(result: string | undefined): RetestWord {
  if (result && hasOwn(RETEST_RESULT_WORDS, result)) return RETEST_RESULT_WORDS[result];
  const c = cleaned(result ?? "");
  return { label: c ? c.charAt(0).toUpperCase() + c.slice(1) : "Not stated", tone: "neutral", detail: "" };
}

/** The chain results, in the order the agent's file lists them (secassess.EnumChainResult). */
export const CHAIN_RESULTS: readonly string[] = ["achieved", "partly", "blocked"];

/** CHAIN_RESULT_WORDS: how one step of a red team chain went, as the agent says it. Achieved draws attention; partly and blocked are not given a success tone, because a blocked step in one box says nothing about another. */
export const CHAIN_RESULT_WORDS: Readonly<Record<string, { label: string; tone: Tone }>> = {
  achieved: { label: "Achieved", tone: "warn" },
  partly: { label: "Partly achieved", tone: "info" },
  blocked: { label: "Blocked", tone: "neutral" },
};

/** chainResultWords is a step's result in words; a result this table lacks reads as written, cleaned. */
export function chainResultWords(result: string | undefined): { label: string; tone: Tone } {
  if (result && hasOwn(CHAIN_RESULT_WORDS, result)) return CHAIN_RESULT_WORDS[result];
  const c = cleaned(result ?? "");
  return { label: c ? c.charAt(0).toUpperCase() + c.slice(1) : "Not stated", tone: "neutral" };
}

/** The closed lists of the threat model schema that have words of their own (the Go lists are in internal/secassess/vocab_enums.go). */
export type EnumName = "sensitivity" | "actor_kind" | "entry_kind" | "authn" | "exposure" | "encrypted" | "element_kind";

/** ENUM_WORDS: the words of each closed list's values, one row per value. */
export const ENUM_WORDS: Readonly<Record<EnumName, Readonly<Record<string, string>>>> = {
  sensitivity: { public: "public", internal: "internal", confidential: "confidential", restricted: "restricted" },
  actor_kind: { end_user: "end user", admin: "administrator", service: "service", third_party: "third party", anonymous: "anonymous" },
  entry_kind: {
    http_route: "web route",
    rpc: "remote call",
    cli: "command line",
    message: "message",
    file: "file",
    webhook: "webhook",
    scheduled: "scheduled job",
    ui: "user interface",
    other: "other",
  },
  authn: {
    none: "none",
    session: "session",
    token: "token",
    api_key: "API key",
    mtls: "client certificate",
    basic: "user and password",
    other: "other",
    unknown: "not known",
  },
  exposure: { internet: "internet", internal_network: "internal network", local_only: "this machine only", unknown: "not known" },
  encrypted: { yes: "yes", no: "no", unknown: "not known" },
  element_kind: { component: "component", actor: "actor", flow: "flow", entry_point: "entry point", asset: "asset" },
};

/** enumWords is a closed value in words: its table row, else the value as written with underscores taken out, else "not stated". */
export function enumWords(name: EnumName, value: string | undefined): string {
  if (!value) return "not stated";
  const table = ENUM_WORDS[name];
  if (hasOwn(table, value)) return table[value];
  return cleaned(value) || "not stated";
}

/** The short names of the frameworks in a table cell and a picker. */
const FRAMEWORK_SHORT: Readonly<Record<string, string>> = {
  stride: "STRIDE",
  linddun: "LINDDUN",
  owasp_llm: "OWASP LLM",
  owasp_agentic: "OWASP agentic",
};

/** frameworkLabel is the framework's short name; a framework no table knows reads as written, cleaned. */
export function frameworkLabel(id: string): string {
  return hasOwn(FRAMEWORK_SHORT, id) ? FRAMEWORK_SHORT[id] : cleaned(id) || id;
}

/** frameworkTitle is the framework's full name where the vocabulary has one (the AI frameworks), else its short name. */
export function frameworkTitle(id: string, vocab: ModelVocab | undefined): string {
  const ai = (vocab?.ai_frameworks ?? []).find((f) => f.id === id);
  return ai ? ai.name : frameworkLabel(id);
}

/** categoryName is a threat category by the vocabulary's name (STRIDE and LINDDUN), the id for the AI frameworks (the OWASP ids, such as LLM01, are names). */
export function categoryName(framework: string, category: string, vocab: ModelVocab | undefined): string {
  if (framework === "stride") return (vocab?.stride ?? []).find((c) => c.id === category)?.name ?? category;
  if (framework === "linddun") return (vocab?.linddun ?? []).find((c) => c.id === category)?.name ?? category;
  return category;
}

/** categoryLabel is a threat category by its name when the framework is not known (a comparison names no framework): a STRIDE or LINDDUN id by the vocabulary's name, any other as written, cleaned. */
export function categoryLabel(category: string, vocab: ModelVocab | undefined): string {
  const named = (vocab?.stride ?? []).find((c) => c.id === category) ?? (vocab?.linddun ?? []).find((c) => c.id === category);
  return named?.name ?? (cleaned(category) || category);
}

/** The short column names of the LINDDUN categories in the matrix: two letters each, so none reads as one of STRIDE's single letters. */
const LINDDUN_ABBR: Readonly<Record<string, string>> = {
  linkability: "Lk",
  identifiability: "Id",
  non_repudiation: "Nr",
  detectability: "Dt",
  disclosure_of_information: "Di",
  unawareness: "Ua",
  non_compliance: "Nc",
};

/** matrixAbbr is a matrix column's short header: the STRIDE letter, or the LINDDUN category's two letters (the first two letters of its name when no row names it). */
export function matrixAbbr(c: { id: string; label: string; letter?: string; framework: string }): string {
  if (c.letter) return c.letter;
  if (hasOwn(LINDDUN_ABBR, c.id)) return LINDDUN_ABBR[c.id];
  const l = c.label.trim();
  return l === "" ? c.id : `${l.charAt(0).toUpperCase()}${l.charAt(1).toLowerCase()}`;
}

// ---- mitigation state ----

/** How a reference's state reads as a mitigation state. A state this view does not know reads as unchecked: no credit, and no claim that the place is missing. */
const REF_TO_MIT: ReadonlyMap<string, MitState> = new Map<string, MitState>([
  ["found", "found"],
  ["exists", "exists"],
  ["claimed_not_found", "claimed_not_found"],
  ["unchecked", "unchecked"],
  ["missing", "not_located"],
  ["invalid", "not_located"],
]);

function refMitState(r: ModelRef | null | undefined): MitState {
  if (r == null) return "not_located";
  if (r.state === undefined || r.state === null) return "unchecked";
  return REF_TO_MIT.get(r.state) ?? "unchecked";
}

/** mitigationState is the best state among refs (see MitState); an empty or missing list is none. */
export function mitigationState(refs: ModelRef[] | undefined): MitState {
  if (!refs || refs.length === 0) return "none";
  let best = MIT_STATES.length - 1;
  for (const r of refs) {
    const rank = MIT_STATES.indexOf(refMitState(r));
    if (rank < best) best = rank;
    if (best === 0) break;
  }
  return MIT_STATES[best];
}

/** existingRefs lists every reference of a threat's existing mitigations. */
function existingRefs(t: ModelThreat): ModelRef[] {
  const all: ModelRef[] = [];
  for (const m of t.existing ?? []) for (const r of m?.refs ?? []) all.push(r);
  return all;
}

/** threatMitState is mitigationState over the refs of the threat's existing[]. */
export function threatMitState(t: ModelThreat): MitState {
  return mitigationState(existingRefs(t));
}

/** MitSummary is a mitigation word with how many references stand behind it: the word is the best state among all of them. */
export type MitSummary = { state: MitState; /** References in that state. */ at: number; /** References cited in all. */ total: number };

/** mitigationSummary is the best state among a list of references, with how many references are in that state and how many are cited. An empty list is none, 0 of 0. */
export function mitigationSummary(refs: ModelRef[] | undefined): MitSummary {
  const list = refs ?? [];
  const state = mitigationState(list);
  let at = 0;
  for (const r of list) if (refMitState(r) === state) at++;
  return { state, at, total: list.length };
}

/** threatMitSummary is mitigationSummary over the refs of the threat's existing[]. */
export function threatMitSummary(t: ModelThreat): MitSummary {
  return mitigationSummary(existingRefs(t));
}

/** mitRefsWords says how many of the references the mitigation word stands on: "1 of 5 references". It is empty when no reference is cited, because the word then has nothing behind it to count. */
export function mitRefsWords(s: MitSummary): string {
  if (s.total === 0) return "";
  return `${s.at} of ${s.total} ${plural(s.total, "reference", "references")}`;
}

/** missingLocated counts a threat's missing[] items that name a location that exists (state found or exists). */
export function missingLocated(t: ModelThreat): { located: number; total: number } {
  const items = t.missing ?? [];
  let located = 0;
  for (const m of items) {
    if ((m?.refs ?? []).some((r) => r?.state === "found" || r?.state === "exists")) located++;
  }
  return { located, total: items.length };
}

// ---- elements and their names ----

/** elementKey is "kind:id". */
export function elementKey(e: ModelElement): string {
  return `${e?.kind ?? ""}:${e?.id ?? ""}`;
}

/** The model's names by id, built once per call that walks many elements. The first of two entries with one id wins. */
type NameIndex = {
  components: Map<string, string>;
  actors: Map<string, string>;
  assets: Map<string, string>;
  zones: Map<string, string>;
  entries: Map<string, ModelEntryPoint>;
  flows: Map<string, ModelFlow>;
};

function indexBy<T extends { id: string }, V>(items: T[] | undefined, value: (t: T) => V | undefined): Map<string, V> {
  const m = new Map<string, V>();
  for (const it of items ?? []) {
    if (it == null || m.has(it.id)) continue;
    const v = value(it);
    if (v !== undefined) m.set(it.id, v);
  }
  return m;
}

function nameIndex(doc: ThreatModelDoc | undefined): NameIndex {
  const s = doc?.system;
  const name = (x: { name: string }) => x.name || undefined;
  return {
    components: indexBy(s?.components, name),
    actors: indexBy(s?.actors, name),
    assets: indexBy(s?.assets, name),
    zones: indexBy(s?.zones, name),
    entries: indexBy(s?.entry_points, (e) => e),
    flows: indexBy(s?.flows, (f) => f),
  };
}

/** nodeName is the name of a flow endpoint: a component, else an actor, else the id. */
function nodeName(ix: NameIndex, id: string): string {
  return ix.components.get(id) ?? ix.actors.get(id) ?? id;
}

/** How each element kind is named. A kind with no row, or an id the model does not have, is not named here (the caller falls back to the id). */
const ELEMENT_NAMERS: ReadonlyMap<string, (ix: NameIndex, id: string) => string | undefined> = new Map([
  ["component", (ix: NameIndex, id: string) => ix.components.get(id)],
  ["actor", (ix: NameIndex, id: string) => ix.actors.get(id)],
  ["asset", (ix: NameIndex, id: string) => ix.assets.get(id)],
  ["zone", (ix: NameIndex, id: string) => ix.zones.get(id)],
  [
    "flow",
    (ix: NameIndex, id: string) => {
      const f = ix.flows.get(id);
      return f ? `${nodeName(ix, f.from)} to ${nodeName(ix, f.to)}` : undefined;
    },
  ],
  [
    "entry_point",
    (ix: NameIndex, id: string) => {
      const e = ix.entries.get(id);
      return e ? `${e.kind} on ${ix.components.get(e.component) ?? e.component}` : undefined;
    },
  ],
]);

/** resolveName is the model's own name for an element, or undefined when the model has no such element. */
function resolveName(ix: NameIndex, e: ModelElement): string | undefined {
  const r = ELEMENT_NAMERS.get(e?.kind ?? "");
  return r ? r(ix, e.id) : undefined;
}

/** elementName is the model's own name for an element (component, actor, asset by name; a flow as "from to to"; an entry point by kind and component), else the id. */
export function elementName(doc: ThreatModelDoc, e: ModelElement): string {
  return resolveName(nameIndex(doc), e) ?? e?.id ?? "";
}

// ---- filtering and sorting threats ----

type FilterCtx = { ix: NameIndex; q: string };

/** The filters, one row each; a filter that is set must pass. This table is the only reason a threat is left out. */
const FILTER_RULES: readonly {
  set: (f: ThreatFilter, c: FilterCtx) => boolean;
  pass: (t: ModelThreat, f: ThreatFilter, c: FilterCtx) => boolean;
}[] = [
  { set: (f) => !!f.framework, pass: (t, f) => t.framework === f.framework },
  { set: (f) => !!f.element, pass: (t, f) => elementKey(t.element) === f.element },
  { set: (f) => !!f.status, pass: (t, f) => t.status === f.status },
  { set: (f) => !!f.band, pass: (t, f) => t.band === f.band },
  { set: (f) => !!f.mitigation, pass: (t, f) => threatMitState(t) === f.mitigation },
  {
    set: (_f, c) => c.q !== "",
    pass: (t, _f, c) =>
      [t.id, t.title, t.category, resolveName(c.ix, t.element) ?? t.element?.id, t.description].some(
        (s) => typeof s === "string" && s.toLowerCase().includes(c.q),
      ),
  },
];

/** filterThreats keeps the threats that pass every filter set. It never drops a threat for any other reason (no cap). The text filter is trimmed; one that is only spaces is not set. */
export function filterThreats(doc: ThreatModelDoc, threats: ModelThreat[], f: ThreatFilter): ModelThreat[] {
  const ctx: FilterCtx = { ix: nameIndex(doc), q: (f.q ?? "").trim().toLowerCase() };
  const active = FILTER_RULES.filter((r) => r.set(f, ctx));
  return threats.filter((t) => active.every((r) => r.pass(t, f, ctx)));
}

/** What a band sort reads of a row: whether it has a score, the score, and the band's rank (-1 for no band). */
type BandKey = { scored: boolean; score: number; rank: number };

/** bandKey reads the fields of an item a band sort compares. */
function bandKey(x: { band?: ModelBand; score?: number }): BandKey {
  const scored = typeof x.score === "number" && Number.isFinite(x.score);
  return { scored, score: scored ? (x.score as number) : 0, rank: x.band ? BANDS.indexOf(x.band) : -1 };
}

/** bandCompare orders by score, then by band; an item with no score is last either way, and among those a band comes before none. `d` is 1 for ascending and -1 for descending. */
function bandCompare(a: BandKey, b: BandKey, d: number): number {
  if (a.scored !== b.scored) return a.scored ? -1 : 1;
  if (!a.scored) {
    // Neither has a score: one with a band comes before one with none.
    if ((a.rank < 0) !== (b.rank < 0)) return a.rank < 0 ? 1 : -1;
    return d * (a.rank - b.rank);
  }
  return d * (a.score - b.score) || d * (a.rank - b.rank);
}

type SortRow = BandKey & { t: ModelThreat; i: number; name: string };

/** The sort keys, one comparator each. `d` is 1 for ascending and -1 for descending. A threat with no score (or no status) is last either way. */
const SORT_COMPARE: Readonly<Record<ThreatSortKey, (a: SortRow, b: SortRow, d: number) => number>> = {
  band: (a, b, d) => bandCompare(a, b, d),
  id: (a, b, d) => d * naturalCompare(a.t.id ?? "", b.t.id ?? ""),
  title: (a, b, d) => d * textCompare(a.t.title ?? "", b.t.title ?? ""),
  element: (a, b, d) => d * textCompare(a.name, b.name),
  status: (a, b, d) => {
    const x = a.t.status ?? "";
    const y = b.t.status ?? "";
    if ((x === "") !== (y === "")) return x === "" ? 1 : -1;
    return d * textCompare(x, y);
  },
};

/** sortThreats returns a sorted copy; band sorts by score (then rank), stable, ties by id. */
export function sortThreats(doc: ThreatModelDoc, threats: ModelThreat[], s: ThreatSort): ModelThreat[] {
  const compare = hasOwn(SORT_COMPARE, s.key) ? SORT_COMPARE[s.key] : SORT_COMPARE.id;
  const d = s.dir === "desc" ? -1 : 1;
  const ix = nameIndex(s.key === "element" ? doc : undefined);
  const rows: SortRow[] = threats.map((t, i) => ({
    ...bandKey(t),
    t,
    i,
    name: s.key === "element" ? (resolveName(ix, t.element) ?? t.element?.id ?? "") : "",
  }));
  rows.sort((a, b) => compare(a, b, d) || naturalCompare(a.t.id ?? "", b.t.id ?? "") || a.i - b.i);
  return rows.map((r) => r.t);
}

// ---- filtering and sorting findings ----

export type FindingFilter = {
  band?: ModelBand;
  /** A WSTG category id. */
  category?: string;
  /** The agent's basis (observed | inferred). */
  basis?: string;
  /** Observer's evidence state (logged | unlogged | not_started); a finding with none reads as unlogged. */
  evidence?: EvidenceState;
  /** Substring of the id, title, category, route, impact, fix, CWE ids or cited paths (case-insensitive). */
  q?: string;
};
export type FindingSortKey = "band" | "id" | "title" | "category" | "status";
export type FindingSort = { key: FindingSortKey; dir: "asc" | "desc" };

/** The sort a finding list opens with: the band, highest first, equal bands in the order the agent wrote them. */
export const DEFAULT_FINDING_SORT: FindingSort = { key: "band", dir: "desc" };

/** nextFindingSort is the finding sort after a click on a column header (see nextThreatSort). */
export function nextFindingSort(cur: FindingSort, k: FindingSortKey): FindingSort {
  return nextSort(cur, k);
}

/** The WSTG category's title from the vocabulary, else the id. */
export function wstgTitle(id: string, vocab: ModelVocab | undefined): string {
  return (vocab?.wstg ?? []).find((w) => w.id === id)?.title ?? id;
}

type FindingCtx = { vocab: ModelVocab | undefined; q: string };

/** The finding filters, one row each; a filter that is set must pass. This table is the only reason a finding is left out of the list. */
const FINDING_FILTER_RULES: readonly {
  set: (f: FindingFilter, c: FindingCtx) => boolean;
  pass: (x: PTFinding, f: FindingFilter, c: FindingCtx) => boolean;
}[] = [
  { set: (f) => !!f.band, pass: (x, f) => x.band === f.band },
  { set: (f) => !!f.category, pass: (x, f) => x.category === f.category },
  { set: (f) => !!f.basis, pass: (x, f) => x.basis === f.basis },
  { set: (f) => !!f.evidence, pass: (x, f) => evidenceState(x) === f.evidence },
  {
    set: (_f, c) => c.q !== "",
    pass: (x, _f, c) =>
      [
        x.id,
        x.title,
        x.category,
        wstgTitle(x.category, c.vocab),
        x.route,
        x.impact,
        x.fix,
        ...(x.cwe ?? []),
        ...(x.where?.refs ?? []).map((r) => r?.path),
      ].some((v) => typeof v === "string" && v.toLowerCase().includes(c.q)),
  },
];

/** filterFindings keeps the findings that pass every filter set. It never drops a finding for any other reason (no cap). The text filter is trimmed; one that is only spaces is not set. */
export function filterFindings(findings: PTFinding[], f: FindingFilter, vocab?: ModelVocab): PTFinding[] {
  const ctx: FindingCtx = { vocab, q: (f.q ?? "").trim().toLowerCase() };
  const active = FINDING_FILTER_RULES.filter((r) => r.set(f, ctx));
  return findings.filter((x) => active.every((r) => r.pass(x, f, ctx)));
}

type FindingSortRow = BandKey & { x: PTFinding; i: number };

/** findingStatusNote is the one sentence that stands in for the Status column when every finding states the same status (UX-15): a column of one repeated word spends 100 px of a table that is already wider than the dialog. "" when the statuses differ (or there is no finding), and the column stays. The status is the agent's own claim, said as such. */
export function findingStatusNote(findings: readonly Pick<PTFinding, "status">[]): string {
  if (findings.length === 0) return "";
  const first = statusWords(findings[0].status);
  if (findings.some((x) => statusWords(x.status) !== first)) return "";
  const one = findings.length === 1;
  if (first === "Not stated") return `The agent stated no status for ${one ? "this finding" : "any finding"}.`;
  return `The agent states ${one ? "this finding" : "every finding"} as "${first}". The status is the agent's own claim.`;
}

/** The finding sort keys, one comparator each. `d` is 1 for ascending and -1 for descending. A finding with no status is last either way. Equal rows keep the agent's order. */
const FINDING_COMPARE: Readonly<Record<FindingSortKey, (a: FindingSortRow, b: FindingSortRow, d: number, v: ModelVocab | undefined) => number>> = {
  band: (a, b, d) => bandCompare(a, b, d),
  id: (a, b, d) => d * naturalCompare(a.x.id ?? "", b.x.id ?? ""),
  title: (a, b, d) => d * textCompare(a.x.title ?? "", b.x.title ?? ""),
  category: (a, b, d, v) => d * textCompare(wstgTitle(a.x.category ?? "", v), wstgTitle(b.x.category ?? "", v)),
  status: (a, b, d) => {
    const x = a.x.status ?? "";
    const y = b.x.status ?? "";
    if ((x === "") !== (y === "")) return x === "" ? 1 : -1;
    return d * textCompare(x, y);
  },
};

/** sortFindings returns a sorted copy. Band sorts by score (then band), and every key breaks a tie by the order the agent wrote the findings in, whatever the direction. */
export function sortFindings(findings: PTFinding[], s: FindingSort, vocab?: ModelVocab): PTFinding[] {
  const compare = hasOwn(FINDING_COMPARE, s.key) ? FINDING_COMPARE[s.key] : FINDING_COMPARE.band;
  const d = s.dir === "desc" ? -1 : 1;
  const rows: FindingSortRow[] = findings.map((x, i) => ({ ...bandKey(x), x, i }));
  rows.sort((a, b) => compare(a, b, d, vocab) || a.i - b.i);
  return rows.map((r) => r.x);
}

/** findingFacets lists the values each finding filter can take in these findings, with counts, for the pickers. Only values that occur are listed: bands highest first, categories in the vocabulary's order, bases as the agent wrote them, evidence states in their own order. */
export function findingFacets(
  findings: PTFinding[],
  vocab?: ModelVocab,
): {
  bands: { value: ModelBand; n: number }[];
  categories: { value: string; label: string; n: number }[];
  bases: { value: string; n: number }[];
  evidence: { value: EvidenceState; label: string; n: number }[];
} {
  const cat = tally(findings.map((x) => x.category));
  const order = (vocab?.wstg ?? []).map((w) => w.id);
  return {
    bands: [...BANDS]
      .reverse()
      .map((value) => ({ value, n: findings.filter((x) => x.band === value).length }))
      .filter((b) => b.n > 0),
    categories: ordered(cat, order).map((c) => ({ value: c.value, label: wstgTitle(c.value, vocab), n: c.n })),
    bases: ordered(tally(findings.map((x) => x.basis)), ["observed", "inferred"]),
    evidence: EVIDENCE_STATES.map((value) => ({ value, label: EVIDENCE_LABELS[value], n: findings.filter((x) => evidenceState(x) === value).length })).filter((e) => e.n > 0),
  };
}

// ---- facets and counts ----

/** FRAMEWORK_ORDER and STATUS_ORDER: the order the pickers list the values the model's vocabulary names; any other value follows, sorted. */
const FRAMEWORK_ORDER: readonly string[] = ["stride", "linddun", "owasp_llm", "owasp_agentic"];
const STATUS_ORDER: readonly string[] = ["identified", "mitigated", "partial", "accepted_by_design"];

function tally<K extends string>(values: (K | undefined)[]): Map<K, number> {
  const m = new Map<K, number>();
  for (const v of values) {
    if (v === undefined || v === null || (v as string) === "") continue;
    m.set(v, (m.get(v) ?? 0) + 1);
  }
  return m;
}

/** ordered lists a tally in a fixed order first, then the rest sorted naturally. */
function ordered<K extends string>(m: Map<K, number>, order: readonly string[]): { value: K; n: number }[] {
  const rank = (k: string) => {
    const i = order.indexOf(k);
    return i < 0 ? order.length : i;
  };
  return [...m.entries()]
    .sort(([a], [b]) => rank(a) - rank(b) || naturalCompare(a, b))
    .map(([value, n]) => ({ value, n }));
}

/** threatFacets lists the values each filter can take in these threats, with counts, for the filter pickers. Only values that occur are listed; bands highest first, mitigations strongest first. */
export function threatFacets(doc: ThreatModelDoc): {
  frameworks: { value: string; n: number }[];
  elements: { value: string; label: string; n: number }[];
  statuses: { value: string; n: number }[];
  bands: { value: ModelBand; n: number }[];
  mitigations: { value: MitState; n: number }[];
} {
  const threats = doc?.threats ?? [];
  const ix = nameIndex(doc);
  const elements = new Map<string, { label: string; id: string; n: number }>();
  for (const t of threats) {
    const key = elementKey(t.element);
    const cur = elements.get(key);
    if (cur) cur.n++;
    else elements.set(key, { label: resolveName(ix, t.element) ?? t.element?.id ?? "", id: t.element?.id ?? "", n: 1 });
  }
  // Two elements can carry one name (every entry point reads "<kind> on <component>"): a picker that lists the same words
  // twenty times cannot be used, so an element whose name is shared is told apart by the agent's own id for it.
  const nameCount = new Map<string, number>();
  for (const e of elements.values()) nameCount.set(e.label, (nameCount.get(e.label) ?? 0) + 1);
  return {
    frameworks: ordered(tally(threats.map((t) => t.framework)), FRAMEWORK_ORDER),
    elements: [...elements.entries()]
      .map(([value, e]) => ({ value, label: (nameCount.get(e.label) ?? 0) > 1 && e.id !== "" ? `${e.label}, ${e.id}` : e.label, n: e.n }))
      .sort((a, b) => textCompare(a.label, b.label) || (a.value < b.value ? -1 : a.value > b.value ? 1 : 0)),
    statuses: ordered(tally(threats.map((t) => t.status)), STATUS_ORDER),
    bands: [...BANDS]
      .reverse()
      .map((value) => ({ value, n: threats.filter((t) => t.band === value).length }))
      .filter((b) => b.n > 0),
    mitigations: mitFacet(threats),
  };
}

function mitFacet(threats: ModelThreat[]): { value: MitState; n: number }[] {
  const m = tally(threats.map((t) => threatMitState(t)));
  return MIT_STATES.filter((s) => m.has(s)).map((value) => ({ value, n: m.get(value) ?? 0 }));
}

/** bandCounts counts the threats (or findings) per band, lowest to highest, zero counts included. */
export function bandCounts(items: { band?: ModelBand }[]): { band: ModelBand; n: number }[] {
  const n = new Map<string, number>();
  for (const it of items ?? []) if (it?.band) n.set(it.band, (n.get(it.band) ?? 0) + 1);
  return BANDS.map((band) => ({ band, n: n.get(band) ?? 0 }));
}

/** BAND_TONE: every band's pill tone, in the one table bandTone reads. */
const BAND_TONE: ReadonlyMap<string, Tone> = new Map<string, Tone>([
  ["critical", "danger"],
  ["high", "danger"],
  ["medium", "warn"],
  ["low", "info"],
]);

/** bandTone maps a band to a Pill tone through one table: critical danger, high danger, medium warn, low info, unknown neutral. */
export function bandTone(b: string | undefined): Tone {
  return (b !== undefined && BAND_TONE.get(b)) || "neutral";
}

/** CVSS_NOTE is the sentence beside every CVSS line; the Go constant secassess.CVSSNote is pinned to it by a test. */
export const CVSS_NOTE = "Base score of the weakness as logged in an in-box copy, not a production risk.";

/** CVSS_APART is said once in the open row of a finding that has a CVSS line: the table's Band column and this score are two readings of the finding, made from different inputs, and neither changes the other. Without it a "medium 9" beside a base score of 9.3 (critical) reads as Observer disagreeing with itself. */
export const CVSS_APART = "This is a separate reading from the Band in the table, which is the agent's likelihood times impact. Neither changes the other.";

/** hasCvssScore is whether any of the findings carries a base score Observer computed. A score is a number Observer made, never one the agent wrote, and a run whose findings have none has nothing to call a CVSS base score. */
export function hasCvssScore(findings: readonly PTFinding[] | null | undefined): boolean {
  return (Array.isArray(findings) ? findings : []).some((f) => typeof f?.cvss_score === "number" && Number.isFinite(f.cvss_score));
}

/** findingsLegend is the line under the findings count: which words are the agent's and which are Observer's. It names only what is on the page, so a run with no CVSS score does not mention one (N-16). */
export function findingsLegend(findings: readonly PTFinding[] | null | undefined): string {
  const ours = hasCvssScore(findings) ? "The band, the CVSS base score, the evidence and the words about each cited place" : "The band, the evidence and the words about each cited place";
  return `The text, the basis and the rating are what the agent wrote. ${ours} are Observer's.`;
}

/** The issue codes that mean a finding's CVSS vector was left out (secassess cvss.go: not a readable base vector, and one that did not score). */
export const CVSS_LEFT_OUT_CODES: readonly string[] = ["bad_cvss_dropped", "cvss_not_scored"];

/** CVSS_LEFT_OUT_NOTE is what the open row of a finding says when the agent wrote a vector for it and the check left it out: otherwise the row shows no CVSS block at all and reads as if the agent wrote none. The reason is the check's own sentence under How checked (it names this finding); the vector is never repeated. */
export const CVSS_LEFT_OUT_NOTE = "The agent wrote a CVSS vector for this finding that was left out, so there is no CVSS reading. How checked says why.";

/** cvssLeftOutIds is the ids of the findings whose CVSS vector the check left out, from the report's issues. A finding is named by the issue's item: an issue without one (a record kept before the id was recorded) names no finding, because its path is a place in the agent's file and says nothing about which kept finding it was. */
export function cvssLeftOutIds(issues: readonly ModelIssue[] | undefined): Set<string> {
  const out = new Set<string>();
  for (const is of Array.isArray(issues) ? issues : []) {
    if (is && CVSS_LEFT_OUT_CODES.includes(is.code) && typeof is.item === "string" && is.item !== "") out.add(is.item);
  }
  return out;
}

/** CvssReading is a finding's CVSS line: the agent's vector, and what Observer computed from it. */
export type CvssReading = { vector: string; text: string };

/** cvssReading is null for a finding with no vector. A score of 0 is a score (it reads "no band", with the vector and the number shown); a vector with no computed score says Observer has none. The score is Observer's own number, never one the agent wrote. */
export function cvssReading(f: PTFinding): CvssReading | null {
  const vector = (f.cvss ?? "").trim();
  if (vector === "") return null;
  if (typeof f.cvss_score !== "number" || !Number.isFinite(f.cvss_score)) return { vector, text: "Observer has no score for this vector." };
  return { vector, text: `Base score ${f.cvss_score.toFixed(1)} (${f.cvss_band ?? "no band"}), computed by Observer from the vector.` };
}

// ---- the STRIDE-per-element matrix ----

export type MatrixCell = {
  category: string;
  /** na: the category does not apply to this element's class (no cell is drawn as empty). */
  state: CellState | "na";
  /** The reason of a waived cell. */
  reason?: string;
  /** Threat ids recorded for this (element, category). */
  threats: string[];
};
export type MatrixRow = { key: string; kind: string; id: string; name: string; class: string; cells: MatrixCell[] };
export type ElementMatrixModel = {
  /** Columns in the published order: the STRIDE categories, then LINDDUN's when any row has them. */
  columns: { id: string; label: string; letter?: string; framework: string }[];
  rows: MatrixRow[];
  /** analysed / waived / empty, as three numbers, never one percentage. */
  totals: { analysed: number; waived: number; empty: number };
};

const cellKey = (kind: string, id: string, category: string) => `${kind}\u0000${id}\u0000${category}`;

/** buildElementMatrix lays the validator's coverage rows (report.tm.rows) out against the vocabulary and adds each cell's waiver reason and threat ids from the model.
 *  A row's name is the model's own name for the element (a flow reads "from to to" in names, not the ids the report spells), else the report's name, else the id. */
export function buildElementMatrix(doc: ThreatModelDoc, cov: TMCoverage, vocab: ModelVocab): ElementMatrixModel {
  const rows = cov?.rows ?? [];
  const linddun = new Set((vocab?.linddun ?? []).map((c) => c.id));
  const withLinddun = rows.some((r) => (r.cells ?? []).some((c) => linddun.has(c.category)));
  const columns: ElementMatrixModel["columns"] = (vocab?.stride ?? []).map((c) => ({
    id: c.id,
    label: c.name,
    letter: c.letter,
    framework: "stride",
  }));
  if (withLinddun) for (const c of vocab?.linddun ?? []) columns.push({ id: c.id, label: c.name, framework: "linddun" });

  const threatIds = new Map<string, string[]>();
  for (const t of doc?.threats ?? []) {
    const k = cellKey(t.element?.kind ?? "", t.element?.id ?? "", t.category);
    const list = threatIds.get(k);
    if (list) list.push(t.id);
    else threatIds.set(k, [t.id]);
  }
  const reasons = new Map<string, string>();
  for (const n of doc?.no_threat ?? []) {
    const k = cellKey(n.element?.kind ?? "", n.element?.id ?? "", n.category);
    if (!reasons.has(k)) reasons.set(k, n.reason);
  }
  const ix = nameIndex(doc);

  return {
    columns,
    rows: rows.map((r) => {
      const byCat = new Map<string, CoverageCell>();
      for (const c of r.cells ?? []) if (!byCat.has(c.category)) byCat.set(c.category, c);
      return {
        key: elementKey(r),
        kind: r.kind,
        id: r.id,
        name: resolveName(ix, r) ?? (r.name || r.id),
        class: r.class,
        cells: columns.map((col): MatrixCell => {
          const c = byCat.get(col.id);
          if (!c) return { category: col.id, state: "na", threats: [] };
          const k = cellKey(r.kind, r.id, col.id);
          const cell: MatrixCell = { category: col.id, state: c.state, threats: threatIds.get(k) ?? [] };
          const reason = c.state === "waived" ? reasons.get(k) : undefined;
          if (reason !== undefined) cell.reason = reason;
          return cell;
        }),
      };
    }),
    totals: { analysed: count(cov?.analysed), waived: count(cov?.waived), empty: count(cov?.empty) },
  };
}

// ---- the flow table ----

export type FlowRow = {
  id: string;
  from: string;
  to: string;
  /** Names, with the id as the fallback. */
  fromName: string;
  toName: string;
  data: string[];
  protocol: string;
  authn: string;
  encrypted: string;
  personalData: boolean;
  /** The flow crosses a trust zone (stated in `crosses`, or the endpoints sit in different zones). */
  crossing: boolean;
  zones: string[];
  /** A crossing with authn "none" or encrypted "no". Highlighted, never blocking. */
  weakCrossing: boolean;
};

/** The display of a flow field the agent left empty: "unknown", in protocol, authn and encrypted only. */
const UNKNOWN = "unknown";

/** flowRows resolves each flow's endpoints and data to names. No flow is left out.
 *  An empty protocol, authn or encrypted reads "unknown" in the row (the weak-crossing check reads what the agent wrote). `zones` are the names of `crosses` only: a flow whose crossing is read from its endpoints' zones has none. */
export function flowRows(doc: ThreatModelDoc): FlowRow[] {
  const ix = nameIndex(doc);
  // The zone of every component ("" when it names none); an actor or an id the model lacks is not in the map.
  const zoneOf = new Map<string, string>();
  for (const c of doc?.system?.components ?? []) if (c && !zoneOf.has(c.id)) zoneOf.set(c.id, c.zone ?? "");
  return (doc?.system?.flows ?? []).map((f) => {
    const crosses = f.crosses ?? [];
    const zFrom = zoneOf.get(f.from);
    const zTo = zoneOf.get(f.to);
    // Both ends are components with a known zone, and the zones differ.
    const crossing = crosses.length > 0 || (!!zFrom && !!zTo && zFrom !== zTo);
    return {
      id: f.id,
      from: f.from,
      to: f.to,
      fromName: nodeName(ix, f.from),
      toName: nodeName(ix, f.to),
      data: (f.data ?? []).map((a) => ix.assets.get(a) ?? a),
      protocol: f.protocol || UNKNOWN,
      authn: f.authn || UNKNOWN,
      encrypted: f.encrypted || UNKNOWN,
      personalData: f.personal_data === true,
      crossing,
      zones: crosses.map((z) => ix.zones.get(z) ?? z),
      weakCrossing: crossing && (f.authn === "none" || f.encrypted === "no"),
    };
  });
}

// ---- the attack tree list ----

export type TreeItem = { id: string; label: string; op?: string; leaf: boolean; depth: number; children: TreeItem[] };

/** treeItems turns an attack tree's parent links into a nested list. A node whose parent is missing hangs from the root; a cycle is cut (the node appears once).
 *  Iterative, so a tree of any size cannot overflow the stack; siblings keep the order of the input. */
export function treeItems(t: ModelTree): TreeItem[] {
  const nodes = t?.nodes ?? [];
  const at = new Map<string, number>();
  nodes.forEach((n, i) => {
    if (!at.has(n.id)) at.set(n.id, i);
  });
  // children[i] lists the nodes whose parent is node i; top lists the nodes that hang from the root.
  const children: number[][] = nodes.map(() => []);
  const parent = new Int32Array(nodes.length).fill(-1);
  const top: number[] = [];
  nodes.forEach((n, i) => {
    const p = n.parent ? at.get(n.parent) : undefined;
    if (p === undefined || p === i) top.push(i);
    else {
      children[p].push(i);
      parent[i] = p;
    }
  });
  const seen = new Uint8Array(nodes.length);
  const out: TreeItem[] = [];
  const walk = (start: number) => {
    // A frame is a node index, its depth and the list it is appended to.
    const stack: { i: number; depth: number; into: TreeItem[] }[] = [{ i: start, depth: 0, into: out }];
    while (stack.length > 0) {
      const { i, depth, into } = stack.pop()!;
      if (seen[i]) continue;
      seen[i] = 1;
      const n = nodes[i];
      const item: TreeItem = { id: n.id, label: n.label, leaf: n.leaf === true, depth, children: [] };
      if (n.op) item.op = n.op;
      into.push(item);
      for (let k = children[i].length - 1; k >= 0; k--) stack.push({ i: children[i][k], depth: depth + 1, into: item.children });
    }
  };
  for (const i of top) walk(i);
  // What is left is a cycle, or hangs from one. Cut each cycle at its first node in input order, so the nodes
  // that hang from it stay under it. An unvisited node's parent is unvisited too, so climbing stays inside its component.
  const stamp = new Int32Array(nodes.length);
  for (let i = 0; i < nodes.length; i++) {
    if (seen[i]) continue;
    let x = i;
    while (x >= 0 && stamp[x] !== i + 1) {
      stamp[x] = i + 1;
      x = parent[x];
    }
    // x is now the first node met twice: it is on the cycle. Take the cycle's first node in input order.
    let first = x >= 0 ? x : i;
    if (x >= 0) for (let y = parent[x]; y !== x && y >= 0; y = parent[y]) if (y < first) first = y;
    walk(first);
  }
  return out;
}

// ---- the pen test coverage words ----

/** The coverage word for an effective value the server sent. Written in Observer's words: what the agent said, and what backs it. */
export type CoverageWord = { label: string; tone: Tone; detail: string };

/** COVERAGE_WORDS: the effective coverage words (tested_claimed ... missing) in Observer's words. */
export const COVERAGE_WORDS: Readonly<Record<string, CoverageWord>> = {
  tested_claimed: {
    label: "Tested (claimed)",
    tone: "neutral",
    detail: "The agent says it tested this category; no request log backs it.",
  },
  tested_logged: {
    label: "Tested (logged request)",
    tone: "info",
    detail:
      "The agent says it tested this category, and the helper log holds a request for it. The log is a file the agent can write, so this is not a trace.",
  },
  skipped: {
    label: "Skipped",
    tone: "warn",
    detail: "The agent skipped this category and gave a reason. Nothing was tested for it.",
  },
  skipped_not_started: {
    label: "Skipped (target not started)",
    tone: "warn",
    detail: "The target did not start, so nothing was tested in a running application for this category.",
  },
  not_applicable: {
    label: "Not applicable",
    tone: "neutral",
    detail: "The agent says this category does not apply to the target. That is its own judgement; Observer did not check it.",
  },
  tool_unavailable: {
    label: "Tool unavailable",
    tone: "warn",
    detail: "The agent had no tool in the box for this category, so it was not tested.",
  },
  missing: {
    label: "No row from the agent",
    tone: "warn",
    detail: "The agent gave no row for this category, so it is not known whether it was tested.",
  },
};

/** coverageWords is COVERAGE_WORDS for an effective word, and a neutral reading of one this view does not know. */
export function coverageWords(effective: string): CoverageWord {
  if (hasOwn(COVERAGE_WORDS, effective)) return COVERAGE_WORDS[effective];
  const label = (effective || "unknown").replace(/[_\s]+/g, " ").trim() || "unknown";
  return { label, tone: "neutral", detail: "A coverage word this view does not know. It is shown as the server sent it." };
}

/** The effective coverage words whose row is one the agent gives a reason for: a category it skipped, called not applicable, or had no tool for. A category it tested, one nothing was tested for because the target did not start, and one it gave no row for have no reason to ask for. */
const REASON_EXPECTED: ReadonlySet<string> = new Set(["skipped", "not_applicable", "tool_unavailable"]);

/** coverageReasonExpected is whether a coverage row is one the agent should have said why for; a row that is not reads as blank in the Reason column, not as a missing reason. */
export function coverageReasonExpected(effective: string): boolean {
  return REASON_EXPECTED.has(effective);
}

/** The count line's tail, one row each, in order: the effective word, and how it reads after the number. Shown only when the count is above zero. */
const COUNT_TAILS: readonly { word: string; tail: (n: number) => string }[] = [
  { word: "skipped", tail: (n) => `${n} skipped` },
  { word: "skipped_not_started", tail: (n) => `${n} skipped (target not started)` },
  { word: "not_applicable", tail: (n) => `${n} not applicable` },
  { word: "tool_unavailable", tail: (n) => `${n} with a tool unavailable` },
  { word: "missing", tail: (n) => `${n} with no row` },
];

/** The counts of a coverage report: its `counts` when it has any, else a tally of its rows. */
function coverageCounts(pt: PTCoverage): Record<string, number> {
  const given = pt?.counts;
  if (given && Object.keys(given).length > 0) return given;
  const tallied: Record<string, number> = {};
  for (const r of pt?.rows ?? []) tallied[r.effective] = (tallied[r.effective] ?? 0) + 1;
  return tallied;
}

/** coverageCountsLine is the matrix's totals, in the words the Go side's coverage line uses:
 *  "5 of 8 categories claimed, 0 with a logged request, 1 skipped, 1 not applicable, 1 with a tool unavailable". */
export function coverageCountsLine(pt: PTCoverage): string {
  const c = coverageCounts(pt);
  const n = (k: string) => (hasOwn(c, k) ? count(c[k]) : 0);
  const logged = n("tested_logged");
  const parts = [`${n("tested_claimed") + logged} of ${pt?.rows?.length ?? 0} categories claimed`, `${logged} with a logged request`];
  for (const row of COUNT_TAILS) if (n(row.word) > 0) parts.push(row.tail(n(row.word)));
  return parts.join(", ");
}

// ---- evidence ----
//
// Evidence is Observer's own check of a finding against the request helper's
// log (depth plan W5b): did a logged attack request return the response the
// finding indicates, and did its control request not. The helper is a small
// program Observer writes into the run folder; the agent sends its requests
// through it and it logs each one. The log is a file in the project the agent
// can write, so the words are "Helper log matches", "No log" and "Not started",
// never a word that says the weakness is real, and every sentence about a match
// says the log is agent-writable and that this is not proof of impact. What the
// agent says about how it knows (its basis) stays the agent's, beside it.

/** EVIDENCE_STATES lists the evidence states in the order a picker shows them. */
export const EVIDENCE_STATES: readonly EvidenceState[] = ["logged", "unlogged", "not_started"];

/** The labels of the three states. These are Observer's words and the only ones a state reads as. */
export const EVIDENCE_LABELS: Readonly<Record<EvidenceState, string>> = {
  logged: "Helper log matches",
  unlogged: "No log",
  not_started: "Not started",
};

/** evidenceState is a finding's state as this view reads it: logged and not_started as sent, any other word (and an absent one, from a copy stored before the helper existed) as unlogged. */
export function evidenceState(f: Pick<PTFinding, "evidence_state"> | null | undefined): EvidenceState {
  const s = f?.evidence_state;
  return s === "logged" || s === "not_started" ? s : "unlogged";
}

/** The sentence every evidence of a logged finding ends with. */
export const EVIDENCE_NOT_PROOF = "The log is a file the agent can write, so this is not proof.";

/** The line under a logged finding's evidence in a table row. */
export const EVIDENCE_AGENT_WRITABLE = "The log is a file the agent can write.";

/** What a logged state says: the match, then what it is not. */
const LOGGED_DETAIL = `In this copy of the project, a request in the helper log returned the indicated response for the attack request and not for its control request. This is not proof of impact, and it says nothing about production. ${EVIDENCE_NOT_PROOF}`;

/** What an unlogged finding's detail ends with, whatever the reason. */
const UNLOGGED_TAIL = "The agent's own claim is shown beside it, and the agent can write any file in the run folder.";

/** The sentence for each reason a finding is not logged (secassess.EvidenceReason*), in Observer's words. A code this table lacks reads through evidenceReasonSentence's generic sentence. */
export const EVIDENCE_REASON_WORDS: Readonly<Record<string, string>> = {
  target_not_started: "The application did not start, so nothing was tested in a running application.",
  probe_helper_off: "The request helper was off for this run (a setting), so no request was logged.",
  helper_withheld: "The request helper was left out because python3 was not seen in the box's standard folders.",
  helper_changed: "The helper or its settings file was changed after Observer wrote it, so its log is not used.",
  helper_missing: "The helper's files could not be read when the run was checked, so the log cannot be compared.",
  log_absent: "The helper log holds no request.",
  log_unreadable: "The helper log could not be read.",
  log_too_large: "The helper log is over the size Observer reads.",
  log_inconsistent: "The helper log does not read like one the helper wrote (a line out of order, missing or malformed), so it is not used.",
  no_probe: "The finding cites no logged request (a request made another way, or read from code, is not logged).",
  probe_not_in_log: "A request the finding cites is not in the helper log.",
  probe_not_sent: "A request the finding cites was refused by the helper, so it never reached the target.",
  probe_no_response: "A request the finding cites got no response.",
  no_indicator: "The finding names no attack request.",
  no_control: "The finding names no control request, or names the same request as the attack.",
  no_condition: "The finding does not say what differs between the attack and the control response.",
  condition_not_met: "The logged attack response does not meet the finding's condition. The log keeps a cookie or token value as [REDACTED], so a condition that names the value itself cannot be met.",
  not_differential: "The condition also holds for the control response, so it does not tell the two apart.",
  not_replayed: "The request named as the attack is not the helper's replay of this finding's stored request, so the label rests on nothing the retest sent.",
  condition_still_holds: "The stored condition still holds for the replayed request in the log, so the log does not back a label that says the weakness is gone.",
  replay_incomplete: "The stored request had values hidden when it was kept, so the replay was not the original request and the log does not back a label that says the weakness is gone.",
};

/** The first sentence of a finding with no log whose reason this view has no words for. */
const GENERIC_NO_LOG = "Observer has no request log that backs this finding";

/** evidenceReasonSentence is a reason code in words: its table row, else the generic sentence with the code cleaned of underscores. */
export function evidenceReasonSentence(code: string): string {
  if (hasOwn(EVIDENCE_REASON_WORDS, code)) return EVIDENCE_REASON_WORDS[code];
  const c = cleaned(code);
  return c ? `${GENERIC_NO_LOG} (${c}).` : `${GENERIC_NO_LOG}.`;
}

/** The reason a finding with none of its own takes from the run's evidence report: the one fact about the helper or its log that explains why no finding of the run has a log. "" when the report explains nothing. */
function reportReason(ev: EvidenceReport | null | undefined): string {
  if (!ev) return "";
  if (ev.mode === "off") return "probe_helper_off";
  if (ev.mode === "withheld") return "helper_withheld";
  if (ev.helper === "changed") return "helper_changed";
  if (ev.helper === "missing") return "helper_missing";
  if (ev.log === "absent") return "log_absent";
  if (ev.log === "unreadable") return "log_unreadable";
  if (ev.log === "too_large") return "log_too_large";
  if (ev.log === "inconsistent") return "log_inconsistent";
  return "";
}

/** EvidenceWord is CoverageWord with the state it words. */
export type EvidenceWord = CoverageWord & { state: EvidenceState };

/** evidenceWords is Observer's evidence for a finding in words: the label, the pill's tone (info for a match, never success: the log is a file the agent can write, so a green pass would say more than it holds) and a detail. A finding with no state of its own (a copy stored before the helper existed) reads as No log; with the run's evidence report, a reason the report itself explains is used when the finding carries none. */
export function evidenceWords(f: PTFinding, report?: EvidenceReport | null): EvidenceWord {
  const state = evidenceState(f);
  const label = EVIDENCE_LABELS[state];
  if (state === "logged") return { state, label, tone: "info", detail: LOGGED_DETAIL };
  const own = typeof f?.evidence_reason === "string" ? f.evidence_reason.trim() : "";
  if (state === "not_started") {
    // The state is the reason: the application did not start. A code this table knows says it more exactly.
    const sentence = own !== "" && hasOwn(EVIDENCE_REASON_WORDS, own) ? EVIDENCE_REASON_WORDS[own] : EVIDENCE_REASON_WORDS.target_not_started;
    return { state, label, tone: "neutral", detail: sentence };
  }
  const code = own !== "" ? own : reportReason(report);
  if (code === "") {
    return { state, label, tone: "neutral", detail: `Observer has no request log for this finding. ${UNLOGGED_TAIL}` };
  }
  return { state, label, tone: "neutral", detail: `${evidenceReasonSentence(code)} ${UNLOGGED_TAIL}` };
}

/** evidenceReasonLines lists why findings are not logged, from the report's by_reason counts: the most findings first, a tie by code. */
export function evidenceReasonLines(ev: EvidenceReport | null | undefined): { code: string; n: number; text: string }[] {
  const by = ev?.by_reason;
  if (!by || typeof by !== "object") return [];
  return Object.entries(by)
    .map(([code, n]) => ({ code, n: count(n) }))
    .filter((r) => r.n > 0)
    .sort((a, b) => b.n - a.n || (a.code < b.code ? -1 : a.code > b.code ? 1 : 0))
    .map((r) => ({ ...r, text: evidenceReasonSentence(r.code) }));
}

/** The head of the summary line for a log the helper wrote: what it holds, or why it is not used. */
function logHead(ev: EvidenceReport): string {
  switch (ev.log) {
    case "ok": {
      const sent = count(ev.sent);
      const refused = count(ev.refused);
      return `${sent} ${plural(sent, "request", "requests")} sent, ${refused} refused`;
    }
    case "absent":
      return "the helper log holds no request";
    case "unreadable":
      return "the helper log could not be read";
    case "too_large":
      return "the helper log is over the size Observer reads";
    case "inconsistent":
      return "the helper log does not read like one the helper wrote, so it is not used";
    case "not_read":
      return "the helper log was not read";
    default:
      return "the helper log is not described";
  }
}

/** The end of the summary line: what the check found of the helper's own files. "" when it is not said. */
function helperTail(ev: EvidenceReport): string {
  switch (ev.helper) {
    case "intact":
      return "helper unchanged";
    case "changed":
      return "helper changed, so its log is not used";
    case "missing":
      return "helper files not readable";
    case "not_checked":
      return "helper not checked";
    default:
      return "";
  }
}

/** evidenceSummaryLine is the one line above the findings that says what the request log held and what became of the findings, such as "Request log: 14 requests sent, 2 refused; 3 findings with a matching log, 5 without, helper unchanged". "" when the report is absent or names no mode (a copy stored before the helper existed). */
export function evidenceSummaryLine(ev: EvidenceReport | null | undefined): string {
  if (!ev) return "";
  let head: string;
  if (ev.mode === "off") head = "the request helper was off for this run";
  else if (ev.mode === "withheld") head = "the request helper was left out (python3 was not seen in the box's standard folders)";
  else if (ev.mode === "on") head = logHead(ev);
  else return "";
  const logged = count(ev.logged);
  const unlogged = count(ev.unlogged);
  const notStarted = count(ev.not_started);
  const findings = `${logged} ${plural(logged, "finding", "findings")} with a matching log, ${unlogged} without${notStarted > 0 ? `, ${notStarted} not started` : ""}`;
  const tail = ev.mode === "on" ? helperTail(ev) : "";
  return `Request log: ${head}; ${findings}${tail ? `, ${tail}` : ""}`;
}

// ---- requests, conditions and the helper's log records ----

/** str reads a wire field as text: the string, else "". An older stored copy or a hostile one can hold anything. */
function str(v: unknown): string {
  return typeof v === "string" ? v : "";
}

/** requestLine is a request in one line, "GET /api/search?q=rent". A request an older stored copy holds as one string is that string; a request with no method or no path is the part it has. */
export function requestLine(r: PTRequest | string | null | undefined): string {
  if (typeof r === "string") return r.trim();
  if (r === null || r === undefined || typeof r !== "object") return "";
  return [str(r.method).trim(), str(r.path).trim()].filter((x) => x !== "").join(" ");
}

/** requestHeaderLines is a request's headers as "Name: value" lines, in the order the agent wrote them; a header with no name is left out. */
export function requestHeaderLines(r: PTRequest | string | null | undefined): string[] {
  if (r === null || r === undefined || typeof r !== "object" || !Array.isArray(r.headers)) return [];
  const lines: string[] = [];
  for (const h of r.headers) {
    const name = str(h?.name).trim();
    if (name !== "") lines.push(`${name}: ${str(h?.value)}`);
  }
  return lines;
}

/** requestBody is a request's body as the agent wrote it, "" when there is none. */
export function requestBody(r: PTRequest | string | null | undefined): string {
  if (r === null || r === undefined || typeof r !== "object") return "";
  return str(r.body);
}

/** hex4At reads the number of a six-character \uXXXX escape at the start of s from position at; null for anything else (fewer than four digits, a digit that is not hexadecimal). */
function hex4At(s: string, at: number): number | null {
  if (s.length < at + 6 || s[at] !== "\\" || s[at + 1] !== "u") return null;
  const digits = s.slice(at + 2, at + 6);
  for (const c of digits) if (!"0123456789abcdefABCDEF".includes(c)) return null;
  return parseInt(digits, 16);
}

/** jsonUnescapeOnce decodes the escapes of a JSON string in text, once and in one pass: \" \\ \/ \b \f \n \r \t and \uXXXX (a surrogate pair is one character). It is the display twin of secassess.jsonUnescape, which the evidence check reads a body through, and it follows the same rules, pinned by one golden table both sides run (internal/secassess/testdata/json_unescape_cases.json): the text need not be JSON, so a backslash that starts none of those escapes, a \u with fewer than four hex digits and a lone surrogate stay as they were written, and an escape the pass produced is not decoded again. The result is never longer than the text. It is for showing a condition the agent wrote inside a JSON string as the text it means, never for deciding anything. */
export function jsonUnescapeOnce(s: string): string {
  if (!s.includes("\\")) return s;
  let out = "";
  for (let i = 0; i < s.length; ) {
    const c = s[i];
    if (c !== "\\" || i + 1 >= s.length) {
      out += c;
      i++;
      continue;
    }
    const n = s[i + 1];
    const simple: Record<string, string> = { '"': '"', "\\": "\\", "/": "/", b: "\b", f: "\f", n: "\n", r: "\r", t: "\t" };
    if (Object.prototype.hasOwnProperty.call(simple, n)) {
      out += simple[n];
      i += 2;
      continue;
    }
    if (n === "u") {
      const hi = hex4At(s, i);
      if (hi !== null) {
        if (hi >= 0xd800 && hi <= 0xdfff) {
          const lo = hex4At(s, i + 6);
          if (hi <= 0xdbff && lo !== null && lo >= 0xdc00 && lo <= 0xdfff) {
            out += String.fromCodePoint(0x10000 + ((hi - 0xd800) << 10) + (lo - 0xdc00));
            i += 12;
            continue;
          }
        } else {
          out += String.fromCharCode(hi);
          i += 6;
          continue;
        }
      }
    }
    out += c;
    i++;
  }
  return out;
}

/** conditionText is one text of an agent's condition for showing: its JSON escapes decoded once (the text is shown, not its encoding) and each run of line breaks and tabs made a space, so a condition reads on one line. Display only: the evidence check reads the condition as it was stored. */
export function conditionText(s: string): string {
  return jsonUnescapeOnce(s).split("\r").join(" ").split("\n").join(" ").split("\t").join(" ");
}

/** quoteList is values in double quotes, joined the way a sentence does: "a", "a" and "b", "a", "b" and "c". Each value is shown as the text it means (conditionText). */
function quoteList(values: unknown[]): string {
  const q = values.filter((v): v is string => typeof v === "string" && v !== "").map((v) => `"${conditionText(v)}"`);
  if (q.length <= 1) return q.join("");
  return `${q.slice(0, -1).join(", ")} and ${q[q.length - 1]}`;
}

/** nameList is header names joined the way a sentence does, with is or are to match. */
function nameList(values: unknown[], isWord: string, areWord: string): string {
  const names = values.filter((v): v is string => typeof v === "string" && v.trim() !== "").map((v) => v.trim());
  if (names.length === 0) return "";
  const joined = names.length === 1 ? names[0] : `${names.slice(0, -1).join(", ")} and ${names[names.length - 1]}`;
  return `${plural(names.length, "the header", "the headers")} ${joined} ${names.length === 1 ? isWord : areWord}`;
}

/** matchWords is the condition the agent wrote in a plain sentence: "status 200; the body contains "x"; the header X-Frame-Options is absent". "" when it holds no condition. Every word inside quotes or beside a header name is the agent's. */
export function matchWords(m: PTMatch | null | undefined): string {
  if (m === null || m === undefined || typeof m !== "object") return "";
  const parts: string[] = [];
  if (typeof m.status === "number" && Number.isFinite(m.status)) parts.push(`status ${m.status}`);
  if (Array.isArray(m.body_contains)) {
    const q = quoteList(m.body_contains);
    if (q) parts.push(`the body contains ${q}`);
  }
  if (Array.isArray(m.body_not_contains)) {
    const q = quoteList(m.body_not_contains);
    if (q) parts.push(`the body does not contain ${q}`);
  }
  if (Array.isArray(m.header_present)) {
    const n = nameList(m.header_present, "is present", "are present");
    if (n) parts.push(n);
  }
  if (Array.isArray(m.header_absent)) {
    const n = nameList(m.header_absent, "is absent", "are absent");
    if (n) parts.push(n);
  }
  if (Array.isArray(m.header_contains)) {
    for (const h of m.header_contains) {
      const name = str(h?.name).trim();
      if (name !== "") parts.push(`the header ${name} contains "${conditionText(str(h?.value))}"`);
    }
  }
  return parts.join("; ");
}

/** REFUSED_WORDS: why the helper refused a request (the log's `refused` codes), in a sentence each. A refused request never reached the target. */
export const REFUSED_WORDS: Readonly<Record<string, string>> = {
  off_target: "The address was not the target's host and port, and the helper sends to the target only.",
  budget: "The run's request budget was already used up.",
  bad_path: "The path held a character or a length the helper does not accept.",
  bad_header: "A header was one the helper does not allow.",
  bad_method: "The method was not one the helper allows.",
  body_too_large: "The request body was over the size the helper allows.",
  bad_config: "The helper's settings file could not be used.",
  lockout: "The attempts at one path and account label were past the lockout limit.",
};

/** refusedWords is a refusal code in a sentence, ending with where the request got to. A code this table lacks reads as written, cleaned. */
export function refusedWords(code: string): string {
  const why = hasOwn(REFUSED_WORDS, code) ? REFUSED_WORDS[code] : `The helper gave a reason this view has no words for (${cleaned(code) || "not stated"}).`;
  return `${why} The request never reached the target.`;
}

/** The words of a logged request's role. */
export const PROBE_ROLE_WORDS: Readonly<Record<string, string>> = { attack: "Attack request", control: "Control request" };

/** probeRoleWords names a request by the role the agent gave it, else as a cited request. */
export function probeRoleWords(role: string | undefined): string {
  return role !== undefined && hasOwn(PROBE_ROLE_WORDS, role) ? PROBE_ROLE_WORDS[role] : "Cited request";
}

/** The caption under a response excerpt. */
export const PROBE_EXCERPT_CAPTION = "first 1 KiB of the response, secrets Observer recognised hidden";

/** The caption under a request body excerpt. */
export const PROBE_REQUEST_BODY_CAPTION = "the start of the request body, secrets Observer recognised hidden";

/** ProbeIndex is the log records of an answer by id. */
export type ProbeIndex = ReadonlyMap<string, ProbeRecord>;

/** probeIndex keys the records by id; when two records share an id the first wins (the helper numbers its requests, so a second is a log that does not read like the helper's). */
export function probeIndex(probes: readonly ProbeRecord[] | null | undefined): Map<string, ProbeRecord> {
  const m = new Map<string, ProbeRecord>();
  for (const p of probes ?? []) {
    const id = str(p?.id);
    if (id !== "" && !m.has(id)) m.set(id, p);
  }
  return m;
}

/** A request a finding names: its id and why it is named (the attack of its indicator, the control, or only cited). */
export type CitedProbe = { id: string; role: "attack" | "control" | "cited" };

/** citedProbes lists the requests a finding names, each once: its attack, its control, then the others it cites in the order it wrote them. */
export function citedProbes(f: Pick<PTFinding, "indicator" | "evidence">): CitedProbe[] {
  const out: CitedProbe[] = [];
  const seen = new Set<string>();
  const add = (id: unknown, role: CitedProbe["role"]) => {
    if (typeof id !== "string" || id === "" || seen.has(id)) return;
    seen.add(id);
    out.push({ id, role });
  };
  add(f?.indicator?.attack, "attack");
  add(f?.indicator?.control, "control");
  for (const id of f?.evidence ?? []) add(id, "cited");
  return out;
}

/** The outcome of a logged request: what became of it, in a sentence, and whether it deserves a warning tone. */
export type ProbeOutcome = { kind: "response" | "refused" | "error" | "none"; text: string; tone: Tone };

/** probeOutcome says what became of a logged request: the response it got, the refusal that stopped it, or that nothing came back. The response's own status is a number the target sent; it is not a verdict. */
export function probeOutcome(p: ProbeRecord): ProbeOutcome {
  const code = str(p.refused);
  if (code !== "") return { kind: "refused", text: `Refused by the helper. ${refusedWords(code)}`, tone: "warn" };
  if (p.sent === false) return { kind: "refused", text: "The helper did not send this request, and it never reached the target.", tone: "warn" };
  const err = str(p.error).trim();
  if (err !== "") return { kind: "error", text: `The request was sent and got no response. The helper recorded: ${err}`, tone: "warn" };
  const status = count(p.status);
  if (status > 0) {
    const ms = count(p.ms);
    const bytes = count(p.body_bytes);
    const extra = [ms > 0 ? `${ms} ms` : "", bytes > 0 ? `${bytes} ${plural(bytes, "byte", "bytes")} of body` : ""].filter((x) => x !== "");
    return { kind: "response", text: `Response ${status}${extra.length > 0 ? `, ${extra.join(", ")}` : ""}.`, tone: "neutral" };
  }
  return { kind: "none", text: "The log records no response for this request.", tone: "warn" };
}

/** probeRedirectLine says what the helper did about a redirect in a response, or "" when there was none. */
export function probeRedirectLine(p: ProbeRecord): string {
  const to = str(p.redirect_to);
  const hops = count(p.hops);
  const parts: string[] = [];
  if (hops > 0) parts.push(`${hops} ${plural(hops, "redirect was", "redirects were")} followed.`);
  if (to !== "") parts.push(p.redirect_blocked === true ? `The response pointed to ${to}, and the helper did not follow it.` : `The response pointed to ${to}.`);
  return parts.join(" ");
}

/** probeExcerptCaption is the caption under a response excerpt: what the excerpt is, how many bytes of the response the helper read and, when the response was longer than the helper reads (more than 64 KiB), that. */
export function probeExcerptCaption(p: Pick<ProbeRecord, "body_bytes" | "body_truncated">): string {
  const bytes = count(p.body_bytes);
  const more = p.body_truncated === true ? "the response was longer than the helper reads" : "";
  if (bytes > 0) return `${PROBE_EXCERPT_CAPTION} (${bytes} ${plural(bytes, "byte", "bytes")} read${more ? `; ${more}` : ""})`;
  return more ? `${PROBE_EXCERPT_CAPTION}; ${more}` : PROBE_EXCERPT_CAPTION;
}

/** probeLogNote says how much of the log this answer holds when it holds only part of it, "" when it holds what the findings cite. */
export function probeLogNote(info: ProbeLogInfo | null | undefined): string {
  if (!info || info.truncated !== true) return "";
  return `This answer holds ${count(info.shown)} of the log's ${count(info.records)} ${plural(count(info.records), "request", "requests")}, so a request that is not shown here may still be in the log.`;
}

/** The agent's basis values this view words itself; any other is shown as the agent wrote it, cleaned. */
const BASIS_WORDS: ReadonlyMap<string, string> = new Map([
  ["observed", "seen in a request"],
  ["inferred", "read from code"],
]);

/** basisWords is the agent's own claim of how it knows, said as the agent's: "The agent says: seen in a request" / "The agent says: read from code". */
export function basisWords(basis: string): string {
  const key = typeof basis === "string" ? basis.trim() : "";
  const known = BASIS_WORDS.get(key);
  if (known) return `The agent says: ${known}`;
  const cleaned = key.replace(/[_\s]+/g, " ").trim();
  return cleaned ? `The agent says: ${cleaned}` : "The agent gave no basis";
}

// ---- the honest limits ----

/** The honest limits (plan section 13), by who they apply to. */
export type LimitId = string;
export type Limit = { id: LimitId; applies: "both" | "threatmodel" | "pentest"; text: string };

/** HONEST_LIMITS is section 13 of the plan, in its order and in plain words. None of the sentences says the project is clear of weaknesses; the wording test pins it. */
export const HONEST_LIMITS: readonly Limit[] = [
  {
    id: "l1",
    applies: "both",
    text: "The agent wrote this, and Observer checked only its structure, its closed word lists, the files it cites and git state. It did not check that the reasoning is right, that a weakness it names can be exploited, or that nothing was missed.",
  },
  {
    id: "l2",
    applies: "both",
    text: "Two runs of the same prompt differ, and how well a run finds a kind of flaw depends on the model and the prompt version. What was measured on the test project applies to that project's kinds of flaw, for one model and one prompt version at a time.",
  },
  {
    id: "l3",
    applies: "both",
    text: "Nothing reported is not a clearance. A run that reports no threats or findings always comes with its coverage line, which says what was and was not covered, and an empty list is never a sign that the project has no flaw left to find.",
  },
  {
    id: "l4",
    applies: "both",
    text: "This is not compliance evidence. No PCI, SOC 2, ISO or customer-assurance claim follows from it, and it does not replace a test by a person.",
  },
  {
    id: "l5",
    applies: "both",
    text: "Imported findings are flags. They carry low confidence, their severity is capped at medium, they close nothing, and they stay outside the high-confidence findings the commit gate blocks on. The band lives in this view.",
  },
  {
    id: "l6",
    applies: "both",
    text: "Reports can be wrong in confident prose. The narrative is shown as text Observer has not checked. Hiding secrets hides only the ones Observer recognises, not all sensitive content, and the files on disk are as the agent wrote them.",
  },
  {
    id: "l7",
    applies: "both",
    text: "The git check looks at git state only: edits to tracked files, HEAD, the branch, the stash and refs. It does not see ignored files (.env files, local databases, caches, node_modules), reads, or anything you changed meanwhile. It is not a trace.",
  },
  {
    id: "l8",
    applies: "threatmodel",
    text: "The model comes from code and docs only. It has no business context, no deployed layout, no cloud or SaaS service the code does not show, and no organisational or physical threats. A component that is not in the model is unknown; it is not ruled out.",
  },
  {
    id: "l9",
    applies: "threatmodel",
    text: "Likelihood and impact are judgements. The band is an ordinal heuristic, the product of two ratings from 1 to 5, not a probability or a loss figure. No residual score is computed.",
  },
  {
    id: "l10",
    applies: "threatmodel",
    text: "Found near the cited line does not mean a working control. It means the file, the cited lines and a quoted text of 8 characters or more on a code line near the cited line exist. The control may be wrong or unreachable, and a quoted text inside a string literal on a code line still matches. Location exists, nothing matched earns no credit.",
  },
  {
    id: "l11",
    applies: "threatmodel",
    text: "Completeness is structural. For each element and category, Observer checks that the model has a threat or a stated reason that none applies, and counts the waived cells apart. It does not check that the threats named are the right ones.",
  },
  {
    id: "l12",
    applies: "pentest",
    text: "The target is a copy of your working tree in a box, with development settings. It is not production: no deployed headers or TLS, no firewall or reverse proxy, no production data volumes, no real identity provider or outside integration (the box has no route to them) and no infrastructure. One origin only.",
  },
  {
    id: "l13",
    applies: "pentest",
    text: "Helper log matches means that a logged request returned the indicated response in that copy, for an attack request and not for its control request, and that the request helper Observer wrote was unchanged when the run was checked. The log is a file the agent can write. It does not show the weakness can be used against production, and it is not proof of impact. A run that did not start the app tested nothing in a running application.",
  },
  {
    id: "l14",
    applies: "pentest",
    text: "The coverage matrix is the agent's claim, set beside a log; it is not a trace. A request made with curl or with the agent's own code is not logged, and Observer cannot see loopback traffic inside the box's network namespace.",
  },
  {
    id: "l15",
    applies: "pentest",
    text: "Scope holds by the sandbox, not by the prompt. With the proxy-only network tier the box has no route out except the model proxy, whose upstream lanes can include a local model server. Under a wider tier, staying on the target is held by the prompt, the host list and your word, and the dialog says so.",
  },
  {
    id: "l16",
    applies: "pentest",
    text: "The workspace is your live tree, and the box can read .env files there. The git check reports changes, not reads.",
  },
  {
    id: "l17",
    applies: "pentest",
    text: "The band is likelihood times impact, from the agent's two ratings. A finding may also carry a CVSS 4.0 base vector the agent wrote, and Observer computes its base score from that vector alone. That score is the weakness as logged in an in-box copy, not a production risk, and it changes neither the band nor the severity an import carries.",
  },
  {
    id: "l18",
    applies: "pentest",
    text: "A red team run is one application in one box: no pivoting, no social engineering, no persistence and no real detection testing. Observer's own guard and observability were not tested by it.",
  },
  {
    id: "l19",
    applies: "pentest",
    text: "Numbers measured on the test project are not coverage, and a public test project may be in a model's training data. Recall on seeded flaws says how one model and prompt pair does on those kinds of flaw.",
  },
  {
    id: "l20",
    applies: "pentest",
    text: "A retest repeats the stored requests of findings from an earlier run and labels each one reproduced, not reproduced or inconclusive. The label reads one replay against the response condition stored with the finding, in an in-box copy. Not reproduced does not mean the weakness is gone from your code or from production, and for a request that had values hidden when it was stored the log does not back it at all. A retest closes nothing and changes no finding's status.",
  },
];

/** Which of the limits' groups a result contract reads. A contract not listed reads the limits of both kinds only. */
const CONTRACT_LIMIT_GROUP: ReadonlyMap<string, Limit["applies"]> = new Map([
  ["threatmodel.v1", "threatmodel"],
  ["pentest.v1", "pentest"],
  ["retest.v1", "pentest"],
]);

/** EXERCISE_STOP_NOTE says whose opinion the "what would have detected or stopped this" column of a red team chain is (the same sentence as secassess.ExerciseStopNote; a Go test pins the two together). */
export const EXERCISE_STOP_NOTE = "What would have detected or stopped a step is the agent's opinion. Observer did not test any of it.";

/** limitsFor is the limits that apply to a contract, in the plan's order. */
export function limitsFor(contract: string): Limit[] {
  const group = CONTRACT_LIMIT_GROUP.get(contract);
  return HONEST_LIMITS.filter((l) => l.applies === "both" || l.applies === group);
}

// ---- how this was checked ----

/** What the model's report says about the contract's own words: one row per contract, the sentence its strip line reads. */
const CONTRACT_LINES: ReadonlyMap<string, (rep: ModelReport) => string> = new Map([
  [
    "threatmodel.v1",
    (rep) => {
      const tm = rep.tm;
      const head = tm
        ? `Element and category pairs: ${count(tm.analysed)} analysed, ${count(tm.waived)} waived and ${count(tm.empty)} with neither. `
        : "";
      return `${head}Analysed means the model records a threat for the pair, waived means it gives a reason that none applies, and a pair with neither is not considered. Observer did not check that a threat or a reason is right.`;
    },
  ],
  [
    "pentest.v1",
    () =>
      "The coverage matrix is the agent's own claim. Observer sees only the requests that went through the request helper, so a category marked tested is claimed until a logged request backs it.",
  ],
  [
    "retest.v1",
    () =>
      "Each label is the agent's, read by Observer against the helper's log of the replay and the condition stored with the finding. A label with no log behind it is shown as having none. A retest closes nothing and changes no finding.",
  ],
]);

/** partialParts is what a partly checked result lost, as phrases: items refused, items left out, references not looked at. Empty when the report counts none of them. */
function partialParts(rep: ModelReport): string[] {
  let refused = 0;
  let leftOut = 0;
  for (const c of Object.values(rep.counts ?? {})) {
    refused += count(c?.refused);
    leftOut += count(c?.left_out);
  }
  const unchecked = count(rep.refs?.unchecked);
  const parts: string[] = [];
  if (refused > 0) parts.push(`${refused} ${plural(refused, "item was", "items were")} refused`);
  if (leftOut > 0) parts.push(`${leftOut} ${plural(leftOut, "item was", "items were")} left out`);
  if (unchecked > 0) parts.push(`${unchecked} ${plural(unchecked, "reference", "references")} could not be looked at within the check's budget`);
  return parts;
}

/** validationLine is the validation state in words: what was refused, what was only partly looked at, or why the file was refused. */
export function validationLine(rec: ModelRecord, rep: ModelReport): { text: string; tone: Tone } {
  const anyway = rec.anyway ? " It was checked before the run ended." : "";
  if (rep.state === "valid") return { text: `Nothing was refused.${anyway}`, tone: "neutral" };
  if (rep.state === "invalid") {
    const fatal = rep.fatal ?? "";
    const why = hasOwn(ASSESS_FATAL_WORDS, fatal) ? ASSESS_FATAL_WORDS[fatal] : fatal ? fatal.replace(/_/g, " ") : "it could not be read";
    return { text: `The file was refused: ${why}.${anyway}`, tone: "danger" };
  }
  if (rep.state === "partial") {
    const parts = partialParts(rep);
    return { text: `Partly checked: ${parts.length > 0 ? parts.join(", ") : "some items were left out"}.${anyway}`, tone: "warn" };
  }
  return { text: `The validation state is ${rep.state ? `"${rep.state}"` : "not stated"}.${anyway}`, tone: "neutral" };
}

/** REF_BUDGET_UNRECORDED is the line under a reference count whose check kept no read budget (a check made before it was recorded). */
export const REF_BUDGET_UNRECORDED = "The file, size and time budget the references were read under was not recorded for this check.";

/** howCheckedLines is the "how this was checked" strip: what Observer did and did not do, in sentences, from the report (references by state, issues, ignored fields, the validation state). A line with nothing to say is left out. */
export function howCheckedLines(rec: ModelRecord): { text: string; tone: Tone }[] {
  const lines: { text: string; tone: Tone }[] = [];
  const rep = rec?.result?.report;
  lines.push({
    text: "Observer checked the structure of the file, its closed word lists and the files the agent cited. It did not check that the reasoning is right, that a weakness can be exploited, or that nothing was missed.",
    tone: "neutral",
  });
  if (rep) {
    lines.push(validationLine(rec, rep));
    const refs = rep.refs ? assessRefTallyWords(rep.refs) : "";
    if (refs) {
      const r = rep.refs;
      lines.push({ text: refs, tone: count(r.claimed_not_found) + count(r.missing) + count(r.invalid) + count(r.unchecked) > 0 ? "warn" : "neutral" });
      // The conditions of the counts: the window, the quoted text hiding secrets changed, and the read budget.
      for (const text of assessRefConditionWords(rep.ref_check?.window_lines, rep.ref_check?.text_hidden)) lines.push({ text, tone: "neutral" });
      const b = rec.ref_budget;
      if (b && b.files > 0 && b.mib > 0 && b.seconds > 0) {
        lines.push({ text: `References were read under a budget of ${b.files} ${plural(b.files, "file", "files")}, ${b.mib} MiB and ${b.seconds} ${plural(b.seconds, "second", "seconds")}; one the check ran out of budget for reads "not checked".`, tone: "neutral" });
      } else {
        // A check made before the budget was kept says so, rather than leaving a count with no conditions (N-20).
        lines.push({ text: REF_BUDGET_UNRECORDED, tone: "neutral" });
      }
    }
    const ignored = count(rep.ignored_fields);
    if (ignored > 0) {
      const keys = (rep.ignored_keys ?? []).filter((k) => typeof k === "string" && k !== "");
      const more = keys.length > 0 && ignored > keys.length ? ", and others" : "";
      lines.push({
        text: `${ignored} ${plural(ignored, "field was", "fields were")} not in the schema and ${plural(ignored, "was", "were")} ignored${keys.length > 0 ? ` (${keys.join(", ")}${more})` : ""}.`,
        tone: "neutral",
      });
    }
    const past = count(rep.issues_more);
    if (past > 0) {
      lines.push({ text: `${past} more ${plural(past, "issue was", "issues were")} found than the list keeps, so ${plural(past, "it is", "they are")} not shown.`, tone: "warn" });
    }
    const contract = CONTRACT_LINES.get(rec.contract) ?? CONTRACT_LINES.get(rep.contract);
    if (contract) lines.push({ text: contract(rep), tone: "neutral" });
  }
  if (rec?.truncated) {
    lines.push({
      text: "The model did not fit the stored copy, so only the report is kept and the model itself cannot be shown here.",
      tone: "warn",
    });
  }
  return lines;
}

// ---- what was not shown, and what this does not tell you ----

/** The part of the check a partial result is announced with above the tabs: null unless some of the file was refused, left out or not looked at. */
export function partialNotice(rec: ModelRecord | undefined): { title: string; text: string } | null {
  const rep = rec?.result?.report;
  if (!rec || !rep || rep.state !== "partial") return null;
  const parts = partialParts(rep);
  return { title: "Partly checked", text: `${parts.length > 0 ? parts.join(", ") : "Some items were left out"}.${rec.anyway ? " It was checked before the run ended." : ""}`.replace(/^./, (c) => c.toUpperCase()) };
}

/** The noun of each list the agent writes items into, in the singular and the plural. */
const LIST_NOUNS: Readonly<Record<"threats" | "findings", readonly [string, string]>> = {
  threats: ["threat", "threats"],
  findings: ["finding", "findings"],
};

/** itemCounts reads what the check did with the items of one list ("threats" or "findings") from the report: how many the agent wrote, refused, left out and kept. A list the report has no count for reads as nothing written. */
export function itemCounts(rec: ModelRecord | undefined, list: "threats" | "findings"): { read: number; refused: number; leftOut: number; kept: number } {
  const c = rec?.result?.report?.counts;
  const row = c && hasOwn(c, list) ? c[list] : undefined;
  return { read: count(row?.read), refused: count(row?.refused), leftOut: count(row?.left_out), kept: count(row?.kept) };
}

/** unlistedWords says what became of the items the agent wrote and the check did not keep, or "" when it kept every one. With none kept it is the empty list's sentence ("The agent wrote 3 threats; the check refused all 3, so none is shown here"); with some kept it is the note under the list.
 *  It is the words a list uses instead of "none was reported" whenever the agent wrote more than was kept. */
export function unlistedWords(list: "threats" | "findings", c: { read: number; refused: number; leftOut: number; kept: number }): string {
  if (c.read <= c.kept) return "";
  const [one, many] = LIST_NOUNS[list];
  const n = c.read;
  const gone = n - c.kept;
  const parts: string[] = [];
  if (c.refused > 0) parts.push(`refused ${c.refused === n ? (n === 1 ? "it" : `all ${n}`) : c.refused}`);
  if (c.leftOut > 0) parts.push(`left out ${c.leftOut === n ? (n === 1 ? "it" : `all ${n}`) : c.leftOut}`);
  const fate = parts.length > 0 ? parts.join(" and ") : "did not keep " + (gone === 1 ? "it" : `${gone}`);
  const wrote = `The agent wrote ${n} ${plural(n, one, many)}`;
  if (c.kept === 0) return `${wrote}; the check ${fate}, so ${n === 1 ? "it is not shown" : "none is shown"} here. The reasons are under How checked.`;
  return `${wrote}; the check ${fate}, so ${gone} ${plural(gone, "is", "are")} not listed here. The reasons are under How checked.`;
}

/** limitsSummary is the two short lines kept above the tabs, the contract's own kind first: what this view does not tell you, with a way to the full list. */
export function limitsSummary(contract: string): string[] {
  const common =
    "The agent wrote this, and Observer checked only its structure and the files it cites, not that the reasoning is right. Nothing reported is not a clearance, and this is not compliance evidence.";
  const own = CONTRACT_SUMMARY.get(contract);
  return own ? [common, own] : [common];
}

/** The second line of the summary, by result contract. */
const CONTRACT_SUMMARY: ReadonlyMap<string, string> = new Map([
  ["threatmodel.v1", "The model comes from code and documents only, so a part it leaves out is unknown, not ruled out."],
  ["pentest.v1", "The target was a copy of your working tree in a box, not production, and the coverage matrix is the agent's claim."],
  ["retest.v1", "A retest repeats stored requests once, in a copy of your working tree in a box. Not reproduced does not mean the weakness is gone."],
]);

/** mermaidCountsLine says what the diagram left out, or "" when it left nothing out. */
export function mermaidCountsLine(m: ModelMermaid): string {
  if (m.omitted_nodes <= 0 && m.omitted_edges <= 0) return "";
  return `${m.nodes} of ${m.total_nodes} nodes drawn, ${m.omitted_edges} ${plural(m.omitted_edges, "flow", "flows")} not drawn: the cap is the diagram size setting (${m.max_nodes} nodes).`;
}

/** mermaidCutLine says how many labels were shortened in the diagram source, or "" when none was. The full names are in the tables. */
export function mermaidCutLine(m: ModelMermaid): string {
  const n = count(m.labels_cut);
  if (n <= 0) return "";
  return `${n} ${plural(n, "label was", "labels were")} shortened to ${count(m.label_chars)} characters; the full names are in the tables.`;
}

/** The settings that bound the diagram source, by the label each has in Settings (Code security, Security assessments). */
export const DIAGRAM_SETTING_LABELS = ["Most nodes the data-flow diagram source draws", "Longest label in the data-flow diagram source"] as const;

/** mermaidSettingsLine points at the two settings when the diagram left something out or cut a label, else "". */
export function mermaidSettingsLine(m: ModelMermaid): string {
  if (mermaidCountsLine(m) === "" && mermaidCutLine(m) === "") return "";
  return `Both limits are settings, "${DIAGRAM_SETTING_LABELS[0]}" and "${DIAGRAM_SETTING_LABELS[1]}" (${ASSESS_SETTINGS_WHERE}).`;
}

// ---- redaction, paths and the run row ----

/** The label of the setting that hides recognised secrets when a report or model is shown (ASSESS_SETTINGS_WHERE). */
export const REDACTION_SETTING_LABEL = "Hide recognised secrets when showing a report or model";

/** The redaction sentence (plan W5a): what is hidden in the text shown here, what is not rewritten, that only known shapes are recognised, and that the files in the project are as the agent wrote them. */
export const REDACTION_NOTE_ON =
  "Secrets Observer recognises are hidden in the text shown here, and only known shapes are recognised. Names that link parts of the model together and file paths are shown as the agent wrote them. The files in your project are as the agent wrote them.";
export const REDACTION_NOTE_OFF = `Hiding recognised secrets is turned off, so what is shown is as stored. The setting is "${REDACTION_SETTING_LABEL}" (${ASSESS_SETTINGS_WHERE}).`;
/** redactionNote is the sentence for the response's redaction state, with the count when some were hidden. A response with no redaction state has no sentence. */
export function redactionNote(r: { on: boolean; hidden: number } | undefined): string {
  if (!r) return "";
  if (!r.on) return REDACTION_NOTE_OFF;
  const n = count(r.hidden);
  return n > 0 ? `${REDACTION_NOTE_ON} In this answer, ${n} ${plural(n, "place was", "places were")} hidden.` : REDACTION_NOTE_ON;
}

/** The URL of the model read for a run, with an optional earlier run to compare against. */
export function assessModelPath(run: string, since?: string): string {
  const q = new URLSearchParams({ run });
  if (since) q.set("since", since);
  return `${ASSESS_MODEL_PATH}?${q.toString()}`;
}

/** The result contracts that carry a model. */
const MODEL_CONTRACTS: ReadonlySet<string> = new Set(["threatmodel.v1", "pentest.v1", "retest.v1"]);

/** modelOpenable is whether a run row offers "Open model": a model contract, a run that is not held or cancelled, a stored validation of any state (a refused file still has its report to read) and a stored checked copy.
 *  The server sends has_model true only while the copy is stored and leaves the key out when it is not, and the dashboard is served by the same binary as the server, so an absent key means there is no copy: Delete evidence leaves the validation on the row, and the button must not open a view that can only say the copy is gone. */
export function modelOpenable(r: {
  contract?: string;
  phase?: string;
  validation?: { state: string } | null;
  has_model?: boolean;
}): boolean {
  return (
    !!r.contract &&
    MODEL_CONTRACTS.has(r.contract) &&
    r.phase !== "held" &&
    r.phase !== "cancelled" &&
    r.validation != null &&
    r.has_model === true
  );
}

/** The fields of a run that sinceCandidates reads. */
type SinceRun = { id: string; created_at: string; project_root_hash: string; kind: string; has_model?: boolean };

/** sinceCandidates lists the earlier runs a threat model can be compared with: other runs of the same project and kind, not started after this one (the server refuses a later run), that have a stored checked copy, newest first. */
export function sinceCandidates<R extends SinceRun>(run: Pick<SinceRun, "id" | "created_at" | "project_root_hash" | "kind">, runs: R[]): R[] {
  const at = Date.parse(run.created_at);
  return runs
    .filter(
      (r) =>
        r.id !== run.id &&
        r.project_root_hash === run.project_root_hash &&
        r.kind === run.kind &&
        r.has_model === true &&
        // A run started after this one is refused by the server; two stamps that cannot be read are left to the server to judge.
        !(Date.parse(r.created_at) > at),
    )
    .sort((a, b) => Date.parse(b.created_at) - Date.parse(a.created_at));
}

/** The words of what a probably-the-same pair has in common (secassess.Basis*), the closed vocabulary of ModelDiffSimilar.basis. */
export const SIMILAR_BASIS_WORDS: Readonly<Record<string, string>> = {
  location: "the place in the code it cites",
  cwe: "a weakness id (CWE) in common",
  words: "similar words in the title",
  category: "the same category",
  element: "the same element",
};

/** similarBasisWords lists what a pair has in common, "a, b and c". A word the table does not know is left out (never shown as a raw value); with none left it says so. */
export function similarBasisWords(basis: readonly string[] | undefined): string {
  const words = (basis ?? []).filter((b) => hasOwn(SIMILAR_BASIS_WORDS, b)).map((b) => SIMILAR_BASIS_WORDS[b]);
  if (words.length === 0) return "signs the table does not name";
  if (words.length === 1) return words[0];
  return `${words.slice(0, -1).join(", ")} and ${words[words.length - 1]}`;
}

/** How many threats of each run were paired (read the same, changed or probably the same), and how many each run lists. */
export type PairingCounts = { paired: number; earlier: number; later: number };

/** pairingCounts reads the pairing out of a comparison: a threat is in exactly one of added/removed (alone in a run) or a pair. */
export function pairingCounts(since: ModelSince): PairingCounts {
  const paired = (since.changed ?? []).length + (since.similar ?? []).length + since.unchanged;
  return { paired, earlier: paired + (since.removed ?? []).length, later: paired + (since.added ?? []).length };
}

/** The least size of a run for which the "few could be paired" note is worth saying: a small model that pairs little says it in its own counts. */
const PAIRING_NOTE_MIN = 10;

/** pairingNote is the sentence that says most threats could not be paired, or "" when enough could (at least half of each run) or the runs are small. Two independent runs word the same flaw differently, so a low share says the lists of added and removed threats overstate what changed. */
export function pairingNote(since: ModelSince): string {
  const { paired, earlier, later } = pairingCounts(since);
  if (Math.max(earlier, later) < PAIRING_NOTE_MIN || (paired * 2 >= earlier && paired * 2 >= later)) return "";
  return `Only ${paired} of the earlier run's ${earlier} ${plural(earlier, "threat", "threats")} and ${paired} of this run's ${later} could be paired. The two runs word things differently, so the added and removed lists overstate what changed.`;
}

/** defaultSince is the earlier run the model view opens its comparison on: the one the run was launched with (its previous_run), when that run is still one the view can compare with (a candidate of sinceCandidates), else none. A run launched without a comparison, and one whose earlier run lost its checked copy, opens on none: the comparison is never guessed. */
export function defaultSince(run: { previous_run?: string }, candidates: readonly { id: string }[]): string {
  const prev = (run.previous_run ?? "").trim();
  return prev !== "" && candidates.some((c) => c.id === prev) ? prev : "";
}

/** modelTitle is the model view's title: the kind of assessment and the project it was run on, or the run's id. The run's handle is a token the launch hands out, never a name, so it is not shown. */
export function modelTitle(run: { kind_title: string; project_name?: string; id: string }): string {
  return `${run.kind_title}: ${run.project_name || run.id}`;
}

/** modelSubtitle is the line under the model view's title: when the run was started and when its model was checked. Each part is left out when its stamp is missing or cannot be read; "" when both are. */
export function modelSubtitle(startedAt: string | undefined, validatedAt: string | undefined, fmtDate: (iso: string) => string, fmtAgo: (iso: string) => string): string {
  const parts: string[] = [];
  if (startedAt && !Number.isNaN(Date.parse(startedAt))) parts.push(`Started ${fmtDate(startedAt)}`);
  if (validatedAt && !Number.isNaN(Date.parse(validatedAt))) parts.push(`Validated ${fmtAgo(validatedAt)}`);
  return parts.join(" · ");
}
