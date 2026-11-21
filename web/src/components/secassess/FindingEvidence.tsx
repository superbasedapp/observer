import { createContext, useCallback, useContext, useId, useMemo, useState } from "react";
import type { ColumnDef } from "@tanstack/react-table";
import { ChevronDown, ChevronRight } from "lucide-react";
import { Button, DataTable, EmptyState, Icon, Input, Pill, Select } from "@/components/primitives";
import { HelpInd } from "@/components/HelpInd";
import { fmtDateTime } from "@/lib/format";
import {
  DEFAULT_FINDING_SORT,
  EVIDENCE_AGENT_WRITABLE,
  MIT_STATE_WORDS,
  PROBE_REQUEST_BODY_CAPTION,
  basisWords,
  bandTone,
  citedProbes,
  cvssLeftOutIds,
  cvssReading,
  findingsLegend,
  CVSS_APART,
  CVSS_LEFT_OUT_NOTE,
  CVSS_NOTE,
  evidenceReasonLines,
  evidenceSummaryLine,
  evidenceWords,
  filterFindings,
  findingFacets,
  matchWords,
  mitRefsWords,
  mitigationSummary,
  nextFindingSort,
  plural,
  probeIndex,
  probeExcerptCaption,
  probeLogNote,
  probeOutcome,
  probeRedirectLine,
  probeRoleWords,
  requestBody,
  requestHeaderLines,
  requestLine,
  sortFindings,
  findingStatusNote,
  statusWords,
  toggleOpenKey,
  unlistedWords,
  wstgTitle,
  type CitedProbe,
  type EvidenceReport,
  type FindingFilter,
  type FindingSort,
  type FindingSortKey,
  type ModelBand,
  type ModelIssue,
  type ModelVocab,
  type ProbeIndex,
  type ProbeLogInfo,
  type ProbeRecord,
  type PTFinding,
} from "@/lib/secAssessModel";
import { AssessFixButton } from "./AssessFixButton";
import { RetestHistory, RetestLine } from "./AssessRetestLabel";
import { RefList } from "./RefList";
import { AgentText, ExpandedFit, SortButton, SubHeading, useSortFocus } from "./modelParts";

// FindingEvidence is the pen test's findings: one row for each finding with the
// agent's claim set beside Observer's evidence. The agent's basis ("seen in a
// request" or "read from code") is what the agent says about how it knows;
// Observer's evidence is what Observer computed from the request helper's log
// (depth plan W5b): "Helper log matches", "No log" (with the reason) or "Not
// started". The log is a file the agent can write, so a match is never called
// more than that and the row says so. The band is Observer's computation from
// the agent's two ratings. Each row opens to the places in the code with
// Observer's finding about each, the logged requests the finding cites (shown
// as text, secrets Observer recognised hidden), the reproduction steps, the
// impact and the fix (the agent's text). The list is the shared DataTable
// rendering in batches, so 1,200 findings do not put 1,200 cards in the page at
// once; no finding is capped or left out, and a filter or a sort runs over all
// of them first.

/** The rows a first render and each Show more adds. */
export const FINDING_BATCH = 75;

/** The findings table's column widths in px. Their sum (1160 with every column) is the table's least width, and it is less than the 1200 the 1240 px dialog leaves at its padding, so at 1280 the last column is not clipped (UX-15; it was 1228 and the last column ran 30 px past). */
export const FINDING_COLUMN_WIDTHS = { id: 92, title: 250, band: 112, category: 160, basis: 130, evidence: 150, status: 96, places: 170 } as const;

function bandText(f: PTFinding): string {
  if (!f.band) return "no band";
  return typeof f.score === "number" ? `${f.band} ${f.score}` : f.band;
}

/** FindingEvidence is the part of a finding every reader sees once it is open: where in the code, and the agent's basis beside Observer's evidence. `evidence` is the run's evidence report, which names the reason a finding with none of its own is not logged. */
export function FindingEvidence({ finding, evidence }: { finding: PTFinding; evidence?: EvidenceReport }) {
  const ev = evidenceWords(finding, evidence);
  return (
    <div className="space-y-2">
      <div className="space-y-1">
        <SubHeading>Where in the code</SubHeading>
        <RefList refs={finding.where?.refs} />
      </div>
      <div className="grid gap-2 sm:grid-cols-2" data-testid="assess-finding-evidence">
        <div className="space-y-1 rounded-2 border border-line-2 bg-bg-2 p-2">
          <SubHeading>Basis</SubHeading>
          <p className="m-0 text-[12px] text-fg-1">{basisWords(finding.basis)}</p>
        </div>
        <div className="space-y-1 rounded-2 border border-line-2 bg-bg-2 p-2">
          <SubHeading>{"Observer's evidence"}</SubHeading>
          <p className="m-0 flex flex-wrap items-center gap-2 text-[12px] text-fg-1">
            <Pill variant={ev.tone} case="none">
              {ev.label}
            </Pill>
            <span className="min-w-0 text-[11.5px] text-fg-3" data-testid="assess-finding-evidence-detail">
              {ev.detail}
            </span>
          </p>
        </div>
      </div>
    </div>
  );
}

/** CodeLines is a few lines of text the agent or the log holds, shown as text in a block that scrolls by keyboard. */
function CodeLines({ label, children, className }: { label: string; children: string; className?: string }) {
  return (
    <pre
      tabIndex={0}
      aria-label={label}
      className={`m-0 max-h-40 overflow-auto whitespace-pre-wrap break-all rounded-1 border border-line-2 bg-bg-3 px-1.5 py-1 font-mono text-[11px] leading-relaxed text-fg-1 ${className ?? ""}`}
    >
      {children}
    </pre>
  );
}

/** ProbeCard is one request of the helper's log, as the log wrote it: the request line, what became of it, the facts the agent gave the helper, the headers and the redacted response excerpt. All of it is text from a file the agent can write; none of it is a finding of Observer's about the target. `role` is why the finding names the request. */
export function ProbeCard({ p, role, vocab }: { p: ProbeRecord; role: CitedProbe["role"]; vocab?: ModelVocab }) {
  const out = probeOutcome(p);
  const line = requestLine({ method: p.method, path: p.path });
  const reqHeaders = (p.req_headers ?? []).filter((h) => !!h?.n).map((h) => `${h.n}: ${h.v ?? ""}`);
  const respHeaders = (p.resp_headers ?? []).filter((h) => !!h?.n).map((h) => `${h.n}: ${h.v ?? ""}`);
  const redirect = probeRedirectLine(p);
  const facts = [
    p.wstg ? `Category: ${wstgTitle(p.wstg, vocab)}` : "",
    p.account ? `Account: ${p.account}` : "",
    p.role && role !== "cited" && p.role !== role ? `The log marks it as ${p.role === "attack" ? "an attack" : "a control"} request` : "",
    p.ts ? `Logged ${fmtDateTime(p.ts)}` : "",
    p.replay ? `Replay of ${p.replay}` : "",
  ].filter((x) => x !== "");
  const pill = out.kind === "response" ? String(p.status) : out.kind === "refused" ? "Refused" : "No response";
  return (
    <div className="min-w-0 space-y-1.5 rounded-2 border border-line-2 bg-bg-2 p-2" data-testid="assess-probe" data-probe-id={p.id}>
      <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
        <span className="text-[12px] font-medium text-fg-1">{probeRoleWords(role === "cited" ? p.role : role)}</span>
        <code className="font-mono text-[11px] text-fg-3">{p.id}</code>
        <Pill variant={out.tone} case="none">
          {pill}
        </Pill>
      </div>
      {line && (
        <div className="min-w-0">
          <code className="break-all font-mono text-[11.5px] text-fg-1">{line}</code>
        </div>
      )}
      <p className="m-0 break-words text-[11.5px] text-fg-2">{out.text}</p>
      {facts.length > 0 && <p className="m-0 break-words text-[11px] text-fg-3">{facts.join(" · ")}</p>}
      {p.note && (
        <p className="m-0 break-words text-[11.5px] text-fg-2">
          {"The agent's note: "}
          <span className="whitespace-pre-wrap">{p.note}</span>
        </p>
      )}
      {redirect && <p className="m-0 break-words text-[11.5px] text-fg-2">{redirect}</p>}
      {reqHeaders.length > 0 && <CodeLines label={`Request headers of ${p.id}`}>{reqHeaders.join("\n")}</CodeLines>}
      {p.req_body_excerpt && (
        <div className="space-y-0.5">
          <CodeLines label={`Request body of ${p.id}`}>{p.req_body_excerpt}</CodeLines>
          <p className="m-0 text-[11px] text-fg-3">{`${PROBE_REQUEST_BODY_CAPTION}${p.req_body_bytes > 0 ? ` (${p.req_body_bytes} ${plural(p.req_body_bytes, "byte", "bytes")} in all)` : ""}`}</p>
        </div>
      )}
      {respHeaders.length > 0 && (
        <details className="text-fg-2">
          <summary className="cursor-pointer text-[11.5px] font-medium text-fg-3 hover:text-fg-1">{`Response headers (${respHeaders.length})`}</summary>
          <CodeLines label={`Response headers of ${p.id}`} className="mt-1">
            {respHeaders.join("\n")}
          </CodeLines>
        </details>
      )}
      {p.body_excerpt && (
        <div className="space-y-0.5">
          <CodeLines label={`Response excerpt of ${p.id}`}>{p.body_excerpt}</CodeLines>
          <p className="m-0 text-[11px] text-fg-3" data-testid="assess-probe-caption">
            {probeExcerptCaption(p)}
          </p>
        </div>
      )}
    </div>
  );
}

/** ProbeMissing stands where a request a finding names has no record in this answer: not in the log, or, when the answer holds only part of the log, not shown. */
function ProbeMissing({ id, role, truncated }: { id: string; role: CitedProbe["role"]; truncated: boolean }) {
  return (
    <div className="min-w-0 rounded-2 border border-dashed border-line-2 bg-bg-2 p-2 text-[11.5px] text-fg-2" data-testid="assess-probe-missing" data-probe-id={id}>
      <span className="font-medium text-fg-1">{probeRoleWords(role === "cited" ? "" : role)}</span> <code className="font-mono text-[11px] text-fg-3">{id}</code>
      {truncated ? ": not shown in this answer." : ": not in the log."}
    </div>
  );
}

/** FindingBody is what a finding's expander opens: the evidence, the indicator, the logged requests the finding cites, the reproduction steps, the impact and the fix. `probes` is the answer's log records by id and `probeLog` says how much of the log the answer holds. */
export function FindingBody({
  f,
  detailId,
  probes,
  probeLog,
  evidence,
  vocab,
  cvssLeftOut,
}: {
  f: PTFinding;
  detailId?: string;
  probes?: ProbeIndex;
  probeLog?: ProbeLogInfo;
  evidence?: EvidenceReport;
  vocab?: ModelVocab;
  /** The check left out a CVSS vector the agent wrote for this finding (the report's issue names it). */
  cvssLeftOut?: boolean;
}) {
  const steps = f.reproduction ?? [];
  const indicator = f.indicator;
  const probeIds = f.evidence ?? [];
  const when = matchWords(indicator?.when);
  const cited = citedProbes(f);
  const cvss = cvssReading(f);
  // The log is in this answer: a run with no log has no record to look an id up in, and a line of "not in the log" for each would only repeat the reason above.
  const hasLog = probeLog !== undefined || (probes?.size ?? 0) > 0;
  const truncated = probeLog?.truncated === true;
  return (
    <div id={detailId} data-testid="assess-finding-detail" data-finding-id={f.id} className="space-y-3 py-1 text-[12px] text-fg-2">
      <FindingEvidence finding={f} evidence={evidence} />
      <AssessFixButton itemId={f.id} itemKind="finding" refs={f.where?.refs} />
      <RetestHistory finding={f.id} />
      {(indicator?.control || indicator?.attack || probeIds.length > 0 || when) && (
        <div className="space-y-1">
          <SubHeading agent>Indicator</SubHeading>
          <p className="m-0 break-words text-[11.5px] text-fg-2">
            {indicator?.attack ? `Attack probe ${indicator.attack}` : "No attack probe named"}
            {indicator?.control ? `, control probe ${indicator.control}` : ""}
            {probeIds.length > 0 ? `. Probes cited: ${probeIds.join(", ")}` : ""}
            {"."}
          </p>
          {when && (
            <p className="m-0 break-words text-[11.5px] text-fg-2" data-testid="assess-finding-condition">
              {`The agent says the attack response meets this condition and the control response does not: ${when}.`}
            </p>
          )}
        </div>
      )}
      {cited.length > 0 && hasLog && (
        <div className="space-y-1.5" data-testid="assess-finding-probes">
          <SubHeading>Requests in the helper log</SubHeading>
          <p className="m-0 text-[11.5px] text-fg-3">
            What the helper wrote down about each request this finding names. {EVIDENCE_AGENT_WRITABLE}
          </p>
          <div className="grid gap-2 lg:grid-cols-2">
            {cited.map((c) => {
              const rec = probes?.get(c.id);
              return rec ? <ProbeCard key={c.id} p={rec} role={c.role} vocab={vocab} /> : <ProbeMissing key={c.id} id={c.id} role={c.role} truncated={truncated} />;
            })}
          </div>
          {truncated && <p className="m-0 text-[11.5px] text-fg-3">{probeLogNote(probeLog)}</p>}
        </div>
      )}
      <div className="space-y-1">
        <SubHeading agent>Reproduction</SubHeading>
        {steps.length === 0 ? (
          <p className="m-0 text-[11.5px] text-fg-3">The agent gave no reproduction steps.</p>
        ) : (
          <ol className="m-0 list-decimal space-y-1.5 pl-5">
            {steps.map((st, i) => {
              const line = requestLine(st.request);
              const headers = requestHeaderLines(st.request);
              const body = requestBody(st.request);
              return (
                <li key={i} className="min-w-0 break-words text-fg-1">
                  <span>{st.step}</span>
                  {line && (
                    <div>
                      <code className="break-all font-mono text-[11px] text-fg-2">{line}</code>
                    </div>
                  )}
                  {headers.length > 0 && <CodeLines label={`Headers of step ${i + 1}`} className="mt-0.5">{headers.join("\n")}</CodeLines>}
                  {body && <CodeLines label={`Body of step ${i + 1}`} className="mt-0.5">{body}</CodeLines>}
                </li>
              );
            })}
          </ol>
        )}
      </div>
      <div className="space-y-1">
        <SubHeading agent>Impact</SubHeading>
        {f.impact ? <AgentText>{f.impact}</AgentText> : <p className="m-0 text-[11.5px] text-fg-3">The agent stated no impact.</p>}
      </div>
      <div className="space-y-1">
        <SubHeading agent>Fix</SubHeading>
        {f.fix ? <AgentText>{f.fix}</AgentText> : <p className="m-0 text-[11.5px] text-fg-3">The agent suggested no fix.</p>}
      </div>
      {cvss && (
        <div className="space-y-1" data-testid="assess-finding-cvss">
          <SubHeading>CVSS 4.0 base vector</SubHeading>
          <code className="block break-all font-mono text-[11px] text-fg-2">{cvss.vector}</code>
          <p className="m-0 text-[11.5px] text-fg-2">{`${cvss.text} ${CVSS_NOTE}`}</p>
          <p className="m-0 text-[11.5px] text-fg-3" data-testid="assess-finding-cvss-apart">
            {CVSS_APART}
          </p>
        </div>
      )}
      {!cvss && cvssLeftOut && (
        <div className="space-y-1" data-testid="assess-finding-cvss-left-out">
          <SubHeading>CVSS 4.0 base vector</SubHeading>
          <p className="m-0 text-[11.5px] text-fg-2">{CVSS_LEFT_OUT_NOTE}</p>
        </div>
      )}
      <p className="m-0 text-[11.5px] text-fg-3">{`Rating, as the agent judged it: likelihood ${f.rating?.likelihood ?? "?"} x impact ${f.rating?.impact ?? "?"}.`}</p>
    </div>
  );
}

/** OpenKeyContext is the row key of the open finding; the id cell reads it so opening a row does not rebuild the column definitions. */
const OpenKeyContext = createContext<string | null>(null);

function IdCell({ f, rowKey, detailId, onToggle }: { f: PTFinding; rowKey: string; detailId: string; onToggle: (key: string) => void }) {
  const open = useContext(OpenKeyContext) === rowKey;
  return (
    <div data-testid="assess-finding" data-finding-id={f.id}>
      <button
        type="button"
        aria-expanded={open}
        aria-controls={open ? detailId : undefined}
        aria-label={`Details of ${f.id}`}
        onClick={() => onToggle(rowKey)}
        className="inline-flex items-center gap-1 rounded-1 font-mono text-[11px] text-fg-1 hover:text-accent focus:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent-ring)]"
      >
        <Icon icon={open ? ChevronDown : ChevronRight} size="xs" className="shrink-0 text-fg-4" />
        {f.id}
      </button>
    </div>
  );
}

/** CitedPlaces is the "where in the code" cell of a row: the best word among the finding's references and how many stand behind it, or that none is cited. */
function CitedPlaces({ f }: { f: PTFinding }) {
  const m = mitigationSummary(f.where?.refs);
  if (m.total === 0) return <span className="text-fg-3">none cited</span>;
  const w = MIT_STATE_WORDS[m.state];
  return (
    <div className="space-y-0.5">
      <Pill variant={w.tone} case="none">
        {w.label}
      </Pill>
      <div className="text-[11px] text-fg-3">{`(${mitRefsWords(m)})`}</div>
    </div>
  );
}

function rowKeys(findings: PTFinding[]): Map<PTFinding, string> {
  const seen = new Map<string, number>();
  const m = new Map<PTFinding, string>();
  for (const f of findings) {
    const n = (seen.get(f.id) ?? 0) + 1;
    seen.set(f.id, n);
    m.set(f, n === 1 ? f.id : `${f.id}#${n}`);
  }
  return m;
}

const NO_FILTER: FindingFilter = {};

function hasFilter(f: FindingFilter): boolean {
  return Object.values(f).some((v) => v !== undefined && v !== "");
}

/** FindingList is every finding of a pen test: filters, a search, a sort (the band, highest first, then the agent's order) and the findings in batches. None is capped or left out. */
export function FindingList({
  findings,
  vocab,
  counts,
  probes,
  probeLog,
  evidence,
  issues,
  initialExpanded,
  initialFilter,
  initialSort,
  batchSize = FINDING_BATCH,
}: {
  findings: PTFinding[] | undefined;
  vocab?: ModelVocab;
  /** The helper's log records the findings cite (the answer's `probes`), looked up by id when a finding opens. */
  probes?: ProbeRecord[];
  /** How much of the log the answer holds (the answer's `probe_log`). */
  probeLog?: ProbeLogInfo;
  /** The run's evidence report: the line above the list, and the reason a finding with none of its own reads as it does. */
  evidence?: EvidenceReport;
  /** The report's issues: a finding whose CVSS vector was left out says so on its own row. */
  issues?: readonly ModelIssue[];
  /** What the check did with the findings the agent wrote (the report's count): an empty list says what became of them. */
  counts?: { read: number; refused: number; leftOut: number; kept: number };
  /** The row key of the finding to open at first (its id). For a deep link and for tests. */
  initialExpanded?: string;
  /** The filters set at first (a deep link, and tests). */
  initialFilter?: FindingFilter;
  /** The sort at first; the band, highest first, when not given. */
  initialSort?: FindingSort;
  /** Rows rendered at first and added by each Show more. */
  batchSize?: number;
}) {
  const list = useMemo(() => findings ?? [], [findings]);
  const [filter, setFilter] = useState<FindingFilter>(initialFilter ?? NO_FILTER);
  const [sort, setSort] = useState<FindingSort>(initialSort ?? DEFAULT_FINDING_SORT);
  const [openKey, setOpenKey] = useState<string | null>(initialExpanded ?? null);
  const keys = useMemo(() => rowKeys(list), [list]);
  const prefix = useId().replace(/[^A-Za-z0-9_-]/g, "");
  const detailId = `${prefix}-detail`;
  const facets = useMemo(() => findingFacets(list, vocab), [list, vocab]);
  const probeById = useMemo(() => probeIndex(probes), [probes]);
  const summary = evidenceSummaryLine(evidence);
  const reasons = useMemo(() => evidenceReasonLines(evidence), [evidence]);
  const leftOut = useMemo(() => cvssLeftOutIds(issues), [issues]);
  // When every finding states the same status, the Status column is one repeated word: it is said once below the count instead, and the column is left out (UX-15).
  const statusNote = useMemo(() => findingStatusNote(list), [list]);
  const shown = useMemo(() => sortFindings(filterFindings(list, filter, vocab), sort, vocab), [list, filter, sort, vocab]);

  const toggle = useCallback((key: string) => setOpenKey((cur) => toggleOpenKey(cur, key)), []);
  const sortFocus = useSortFocus(`${sort.key}:${sort.dir}`);
  const { pressed } = sortFocus;
  const onSort = useCallback(
    (k: FindingSortKey) => {
      pressed(k);
      setSort((cur) => nextFindingSort(cur, k));
    },
    [pressed],
  );

  const columns = useMemo<ColumnDef<PTFinding>[]>(() => {
    const head = (key: FindingSortKey, label: string) => () => <SortButton label={label} name={key} dir={sort.key === key ? sort.dir : undefined} onSort={() => onSort(key)} />;
    const status: ColumnDef<PTFinding> = {
      id: "status",
      enableSorting: false,
      header: head("status", "Status"),
      meta: { width: FINDING_COLUMN_WIDTHS.status },
      cell: ({ row }) => <span className="text-fg-2">{statusWords(row.original.status)}</span>,
    };
    return [
      {
        id: "id",
        enableSorting: false,
        header: head("id", "Id"),
        meta: { width: FINDING_COLUMN_WIDTHS.id },
        cell: ({ row }) => <IdCell f={row.original} rowKey={keys.get(row.original) ?? row.original.id} detailId={detailId} onToggle={toggle} />,
      },
      {
        id: "title",
        enableSorting: false,
        header: head("title", "Finding"),
        meta: { width: FINDING_COLUMN_WIDTHS.title },
        cell: ({ row }) => (
          <>
            <div className="break-words font-medium text-fg-1">{row.original.title}</div>
            {row.original.route && (
              <div className="mt-0.5 text-[11px] text-fg-3">
                {"Route: "}
                <code className="break-all font-mono text-[11px] text-fg-2">{row.original.route}</code>
              </div>
            )}
            <RetestLine finding={row.original.id} />
          </>
        ),
      },
      {
        id: "band",
        enableSorting: false,
        header: head("band", "Band"),
        meta: { width: FINDING_COLUMN_WIDTHS.band },
        cell: ({ row }) => (
          <Pill variant={bandTone(row.original.band)} case="none">
            {bandText(row.original)}
          </Pill>
        ),
      },
      {
        id: "category",
        enableSorting: false,
        header: head("category", "Category"),
        meta: { width: FINDING_COLUMN_WIDTHS.category },
        cell: ({ row }) => (
          <>
            <div className="break-words text-fg-2" title="The test category, from the OWASP Web Security Testing Guide, as the agent filed it">
              {wstgTitle(row.original.category, vocab)}
            </div>
            {(row.original.cwe ?? []).length > 0 && <div className="mt-0.5 break-words text-[11px] text-fg-3">{(row.original.cwe ?? []).join(", ")}</div>}
          </>
        ),
      },
      {
        id: "basis",
        enableSorting: false,
        header: "The agent's basis",
        meta: { width: FINDING_COLUMN_WIDTHS.basis },
        cell: ({ row }) => <span className="text-fg-2">{basisWords(row.original.basis)}</span>,
      },
      {
        id: "evidence",
        enableSorting: false,
        header: () => (
          <span className="inline-flex items-center">
            {"Observer's evidence"}
            <HelpInd id="card.code_security_assess_evidence" />
          </span>
        ),
        meta: { width: FINDING_COLUMN_WIDTHS.evidence },
        cell: ({ row }) => {
          const ev = evidenceWords(row.original, evidence);
          return (
            <div className="space-y-0.5">
              <Pill variant={ev.tone} case="none">
                {ev.label}
              </Pill>
              {ev.state === "logged" && <div className="text-[11px] text-fg-3">{EVIDENCE_AGENT_WRITABLE}</div>}
            </div>
          );
        },
      },
      ...(statusNote === "" ? [status] : []),
      { id: "places", enableSorting: false, header: "Cited places", meta: { width: FINDING_COLUMN_WIDTHS.places }, cell: ({ row }) => <CitedPlaces f={row.original} /> },
    ];
  }, [sort, onSort, keys, detailId, toggle, vocab, evidence, statusNote]);
  // The table's least width is the sum of its columns' widths, so it cannot drift from them (it was typed by hand, and was 30 px wider than the dialog's room at 1280).
  const tableWidth = useMemo(() => columns.reduce((n, c) => n + (c.meta?.width ?? 0), 0), [columns]);

  const set = (patch: Partial<FindingFilter>) => setFilter((cur) => ({ ...cur, ...patch }));
  const total = list.length;
  const gone = unlistedWords("findings", counts ?? { read: total, refused: 0, leftOut: 0, kept: total });

  if (total === 0) {
    return (
      <div data-testid="assess-findings">
        {gone ? (
          <EmptyState variant="inline" title="No finding is shown" body={gone} />
        ) : (
          <EmptyState
            variant="inline"
            title="The agent reported no findings"
            body="That says what the agent wrote. It does not say the target has no weakness: read the coverage matrix to see what was tested."
          />
        )}
      </div>
    );
  }

  return (
    <div className="min-w-0 space-y-3" data-testid="assess-findings">
      <div className="grid grid-cols-2 gap-2 sm:flex sm:flex-wrap sm:items-end">
        <Select
          label="Band"
          aria-label="Filter findings by band"
          className="w-full sm:w-32"
          value={filter.band ?? ""}
          onChange={(e) => set({ band: (e.target.value || undefined) as ModelBand | undefined })}
          options={[{ value: "", label: "All" }, ...facets.bands.map((b) => ({ value: b.value, label: `${b.value} (${b.n})` }))]}
        />
        <Select
          label="Category"
          aria-label="Filter findings by category"
          className="w-full sm:w-56"
          value={filter.category ?? ""}
          onChange={(e) => set({ category: e.target.value || undefined })}
          options={[{ value: "", label: "All" }, ...facets.categories.map((c) => ({ value: c.value, label: `${c.label} (${c.n})` }))]}
        />
        <Select
          label="Basis"
          aria-label="Filter findings by basis"
          className="w-full sm:w-48"
          value={filter.basis ?? ""}
          onChange={(e) => set({ basis: e.target.value || undefined })}
          options={[{ value: "", label: "All" }, ...facets.bases.map((b) => ({ value: b.value, label: `${basisWords(b.value).replace(/^The agent says: /, "")} (${b.n})` }))]}
        />
        <Select
          label="Evidence"
          aria-label="Filter findings by evidence"
          className="w-full sm:w-44"
          value={filter.evidence ?? ""}
          onChange={(e) => set({ evidence: (e.target.value || undefined) as FindingFilter["evidence"] })}
          options={[{ value: "", label: "All" }, ...facets.evidence.map((v) => ({ value: v.value, label: `${v.label} (${v.n})` }))]}
        />
        <div className="col-span-2 sm:col-span-1">
          <Input
            label="Search"
            aria-label="Search findings"
            type="search"
            className="w-full sm:w-56"
            placeholder="Id, title, route, text"
            value={filter.q ?? ""}
            onChange={(e) => set({ q: e.target.value || undefined })}
          />
        </div>
        {hasFilter(filter) && (
          <div className="col-span-2 sm:col-span-1">
            <Button size="sm" variant="ghost" onClick={() => setFilter(NO_FILTER)}>
              Clear filters
            </Button>
          </div>
        )}
      </div>

      <div className="space-y-1">
        <p className="m-0 text-[12px] text-fg-2" data-testid="assess-findings-count" aria-live="polite">
          {`Showing ${shown.length} of ${total} ${plural(total, "finding", "findings")}`}
        </p>
        {statusNote && (
          <p className="m-0 text-[11.5px] text-fg-3" data-testid="assess-findings-status-note">
            {statusNote}
          </p>
        )}
        {summary && (
          <p className="m-0 text-[12px] text-fg-1" data-testid="assess-evidence-summary">
            {summary}
          </p>
        )}
        {summary && reasons.length > 0 && (
          <details className="text-fg-2" data-testid="assess-evidence-reasons">
            <summary className="cursor-pointer text-[11.5px] font-medium text-fg-3 hover:text-fg-1">Why findings are not logged</summary>
            <ul className="m-0 mt-1 list-none space-y-0.5 border-l-2 border-line-2 p-0 pl-3 text-[11.5px]">
              {reasons.map((r) => (
                <li key={r.code}>{`${r.n} ${plural(r.n, "finding", "findings")}: ${r.text}`}</li>
              ))}
            </ul>
          </details>
        )}
        <p className="m-0 text-[11.5px] text-fg-3" data-testid="assess-findings-legend">
          {findingsLegend(list)}
        </p>
        {gone && (
          <p className="m-0 text-[11.5px] text-fg-1" data-testid="assess-findings-unlisted">
            {gone}
          </p>
        )}
      </div>

      {shown.length === 0 ? (
        <EmptyState variant="inline" title="No finding matches these filters" body="Clear the filters to see all the findings again." />
      ) : (
        <OpenKeyContext.Provider value={openKey}>
          <div ref={sortFocus.ref} className="rounded-3 border border-line-2 bg-bg-2">
            <DataTable<PTFinding>
              // A new filter or sort starts again from the first batch.
              key={`${sort.key}:${sort.dir}:${JSON.stringify(filter)}`}
              data={shown}
              columns={columns}
              rowKey={(f) => keys.get(f) ?? f.id}
              layout="fixed"
              minWidth={tableWidth}
              incrementalRows={batchSize}
              expandedKey={openKey}
              renderExpanded={(f) => (
                <ExpandedFit>
                  <FindingBody f={f} detailId={detailId} probes={probeById} probeLog={probeLog} evidence={evidence} vocab={vocab} cvssLeftOut={leftOut.has(f.id)} />
                </ExpandedFit>
              )}
            />
          </div>
        </OpenKeyContext.Provider>
      )}
    </div>
  );
}
