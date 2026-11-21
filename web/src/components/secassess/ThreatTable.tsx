import { createContext, useCallback, useContext, useId, useMemo, useState } from "react";
import type { ColumnDef } from "@tanstack/react-table";
import { ChevronDown, ChevronRight } from "lucide-react";
import { Button, DataTable, EmptyState, Icon, Input, Pill, Select } from "@/components/primitives";
import {
  DEFAULT_THREAT_SORT,
  MIT_STATE_WORDS,
  bandTone,
  categoryName,
  effortWords,
  filterThreats,
  frameworkLabel,
  frameworkTitle,
  missingLocated,
  mitRefsWords,
  nextThreatSort,
  plural,
  sortThreats,
  statusWords,
  threatFacets,
  threatMitSummary,
  toggleOpenKey,
  unlistedWords,
  type MitState,
  type ModelBand,
  type ModelThreat,
  type ModelVocab,
  type ThreatFilter,
  type ThreatModelDoc,
  type ThreatSort,
  type ThreatSortKey,
} from "@/lib/secAssessModel";
import { AssessFixButton } from "./AssessFixButton";
import { RefList } from "./RefList";
import { AgentText, ExpandedFit, SortButton, SubHeading, useSortFocus } from "./modelParts";

// ThreatTable lists every threat of a threat model. Nothing is capped or
// hidden: the filters narrow the list, the count line says how many of the
// whole match, and Clear filters brings the rest back. The list is the shared
// DataTable rendering in batches (every row is reached by scrolling or by Show
// more), so 1,500 threats do not put 1,500 rows in the page at once; sorting
// and filtering run over all of them before the first batch is cut. The band
// is Observer's computation from the agent's two ratings; the status, the
// description and the mitigations are the agent's claims; the words about each
// cited place are Observer's finding. One row is open at a time, under its row.

/** The rows a first render and each Show more adds. */
export const THREAT_BATCH = 75;

/** A band's text for the pill: the band and the score Observer computed. */
function bandText(t: ModelThreat): string {
  if (!t.band) return "no band";
  return typeof t.score === "number" ? `${t.band} ${t.score}` : t.band;
}

/** OpenKeyContext is the row key of the open threat; a cell reads it so opening a row does not rebuild the column definitions every body row is compared against. */
const OpenKeyContext = createContext<string | null>(null);

/** MitigationWords is a threat's mitigation word with how many of its references it stands on. */
function MitigationWords({ t }: { t: ModelThreat }) {
  const m = threatMitSummary(t);
  const w = MIT_STATE_WORDS[m.state];
  const refs = mitRefsWords(m);
  return (
    <div className="space-y-0.5">
      <Pill variant={w.tone} case="none">
        {w.label}
      </Pill>
      {refs && <div className="text-[11px] text-fg-3">{`(${refs})`}</div>}
    </div>
  );
}

export function ThreatDetail({ t, actors, vocab, detailId }: { t: ModelThreat; actors: ReadonlyMap<string, string>; vocab: ModelVocab; detailId: string }) {
  const mit = threatMitSummary(t);
  const words = MIT_STATE_WORDS[mit.state];
  const refs = mitRefsWords(mit);
  const located = missingLocated(t);
  const existing = t.existing ?? [];
  const missing = t.missing ?? [];
  const standards = [...(t.cwe ?? []), ...(t.capec ?? []), ...(t.asvs ?? [])];
  const actorName = (id: string | undefined) => (id ? (actors.get(id) ?? id) : "");
  return (
    <div id={detailId} data-testid="assess-threat-detail" data-threat-id={t.id} className="space-y-3 py-1 text-[12px] text-fg-2">
      <div className="space-y-1">
        <SubHeading agent>Description</SubHeading>
        {t.description ? <AgentText>{t.description}</AgentText> : <p className="m-0 text-[11.5px] text-fg-3">The agent gave no description.</p>}
        {t.actor && <p className="m-0 text-[11.5px] text-fg-3">{`Actor: ${actorName(t.actor)}`}</p>}
      </div>

      <div className="space-y-1">
        <SubHeading>Rating</SubHeading>
        <p className="m-0 flex flex-wrap items-center gap-x-2 gap-y-1 text-[12px] text-fg-1">
          <span>{`Likelihood ${t.rating?.likelihood ?? "?"} x impact ${t.rating?.impact ?? "?"}`}</span>
          <span className="text-[11.5px] text-fg-3">the agent's judgement</span>
        </p>
        {t.band && (
          <p className="m-0 flex flex-wrap items-center gap-2 text-[11.5px] text-fg-3">
            <span>Observer reads the two ratings as</span>
            <Pill variant={bandTone(t.band)} case="none">
              {bandText(t)}
            </Pill>
          </p>
        )}
      </div>

      <div className="space-y-1.5">
        <SubHeading agent>Existing mitigations</SubHeading>
        {existing.length === 0 ? (
          <p className="m-0 text-[11.5px] text-fg-3">The agent lists no existing mitigation.</p>
        ) : (
          <>
            <p className="m-0 flex flex-wrap items-center gap-2 text-[11.5px] text-fg-3">
              <Pill variant={words.tone} case="none">
                {words.label}
              </Pill>
              {refs && <span>{`(${refs})`}</span>}
              <span className="min-w-0">{words.detail}</span>
            </p>
            <ul className="m-0 list-none space-y-2 p-0">
              {existing.map((m, i) => (
                <li key={i} className="space-y-1 border-l-2 border-line-2 pl-3">
                  <AgentText>{m.text}</AgentText>
                  <RefList refs={m.refs} />
                </li>
              ))}
            </ul>
          </>
        )}
      </div>

      <div className="space-y-1.5">
        <SubHeading agent>Missing mitigations</SubHeading>
        {missing.length === 0 ? (
          <p className="m-0 text-[11.5px] text-fg-3">The agent lists no missing mitigation.</p>
        ) : (
          <>
            <p className="m-0 text-[11.5px] text-fg-3">{`A place in the code that exists is cited by ${located.located} of ${located.total} missing ${plural(located.total, "mitigation", "mitigations")}.`}</p>
            <ul className="m-0 list-none space-y-2 p-0">
              {missing.map((m, i) => (
                <li key={i} className="space-y-1 border-l-2 border-line-2 pl-3">
                  <AgentText>{m.text}</AgentText>
                  {(m.control || m.effort) && (
                    <div className="flex flex-wrap items-center gap-1.5">
                      {m.control && (
                        <Pill variant="neutral" case="none">
                          {`control: ${m.control}`}
                        </Pill>
                      )}
                      {m.effort && (
                        <Pill variant="neutral" case="none">
                          {`effort: ${effortWords(m.effort)}`}
                        </Pill>
                      )}
                    </div>
                  )}
                  <RefList refs={m.refs} />
                </li>
              ))}
            </ul>
          </>
        )}
      </div>

      <AssessFixButton itemId={t.id} itemKind="threat" refs={missing.flatMap((m) => m.refs ?? [])} />

      {standards.length > 0 && (
        <div className="space-y-1">
          <SubHeading agent>Standards cited</SubHeading>
          <div className="flex flex-wrap gap-1.5">
            {standards.map((s, i) => (
              <Pill key={i} variant="neutral" case="none">
                {s}
              </Pill>
            ))}
          </div>
        </div>
      )}

      {t.abuse_case && (
        <div className="space-y-1">
          <SubHeading agent>Abuse case</SubHeading>
          <AgentText>{`${t.abuse_case.actor ? `${actorName(t.abuse_case.actor)}: ` : ""}${t.abuse_case.goal}`}</AgentText>
          {(t.abuse_case.steps ?? []).length > 0 && (
            <ol className="m-0 list-decimal space-y-0.5 pl-5 text-[12px] text-fg-1">
              {(t.abuse_case.steps ?? []).map((s, i) => (
                <li key={i} className="min-w-0 break-words">
                  {s}
                </li>
              ))}
            </ol>
          )}
        </div>
      )}
      <p className="m-0 text-[11px] text-fg-3">{`${frameworkTitle(t.framework, vocab)}, ${categoryName(t.framework, t.category, vocab)}`}</p>
    </div>
  );
}

/** IdCell is a row's first cell: the expander button, named for the threat, and the hooks the tests and the browser spec find the row by. */
function IdCell({ t, rowKey, detailId, onToggle }: { t: ModelThreat; rowKey: string; detailId: string; onToggle: (key: string) => void }) {
  const open = useContext(OpenKeyContext) === rowKey;
  return (
    <div data-testid="assess-threat" data-threat-id={t.id}>
      <button
        type="button"
        aria-expanded={open}
        aria-controls={open ? detailId : undefined}
        aria-label={`Details of ${t.id}`}
        onClick={() => onToggle(rowKey)}
        className="inline-flex items-center gap-1 rounded-1 font-mono text-[11px] text-fg-1 hover:text-accent focus:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent-ring)]"
      >
        <Icon icon={open ? ChevronDown : ChevronRight} size="xs" className="shrink-0 text-fg-4" />
        {t.id}
      </button>
    </div>
  );
}

const NO_FILTER: ThreatFilter = {};

/** rowKeys gives each threat one row key: its id, with a counter for an id the model repeats. */
function rowKeys(threats: ModelThreat[]): Map<ModelThreat, string> {
  const seen = new Map<string, number>();
  const m = new Map<ModelThreat, string>();
  for (const t of threats) {
    const n = (seen.get(t.id) ?? 0) + 1;
    seen.set(t.id, n);
    m.set(t, n === 1 ? t.id : `${t.id}#${n}`);
  }
  return m;
}

function hasFilter(f: ThreatFilter): boolean {
  return Object.values(f).some((v) => v !== undefined && v !== "");
}

export function ThreatTable({
  doc,
  vocab,
  counts,
  initialExpanded,
  initialFilter,
  initialSort,
  batchSize = THREAT_BATCH,
}: {
  doc: ThreatModelDoc;
  vocab: ModelVocab;
  /** What the check did with the threats the agent wrote (the report's count): an empty list says what became of them. */
  counts?: { read: number; refused: number; leftOut: number; kept: number };
  /** The filters set at first (a deep link, and tests). */
  initialFilter?: ThreatFilter;
  /** The sort at first; the band, highest first, when not given. */
  initialSort?: ThreatSort;
  /** The row key of the threat to open at first (its id). Opening a row is always the reader's choice; this is for a deep link and for tests. */
  initialExpanded?: string;
  /** Rows rendered at first and added by each Show more. */
  batchSize?: number;
}) {
  const threats = useMemo(() => doc?.threats ?? [], [doc]);
  const [filter, setFilter] = useState<ThreatFilter>(initialFilter ?? NO_FILTER);
  const [sort, setSort] = useState<ThreatSort>(initialSort ?? DEFAULT_THREAT_SORT);
  const keys = useMemo(() => rowKeys(threats), [threats]);
  const [openKey, setOpenKey] = useState<string | null>(initialExpanded ?? null);
  const prefix = useId().replace(/[^A-Za-z0-9_-]/g, "");
  const detailId = `${prefix}-detail`;

  const facets = useMemo(() => threatFacets(doc), [doc]);
  const elementLabels = useMemo(() => new Map(facets.elements.map((e) => [e.value, e.label])), [facets]);
  const actors = useMemo(() => new Map((doc?.system?.actors ?? []).map((a) => [a.id, a.name] as const)), [doc]);

  // Filtering and sorting run over every threat; the table cuts the first batch from the result.
  const shown = useMemo(() => sortThreats(doc, filterThreats(doc, threats, filter), sort), [doc, threats, filter, sort]);

  const toggle = useCallback((key: string) => setOpenKey((cur) => toggleOpenKey(cur, key)), []);
  const sortFocus = useSortFocus(`${sort.key}:${sort.dir}`);
  const { pressed } = sortFocus;
  const onSort = useCallback(
    (k: ThreatSortKey) => {
      pressed(k);
      setSort((cur) => nextThreatSort(cur, k));
    },
    [pressed],
  );

  const columns = useMemo<ColumnDef<ModelThreat>[]>(() => {
    const head = (key: ThreatSortKey, label: string) => () => <SortButton label={label} name={key} dir={sort.key === key ? sort.dir : undefined} onSort={() => onSort(key)} />;
    return [
      {
        id: "id",
        enableSorting: false,
        header: head("id", "Id"),
        meta: { width: 96 },
        cell: ({ row }) => <IdCell t={row.original} rowKey={keys.get(row.original) ?? row.original.id} detailId={detailId} onToggle={toggle} />,
      },
      { id: "title", enableSorting: false, header: head("title", "Threat"), meta: { width: 280 }, cell: ({ row }) => <span className="break-words text-fg-1">{row.original.title}</span> },
      {
        id: "band",
        enableSorting: false,
        header: head("band", "Band"),
        meta: { width: 112 },
        cell: ({ row }) => (
          <Pill variant={bandTone(row.original.band)} case="none">
            {bandText(row.original)}
          </Pill>
        ),
      },
      {
        id: "category",
        enableSorting: false,
        header: "Category",
        meta: { width: 150 },
        cell: ({ row }) => (
          <>
            <div className="break-words text-fg-2">{categoryName(row.original.framework, row.original.category, vocab)}</div>
            <div className="text-[10.5px] text-fg-3">{frameworkLabel(row.original.framework)}</div>
          </>
        ),
      },
      {
        id: "element",
        enableSorting: false,
        header: head("element", "Element"),
        meta: { width: 160 },
        cell: ({ row }) => {
          const t = row.original;
          return <span className="break-words text-fg-2">{elementLabels.get(`${t.element?.kind ?? ""}:${t.element?.id ?? ""}`) ?? t.element?.id ?? ""}</span>;
        },
      },
      { id: "status", enableSorting: false, header: head("status", "Status"), meta: { width: 120 }, cell: ({ row }) => <span className="text-fg-2">{statusWords(row.original.status)}</span> },
      { id: "mitigation", enableSorting: false, header: "Existing mitigations", meta: { width: 190 }, cell: ({ row }) => <MitigationWords t={row.original} /> },
      {
        id: "located",
        enableSorting: false,
        header: "Fixes located",
        meta: { width: 100 },
        cell: ({ row }) => {
          const located = missingLocated(row.original);
          return located.total === 0 ? (
            <span className="text-fg-3">none listed</span>
          ) : (
            // relative: an absolutely positioned screen-reader span is placed against its nearest positioned ancestor, and without one it sits outside the table's own scroller and stretches the dialog's body sideways.
            <span className="relative tabular-nums text-fg-2">
              <span className="sr-only">Missing mitigations that name a place in the code that exists: </span>
              {`${located.located} of ${located.total}`}
            </span>
          );
        },
      },
    ];
  }, [sort, onSort, keys, detailId, toggle, vocab, elementLabels]);

  const set = (patch: Partial<ThreatFilter>) => setFilter((cur) => ({ ...cur, ...patch }));
  const total = threats.length;
  const gone = counts ? unlistedWords("threats", counts) : "";

  if (total === 0) {
    return (
      <div data-testid="assess-threats">
        {gone ? (
          <EmptyState variant="inline" title="No threat is shown" body={gone} />
        ) : (
          <EmptyState variant="inline" title="The model lists no threats" body="The agent recorded no threat. That is not a finding that none exists; the coverage line and the matrix say what the agent looked at." />
        )}
      </div>
    );
  }

  return (
    <div className="min-w-0 space-y-3" data-testid="assess-threats">
      <div className="grid grid-cols-2 gap-2 sm:flex sm:flex-wrap sm:items-end">
        <Select
          label="Framework"
          aria-label="Filter by framework"
          className="w-full sm:w-40"
          value={filter.framework ?? ""}
          onChange={(e) => set({ framework: e.target.value || undefined })}
          options={[{ value: "", label: "All" }, ...facets.frameworks.map((f) => ({ value: f.value, label: `${frameworkLabel(f.value)} (${f.n})` }))]}
        />
        <Select
          label="Element"
          aria-label="Filter by element"
          className="w-full sm:w-48"
          value={filter.element ?? ""}
          onChange={(e) => set({ element: e.target.value || undefined })}
          options={[{ value: "", label: "All" }, ...facets.elements.map((el) => ({ value: el.value, label: `${el.label} (${el.n})` }))]}
        />
        <Select
          label="Status"
          aria-label="Filter by status"
          className="w-full sm:w-44"
          value={filter.status ?? ""}
          onChange={(e) => set({ status: e.target.value || undefined })}
          options={[{ value: "", label: "All" }, ...facets.statuses.map((s) => ({ value: s.value, label: `${statusWords(s.value)} (${s.n})` }))]}
        />
        <Select
          label="Band"
          aria-label="Filter by band"
          className="w-full sm:w-32"
          value={filter.band ?? ""}
          onChange={(e) => set({ band: (e.target.value || undefined) as ModelBand | undefined })}
          options={[{ value: "", label: "All" }, ...facets.bands.map((b) => ({ value: b.value, label: `${b.value} (${b.n})` }))]}
        />
        <Select
          label="Best reference state"
          aria-label="Filter by mitigation state"
          className="w-full sm:w-56"
          value={filter.mitigation ?? ""}
          onChange={(e) => set({ mitigation: (e.target.value || undefined) as MitState | undefined })}
          options={[{ value: "", label: "All" }, ...facets.mitigations.map((m) => ({ value: m.value, label: `${MIT_STATE_WORDS[m.value].label} (${m.n})` }))]}
        />
        <div className="col-span-2 sm:col-span-1">
          <Input
            label="Search"
            aria-label="Search threats"
            type="search"
            className="w-full sm:w-56"
            placeholder="Id, title, element, text"
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
        <p className="m-0 text-[12px] text-fg-2" data-testid="assess-threats-count" aria-live="polite">
          {`Showing ${shown.length} of ${total} ${plural(total, "threat", "threats")}`}
        </p>
        <p className="m-0 text-[11.5px] text-fg-3">The status, the text and the mitigations are what the agent wrote. The band and the words about each cited place are Observer's.</p>
        <p className="m-0 text-[11.5px] text-fg-3">{"A threat's mitigation word is the best state among its references, and the filter reads the same word: Found near the cited line means at least one reference was found."}</p>
        {gone && (
          <p className="m-0 text-[11.5px] text-warn" data-testid="assess-threats-unlisted">
            {gone}
          </p>
        )}
      </div>

      {shown.length === 0 ? (
        <EmptyState variant="inline" title="No threat matches these filters" body="Clear the filters to see all the threats again." />
      ) : (
        <OpenKeyContext.Provider value={openKey}>
          <div ref={sortFocus.ref} className="rounded-3 border border-line-2 bg-bg-2">
            <DataTable<ModelThreat>
              // A new filter or sort starts again from the first batch.
              key={`${sort.key}:${sort.dir}:${JSON.stringify(filter)}`}
              data={shown}
              columns={columns}
              rowKey={(t) => keys.get(t) ?? t.id}
              layout="fixed"
              minWidth={1100}
              incrementalRows={batchSize}
              expandedKey={openKey}
              renderExpanded={(t) => (
                <ExpandedFit>
                  <ThreatDetail t={t} actors={actors} vocab={vocab} detailId={detailId} />
                </ExpandedFit>
              )}
            />
          </div>
        </OpenKeyContext.Provider>
      )}
    </div>
  );
}
