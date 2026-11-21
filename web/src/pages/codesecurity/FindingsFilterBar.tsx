import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import clsx from "clsx";
import {
  ActiveFilterChips,
  Button,
  ComboChip,
  EntityMultiPicker,
  Input,
  SegmentedControl,
  type ComboOption,
  type EntityMultiPickerOption,
  type FilterChip,
} from "@/components/primitives";
import type { ApiState } from "@/lib/useApi";
import {
  activeFindingsFilters,
  clearFindingsFilters,
  projectFilterLabel,
  setFindingsFilter,
  severityRank,
  sortProjects,
  toggleFindingsFilter,
  visibleFacetOptions,
  type ActiveFindingsFilter,
  type FacetOption,
  type FindingsListFilter,
  type SecurityProject,
} from "@/lib/codeSecurity";
import type { FindingsFacets, FindingsFilters, FindingsGroupBy } from "@/lib/codeSecurityApi";
import {
  countWords,
  FACET_TITLE,
  facetValueLabel,
  FINDING_STATUS_OPTIONS,
  GROUP_BY_OPTIONS,
  shortenChipValue,
  statusLabel,
} from "@/lib/findingsLabels";

// FindingsFilterBar is the Findings tab's filters (redesign plan section
// 4.4): a search box, the grouping, the severity chips, the status, and a
// picker per facet (type, scanner, ecosystem, language, project, baseline).
// Every option shows how many findings it would show with the other filters
// applied (GET /api/security/findings/facets); an option with none is
// hidden unless it is selected. The filters in force show as removable
// chips with "Clear filters". The tab owns the filters (they live in the
// URL): every change goes through onChange, and nothing here keeps a copy
// but the search box's draft, which is written 300 ms after typing stops.
//
// Below 640 px the facet filters fold behind a "Filters (N)" button; the
// search box and the grouping stay in view.

/** How long the search box waits after the last keystroke. */
export const SEARCH_DEBOUNCE_MS = 300;

/** A change to the filters, and whether it should add a history entry
 *  (push, a discrete choice) or replace the current one (typing). */
export type FindingsFiltersChange = (change: (f: FindingsFilters) => FindingsFilters, history?: "push" | "replace") => void;

// The severities, worst first: the chips' order and the facets' vocabulary
// before the counts answer.
const SEVERITIES = ["critical", "high", "medium", "low", "info"];

// The pickers, in the bar's order. A vocabulary is listed (uncounted)
// before the facets answer, or when they failed: the common types, the
// projects with open findings from the status read, the baseline values.
// The rest wait for the counts.
const PICKERS: readonly {
  key: Exclude<FindingsListFilter, "severity">;
  placeholder: string;
  vocabulary?: (projects: readonly SecurityProject[]) => readonly string[];
}[] = [
  {
    key: "category",
    placeholder: "Any type",
    vocabulary: () => ["vulnerable_dependency", "secret", "code_vuln", "iac", "ci_config", "agent_config", "test_tampering"],
  },
  { key: "driver", placeholder: "Any scanner" },
  { key: "ecosystem", placeholder: "Any ecosystem" },
  { key: "language", placeholder: "Any language" },
  {
    key: "project",
    placeholder: "Any project",
    vocabulary: (projects) => sortProjects([...projects]).filter((p) => p.open > 0).map((p) => p.project_root_hash),
  },
  { key: "baseline", placeholder: "New or pre-existing", vocabulary: () => ["new", "pre_existing", "untrusted_baseline"] },
];

/** countSuffix is an option's count in words, "" while uncounted. */
function countSuffix(o: FacetOption): string {
  return o.count == null ? "" : countWords(o.count);
}

/** chipLabel is an active filter as its chip reads: "Type: Dependency".
 *  A long value is shortened when `short` (the chip), whole otherwise (its
 *  tooltip). */
function chipLabel(a: ActiveFindingsFilter, projectName: (hash: string) => string, short: boolean): string {
  const v = (value: string, keepEnd = false) => (short ? shortenChipValue(value, keepEnd) : value);
  switch (a.field) {
    case "status":
      return `Status: ${statusLabel(a.value)}`;
    case "rule":
      return `Rule: ${v(a.value)}`;
    case "pkg":
      return `Package: ${v(a.value)}`;
    case "path":
      return `Path: ${v(a.value, true)}`;
    case "q":
      return `Search: ${v(a.value)}`;
    default:
      return `${FACET_TITLE[a.field]}: ${v(facetValueLabel(a.field, a.value, projectName))}`;
  }
}

/** SearchBox is the free-text filter: a local draft, written after the
 *  person stops typing; a change of the filter from elsewhere (a cleared
 *  chip) resets the draft. */
function SearchBox({ value, onCommit }: { value: string; onCommit: (q: string) => void }) {
  const [draft, setDraft] = useState(value);
  // The value this box last wrote: the URL coming back with it is our own
  // write landing, not a change from elsewhere, so the draft is kept (the
  // person may have typed on since).
  const written = useRef(value);
  useEffect(() => {
    if (value === written.current) return;
    written.current = value;
    setDraft(value);
  }, [value]);
  useEffect(() => {
    const q = draft.trim();
    if (q === written.current) return;
    const t = setTimeout(() => {
      written.current = q;
      onCommit(q);
    }, SEARCH_DEBOUNCE_MS);
    return () => clearTimeout(t);
  }, [draft, onCommit]);
  return (
    <Input
      type="search"
      value={draft}
      onChange={(e) => setDraft(e.target.value)}
      placeholder="Search package, rule, message or path"
      aria-label="Search findings"
      className="w-full sm:w-80"
      data-testid="code-security-findings-search"
    />
  );
}

export function FindingsFilterBar({
  filters,
  facets,
  projects,
  projectsLoaded,
  onChange,
}: {
  filters: FindingsFilters;
  facets: ApiState<FindingsFacets>;
  projects: SecurityProject[];
  /** The status read answered, so a project it does not list is one
   *  Observer no longer tracks (not one still loading). */
  projectsLoaded: boolean;
  onChange: FindingsFiltersChange;
}) {
  const [expanded, setExpanded] = useState(false);
  const counts = facets.data?.facets ?? null;
  const projectName = useMemo(() => {
    const byHash = projectsLoaded ? new Map<string, SecurityProject>(projects.map((p) => [p.project_root_hash, p])) : null;
    return (hash: string) => projectFilterLabel(hash, byHash);
  }, [projects, projectsLoaded]);
  const active = activeFindingsFilters(filters);
  const onSearch = useCallback((q: string) => onChange((f) => ({ ...f, q }), "replace"), [onChange]);

  const severities = visibleFacetOptions(counts?.severity, filters.severity, SEVERITIES).sort(
    (a, b) => severityRank(a.value) - severityRank(b.value),
  );

  // The status: Open and Every status always listed, the rest while they
  // count something or are chosen; a status the facets report that the
  // fixed list does not name is listed after it.
  const statusCounts = new Map((counts?.status ?? []).map((s) => [s.value, s.count]));
  const statusTotal = counts ? (counts.status ?? []).reduce((n, s) => n + s.count, 0) : null;
  const statusOptions: ComboOption[] = [
    ...FINDING_STATUS_OPTIONS.map((o) => ({ value: o.value, label: o.label })),
    ...[...statusCounts.keys()]
      .filter((v) => v !== "" && !FINDING_STATUS_OPTIONS.some((o) => o.value === v))
      .map((v) => ({ value: v, label: statusLabel(v) })),
  ]
    .map((o) => {
      const n = o.value === "" ? statusTotal : counts ? (statusCounts.get(o.value) ?? 0) : null;
      return { ...o, n };
    })
    .filter((o) => o.value === "open" || o.value === "" || o.value === filters.status || o.n == null || o.n > 0)
    .map((o) => ({
      value: o.value,
      label: o.label,
      searchable: `${o.label} ${o.value}`.toLowerCase(),
      rightMeta: o.n == null ? undefined : <span className="tabular-nums text-fg-3">{countWords(o.n)}</span>,
    }));

  const chips: FilterChip[] = active.map((a) => ({
    label: chipLabel(a, projectName, true),
    title: `Remove ${chipLabel(a, projectName, false)}`,
    onClear: () => onChange(() => a.without),
  }));

  return (
    <div className="space-y-3" data-testid="code-security-findings-filters">
      <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
        <div className="min-w-0 basis-full sm:basis-auto">
          <SearchBox value={filters.q} onCommit={onSearch} />
        </div>
        <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
          <span className="text-[11.5px] text-fg-3">Group by</span>
          <SegmentedControl<FindingsGroupBy>
            size="sm"
            options={GROUP_BY_OPTIONS.map((o) => ({ value: o.value, label: o.label }))}
            value={filters.group}
            onChange={(group) => onChange((f) => ({ ...f, group }))}
          />
        </div>
        <Button
          size="sm"
          variant="secondary"
          className="sm:hidden"
          aria-expanded={expanded}
          aria-controls="code-security-findings-filter-panel"
          onClick={() => setExpanded((v) => !v)}
        >
          {active.length > 0 ? `Filters (${active.length})` : "Filters"}
        </Button>
      </div>

      <div id="code-security-findings-filter-panel" className={clsx("space-y-3 sm:block", expanded ? "block" : "hidden")}>
        <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
          <div className="flex flex-wrap items-center gap-1.5" role="group" aria-label="Severity">
            <span className="mr-1 text-[11.5px] text-fg-3">Severity</span>
            {severities.map((o) => {
              const on = filters.severity.includes(o.value);
              return (
                <button
                  key={o.value}
                  type="button"
                  aria-pressed={on}
                  data-testid={`code-security-severity-${o.value}`}
                  onClick={() => onChange((f) => toggleFindingsFilter(f, "severity", o.value))}
                  className={clsx(
                    "inline-flex h-7 items-center gap-1.5 rounded-pill border px-2.5 text-[11px] transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-accent-ring",
                    on ? "border-accent/50 bg-accent-soft text-fg-0" : "border-line-2 bg-bg-2 text-fg-2 hover:bg-bg-3 hover:text-fg-1",
                  )}
                >
                  {facetValueLabel("severity", o.value, projectName)}
                  {o.count != null && <span className="tabular-nums text-fg-3">{countSuffix(o)}</span>}
                </button>
              );
            })}
          </div>
          <ComboChip
            label="Status"
            value={filters.status}
            onChange={(status) => onChange((f) => ({ ...f, status }))}
            options={statusOptions}
            popoverWidth={280}
            placeholder="Find a status"
          />
        </div>

        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {PICKERS.map((p) => {
            const options = visibleFacetOptions(counts?.[p.key], filters[p.key], counts ? [] : (p.vocabulary?.(projects) ?? []));
            // A facet with nothing to pick and nothing picked adds nothing
            // (no dependency findings: no ecosystem picker).
            if (counts && options.length === 0) return null;
            const pickerOptions: EntityMultiPickerOption[] = options.map((o) => ({
              id: o.value,
              label: facetValueLabel(p.key, o.value, projectName),
              sublabel: o.count == null ? undefined : `${countSuffix(o)} ${o.count === 1 ? "finding" : "findings"}`,
            }));
            // Uncounted options read best in name order.
            if (!counts) pickerOptions.sort((a, b) => a.label.localeCompare(b.label));
            const headingId = `code-security-filter-${p.key}`;
            return (
              <div key={p.key} className="min-w-0" data-testid={headingId}>
                <span id={headingId} className="mb-1 block text-[11.5px] text-fg-3">
                  {FACET_TITLE[p.key]}
                </span>
                <EntityMultiPicker
                  options={pickerOptions}
                  value={filters[p.key]}
                  onChange={(next) => onChange((f) => setFindingsFilter(f, p.key, next))}
                  placeholder={p.placeholder}
                  ariaLabel={FACET_TITLE[p.key]}
                  hideIds
                  loading={facets.loading}
                  loadingHint="Counting findings"
                  notice={facets.error ? "The counts did not load, so only known values are listed." : undefined}
                  emptyHint="Nothing else to pick in this view."
                  maxVisibleChips={3}
                />
              </div>
            );
          })}
        </div>
      </div>

      {chips.length > 0 && (
        <div className="flex flex-wrap items-start gap-2" data-testid="code-security-findings-active">
          <ActiveFilterChips chips={chips} caption="Filters" className="min-w-0 flex-1" />
          <Button size="sm" variant="ghost" onClick={() => onChange(clearFindingsFilters)}>
            Clear filters
          </Button>
        </div>
      )}
    </div>
  );
}
