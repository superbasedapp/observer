import { Fragment, useMemo, useState } from "react";
import {
  ChartShell,
  PageHeader,
  Pill,
  SegmentedControl,
  Tooltip,
  TruncatedPath,
} from "@/components/primitives";
import { Pagination } from "@/components/DataTable";
import { ChartState } from "@/components/ChartState";
import { useApi } from "@/lib/useApi";
import { useFilters } from "@/lib/filters";
import { fmtInt } from "@/lib/format";
import type {
  PatternRow,
  PatternsResponse,
  PatternsTimeseries,
} from "@/lib/types";

const PAGE_LIMIT = 30;

// Backend keys verified against project_patterns.pattern_type live
// data: hot_file, co_change, common_command, edit_test_pair,
// knowledge_snippet. The brief's `cs_change`/`command` aliases
// don't match the live schema.
type Filter =
  | "all"
  | "hot_file"
  | "co_change"
  | "common_command"
  | "edit_test_pair"
  | "knowledge_snippet";

const PATTERN_TOKEN: Record<string, string> = {
  hot_file: "var(--pat-hot)",
  co_change: "var(--pat-cochange)",
  edit_test_pair: "var(--pat-edittest)",
  knowledge_snippet: "var(--pat-knowledge)",
  common_command: "var(--pat-command)",
};

const PATTERN_LABEL: Record<string, string> = {
  hot_file: "Hot file",
  co_change: "Co-change",
  edit_test_pair: "Edit ↔ test",
  knowledge_snippet: "Knowledge",
  common_command: "Command",
};

export function PatternsPage() {
  const { project, tool } = useFilters();
  const projectRoot = project === "all" ? "" : project;
  const projectParam = project === "all" ? undefined : project;
  const toolParam = tool === "all" ? undefined : tool;
  const [page, setPage] = useState(1);
  const [filter, setFilter] = useState<Filter>("all");

  const patterns = useApi<PatternsResponse>(
    "/api/patterns",
    { page, limit: PAGE_LIMIT, project: projectParam, tool: toolParam },
    [page, project, tool],
  );

  const filtered = useMemo(() => {
    const rows = patterns.data?.rows ?? [];
    return filter === "all" ? rows : rows.filter((r) => r.pattern_type === filter);
  }, [patterns.data, filter]);

  const typeCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const r of patterns.data?.rows ?? []) {
      counts[r.pattern_type] = (counts[r.pattern_type] ?? 0) + 1;
    }
    return counts;
  }, [patterns.data]);

  return (
    <div className="space-y-6 p-6">
      <PageHeader
        title="Patterns"
        sub={`Repeatable behaviours the observer noticed across your sessions - for example, "after running \`go test\`, you almost always run \`go vet\`." These get fed into observer-suggest which writes them into CLAUDE.md / AGENTS.md / .cursorrules, so new sessions inherit the habit without you re-typing instructions.`}
        helpId="tab.patterns"
      />
      <ChartShell
        title="Learned patterns"
        sub={
          patterns.data
            ? `${fmtInt(patterns.data.total)} total · derived by \`observer patterns\` via decay-weighted analysis. \`observer suggest\` composes these into CLAUDE.md / AGENTS.md / .cursorrules.`
            : "Loading…"
        }
        right={
          <div className="flex items-center gap-2">
            <SegmentedControl<Filter>
              options={[
                { value: "all", label: `All ${fmtInt(patterns.data?.total ?? 0)}` },
                {
                  value: "hot_file",
                  label: `Hot ${typeCounts.hot_file ?? 0}`,
                },
                {
                  value: "co_change",
                  label: `Co-change ${typeCounts.co_change ?? 0}`,
                },
                {
                  value: "common_command",
                  label: `Command ${typeCounts.common_command ?? 0}`,
                },
                {
                  value: "edit_test_pair",
                  label: `Edit↔Test ${typeCounts.edit_test_pair ?? 0}`,
                },
                {
                  value: "knowledge_snippet",
                  label: `Knowledge ${typeCounts.knowledge_snippet ?? 0}`,
                },
              ]}
              value={filter}
              onChange={setFilter}
              size="sm"
            />
            <Tooltip
              content={
                projectRoot
                  ? "Jump to instruction-file generation panel"
                  : "Pick a project in the global filter first"
              }
              maxWidth={280}
            >
              <a
                href="#instruction-files"
                className={
                  "h-7 rounded-2 border border-accent/40 bg-accent-soft px-3 text-[11px] font-medium text-accent transition-opacity hover:bg-accent-soft/80 inline-flex items-center" +
                  (projectRoot ? "" : " pointer-events-none opacity-40")
                }
              >
                Generate suggestions
              </a>
            </Tooltip>
          </div>
        }
      >
        <ChartState
          loading={patterns.loading && !patterns.data}
          error={patterns.error}
          empty={!patterns.loading && !filtered.length}
          emptyHint={
            filter === "all"
              ? "No patterns mined yet. Run `observer patterns` to derive hot files, co-change pairs, and command sequences from session activity."
              : `No "${PATTERN_LABEL[filter] ?? filter}" patterns in this page. Try another filter or pagination.`
          }
          height={220}
        >
          <ul className="grid grid-cols-1 gap-3 lg:grid-cols-2">
            {filtered.map((r, i) => (
              <PatternCard key={`${r.project}|${r.pattern_type}|${i}`} row={r} />
            ))}
          </ul>
        </ChartState>

        {patterns.data && (
          <Pagination
            page={patterns.data.page}
            limit={patterns.data.limit}
            total={patterns.data.total}
            onPage={setPage}
            loading={patterns.loading}
          />
        )}
      </ChartShell>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-[1.4fr_1fr]">
        <PatternDistributionChart
          rows={patterns.data?.rows ?? []}
          loading={patterns.loading && !patterns.data}
        />
        <div id="instruction-files">
          <InstructionFilesSection
            total={patterns.data?.total ?? 0}
            projectRoot={projectRoot}
          />
        </div>
      </div>
    </div>
  );
}

// PatternDistributionChart — real per-day timeseries powered by
// `/api/patterns/timeseries`. Stacked vertical bars: one bar per day,
// segments colored by pattern_type. Falls back to a per-type rollup
// when the timeseries call errors so the panel never goes blank.
function PatternDistributionChart({
  rows,
  loading,
}: {
  rows: PatternRow[];
  loading: boolean;
}) {
  const { project, tool } = useFilters();
  const projectParam = project === "all" ? undefined : project;
  const toolParam = tool === "all" ? undefined : tool;
  const ts = useApi<PatternsTimeseries>(
    "/api/patterns/timeseries",
    { days: 30, project: projectParam, tool: toolParam },
    [project, tool],
  );
  const days = ts.data?.points ?? [];
  const types = useMemo(() => {
    const set = new Set<string>();
    for (const p of days) for (const t of Object.keys(p.by_type)) set.add(t);
    return [...set].sort(
      (a, b) =>
        (rows.find((r) => r.pattern_type === a)?.observation_count ?? 0) -
        (rows.find((r) => r.pattern_type === b)?.observation_count ?? 0),
    );
  }, [days, rows]);
  const max = Math.max(1, ...days.map((p) => p.total));

  return (
    <ChartShell
      title="Pattern discovery over time"
      sub={`Patterns reinforced per day over the last ${ts.data?.days ?? 30} days, stacked by type.`}
    >
      <ChartState
        loading={loading || ts.loading}
        error={ts.error}
        empty={days.length === 0}
        emptyHint="No pattern reinforcements in window. Run `observer patterns` to mine more, or widen the window when more endpoints accept ?days."
        height={220}
      >
        <div className="flex flex-col gap-2">
          <div className="flex h-[180px] items-end gap-1 overflow-x-auto pb-1">
            {days.map((p) => {
              return (
                <Tooltip
                  key={p.day}
                  content={`${p.day} · ${fmtInt(p.total)} reinforcements`}
                >
                  <div
                    tabIndex={0}
                    className="flex h-full min-w-[14px] cursor-help flex-col items-stretch justify-end focus:outline-none"
                  >
                    <div className="flex w-full flex-col-reverse overflow-hidden rounded-1 bg-bg-3">
                      {types.map((t) => {
                        const n = p.by_type[t] ?? 0;
                        if (n === 0) return null;
                        const h = (n / max) * 178;
                        return (
                          <Tooltip
                            key={t}
                            content={`${PATTERN_LABEL[t] ?? humanize(t)}: ${n}`}
                          >
                            <span
                              className="block"
                              style={{
                                height: `${h}px`,
                                background: PATTERN_TOKEN[t] ?? "var(--fg-3)",
                              }}
                            />
                          </Tooltip>
                        );
                      })}
                    </div>
                  </div>
                </Tooltip>
              );
            })}
          </div>
          <ul className="flex flex-wrap items-center gap-x-3 gap-y-1 text-[10.5px]">
            {types.map((t) => (
              <li key={t} className="inline-flex items-center gap-1.5">
                <span
                  className="h-2 w-2 rounded-pill"
                  style={{ background: PATTERN_TOKEN[t] ?? "var(--fg-3)" }}
                />
                <span className="text-fg-2">
                  {PATTERN_LABEL[t] ?? humanize(t)}
                </span>
              </li>
            ))}
          </ul>
        </div>
      </ChartState>
    </ChartShell>
  );
}

function InstructionFilesSection({
  total,
  projectRoot,
}: {
  total: number;
  projectRoot: string;
}) {
  // POST /api/suggest + POST /api/suggest/write are now wired. Each
  // card's Preview fires a preview-only fetch (no disk write) and
  // shows the rendered body in an inline drawer; Write calls the
  // write endpoint and reports the resulting file path + change
  // status. When no project is selected (filter=all) the cards
  // surface a project-picker requirement instead of guessing.
  const files: InstructionFile[] = [
    {
      name: "CLAUDE.md",
      target: "claude",
      tool: "Claude Code",
      summary:
        "Per-project rules for Claude Code. Hot-file shortcuts, edit/test pairs, knowledge snippets.",
    },
    {
      name: "AGENTS.md",
      target: "agents",
      tool: "Codex, Cursor",
      summary:
        "Multi-tool agent rules. Same patterns, written in AGENTS.md syntax for Codex / Cursor agents.",
    },
    {
      name: ".cursorrules",
      target: "cursor",
      tool: "Cursor (legacy)",
      summary:
        "Legacy Cursor format. Single-file ruleset for older Cursor versions.",
    },
  ];
  return (
    <ChartShell
      title="Generate instruction files"
      sub={
        projectRoot
          ? `Compose CLAUDE.md / AGENTS.md / .cursorrules from the patterns above for ${projectRoot}.`
          : "Compose CLAUDE.md / AGENTS.md / .cursorrules from the patterns above. Pick a project in the global filter to enable preview + write."
      }
    >
      {!projectRoot && (
        <p className="mb-3 rounded-2 border border-dashed border-line-2 bg-bg-3/40 px-3 py-2 text-[11.5px] text-fg-3">
          No project selected. Use the Project filter at the top to pick the
          project to write these files into.
        </p>
      )}
      <ul className="grid grid-cols-1 gap-3 md:grid-cols-3">
        {files.map((f) => (
          <FileCard
            key={f.name}
            file={f}
            total={total}
            projectRoot={projectRoot}
          />
        ))}
      </ul>
    </ChartShell>
  );
}

type InstructionFile = {
  name: string;
  target: "claude" | "agents" | "cursor";
  tool: string;
  summary: string;
};

function FileCard({
  file,
  total,
  projectRoot,
}: {
  file: InstructionFile;
  total: number;
  projectRoot: string;
}) {
  const [busy, setBusy] = useState<"" | "preview" | "write">("");
  const [body, setBody] = useState<string | null>(null);
  const [writeMsg, setWriteMsg] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);

  async function preview() {
    if (!projectRoot) return;
    setBusy("preview");
    setErr(null);
    setWriteMsg(null);
    try {
      const res = await fetch("/api/suggest", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ project_root: projectRoot, days: 30 }),
      });
      if (!res.ok) throw new Error(await res.text());
      const out = (await res.json()) as {
        markdown: string;
        cursorrules: string;
      };
      setBody(file.target === "cursor" ? out.cursorrules : out.markdown);
    } catch (e: unknown) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy("");
    }
  }

  async function write() {
    if (!projectRoot) return;
    if (
      !window.confirm(
        `Write ${file.name} into ${projectRoot}? Existing observer-managed sections will be overwritten in place; other content is preserved.`,
      )
    ) {
      return;
    }
    setBusy("write");
    setErr(null);
    try {
      const res = await fetch("/api/suggest/write", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          project_root: projectRoot,
          days: 30,
          target: file.target,
        }),
      });
      if (!res.ok) throw new Error(await res.text());
      const out = (await res.json()) as {
        path: string;
        changed: boolean;
        body: string;
      };
      setWriteMsg(
        out.changed
          ? `Wrote ${out.path}.`
          : `No changes - ${out.path} already up to date.`,
      );
      setBody(out.body);
    } catch (e: unknown) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy("");
    }
  }

  const disabled = !projectRoot || busy !== "";

  return (
    <li className="rounded-3 border border-line-2 bg-bg-2 p-3">
      <div className="flex items-baseline justify-between gap-2">
        <span className="font-mono text-[13px] font-semibold text-fg-0">
          {file.name}
        </span>
        <Pill variant="info">{fmtInt(total)} learned</Pill>
      </div>
      <div className="mt-0.5 text-[10.5px] uppercase tracking-[0.06em] text-fg-3">
        {file.tool}
      </div>
      <p className="mt-2 text-[11.5px] leading-snug text-fg-2">{file.summary}</p>
      <div className="mt-3 flex gap-2">
        <button
          type="button"
          disabled={disabled}
          onClick={preview}
          className="flex-1 rounded-2 border border-line-2 bg-bg-3 px-2 py-1 text-[11px] text-fg-2 transition-opacity disabled:opacity-40"
        >
          {busy === "preview" ? "…" : "Preview"}
        </button>
        <button
          type="button"
          disabled={disabled}
          onClick={write}
          className="flex-1 rounded-2 border border-accent/40 bg-accent-soft px-2 py-1 text-[11px] font-medium text-accent transition-opacity disabled:opacity-40"
        >
          {busy === "write" ? "…" : "Write"}
        </button>
      </div>
      {writeMsg && (
        <p className="mt-2 text-[10.5px] text-success">{writeMsg}</p>
      )}
      {err && <p className="mt-2 text-[10.5px] text-danger">{err}</p>}
      {body && (
        <details className="mt-3 rounded-2 border border-line-1 bg-bg-1">
          <summary className="cursor-pointer px-2 py-1 text-[11px] text-fg-2 hover:text-fg-1">
            Preview body ({body.length.toLocaleString()} chars)
          </summary>
          <pre className="m-0 max-h-[280px] overflow-auto whitespace-pre-wrap break-words px-2 py-1.5 font-mono text-[10.5px] text-fg-2">
            {body}
          </pre>
        </details>
      )}
    </li>
  );
}

function PatternCard({ row }: { row: PatternRow }) {
  const color = PATTERN_TOKEN[row.pattern_type] ?? "var(--fg-3)";
  const label = PATTERN_LABEL[row.pattern_type] ?? humanize(row.pattern_type);
  const kvs = parseDataKv(row.data);
  return (
    <li
      className="flex flex-col gap-2 rounded-3 border border-line-2 bg-bg-2 p-3"
      style={{ borderLeft: `3px solid ${color}` }}
    >
      <header className="flex items-baseline justify-between gap-2">
        <span className="flex items-center gap-2 min-w-0">
          <span
            className="inline-flex shrink-0 items-center gap-1.5 rounded-pill border px-2 py-0.5 text-[10.5px] font-medium"
            style={{
              borderColor: `color-mix(in srgb, ${color} 35%, transparent)`,
              background: `color-mix(in srgb, ${color} 12%, transparent)`,
              color,
            }}
          >
            <span
              className="h-1 w-1 rounded-full"
              style={{ background: color }}
            />
            {label}
          </span>
          {row.project ? (
            <TruncatedPath
              value={row.project}
              className="font-mono text-[10.5px] text-fg-3"
            />
          ) : (
            <span className="truncate font-mono text-[10.5px] text-fg-3">
              <Pill>no project</Pill>
            </span>
          )}
        </span>
        <span className="flex shrink-0 items-baseline gap-2 font-mono tabular-nums text-[10.5px]">
          <span className="font-semibold text-fg-0">
            {row.confidence.toFixed(2)}
          </span>
          <span className="text-fg-3">{fmtInt(row.observation_count)} obs</span>
        </span>
      </header>

      {row.pattern_type === "edit_test_pair" ? (
        <EditTestPairFlow kvs={kvs} color={color} />
      ) : kvs.length > 0 ? (
        <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-0.5 rounded-2 bg-bg-1 px-2 py-1.5 font-mono text-[11px]">
          {kvs.map(([k, v]) => (
            <Fragment key={k}>
              <dt className="text-fg-3">{k}:</dt>
              <Tooltip
                content={<span className="break-all">{String(v)}</span>}
                maxWidth={420}
              >
                <dd
                  tabIndex={0}
                  className="min-w-0 cursor-help truncate text-fg-1 focus:outline-none"
                >
                  {formatVal(v)}
                </dd>
              </Tooltip>
            </Fragment>
          ))}
        </dl>
      ) : (
        <pre className="m-0 max-h-[140px] overflow-auto whitespace-pre-wrap break-words rounded-2 bg-bg-1 px-2 py-1.5 font-mono text-[11px] text-fg-1">
          {row.data || "(no data)"}
        </pre>
      )}

      {/* Confidence meter — design's inline meter at the foot of each
          card (page-patterns.jsx:101-106). One thin bar, no label —
          the numeric confidence is already in the header. */}
      <div className="-mx-3 -mb-3 mt-1 h-[3px] overflow-hidden bg-bg-3">
        <span
          className="block h-full"
          style={{
            width: `${Math.max(0, Math.min(1, row.confidence)) * 100}%`,
            background: color,
          }}
        />
      </div>
    </li>
  );
}

// EditTestPairFlow — bespoke layout for `edit_test_pair` patterns
// per `design/page-patterns.jsx:113-120`. Renders the file → test →
// command triple as a horizontal flow with arrow connectors, falling
// back to the generic kv block when the expected keys aren't present.
function EditTestPairFlow({
  kvs,
  color,
}: {
  kvs: [string, unknown][];
  color: string;
}) {
  const m = new Map(kvs);
  const file = stringy(m.get("source") ?? m.get("file") ?? m.get("from"));
  const test = stringy(m.get("test") ?? m.get("paired_test") ?? m.get("target"));
  const command = stringy(
    m.get("command") ?? m.get("test_command") ?? m.get("via"),
  );
  if (!file && !test && !command) {
    // Pattern didn't carry the expected triple — fall back to generic
    // kv rendering so we don't show empty boxes.
    return (
      <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-0.5 rounded-2 bg-bg-1 px-2 py-1.5 font-mono text-[11px]">
        {kvs.map(([k, v]) => (
          <Fragment key={k}>
            <dt className="text-fg-3">{k}:</dt>
            <Tooltip
              content={<span className="break-all">{String(v)}</span>}
              maxWidth={420}
            >
              <dd
                tabIndex={0}
                className="min-w-0 cursor-help truncate text-fg-1 focus:outline-none"
              >
                {formatVal(v)}
              </dd>
            </Tooltip>
          </Fragment>
        ))}
      </dl>
    );
  }
  return (
    <div className="flex items-stretch gap-2 rounded-2 bg-bg-1 px-2.5 py-2 font-mono text-[11px]">
      <FlowNode label="file" value={file} color={color} />
      <FlowArrow color={color} />
      <FlowNode label="test" value={test} color={color} />
      <FlowArrow color={color} />
      <FlowNode label="run" value={command} color={color} />
    </div>
  );
}

function FlowNode({
  label,
  value,
  color,
}: {
  label: string;
  value: string;
  color: string;
}) {
  return (
    <div className="min-w-0 flex-1">
      <div
        className="text-[9.5px] font-semibold uppercase tracking-[0.06em]"
        style={{ color }}
      >
        {label}
      </div>
      <Tooltip content={<span className="break-all">{value || "(unset)"}</span>} maxWidth={420}>
        <div tabIndex={0} className="mt-0.5 cursor-help truncate text-fg-1 focus:outline-none">
          {value || <span className="text-fg-4">-</span>}
        </div>
      </Tooltip>
    </div>
  );
}

function FlowArrow({ color }: { color: string }) {
  return (
    <div
      aria-hidden
      className="flex shrink-0 items-center text-[14px]"
      style={{ color }}
    >
      →
    </div>
  );
}

function stringy(v: unknown): string {
  if (v == null) return "";
  if (typeof v === "string") return v;
  if (typeof v === "number" || typeof v === "boolean") return String(v);
  try {
    return JSON.stringify(v);
  } catch {
    return "";
  }
}

// Parse the JSON-encoded data field into ordered (key, value) entries.
// Returns [] if the field isn't valid JSON or isn't a plain object —
// the card falls back to a raw <pre> in that case.
function parseDataKv(raw: string): [string, unknown][] {
  if (!raw) return [];
  try {
    const obj = JSON.parse(raw);
    if (obj && typeof obj === "object" && !Array.isArray(obj)) {
      return Object.entries(obj);
    }
  } catch {
    // not JSON; let caller render raw.
  }
  return [];
}

function formatVal(v: unknown): string {
  if (v == null) return "-";
  if (typeof v === "number") return fmtInt(v);
  if (typeof v === "string") return v;
  return JSON.stringify(v);
}

function humanize(s: string): string {
  return s
    .replace(/_/g, " ")
    .replace(/\b\w/g, (c) => c.toUpperCase());
}
