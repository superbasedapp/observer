import { useMemo } from "react";
import { ChartState } from "@/components/ChartState";
import { HelpInd } from "@/components/HelpInd";
import { sessionLOCPath } from "@/lib/api";
import { fmtInt } from "@/lib/format";
import { useApi } from "@/lib/useApi";
import type { LOCBucket, LOCStats, SessionLOCResponse } from "@/lib/types";

// SessionLOCCard — the per-session "Code lines" card
// (docs/plans/lines-of-code-tracking-plan-2026-09-07.md §3.4/§3.5). Reads
// GET /api/session/<id>/loc, a node-local read over `file_changes`.
//
// The plan's honesty rules are REQUIREMENTS, and this card is where three of
// them land:
//
//  1. No AI share is rendered here, ever. The session payload carries no
//     share and this card does not synthesise one: while nothing measures the
//     developer's own typing, a share would be 100% by construction - a claim
//     about the developer, not a fact about the agent. When human capture is
//     absent the server's own `capture_note` sentence is rendered verbatim in
//     place of a human row.
//  2. The `unknown` bucket is always a column, and each row's
//     low-confidence / overwrite file counts sit NEXT TO that row's numbers
//     rather than in a footnote.
//  3. Overwrites are labelled for what they are: counted as added, because
//     the before-image came from the prior read (or from nothing at all).
//
// Sidechain (subagent) work is a SEPARATE headline figure, never folded into
// the main-agent number - on the reference node 47% of edit rows are
// subagent work, so folding them would hide half the story.
export function SessionLOCCard({ sessionId }: { sessionId: string }) {
  const loc = useApi<SessionLOCResponse>(sessionLOCPath(sessionId), undefined, [
    sessionId,
  ]);

  const data = loc.data;
  const rows = useMemo(() => foldRows(data), [data]);
  // A session predating the feature, or one that edited nothing, has no rows
  // at all. That is NOT "zero lines written" - rendering zeros would present
  // an absence of measurement as a measurement.
  const uncounted = !!data && data.buckets.length === 0;

  return (
    <section className="mt-5 rounded-3 border bg-bg-2 px-4 py-3">
      <div className="flex items-center justify-between gap-2">
        <span className="flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-[0.06em] text-fg-3">
          Code lines
          <HelpInd id="card.session_loc" />
        </span>
        {data && !uncounted && (
          <span className="text-[10px] tabular-nums text-fg-3">
            {fmtInt(data.files)} file{data.files === 1 ? "" : "s"} · classifier
            v{data.classifier_version}
          </span>
        )}
      </div>
      <p className="mt-1 text-[10.5px] text-fg-3">
        Lines this session changed, classified as code, comment, whitespace or
        blank and attributed to whoever authored them. Counted from the edit's
        own before/after text, not from a filesystem or git diff.
      </p>

      <ChartState
        loading={loc.loading && !loc.data}
        error={loc.error}
        empty={false}
        height={96}
      >
        {data &&
          (uncounted ? <UncountedBlock /> : <LOCBody data={data} rows={rows} />)}
      </ChartState>
    </section>
  );
}

// UncountedBlock is the honest empty state: it says the counts do not exist
// yet and how to make them exist. It deliberately shows no numbers.
function UncountedBlock() {
  return (
    <div className="mt-2 rounded-2 border border-line-2 bg-bg-1 px-3 py-2.5 text-[10.5px] leading-relaxed text-fg-3">
      Line counts have not been computed for this session. Either it predates
      line tracking or it changed no files. Run{" "}
      <code className="rounded-1 bg-bg-2 px-1 py-0.5 font-mono text-[10px] text-fg-2">
        observer backfill --loc
      </code>{" "}
      to populate history, then reopen this session.
    </div>
  );
}

// ----- body ---------------------------------------------------------

function LOCBody({
  data,
  rows,
}: {
  data: SessionLOCResponse;
  rows: FoldedRows;
}) {
  const captured = data.human_capture !== "none";
  return (
    <div className="mt-2.5 space-y-3">
      {/* Headline: main-agent code lines, with the subagent split beside it
          as its own figure. Never summed into one number. */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <Headline
          label="AI code lines"
          value={data.ai_main.code_touched}
          sub="main agent · added + modified"
          strong
        />
        <Headline
          label="Subagent code lines"
          value={data.ai_sidechain.code_touched}
          sub="sidechain runs, counted separately"
        />
        {captured ? (
          <Headline
            label="Human code lines"
            value={data.human.code_touched}
            sub="editor-reported (VS Code)"
          />
        ) : (
          <Headline
            label="Human code lines"
            value={null}
            sub="not measured"
            muted
          />
        )}
        <Headline
          label="Deleted code lines"
          value={
            data.ai_main.deleted_code +
            data.ai_sidechain.deleted_code +
            data.human.deleted_code +
            data.system.deleted_code
          }
          sub="not part of lines written"
          muted
        />
      </div>

      {/* The capture note is the SERVER's sentence, rendered verbatim. */}
      <p
        className={
          captured
            ? "text-[10px] text-fg-3"
            : "rounded-2 border border-line-2 bg-bg-1 px-2.5 py-1.5 text-[10px] leading-relaxed text-fg-3"
        }
      >
        {data.capture_note}
      </p>

      {rows.code.length > 0 && (
        <BucketTable title="Code" rows={rows.code} />
      )}
      {rows.other.length > 0 && (
        <BucketTable
          title="Docs and config"
          note="Kept out of the code numbers above."
          rows={rows.other}
        />
      )}

      {rows.skippedFiles > 0 && (
        <p className="text-[10px] text-fg-3">
          {fmtInt(rows.skippedFiles)} file
          {rows.skippedFiles === 1 ? "" : "s"} skipped as generated, vendored or
          unrecognised. Those carry no line counts.
        </p>
      )}

      {data.languages.length > 0 && <LanguageChips data={data} />}
    </div>
  );
}

function Headline({
  label,
  value,
  sub,
  strong,
  muted,
}: {
  label: string;
  // null renders a dash: "we are not measuring this", never a zero.
  value: number | null;
  sub: string;
  strong?: boolean;
  muted?: boolean;
}) {
  return (
    <div className="rounded-2 border border-line-2 bg-bg-1 px-2.5 py-2">
      <span className="block text-[9.5px] font-semibold uppercase tracking-[0.06em] text-fg-3">
        {label}
      </span>
      <span
        className={[
          "mt-0.5 block tabular-nums leading-none",
          strong ? "text-[22px] font-bold" : "text-[18px] font-semibold",
          muted ? "text-fg-3" : strong ? "text-fg-0" : "text-fg-1",
        ].join(" ")}
      >
        {value === null ? "-" : fmtInt(value)}
      </span>
      <span className="mt-1 block text-[9.5px] leading-tight text-fg-3">
        {sub}
      </span>
    </div>
  );
}

// ----- bucket table -------------------------------------------------

const COLUMNS: { key: keyof LOCStats; label: string; title: string }[] = [
  { key: "code_touched", label: "code", title: "Code lines written: added + modified" },
  { key: "added_code", label: "+code", title: "Code lines added" },
  { key: "modified_code", label: "~code", title: "Code lines modified (a replaced line counts once)" },
  { key: "deleted_code", label: "-code", title: "Code lines deleted" },
  { key: "added_comment", label: "+cmt", title: "Comment lines added" },
  { key: "deleted_comment", label: "-cmt", title: "Comment lines deleted" },
  { key: "whitespace", label: "wspace", title: "Lines that changed only in whitespace (reindents)" },
  { key: "blank", label: "blank", title: "Blank lines" },
  { key: "unknown", label: "unknown", title: "Lines the classifier could not classify (truncated input, fragment boundary, path-only edit)" },
];

function BucketTable({
  title,
  note,
  rows,
}: {
  title: string;
  note?: string;
  rows: FoldedRow[];
}) {
  return (
    <div>
      <div className="mb-1 flex items-baseline gap-2">
        <span className="text-[10px] font-semibold uppercase tracking-[0.06em] text-fg-3">
          {title}
        </span>
        {note && <span className="text-[9.5px] text-fg-3">{note}</span>}
      </div>
      <div className="overflow-x-auto">
        <table className="w-full min-w-[560px] border-collapse text-[10.5px]">
          <thead>
            <tr className="border-b border-line-2 text-fg-3">
              <th className="py-1 pr-2 text-left font-medium">who</th>
              {COLUMNS.map((c) => (
                <th
                  key={c.key}
                  title={c.title}
                  className="cursor-help py-1 pl-2 text-right font-medium"
                >
                  {c.label}
                </th>
              ))}
              <th className="py-1 pl-2 text-right font-medium" title="Files touched">
                files
              </th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.key} className="border-b border-line-1/60 last:border-0">
                <td className="py-1 pr-2 align-top">
                  <span className="block text-fg-1">{r.label}</span>
                  {r.note && (
                    <span className="block text-[9.5px] text-fg-3">{r.note}</span>
                  )}
                  {/* Honesty rule: the caveats sit WITH the numbers. */}
                  {(r.lowConfidence > 0 || r.overwrites > 0) && (
                    <span className="mt-0.5 flex flex-wrap gap-1">
                      {r.lowConfidence > 0 && (
                        <span
                          className="rounded-1 bg-warn-soft px-1 py-0.5 text-[9px] text-warn"
                          title="Files whose line classification is not high confidence: a truncated tool input, a fragment that started mid block-comment or mid-string, or an edit that carried only a path."
                        >
                          {fmtInt(r.lowConfidence)} low confidence
                        </span>
                      )}
                      {r.overwrites > 0 && (
                        <span
                          className="rounded-1 bg-bg-1 px-1 py-0.5 text-[9px] text-fg-3"
                          title="Whole-file writes over an existing file."
                        >
                          {fmtInt(r.overwrites)} overwrite: counted as added
                          (before-image from the prior read, or none)
                        </span>
                      )}
                    </span>
                  )}
                </td>
                {COLUMNS.map((c) => (
                  <td
                    key={c.key}
                    className={[
                      "py-1 pl-2 text-right align-top font-mono tabular-nums",
                      r.stats[c.key] === 0
                        ? "text-fg-4"
                        : c.key === "code_touched"
                          ? "text-fg-0"
                          : "text-fg-2",
                    ].join(" ")}
                  >
                    {r.stats[c.key] === 0 ? "-" : fmtInt(r.stats[c.key])}
                  </td>
                ))}
                <td className="py-1 pl-2 text-right align-top font-mono tabular-nums text-fg-2">
                  {fmtInt(r.files)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {rows.some((r) => r.overwrites > 0) && (
        <p className="mt-1 text-[9.5px] leading-relaxed text-fg-3">
          Overwrite rows are counted as added (before-image from the prior
          read, or none).
        </p>
      )}
    </div>
  );
}

function LanguageChips({ data }: { data: SessionLOCResponse }) {
  const langs = data.languages
    .filter((l) => l.stats.total > 0 || l.files > 0)
    .slice(0, 10);
  if (langs.length === 0) return null;
  return (
    <div className="flex flex-wrap gap-1">
      {langs.map((l) => (
        <span
          key={`${l.language}-${l.category}`}
          className="rounded-2 bg-bg-1 px-1.5 py-0.5 text-[10px] text-fg-2"
          title={`${l.category} · ${fmtInt(l.files)} file${l.files === 1 ? "" : "s"}`}
        >
          {l.language || "unknown"}{" "}
          <span className="tabular-nums text-fg-3">
            {fmtInt(l.stats.code_touched)}
          </span>
        </span>
      ))}
    </div>
  );
}

// ----- folding ------------------------------------------------------

type FoldedRow = {
  key: string;
  label: string;
  note?: string;
  stats: LOCStats;
  files: number;
  lowConfidence: number;
  overwrites: number;
  deletedFiles: number;
};

type FoldedRows = {
  code: FoldedRow[];
  other: FoldedRow[];
  // Files in generated / vendored / unrecognised categories. They carry no
  // line counts by construction, so they are reported as a file count only.
  skippedFiles: number;
};

const ZERO_STATS: LOCStats = {
  added_code: 0,
  modified_code: 0,
  deleted_code: 0,
  added_comment: 0,
  deleted_comment: 0,
  whitespace: 0,
  blank: 0,
  unknown: 0,
  code_touched: 0,
  total: 0,
};

function addStats(a: LOCStats, b: LOCStats): LOCStats {
  return {
    added_code: a.added_code + b.added_code,
    modified_code: a.modified_code + b.modified_code,
    deleted_code: a.deleted_code + b.deleted_code,
    added_comment: a.added_comment + b.added_comment,
    deleted_comment: a.deleted_comment + b.deleted_comment,
    whitespace: a.whitespace + b.whitespace,
    blank: a.blank + b.blank,
    unknown: a.unknown + b.unknown,
    code_touched: a.code_touched + b.code_touched,
    total: a.total + b.total,
  };
}

// ACTOR_LABELS mirrors the store's actor vocabulary. `system` is the
// formatter-on-save delta the editor reports, NOT a command class.
const ACTOR_LABELS: Record<string, { label: string; note?: string }> = {
  ai: { label: "AI agent" },
  human: { label: "Human", note: "editor-reported (VS Code)" },
  system: { label: "System", note: "format-on-save reflow, editor-reported" },
  unknown: {
    label: "Unattributed",
    note: "edit shape could not be parsed",
  },
};

// ROW_ORDER fixes the reading order so the main agent leads and the
// unattributed bucket is always last but never hidden.
const ROW_ORDER = ["ai", "ai-sidechain", "human", "system", "unknown"];

// foldRows collapses the (actor, sidechain, category) buckets into the two
// tables the card renders. The code fold mirrors the server's own fold so
// the table always reconciles with the headline roll-ups.
function foldRows(data: SessionLOCResponse | null): FoldedRows {
  const out: FoldedRows = { code: [], other: [], skippedFiles: 0 };
  if (!data) return out;

  const code = new Map<string, FoldedRow>();
  const other = new Map<string, FoldedRow>();

  for (const b of data.buckets) {
    if (b.category === "code") {
      const key = b.actor === "ai" && b.sidechain ? "ai-sidechain" : b.actor;
      const meta = ACTOR_LABELS[b.actor] ?? { label: b.actor || "unknown" };
      const label =
        key === "ai-sidechain" ? "AI subagent (sidechain)" : meta.label;
      merge(code, key, label, meta.note, b);
      continue;
    }
    if (b.category === "docs" || b.category === "config") {
      merge(other, b.category, b.category === "docs" ? "Docs" : "Config", undefined, b);
      continue;
    }
    // generated / vendored / unknown category: files only.
    out.skippedFiles += b.files;
  }

  out.code = [...code.values()].sort(
    (a, z) => ROW_ORDER.indexOf(a.key) - ROW_ORDER.indexOf(z.key),
  );
  out.other = [...other.values()].sort((a, z) => a.key.localeCompare(z.key));
  return out;
}

function merge(
  into: Map<string, FoldedRow>,
  key: string,
  label: string,
  note: string | undefined,
  b: LOCBucket,
) {
  const prev =
    into.get(key) ??
    ({
      key,
      label,
      note,
      stats: ZERO_STATS,
      files: 0,
      lowConfidence: 0,
      overwrites: 0,
      deletedFiles: 0,
    } satisfies FoldedRow);
  into.set(key, {
    ...prev,
    stats: addStats(prev.stats, b.stats),
    files: prev.files + b.files,
    lowConfidence: prev.lowConfidence + b.low_confidence_files,
    overwrites: prev.overwrites + b.overwrite_files,
    deletedFiles: prev.deletedFiles + b.deleted_files,
  });
}
