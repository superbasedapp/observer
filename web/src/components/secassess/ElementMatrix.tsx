import { useMemo } from "react";
import clsx from "clsx";
import { Ban, Check, CircleAlert } from "lucide-react";
import { EmptyState, Icon, Table, Tooltip } from "@/components/primitives";
import {
  buildElementMatrix,
  enumWords,
  frameworkLabel,
  frameworkTitle,
  matrixAbbr,
  plural,
  type ElementMatrixModel,
  type MatrixCell,
  type ModelVocab,
  type TMCoverage,
  type ThreatModelDoc,
} from "@/lib/secAssessModel";
import { AgentText, SubHeading } from "./modelParts";

// ElementMatrix is the STRIDE-per-element matrix: one row for each element of
// the model, one column for each category, and a mark in each cell the
// category applies to. Observer counted the cells; it did not check that a
// threat or a reason is right. Three states, each with a glyph and words (never
// colour alone):
//   analysed        the model records a threat for the pair
//   waived          the model gives a reason that none applies (the agent
//                   says so; counted apart from analysed)
//   not considered  neither a threat nor a reason: highlighted
// A blank cell means the category does not apply to that kind of element.
// The words in a cell are the page's ordinary text colour on a tinted box (the
// tone colours alone do not reach 4.5:1 on a 10% tint in the light theme); the
// glyph carries the tone.

type DrawnState = "analysed" | "waived" | "empty";

const CELL_LOOK: Readonly<Record<DrawnState, { box: string; icon: string; word: string }>> = {
  analysed: { box: "bg-success-soft text-fg-1", icon: "text-success", word: "Analysed" },
  waived: { box: "bg-bg-3 text-fg-1", icon: "text-fg-2", word: "Waived" },
  empty: { box: "bg-warn-soft text-fg-1", icon: "text-warn", word: "Not considered" },
};

function Mark({ cell, count }: { cell: MatrixCell & { state: DrawnState }; count: number }) {
  const look = CELL_LOOK[cell.state];
  if (cell.state === "analysed") {
    return (
      <span className="inline-flex items-center gap-0.5">
        <Icon icon={Check} size="xs" className={clsx("shrink-0", look.icon)} />
        <span className="tabular-nums">{count}</span>
      </span>
    );
  }
  if (cell.state === "waived") {
    return (
      <span className="inline-flex items-center gap-0.5">
        <Icon icon={Ban} size="xs" className={clsx("shrink-0", look.icon)} />
        <span>waived</span>
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-0.5">
      <Icon icon={CircleAlert} size="xs" className={clsx("shrink-0", look.icon)} />
      <span>not considered</span>
    </span>
  );
}

/** groupRuns lists the runs of columns that share a framework, in order: the group header above the column abbreviations. */
function groupRuns(columns: ElementMatrixModel["columns"]): { framework: string; n: number }[] {
  const out: { framework: string; n: number }[] = [];
  for (const c of columns) {
    const last = out[out.length - 1];
    if (last && last.framework === c.framework) last.n++;
    else out.push({ framework: c.framework, n: 1 });
  }
  return out;
}

export function ElementMatrix({ doc, cov, vocab }: { doc: ThreatModelDoc; cov: TMCoverage | undefined; vocab: ModelVocab }) {
  const model = useMemo(() => (cov ? buildElementMatrix(doc, cov, vocab) : null), [doc, cov, vocab]);
  if (!model || model.rows.length === 0) {
    return (
      <div data-testid="assess-matrix">
        <EmptyState variant="inline" title="No elements to lay out" body="The model names no component, actor or flow, so there is no matrix to draw. Observer cannot say what the agent considered." />
      </div>
    );
  }
  const waivers = model.rows.flatMap((r) =>
    r.cells.filter((c) => c.state === "waived").map((c) => ({ row: r, cell: c, column: model.columns.find((col) => col.id === c.category) })),
  );
  const ai = Object.entries(cov?.ai_threats ?? {}).filter(([, n]) => typeof n === "number" && n > 0);
  const t = model.totals;

  return (
    <div className="min-w-0 space-y-3" data-testid="assess-matrix">
      <p className="m-0 text-[12px] text-fg-1" data-testid="assess-matrix-totals">
        {`${t.analysed} analysed, ${t.waived} waived with a reason, ${t.empty} with neither`}
      </p>

      <ul className="m-0 flex list-none flex-wrap gap-x-4 gap-y-1 p-0 text-[11.5px] text-fg-2" aria-label="How to read the matrix">
        {(Object.keys(CELL_LOOK) as DrawnState[]).map((s) => (
          <li key={s} className="inline-flex items-center gap-1.5">
            <span className={clsx("inline-flex rounded-1 px-1.5 py-0.5", CELL_LOOK[s].box)}>
              <Mark cell={{ category: "", state: s, threats: [] }} count={2} />
            </span>
            <span>
              {s === "analysed" && "the model records a threat for the pair"}
              {s === "waived" && "the model gives a reason that none applies"}
              {s === "empty" && "neither a threat nor a reason"}
            </span>
          </li>
        ))}
        <li className="inline-flex items-center gap-1.5">
          <span className="inline-flex h-5 w-8 rounded-1 border border-dashed border-line-2" aria-hidden />
          <span>blank: the category does not apply to this kind of element</span>
        </li>
      </ul>

      <Table
        minWidth={Math.max(480, 200 + model.columns.length * 78)}
        size="sm"
        head={
          <>
            <tr>
              <th scope="col" rowSpan={2} className="sticky left-0 z-[1] bg-bg-1 py-1.5 pr-3 align-bottom font-medium">
                Element
              </th>
              {groupRuns(model.columns).map((g) => (
                <th key={g.framework} scope="colgroup" colSpan={g.n} className="border-l border-line-2 px-1 pt-1.5 text-center font-medium text-fg-2">
                  {frameworkLabel(g.framework)}
                </th>
              ))}
            </tr>
            <tr>
              {model.columns.map((c) => (
                <th key={c.id} scope="col" className="px-1 py-1.5 text-center font-medium">
                  <Tooltip content={`${frameworkTitle(c.framework, vocab)}: ${c.label}`}>
                    <span tabIndex={0} aria-label={`${frameworkLabel(c.framework)}, ${c.label}`} className="cursor-help rounded-1 focus:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent-ring)]">
                      {matrixAbbr(c)}
                    </span>
                  </Tooltip>
                </th>
              ))}
            </tr>
          </>
        }
      >
        {model.rows.map((r) => (
          <tr key={r.key} className="border-b border-line-1">
            <th scope="row" className="sticky left-0 z-[1] min-w-[10rem] bg-bg-1 py-1.5 pr-3 text-left font-normal text-fg-1">
              <div className="break-words">{r.name}</div>
              <div className="text-[10.5px] text-fg-3">{enumWords("element_kind", r.kind)}</div>
            </th>
            {r.cells.map((c) => {
              if (c.state === "na") {
                return (
                  // relative: the screen-reader span is positioned against its nearest positioned ancestor, and without one it sits outside the table's own scroller and stretches the dialog's body sideways.
                  <td key={c.category} className="relative px-1 py-1 text-center">
                    <span className="sr-only">does not apply to this kind of element</span>
                  </td>
                );
              }
              const look = CELL_LOOK[c.state];
              const label =
                c.state === "analysed"
                  ? `${look.word}: ${c.threats.join(", ")}`
                  : c.state === "waived"
                    ? `${look.word}: ${c.reason ?? "no reason is stored"}`
                    : look.word;
              return (
                <td key={c.category} className="px-1 py-1 text-center align-top">
                  <div
                    role="img"
                    data-testid="assess-matrix-cell"
                    data-state={c.state}
                    data-element={r.key}
                    data-category={c.category}
                    aria-label={`${r.name}, ${model.columns.find((col) => col.id === c.category)?.label ?? c.category}: ${label}`}
                    className={clsx("inline-flex min-w-[3.5rem] flex-col items-center rounded-1 px-1.5 py-0.5 text-[10.5px]", look.box)}
                  >
                    <Mark cell={{ ...c, state: c.state }} count={c.threats.length} />
                    {c.state === "analysed" && c.threats.length > 0 && <span className="max-w-[6rem] break-words font-mono text-[10px] text-fg-3">{c.threats.join(", ")}</span>}
                  </div>
                </td>
              );
            })}
          </tr>
        ))}
      </Table>

      <ul className="m-0 flex list-none flex-wrap gap-x-4 gap-y-0.5 p-0 text-[11px] text-fg-3" aria-label="Column names">
        {model.columns.map((c) => (
          <li key={c.id}>
            <span className="font-medium text-fg-2">{matrixAbbr(c)}</span>
            {` ${c.label}`}
            <span className="sr-only">{`, ${frameworkLabel(c.framework)}`}</span>
          </li>
        ))}
      </ul>

      {ai.length > 0 && (
        <p className="m-0 text-[11.5px] text-fg-3" data-testid="assess-matrix-ai">
          {ai.map(([id, n]) => `${n} ${plural(n, "threat", "threats")} under ${frameworkTitle(id, vocab)} ${plural(n, "has", "have")} no matrix cells`).join(". ")}.
        </p>
      )}

      {waivers.length > 0 && (
        <div className="space-y-1.5" data-testid="assess-waivers">
          <SubHeading agent>{`Waived pairs (${waivers.length})`}</SubHeading>
          <ul className="m-0 list-none space-y-1.5 p-0">
            {waivers.map((w) => (
              <li key={`${w.row.key}|${w.cell.category}`} className="space-y-0.5 border-l-2 border-line-2 pl-3 text-[12px]">
                <div className="text-fg-1">{`${w.row.name}, ${w.column?.label ?? w.cell.category}`}</div>
                {w.cell.reason ? <AgentText className="text-fg-2">{w.cell.reason}</AgentText> : <p className="m-0 text-[11.5px] text-fg-3">No reason is stored for this pair.</p>}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
