import type { ReactNode } from "react";
import type { ProjectTruncationMeta } from "@/lib/types";

// TruncationBanner — the one-owner "row caps hit" notice for the
// Projects-detail tabs. Before the 2026-09-22 rework's SOL-F10 fix, only
// OverviewTab rendered this (over GET /api/project/{id}'s own bare
// `truncated` boolean); the three secondary endpoints (/commits,
// /prompts, /cost?by=commit) discarded their loaders' truncation booleans
// entirely and returned only `rows`, so a tab could present partial
// prompt-to-commit linkage as complete with no signal at all. Those
// endpoints now carry ProjectTruncationMeta (truncated/truncated_inputs/
// affects) alongside `rows`; every consumer renders it through this ONE
// component so the banner's markup has a single owner. The COPY stays
// per-tab (OverviewTab's caps are fixed numbers worth naming explicitly;
// the other three vary by which loader actually truncated) — pass it as
// children.
export function TruncationBanner({ children }: { children: ReactNode }) {
  return (
    <div className="rounded-3 border border-line bg-surface-2 px-3 py-2 text-[11.5px] text-fg-3">
      {children}
    </div>
  );
}

// FIELD_LABEL turns a wire-level snake_case input/affects key into the
// short human phrase describeTruncation composes into a sentence — the
// same vocabulary the three secondary endpoints' `truncated_inputs`/
// `affects` arrays use (internal/intelligence/dashboard/projects.go's
// buildTruncationMeta call sites).
const FIELD_LABEL: Record<string, string> = {
  prompts: "prompts",
  edits: "AI edits",
  commits: "commits",
  ai_files: "AI-touched files",
  ai_lines: "AI code line counts",
  ai_split: "AI code/comment splits",
  owner: "commit owners",
  rows: "commits listed",
  share: "shares",
  files: "files",
  code_lines: "code lines",
  comment_lines: "comment lines",
  spend_usd: "attributed spend",
  cost_usd: "cost totals",
  status: "prompt status",
  commit_rows: "commit rows",
  prompt_rows: "prompt rows",
};

// ROW_CAP_INPUTS names the `truncated_inputs` entries that are an OUTPUT
// row cap (commitRowsCap/promptRowsCap) rather than a LINK cap
// (promptLinkCap/editLinkCap/commitLinkCap feeding projectroi.Link). The
// two are not the same kind of gap: a row cap means real rows for this
// window are missing from the response entirely (a "showing the newest
// N" pagination fact), while a link cap means a row that IS shown may
// carry an undercounted figure (spend/AI lines/status) because Link ran
// over a capped input. Collapsing them into one sentence (SOL-F10
// residue, 2026-09-22 rework: the two secondary endpoints that hit an
// output cap discarded the fact entirely) would blur that distinction
// even once the wire carried both signals correctly.
const ROW_CAP_INPUTS = new Set(["commit_rows", "prompt_rows"]);

function labelList(keys: string[] | undefined, fallback: string): string {
  if (!keys || keys.length === 0) return fallback;
  return keys.map((k) => FIELD_LABEL[k] ?? k).join(", ");
}

// describeTruncation composes the caveat sentence(s) a secondary
// endpoint's TruncationBanner renders. It renders an output-row cap and a
// linkage cap as separate sentences, since they mean different things to
// a reader (missing rows vs. undercounted figures on shown rows) — see
// ROW_CAP_INPUTS. Returns null when meta says nothing truncated (the
// caller should skip rendering the banner entirely in that case), or
// when meta itself is absent — `| null` covers useApi's `data: T | null`
// before the first response lands.
export function describeTruncation(meta: ProjectTruncationMeta | null | undefined, subject: string): string | null {
  if (!meta?.truncated) return null;
  const allInputs = meta.truncated_inputs ?? [];
  const rowCapInputs = allInputs.filter((k) => ROW_CAP_INPUTS.has(k));
  const linkCapInputs = allInputs.filter((k) => !ROW_CAP_INPUTS.has(k));

  const sentences: string[] = [];
  if (rowCapInputs.length > 0) {
    sentences.push(
      `Showing only the first page of ${labelList(rowCapInputs, subject)} for this window - more exist and are not returned here.`,
    );
  }
  // A row-cap-only truncation still sets `truncated: true` with no
  // link-cap inputs; only render the undercount sentence when a link cap
  // (or an unrecognized legacy input, defensively) actually fired.
  if (linkCapInputs.length > 0 || (rowCapInputs.length === 0 && allInputs.length === 0)) {
    const inputs = labelList(linkCapInputs.length > 0 ? linkCapInputs : allInputs, "this window's linkage inputs");
    const affects = labelList(meta.affects, `some figures on ${subject}`);
    sentences.push(`Row caps hit on ${inputs} for this window - ${affects} may be undercounted for the ${subject} shown.`);
  }
  return sentences.join(" ");
}
