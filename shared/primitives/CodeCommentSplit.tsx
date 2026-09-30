import clsx from "clsx";
import { fmtCompact, fmtInt, fmtPct } from "../lib/format";
import { Tooltip } from "./Tooltip";

// CodeCommentSplit renders the code-vs-comment split of AI-authored lines
// (operator ask 2026-09-28: "we need a sense of code generated vs comments
// generated"). It is the ONE renderer every node (web/) and org (web2/)
// surface uses for that split, and it does no line arithmetic of its own:
// the counts AND the share arrive precomputed by the Go derivation
// internal/loc.SplitAuthored, which is the single definition:
//
//   code    = added + modified code lines
//   comment = added comment lines
//   share   = comment / (code + comment), absent when both are zero
//
// Blank, whitespace-only and unknown lines are in neither number.
//
// This is NOT an AI-vs-human share and needs no human measurement, so it
// is honest to show even where human_capture is "none".

// AuthoredSplit mirrors internal/loc.AuthoredSplit's JSON shape.
export type AuthoredSplit = {
  code_lines: number;
  comment_lines: number;
  // Fraction in [0,1]; absent when there were no authored lines.
  comment_share?: number | null;
};

const TOOLTIP =
  "Code = lines the agent added or modified; comments = comment lines it added. " +
  "Blank and whitespace-only lines are in neither number. The share is comments over " +
  "code plus comments.";

export function CodeCommentSplit({
  split,
  variant = "inline",
  compact = false,
  className,
}: {
  split?: AuthoredSplit | null;
  // inline: one line of text. bar: text plus a two-segment bar.
  // share: only the comment share, for a narrow table cell.
  variant?: "inline" | "bar" | "share";
  // compact renders counts as 1.2k rather than 1,234.
  compact?: boolean;
  className?: string;
}) {
  const fmt = compact ? fmtCompact : fmtInt;
  const share = split?.comment_share;
  if (!split || share == null) {
    return (
      <span className={clsx("text-fg-4", className)} title="No AI-authored code or comment lines">
        {variant === "share" ? "-" : "no authored lines"}
      </span>
    );
  }
  const shareText = `${fmtPct(share, 0)} comments`;
  if (variant === "share") {
    return (
      <Tooltip content={`${fmt(split.code_lines)} code, ${fmt(split.comment_lines)} comment lines. ${TOOLTIP}`}>
        <span className={clsx("font-mono text-fg-2", className)} tabIndex={0}>
          {fmtPct(share, 0)}
        </span>
      </Tooltip>
    );
  }
  const text = (
    <span className="whitespace-nowrap">
      <span className="font-mono text-fg-1">{fmt(split.code_lines)}</span>
      <span className="text-fg-3"> code · </span>
      <span className="font-mono text-fg-1">{fmt(split.comment_lines)}</span>
      <span className="text-fg-3"> comments ({shareText})</span>
    </span>
  );
  if (variant === "inline") {
    return (
      <Tooltip content={TOOLTIP}>
        <span className={clsx("text-caption", className)} tabIndex={0}>
          {text}
        </span>
      </Tooltip>
    );
  }
  const commentPct = Math.max(0, Math.min(1, share)) * 100;
  return (
    <Tooltip content={TOOLTIP}>
      <div className={clsx("text-caption", className)} tabIndex={0}>
        {text}
        <div
          className="mt-1 flex h-1.5 w-full overflow-hidden rounded-pill bg-bg-3"
          role="img"
          aria-label={`${fmtPct(share, 0)} of AI-authored lines are comments`}
        >
          <div className="h-full bg-info" style={{ width: `${100 - commentPct}%` }} />
          <div className="h-full bg-fg-4" style={{ width: `${commentPct}%` }} />
        </div>
      </div>
    </Tooltip>
  );
}
