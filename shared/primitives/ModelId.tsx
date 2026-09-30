import clsx from "clsx";
import { formatModelId, shortModel } from "../lib/models";
import { ModelMark } from "./ModelMark";
import { Pill } from "./Pill";

// ModelId — the ONE "render a model id" primitive for every app (moved from
// web2 2026-09-28; web2's old path is a re-export shim). Use it everywhere a
// raw model string would otherwise be dropped into a table cell, list or
// dropdown:
//   - the model FAMILY mark (ModelMark, table-driven modelFamily()) sits
//     before the label; an unmatched / stealth id keeps the plain family dot,
//     never a guessed vendor logo;
//   - a leading "~" becomes a small "provisional" chip;
//   - empty / placeholder ids render a muted "No model reported" instead of
//     "(none)" / "(unknown)" / a blank cell.
// `short` trims a vendor prefix the proxy stores verbatim
// ("anthropic/claude-opus-4-7" -> "claude-opus-4-7"); the tooltip keeps the
// full id. `mark={false}` drops the family mark for places that already show
// one (e.g. a legend swatch).
export function ModelId({
  model,
  className,
  short = false,
  mark = true,
  markSize = 12,
  mono = true,
}: {
  model?: string | null;
  className?: string;
  short?: boolean;
  mark?: boolean;
  markSize?: number;
  mono?: boolean;
}) {
  const f = formatModelId(model);
  if (!f.known) {
    return <span className={clsx("text-fg-4", className)}>{f.label}</span>;
  }
  const label = short ? shortModel(f.label) : f.label;
  return (
    <span className={clsx("inline-flex min-w-0 items-center gap-1.5", className)}>
      {mark && <ModelMark model={f.label} size={markSize} />}
      <span className={clsx("truncate text-fg-1", mono && "font-mono")} title={f.label}>
        {label}
      </span>
      {f.provisional && (
        <Pill
          variant="warn"
          title="Provisional - this model id was resolved from partial data and may be inaccurate."
        >
          provisional
        </Pill>
      )}
    </span>
  );
}
