import clsx from "clsx";
import { modelFamily } from "../lib/modelFamilies";
import { MODEL_FAMILY_MARKS } from "../lib/brandMarks";
import { modelColorVar } from "../lib/models";
import { Tooltip } from "./Tooltip";

// ModelMark — the model FAMILY's logo (Claude spark, OpenAI knot, Gemini
// sparkle, Qwen, DeepSeek whale, ...) resolved by the table-driven
// modelFamily() matcher. Drop-in upgrade for ModelDot: an unmatched id (a
// stealth / preview model) falls back to the existing provider dot rather
// than guessing a vendor. Router sentinels ("auto", "openrouter/free",
// "copilot/auto") get the auto-routed mark so a routed turn is visibly not a
// named model.
export function ModelMark({
  model,
  size = 12,
  className,
  tooltip = true,
}: {
  model: string | null | undefined;
  size?: number;
  className?: string;
  tooltip?: boolean;
}) {
  const fam = modelFamily(model);
  if (!fam || fam.hidden) {
    return (
      <span
        aria-hidden
        className={clsx("inline-block shrink-0 rounded-full", className)}
        style={{ width: Math.round(size * 0.5), height: Math.round(size * 0.5), background: modelColorVar(model) }}
      />
    );
  }
  const mark = (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="currentColor"
      fillRule="evenodd"
      className={clsx("shrink-0 text-fg-2", className)}
      aria-hidden
    >
      {MODEL_FAMILY_MARKS[fam.id]}
    </svg>
  );
  if (!tooltip) return mark;
  return (
    <Tooltip content={`${fam.label} · ${fam.maker}`}>
      <span className="inline-flex">{mark}</span>
    </Tooltip>
  );
}
