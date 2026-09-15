import { modelColorVar } from "../lib/models";

// ModelDot — 6px provider-tinted swatch for a model identifier.
// Used next to model names in Sessions / Cost / Analysis tables to
// give the column visual rhythm. Inline-block + flex-safe so it
// flows next to text.
export function ModelDot({
  model,
  size = 6,
}: {
  model: string;
  size?: number;
}) {
  return (
    <span
      aria-hidden
      className="inline-block shrink-0 rounded-full"
      style={{
        width: size,
        height: size,
        background: modelColorVar(model),
      }}
    />
  );
}
