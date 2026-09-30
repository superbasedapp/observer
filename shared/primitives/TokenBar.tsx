import clsx from "clsx";
import { Tooltip } from "./Tooltip";
import { cachedNumberFormat } from "../lib/format";
import {
  tokenBarModel,
  tokenShareText,
  type TokenBuckets,
} from "./tokenBarModel";

// TokenBar: a compact four-bucket token mix (net input / cache read / cache
// write / output) as proportional flex segments in the --tok-* colours, the
// mini sibling of TokenBucketsPanel. Hover or focus shows the counts. Pure
// presentation: the numbers and the formatter come in as props.
//
// Unknown means unknown (see tokenBarModel.ts): a null bucket gets no segment
// and no tooltip row; all-unknown renders nothing at all; a known total of
// zero renders an empty track.

// One shared formatter (was a new Intl.NumberFormat per call, per bar, per
// table row); output identical.
const defaultFormat = (n: number): string =>
  cachedNumberFormat("en", { notation: "compact", maximumFractionDigits: 1 }).format(n);

export function TokenBar({
  buckets,
  format = defaultFormat,
  label = "Token mix",
  className,
  trackClassName = "h-1.5",
}: {
  /** The four counts; a missing / null bucket is unknown. */
  buckets: TokenBuckets;
  /** Count formatter for the tooltip and the segment labels. */
  format?: (n: number) => string;
  /** Accessible name of the bar as a whole. */
  label?: string;
  className?: string;
  /** Track height / radius classes (default a 6px pill). */
  trackClassName?: string;
}) {
  const m = tokenBarModel(buckets);
  if (m.known.length === 0) return null;
  const tip = (
    <div className="space-y-0.5 text-[11px]">
      {m.known.map((r) => (
        <div key={r.key} className="flex items-center gap-2">
          <span aria-hidden className="h-2 w-2 shrink-0 rounded-[2px]" style={{ background: r.color }} />
          <span className="text-fg-2">{r.label}</span>
          <span className="ml-auto pl-3 font-medium tabular-nums text-fg-0">{format(r.value)}</span>
          <span className="w-9 text-right tabular-nums text-fg-3">{tokenShareText(r.share)}</span>
        </div>
      ))}
    </div>
  );
  return (
    <Tooltip content={tip} maxWidth={260}>
      <div
        role="group"
        aria-label={`${label}: ${format(m.total)} tokens`}
        tabIndex={0}
        className={clsx(
          "flex w-full cursor-help gap-px overflow-hidden rounded-pill bg-bg-3 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--accent-ring)]",
          trackClassName,
          className,
        )}
      >
        {m.segments.map((r) => (
          <span
            key={r.key}
            role="img"
            aria-label={`${r.label} ${format(r.value)} tokens, ${tokenShareText(r.share)}`}
            className="h-full min-w-[2px]"
            style={{
              flexGrow: r.share,
              flexBasis: 0,
              background: r.color,
              transition: "flex-grow var(--dur-slower) var(--ease-out)",
            }}
          />
        ))}
      </div>
    </Tooltip>
  );
}
