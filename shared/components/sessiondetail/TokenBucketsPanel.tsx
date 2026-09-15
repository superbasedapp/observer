import { Tooltip } from "../../primitives";
import { fmtCompact } from "../../lib/format";
import type { TokenBucketsLike } from "../../lib/types";

// TokenBucketsPanel — the token-movement split (net input / cache read / cache
// write 5m+1h / output) shown in the session-detail Overview band. Promoted
// into the shared design system unchanged (it is pure: token counts in, bars
// out). It has NO cost figures, so it takes no renderCost slot.

export function TokenBucketsPanel({ tokens }: { tokens: TokenBucketsLike }) {
  // Cache-write splits into 5m and 1h ephemeral tiers; the 1h sub-row
  // only renders when the session actually carried 1h-tier writes
  // (every non-Anthropic provider stays at 0 — irrelevant noise to
  // show as a perpetual "—" row). Same colour family as 5m so the
  // two read as siblings; slight opacity drop on 1h so the visual
  // hierarchy still leads with the dominant tier.
  const cache1h = tokens.cache_creation_1h || 0;
  const cache5m = Math.max(0, tokens.cache_creation - cache1h);
  const cacheRows: {
    label: string;
    value: number;
    color: string;
    help: string;
  }[] =
    cache1h > 0
      ? [
          {
            label: "Cache Write (5m)",
            value: cache5m,
            color: "var(--tok-write)",
            help: "Prompt prefix written to Anthropic's 5-minute ephemeral cache (default tier). Charged at the model's cache_creation rate (≈125% of input). The TTL is sliding - every cache hit refreshes it for another 5 minutes from the read.",
          },
          {
            label: "Cache Write (1h)",
            value: cache1h,
            color: "color-mix(in oklab, var(--tok-write) 70%, var(--bg-3))",
            help: "Prompt prefix written to Anthropic's 1-hour ephemeral cache (cache_control.ttl = '1h'). Charged at 2× input rate - 60% premium over the 5m tier. The TTL is fixed (no sliding refresh). Worth the premium when the cached prefix is stable for the full session.",
          },
        ]
      : [
          {
            label: "Cache Write",
            value: tokens.cache_creation,
            color: "var(--tok-write)",
            help: "Prompt prefix written into Anthropic's cache. Charged at the model's cache_creation rate (≈125% of input).",
          },
        ];
  const rows: {
    label: string;
    value: number;
    color: string;
    help: string;
  }[] = [
    {
      label: "Net Input",
      value: tokens.input,
      color: "var(--tok-net)",
      help: "Fresh prompt tokens (uncached). Charged at the model's input rate.",
    },
    {
      label: "Cache Read",
      value: tokens.cache_read,
      color: "var(--tok-read)",
      help: "Prompt prefix served from Anthropic's prefix cache. Charged at the model's cache_read rate (≈10% of input).",
    },
    ...cacheRows,
    {
      label: "Output",
      value: tokens.output,
      color: "var(--tok-out)",
      help: "Assistant response tokens. Charged at the model's output rate (typically 5× input).",
    },
  ];
  const total = rows.reduce((a, r) => a + r.value, 0);
  const max = Math.max(1, ...rows.map((r) => r.value));
  return (
    <section className="rounded-3 border border-line-2 bg-bg-2 p-4">
      <h4 className="text-[12px] font-semibold text-fg-1">Token buckets</h4>
      <p className="mt-0.5 text-[10.5px] text-fg-3">
        {fmtCompact(total)} total · net input · cache read · cache write · output
      </p>
      <ul className="mt-3 space-y-2.5 text-[11.5px]">
        {rows.map((r) => {
          const pct = total > 0 ? (r.value / total) * 100 : 0;
          return (
            <Tooltip key={r.label} content={r.help} maxWidth={360}>
              <li
                tabIndex={0}
                className="flex cursor-help items-center gap-3 focus:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent-ring)]"
              >
              <span className="w-[88px] shrink-0 text-fg-2">{r.label}</span>
              <span className="relative h-2 flex-1 overflow-hidden rounded-pill bg-bg-3">
                <span
                  className="block h-full"
                  style={{
                    width: `${(r.value / max) * 100}%`,
                    background: r.color,
                  }}
                />
              </span>
              <span className="w-[70px] shrink-0 text-right font-mono tabular-nums text-fg-1">
                {r.value > 0 ? fmtCompact(r.value) : "-"}
              </span>
              <span className="w-[44px] shrink-0 text-right font-mono tabular-nums text-fg-3">
                {r.value > 0 ? `${pct.toFixed(1)}%` : "-"}
              </span>
              </li>
            </Tooltip>
          );
        })}
      </ul>
      {tokens.reasoning > 0 && (
        <div className="mt-2 border-t border-line-1 pt-2 text-[10.5px] text-fg-3">
          plus {fmtCompact(tokens.reasoning)} reasoning tokens (billed at output rate)
        </div>
      )}
    </section>
  );
}
