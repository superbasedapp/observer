// displayFormat - the plain display formatters (counts, percentages,
// durations, dates) the org dashboard has always used, promoted from
// web2/src/lib/format.ts for Plane A B5-0 (2026-11-19) so the Plane A
// components in shared/components/planea render byte-identically on the node
// and the org dashboards. web2's format.ts re-exports every one, so no web2
// importer changed. Pure (no React); relative .ts imports so plain node:test
// loads it.
import { fmtShortDay, localeString } from "./format.ts";

export function num(n: number): string {
  return n.toLocaleString("en-US");
}

export function pct(ratio: number): string {
  // A non-zero share under 1% must not read as "0%" (O3).
  if (ratio > 0 && ratio < 0.01) return "<1%";
  return `${(ratio * 100).toFixed(0)}%`;
}

// pct1 is a one-decimal percentage (for deltas / cache hit rates).
export function pct1(ratio: number): string {
  return `${(ratio * 100).toFixed(1)}%`;
}

// compact abbreviates large counts: 1234 → 1.2k, 3_400_000 → 3.4M.
export function compact(n: number): string {
  const abs = Math.abs(n);
  if (abs >= 1e9) return `${(n / 1e9).toFixed(1)}B`;
  if (abs >= 1e6) return `${(n / 1e6).toFixed(1)}M`;
  if (abs >= 1e3) return `${(n / 1e3).toFixed(1)}k`;
  return String(n);
}

// ms formats a millisecond duration: 850 → 850ms, 2400 → 2.4s.
export function ms(n: number): string {
  if (n >= 1000) return `${(n / 1000).toFixed(1)}s`;
  return `${Math.round(n)}ms`;
}

export function shortDate(iso: string): string {
  if (!iso) return "-";
  return fmtShortDay(iso);
}

export function dateTime(iso: string): string {
  if (!iso) return "-";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return localeString(d, "en-US", {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}
