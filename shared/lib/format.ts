// Pure formatting helpers — no React, no DOM. Reused across cards,
// tables, tooltips. Locale is locked to en-US for now since the
// current dashboard is en-US only.

const compactFmt = new Intl.NumberFormat("en-US", {
  notation: "compact",
  maximumFractionDigits: 1,
});

const intFmt = new Intl.NumberFormat("en-US");

const currencyFmt = new Intl.NumberFormat("en-US", {
  style: "currency",
  currency: "USD",
  maximumFractionDigits: 2,
});

const currencyPreciseFmt = new Intl.NumberFormat("en-US", {
  style: "currency",
  currency: "USD",
  minimumFractionDigits: 4,
  maximumFractionDigits: 4,
});

export function fmtInt(n: number | null | undefined): string {
  if (n == null || !Number.isFinite(n)) return "—";
  return intFmt.format(Math.round(n));
}

export function fmtCompact(n: number | null | undefined): string {
  if (n == null || !Number.isFinite(n)) return "—";
  return compactFmt.format(n);
}

export function fmtUSD(n: number | null | undefined, precise = false): string {
  if (n == null || !Number.isFinite(n)) return "—";
  return (precise ? currencyPreciseFmt : currencyFmt).format(n);
}

// fmtTaskUSD is the Tasks-feature (docs/task-tracking.md) currency
// formatter: 2 decimals normally, escalating to 4 only for sub-cent
// amounts that would otherwise round to $0.00 — the rounding-to-zero
// anti-pattern the feature's own audit flagged. Shared by the Session
// Detail Tasks tab and the Analysis page's task-tracking rollup section
// so the two surfaces can never format the same number two different
// ways.
export function fmtTaskUSD(n: number | null | undefined): string {
  if (n == null || !Number.isFinite(n)) return "—";
  if (n > 0 && n < 0.01) return fmtUSD(n, true);
  return fmtUSD(n);
}

export function fmtPct(
  n: number | null | undefined,
  digits = 1,
  fromFraction = true,
): string {
  if (n == null || !Number.isFinite(n)) return "—";
  const v = fromFraction ? n * 100 : n;
  return `${v.toFixed(digits)}%`;
}

export function fmtBytes(n: number | null | undefined): string {
  if (n == null || !Number.isFinite(n) || n < 0) return "—";
  if (n < 1024) return `${n} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(v < 10 ? 1 : 0)} ${units[i]}`;
}

export function fmtDuration(ms: number | null | undefined): string {
  if (ms == null || !Number.isFinite(ms) || ms < 0) return "—";
  if (ms < 1000) return `${Math.round(ms)}ms`;
  const s = ms / 1000;
  if (s < 60) return `${s.toFixed(1)}s`;
  const m = s / 60;
  if (m < 60) return `${m.toFixed(1)}m`;
  const h = m / 60;
  return `${h.toFixed(1)}h`;
}

// fmtClock renders an RFC3339/ISO timestamp as a compact local wall-clock
// time for table cells — e.g. "Jun 25, 14:32:10" (24h, locale month). Used
// where a row needs the ACTUAL capture time, not just elapsed/duration.
// Returns "—" for empty/unparseable input.
export function fmtClock(iso: string | null | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString("en-US", {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  });
}

// fmtElapsed renders a whole-second duration compactly: "42s" · "3m 20s" ·
// "2h 15m". Returns "-" for null/negative/non-finite input. Promoted out of
// web/src/lib/cockpit.ts (which now re-exports it) so the shared session-detail
// components can render task elapsed times without importing an app.
export function fmtElapsed(secs: number | null | undefined): string {
  if (secs == null || !Number.isFinite(secs) || secs < 0) return "-";
  if (secs < 60) return `${secs}s`;
  const m = Math.floor(secs / 60);
  const s = secs % 60;
  if (m < 60) return s ? `${m}m ${s}s` : `${m}m`;
  const h = Math.floor(m / 60);
  const rm = m % 60;
  return rm ? `${h}h ${rm}m` : `${h}h`;
}

// ---------------------------------------------------------------------------
// Timestamps and identifiers for READERS (2026-09-16). Every application
// surface renders an instant or an opaque id through one of these, never a
// raw RFC3339 string or a bare 32-hex/uuid token. Locale locked to en-US like
// the rest of this file; times are the reader's local wall clock.
// ---------------------------------------------------------------------------

const dateTimeFmt = new Intl.DateTimeFormat("en-US", {
  year: "numeric",
  month: "short",
  day: "numeric",
  hour: "2-digit",
  minute: "2-digit",
  hour12: false,
});

const dateOnlyFmt = new Intl.DateTimeFormat("en-US", {
  year: "numeric",
  month: "short",
  day: "numeric",
});

// parseInstant parses an RFC3339/ISO instant OR a bare calendar day
// (YYYY-MM-DD). A bare day is read as a LOCAL day, not UTC midnight, so
// "2026-09-12" never renders as Sep 11 for a reader west of Greenwich.
function parseInstant(iso: string): Date | null {
  const s = iso.trim();
  if (!s) return null;
  const day = /^(\d{4})-(\d{2})-(\d{2})$/.exec(s);
  const d = day
    ? new Date(Number(day[1]), Number(day[2]) - 1, Number(day[3]))
    : new Date(s);
  return Number.isNaN(d.getTime()) ? null : d;
}

// fmtDateTime renders an instant with its year and minute precision:
// "Sep 12, 2026, 20:10". Returns "—" for empty input and the raw string for
// an unparseable one (never invents a value).
export function fmtDateTime(iso: string | null | undefined): string {
  if (!iso) return "—";
  const d = parseInstant(iso);
  return d ? dateTimeFmt.format(d) : iso;
}

// fmtDateOnly renders the calendar day of an instant or a bare YYYY-MM-DD:
// "Sep 12, 2026".
export function fmtDateOnly(iso: string | null | undefined): string {
  if (!iso) return "—";
  const d = parseInstant(iso);
  return d ? dateOnlyFmt.format(d) : iso;
}

// fmtDateRange renders two days as one span, eliding the repeated parts:
// "Sep 12–14, 2026" · "Sep 12 – Oct 3, 2026" · "Dec 30, 2025 – Jan 2, 2026" ·
// a single day when both ends fall on it.
export function fmtDateRange(
  from: string | null | undefined,
  to: string | null | undefined,
): string {
  const a = from ? parseInstant(from) : null;
  const b = to ? parseInstant(to) : null;
  if (!a && !b) return "—";
  if (!a || !b) return fmtDateOnly(from || to);
  const sameYear = a.getFullYear() === b.getFullYear();
  const sameMonth = sameYear && a.getMonth() === b.getMonth();
  if (sameMonth && a.getDate() === b.getDate()) return dateOnlyFmt.format(a);
  const md = new Intl.DateTimeFormat("en-US", { month: "short", day: "numeric" });
  if (sameMonth) return `${md.format(a)}–${b.getDate()}, ${b.getFullYear()}`;
  if (sameYear) return `${md.format(a)} – ${md.format(b)}, ${b.getFullYear()}`;
  return `${dateOnlyFmt.format(a)} – ${dateOnlyFmt.format(b)}`;
}

// fmtRelative renders how far an instant is from now: "just now" · "5 min
// ago" · "3 hours ago" · "2 days ago" · "in 6 days". Beyond 30 days either
// way it falls back to fmtDateOnly, because "412 days ago" reads worse than
// the date. `now` is injectable for tests.
export function fmtRelative(
  iso: string | null | undefined,
  now: number = Date.now(),
): string {
  if (!iso) return "—";
  const d = parseInstant(iso);
  if (!d) return iso;
  const diff = d.getTime() - now;
  const abs = Math.abs(diff);
  const past = diff < 0;
  const unit = (n: number, w: string) =>
    past ? `${n} ${w}${n === 1 ? "" : "s"} ago` : `in ${n} ${w}${n === 1 ? "" : "s"}`;
  if (abs < 45_000) return "just now";
  if (abs < 60 * 60_000) return unit(Math.round(abs / 60_000), "min");
  if (abs < 24 * 60 * 60_000) return unit(Math.round(abs / 3_600_000), "hour");
  const days = Math.round(abs / 86_400_000);
  if (days <= 30) return unit(days, "day");
  return fmtDateOnly(iso);
}

// fmtYearMonth renders a bare "YYYY-MM" (or any instant) as its calendar
// month: "September 2026". A bare year-month is read as a LOCAL month, the
// same discipline parseInstant applies to a bare day.
export function fmtYearMonth(value: string | null | undefined): string {
  if (!value) return "—";
  const s = value.trim();
  const ym = /^(\d{4})-(\d{2})$/.exec(s);
  const d = ym ? new Date(Number(ym[1]), Number(ym[2]) - 1, 1) : parseInstant(s);
  if (!d || Number.isNaN(d.getTime())) return value;
  return new Intl.DateTimeFormat("en-US", { year: "numeric", month: "long" }).format(d);
}

// fmtShortId abbreviates an opaque identifier for a table cell or a caption:
// the first `keep` characters plus an ellipsis. A short id is returned whole.
// Pair it with the full id in a title/tooltip or a CopyOnClick so nothing is
// lost, only hidden.
export function fmtShortId(id: string | null | undefined, keep = 8): string {
  if (!id) return "—";
  const s = id.trim();
  return s.length <= keep + 1 ? s : s.slice(0, keep) + "…";
}
