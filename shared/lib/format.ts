// Pure formatting helpers — no React, no DOM. Reused across cards,
// tables, tooltips. Locale is locked to en-US for now since the
// current dashboard is en-US only.

// ---------------------------------------------------------------------------
// Cached Intl formatters (perf audit 2026-09-29).
//
// Date.prototype.toLocaleString / toLocaleDateString / toLocaleTimeString and
// Number.prototype.toLocaleString build a brand-new Intl formatter on EVERY
// call whenever an options object is passed (the engine only caches the
// no-options form), and building one costs far more than formatting with it.
// On a 50-row table or a chart re-render that was a top self-time item
// (Sessions fmtTimestamp ~370 ms per load, chart shortDate ~700 ms).
//
// These helpers keep ONE formatter per (locales, options) and reproduce the
// native methods byte-for-byte, including their option defaulting (ECMA-402
// CreateDateTimeFormat "required"/"defaults"), which differs per method:
//
//   new Intl.DateTimeFormat  required any,  defaults date
//   toLocaleString           required any,  defaults all (date AND time)
//   toLocaleDateString       required date, defaults date
//   toLocaleTimeString       required time, defaults time
//
// An invalid Date renders "Invalid Date" (the native methods' output; a
// formatter's format() would throw). A formatter captures the default time
// zone when it is built, like every module-level formatter in this file.
// Parity with the native methods is pinned by web/src/lib/cachedFormat.test.ts.
// ---------------------------------------------------------------------------

type Locales = string | readonly string[] | undefined;
type DateFieldOptions = Intl.DateTimeFormatOptions & {
  // Spec-listed fields, typed loosely so an older lib.d.ts still compiles.
  dayPeriod?: unknown;
  fractionalSecondDigits?: unknown;
};

const FORMATTER_CACHE_MAX = 256;
const dtfCache = new Map<string, Intl.DateTimeFormat>();
const nfCache = new Map<string, Intl.NumberFormat>();

// cacheKey serializes (locales, options) stably: sorted keys, undefined
// values dropped (the spec reads an undefined option as absent).
function cacheKey(locales: Locales, options: object | undefined): string {
  let key = locales == null ? "" : typeof locales === "string" ? locales : locales.join(",");
  key += "|";
  if (options) {
    const o = options as Record<string, unknown>;
    const keys = Object.keys(o).sort();
    for (const k of keys) {
      const v = o[k];
      if (v === undefined) continue;
      key += `${k}=${String(v)}:${typeof v};`;
    }
  }
  return key;
}

function remember<V>(cache: Map<string, V>, key: string, make: () => V): V {
  let v = cache.get(key);
  if (v === undefined) {
    v = make();
    // Bounded: call sites use a handful of fixed option sets, so the cap is
    // a leak guard, not an eviction policy.
    if (cache.size >= FORMATTER_CACHE_MAX) cache.clear();
    cache.set(key, v);
  }
  return v;
}

/** cachedDateTimeFormat returns a shared `new Intl.DateTimeFormat(locales, options)`. */
export function cachedDateTimeFormat(
  locales?: Locales,
  options?: Intl.DateTimeFormatOptions,
): Intl.DateTimeFormat {
  return remember(dtfCache, cacheKey(locales, options), () =>
    new Intl.DateTimeFormat(locales as string | string[] | undefined, options),
  );
}

/** cachedNumberFormat returns a shared `new Intl.NumberFormat(locales, options)`. */
export function cachedNumberFormat(
  locales?: Locales,
  options?: Intl.NumberFormatOptions,
): Intl.NumberFormat {
  return remember(nfCache, cacheKey(locales, options), () =>
    new Intl.NumberFormat(locales as string | string[] | undefined, options),
  );
}

type RequiredFields = "date" | "time" | "any";
type DefaultFields = "date" | "time" | "all";

const DATE_FIELDS = ["weekday", "year", "month", "day"] as const;
const TIME_FIELDS = ["dayPeriod", "hour", "minute", "second", "fractionalSecondDigits"] as const;

// withDateDefaults applies ECMA-402's option defaulting for one of the
// Date.prototype methods, returning options that a plain Intl.DateTimeFormat
// (required any, defaults date) formats identically with. Returns null for
// the combinations the native method rejects with a TypeError, so the caller
// defers to the native method and throws exactly as it would.
function withDateDefaults(
  options: Intl.DateTimeFormatOptions | undefined,
  required: RequiredFields,
  defaults: DefaultFields,
): Intl.DateTimeFormatOptions | null {
  const o = (options ?? {}) as DateFieldOptions;
  if (required === "date" && o.timeStyle !== undefined) return null;
  if (required === "time" && o.dateStyle !== undefined) return null;
  let needDefaults = o.dateStyle === undefined && o.timeStyle === undefined;
  if (needDefaults && (required === "date" || required === "any")) {
    for (const f of DATE_FIELDS) if (o[f] !== undefined) needDefaults = false;
  }
  if (needDefaults && (required === "time" || required === "any")) {
    for (const f of TIME_FIELDS) if (o[f] !== undefined) needDefaults = false;
  }
  if (!needDefaults) return options ?? {};
  const out: Intl.DateTimeFormatOptions = { ...options };
  if (defaults === "date" || defaults === "all") {
    out.year = "numeric";
    out.month = "numeric";
    out.day = "numeric";
  }
  if (defaults === "time" || defaults === "all") {
    out.hour = "numeric";
    out.minute = "numeric";
    out.second = "numeric";
  }
  return out;
}

type DateMethod = "string" | "date" | "time";

const METHOD_FIELDS: Record<DateMethod, [RequiredFields, DefaultFields]> = {
  string: ["any", "all"],
  date: ["date", "date"],
  time: ["time", "time"],
};

// One memo per (method, locales, options): the defaulting above runs once.
// null marks a combination the native method throws on.
const methodCache = new Map<string, Intl.DateTimeFormat | null>();

function dateMethod(
  method: DateMethod,
  value: Date | number,
  locales: Locales,
  options: Intl.DateTimeFormatOptions | undefined,
): string {
  const d = typeof value === "number" ? new Date(value) : value;
  const key = method + "#" + cacheKey(locales, options);
  let fmt = methodCache.get(key);
  if (fmt === undefined) {
    const [required, defaults] = METHOD_FIELDS[method];
    const eff = withDateDefaults(options, required, defaults);
    fmt = eff == null ? null : cachedDateTimeFormat(locales, eff);
    if (methodCache.size >= FORMATTER_CACHE_MAX) methodCache.clear();
    methodCache.set(key, fmt);
  }
  if (fmt === null) {
    const loc = locales as string | string[] | undefined;
    if (method === "string") return d.toLocaleString(loc, options);
    if (method === "date") return d.toLocaleDateString(loc, options);
    return d.toLocaleTimeString(loc, options);
  }
  if (Number.isNaN(d.getTime())) return "Invalid Date";
  return fmt.format(d);
}

/** Byte-identical, cached `date.toLocaleString(locales, options)`. */
export function localeString(
  date: Date | number,
  locales?: Locales,
  options?: Intl.DateTimeFormatOptions,
): string {
  return dateMethod("string", date, locales, options);
}

/** Byte-identical, cached `date.toLocaleDateString(locales, options)`. */
export function localeDateString(
  date: Date | number,
  locales?: Locales,
  options?: Intl.DateTimeFormatOptions,
): string {
  return dateMethod("date", date, locales, options);
}

/** Byte-identical, cached `date.toLocaleTimeString(locales, options)`. */
export function localeTimeString(
  date: Date | number,
  locales?: Locales,
  options?: Intl.DateTimeFormatOptions,
): string {
  return dateMethod("time", date, locales, options);
}

/** Byte-identical, cached `n.toLocaleString(locales, options)` for a number. */
export function localeNumber(
  n: number,
  locales?: Locales,
  options?: Intl.NumberFormatOptions,
): string {
  return cachedNumberFormat(locales, options).format(n);
}

// fmtShortDay's per-input memo: a chart asks for the same few dozen bucket
// labels (axis ticks + tooltip) on every render.
const shortDayMemo = new Map<string, string>();

/**
 * fmtShortDay renders an instant (typically an ISO day bucket "2026-05-15")
 * as "May 15" in the reader's local time zone, or returns the input unchanged
 * when it does not parse:
 * `new Date(s).toLocaleDateString("en-US", { month: "short", day: "numeric" })`.
 * Charts no longer use it: every time-series axis/tooltip labels its buckets
 * through shared/lib/granularity.ts fmtBucket, which also handles sub-day
 * and week buckets and reads a "YYYY-MM-DD" key as the LOCAL date (this
 * helper reads it as UTC midnight). Kept for non-chart date stamps.
 */
export function fmtShortDay(s: string): string {
  let out = shortDayMemo.get(s);
  if (out !== undefined) return out;
  const d = new Date(s);
  out = Number.isNaN(d.getTime())
    ? s
    : localeDateString(d, "en-US", { month: "short", day: "numeric" });
  if (shortDayMemo.size >= 2048) shortDayMemo.clear();
  shortDayMemo.set(s, out);
  return out;
}

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
  return localeString(d, "en-US", {
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
  const md = cachedDateTimeFormat("en-US", { month: "short", day: "numeric" });
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
  return cachedDateTimeFormat("en-US", { year: "numeric", month: "long" }).format(d);
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
