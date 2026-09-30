// dateRange - pure date helpers behind the DateRangePopover picker
// (calendar grid, one-click presets, day + time composition). Every
// function works in the BROWSER'S LOCAL ZONE (the picker shows local
// dates) and takes `now` explicitly so tests can pin it. No React, no DOM.

/** startOfDay returns local midnight of d's calendar day. */
export function startOfDay(d: Date): Date {
  return new Date(d.getFullYear(), d.getMonth(), d.getDate());
}

/** addDays returns d shifted by n calendar days (DST-safe: calendar math). */
export function addDays(d: Date, n: number): Date {
  return new Date(d.getFullYear(), d.getMonth(), d.getDate() + n, d.getHours(), d.getMinutes(), d.getSeconds(), d.getMilliseconds());
}

/** sameDay reports whether a and b fall on the same local calendar day. */
export function sameDay(a: Date, b: Date): boolean {
  return a.getFullYear() === b.getFullYear() && a.getMonth() === b.getMonth() && a.getDate() === b.getDate();
}

/** startOfWeek returns local midnight of the Monday on or before d. */
export function startOfWeek(d: Date): Date {
  const day = startOfDay(d);
  const dow = (day.getDay() + 6) % 7; // Monday = 0
  return addDays(day, -dow);
}

/**
 * monthGrid returns the 42 days (6 weeks, Monday-first) that cover the
 * given month, including the leading / trailing days of the neighbours.
 */
export function monthGrid(year: number, month: number): Date[] {
  const first = startOfWeek(new Date(year, month, 1));
  return Array.from({ length: 42 }, (_, i) => addDays(first, i));
}

/** END_OF_HOUR_MINUTE is the minute choice that means "to the end of that minute's hour". */
export const END_OF_HOUR_MINUTE = 59;

/** MINUTE_CHOICES are the minute options the time selects offer. */
export const MINUTE_CHOICES = [0, 5, 10, 15, 20, 25, 30, 35, 40, 45, 50, 55, END_OF_HOUR_MINUTE];

/**
 * atTime composes a local day with an hour and minute. For an END time,
 * minute 59 means through the end of that minute (hh:59:59.999), so
 * "23:59" covers the whole day.
 */
export function atTime(day: Date, hour: number, minute: number, isEnd = false): Date {
  const d = new Date(day.getFullYear(), day.getMonth(), day.getDate(), hour, minute);
  if (isEnd && minute === END_OF_HOUR_MINUTE) d.setSeconds(59, 999);
  return d;
}

/** nearestMinuteChoice snaps a minute to the closest offered choice at or below it. */
export function nearestMinuteChoice(minute: number): number {
  let best = 0;
  for (const m of MINUTE_CHOICES) if (m <= minute) best = m;
  return best;
}

/** A PresetRange is a resolved preset: `until` null means "now". */
export type PresetRange = { since: Date; until: Date | null };

/** DateRangePreset is one one-click preset row. `openEnded` presets end now. */
export type DateRangePreset = {
  key: string;
  label: string;
  openEnded: boolean;
  resolve: (now: Date) => PresetRange;
};

/** DATE_RANGE_PRESETS is the ordered preset table the picker renders. */
export const DATE_RANGE_PRESETS: DateRangePreset[] = [
  { key: "today", label: "Today", openEnded: true, resolve: (now) => ({ since: startOfDay(now), until: null }) },
  {
    key: "yesterday",
    label: "Yesterday",
    openEnded: false,
    resolve: (now) => ({ since: addDays(startOfDay(now), -1), until: startOfDay(now) }),
  },
  { key: "this-week", label: "This week", openEnded: true, resolve: (now) => ({ since: startOfWeek(now), until: null }) },
  {
    key: "last-week",
    label: "Last week",
    openEnded: false,
    resolve: (now) => ({ since: addDays(startOfWeek(now), -7), until: startOfWeek(now) }),
  },
  {
    key: "this-month",
    label: "This month",
    openEnded: true,
    resolve: (now) => ({ since: new Date(now.getFullYear(), now.getMonth(), 1), until: null }),
  },
  {
    key: "last-month",
    label: "Last month",
    openEnded: false,
    resolve: (now) => ({
      since: new Date(now.getFullYear(), now.getMonth() - 1, 1),
      until: new Date(now.getFullYear(), now.getMonth(), 1),
    }),
  },
];

/** fmtSpan renders a duration as a compact "3d 4h" / "5h 10m" / "45m". */
export function fmtSpan(ms: number): string {
  if (!Number.isFinite(ms) || ms <= 0) return "";
  const mins = Math.round(ms / 60_000);
  const d = Math.floor(mins / 1440);
  const h = Math.floor((mins % 1440) / 60);
  const m = mins % 60;
  if (d > 0) return h > 0 ? `${d}d ${h}h` : `${d}d`;
  if (h > 0) return m > 0 ? `${h}h ${m}m` : `${h}h`;
  return `${m}m`;
}
