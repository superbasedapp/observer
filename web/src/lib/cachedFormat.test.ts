import assert from "node:assert/strict";
import test from "node:test";

// A fixed, DST-observing default zone for the no-timeZone cases. Set before
// any formatter is built (the cached formatters are created lazily).
process.env.TZ = "America/Los_Angeles";

const {
  cachedDateTimeFormat,
  cachedNumberFormat,
  fmtShortDay,
  localeDateString,
  localeNumber,
  localeString,
  localeTimeString,
} = await import("../../../shared/lib/format.ts");

// The cached formatters in shared/lib/format.ts replace per-call
// toLocaleString / toLocaleDateString / toLocaleTimeString (perf audit
// 2026-09-29). They must be byte-identical to the native methods, including
// each method's option defaulting and its errors. This pins that over a
// grid of instants x option sets x locales.

const INSTANTS: (Date | number)[] = [
  new Date(0),
  new Date(NaN),
  new Date("not a date"),
  new Date("2026-03-08T09:59:59Z"), // US spring-forward edge (LA)
  new Date("2026-03-08T10:00:00Z"),
  new Date("2026-11-01T08:30:00Z"), // US fall-back ambiguous hour (LA)
  new Date("2026-03-29T01:00:00Z"), // EU spring-forward edge
  new Date("2026-10-25T00:59:59Z"),
  new Date("2024-02-29T12:00:00Z"), // leap day
  new Date("2026-09-29T23:59:59.999Z"),
  new Date("2026-01-01T00:00:00Z"),
  new Date("1900-01-01T00:00:00Z"),
  new Date("0001-01-01T00:00:00Z"),
  new Date(-62198755200000), // year -1
  new Date("9999-12-31T23:59:59Z"),
  new Date(8.64e15), // max representable instant
  new Date(-8.64e15),
  new Date(2026, 4, 15), // local midnight
  new Date("2026-05-15"), // UTC midnight (the chart bucket shape)
  1_758_000_000_000, // plain epoch-ms number
];

type Opts = Intl.DateTimeFormatOptions | undefined;

const OPTION_SETS: Opts[] = [
  undefined,
  {},
  { month: "short", day: "numeric" },
  { month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit", hour12: false },
  { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" },
  { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false },
  { month: "short", day: "numeric", timeZone: "UTC" },
  { year: "numeric", month: "short", day: "numeric" },
  { month: "short", day: "numeric", year: "2-digit" },
  { month: "short", day: "numeric", year: "numeric" },
  { hour: "2-digit", minute: "2-digit" },
  { hour: "2-digit", minute: "2-digit", second: "2-digit" },
  { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false },
  { hour12: false },
  { hour12: true },
  { hourCycle: "h23" },
  { timeZone: "UTC" },
  { timeZone: "America/New_York" },
  { timeZone: "Asia/Kolkata", hour: "numeric" },
  { timeZoneName: "short" },
  { timeZoneName: "long", timeZone: "Europe/Berlin" },
  { weekday: "long" },
  { weekday: "short", hour: "numeric" },
  { era: "short" },
  { year: "2-digit" },
  { month: "long" },
  { day: "numeric" },
  { second: "numeric" },
  { fractionalSecondDigits: 3 } as Intl.DateTimeFormatOptions,
  { dayPeriod: "short" } as Intl.DateTimeFormatOptions,
  { dateStyle: "medium" },
  { dateStyle: "full", timeZone: "UTC" },
  { timeStyle: "short" },
  { dateStyle: "short", timeStyle: "short" },
  { month: undefined, day: undefined },
  { month: "short", day: undefined },
  { hour: "numeric", hour12: true },
  { minute: "2-digit", timeZone: "Asia/Kathmandu" },
  { calendar: "gregory", numberingSystem: "latn" },
];

const LOCALES: (string | string[] | undefined)[] = [
  "en-US",
  undefined,
  "de-DE",
  [],
  ["fr-FR", "en-US"],
];

type Native = (d: Date, l: string | string[] | undefined, o: Opts) => string;
type Cached = (d: Date | number, l: string | string[] | undefined, o: Opts) => string;

// outcome returns the result or the thrown error's constructor name, so a
// combination the native method rejects must be rejected the same way.
function outcome(fn: () => string): string {
  try {
    return `ok:${fn()}`;
  } catch (e) {
    return `throw:${(e as Error).constructor.name}`;
  }
}

function checkMethod(name: string, native: Native, cached: Cached) {
  let compared = 0;
  // Twice: the second pass reads every formatter from the cache.
  for (let pass = 0; pass < 2; pass++) {
    for (const locale of LOCALES) {
      for (const opts of OPTION_SETS) {
        for (const inst of INSTANTS) {
          const d = typeof inst === "number" ? new Date(inst) : inst;
          const want = outcome(() => native(d, locale, opts));
          const got = outcome(() => cached(inst, locale, opts));
          assert.equal(
            got,
            want,
            `${name} pass=${pass} locale=${JSON.stringify(locale)} opts=${JSON.stringify(opts)} t=${d.getTime()}`,
          );
          compared++;
        }
      }
    }
  }
  return compared;
}

test("localeString is byte-identical to Date.prototype.toLocaleString", () => {
  const n = checkMethod(
    "toLocaleString",
    (d, l, o) => d.toLocaleString(l, o),
    (d, l, o) => localeString(d, l, o),
  );
  assert.ok(n > 1000);
});

test("localeDateString is byte-identical to Date.prototype.toLocaleDateString", () => {
  checkMethod(
    "toLocaleDateString",
    (d, l, o) => d.toLocaleDateString(l, o),
    (d, l, o) => localeDateString(d, l, o),
  );
});

test("localeTimeString is byte-identical to Date.prototype.toLocaleTimeString", () => {
  checkMethod(
    "toLocaleTimeString",
    (d, l, o) => d.toLocaleTimeString(l, o),
    (d, l, o) => localeTimeString(d, l, o),
  );
});

test("the defaulting differs per method exactly like the native methods", () => {
  const d = new Date("2026-05-15T13:04:05Z");
  const o = { timeZone: "UTC" } as const;
  // toLocaleString with no component fields = date AND time, whereas a
  // plain Intl.DateTimeFormat defaults to the date only.
  assert.equal(localeString(d, "en-US", o), "5/15/2026, 1:04:05 PM");
  assert.equal(new Intl.DateTimeFormat("en-US", o).format(d), "5/15/2026");
  assert.equal(localeDateString(d, "en-US", o), "5/15/2026");
  assert.equal(localeTimeString(d, "en-US", o), "1:04:05 PM");
  // A time-only field on toLocaleDateString still gets the date defaults.
  assert.equal(
    localeDateString(d, "en-US", { ...o, hour: "numeric" }),
    d.toLocaleDateString("en-US", { ...o, hour: "numeric" }),
  );
  // The rejected combinations throw the native TypeError.
  assert.throws(() => localeDateString(d, "en-US", { timeStyle: "short" }), TypeError);
  assert.throws(() => localeTimeString(d, "en-US", { dateStyle: "short" }), TypeError);
  assert.equal(localeString(new Date(NaN), "en-US", { month: "short" }), "Invalid Date");
});

test("localeNumber is byte-identical to Number.prototype.toLocaleString", () => {
  const values = [
    0, -0, 1, -1, 0.5, 1.005, 12.345678, 999.995, 1000, 1234.5, -9876543.21,
    1e21, 1e-7, 123456789012345, Number.MAX_SAFE_INTEGER, NaN, Infinity, -Infinity,
  ];
  const opts: (Intl.NumberFormatOptions | undefined)[] = [
    undefined,
    {},
    { maximumFractionDigits: 0 },
    { minimumFractionDigits: 2, maximumFractionDigits: 2 },
    { style: "currency", currency: "USD" },
    { style: "currency", currency: "USD", minimumFractionDigits: 4, maximumFractionDigits: 4 },
    { notation: "compact", maximumFractionDigits: 1 },
    { style: "percent", maximumFractionDigits: 1 },
    { useGrouping: false },
    { maximumSignificantDigits: 3 },
    { style: "unit", unit: "kilobyte" },
  ];
  for (let pass = 0; pass < 2; pass++) {
    for (const l of LOCALES) {
      for (const o of opts) {
        for (const v of values) {
          assert.equal(
            outcome(() => localeNumber(v, l, o)),
            outcome(() => v.toLocaleString(l, o)),
            `locale=${JSON.stringify(l)} opts=${JSON.stringify(o)} v=${v}`,
          );
        }
      }
    }
  }
});

test("formatters are shared per (locales, options), key order and undefined ignored", () => {
  const a = cachedDateTimeFormat("en-US", { month: "short", day: "numeric" });
  const b = cachedDateTimeFormat("en-US", { day: "numeric", month: "short", year: undefined });
  assert.equal(a, b);
  assert.notEqual(a, cachedDateTimeFormat("en-GB", { month: "short", day: "numeric" }));
  assert.notEqual(a, cachedDateTimeFormat("en-US", { month: "long", day: "numeric" }));
  // A number option and its string spelling are distinct keys (the value's
  // type is part of the key), never a collision.
  assert.notEqual(
    cachedNumberFormat("en-US", { maximumFractionDigits: 2 }),
    cachedNumberFormat("en-US", { maximumFractionDigits: "2" as unknown as number }),
  );
});

test("fmtShortDay matches the chart shortDate helpers it replaced", () => {
  const old = (s: string): string => {
    const d = new Date(s);
    if (Number.isNaN(d.getTime())) return s;
    return d.toLocaleDateString("en-US", { month: "short", day: "numeric" });
  };
  const inputs = [
    "2026-05-15",
    "2026-01-01",
    "2026-03-08",
    "2026-11-01",
    "2024-02-29",
    "2026-05-15T00:00:00Z",
    "2026-05-15T23:30:00-07:00",
    "2026-05-15 10:00",
    "",
    "garbage",
    "Other",
    "1970-01-01",
  ];
  for (let pass = 0; pass < 2; pass++) {
    for (const s of inputs) assert.equal(fmtShortDay(s), old(s), s);
  }
});
