import assert from "node:assert/strict";
import test from "node:test";
import {
  FILTER_DEFAULTS,
  FILTER_PARAMS,
  applyFilterParams,
  parseFilterParams,
  reconcileFromUrl,
  sameUrlFilters,
  serializeFilterParams,
  type UrlFilters,
} from "./filterUrl.ts";

const RANGE = { since: "2026-07-10T00:00:00.000Z", until: "2026-07-16T00:00:00.000Z" };

function f(over: Partial<UrlFilters> = {}): UrlFilters {
  return { ...FILTER_DEFAULTS, customRange: { ...FILTER_DEFAULTS.customRange }, ...over };
}

// One case per table row: a valid value is read, a junk value is ignored.
const rowCases: Array<{
  param: string;
  good: string;
  search: string;
  want: Partial<UrlFilters>;
  junk: string;
}> = [
  { param: "window", good: "7d", search: "?window=7d", want: { win: "7d" }, junk: "?window=8d" },
  {
    param: "since",
    good: RANGE.since,
    search: `?window=custom&since=${RANGE.since}`,
    want: { win: "custom", customRange: { since: RANGE.since, until: "" } },
    junk: "?window=custom&since=2026-07-10",
  },
  {
    param: "until",
    good: RANGE.until,
    search: `?window=custom&since=${RANGE.since}&until=${RANGE.until}`,
    want: { win: "custom", customRange: RANGE },
    junk: `?window=custom&since=${RANGE.since}&until=2026-07-01T00:00:00Z`,
  },
  { param: "tool", good: "claude-code", search: "?tool=claude-code", want: { tool: "claude-code" }, junk: "?tool=%3Cscript%3E" },
  {
    param: "proj",
    good: "/home/me/repo",
    search: "?proj=%2Fhome%2Fme%2Frepo",
    want: { project: "/home/me/repo" },
    junk: "?proj=%0Abad",
  },
  {
    param: "model",
    good: "openrouter/qwen/qwen3-coder:free",
    search: "?model=openrouter%2Fqwen%2Fqwen3-coder%3Afree",
    want: { model: "openrouter/qwen/qwen3-coder:free" },
    junk: "?model=%0Abad",
  },
  { param: "search", good: "abc", search: "?search=abc", want: { query: "abc" }, junk: "?search=%20%20" },
  { param: "gran", good: "1h", search: "?gran=1h", want: { gran: "1h" }, junk: "?gran=2h" },
];

test("every table row has a case", () => {
  assert.deepEqual(
    rowCases.map((c) => c.param),
    FILTER_PARAMS.map((r) => r.param),
  );
});

for (const c of rowCases) {
  test(`row ${c.param}: valid value parses`, () => {
    assert.deepEqual(parseFilterParams(c.search), c.want);
  });
  test(`row ${c.param}: invalid value is ignored`, () => {
    const got = parseFilterParams(c.junk);
    // junk never yields a guessed value: the custom rows drop the whole
    // custom window (a bad range is not a window at all).
    assert.equal(Object.keys(got).length, 0, JSON.stringify(got));
  });
}

test("since/until without window=custom are ignored", () => {
  assert.deepEqual(parseFilterParams(`?since=${RANGE.since}&until=${RANGE.until}`), {});
});

test("custom range values are canonicalized to UTC", () => {
  assert.deepEqual(parseFilterParams("?window=custom&since=2026-07-10T02:00:00%2B02:00"), {
    win: "custom",
    customRange: { since: "2026-07-10T00:00:00.000Z", until: "" },
  });
});

test("junk input: empty, garbage, unknown params", () => {
  assert.deepEqual(parseFilterParams(""), {});
  assert.deepEqual(parseFilterParams("?"), {});
  assert.deepEqual(parseFilterParams("?&&=&window"), {});
  assert.deepEqual(parseFilterParams("?foo=bar&window=ALL&tool="), {});
  assert.deepEqual(parseFilterParams("?search=" + "x".repeat(201)), {});
});

test("defaults serialize to no params", () => {
  for (const v of Object.values(serializeFilterParams(f()))) assert.equal(v, null);
  assert.equal(applyFilterParams("", f()), "");
});

test("custom range is only written under window=custom", () => {
  assert.equal(applyFilterParams("", f({ win: "7d", customRange: RANGE })), "?window=7d");
});

const roundTrips: UrlFilters[] = [
  f({ win: "1h" }),
  f({ win: "all", tool: "codex" }),
  f({ win: "custom", customRange: RANGE, project: "/srv/a b&c", query: "fix bug" }),
  f({ win: "custom", customRange: { since: RANGE.since, until: "" } }),
  f({ tool: "cursor", project: "/x", query: "a=b&c" }),
  f({ win: "7d", tool: "claude-code", model: "claude-opus-4-7" }),
  f({ model: "openrouter/qwen/qwen3-coder:free" }),
];
for (const s of roundTrips) {
  test(`round-trip ${JSON.stringify(s)}`, () => {
    const search = applyFilterParams("", s);
    const back = reconcileFromUrl(f(), search, "pop");
    assert.ok(sameUrlFilters(back, s), `${search} -> ${JSON.stringify(back)}`);
  });
}

test("does not touch unrelated params (and keeps their order)", () => {
  const search = "?session=abc&tab=cost&section=proxy&q=hello&project=12&root=%2Fr";
  const out = applyFilterParams(search, f({ win: "7d", tool: "codex" }));
  assert.equal(out, "?session=abc&tab=cost&section=proxy&q=hello&project=12&root=%2Fr&window=7d&tool=codex");
  // Resetting to defaults removes only our params.
  assert.equal(applyFilterParams(out, f()), search);
});

test("page-owned params are not read as filters", () => {
  assert.deepEqual(parseFilterParams("?project=12&q=hello&tab=x&root=%2Fr"), {});
});

// The Code security build of 2026-11-06 wrote a Findings project (a root
// hash) under proj=, and the bar adopted it: the Projects page then showed
// the raw hash in the Project chip and "No project has activity". A root
// hash is never a root path, so a link that still carries one is ignored
// and the write-back drops it from the URL.
test("proj: a project root hash is not a project filter", () => {
  const hash = "ad3060312d786b3d154dacb6caf3e90257a6d58e9c89f2c9ce063282a8fac037";
  const search = `?project=345&proj=${hash}`;
  assert.deepEqual(parseFilterParams(search), {});
  assert.deepEqual(parseFilterParams(`?proj=${hash.toUpperCase()}`), {});
  assert.deepEqual(reconcileFromUrl(f(), search, "pop"), f());
  assert.deepEqual(reconcileFromUrl(f(), search, "push"), f());
  assert.equal(applyFilterParams(search, f()), "?project=345");
  // A root path is still a project filter, and so is a synthetic cloud root.
  assert.deepEqual(parseFilterParams("?proj=%2Fmnt%2Fd%2Fprogramsx%2Fsuperbased-observer"), {
    project: "/mnt/d/programsx/superbased-observer",
  });
  assert.deepEqual(parseFilterParams("?proj=cloud%3Agithub.com%2Fa%2Fb"), { project: "cloud:github.com/a/b" });
});

test("reconcile pop: absent fields take the fallback", () => {
  const cur = f({ win: "7d", tool: "codex", query: "x", customRange: RANGE });
  const got = reconcileFromUrl(cur, "?window=14d", "pop");
  assert.deepEqual(got, f({ win: "14d", customRange: RANGE }));
});

test("reconcile first load: URL, then stored preference", () => {
  const stored = f({ win: "90d" });
  assert.equal(reconcileFromUrl(f(), "", "pop", stored).win, "90d");
  assert.equal(reconcileFromUrl(f(), "?window=1d", "pop", stored).win, "1d");
  assert.equal(reconcileFromUrl(f(), "?window=nope", "pop", stored).win, "90d");
});

test("reconcile push: URL fields win, absent fields follow the user", () => {
  const cur = f({ win: "7d", tool: "codex" });
  assert.deepEqual(reconcileFromUrl(cur, "?session=abc", "push"), cur);
  assert.deepEqual(reconcileFromUrl(cur, "?tool=cursor", "push"), f({ win: "7d", tool: "cursor" }));
});

test("model: a deep link sets it, all/absent is the unfiltered default", () => {
  assert.deepEqual(reconcileFromUrl(f(), "?model=gpt-5.1", "pop"), f({ model: "gpt-5.1" }));
  // "all" is the default, so it is never written back to the URL.
  assert.equal(applyFilterParams("", f({ model: "all" })), "");
  assert.equal(applyFilterParams("", f({ model: "gpt-5.1" })), "?model=gpt-5.1");
  // An in-app navigation carries the active model filter along.
  const cur = f({ model: "claude-opus-4-7" });
  assert.deepEqual(reconcileFromUrl(cur, "?session=abc", "push"), cur);
});
