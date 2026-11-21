// The AI apps explorer pieces the design pass rebuilt on the shared
// primitives (2026-11-21): the filter chips' option list, the chip-height
// search, the live tail and the saved views, rendered with react-dom/server.

import { test } from "node:test";
import assert from "node:assert/strict";
import { renderToStaticMarkup } from "react-dom/server";
import { ExplorerSearchInput, explorerValueOptions } from "@shared/components/planea/explorerFilters";
import { LiveTailPanel } from "@shared/components/planea/liveTail";
import { SavedViewsBar } from "@shared/components/planea/savedViews";

const noop = () => undefined;

test("explorerValueOptions: any first, values once, empty keys dropped", () => {
  const opts = explorerValueOptions(["user-ada", "", "user-bo", "user-ada"], "", "Any end user");
  assert.deepEqual(
    opts.map((o) => o.value),
    ["", "user-ada", "user-bo"],
  );
  assert.equal(opts[0].label, "Any end user");
});

test("explorerValueOptions: a current value the list lacks stays selectable", () => {
  const opts = explorerValueOptions(["svc-a"], "svc-gone", "Any service");
  assert.deepEqual(
    opts.map((o) => o.value),
    ["", "svc-gone", "svc-a"],
  );
});

test("ExplorerSearchInput is a search form with a clear button only when set", () => {
  const empty = renderToStaticMarkup(<ExplorerSearchInput value="" onSubmit={noop} placeholder="Search trace id or name" />);
  assert.match(empty, /role="search"/);
  assert.doesNotMatch(empty, /Clear the search/);
  const set = renderToStaticMarkup(<ExplorerSearchInput value="turn-3" onSubmit={noop} placeholder="Search trace id or name" />);
  assert.match(set, /Clear the search/);
});

test("LiveTailPanel: status through the vocabulary, an unpriced cost is a dash", () => {
  const html = renderToStaticMarkup(
    <LiveTailPanel
      rows={[{ trace_id: "t1", root_name: "turn-1", status: "ok", cost_usd: undefined, duration_ms: 20, started_at: "2026-11-20T10:00:00Z" }]}
      state="live"
      onTogglePause={noop}
      onClear={noop}
    />,
  );
  assert.match(html, /turn-1/);
  assert.match(html, />ok</);
  assert.doesNotMatch(html, /\$0\.00/);
  assert.match(html, /Pause/);
});

test("LiveTailPanel: an empty tail says what it waits for", () => {
  const html = renderToStaticMarkup(<LiveTailPanel rows={[]} state="paused" onTogglePause={noop} onClear={noop} />);
  assert.match(html, /Waiting for new traces that match the filters/);
  assert.match(html, /Resume/);
});

test("SavedViewsBar: a machine offers no sharing choice and needs a name to save", () => {
  const html = renderToStaticMarkup(<SavedViewsBar views={[]} onApply={noop} onSave={noop} onDelete={noop} />);
  assert.match(html, /No saved views/);
  assert.doesNotMatch(html, /Share with/);
  assert.match(html, /<button(?=[^>]*type="submit")(?=[^>]*disabled)/);
});
