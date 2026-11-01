// R-183: a dock tile whose tool exits within a second of launch follows the
// run's end at once from the daemon's status stream, instead of reading
// LIVE until its own socket notices (about a minute on the Windows run).
// Rendered with react-dom/server under node's test runner
// (scripts/test-components.mjs).

import { test } from "node:test";
import assert from "node:assert/strict";
import { renderToStaticMarkup } from "react-dom/server";
import { foldAgentExits, isLiveStatus, type Status } from "@/lib/launchStatus";

// TileLabel is the tile header's live-or-ended reading (WorkspaceGrid's
// TerminalTile shows "live" while isLiveStatus holds).
function TileLabel({ status }: { status: Status | undefined }) {
  return <span data-testid="tile-label">{isLiveStatus(status) ? "live" : (status ?? "connecting")}</span>;
}

test("a trusted exit on the stream ends a live tile at once", () => {
  const prev: Record<string, Status> = { t1: "open", t2: "open" };
  const next = foldAgentExits(prev, ["t1", "t2"], { t1: { status: "exited", confidence: "trusted" } });
  assert.equal(next.t1, "exited");
  assert.equal(next.t2, "open", "a tile whose run did not end stays live");
  assert.match(renderToStaticMarkup(<TileLabel status={prev.t1} />), />live</);
  assert.match(renderToStaticMarkup(<TileLabel status={next.t1} />), />exited</);
});

test("a tile still connecting when its run ended reads ended", () => {
  const next = foldAgentExits({}, ["t1"], { t1: { status: "exited", confidence: "trusted" } });
  assert.equal(next.t1, "exited");
  assert.match(renderToStaticMarkup(<TileLabel status={next.t1} />), />exited</);
});

test("only a trusted exit of a dock token moves a tile", () => {
  const prev: Record<string, Status> = { t1: "open", t2: "reconnecting", t3: "error" };
  const same = foldAgentExits(prev, ["t1", "t2", "t3"], {
    t1: { status: "exited", confidence: "hint" },
    t2: { status: "working", confidence: "trusted" },
    t3: { status: "exited", confidence: "trusted" },
    other: { status: "exited", confidence: "trusted" },
  });
  assert.equal(same, prev, "nothing changed, so the same object comes back (no render loop)");
  assert.equal(same.t3, "error", "an error tile keeps its error");
  assert.equal("other" in same, false, "a handle that is not a dock tile is never added");
});
