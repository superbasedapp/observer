import assert from "node:assert/strict";
import test from "node:test";

import { linkedCalls, panelState, type SessionMCPCallsLike } from "../../../shared/lib/mcpCalls.ts";

// The node SessionDetailPanel's MCP calls tab (Agent Access P11(a)) renders
// the shared panel over GET /api/session/<id>/mcp-calls. These pin the frame
// the tab shows before any row: loading, the error, and an empty state that
// says WHY it is empty (the unlinked count is stated, never listed). The
// wording rules of the rows are pinned by web2/src/lib/mcpCalls.test.ts.

function result(over: Partial<SessionMCPCallsLike>): SessionMCPCallsLike {
  return {
    session_id: "s-1",
    calls: [],
    totals: { calls: 0, exact: 0, inferred: 0, unlinked: 0, folded_duplicates: 0 },
    truncated: false,
    ...over,
  };
}

test("panelState: loading before the first response, error wins", () => {
  assert.deepEqual(panelState(null, true, null), { kind: "loading" });
  assert.deepEqual(panelState(result({}), false, "boom"), { kind: "error", message: "boom" });
  assert.equal(panelState(null, false, null).kind, "empty");
});

test("panelState: an empty session says no call could be tied, unless calls were unlinked", () => {
  const none = panelState(result({}), false, null);
  assert.equal(none.kind, "empty");
  assert.match(none.kind === "empty" ? none.message : "", /No MCP calls are tied to this session/);
  const unlinked = panelState(
    result({ totals: { calls: 0, exact: 0, inferred: 0, unlinked: 2, folded_duplicates: 0 } }),
    false,
    null,
  );
  assert.equal(unlinked.kind, "empty");
  assert.match(unlinked.kind === "empty" ? unlinked.message : "", /^2 MCP calls could not be tied/);
});

test("panelState: rows only when a linked call exists; a 'none' call alone is still empty", () => {
  const onlyNone = result({
    calls: [
      {
        sources: ["node"],
        ts: 1,
        completed: false,
        correlation: { confidence: "none", level: "none", method: "no_session_anchor" },
      },
    ],
  });
  assert.equal(panelState(onlyNone, false, null).kind, "empty");
  assert.deepEqual(linkedCalls(onlyNone), []);
  const linked = result({
    calls: [
      {
        sources: ["node"],
        ts: 1,
        completed: true,
        correlation: { confidence: "exact", level: "turn", method: "turn_ref", turn_index: 3 },
      },
    ],
  });
  assert.deepEqual(panelState(linked, false, null), { kind: "rows" });
});
