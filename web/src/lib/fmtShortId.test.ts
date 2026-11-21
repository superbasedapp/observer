import { test } from "node:test";
import assert from "node:assert/strict";
import { fmtShortId } from "../../../shared/lib/format.ts";

// fmtShortId: a subagent session id keeps both halves, so the subagents of
// one session do not all read as their parent's 8 characters.
test("fmtShortId: plain ids, short ids, empty and subagent ids", () => {
  const cases: { id: string | null; want: string }[] = [
    { id: "00392aa6-02ee-46bc-b2c3-3e502e966e21", want: "00392aa6…" },
    { id: "abc", want: "abc" },
    { id: null, want: "—" },
    { id: "00392aa6-02ee-46bc-b2c3-3e502e966e21:agent:a0d28add704e2a16c", want: "00392aa6… · subagent a0d28add…" },
    { id: "00392aa6-02ee-46bc-b2c3-3e502e966e21:agent:a16f03d757db6e6c6", want: "00392aa6… · subagent a16f03d7…" },
  ];
  for (const c of cases) assert.equal(fmtShortId(c.id), c.want, String(c.id));
});
