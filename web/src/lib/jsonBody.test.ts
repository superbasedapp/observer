import { test } from "node:test";
import assert from "node:assert/strict";
import { parseJSONBody } from "./jsonBody.ts";

// The live-run report (2026-11-18): Agree on the in-dialog clone consent
// showed "Unexpected end of JSON input" although the agreement was saved,
// because the consent route answers 200 with no body and fetchJSON parsed
// it. Every write route that answers that way is a success.

test("parseJSONBody: an empty 200 or a 204 is a success with nothing to read", () => {
  assert.equal(parseJSONBody(200, ""), undefined);
  assert.equal(parseJSONBody(200, "  \n"), undefined);
  assert.equal(parseJSONBody(204, ""), undefined);
  assert.equal(parseJSONBody(201, ""), undefined);
});

test("parseJSONBody: a JSON body parses as before, a malformed one still throws", () => {
  assert.deepEqual(parseJSONBody(200, '{"ok":true}'), { ok: true });
  assert.deepEqual(parseJSONBody(200, "[1,2]"), [1, 2]);
  assert.equal(parseJSONBody(200, "null"), null);
  assert.throws(() => parseJSONBody(200, "{"), SyntaxError);
});

test("fetchJSON reads its body through parseJSONBody", async () => {
  const { readFileSync } = await import("node:fs");
  const src = readFileSync(new URL("./api.ts", import.meta.url), "utf8");
  assert.match(src, /return parseJSONBody<T>\(res\.status, await res\.text\(\)\);/);
  assert.doesNotMatch(src, /return res\.json\(\) as Promise<T>;/);
});
