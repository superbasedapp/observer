// The deletion routes' client (plan 07 M6.9): each call's method, path and
// body, and the refusal parsing: the server's {"error": message, "code"}
// shape and the {"error": code, "message"} spelling both yield the code and
// the sentence, and an account_deletion_blocked body's blockers are read.

import { test } from "node:test";
import assert from "node:assert/strict";

// api.ts opens a BroadcastChannel for the multi-tab CSRF sync at import
// time; under node an open channel keeps the test process alive, so the
// global is removed (api.ts then skips the channel) before a dynamic import.
delete (globalThis as { BroadcastChannel?: unknown }).BroadcastChannel;
const {
  ApiError,
  cancelOrgDeletion,
  getAccountDeletionPrecheck,
  getOrgDeletion,
  refusalBlockers,
  requestDeletionWithStepUp,
  requestOrgDeletion,
} = await import("../../api");

type Seen = { url: string; method: string; body: unknown };

function stubFetch(status: number, body: unknown): Seen[] {
  const seen: Seen[] = [];
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    seen.push({
      url: String(input),
      method: init?.method ?? "GET",
      body: init?.body ? JSON.parse(String(init.body)) : undefined,
    });
    return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
  }) as typeof fetch;
  return seen;
}

test("the org deletion calls hit their routes", async () => {
  let seen = stubFetch(200, { deletion: null, preview: {} });
  await getOrgDeletion("org a");
  assert.deepEqual(seen[0], { url: "/portal/api/orgs/org%20a/deletion", method: "GET", body: undefined });

  seen = stubFetch(202, { state: "cooling_off" });
  await requestOrgDeletion("o1", "acme");
  assert.deepEqual(seen[0], { url: "/portal/api/orgs/o1/deletion", method: "POST", body: { confirm_slug: "acme" } });

  seen = stubFetch(200, { state: "canceled" });
  await cancelOrgDeletion("o1");
  assert.equal(seen[0].method, "DELETE");
  assert.equal(seen[0].url, "/portal/api/orgs/o1/deletion");

  seen = stubFetch(200, { can_delete: true, blockers: [] });
  await getAccountDeletionPrecheck();
  assert.equal(seen[0].url, "/portal/api/account/deletion-precheck");
});

test("a refusal is read in either error spelling", async () => {
  stubFetch(400, { error: "confirm_slug does not match", code: "confirm_mismatch" });
  await assert.rejects(requestOrgDeletion("o1", "x"), (e: unknown) => {
    assert.ok(e instanceof ApiError);
    assert.equal(e.code, "confirm_mismatch");
    assert.equal(e.message, "confirm_slug does not match");
    return true;
  });
  stubFetch(409, { error: "not_cancellable", message: "the purge has started" });
  await assert.rejects(cancelOrgDeletion("o1"), (e: unknown) => {
    assert.ok(e instanceof ApiError);
    assert.equal(e.code, "not_cancellable");
    assert.equal(e.message, "the purge has started");
    return true;
  });
});

test("an account_deletion_blocked refusal carries its blockers", async () => {
  const blockers = [
    { code: "sole_owner_alone", org_id: "o1", slug: "acme", display_name: "Acme" },
    { code: "pays_for_live_org", org_id: "o2", slug: "beta", display_name: "Beta" },
  ];
  stubFetch(409, { error: "Your account cannot be deleted yet.", code: "account_deletion_blocked", blockers });
  let caught: unknown;
  try {
    await requestDeletionWithStepUp("su_1");
  } catch (e) {
    caught = e;
  }
  assert.ok(caught instanceof ApiError);
  assert.equal(caught.code, "account_deletion_blocked");
  assert.deepEqual(refusalBlockers(caught), blockers);
  // Anything else has none; a malformed row is dropped.
  assert.deepEqual(refusalBlockers(new Error("x")), []);
  assert.deepEqual(refusalBlockers(new ApiError(409, "account_deletion_blocked", "m", { blockers: [{ nope: 1 }, null] })), []);
});
