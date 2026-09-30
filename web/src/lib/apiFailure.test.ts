import assert from "node:assert/strict";
import test from "node:test";

import { describeApiFailure, isAccessDenied, permissionNamedIn, statusOf } from "./apiFailure.ts";

// FakeApiError mirrors web/src/lib/api.ts ApiError's shape (a numeric
// `status` and the wrapped `api <status> <path>: <body>` message) without
// importing it, the way apiFailure reads it.
class FakeApiError extends Error {
  readonly status: number;
  constructor(status: number, path: string, body: string) {
    super(`api ${status} ${path}: ${body.slice(0, 200)}`);
    this.status = status;
  }
}

// One case per row of the status table plus the fall-throughs: a 403 is a
// denial (never an error); everything else, and a failure with no response,
// stays an ordinary error.
const CASES: {
  name: string;
  err: unknown;
  status: number | null;
  denied: boolean;
  permission: string | null;
}[] = [
  {
    name: "403 with a plain body is a denial with no named key",
    err: new FakeApiError(403, "/api/processes", "forbidden: unrecognized Host header"),
    status: 403,
    denied: true,
    permission: null,
  },
  {
    name: "403 whose body names a key reports that key",
    err: new FakeApiError(403, "/api/patterns/apply", "requires write:patterns"),
    status: 403,
    denied: true,
    permission: "write:patterns",
  },
  {
    name: "401 is an error, not a denial",
    err: new FakeApiError(401, "/api/status", ""),
    status: 401,
    denied: false,
    permission: null,
  },
  {
    name: "a 500 naming a key is still not a denial and names no key",
    err: new FakeApiError(500, "/api/cost", "read:people lookup failed"),
    status: 500,
    denied: false,
    permission: null,
  },
  {
    name: "404 is an error",
    err: new FakeApiError(404, "/api/session/x", "not found"),
    status: 404,
    denied: false,
    permission: null,
  },
  {
    name: "a network failure has no status",
    err: new TypeError("Failed to fetch"),
    status: null,
    denied: false,
    permission: null,
  },
  {
    name: "a non-Error throw has no status",
    err: "boom",
    status: null,
    denied: false,
    permission: null,
  },
  {
    name: "a non-numeric status is ignored",
    err: { status: "403" },
    status: null,
    denied: false,
    permission: null,
  },
];

for (const c of CASES) {
  test(`describeApiFailure: ${c.name}`, () => {
    const f = describeApiFailure(c.err);
    assert.equal(f.status, c.status);
    assert.equal(f.denied, c.denied);
    assert.equal(f.permission, c.permission);
    assert.equal(isAccessDenied(c.err), c.denied);
    assert.equal(statusOf(c.err), c.status);
  });
}

test("permissionNamedIn: finds a key, ignores prose", () => {
  assert.equal(permissionNamedIn("needs read:content to view"), "read:content");
  assert.equal(permissionNamedIn("forbidden"), null);
  assert.equal(permissionNamedIn(""), null);
  assert.equal(permissionNamedIn(null), null);
});
