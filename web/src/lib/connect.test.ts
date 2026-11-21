import assert from "node:assert/strict";
import test from "node:test";

import { CONNECT_STATUS_PATH, type ConnectStatus } from "./connect.ts";
import { accountOf } from "./getStarted.ts";

// The front door's status shape still feeds every account surface
// (lib/getStarted.ts accountOf); the old Connect card it used to decide is
// gone (Getting started v2).
test("the front door's status feeds the account", () => {
  assert.equal(CONNECT_STATUS_PATH, "/api/connect/status");
  const st: ConnectStatus = {
    sentence: "Acme (individual) as sam@acme.example",
    kind: "individual",
    destination: "Acme",
    signed_in: true,
    identity_known: true,
    locked: false,
  };
  const a = accountOf(st, null, null);
  assert.ok(a);
  assert.equal(a.connected, true);
  assert.equal(a.displayName, "Acme");
  assert.equal(a.signedIn, true);
});
