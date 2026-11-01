import assert from "node:assert/strict";
import test from "node:test";

import {
  SECURITY_SHARE_CHOICES,
  SECURITY_SHARE_KEY,
  securityShareLevel,
  securityShareNote,
  securitySharePatch,
} from "./securityShare.ts";

test("the picker offers exactly the schema's three values", () => {
  assert.deepEqual(
    SECURITY_SHARE_CHOICES.map((c) => c.id),
    ["off", "posture", "findings"],
  );
  assert.equal(SECURITY_SHARE_KEY, "org_client.share.security");
});

test("the level reads the config; unset is off; an unknown value offers no picker", () => {
  assert.equal(securityShareLevel({ OrgClient: { Share: {} } }), "off");
  assert.equal(securityShareLevel({ OrgClient: { Share: { Security: "" } } }), "off");
  assert.equal(securityShareLevel({ OrgClient: { Share: { Security: "posture" } } }), "posture");
  assert.equal(securityShareLevel({ OrgClient: { Share: { Security: "everything" } } }), null);
  assert.equal(securityShareLevel(null), null);
  assert.equal(securityShareLevel({}), null);
});

test("the patch carries the old value and no change is no patch", () => {
  assert.deepEqual(securitySharePatch("off", "findings"), { key: SECURITY_SHARE_KEY, value: "findings", was: "off" });
  assert.equal(securitySharePatch("posture", "posture"), null);
});

test("the note says who decides", () => {
  assert.match(securityShareNote(true), /managed security policy decides/);
  assert.match(securityShareNote(false), /never raise it/);
});
