import assert from "node:assert/strict";
import test from "node:test";

import { CLOUD_LOGIN_PORT_DEFAULT, cloudLoginPortError, cloudLoginPortShown } from "./cloudLoginPort.ts";

// B-S2: the Advanced fold's login callback port, one case per rule.
test("the login callback port accepts 0 or 1024-65535", () => {
  const cases: [number, boolean][] = [
    [0, true],
    [1024, true],
    [9797, true],
    [65535, true],
    [1023, false],
    [80, false],
    [65536, false],
    [-1, false],
    [9797.5, false],
    [Number.NaN, false],
  ];
  for (const [port, ok] of cases) {
    assert.equal(cloudLoginPortError(port) === null, ok, `port ${port}`);
  }
});

test("an unset port shows the built-in default", () => {
  assert.equal(cloudLoginPortShown(0), CLOUD_LOGIN_PORT_DEFAULT);
  assert.equal(cloudLoginPortShown(9800), 9800);
});
