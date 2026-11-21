// Tests of the Hosted sandboxes panel's "folders that are not git
// repositories" block's pure half (sandboxHostedUpload.ts, decision SBXD-8).

import assert from "node:assert/strict";
import test from "node:test";

import { ignoreLines, ignoreProblem, uploadNonGitOn, UPLOAD_IGNORE_MAX } from "./sandboxHostedUpload.ts";

test("upload_non_git is on unless the daemon says off", () => {
  assert.equal(uploadNonGitOn(undefined), true, "a daemon that predates the key");
  assert.equal(uploadNonGitOn(true), true);
  assert.equal(uploadNonGitOn(false), false);
});

test("the textarea's lines are the saved list, trimmed and without blanks", () => {
  assert.deepEqual(ignoreLines(" *.log \r\n\n!dist/\n"), ["*.log", "!dist/"]);
  assert.deepEqual(ignoreLines(""), []);
});

test("each pattern the daemon refuses is said", () => {
  assert.equal(ignoreProblem(["*.log", "!dist/", "\\#notes"]), null);
  assert.match(ignoreProblem(["# note"]) ?? "", /comment/);
  assert.match(ignoreProblem(["!"]) ?? "", /names nothing/);
  assert.match(ignoreProblem(["/"]) ?? "", /names nothing/);
  assert.match(ignoreProblem(["a".repeat(257)]) ?? "", /longer than 256/);
  assert.match(ignoreProblem(["a\u0007"]) ?? "", /control character/);
  assert.match(ignoreProblem(Array.from({ length: UPLOAD_IGNORE_MAX + 1 }, () => "a")) ?? "", /At most 200/);
});
