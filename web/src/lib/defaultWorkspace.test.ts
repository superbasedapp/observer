import { test } from "node:test";
import assert from "node:assert/strict";
import {
  consentDefault,
  folderProblem,
  putBody,
  savedWords,
  statusLine,
  type DefaultWorkspaceView,
} from "./defaultWorkspace.ts";

const view = (over: Partial<DefaultWorkspaceView> = {}): DefaultWorkspaceView => ({
  dir: "/home/dev/observer-workspace",
  builtin: true,
  builtin_dir: "/home/dev/observer-workspace",
  configured: "",
  exists: true,
  ready: true,
  ...over,
});

test("folderProblem mirrors the daemon's shape rules", () => {
  const cases: [string, boolean][] = [
    ["/home/dev/scratch", true],
    ["C:\\Users\\dev\\scratch", true],
    ["D:/work/scratch", true],
    ["", false],
    ["   ", false],
    ["relative/dir", false],
    ["~/scratch", false],
    ["/a\nb", false],
    ["/" + "a".repeat(5000), false],
  ];
  for (const [p, ok] of cases) {
    assert.equal(folderProblem(p) === "", ok, `folderProblem(${JSON.stringify(p)})`);
  }
});

test("putBody trims a folder and sends null for the built-in folder", () => {
  assert.deepEqual(putBody("  /x/y  "), { dir: "/x/y" });
  assert.deepEqual(putBody(null), { dir: null });
});

test("statusLine says what the folder is and reports a problem first", () => {
  assert.equal(statusLine(view()), "The built-in folder.");
  assert.equal(statusLine(view({ builtin: false })), "A folder you chose.");
  assert.match(statusLine(view({ exists: false })), /created the next time Observer starts/);
  assert.equal(statusLine(view({ problem: "That folder is inside a git repository." })), "That folder is inside a git repository.");
});

test("savedWords", () => {
  assert.match(savedWords(true), /built-in/);
  assert.match(savedWords(false), /Saved/);
  assert.equal(savedWords(false, "Not set up yet."), "Saved. Not set up yet.");
});

test("consentDefault starts on the workspace only when it is ready", () => {
  assert.equal(consentDefault(view()), "/home/dev/observer-workspace");
  assert.equal(consentDefault(view({ problem: "bad" })), "");
  assert.equal(consentDefault(view({ dir: "" })), "");
  assert.equal(consentDefault(view({ ready: false })), "", "a workspace that is not set up is never the default");
  assert.equal(consentDefault(null), "");
  assert.equal(consentDefault(undefined), "");
});
