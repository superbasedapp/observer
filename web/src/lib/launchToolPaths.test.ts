import assert from "node:assert/strict";
import test from "node:test";

import { addableTools, isAbsolutePath, pathItems, pathProblem, putBody, savedWords } from "./launchToolPaths.ts";

const abs: Array<[string, boolean]> = [
  ["/usr/local/bin/codex", true],
  ["C:\\Tools\\codex.exe", true],
  ["c:/tools/codex.exe", true],
  ["\\\\server\\share\\codex.exe", true],
  ["codex", false],
  ["./codex", false],
  ["bin\\codex.exe", false],
  ["C:codex.exe", false],
  ["", false],
];
for (const [p, want] of abs) {
  test(`isAbsolutePath ${JSON.stringify(p)}`, () => assert.equal(isAbsolutePath(p), want));
}

const problems: Array<{ name: string; path: string; want: string }> = [
  { name: "ok posix", path: "/opt/x/bin", want: "" },
  { name: "ok windows, padded", path: "  C:\\x\\y.exe ", want: "" },
  { name: "blank", path: "   ", want: "Enter the full path to the program." },
  { name: "relative", path: "bin/codex", want: "The path must be absolute (start at the drive or at /), not relative." },
  { name: "control char", path: "/opt/x\u0007", want: "That path contains a control character." },
  { name: "too long", path: "/" + "a".repeat(4100), want: "That path is longer than 4096 bytes." },
];
for (const c of problems) {
  test(`pathProblem ${c.name}`, () => assert.equal(pathProblem(c.path), c.want));
}

test("putBody trims a path and keeps null", () => {
  assert.deepEqual(putBody("codex", " /a/b "), { tool: "codex", path: "/a/b" });
  assert.deepEqual(putBody("codex", null), { tool: "codex", path: null });
});

test("pathItems sorts and flags a missing file", () => {
  const items = pathItems([
    { tool: "zed", path: "/z", exists: true },
    { tool: "aider", path: "/a", exists: false },
  ]);
  assert.deepEqual(
    items.map((i) => i.tool),
    ["aider", "zed"],
  );
  assert.equal(items[0].nothingThere, true);
  assert.match(items[0].note, /Nothing is there/);
  assert.equal(items[1].nothingThere, false);
  assert.deepEqual(pathItems(undefined), []);
});

test("addableTools drops tools that already have an override and dedupes", () => {
  assert.deepEqual(addableTools(["codex", "aider", "codex", "zed"], [{ tool: "aider", path: "/a", exists: true }]), [
    "codex",
    "zed",
  ]);
  assert.deepEqual(addableTools(undefined, undefined), []);
});

test("savedWords", () => {
  assert.equal(savedWords(false, false), "Saved. It applies to the next launch.");
  assert.equal(savedWords(true, false), "Saved. Restart the daemon to apply it.");
  assert.equal(savedWords(false, true), "Removed. Launches look the tool up again. It applies to the next launch.");
});
