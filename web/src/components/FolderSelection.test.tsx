// Component tests of the Terminals page's Folder Selection (Windows 11 Pro
// run 3 RERUN2, D5b and D5c), rendered with react-dom/server under node's
// test runner (scripts/test-components.mjs).

import { test } from "node:test";
import assert from "node:assert/strict";
import { renderToStaticMarkup } from "react-dom/server";
import {
  FolderRootPicker,
  FolderSuggestions,
  folderSuggestionHint,
  rootKind,
  rootsWithAdded,
  shortenFolder,
  sortSuggestions,
} from "@/components/FolderSelection";
import { enterRow } from "@shared/primitives/EntityMultiPicker";
import type { ProjectRow } from "@/lib/types";

const consoleError = console.error;
console.error = (...args: unknown[]) => {
  if (typeof args[0] === "string" && args[0].includes("useLayoutEffect does nothing on the server")) return;
  consoleError(...args);
};

const winRepo = "C:\\Users\\agent\\AppData\\Local\\Temp\\iso\\repo";
const winWork2 = "C:\\Users\\agent\\AppData\\Local\\Temp\\iso\\work2";
const row = (root_path: string): ProjectRow => ({ id: 1, root_path, session_count: 1, action_count: 1 }) as ProjectRow;
const seen = () => "1 session";

// D5b: the save wrote an observed project the owner never added. Enter in
// the root picker committed the highlighted row, the first suggestion,
// whenever nothing had been moved to. With explicitPick an untouched Enter
// commits the typed path, or nothing; a suggestion only after an arrow move.
test("Enter in the folder picker never adds a suggestion the owner did not choose", () => {
  // The old rule (and every other picker's): the first suggestion.
  assert.equal(enterRow({ activeIdx: 0, moved: false, pickableLen: 1, hasFree: false, explicitPick: false }), 0);
  // Folder Selection: an untouched Enter on the open list adds nothing.
  assert.equal(enterRow({ activeIdx: 0, moved: false, pickableLen: 1, hasFree: false, explicitPick: true }), -1);
  // A typed path beside a matching suggestion: the typed path (row after the suggestions).
  assert.equal(enterRow({ activeIdx: 0, moved: false, pickableLen: 1, hasFree: true, explicitPick: true }), 1);
  // The owner moved onto the suggestion with the arrow keys: that one.
  assert.equal(enterRow({ activeIdx: 0, moved: true, pickableLen: 1, hasFree: true, explicitPick: true }), 0);
  assert.equal(enterRow({ activeIdx: 0, moved: false, pickableLen: 0, hasFree: false, explicitPick: true }), -1);
  // The page's picker runs with the rule on.
  const html = renderToStaticMarkup(
    <FolderRootPicker suggestions={[row(winRepo)]} roots={[]} value="" onChange={() => {}} hostOS="windows" seenHint={seen} />,
  );
  assert.match(html, /data-explicit-pick="true"/);
  // One explicit add changes the list by exactly that folder.
  assert.deepEqual(rootsWithAdded(["C:\\w\\work"], ` ${winWork2} `), ["C:\\w\\work", winWork2]);
  assert.deepEqual(rootsWithAdded(["C:\\w\\work"], "C:\\w\\work"), ["C:\\w\\work"]);
});

// D5c: on a Windows node a drive-letter root is the native one: no grey, no
// "foreign (Windows/UNC)" hint. The OS is the node's own report.
test("the suggestions are OS-aware from the node's reported OS", () => {
  assert.equal(rootKind(winRepo, "windows"), "native");
  assert.equal(rootKind("\\\\server\\share\\x", "windows"), "foreign");
  assert.equal(rootKind("/home/a", "windows"), "foreign");
  assert.equal(rootKind("/home/a", "linux"), "native");
  assert.equal(rootKind(winRepo, "linux"), "foreign");
  assert.equal(rootKind(winRepo, null), "unknown");
  assert.equal(shortenFolder(winRepo), "...\\iso\\repo");
  assert.equal(shortenFolder("/home/a/b/c"), ".../b/c");

  const win = renderToStaticMarkup(
    <FolderSuggestions suggestions={[row(winRepo)]} roots={[]} hostOS="windows" writable onAdd={() => {}} seenHint={seen} />,
  );
  assert.doesNotMatch(win, /foreign \(Windows\/UNC\)/);
  assert.match(win, /data-root-kind="native"/);
  assert.doesNotMatch(win, /font-mono text-\[11px\] text-fg-3/);
  assert.match(win, /font-mono text-\[11px\] text-fg-2/);
  assert.equal(folderSuggestionHint("windows").includes("foreign (Windows/UNC)"), false);

  const lin = renderToStaticMarkup(
    <FolderSuggestions suggestions={[row(winRepo), row("/home/a")]} roots={[]} hostOS="linux" writable onAdd={() => {}} seenHint={seen} />,
  );
  assert.match(lin, /foreign \(Windows\/UNC\)/);
  assert.match(lin, /data-root-kind="foreign"/);
  // An unknown OS calls nothing foreign.
  const unk = renderToStaticMarkup(
    <FolderSuggestions suggestions={[row(winRepo)]} roots={[]} hostOS={null} writable onAdd={() => {}} seenHint={seen} />,
  );
  assert.match(unk, /data-root-kind="unknown"/);
  assert.deepEqual(
    sortSuggestions([row("/home/a"), row(winRepo)], "windows").map((r) => r.root_path),
    [winRepo, "/home/a"],
  );
});
