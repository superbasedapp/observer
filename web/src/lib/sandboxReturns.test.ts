// Tests of the "Changes from sandboxed runs" panel's pure half
// (sandboxReturns.ts, lane RETURNS): one test per status row and helper.

import assert from "node:assert/strict";
import test from "node:test";

import {
  actionError,
  bulkResultLines,
  copyTotals,
  removeSafeLabel,
  sizeLabel,
  diffLineKind,
  diffPreviewLines,
  excludedNote,
  fileStatsLabel,
  hasAnything,
  hostedDiffOffer,
  localReturnStatus,
  sourceLabel,
  type HostedDiff,
  type LocalReturn,
} from "./sandboxReturns.ts";

const diff = (over: Partial<HostedDiff>): HostedDiff => ({
  run: "RUN1",
  saved_at: "2026-11-18T10:00:00Z",
  bytes: 120,
  path: "/home/dev/.observer/sandbox-hosted/returns/RUN1.diff",
  exact: false,
  apply_command: "git apply --index /home/dev/.observer/sandbox-hosted/returns/RUN1.diff",
  ...over,
});

const local = (over: Partial<LocalReturn>): LocalReturn => ({
  id: "RUN2",
  source: "clone-local",
  origin: "/home/dev/app",
  created_at: "2026-11-18T10:00:00Z",
  size_bytes: 1024,
  run_live: false,
  commits: -1,
  removable: true,
  ...over,
});

// SBXD-2: the copies' totals and the one-click removal. The candidates are
// exactly the copies the server's removal verdict calls safe (D4: a copy the
// click keeps, here "i", is never counted).
test("copy totals count clone copies, and only the copies the server calls safe", () => {
  const t = copyTotals([
    local({ id: "a", copy_dir: "/w/a/src", state: "returned", size_bytes: 1000, safe_to_remove: true }),
    local({ id: "b", copy_dir: "/w/b/src", state: "nothing_new", size_bytes: 2000, safe_to_remove: true }),
    local({ id: "c", copy_dir: "/w/c/src", state: "unknown", size_bytes: 4000, safe_to_remove: true }),
    local({ id: "d", copy_dir: "/w/d/src", state: "refused", size_bytes: 8000, safe_to_remove: false }),
    local({ id: "e", copy_dir: "/w/e/src", state: "pending", size_bytes: 16000 }),
    local({ id: "f", copy_dir: "/w/f/src", state: "returned", run_live: true, removable: false, size_bytes: 32000 }),
    local({ id: "g", source: "worktree", copy_dir: "/w/g/src", size_bytes: 64000 }),
    local({ id: "h", state: "returned", size_bytes: 128000 }),
    local({
      id: "i",
      copy_dir: "/w/i/src",
      state: "returned",
      size_bytes: 29 * 1024,
      safe_to_remove: false,
      keep_reason: "1 file(s) in the copy are not in its last commit and not ignored (work that never came back)",
    }),
  ]);
  assert.deepEqual(t, { count: 7, bytes: 63000 + 29 * 1024, candidates: 3, candidateBytes: 7000 });
  assert.equal(removeSafeLabel(t), "Remove all copies that are safe to remove (3, 6.8 KB)");
});

test("no copies means nothing to remove", () => {
  assert.deepEqual(copyTotals([]), { count: 0, bytes: 0, candidates: 0, candidateBytes: 0 });
});

test("sizes are in plain units", () => {
  assert.equal(sizeLabel(512), "512 B");
  assert.equal(sizeLabel(1536), "1.5 KB");
  assert.equal(sizeLabel(50 * 1024 * 1024), "50 MB");
  assert.equal(sizeLabel(3 * 1024 * 1024 * 1024), "3.0 GB");
});

test("the click's answer says what was removed, each kept copy's reason, and what is left", () => {
  const lines = bulkResultLines({
    removed: [{ id: "a", bytes: 1024 }, { id: "b", bytes: 1024 }],
    kept: [{ id: "c", bytes: 10, reason: "the run is still going" }, { id: "d", bytes: 10 }],
    freed_bytes: 2048,
    left: 1,
  });
  assert.deepEqual(lines, [
    "Removed 2 copies, freeing 2.0 KB.",
    "Kept c: the run is still going.",
    "Kept d: the removal rules keep it.",
    "1 more copy was not checked this time; click again to check them.",
  ]);
  assert.deepEqual(bulkResultLines({ removed: [], kept: [], freed_bytes: 0, left: 0 }), ["No copy was removed."]);
});

test("a diff that opens as a branch names the branch first", () => {
  const o = hostedDiffOffer(diff({ exact: true, branch: "observer-sandbox/RUN1/changes" }));
  assert.equal(o.canBranch, true);
  assert.equal(o.branch, "observer-sandbox/RUN1/changes");
  assert.equal(o.status.tone, "info");
});

test("a diff already opened says so and offers no second branch", () => {
  const o = hostedDiffOffer(diff({ exact: true, branch: "observer-sandbox/RUN1/changes", branch_exists: true }));
  assert.equal(o.canBranch, false);
  assert.match(o.status.label, /Opened as a branch/);
});

test("a diff whose start is not a commit is a file only, with the reason", () => {
  const o = hostedDiffOffer(diff({ why: "the folder had uncommitted changes" }));
  assert.equal(o.canBranch, false);
  assert.equal(o.status.tone, "warn");
  assert.match(o.status.detail ?? "", /uncommitted changes\.$/);
  assert.deepEqual(o.copy, { label: "Copy the apply command", text: diff({}).apply_command });
});

test("a diff from a folder that is not a repository offers its path (SBXD-8)", () => {
  const d = diff({ no_repository: true, why: "the files were sent from a folder that is not a git repository" });
  const o = hostedDiffOffer(d);
  assert.equal(o.canBranch, false);
  assert.equal(o.status.label, "Saved as a diff file");
  assert.match(o.status.detail ?? "", /not a git repository/);
  assert.deepEqual(o.copy, { label: "Copy the diff path", text: d.path });
});

test("the left-out files are said in plain words", () => {
  assert.equal(excludedNote(0), undefined);
  assert.match(excludedNote(1) ?? "", /^1 file was not sent/);
  assert.match(excludedNote(3) ?? "", /^3 files were not sent/);
});

test("each local return state has words and a tone", () => {
  assert.equal(localReturnStatus(local({ state: "pending", run_live: true })).label, "Run still going");
  assert.equal(localReturnStatus(local({ state: "pending" })).label, "Bringing commits back");
  const back = localReturnStatus(local({ state: "returned", commits: 2, ref: "refs/observer/sandbox/RUN2" }));
  assert.equal(back.label, "2 commits came back");
  assert.equal(back.tone, "success");
  assert.match(back.detail ?? "", /refs\/observer\/sandbox\/RUN2/);
  assert.equal(localReturnStatus(local({ state: "returned", commits: 1 })).label, "1 commit came back");
  assert.equal(localReturnStatus(local({ state: "returned", commits: -1 })).label, "Commits came back");
  assert.equal(localReturnStatus(local({ state: "nothing_new" })).label, "No new commits");
  const refused = localReturnStatus(local({ state: "refused", reason: "the copy planted a hook" }));
  assert.equal(refused.tone, "danger");
  assert.equal(refused.detail, "the copy planted a hook");
  assert.equal(localReturnStatus(local({ state: "unknown" })).label, "No record of a return");
  assert.equal(localReturnStatus(local({ state: "something new" })).label, "No record of a return");
});

test("a worktree row says its branch is kept", () => {
  const s = localReturnStatus(local({ source: "worktree", branch: "observer-sandbox/RUN3/work", kept: "" }));
  assert.equal(s.label, "Branch kept in your repository");
  assert.match(s.detail ?? "", /observer-sandbox\/RUN3\/work/);
});

test("sources read in plain words", () => {
  assert.equal(sourceLabel("clone-local"), "Copy of a local folder");
  assert.equal(sourceLabel("clone-remote"), "Copy cloned from a URL");
  assert.equal(sourceLabel("worktree"), "Git worktree");
  assert.equal(sourceLabel("x"), "Copy");
});

test("diff lines are classified for their colour", () => {
  assert.equal(diffLineKind("diff --git a/x b/x"), "file");
  assert.equal(diffLineKind("@@ -1 +1 @@"), "hunk");
  assert.equal(diffLineKind("+++ b/x"), "meta");
  assert.equal(diffLineKind("index 1..2 100644"), "meta");
  assert.equal(diffLineKind("GIT binary patch"), "meta");
  assert.equal(diffLineKind("+new"), "add");
  assert.equal(diffLineKind("-old"), "del");
  assert.equal(diffLineKind(" same"), "context");
});

test("the preview stops at its line cap and says so", () => {
  const { lines, more } = diffPreviewLines("a\nb\nc\n", 2);
  assert.equal(lines.length, 2);
  assert.equal(more, true);
  assert.equal(diffPreviewLines("a\n").more, false);
  assert.equal(diffPreviewLines("a\n").lines.length, 1);
});

test("file stats sum in plain words", () => {
  assert.equal(fileStatsLabel([]), "No files listed");
  assert.equal(
    fileStatsLabel([
      { path: "a", added: 3, deleted: 1 },
      { path: "b", added: 0, deleted: 0, binary: true },
    ]),
    "2 files, 3 added, 1 removed, 1 binary",
  );
});

test("a refused action's reason is read from its body", () => {
  assert.equal(actionError(`{"error":"the branch already exists"}`, "x"), "the branch already exists");
  assert.equal(actionError("plain text\n", "x"), "plain text");
  assert.equal(actionError("", "fallback"), "fallback");
});

test("the panel knows when it is empty", () => {
  assert.equal(hasAnything(null), false);
  assert.equal(hasAnything({ hosted: [], local: [] }), false);
  assert.equal(hasAnything({ hosted: [diff({})], local: [] }), true);
});
