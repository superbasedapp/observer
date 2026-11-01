package codex

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// countEditRows splits the edit_file rows of a parse by raw_tool_name.
// An invocation row that was merged carries "patch_apply_end" (the merge
// overwrites RawToolName), so a surviving "apply_patch" row is exactly
// an invocation that never found its executor.
func countEditRows(t *testing.T, path string) (invocations, executors int, rows []models.ToolEvent) {
	t.Helper()
	res, err := New().ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	for _, e := range res.ToolEvents {
		if e.ActionType != models.ActionEditFile {
			continue
		}
		rows = append(rows, e)
		switch e.RawToolName {
		case "apply_patch":
			invocations++
		case "patch_apply_end":
			executors++
		}
	}
	return invocations, executors, rows
}

// TestPatchApplyPairsWithoutCallIDJoin pins the collapse of the
// duplicate row that modern Codex builds produce.
//
// apply_patch now runs from inside an `exec` custom_tool_call, and the
// executor stamps patch_apply_end with its own `exec-<uuid>` while the
// response_item carries `call_<hash>`. The namespaces are disjoint, so
// pending[call_id] cannot match and BOTH rows used to survive — one
// patch, two edit_file rows, and the added bytes counted twice.
// Measured over 333 July rollouts before this fix: 838 invocation rows
// alongside 2,445 executor rows, 57 rollouts carrying both.
//
// turn-A is the simple case (one patch, one executor). turn-B is the
// case only ORDER can resolve: the same file patched twice in one turn,
// so both invocations carry an identical file set.
func TestPatchApplyPairsWithoutCallIDJoin(t *testing.T) {
	t.Parallel()
	inv, exe, rows := countEditRows(t, fixture(t, "rollout-patch-pairing.jsonl"))

	// Three patches went in; three rows must come out, every one of them
	// merged. A count of 6 is the pre-fix duplication.
	if len(rows) != 3 {
		t.Errorf("edit_file rows = %d, want 3 (one per patch)", len(rows))
		for i, r := range rows {
			t.Logf("  row %d: raw=%s target=%s bytes=%d", i, r.RawToolName, r.Target, r.ContentBytes)
		}
	}
	if inv != 0 {
		t.Errorf("unmerged apply_patch rows = %d, want 0 — every patch here has an executor", inv)
	}
	if exe != 3 {
		t.Errorf("merged patch_apply_end rows = %d, want 3", exe)
	}

	// The merge must carry the executor's outcome onto the row, not just
	// suppress a duplicate.
	for i, r := range rows {
		if !r.Success {
			t.Errorf("row %d: Success=false, want true", i)
		}
		if r.ToolOutput == "" {
			t.Errorf("row %d: ToolOutput empty — executor stdout did not reach the merged row", i)
		}
		if r.RawToolInput == "" {
			t.Errorf("row %d: RawToolInput empty — the invocation's own patch text was lost", i)
		}
	}
}

// TestPatchApplyDoesNotPairOnFileSetMismatch is the other half of the
// guard: when the invocation's declared paths and the executor's
// reported paths disagree, NOTHING is merged. Degrading to two rows is
// correct — a wrong pairing would silently attribute one patch's bytes
// and outcome to a different patch.
func TestPatchApplyDoesNotPairOnFileSetMismatch(t *testing.T) {
	t.Parallel()
	inv, exe, rows := countEditRows(t, fixture(t, "rollout-patch-pairing-mismatch.jsonl"))

	if len(rows) != 2 {
		t.Errorf("edit_file rows = %d, want 2 (mismatch must NOT merge)", len(rows))
	}
	if inv != 1 {
		t.Errorf("standalone apply_patch rows = %d, want 1", inv)
	}
	if exe != 1 {
		t.Errorf("standalone patch_apply_end rows = %d, want 1", exe)
	}
}

// TestPatchApplyInvocationIsClaimedOnlyOnce covers the seam the
// dropPatchInvocation CALL SITE owns, which the unit test on the
// function itself cannot reach: when the call_id join wins, the
// invocation row must ALSO leave the fallback queue, or a later
// id-less patch_apply_end in the same turn merges into a row that has
// already been merged — silently overwriting one patch's outcome with
// another's and losing a row.
//
// The fixture is one invocation whose executor joins by call_id,
// followed by a second executor for the same file in the same turn.
// Correct behaviour is two rows: the merged invocation, plus a
// standalone for the second executor. Deleting the drop yields one.
func TestPatchApplyInvocationIsClaimedOnlyOnce(t *testing.T) {
	t.Parallel()
	inv, exe, rows := countEditRows(t, fixture(t, "rollout-patch-pairing-doubleclaim.jsonl"))

	if len(rows) != 2 {
		t.Errorf("edit_file rows = %d, want 2 — a merged row must not be claimable twice", len(rows))
		for i, r := range rows {
			t.Logf("  row %d: raw=%s target=%s", i, r.RawToolName, r.Target)
		}
	}
	if inv != 0 {
		t.Errorf("unmerged apply_patch rows = %d, want 0 (the call_id join covers it)", inv)
	}
	if exe != 2 {
		t.Errorf("patch_apply_end rows = %d, want 2", exe)
	}
}

// TestPatchApplyFallbackClaimRetiresPendingEntry is the MIRROR of
// TestPatchApplyInvocationIsClaimedOnlyOnce, and closes the asymmetry a
// codex review caught: claimability was represented in two places
// (pending and patchInvocations) and only one direction invalidated the
// other. When the FALLBACK claims an invocation, its pending[call_hash]
// entry must be retired too — otherwise a later patch_apply_end that
// DOES carry the call_hash joins and merges the same row a second time,
// overwriting the first executor's outcome and losing a row.
//
// Fixture order is deliberately the reverse of the doubleclaim one:
// id-less executor first (fallback claims), call_hash executor second.
func TestPatchApplyFallbackClaimRetiresPendingEntry(t *testing.T) {
	t.Parallel()
	inv, exe, rows := countEditRows(t, fixture(t, "rollout-patch-pairing-reverseclaim.jsonl"))

	if len(rows) != 2 {
		t.Errorf("edit_file rows = %d, want 2 — a fallback-merged row must not be re-claimable by call_id", len(rows))
		for i, r := range rows {
			t.Logf("  row %d: raw=%s target=%s", i, r.RawToolName, r.Target)
		}
	}
	if inv != 0 {
		t.Errorf("unmerged apply_patch rows = %d, want 0", inv)
	}
	if exe != 2 {
		t.Errorf("patch_apply_end rows = %d, want 2", exe)
	}
}

func TestPatchFileSet(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		patch string
		base  string
		want  []string
	}{
		{
			name:  "add",
			patch: "*** Begin Patch\n*** Add File: /tmp/a.go\n+package a\n*** End Patch",
			want:  []string{"/tmp/a.go"},
		},
		{
			name:  "update and delete in one envelope",
			patch: "*** Begin Patch\n*** Update File: /tmp/a.go\n@@\n+x\n*** Delete File: /tmp/b.go\n*** End Patch",
			want:  []string{"/tmp/a.go", "/tmp/b.go"},
		},
		{
			name:  "paths are cleaned so equal paths compare equal",
			patch: "*** Begin Patch\n*** Update File: /tmp/./sub/../a.go\n*** End Patch",
			want:  []string{"/tmp/a.go"},
		},
		{
			// A `+` line that happens to start with the header prefix is
			// content, not a header — it must not enter the set.
			name:  "content lines are not headers",
			patch: "*** Begin Patch\n*** Add File: /tmp/a.go\n+*** Update File: /tmp/decoy.go\n*** End Patch",
			want:  []string{"/tmp/a.go"},
		},
		{
			// The executor always reports absolute paths, so a relative
			// header must be resolved or the guard abstains on a real
			// shape. This is the shape of the pre-existing
			// rollout-patch-apply-exec-namespace fixture.
			name:  "relative header resolves against the session cwd",
			patch: "*** Begin Patch\n*** Update File: main.go\n@@\n+x\n*** End Patch",
			base:  "/repo/proj",
			want:  []string{"/repo/proj/main.go"},
		},
		{
			name:  "relative header with no base stays relative and simply will not match",
			patch: "*** Begin Patch\n*** Update File: main.go\n*** End Patch",
			want:  []string{"main.go"},
		},
		{
			name:  "an absolute header ignores the base",
			patch: "*** Begin Patch\n*** Add File: /abs/a.go\n*** End Patch",
			base:  "/repo/proj",
			want:  []string{"/abs/a.go"},
		},
		{
			// A Windows rollout parsed on a Linux/WSL daemon: filepath.IsAbs
			// says false for a drive-letter path, so without isAbsAnyOS this
			// gets the cwd prepended and can never equal the executor's key.
			// The adapter supports foreign-OS rollouts, so this is live.
			name:  "windows drive-letter header is absolute on a linux host",
			patch: "*** Begin Patch\n*** Update File: C:\\repo\\a.go\n*** End Patch",
			base:  "/home/u/proj",
			want:  []string{"C:\\repo\\a.go"},
		},
		{
			name:  "windows forward-slash drive-letter header is absolute",
			patch: "*** Begin Patch\n*** Update File: d:/repo/a.go\n*** End Patch",
			base:  "/home/u/proj",
			want:  []string{"d:/repo/a.go"},
		},
		{
			name:  "UNC header is absolute",
			patch: "*** Begin Patch\n*** Update File: \\\\srv\\share\\a.go\n*** End Patch",
			base:  "/home/u/proj",
			want:  []string{"\\\\srv\\share\\a.go"},
		},
		{
			name:  "no headers yields an empty set",
			patch: "not a patch at all",
			want:  nil,
		},
		{
			name:  "header with an empty path is skipped",
			patch: "*** Begin Patch\n*** Add File: \n*** End Patch",
			want:  nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := patchFileSet(tt.patch, tt.base)
			if len(got) != len(tt.want) {
				t.Fatalf("patchFileSet size = %d (%v), want %d (%v)", len(got), keysOf(got), len(tt.want), tt.want)
			}
			for _, p := range tt.want {
				// Both pairing sides key by filepath.Clean (changesFileSet
				// does too), which uses the host separator.
				if _, ok := got[filepath.Clean(p)]; !ok {
					t.Errorf("patchFileSet missing %q (got %v)", p, keysOf(got))
				}
			}
		})
	}
}

func keysOf(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestSameFileSet(t *testing.T) {
	t.Parallel()
	set := func(paths ...string) map[string]struct{} {
		m := map[string]struct{}{}
		for _, p := range paths {
			m[p] = struct{}{}
		}
		return m
	}
	tests := []struct {
		name string
		a, b map[string]struct{}
		want bool
	}{
		{"equal single", set("a"), set("a"), true},
		{"equal multi, order irrelevant", set("a", "b"), set("b", "a"), true},
		{"disjoint", set("a"), set("b"), false},
		{"subset is NOT equal", set("a"), set("a", "b"), false},
		{"superset is NOT equal", set("a", "b"), set("a"), false},
		// Two empty sets are deliberately NOT "equal": an empty set
		// carries no evidence, and pairing on no evidence is exactly the
		// mis-merge the guard exists to prevent.
		{"both empty is not a match", set(), set(), false},
		{"one empty is not a match", set(), set("a"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := sameFileSet(tt.a, tt.b); got != tt.want {
				t.Errorf("sameFileSet = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestClaimPatchInvocation covers the queue mechanics directly: FIFO
// within a turn, scoping by turn, and claim-once.
func TestClaimPatchInvocation(t *testing.T) {
	t.Parallel()
	files := func(paths ...string) map[string]struct{} {
		m := map[string]struct{}{}
		for _, p := range paths {
			m[p] = struct{}{}
		}
		return m
	}

	t.Run("oldest matching entry wins and is removed", func(t *testing.T) {
		t.Parallel()
		q := map[string][]patchInvocation{
			"turn-1": {
				{idx: 10, files: files("a.go")},
				{idx: 11, files: files("a.go")},
			},
		}
		cand, ok := claimPatchInvocation(q, "turn-1", files("a.go"))
		if !ok || cand.idx != 10 {
			t.Fatalf("first claim = (%d,%v), want (10,true)", cand.idx, ok)
		}
		cand, ok = claimPatchInvocation(q, "turn-1", files("a.go"))
		if !ok || cand.idx != 11 {
			t.Fatalf("second claim = (%d,%v), want (11,true)", cand.idx, ok)
		}
		if _, ok = claimPatchInvocation(q, "turn-1", files("a.go")); ok {
			t.Error("third claim succeeded; the queue must be exhausted")
		}
	})

	t.Run("a non-matching head does not block a later match", func(t *testing.T) {
		t.Parallel()
		q := map[string][]patchInvocation{
			"turn-1": {
				{idx: 10, files: files("other.go")},
				{idx: 11, files: files("a.go")},
			},
		}
		cand, ok := claimPatchInvocation(q, "turn-1", files("a.go"))
		if !ok || cand.idx != 11 {
			t.Fatalf("claim = (%d,%v), want (11,true)", cand.idx, ok)
		}
		if len(q["turn-1"]) != 1 || q["turn-1"][0].idx != 10 {
			t.Errorf("queue = %v, want the non-matching entry 10 still present", q["turn-1"])
		}
	})

	t.Run("another turn's invocation is never claimed", func(t *testing.T) {
		t.Parallel()
		q := map[string][]patchInvocation{
			"turn-1": {{idx: 10, files: files("a.go")}},
		}
		if _, ok := claimPatchInvocation(q, "turn-2", files("a.go")); ok {
			t.Error("claimed across turns; sub-agent patches would mis-pair")
		}
	})

	t.Run("no match leaves the queue untouched", func(t *testing.T) {
		t.Parallel()
		q := map[string][]patchInvocation{
			"turn-1": {{idx: 10, files: files("a.go")}},
		}
		if _, ok := claimPatchInvocation(q, "turn-1", files("zzz.go")); ok {
			t.Fatal("claimed on a mismatched file set")
		}
		if len(q["turn-1"]) != 1 {
			t.Errorf("queue length = %d, want 1", len(q["turn-1"]))
		}
	})
}

// TestDropPatchInvocation pins the double-claim guard: when the call_id
// join wins, the row must leave the fallback queue too, or a later
// patch_apply_end can merge into an already-merged row.
func TestDropPatchInvocation(t *testing.T) {
	t.Parallel()
	files := map[string]struct{}{"a.go": {}}
	q := map[string][]patchInvocation{
		"turn-1": {{idx: 10, files: files}, {idx: 11, files: files}},
	}
	dropPatchInvocation(q, 10)
	if len(q["turn-1"]) != 1 || q["turn-1"][0].idx != 11 {
		t.Fatalf("queue = %v, want only idx 11", q["turn-1"])
	}
	// Dropping an index that is not queued must be a no-op, not a panic.
	dropPatchInvocation(q, 999)
	if len(q["turn-1"]) != 1 {
		t.Errorf("queue length = %d after dropping an absent idx, want 1", len(q["turn-1"]))
	}
}
