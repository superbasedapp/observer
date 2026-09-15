package loc

import (
	"strings"
	"testing"
)

// TestParseBeginPatchTolerances pins the envelope quirks the live corpus
// actually carries, one row per quirk. The apply_patch format the model
// emits is not the format its specification describes.
func TestParseBeginPatchTolerances(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		patch     string
		wantPaths []string
		wantStats []Stats
	}{
		{
			// The dominant live form: a bare `@@` with no line numbers.
			name: "bare @@ marker with no line numbers",
			patch: "*** Begin Patch\n*** Update File: a.go\n@@\n" +
				" ctx := 1\n-old := 2\n+new := 3\n*** End Patch",
			wantPaths: []string{"a.go"},
			wantStats: []Stats{{ModifiedCode: 1}},
		},
		{
			// A truncated rollout loses the terminator.
			name: "no End Patch terminator",
			patch: "*** Begin Patch\n*** Update File: a.go\n@@\n" +
				"-old := 2\n+new := 3\n",
			wantPaths: []string{"a.go"},
			wantStats: []Stats{{ModifiedCode: 1}},
		},
		{
			name: "several hunks in one file",
			patch: "*** Begin Patch\n*** Update File: a.go\n" +
				"@@\n-a := 1\n+a := 2\n" +
				"@@\n-b := 1\n+b := 2\n*** End Patch",
			wantPaths: []string{"a.go"},
			wantStats: []Stats{{ModifiedCode: 2}},
		},
		{
			// A rename: the destination is the file that now exists.
			name: "Move to renames the file",
			patch: "*** Begin Patch\n*** Update File: old.go\n*** Move to: new.go\n" +
				"@@\n-a := 1\n+a := 2\n*** End Patch",
			wantPaths: []string{"new.go"},
			wantStats: []Stats{{ModifiedCode: 1}},
		},
		{
			// A delete carries no body, so its removed lines are not
			// countable. Reporting zero is honest; guessing is not.
			name:      "Delete File has no countable lines",
			patch:     "*** Begin Patch\n*** Delete File: gone.go\n*** End Patch",
			wantPaths: []string{"gone.go"},
			wantStats: []Stats{{}},
		},
		{
			name: "Add File counts every plus line",
			patch: "*** Begin Patch\n*** Add File: new.go\n" +
				"+package q\n+\n+// doc\n+func f() {}\n*** End Patch",
			wantPaths: []string{"new.go"},
			wantStats: []Stats{{AddedCode: 2, AddedComment: 1, Blank: 1}},
		},
		{
			// "\ No newline at end of file" is a diff ANNOTATION. Booking
			// it as an added line would inflate every patch that ends
			// without a trailing newline.
			name: "no-newline annotation is not a line",
			patch: "*** Begin Patch\n*** Update File: a.go\n@@\n" +
				"-a := 1\n+a := 2\n\\ No newline at end of file\n*** End Patch",
			wantPaths: []string{"a.go"},
			wantStats: []Stats{{ModifiedCode: 1}},
		},
		{
			// An "Add File" whose own source line begins with "+" — the
			// C-style increment trap that bit authoredBytesFromPatch.
			name: "added source beginning with a plus survives",
			patch: "*** Begin Patch\n*** Add File: a.c\n" +
				"+int n = 0;\n+++n;\n*** End Patch",
			wantPaths: []string{"a.c"},
			wantStats: []Stats{{AddedCode: 2}},
		},
		{
			name:      "empty envelope yields nothing",
			patch:     "*** Begin Patch\n*** End Patch",
			wantPaths: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := parseBeginPatch(tt.patch, ShapeCodexPatch)
			if len(got) != len(tt.wantPaths) {
				t.Fatalf("got %d files %+v, want %d", len(got), got, len(tt.wantPaths))
			}
			for i := range tt.wantPaths {
				if got[i].Path != tt.wantPaths[i] {
					t.Errorf("file %d: path = %q, want %q", i, got[i].Path, tt.wantPaths[i])
				}
				if got[i].Stats != tt.wantStats[i] {
					t.Errorf("file %d (%s): stats = %+v, want %+v",
						i, got[i].Path, got[i].Stats, tt.wantStats[i])
				}
			}
		})
	}
}

// TestUnifiedDiffStatsIgnoresFileHeaders pins that `---`/`+++`/`diff
// --git`/`index` lines are metadata, never a deleted or added line. A
// three-hunk diff with headers must count the same as one without.
func TestUnifiedDiffStatsIgnoresFileHeaders(t *testing.T) {
	t.Parallel()
	bare := "@@ -1,2 +1,2 @@\n ctx\n-old\n+new\n"
	withHeaders := "diff --git a/x.go b/x.go\nindex 111..222 100644\n" +
		"--- a/x.go\n+++ b/x.go\n" + bare

	a := unifiedDiffStats("x.go", bare)
	b := unifiedDiffStats("x.go", withHeaders)
	if a.Stats != b.Stats {
		t.Errorf("headers changed the count: %+v vs %+v", a.Stats, b.Stats)
	}
	if a.Stats.ModifiedCode != 1 {
		t.Errorf("modified_code = %d, want 1", a.Stats.ModifiedCode)
	}
}

// TestHandCountedClaudeCodeEdits is acceptance criterion 1: three sampled
// edits whose CODE lines are counted by hand here, with comments, blanks
// and whitespace-only reflows excluded from the code buckets.
//
// The payloads are synthetic, in the exact shape claude-code stores.
func TestHandCountedClaudeCodeEdits(t *testing.T) {
	t.Parallel()

	t.Run("one-line replacement is one modified", func(t *testing.T) {
		got := Extract(Input{
			ActionType: "edit_file", Target: "/repo/a.go", BeforeLines: -1,
			RawToolInput: `{"file_path":"/repo/a.go",` +
				`"old_string":"\tcount := 1","new_string":"\tcount := 2"}`,
		})
		want := Stats{ModifiedCode: 1}
		if got[0].Stats != want {
			t.Errorf("stats = %+v, want %+v", got[0].Stats, want)
		}
	})

	t.Run("comments and blanks stay out of the code buckets", func(t *testing.T) {
		// Before: two code lines.
		// After: the first changed, a doc comment inserted after it, a
		// blank, and the second left alone.
		// By hand: 1 modified code (the changed line pairs positionally
		// with the deleted one), 1 added comment, 1 blank, 0 added code,
		// 0 deleted code — the comment and the blank never touch the
		// code buckets.
		got := Extract(Input{
			ActionType: "edit_file", Target: "/repo/a.go", BeforeLines: -1,
			RawToolInput: `{"file_path":"/repo/a.go",` +
				`"old_string":"count := 1\nreturn count",` +
				`"new_string":"count := 2\n// count is the tally.\n\nreturn count"}`,
		})
		want := Stats{ModifiedCode: 1, AddedComment: 1, Blank: 1}
		if got[0].Stats != want {
			t.Errorf("stats = %+v, want %+v", got[0].Stats, want)
		}
	})

	t.Run("a 200-line reindent is whitespace, not modified", func(t *testing.T) {
		// Acceptance criterion 1's headline case: re-indenting a block
		// must never read as 200 modified lines of authorship.
		var before, after []string
		for i := 0; i < 200; i++ {
			before = append(before, "x := 1")
			// Two ESCAPED tabs: a literal tab byte inside a JSON string
			// is an illegal control character, and the payload would not
			// parse — which is a fixture bug that silently changes which
			// ladder row matches, not a counting result.
			after = append(after, `\t\tx := 1`)
		}
		got := Extract(Input{
			ActionType: "edit_file", Target: "/repo/a.go", BeforeLines: -1,
			RawToolInput: `{"file_path":"/repo/a.go","old_string":"` +
				strings.Join(before, `\n`) + `","new_string":"` +
				strings.Join(after, `\n`) + `"}`,
		})
		want := Stats{Whitespace: 200}
		if got[0].Stats != want {
			t.Errorf("stats = %+v, want %+v", got[0].Stats, want)
		}
	})
}

// TestPairingIsPositionalWithinAChangeRegion documents a real, accepted
// limitation of the plan's counting rule rather than hiding it.
//
// Within one change region the rule is "min(deleted, added) pairs are
// modified, the rest are added or deleted" (plan §1), and the pairing is
// POSITIONAL — the first deleted line pairs with the first inserted line.
// When an agent inserts a comment ABOVE a line it also changed, the
// deleted code line therefore pairs with the inserted COMMENT, and the
// transition table books code→comment as one deleted_code plus one
// added_comment, with the real replacement showing up as a separate
// added_code.
//
// The totals stay honest (nothing is invented or dropped) and the code
// bucket is not inflated; only the split between "modified" and
// "added + deleted" shifts. Content-aware pairing is a v2 concern.
func TestPairingIsPositionalWithinAChangeRegion(t *testing.T) {
	t.Parallel()
	got := Extract(Input{
		ActionType: "edit_file", Target: "/repo/a.go", BeforeLines: -1,
		RawToolInput: `{"file_path":"/repo/a.go",` +
			`"old_string":"func f() {}",` +
			`"new_string":"// f does the thing.\n\nfunc f() int { return 1 }\nvar g = f()"}`,
	})
	want := Stats{DeletedCode: 1, AddedComment: 1, Blank: 1, AddedCode: 2}
	if got[0].Stats != want {
		t.Errorf("stats = %+v, want %+v — if this changed, the pairing rule changed;\n"+
			"re-read plan §1 before adjusting the expectation", got[0].Stats, want)
	}
}

// TestNormalizeBodyDropsHunkHeaders pins the one normalization that makes
// codex's two renderings of a patch hash alike.
func TestNormalizeBodyDropsHunkHeaders(t *testing.T) {
	t.Parallel()
	withCounts := "@@ -1,2 +1,2 @@\n ctx\n-old\n+new"
	bare := "@@\n ctx\n-old  \n+new"
	if normalizeBody(withCounts) != normalizeBody(bare) {
		t.Errorf("normalizeBody differs:\n  %q\n  %q",
			normalizeBody(withCounts), normalizeBody(bare))
	}
	if strings.Contains(normalizeBody(withCounts), "@@") {
		t.Error("normalizeBody kept a hunk header")
	}
}

// ---------------------------------------------------------------------
// Review fixes (2026-09-07): H2, L1
// ---------------------------------------------------------------------

// codexPairingFixture is the REAL invocation/executor pair the codex
// adapter's own fixture carries (testdata/codex/rollout-patch-pairing.jsonl
// lines 3 and 4, turn-A): the model's JS-wrapped envelope with a bare
// `@@` and NO context, and the executor's `unified_diff` with the
// standard one line of leading context.
//
// It is transcribed rather than read from testdata because internal/loc
// must not depend on an adapter's fixture tree — but it is byte-for-byte
// the payload of those two lines, which is the point: the store test that
// claimed this pair collapsed used a fixture with identical context on
// BOTH sides, a shape the corpus never produces.
const (
	codexPairInvocation = "const patch = \"*** Begin Patch\\n" +
		"*** Update File: /tmp/fx/a.go\\n@@\\n+var one = 1\\n*** End Patch\";\n" +
		"text(await tools.apply_patch(patch));\n"
	codexPairExecutor = `{"/tmp/fx/a.go":{"type":"update","move_path":null,` +
		`"unified_diff":"@@ -1,1 +1,2 @@\n package main\n+var one = 1\n"}}`
)

// TestCodexPairDigestsMatchOnRealShapedInput is the loc-level half of
// review finding H2. The two renderings of ONE change must hash alike, or
// the store's collapse on (session, file, input_digest) keeps both rows
// and every codex patch is counted twice on every surface.
//
// The executor side carries context and a `\ No newline` annotation the
// model side never emits, so a digest over the hunk BODY cannot match.
// The digest is over the change lines.
func TestCodexPairDigestsMatchOnRealShapedInput(t *testing.T) {
	t.Parallel()

	inv := Extract(Input{
		RawToolInput: codexPairInvocation,
		ActionType:   "edit_file", Target: "/tmp/fx/a.go", BeforeLines: -1,
	})
	exe := Extract(Input{
		RawToolInput: codexPairExecutor,
		ActionType:   "edit_file", Target: "/tmp/fx/a.go", BeforeLines: -1,
	})
	if len(inv) != 1 || len(exe) != 1 {
		t.Fatalf("rows: invocation %d, executor %d, want 1 each", len(inv), len(exe))
	}
	if inv[0].Shape != ShapeCodexJS {
		t.Errorf("invocation shape = %q, want %q", inv[0].Shape, ShapeCodexJS)
	}
	if exe[0].Shape != ShapeCodexChanges {
		t.Errorf("executor shape = %q, want %q", exe[0].Shape, ShapeCodexChanges)
	}
	if inv[0].InputDigest != exe[0].InputDigest {
		t.Errorf("digests differ — the codex pair will double-count:\n  invocation %s\n  executor   %s",
			inv[0].InputDigest, exe[0].InputDigest)
	}
	if inv[0].Stats.AddedCode != 1 || exe[0].Stats.AddedCode != 1 {
		t.Errorf("added_code: invocation %+v, executor %+v, want 1 each",
			inv[0].Stats, exe[0].Stats)
	}
}

// TestCodexPairDigestIgnoresContextAndNoNewlineAnnotations pins the two
// pieces of a unified diff that must NOT reach the digest: context lines
// and `\ No newline at end of file`. Both are producer noise the
// invocation side never carries.
func TestCodexPairDigestIgnoresContextAndNoNewlineAnnotations(t *testing.T) {
	t.Parallel()

	bare := unifiedDiffStats("a.go", "@@ -1,1 +1,2 @@\n-old := 1\n+new := 2\n")
	padded := unifiedDiffStats("a.go",
		"@@ -1,6 +1,7 @@\n package main\n\n func f() {\n-old := 1\n+new := 2\n }\n"+
			"\\ No newline at end of file\n")
	if bare.InputDigest != padded.InputDigest {
		t.Errorf("context/annotation lines reached the digest:\n  bare   %s\n  padded %s",
			bare.InputDigest, padded.InputDigest)
	}
	// The digest must still SEPARATE different changes — a fingerprint
	// that collapses everything is worse than one that collapses nothing.
	other := unifiedDiffStats("a.go", "@@ -1,1 +1,2 @@\n-old := 1\n+different := 3\n")
	if other.InputDigest == bare.InputDigest {
		t.Error("two different changes hash alike — the digest no longer identifies a patch")
	}
	// And the SIDE a line is on must matter.
	flipped := unifiedDiffStats("a.go", "@@ -1,1 +1,2 @@\n-new := 2\n+old := 1\n")
	if flipped.InputDigest == bare.InputDigest {
		t.Error("a change and its inverse hash alike — the +/- prefix is not in the digest")
	}
}

// TestDeletedCommentLineIsNotADiffHeader pins review finding L1: `---`
// and `+++` are file headers ONLY before the first `@@`. Inside a hunk,
// `--- old comment` is a deleted `-- old comment` in SQL, Lua, Haskell or
// Ada, and skipping it lost the line on the executor side while the
// invocation side counted it — a wrong count AND a forked digest.
func TestDeletedCommentLineIsNotADiffHeader(t *testing.T) {
	t.Parallel()

	got := unifiedDiffStats("y.sql", "@@ -1,2 +1,1 @@\n select 1;\n--- drop this comment\n")
	if got.Stats.DeletedComment != 1 {
		t.Errorf("deleted_comment = %d, want 1 — a deleted `-- comment` was skipped as a "+
			"diff header (stats %+v)", got.Stats.DeletedComment, got.Stats)
	}

	// A real header, which only ever appears before the first @@, is
	// still skipped.
	withHeaders := unifiedDiffStats("y.sql",
		"diff --git a/y.sql b/y.sql\nindex 1234567..89abcde 100644\n"+
			"--- a/y.sql\n+++ b/y.sql\n@@ -1,2 +1,1 @@\n select 1;\n--- drop this comment\n")
	if withHeaders.Stats.DeletedComment != 1 {
		t.Errorf("deleted_comment = %d with headers present, want 1 (stats %+v)",
			withHeaders.Stats.DeletedComment, withHeaders.Stats)
	}
	if withHeaders.Stats.DeletedCode != 0 || withHeaders.Stats.AddedCode != 0 {
		t.Errorf("a file header was booked as content: %+v", withHeaders.Stats)
	}

	// The invocation rendering of the SAME change must agree, which is
	// what makes the pair collapse.
	inv := parseBeginPatch(
		"*** Begin Patch\n*** Update File: y.sql\n@@\n select 1;\n--- drop this comment\n*** End Patch",
		ShapeCodexPatch,
	)
	if len(inv) != 1 {
		t.Fatalf("invocation rows = %d, want 1", len(inv))
	}
	if inv[0].Stats.DeletedComment != 1 {
		t.Errorf("invocation deleted_comment = %d, want 1 (stats %+v)",
			inv[0].Stats.DeletedComment, inv[0].Stats)
	}
	if inv[0].InputDigest != got.InputDigest {
		t.Errorf("the SQL delete pair still hashes apart:\n  invocation %s\n  executor   %s",
			inv[0].InputDigest, got.InputDigest)
	}
}
