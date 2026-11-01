package loc

import "testing"

// TestExtractBobChanges is the golden for the ShapeBobChanges row: the
// exact hunks the ibm-bob adapter copies from a tool result's
// `_meta.changes` (live shape, testdata/ibmbob/real.sql; content synthetic).
func TestExtractBobChanges(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   Input
		want []wantFile
	}{
		{
			// write_file creating a file: the vendor patch is
			// "@@ -0,0 +1,N @@" and every line is an addition.
			name: "write_file new file",
			in: Input{
				ActionType: "write_file", Target: "/w/hello.py", BeforeLines: -1,
				RawToolInput: `{"path":"/w/hello.py","content":"print(\"hi\")\n# done\n",` +
					`"_bob_changes":[{"path":"/w/hello.py","hunks":"@@\n+print(\"hi\")\n+# done\n"}]}`,
			},
			want: []wantFile{{
				shape: ShapeBobChanges, path: "/w/hello.py", lang: LangPython, cat: CategoryCode,
				conf: ConfidenceHigh, stats: Stats{AddedCode: 1, AddedComment: 1},
			}},
		},
		{
			// write_file over an existing file: the arguments carry only
			// the after-image (the content row would book an overwrite at
			// low confidence); the change record is exact.
			name: "write_file overwrite is exact",
			in: Input{
				ActionType: "write_file", Target: "/w/a.go", Existed: true, BeforeLines: -1,
				RawToolInput: `{"path":"/w/a.go","content":"package a\n\nvar x = 2\n",` +
					`"_bob_changes":[{"path":"/w/a.go","hunks":"@@\n-var x = 1\n+var x = 2\n"}]}`,
			},
			want: []wantFile{{
				shape: ShapeBobChanges, path: "/w/a.go", lang: LangGo, cat: CategoryCode,
				conf: ConfidenceHigh, stats: Stats{ModifiedCode: 1},
			}},
		},
		{
			// search_and_replace that matched twice: the arguments say one
			// line, the change record says two runs split by context.
			name: "search_and_replace two occurrences",
			in: Input{
				ActionType: "edit_file", Target: "/w/a.py", BeforeLines: -1,
				RawToolInput: `{"path":"/w/a.py","search":"x = 1","replace":"x = 2",` +
					`"_bob_changes":[{"path":"/w/a.py","hunks":"@@\n-x = 1\n+x = 2\n@@\n-x = 1\n+x = 2\n"}]}`,
			},
			want: []wantFile{{
				shape: ShapeBobChanges, path: "/w/a.py", lang: LangPython, cat: CategoryCode,
				conf: ConfidenceHigh, stats: Stats{ModifiedCode: 2},
			}},
		},
		{
			// A delete run and an add run separated by context stay
			// separate fragments: one deleted + one added, not a modified
			// pair.
			name: "separated runs do not pair",
			in: Input{
				ActionType: "edit_file", Target: "/w/a.py", BeforeLines: -1,
				RawToolInput: `{"path":"/w/a.py","diff":"x",` +
					`"_bob_changes":[{"path":"/w/a.py","hunks":"@@\n-old = 1\n@@\n+new = 2\n"}]}`,
			},
			want: []wantFile{{
				shape: ShapeBobChanges, path: "/w/a.py", lang: LangPython, cat: CategoryCode,
				conf: ConfidenceHigh, stats: Stats{DeletedCode: 1, AddedCode: 1},
			}},
		},
		{
			// Several files, sorted by path; an entry without a path takes
			// the action target.
			name: "multi file",
			in: Input{
				ActionType: "edit_file", Target: "/w/b.go", BeforeLines: -1,
				RawToolInput: `{"_bob_changes":[{"hunks":"@@\n+var b = 1\n"},` +
					`{"path":"/w/a.go","hunks":"@@\n-var a = 1\n"}]}`,
			},
			want: []wantFile{
				{shape: ShapeBobChanges, path: "/w/a.go", lang: LangGo, cat: CategoryCode, conf: ConfidenceHigh, stats: Stats{DeletedCode: 1}},
				{shape: ShapeBobChanges, path: "/w/b.go", lang: LangGo, cat: CategoryCode, conf: ConfidenceHigh, stats: Stats{AddedCode: 1}},
			},
		},
		{
			// No usable entry: falls through to the argument rows
			// (here the search/replace estimate).
			name: "empty record falls through",
			in: Input{
				ActionType: "edit_file", Target: "/w/a.py", BeforeLines: -1,
				RawToolInput: `{"path":"/w/a.py","search":"a = 1","replace":"a = 2","_bob_changes":[{"path":"/w/a.py","hunks":""}]}`,
			},
			want: []wantFile{{
				shape: ShapeSearchReplKeys, path: "/w/a.py", lang: LangPython, cat: CategoryCode,
				conf: ConfidenceHigh, stats: Stats{ModifiedCode: 1},
			}},
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assertFiles(t, Extract(tc.in), tc.want)
		})
	}
}

// TestExtractBobChangesDigestMatchesFullDiff pins that the reduced hunks
// hash like the vendor's full diff (context and headers included), so the
// digest a row carries does not depend on the reduction.
func TestExtractBobChangesDigestMatchesFullDiff(t *testing.T) {
	t.Parallel()
	full := unifiedDiffStats("/w/a.py", "--- a\n+++ b\n@@ -1,3 +1,3 @@\n-x = 1\n+x = 2\n ctx\n-y = 1\n")
	got := Extract(Input{
		ActionType: "edit_file", Target: "/w/a.py", BeforeLines: -1,
		RawToolInput: `{"_bob_changes":[{"path":"/w/a.py","hunks":"@@\n-x = 1\n+x = 2\n@@\n-y = 1\n"}]}`,
	})
	if len(got) != 1 {
		t.Fatalf("got %d rows, want 1", len(got))
	}
	if got[0].InputDigest != full.InputDigest {
		t.Errorf("digest = %s, want the full diff's %s", got[0].InputDigest, full.InputDigest)
	}
	if got[0].Stats != full.Stats {
		t.Errorf("stats = %+v, want the full diff's %+v", got[0].Stats, full.Stats)
	}
}
