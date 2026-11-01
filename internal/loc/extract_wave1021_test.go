package loc

import "testing"

// TestExtractWave1021Shapes is the golden per ladder row added in the
// 2026-10-21 ten-adapter wave (loc.Version 3). Every payload SHAPE was read
// off a live store, a fixture or the vendor's own tool definition (named
// per row); the content is synthetic.
func TestExtractWave1021Shapes(t *testing.T) {
	t.Parallel()
	edit := func(target, raw string) Input {
		return Input{ActionType: "edit_file", Target: target, BeforeLines: -1, RawToolInput: raw}
	}
	tests := []struct {
		name string
		in   Input
		want []wantFile
	}{
		{
			// kimchi (testdata/kimchi/session-wsl.jsonl) and pi (live
			// Windows store): edits[] spelled oldText/newText. Counted
			// ZERO lines before v3.
			name: "edits array oldText newText",
			in: edit("hello.py", `{"path":"hello.py","edits":[`+
				`{"oldText":"print(\"hello world\")","newText":"print(\"hello autohand\")"},`+
				`{"oldText":"x = 1","newText":"x = 2\ny = 3"}]}`),
			want: []wantFile{{
				shape: ShapeEdits, path: "hello.py", lang: LangPython, cat: CategoryCode,
				conf: ConfidenceHigh, stats: Stats{ModifiedCode: 2, AddedCode: 1},
			}},
		},
		{
			// dimcode edit (testdata/dimcode/fixture-wsl.sql), kimchi
			// single edit.
			name: "oldText newText pair",
			in:   edit("/w/a.py", `{"path":"/w/a.py","oldText":"a = 1","newText":"a = 2\n# done"}`),
			want: []wantFile{{
				shape: ShapeOldNewText, path: "/w/a.py", lang: LangPython, cat: CategoryCode,
				conf: ConfidenceHigh, stats: Stats{ModifiedCode: 1, AddedComment: 1},
			}},
		},
		{
			// ibm-bob search_and_replace (testdata/ibmbob/fixture.sql).
			name: "search replace pair",
			in:   edit("/home/user/proj/hello.py", `{"path":"/home/user/proj/hello.py","search":"print(\"hi\")","replace":"print(\"hello\")"}`),
			want: []wantFile{{
				shape: ShapeSearchReplKeys, path: "/home/user/proj/hello.py", lang: LangPython,
				cat: CategoryCode, conf: ConfidenceHigh, stats: Stats{ModifiedCode: 1},
			}},
		},
		{
			// ibm-bob insert_content (bobshell 2.0.6 tool definition): a
			// fragment, additions only — never a whole-file overwrite.
			name: "insert_content adds lines only",
			in: Input{
				ActionType: "edit_file", Target: "/w/a.go", Existed: true, BeforeLines: 40,
				RawToolInput: `{"path":"/w/a.go","line":3,"content":"import \"os\"\n// os\n"}`,
			},
			want: []wantFile{{
				shape: ShapeInsertContent, path: "/w/a.go", lang: LangGo, cat: CategoryCode,
				conf: ConfidenceHigh, stats: Stats{AddedCode: 1, AddedComment: 1},
			}},
		},
		{
			// autohand write_file (testdata/autohand/windows conversation.jsonl).
			name: "autohand contents new file",
			in: Input{
				ActionType: "write_file", Target: "hello_world.py", BeforeLines: -1,
				RawToolInput: `{"path":"hello_world.py","contents":"print(\"hello world\")\n"}`,
			},
			want: []wantFile{{
				shape: ShapeContents, path: "hello_world.py", lang: LangPython, cat: CategoryCode,
				conf: ConfidenceHigh, stats: Stats{AddedCode: 1}, newFile: true,
			}},
		},
		{
			// autohand search_replace (same fixture).
			name: "autohand blocks",
			in: edit("hello_world.py", `{"path":"hello_world.py","blocks":"<<<<<<< SEARCH\nprint(\"hello world\")\n`+
				`=======\nprint(\"hello autohand\")\n>>>>>>> REPLACE"}`),
			want: []wantFile{{
				shape: ShapeSearchReplace, path: "hello_world.py", lang: LangPython, cat: CategoryCode,
				conf: ConfidenceHigh, stats: Stats{ModifiedCode: 1},
			}},
		},
		{
			// autohand apply_patch (autohand-cli dist definition: path +
			// unified-diff patch).
			name: "autohand patch unified diff",
			in:   edit("a.py", `{"path":"a.py","patch":"--- a/a.py\n+++ b/a.py\n@@ -1,2 +1,3 @@\n x = 1\n-y = 2\n+y = 3\n+z = 4\n"}`),
			want: []wantFile{{
				shape: ShapePatchDiff, path: "a.py", lang: LangPython, cat: CategoryCode,
				conf: ConfidenceHigh, stats: Stats{ModifiedCode: 1, AddedCode: 1},
			}},
		},
		{
			// vtcode apply_patch wrapped in an object (vtcode tools.go
			// patchText keys input|patch).
			name: "vtcode wrapped begin patch",
			in:   edit("src/a.rs", `{"input":"*** Begin Patch\n*** Update File: src/a.rs\n@@\n-let a = 1;\n+let a = 2;\n*** End Patch"}`),
			want: []wantFile{{
				shape: ShapeWrappedPatch, path: "src/a.rs", lang: LangRust, cat: CategoryCode,
				conf: ConfidenceHigh, stats: Stats{ModifiedCode: 1},
			}},
		},
		{
			// vtcode apply_patch stored as a bare JSON string: was counted
			// as a whole-file write of the patch text before v3.
			name: "vtcode json string begin patch",
			in:   edit("src/a.rs", `"*** Begin Patch\n*** Update File: src/a.rs\n@@\n-let a = 1;\n+let a = 2;\n*** End Patch"`),
			want: []wantFile{{
				shape: ShapeWrappedPatch, path: "src/a.rs", lang: LangRust, cat: CategoryCode,
				conf: ConfidenceHigh, stats: Stats{ModifiedCode: 1},
			}},
		},
		{
			// dirac edit_file (live Windows task 1792584662340): an insert
			// is exact; a one-line replace is exact.
			name: "dirac anchor edits",
			in: edit("probe.py", `{"files":[{"path":"probe.py","edits":[`+
				`{"edit_type":"insert_after","anchor":"Award§x = 1","end_anchor":null,"text":"gamma = 1"},`+
				`{"edit_type":"replace","anchor":"Bfox§y = 2","end_anchor":"Bfox§y = 2","text":"y = 3"}]}]}`),
			want: []wantFile{{
				shape: ShapeAnchorEdits, path: "probe.py", lang: LangPython, cat: CategoryCode,
				conf: ConfidenceHigh, stats: Stats{AddedCode: 1, ModifiedCode: 1},
			}},
		},
		{
			// dirac edit_file multi-line replace: endpoints known, the
			// lines between them are not — partial, so ConfidenceLow.
			name: "dirac anchor range replace is low confidence",
			in: edit("probe.py", `{"files":[{"path":"probe.py","edits":[`+
				`{"edit_type":"replace","anchor":"Aa§def f():","end_anchor":"Bb§    return 1","text":"def f():\n    return 2"}]}]}`),
			want: []wantFile{{
				shape: ShapeAnchorEdits, path: "probe.py", lang: LangPython, cat: CategoryCode,
				conf: ConfidenceLow, stats: Stats{ModifiedCode: 1},
			}},
		},
		{
			// dirac edit_ast replace (dirac-cli EditAstTool.ts): the new
			// definition is additions; the old one is not in the payload.
			name: "dirac edit_ast replace",
			in:   edit("svc.go", `{"operation":"replace","targets":[{"path":"svc.go","symbol":"Load","replacement":"func Load() {\n}"}]}`),
			want: []wantFile{{
				shape: ShapeASTReplace, path: "svc.go", lang: LangGo, cat: CategoryCode,
				conf: ConfidenceLow, stats: Stats{AddedCode: 2},
			}},
		},
		{
			// dirac edit_ast rename: nothing measurable, file touched.
			name: "dirac edit_ast rename",
			in:   edit("svc.go", `{"operation":"rename","targets":[{"path":"svc.go","symbol":"Load","replacement":"Fetch"}]}`),
			want: []wantFile{{shape: ShapePathOnly, path: "svc.go", lang: LangGo, cat: CategoryCode, conf: ConfidenceLow}},
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

// TestExtractWave1021FallThrough pins the guards: a `patch`/`input` that is
// neither an envelope nor a diff body, and a `files` array that is not
// dirac's shape, fall through instead of reporting a confident zero.
func TestExtractWave1021FallThrough(t *testing.T) {
	t.Parallel()
	for _, raw := range []string{
		`{"input":"just some text"}`,
		`{"files":["a.go","b.go"]}`,
	} {
		got := Extract(Input{ActionType: "edit_file", Target: "a.go", RawToolInput: raw})
		if len(got) != 1 || got[0].Shape != ShapeUnrecognized {
			t.Errorf("%s: got %+v, want one unrecognized row", raw, got)
		}
	}
}
