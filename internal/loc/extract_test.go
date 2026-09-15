package loc

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestExtractShapeLadder is the golden per shape (plan §3.1): one row per
// input shape the live corpus carries, each asserting the Shape that
// matched, the file(s) it resolved, and the buckets it produced.
//
// The payloads are SYNTHETIC equivalents of the real shapes — the shapes
// were read off a live corpus, the content was written for this test.
func TestExtractShapeLadder(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		in    Input
		want  []wantFile
		files int
	}{
		{
			// claude-code / gemini / cowork / command-code.
			name: "old_string new_string",
			in: Input{
				ActionType:  "edit_file",
				Target:      "/repo/a.go",
				BeforeLines: -1,
				RawToolInput: `{"file_path":"/repo/a.go",` +
					`"old_string":"a := 1\n// note\n","new_string":"a := 2\n// note\n\nb := 3\n"}`,
			},
			want: []wantFile{{
				shape: ShapeOldNewString, path: "/repo/a.go", lang: LangGo, cat: CategoryCode,
				conf:  ConfidenceHigh,
				stats: Stats{ModifiedCode: 1, AddedCode: 1, Blank: 1},
			}},
		},
		{
			// opencode.
			name: "oldString newString",
			in: Input{
				ActionType:  "edit_file",
				Target:      `C:\proj\vite.config.ts`,
				BeforeLines: -1,
				RawToolInput: `{"filePath":"C:\\proj\\vite.config.ts",` +
					`"oldString":"const a = 1","newString":"const a = 2"}`,
			},
			want: []wantFile{{
				shape: ShapeOldNewCamel, path: `C:\proj\vite.config.ts`,
				lang: LangTypeScript, cat: CategoryCode, conf: ConfidenceHigh,
				stats: Stats{ModifiedCode: 1},
			}},
		},
		{
			// copilot-cli.
			name: "old_str new_str",
			in: Input{
				ActionType:   "edit_file",
				Target:       "/repo/x.py",
				BeforeLines:  -1,
				RawToolInput: `{"path":"/repo/x.py","old_str":"x = 1","new_str":"x = 2"}`,
			},
			want: []wantFile{{
				shape: ShapeOldNewSnakeAbb, path: "/repo/x.py", lang: LangPython,
				cat: CategoryCode, conf: ConfidenceHigh,
				stats: Stats{ModifiedCode: 1},
			}},
		},
		{
			// MultiEdit: several pairs against ONE file, summed into one row.
			name: "edits array",
			in: Input{
				ActionType:  "edit_file",
				Target:      "/repo/a.go",
				BeforeLines: -1,
				RawToolInput: `{"file_path":"/repo/a.go","edits":[` +
					`{"old_string":"a := 1","new_string":"a := 2"},` +
					`{"old_string":"b := 1","new_string":"b := 2"}]}`,
			},
			want: []wantFile{{
				shape: ShapeEdits, path: "/repo/a.go", lang: LangGo, cat: CategoryCode,
				conf: ConfidenceHigh, stats: Stats{ModifiedCode: 2},
			}},
		},
		{
			// NotebookEdit.
			name: "new_source",
			in: Input{
				ActionType:   "edit_file",
				Target:       "/repo/nb.ipynb",
				BeforeLines:  -1,
				RawToolInput: `{"notebook_path":"/repo/nb.ipynb","new_source":"x = 1\ny = 2"}`,
			},
			want: []wantFile{{
				shape: ShapeNewSource, path: "/repo/nb.ipynb", lang: LangNotebook,
				cat: CategoryCode, conf: ConfidenceHigh, stats: Stats{AddedCode: 2},
			}},
		},
		{
			// codex patch_apply_end executor shape: keys are PATHS.
			name: "codex changes map",
			in: Input{
				ActionType:  "edit_file",
				Target:      "calc.py",
				BeforeLines: -1,
				RawToolInput: `{"/t/calc.py":{"move_path":null,"type":"update",` +
					`"unified_diff":"@@ -1,2 +1,2 @@\n def add(a, b):\n-    return a - b\n+    return a + b\n"}}`,
			},
			want: []wantFile{{
				shape: ShapeCodexChanges, path: "/t/calc.py", lang: LangPython,
				cat: CategoryCode, conf: ConfidenceHigh, stats: Stats{ModifiedCode: 1},
			}},
		},
		{
			// A bare envelope touching THREE files, one of them a delete.
			// Acceptance criterion 2.
			name: "bare begin patch, multi file with a delete",
			in: Input{
				ActionType:  "edit_file",
				Target:      "src/a.go",
				BeforeLines: -1,
				RawToolInput: "*** Begin Patch\n" +
					"*** Update File: src/a.go\n@@\n-old := 1\n+new := 2\n" +
					"*** Delete File: src/gone.go\n" +
					"*** Add File: src/new.go\n+package q\n+// c\n" +
					"*** End Patch",
			},
			want: []wantFile{
				{
					shape: ShapeCodexPatch, path: "src/a.go", lang: LangGo, cat: CategoryCode,
					conf: ConfidenceHigh, stats: Stats{ModifiedCode: 1},
				},
				{
					shape: ShapeCodexPatch, path: "src/gone.go", lang: LangGo, cat: CategoryCode,
					conf: ConfidenceMedium, deleted: true,
				},
				{
					shape: ShapeCodexPatch, path: "src/new.go", lang: LangGo, cat: CategoryCode,
					conf: ConfidenceHigh, newFile: true,
					stats: Stats{AddedCode: 1, AddedComment: 1},
				},
			},
		},
		{
			// The unified-exec JS wrapper, decoded through internal/codexpatch.
			name: "codex js wrapper",
			in: Input{
				ActionType:  "edit_file",
				Target:      "a.ts",
				BeforeLines: -1,
				RawToolInput: "const patch = \"*** Begin Patch\\n*** Update File: a.ts\\n" +
					"@@\\n-let x = 1\\n+let x = 2\\n*** End Patch\";\n" +
					"await tools.apply_patch(patch);",
			},
			want: []wantFile{{
				shape: ShapeCodexJS, path: "a.ts", lang: LangTypeScript,
				cat: CategoryCode, conf: ConfidenceHigh, stats: Stats{ModifiedCode: 1},
			}},
		},
		{
			// cursor's afterFileEdit hook: the whole body IS the path. The
			// same edit's before/after text lives on cursor's OTHER row
			// (the transcript StrReplace one), so nothing is lost — but
			// counting this line as a one-line file would be a fabrication.
			name: "path only hook row",
			in: Input{
				ActionType:   "edit_file",
				Target:       "/repo/docs/x.md",
				BeforeLines:  -1,
				RawToolInput: "/repo/docs/x.md",
			},
			want: []wantFile{{
				shape: ShapePathOnly, path: "/repo/docs/x.md", lang: LangMarkdown,
				cat: CategoryDocs, conf: ConfidenceLow,
			}},
		},
		{
			// junie writes the change's after-content into raw_tool_input
			// with no envelope at all.
			name: "plain content",
			in: Input{
				ActionType:   "write_file",
				Target:       "/repo/hello.py",
				BeforeLines:  -1,
				RawToolInput: "print(\"Hello\")",
			},
			want: []wantFile{{
				shape: ShapePlainContent, path: "/repo/hello.py", lang: LangPython,
				cat: CategoryCode, conf: ConfidenceHigh, newFile: true,
				stats: Stats{AddedCode: 1},
			}},
		},
		{
			// A capped input is a PARTIAL edit, not a smaller one.
			name: "truncated",
			in: Input{
				ActionType:   "edit_file",
				Target:       "/repo/a.go",
				BeforeLines:  -1,
				RawToolInput: `{"file_path":"/repo/a.go","old_string":"a` + truncationMarker,
			},
			want: []wantFile{{
				shape: ShapeTruncated, path: "/repo/a.go", lang: LangGo,
				cat: CategoryCode, conf: ConfidenceLow,
			}},
		},
		{
			name: "json with no known keys",
			in: Input{
				ActionType:   "edit_file",
				Target:       "/repo/a.go",
				BeforeLines:  -1,
				RawToolInput: `{"something":"else"}`,
			},
			want: []wantFile{{
				shape: ShapeUnrecognized, path: "/repo/a.go", lang: LangGo,
				cat: CategoryCode, conf: ConfidenceLow,
			}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := Extract(tt.in)
			assertFiles(t, got, tt.want)
		})
	}
}

// wantFile is one expected FileStats.
type wantFile struct {
	shape   Shape
	path    string
	lang    Lang
	cat     Category
	conf    Confidence
	stats   Stats
	newFile bool
	deleted bool
	overwr  bool
}

// assertFiles compares extracted rows against expectations, reporting
// every mismatch rather than stopping at the first.
func assertFiles(t *testing.T, got []FileStats, want []wantFile) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %d files, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		g, w := got[i], want[i]
		if g.Shape != w.shape {
			t.Errorf("file %d: shape = %q, want %q", i, g.Shape, w.shape)
		}
		if g.Path != w.path {
			t.Errorf("file %d: path = %q, want %q", i, g.Path, w.path)
		}
		if g.Lang != w.lang {
			t.Errorf("file %d: lang = %q, want %q", i, g.Lang, w.lang)
		}
		if g.Category != w.cat {
			t.Errorf("file %d: category = %q, want %q", i, g.Category, w.cat)
		}
		if g.Confidence != w.conf {
			t.Errorf("file %d: confidence = %q, want %q", i, g.Confidence, w.conf)
		}
		if g.Stats != w.stats {
			t.Errorf("file %d: stats = %+v, want %+v", i, g.Stats, w.stats)
		}
		if g.NewFile != w.newFile {
			t.Errorf("file %d: new_file = %v, want %v", i, g.NewFile, w.newFile)
		}
		if g.DeletedFile != w.deleted {
			t.Errorf("file %d: deleted_file = %v, want %v", i, g.DeletedFile, w.deleted)
		}
		if g.Overwrite != w.overwr {
			t.Errorf("file %d: overwrite = %v, want %v", i, g.Overwrite, w.overwr)
		}
	}
}

// TestExtractWriteOverwriteAndNewFile pins acceptance criterion 3: a
// write over an existing file is overwrite=true with the prior read's
// line count as before-image at medium confidence, and a write of a file
// nothing has seen is a new file at high confidence.
func TestExtractWriteOverwriteAndNewFile(t *testing.T) {
	t.Parallel()
	payload := `{"file_path":"/repo/b.go","content":"package x\n\n// hi\nfunc f() {}\n"}`

	t.Run("new file", func(t *testing.T) {
		got := Extract(Input{
			ActionType: "write_file", Target: "/repo/b.go",
			RawToolInput: payload, BeforeLines: -1, Existed: false,
		})
		assertFiles(t, got, []wantFile{{
			shape: ShapeContent, path: "/repo/b.go", lang: LangGo, cat: CategoryCode,
			conf: ConfidenceHigh, newFile: true,
			stats: Stats{AddedCode: 2, AddedComment: 1, Blank: 1},
		}})
	})

	t.Run("overwrite with a before-image line count", func(t *testing.T) {
		got := Extract(Input{
			ActionType: "write_file", Target: "/repo/b.go",
			RawToolInput: payload, BeforeLines: 6, Existed: true,
		})
		// 6 un-measurable old lines against 4 new ones: four pair up
		// (each booking one Unknown for the old side plus the new line's
		// own class) and two are pure deletes, also Unknown. The row
		// carries overwrite=true so the UI labels the reconstruction.
		assertFiles(t, got, []wantFile{{
			shape: ShapeContent, path: "/repo/b.go", lang: LangGo, cat: CategoryCode,
			conf: ConfidenceMedium, overwr: true,
			stats: Stats{AddedCode: 2, AddedComment: 1, Blank: 1, Unknown: 6},
		}})
	})

	t.Run("overwrite with no before-image at all", func(t *testing.T) {
		got := Extract(Input{
			ActionType: "write_file", Target: "/repo/b.go",
			RawToolInput: payload, BeforeLines: -1, Existed: true,
		})
		if len(got) != 1 {
			t.Fatalf("got %d files, want 1", len(got))
		}
		if !got[0].Overwrite {
			t.Error("overwrite = false, want true")
		}
		if got[0].Confidence != ConfidenceLow {
			t.Errorf("confidence = %q, want low — the before-image is unknown", got[0].Confidence)
		}
	})
}

// TestExtractSkipsGeneratedAndVendored pins acceptance criterion 5: a
// lockfile, a node_modules path, a dist bundle and a *.pb.go contribute
// no lines, while testdata/ and build/ source files DO (codeintel
// excludes those by basename; loc deliberately does not).
func TestExtractSkipsGeneratedAndVendored(t *testing.T) {
	t.Parallel()
	body := "line one\nline two\nline three\n"
	tests := []struct {
		path      string
		wantCat   Category
		wantLines bool
	}{
		{"/repo/package-lock.json", CategoryGenerated, false},
		{"/repo/node_modules/x/index.js", CategoryVendored, false},
		{"/repo/dist/bundle.js", CategoryGenerated, false},
		{"/repo/api/service.pb.go", CategoryGenerated, false},
		{"/repo/vendor/x/y.go", CategoryVendored, false},
		{"/repo/testdata/fixture.go", CategoryCode, true},
		{"/repo/build/tool.go", CategoryCode, true},
		{"/repo/bin/helper.go", CategoryCode, true},
		{"/repo/target/gen.rs", CategoryCode, true},
		{"/repo/README.md", CategoryDocs, true},
		{"/repo/config.yaml", CategoryConfig, true},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := Extract(Input{
				ActionType:   "write_file",
				Target:       tt.path,
				BeforeLines:  -1,
				RawToolInput: mustJSONWrite(tt.path, body),
			})
			if len(got) != 1 {
				t.Fatalf("got %d files, want 1", len(got))
			}
			if got[0].Category != tt.wantCat {
				t.Errorf("category = %q, want %q", got[0].Category, tt.wantCat)
			}
			if hasLines := got[0].Stats.Total() > 0; hasLines != tt.wantLines {
				t.Errorf("counted lines = %v (stats %+v), want %v",
					hasLines, got[0].Stats, tt.wantLines)
			}
		})
	}
}

// mustJSONWrite builds a Write payload for a path and body.
func mustJSONWrite(path, body string) string {
	esc := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)
	return `{"file_path":"` + esc.Replace(path) + `","content":"` + esc.Replace(body) + `"}`
}

// TestExtractCodexInvocationAndExecutorShareADigest pins the dedup key
// (plan §3.2, acceptance criterion 2): the model's `*** Begin Patch`
// invocation and the executor's `unified_diff` are the SAME change in two
// renderings, and must hash alike so the store collapses the pair into
// one counted authorship.
func TestExtractCodexInvocationAndExecutorShareADigest(t *testing.T) {
	t.Parallel()
	invocation := Extract(Input{
		ActionType: "edit_file", Target: "calc.py", BeforeLines: -1,
		RawToolInput: "*** Begin Patch\n*** Update File: calc.py\n@@\n" +
			" def add(a, b):\n-    return a - b\n+    return a + b\n*** End Patch",
	})
	executor := Extract(Input{
		ActionType: "edit_file", Target: "calc.py", BeforeLines: -1,
		RawToolInput: `{"calc.py":{"move_path":null,"type":"update","unified_diff":` +
			`"@@ -1,2 +1,2 @@\n def add(a, b):\n-    return a - b\n+    return a + b\n"}}`,
	})
	if len(invocation) != 1 || len(executor) != 1 {
		t.Fatalf("want one file each, got %d and %d", len(invocation), len(executor))
	}
	if invocation[0].InputDigest != executor[0].InputDigest {
		t.Errorf("digests differ — the codex invocation/executor pair would double-count:\n"+
			"  invocation %s\n  executor   %s",
			invocation[0].InputDigest, executor[0].InputDigest)
	}
	if invocation[0].Stats != executor[0].Stats {
		t.Errorf("same change counted differently: %+v vs %+v",
			invocation[0].Stats, executor[0].Stats)
	}
}

// TestExtractEmptyAndGarbageAreSafe pins that no input panics and that an
// empty one produces no row at all (an action with no input is not a file
// that was touched).
func TestExtractEmptyAndGarbageAreSafe(t *testing.T) {
	t.Parallel()
	for _, raw := range []string{"", "   ", "\n\n", "{", "{]", "\x00\x01\x02"} {
		got := Extract(Input{
			ActionType: "edit_file", Target: "/repo/a.go",
			RawToolInput: raw, BeforeLines: -1,
		})
		if strings.TrimSpace(raw) == "" && len(got) != 0 {
			t.Errorf("Extract(%q) = %d rows, want none", raw, len(got))
		}
		for _, fs := range got {
			if fs.Stats.Total() != 0 && fs.Shape == ShapeUnrecognized {
				t.Errorf("Extract(%q) invented %+v for an unrecognised shape", raw, fs.Stats)
			}
		}
	}
}

// TestExtractDeterministicFileOrder pins that a multi-file patch always
// returns files in the same order — map iteration is not ordered and a
// flapping order would make every golden flaky.
func TestExtractDeterministicFileOrder(t *testing.T) {
	t.Parallel()
	raw := `{"z.go":{"type":"add","content":"package z\n"},` +
		`"a.go":{"type":"add","content":"package a\n"},` +
		`"m.go":{"type":"add","content":"package m\n"}}`
	for i := 0; i < 20; i++ {
		got := Extract(Input{ActionType: "edit_file", Target: "", RawToolInput: raw, BeforeLines: -1})
		if len(got) != 3 {
			t.Fatalf("got %d files, want 3", len(got))
		}
		if got[0].Path != "a.go" || got[1].Path != "m.go" || got[2].Path != "z.go" {
			t.Fatalf("iteration %d: order = %q %q %q, want a.go m.go z.go",
				i, got[0].Path, got[1].Path, got[2].Path)
		}
	}
}

// ---------------------------------------------------------------------
// Review fixes (2026-09-07): L2 (shape-ladder gaps), L3 (generated header)
// ---------------------------------------------------------------------

// TestClineReplaceInFileIsCounted pins review finding L2's first half.
// cline (and its Kilo fork) store `replace_in_file` as
// {"path":…,"diff":"------- SEARCH…"}, which matched no ladder row and
// landed as `unrecognized` with zero lines — an honest zero, but a
// coverage hole across three VS-Code-family adapters.
func TestClineReplaceInFileIsCounted(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		raw   string
		want  Stats
		paths string
	}{
		{
			// The reviewer's executed probe input, verbatim.
			name: "dashed markers, one block",
			raw: `{"path":"src/a.go","diff":"------- SEARCH\nfunc a() {}\n` +
				`=======\nfunc a() { return }\n+++++++ REPLACE"}`,
			want:  Stats{ModifiedCode: 1},
			paths: "src/a.go",
		},
		{
			name: "conflict-marker family, older builds",
			raw: `{"path":"src/a.go","diff":"<<<<<<< SEARCH\nfunc a() {}\n` +
				`=======\nfunc a() { return }\n>>>>>>> REPLACE"}`,
			want:  Stats{ModifiedCode: 1},
			paths: "src/a.go",
		},
		{
			name: "several blocks against one file are summed",
			raw: `{"path":"src/a.go","diff":"------- SEARCH\na := 1\n=======\na := 2\n` +
				`+++++++ REPLACE\n------- SEARCH\nb := 1\n=======\nb := 2\nc := 3\n+++++++ REPLACE"}`,
			want:  Stats{ModifiedCode: 2, AddedCode: 1},
			paths: "src/a.go",
		},
		{
			// A pure insertion: an empty SEARCH half.
			name: "empty search half is an insertion",
			raw: `{"path":"src/a.go","diff":"------- SEARCH\n=======\nadded := 1\n` +
				`+++++++ REPLACE"}`,
			want:  Stats{AddedCode: 1},
			paths: "src/a.go",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := Extract(Input{
				RawToolInput: tt.raw, ActionType: "edit_file",
				Target: "src/a.go", BeforeLines: -1,
			})
			if len(got) != 1 {
				t.Fatalf("rows = %d, want 1: %+v", len(got), got)
			}
			if got[0].Shape != ShapeSearchReplace {
				t.Errorf("shape = %q, want %q", got[0].Shape, ShapeSearchReplace)
			}
			if got[0].Path != tt.paths {
				t.Errorf("path = %q, want %q", got[0].Path, tt.paths)
			}
			if got[0].Stats != tt.want {
				t.Errorf("stats = %+v, want %+v", got[0].Stats, tt.want)
			}
			if got[0].InputDigest == "" {
				t.Error("no input digest — the row cannot deduplicate")
			}
		})
	}
}

// TestSearchReplaceWithNoBlocksFallsThrough pins that a `diff` key that
// carries something else does not become a confident zero: the ladder
// falls through and the row says `unrecognized`, which is the honest
// answer.
func TestSearchReplaceWithNoBlocksFallsThrough(t *testing.T) {
	t.Parallel()
	got := Extract(Input{
		RawToolInput: `{"path":"src/a.go","diff":"not a search replace block at all"}`,
		ActionType:   "edit_file", Target: "src/a.go", BeforeLines: -1,
	})
	if len(got) != 1 {
		t.Fatalf("rows = %d, want 1", len(got))
	}
	if got[0].Shape != ShapeUnrecognized {
		t.Errorf("shape = %q, want %q", got[0].Shape, ShapeUnrecognized)
	}
	if got[0].Stats.Total() != 0 {
		t.Errorf("an unreadable diff produced counts: %+v", got[0].Stats)
	}
}

// TestGooseWriteFileTextIsCounted pins review finding L2's second half.
// goose's developer extension stores a whole-file write as
// {"command":"write","path":…,"file_text":…}.
func TestGooseWriteFileTextIsCounted(t *testing.T) {
	t.Parallel()

	// The reviewer's executed probe input, verbatim.
	raw := `{"command":"write","path":"src/b.go","file_text":"package b\n\nfunc B() {}\n"}`

	t.Run("new file", func(t *testing.T) {
		t.Parallel()
		got := Extract(Input{
			RawToolInput: raw, ActionType: "write_file",
			Target: "src/b.go", BeforeLines: -1,
		})
		if len(got) != 1 {
			t.Fatalf("rows = %d, want 1: %+v", len(got), got)
		}
		if got[0].Shape != ShapeFileText {
			t.Errorf("shape = %q, want %q", got[0].Shape, ShapeFileText)
		}
		if got[0].Path != "src/b.go" || got[0].Lang != LangGo {
			t.Errorf("path/lang = %q/%q, want src/b.go/go", got[0].Path, got[0].Lang)
		}
		if !got[0].NewFile {
			t.Error("a write to a file with no before-image is not marked NewFile")
		}
		if got[0].Stats.AddedCode != 2 || got[0].Stats.Blank != 1 {
			t.Errorf("stats = %+v, want 2 added code + 1 blank", got[0].Stats)
		}
	})

	t.Run("overwrite uses the before-image line count", func(t *testing.T) {
		t.Parallel()
		got := Extract(Input{
			RawToolInput: raw, ActionType: "write_file",
			Target: "src/b.go", Existed: true, BeforeLines: 3,
		})
		if len(got) != 1 {
			t.Fatalf("rows = %d, want 1", len(got))
		}
		if !got[0].Overwrite || got[0].NewFile {
			t.Errorf("overwrite=%v newfile=%v, want overwrite only",
				got[0].Overwrite, got[0].NewFile)
		}
		if got[0].Confidence != ConfidenceMedium {
			t.Errorf("confidence = %q, want medium (the before-image is a reconstruction)",
				got[0].Confidence)
		}
	})
}

// TestGeneratedHeaderMakesAWholeWriteGenerated pins review finding L3's
// content half: a generator that names its output whatever the spec said
// still stamps the canonical banner, and the after-image of a
// whole-content write is in hand at count time.
func TestGeneratedHeaderMakesAWholeWriteGenerated(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		content string
		want    bool
	}{
		{
			name:    "go banner on line 1",
			content: "// Code generated by oapi-codegen. DO NOT EDIT.\npackage gen\n\nvar X = 1\n",
			want:    true,
		},
		{
			name:    "banner after a build tag",
			content: "//go:build !ignore\n\n// Code generated by mockgen. DO NOT EDIT.\npackage m\n",
			want:    true,
		},
		{
			name:    "python leader",
			content: "# Code generated by protoc-gen-python. DO NOT EDIT.\nimport os\n",
			want:    true,
		},
		{
			// Past the scan window it is prose ABOUT generated code.
			name: "banner too far down is prose",
			content: "package a\n\nvar x = 1\n\n" +
				"// Code generated files carry DO NOT EDIT. banners.\n",
			want: false,
		},
		{
			// Both halves must be on the SAME line.
			name:    "half a banner is not a banner",
			content: "// Code generated by hand, edit freely\npackage a\n\nvar x = 1\n",
			want:    false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := HasGeneratedHeader(tt.content); got != tt.want {
				t.Fatalf("HasGeneratedHeader = %v, want %v", got, tt.want)
			}
			raw, err := json.Marshal(map[string]string{
				"file_path": "internal/api/models.go", "content": tt.content,
			})
			if err != nil {
				t.Fatal(err)
			}
			rows := Extract(Input{
				RawToolInput: string(raw), ActionType: "write_file",
				Target: "internal/api/models.go", BeforeLines: -1,
			})
			if len(rows) != 1 {
				t.Fatalf("rows = %d, want 1", len(rows))
			}
			if tt.want {
				if rows[0].Category != CategoryGenerated {
					t.Errorf("category = %q, want generated", rows[0].Category)
				}
				if rows[0].Stats.Total() != 0 {
					t.Errorf("a generated file contributed %+v, want nothing", rows[0].Stats)
				}
				return
			}
			if rows[0].Category != CategoryCode {
				t.Errorf("category = %q, want code", rows[0].Category)
			}
			if rows[0].Stats.Total() == 0 {
				t.Error("a hand-written file counted nothing")
			}
		})
	}
}
