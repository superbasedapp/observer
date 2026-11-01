package ibmbob

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/loc"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/scrub"
)

func TestChangedLines(t *testing.T) {
	tests := []struct {
		name, patch, want string
	}{
		{
			// Live write_file shape (testdata/ibmbob/real.sql).
			name: "new file with headers",
			patch: "Index: file:///home/user/proj/a.py\n" +
				"===================================================================\n" +
				"--- file:///home/user/proj/a.py\n+++ file:///home/user/proj/a.py\n" +
				"@@ -0,0 +1,1 @@\n+print(\"hi\")\n",
			want: "@@\n+print(\"hi\")\n",
		},
		{
			name:  "context runs become separators",
			patch: "--- a\n+++ b\n@@ -1,6 +1,6 @@\n keep1\n-old1\n+new1\n keep2\n keep3\n-old2\n+new2\n keep4\n",
			want:  "@@\n-old1\n+new1\n@@\n-old2\n+new2\n",
		},
		{
			name:  "second hunk header",
			patch: "@@ -1,1 +1,1 @@\n-a\n+b\n@@ -9,1 +9,1 @@\n-c\n+d\n",
			want:  "@@\n-a\n+b\n@@\n-c\n+d\n",
		},
		{
			name:  "no newline marker dropped, sql comment kept",
			patch: "@@ -1,1 +1,1 @@\n--- old sql comment\n\\ No newline at end of file\n+-- new\n",
			want:  "@@\n--- old sql comment\n+-- new\n",
		},
		{
			name:  "no change lines",
			patch: "Index: x\n--- x\n+++ x\n@@ -1,1 +1,1 @@\n same\n",
			want:  "",
		},
		{name: "empty", patch: "", want: ""},
	}
	for _, tc := range tests {
		if got := changedLines(tc.patch); got != tc.want {
			t.Errorf("%s: changedLines = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestURIPath(t *testing.T) {
	for in, want := range map[string]string{
		"file:///home/user/proj/a.py":       "/home/user/proj/a.py",
		"file:///C:/Users/user/proj/a.py":   "C:/Users/user/proj/a.py",
		"file:///c%3A/Users/user/my%20a.py": "c:/Users/user/my a.py",
		"/plain/path.go":                    "/plain/path.go",
	} {
		if got := uriPath(in); got != want {
			t.Errorf("uriPath(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestRealChangeRecords: the real write_file and search_and_replace calls
// carry the exact change under loc.BobChangesKey, and the LOC counter
// counts it with the ShapeBobChanges row on the call's own path.
func TestRealChangeRecords(t *testing.T) {
	res := parseReal(t)
	type want struct {
		path  string
		stats loc.Stats
	}
	wants := map[string]want{
		realWSLTask + "|write_file":         {"/home/user/proj/hello_world.py", loc.Stats{AddedCode: 1}},
		realWSLTask + "|search_and_replace": {"/home/user/proj/hello_world.py", loc.Stats{ModifiedCode: 1}},
		realWinTask + "|write_file":         {`C:\Users\user\proj\hello_world.py`, loc.Stats{AddedCode: 1}},
		realWinTask + "|search_and_replace": {`C:\Users\user\proj\hello_world.py`, loc.Stats{ModifiedCode: 1}},
	}
	seen := 0
	for _, e := range res.ToolEvents {
		w, ok := wants[e.SessionID+"|"+e.RawToolName]
		if !ok {
			if strings.Contains(e.RawToolInput, loc.BobChangesKey) {
				t.Errorf("%s (%s) carries a change record", e.SourceEventID, e.ActionType)
			}
			continue
		}
		seen++
		var obj map[string]json.RawMessage
		if err := json.Unmarshal([]byte(e.RawToolInput), &obj); err != nil {
			t.Fatalf("%s RawToolInput is not JSON: %v", e.SourceEventID, err)
		}
		if _, ok := obj["path"]; !ok {
			t.Errorf("%s lost its native arguments: %s", e.SourceEventID, e.RawToolInput)
		}
		var recs []changeRecord
		if err := json.Unmarshal(obj[loc.BobChangesKey], &recs); err != nil || len(recs) != 1 {
			t.Fatalf("%s change records = %s (%v)", e.SourceEventID, obj[loc.BobChangesKey], err)
		}
		if strings.Contains(recs[0].Hunks, "file://") || strings.Contains(recs[0].Hunks, "Index:") {
			t.Errorf("%s hunks keep diff headers: %q", e.SourceEventID, recs[0].Hunks)
		}
		files := loc.Extract(loc.Input{RawToolInput: e.RawToolInput, ActionType: e.ActionType, Target: e.Target, BeforeLines: -1})
		if len(files) != 1 {
			t.Fatalf("%s: %d LOC rows", e.SourceEventID, len(files))
		}
		f := files[0]
		if f.Shape != loc.ShapeBobChanges || f.Path != w.path || f.Stats != w.stats || f.Confidence != loc.ConfidenceHigh {
			t.Errorf("%s LOC = shape %s path %q stats %+v conf %s, want %q %+v",
				e.SourceEventID, f.Shape, f.Path, f.Stats, f.Confidence, w.path, w.stats)
		}
		if f.Path != e.Target {
			t.Errorf("%s LOC path %q != action target %q", e.SourceEventID, f.Path, e.Target)
		}
	}
	if seen != len(wants) {
		t.Errorf("saw %d edit/write calls, want %d", seen, len(wants))
	}
}

// TestRawToolInputFallbacks: the plain arguments are kept when no record
// applies.
func TestRawToolInputFallbacks(t *testing.T) {
	a := NewWithOptions(scrub.New(), []string{"x"})
	change := map[string]fileChange{"file:///w/a.py": {Patch: "@@ -1 +1 @@\n-a = 1\n+a = 2\n"}}
	args := json.RawMessage(`{"path":"/w/a.py","search":"a = 1","replace":"a = 2"}`)
	plain := a.scrubRaw(args)

	if got := a.rawToolInput(models.ActionEditFile, args, change); !strings.Contains(got, loc.BobChangesKey) {
		t.Fatalf("edit with changes lost its record: %s", got)
	}
	if got := a.rawToolInput(models.ActionRunCommand, args, change); got != plain {
		t.Errorf("non-edit action got %s", got)
	}
	if got := a.rawToolInput(models.ActionEditFile, args, nil); got != plain {
		t.Errorf("no changes got %s", got)
	}
	if got := a.rawToolInput(models.ActionEditFile, args, map[string]fileChange{"file:///w/a.py": {Patch: "@@\n same\n"}}); got != plain {
		t.Errorf("context-only diff got %s", got)
	}
	taken := json.RawMessage(`{"path":"/w/a.py","_bob_changes":"vendor"}`)
	if got := a.rawToolInput(models.ActionEditFile, taken, change); got != a.scrubRaw(taken) {
		t.Errorf("vendor key collision got %s", got)
	}
	if got := a.rawToolInput(models.ActionEditFile, json.RawMessage(`"bare string"`), change); got != `"bare string"` {
		t.Errorf("non-object args got %s", got)
	}

	// Arguments that fit the cap alone but not with the record keep the
	// plain arguments rather than a truncated payload.
	big := strings.Repeat("x = 1\n", scrub.MaxRawInputBytes/12)
	bigArgs, _ := json.Marshal(map[string]string{"path": "/w/a.py", "content": big})
	bigChange := map[string]fileChange{"file:///w/a.py": {Patch: "@@ -0,0 +1 @@\n" + strings.ReplaceAll(big, "x = 1\n", "+x = 1\n")}}
	if got := a.rawToolInput(models.ActionWriteFile, bigArgs, bigChange); got != a.scrubRaw(bigArgs) {
		t.Errorf("oversized record was not dropped (len %d)", len(got))
	}
}
