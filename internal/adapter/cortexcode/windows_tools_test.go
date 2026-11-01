package cortexcode

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

// TestParseWindowsToolFixture pins the live Windows tool-call session
// (2026-10-22). Cortex stores the native tool names on Windows too: the
// TUI labels the shell calls POWERSHELL, but the record says `bash` and
// only the result text names PowerShell. File paths are Windows drive
// paths and land relative to the (translated) project root; glob and grep
// targets are their patterns. Each row is one tool call in order.
func TestParseWindowsToolFixture(t *testing.T) {
	dir := stageFixture(t, "windows", winToolSID)
	res := parse(t, NewWithOptions(nil, dir), filepath.Join(dir, winToolSID+historySuffix), 0)

	want := []struct {
		raw, action, target string
		bytes, durationMs   int64
		outputContains      string
	}{
		{"write", models.ActionWriteFile, "notes.txt", int64(len("alpha")), 52, "File written successfully"},
		{"read", models.ActionReadFile, "notes.txt", 0, 48, "alpha"},
		{"edit", models.ActionEditFile, "notes.txt", int64(len("beta")), 37, "File edited successfully"},
		{"bash", models.ActionRunCommand, "echo hi", 0, 321, "PowerShell command `echo hi`"},
		{"bash", models.ActionRunCommand, "dir", 0, 335, "Directory: C:\\Users\\user\\project"},
		{"glob", models.ActionSearchFiles, "*.txt", 0, 289, "[1 file(s) found]"},
		{"grep", models.ActionSearchText, "beta", 0, 99, "notes.txt:1: beta"},
	}
	var tools []models.ToolEvent
	counts := countBy(res.ToolEvents)
	for _, ev := range res.ToolEvents {
		if ev.ActionType == models.ActionUserPrompt || ev.ActionType == models.ActionAssistantMessage {
			continue
		}
		tools = append(tools, ev)
	}
	if counts[models.ActionUserPrompt] != 1 || counts[models.ActionAssistantMessage] != 2 || len(tools) != len(want) {
		t.Fatalf("counts = %v (tool calls %d), want 1 prompt / 2 assistant / %d tool calls", counts, len(tools), len(want))
	}
	if len(res.Warnings) != 0 {
		t.Errorf("warnings = %v", res.Warnings)
	}
	for i, w := range want {
		ev := tools[i]
		if ev.RawToolName != w.raw || ev.ActionType != w.action || ev.Target != w.target {
			t.Errorf("call %d = %s/%s target %q, want %s/%s target %q", i, ev.RawToolName, ev.ActionType, ev.Target, w.raw, w.action, w.target)
		}
		if ev.ContentBytes != w.bytes || ev.DurationMs != w.durationMs {
			t.Errorf("call %d (%s) bytes %d dur %d, want %d / %d", i, w.raw, ev.ContentBytes, ev.DurationMs, w.bytes, w.durationMs)
		}
		if !ev.Success || ev.OutcomePending || ev.ErrorMessage != "" {
			t.Errorf("call %d (%s) outcome = ok %v pending %v err %q", i, w.raw, ev.Success, ev.OutcomePending, ev.ErrorMessage)
		}
		if !strings.Contains(ev.ToolOutput, w.outputContains) {
			t.Errorf("call %d (%s) output %q lacks %q", i, w.raw, ev.ToolOutput, w.outputContains)
		}
		// The raw input keeps the vendor's own Windows path.
		if w.action == models.ActionReadFile && !strings.Contains(ev.RawToolInput, `C:\\Users\\user\\project\\notes.txt`) {
			t.Errorf("read raw input = %q", ev.RawToolInput)
		}
		if ev.Model != "claude-opus-5-5" || ev.Metadata == nil || ev.Metadata.EffortLevel != "low" {
			t.Errorf("call %d model/effort = %q %+v", i, ev.Model, ev.Metadata)
		}
		if !strings.HasSuffix(filepath.ToSlash(ev.ProjectRoot), "Users/user/project") {
			t.Errorf("call %d root = %q", i, ev.ProjectRoot)
		}
		// The PreToolUse hook output Cortex injects beside each result is
		// harness noise, never a prompt or part of the output.
		if strings.Contains(ev.ToolOutput, "system-reminder") {
			t.Errorf("call %d output carries the injected hook block", i)
		}
	}
}

func TestRelativeTarget(t *testing.T) {
	winRoot := crossmount.TranslateForeignPath(`C:\Users\user\project`)
	cases := []struct {
		name, target, key, root string
		want                    string // "" = expect the "[external]/" prefix
	}{
		{"windows drive path under the translated root", `C:\Users\user\project\notes.txt`, "file_path", winRoot, "notes.txt"},
		{"forward-slash drive path", `C:/Users/user/project/src/a.go`, "file_path", winRoot, "src/a.go"},
		{"posix path under root", "/home/user/project/hello_world.py", "file_path", "/home/user/project", "hello_world.py"},
		{"notebook path", "/home/user/project/nb.ipynb", "notebook_path", "/home/user/project", "nb.ipynb"},
		{"directory path key", "/home/user/project/src", "path", "/home/user/project", "src"},
		{"outside the root", "/etc/hosts", "file_path", "/home/user/project", ""},
		{"relative path untouched", "notes.txt", "file_path", "/home/user/project", "notes.txt"},
		{"non-path key untouched", "/home/user/project/x", "command", "/home/user/project", "/home/user/project/x"},
		{"placeholder root untouched", `C:\Users\user\project\notes.txt`, "file_path", placeholderRoot, `C:\Users\user\project\notes.txt`},
		{"empty root untouched", "/home/user/project/x", "file_path", "", "/home/user/project/x"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := relativeTarget(tc.target, tc.key, tc.root)
			if tc.want == "" {
				if !strings.HasPrefix(got, "[external]/") {
					t.Fatalf("relativeTarget(%q) = %q, want an [external]/ path", tc.target, got)
				}
				return
			}
			if got != tc.want {
				t.Fatalf("relativeTarget(%q, %q, %q) = %q, want %q", tc.target, tc.key, tc.root, got, tc.want)
			}
		})
	}
}

func TestIsAbsAnyOS(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"/home/user/x", true},
		{`C:\Users\user\x`, true},
		{"c:/Users/user/x", true},
		{`\\server\share\x`, true},
		{"notes.txt", false},
		{`C:notes.txt`, false},
		{"1:/x", false},
		{"", false},
		{"*.txt", false},
	}
	for _, tc := range cases {
		if got := isAbsAnyOS(tc.in); got != tc.want {
			t.Errorf("isAbsAnyOS(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

// TestLogSeedNeedsHistory: the real Windows log's pid 37496 run names
// session ...0003 and never logged an exit (it died on sign-in). A
// metadata-only session (no history log: no message ever recorded) gets
// no process seed; the same session with a history log does.
func TestLogSeedNeedsHistory(t *testing.T) {
	noForeignHomes(t)
	const hookOnly = "00000000-0000-4000-8000-000000000003"
	dir := stageDataHome(t, "windows", winSID)
	// SYNTHETIC: the metadata a failed-sign-in run leaves behind
	// (history_length 0, no token usage), shaped like the live files.
	metaPath := filepath.Join(dir, hookOnly+metaSuffix)
	writeFile(t, metaPath, `{"session_id":"`+hookOnly+`","working_directory":"C:\\Users\\user\\project","history_length":0,"session_type":"main"}`)
	a := NewWithOptions(nil, dir)

	res := parse(t, a, metaPath, 0)
	if len(res.SessionProcessSeeds) != 0 {
		t.Fatalf("metadata-only seeds = %+v, want none", res.SessionProcessSeeds)
	}
	if len(res.SessionToolVersions) != 1 || len(res.SessionSurfaces) != 1 {
		t.Errorf("version/surface still stamp: %+v %+v", res.SessionToolVersions, res.SessionSurfaces)
	}

	writeFile(t, filepath.Join(dir, hookOnly+historySuffix), "")
	a = NewWithOptions(nil, dir)
	res = parse(t, a, metaPath, 0)
	if len(res.SessionProcessSeeds) != 1 || res.SessionProcessSeeds[0].PID != 37496 {
		t.Fatalf("seeds with a history log = %+v, want pid 37496", res.SessionProcessSeeds)
	}
}
