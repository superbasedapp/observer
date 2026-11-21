//go:build linux

package sandboxrelayd

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/sandboxrelay"
)

// TestPathRefusalLogNamesTheKey (lane FX6, F-P7-5): a hook refused
// path_outside_run was visible only on the box hook's stderr. Every refusal
// is one daemon log line with the run, the class and, for a path refusal,
// the payload key in its canonical spelling, never the value or the body.
func TestPathRefusalLogNamesTheKey(t *testing.T) {
	tr := newBindTree(t)
	state := filepath.Join(t.TempDir(), "state")
	if err := os.MkdirAll(state, 0o700); err != nil {
		t.Fatal(err)
	}
	rec, err := NewRunRecord(RunRecord{RunID: "run-k", Tool: "claude-code", ProjectRoot: tr.ws, WorkspaceDir: tr.ws, Roots: []string{tr.ws, state}, RemoteBox: true})
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var lines []string
	d := &Daemon{
		SweepInterval: -1, SessionOwner: func(_ context.Context, id string) (string, error) {
			if id == "foreign" {
				return tr.other, nil
			}
			return "", nil
		},
		Log: func(runID, reason string) {
			mu.Lock()
			defer mu.Unlock()
			lines = append(lines, runID+": "+reason)
		},
	}
	h := startBindHarness(t, d, rec)
	deep := `{"a":` + strings.Repeat(`{"a":`, 70) + `1` + strings.Repeat(`}`, 71)
	// The binding row a path refusal is logged under: a file value that is
	// not a clean absolute path is the files row's, not the working
	// directories row's (lane FX6, F-P8-2).
	const dirRow, fileRow = "(the payload's working directories lie in the run)", "(the payload's files lie under the run's roots)"
	for _, tc := range []struct {
		name, payload, key, value, row string
	}{
		{"a cwd outside", `{"cwd":"` + tr.other + `"}`, "cwd", tr.other, dirRow},
		{"a transcript outside", `{"transcript_path":"` + filepath.Join(tr.other, "s.jsonl") + `"}`, "transcript_path", tr.other, fileRow},
		{"another spelling", `{"TRANSCRIPTPATH":"/etc/passwd"}`, "transcriptPath", "/etc/passwd", fileRow},
		{"a home-relative transcript on a remote box", `{"transcript_path":"~/.claude.json"}`, "transcript_path", ".claude.json", fileRow},
		{"a relative transcript", `{"transcript_path":"s.jsonl"}`, "transcript_path", `"s.jsonl"`, fileRow},
		{"a relative cwd", `{"cwd":"sub"}`, "cwd", `"sub"`, dirRow},
		{"past the depth bound", deep, keyPayloadBounds, "", dirRow},
	} {
		mu.Lock()
		lines = nil
		mu.Unlock()
		resp := h.send(t, rec, sandboxrelay.HookRequest{Stdin: []byte(tc.payload)})
		if resp.Refused != sandboxrelay.RefusedPath {
			t.Fatalf("%s: refused %q", tc.name, resp.Refused)
		}
		mu.Lock()
		got := strings.Join(lines, "\n")
		mu.Unlock()
		if !strings.Contains(got, "run-k: refused a ") || !strings.Contains(got, "path_outside_run") || !strings.HasSuffix(got, " key="+tc.key) {
			t.Errorf("%s: log %q, want the run, the class and key=%s", tc.name, got, tc.key)
		}
		if !strings.Contains(got, tc.row) {
			t.Errorf("%s: log %q, want the row %s", tc.name, got, tc.row)
		}
		if tc.value != "" && strings.Contains(got, tc.value) {
			t.Errorf("%s: the log carries the payload's value: %q", tc.name, got)
		}
	}
	// A refusal of another class names no key.
	mu.Lock()
	lines = nil
	mu.Unlock()
	if resp := h.send(t, rec, sandboxrelay.HookRequest{Stdin: []byte(`{"cwd":"` + tr.ws + `","session_id":"foreign"}`)}); resp.Refused != sandboxrelay.RefusedSession {
		t.Fatalf("another project's session refused %q", resp.Refused)
	}
	mu.Lock()
	defer mu.Unlock()
	if got := strings.Join(lines, "\n"); !strings.Contains(got, "session_not_this_run") || strings.Contains(got, "key=") {
		t.Errorf("session refusal log %q", got)
	}
}
