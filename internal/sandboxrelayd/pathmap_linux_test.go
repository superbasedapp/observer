//go:build linux

package sandboxrelayd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/sandboxrelay"
)

// TestMapBoxPath (lane G4 fix round 2, G4-R2): a box path maps by whole
// components after cleaning, and anything else comes back unchanged.
func TestMapBoxPath(t *testing.T) {
	m := []PathPrefix{{Box: "/sandbox/workspace", Host: "/home/dev/app"}}
	cases := []struct {
		in, want string
		ok       bool
	}{
		{"/sandbox/workspace", "/home/dev/app", true},
		{"/sandbox/workspace/", "/home/dev/app", true},
		{"/sandbox/workspace/src/a.go", "/home/dev/app/src/a.go", true},
		{"//sandbox/workspace//src", "/home/dev/app/src", true},
		{"/sandbox/workspace/src/../b", "/home/dev/app/b", true},
		{"/sandbox/workspace/../run/secret", "/sandbox/workspace/../run/secret", false},
		{"/sandbox/workspacefoo", "/sandbox/workspacefoo", false},
		{"/sandbox/run/baseline", "/sandbox/run/baseline", false},
		{"sandbox/workspace/a", "sandbox/workspace/a", false},
		{"/etc/passwd", "/etc/passwd", false},
	}
	for _, tc := range cases {
		got, ok := MapBoxPath(m, tc.in)
		if got != tc.want || ok != tc.ok {
			t.Errorf("%q: %q %v, want %q %v", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}

// TestRunRecordPathMapValidated: a map row with a relative, unclean or
// root box prefix, or a relative host directory, is a bad record.
func TestRunRecordPathMapValidated(t *testing.T) {
	for _, bad := range []PathPrefix{
		{Box: "/", Host: "/h"},
		{Box: "sandbox/workspace", Host: "/h"},
		{Box: "/sandbox/workspace/", Host: "/h"},
		{Box: "/sandbox/workspace", Host: "h"},
		{Box: "/sandbox/workspace", Host: ""},
	} {
		if _, err := NewRunRecord(RunRecord{RunID: "run-a", Tool: "claude-code", PathMap: []PathPrefix{bad}}); err == nil {
			t.Errorf("%+v accepted", bad)
		}
	}
}

// TestBindMapsBoxPathsOntoTheRun (G4-R2): a hosted box names its fixed
// workspace; the relay rewrites it to the run's directory before the
// binding and the confined reader see it, so a box-path transcript read is
// served from the laptop's file. A box path outside the map is refused, a
// tool call's operands are left as written, and the laptop's own
// /sandbox/workspace is never a root.
func TestBindMapsBoxPathsOntoTheRun(t *testing.T) {
	tr := newBindTree(t)
	const box = "/sandbox/workspace"
	if err := os.WriteFile(filepath.Join(tr.ws, "t.jsonl"), []byte("transcript\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	run, err := NewRunRecord(RunRecord{RunID: "run-m", Tool: "claude-code", ProjectRoot: tr.ws, WorkspaceDir: tr.ws, Roots: []string{tr.ws}, PathMap: []PathPrefix{{Box: box, Host: tr.ws}}})
	if err != nil {
		t.Fatal(err)
	}
	h := startBindHarness(t, &Daemon{}, run)
	cases := []struct {
		name, payload string
		refused       bool
		saw           []string
	}{
		{
			"box cwd and transcript", `{"cwd":"` + box + `/sub","transcript_path":"` + box + `/t.jsonl"}`, false,
			[]string{`"cwd":"` + tr.ws + `/sub"`, `"transcript_path":"` + tr.ws + `/t.jsonl"`},
		},
		{"a workspace_roots array", `{"workspace_roots":["` + box + `"]}`, false, []string{`["` + tr.ws + `"]`}},
		{
			"operands left as written", `{"cwd":"` + box + `","tool_input":{"file_path":"` + box + `/a.go"}}`, false,
			[]string{`"file_path":"` + box + `/a.go"`, `"cwd":"` + tr.ws + `"`},
		},
		{"the box run dir", `{"transcript_path":"/sandbox/run/sessions.json"}`, true, nil},
		{"dot-dot out of the map", `{"cwd":"` + box + `/../run"}`, true, nil},
		{"a prefix that is no component", `{"cwd":"` + box + `foo"}`, true, nil},
		{"a host path outside the run", `{"transcript_path":"/etc/passwd"}`, true, nil},
	}
	for _, tc := range cases {
		before := h.executed()
		resp := h.send(t, run, sandboxrelay.HookRequest{Stdin: []byte(tc.payload)})
		if got := resp.Refused == sandboxrelay.RefusedPath; got != tc.refused {
			t.Errorf("%s: refused=%q, want refused %v", tc.name, resp.Refused, tc.refused)
			continue
		}
		if tc.refused {
			if h.executed() != before {
				t.Errorf("%s: the executor ran", tc.name)
			}
			continue
		}
		h.mu.Lock()
		seen := h.ran[len(h.ran)-1]
		h.mu.Unlock()
		for _, w := range tc.saw {
			if !strings.Contains(seen, w) {
				t.Errorf("%s: the hook saw %s, want %s", tc.name, seen, w)
			}
		}
	}
	// The mapped transcript is read from the laptop's file through the
	// run's own roots; the laptop's /sandbox/workspace is no root.
	files := ConfinedFiles(run.Roots)
	mapped, _ := MapBoxPath(run.PathMap, box+"/t.jsonl")
	if b, err := files.ReadFile(mapped); err != nil || string(b) != "transcript\n" {
		t.Errorf("mapped read %q %v", b, err)
	}
	if _, err := files.ReadFile(box + "/t.jsonl"); err == nil {
		t.Error("the laptop's own /sandbox/workspace was read")
	}
	if RootsContain(run.Roots, box) || ConfinedContains(run.Roots)(box+"/t.jsonl") {
		t.Error("the laptop's own /sandbox/workspace is a root")
	}
}

// TestRelayCwdIsMapped is G4-R7: the request header's cwd, a box path, is
// mapped onto the run's directory before the executor sees it (a hook run
// from a subdirectory keeps it); a cwd under no prefix is left as written.
func TestRelayCwdIsMapped(t *testing.T) {
	tr := newBindTree(t)
	const box = "/sandbox/workspace"
	run, err := NewRunRecord(RunRecord{RunID: "run-c", Tool: "claude-code", ProjectRoot: tr.ws, WorkspaceDir: tr.ws, Roots: []string{tr.ws}, PathMap: []PathPrefix{{Box: box, Host: tr.ws}}})
	if err != nil {
		t.Fatal(err)
	}
	h := startBindHarness(t, &Daemon{}, run)
	for _, tc := range []struct{ cwd, want string }{
		{box + "/sub", filepath.Join(tr.ws, "sub")},
		{box, tr.ws},
		{"/elsewhere", "/elsewhere"},
		{"", ""},
	} {
		resp := h.send(t, run, sandboxrelay.HookRequest{Cwd: tc.cwd, Stdin: []byte(`{"cwd":"` + box + `"}`)})
		if resp.Refused != "" {
			t.Fatalf("cwd %q: refused %q", tc.cwd, resp.Refused)
		}
		h.mu.Lock()
		got := h.cwds[len(h.cwds)-1]
		h.mu.Unlock()
		if got != tc.want {
			t.Errorf("cwd %q reached the executor as %q, want %q", tc.cwd, got, tc.want)
		}
	}
}

// TestMapPayloadPathsLeavesOthersAlone: no map, a payload with no mapped
// path, or one that is not a JSON object comes back byte for byte.
func TestMapPayloadPathsLeavesOthersAlone(t *testing.T) {
	m := []PathPrefix{{Box: "/sandbox/workspace", Host: "/home/dev/app"}}
	for _, in := range []string{`{"cwd":"/home/dev/app", "x": 1.50}`, `plain`, `["/sandbox/workspace"]`, `{"tool_input":{"cwd":"/sandbox/workspace"}}`} {
		if got := mapPayloadPaths([]byte(in), m); string(got) != in {
			t.Errorf("%s became %s", in, got)
		}
	}
	if got := mapPayloadPaths([]byte(`{"cwd":"/sandbox/workspace"}`), nil); string(got) != `{"cwd":"/sandbox/workspace"}` {
		t.Errorf("no map changed %s", got)
	}
}
