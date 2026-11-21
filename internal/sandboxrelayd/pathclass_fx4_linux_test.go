//go:build linux

package sandboxrelayd

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/sandboxrelay"
)

// TestBindAgentStateClass (FX4 item 3, live L3-07): a committed project
// hook in an org box sends a payload whose transcript_path is under the
// box's agent home (/home/sandbox/.claude/...). With only the workspace
// class in the run's map (before FX4) it is refused path_outside_run, and
// Claude Code turns that into a failed tool call. With the agent-state
// class (the box's tool state dir mapped onto the run's quarantine copy) it
// binds; a working directory there, any other part of the agent home, and
// a path under no class are still refused.
func TestBindAgentStateClass(t *testing.T) {
	tr := newBindTree(t)
	const (
		box   = "/sandbox/workspace"
		state = "/home/sandbox/.claude"
	)
	quar := filepath.Join(filepath.Dir(tr.ws), "quarantine", "run-q", "0")
	if err := os.MkdirAll(filepath.Join(quar, "projects", "-sandbox-workspace"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(quar, "projects", "-sandbox-workspace", "s.jsonl"), []byte("pulled\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	hook := `{"session_id":"s","hook_event_name":"PreToolUse","cwd":"` + box + `","transcript_path":"` + state + `/projects/-sandbox-workspace/s.jsonl","tool_name":"Bash","tool_input":{"command":"ls"}}`

	before, err := NewRunRecord(RunRecord{RunID: "run-p", Tool: "claude-code", ProjectRoot: tr.ws, WorkspaceDir: tr.ws, Roots: []string{tr.ws}, PathMap: []PathPrefix{{Box: box, Host: tr.ws}}})
	if err != nil {
		t.Fatal(err)
	}
	hb := startBindHarness(t, &Daemon{}, before)
	if resp := hb.send(t, before, sandboxrelay.HookRequest{Stdin: []byte(hook)}); resp.Refused != sandboxrelay.RefusedPath {
		t.Fatalf("the pre-FX4 map did not reproduce L3-07: %+v", resp)
	}

	run, err := NewRunRecord(RunRecord{
		RunID: "run-q", Tool: "claude-code", ProjectRoot: tr.ws, WorkspaceDir: tr.ws, Roots: []string{tr.ws, quar},
		PathMap: []PathPrefix{{Box: box, Host: tr.ws}, {Box: state, Host: quar}},
	})
	if err != nil {
		t.Fatal(err)
	}
	h := startBindHarness(t, &Daemon{}, run)
	cases := []struct {
		name, payload string
		refused       bool
	}{
		{"the project hook's payload", hook, false},
		{"a working directory in the agent state", `{"cwd":"` + state + `/projects"}`, true},
		{"another dot directory of the agent home", `{"transcript_path":"/home/sandbox/.ssh/id_ed25519"}`, true},
		{"the agent home's own state file beside the class", `{"transcript_path":"/home/sandbox/.claude.json"}`, true},
		{"the agent home itself", `{"transcript_path":"/home/sandbox"}`, true},
		{"dot-dot out of the class", `{"transcript_path":"` + state + `/../.ssh/id_ed25519"}`, true},
		{"the box run dir", `{"transcript_path":"/sandbox/run/sessions.json"}`, true},
	}
	for _, tc := range cases {
		resp := h.send(t, run, sandboxrelay.HookRequest{Stdin: []byte(tc.payload)})
		if got := resp.Refused == sandboxrelay.RefusedPath; got != tc.refused {
			t.Errorf("%s: refused=%q, want refused %v", tc.name, resp.Refused, tc.refused)
		}
	}
	mapped, ok := MapBoxPath(run.PathMap, state+"/projects/-sandbox-workspace/s.jsonl")
	if b, err := ConfinedFiles(run.Roots).ReadFile(mapped); !ok || err != nil || string(b) != "pulled\n" {
		t.Errorf("the transcript is not read from the run's quarantine copy: %q %v %v", b, ok, err)
	}
}

// TestBindRefusesThisMachinesHomeOnARemoteRecord (FX4-A1): on a hosted
// (remote-box) record a "~/" or "$HOME" file value is refused
// path_outside_run, never expanded to this machine's home, even if the
// record still listed this machine's tool state as a root (a record written
// before FX4); on a local record "~/" still expands to this machine's home,
// as before.
func TestBindRefusesThisMachinesHomeOnARemoteRecord(t *testing.T) {
	tr := newBindTree(t)
	home := filepath.Join(filepath.Dir(tr.ws), "home")
	if err := os.MkdirAll(filepath.Join(home, ".claude", "projects", "a"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	old := []string{tr.ws, filepath.Join(home, ".claude"), filepath.Join(home, ".claude.json")}
	remote, err := NewRunRecord(RunRecord{
		RunID: "run-r", Tool: "claude-code", ProjectRoot: tr.ws, WorkspaceDir: tr.ws, Roots: old,
		PathMap: []PathPrefix{{Box: "/sandbox/workspace", Host: tr.ws}}, RemoteBox: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	h := startBindHarness(t, &Daemon{}, remote)
	for _, p := range []string{
		`{"transcript_path":"~/.claude/projects/a/b.jsonl"}`,
		`{"transcript_path":"$HOME/.claude.json"}`,
		`{"transcript_path":"~/.claude.json"}`,
		`{"agent_transcript_path":"~"}`,
	} {
		if resp := h.send(t, remote, sandboxrelay.HookRequest{Stdin: []byte(p)}); resp.Refused != sandboxrelay.RefusedPath {
			t.Errorf("remote record %s: %+v, want path_outside_run", p, resp)
		}
	}
	local, err := NewRunRecord(RunRecord{RunID: "run-l", Tool: "claude-code", ProjectRoot: tr.ws, WorkspaceDir: tr.ws, Roots: old})
	if err != nil {
		t.Fatal(err)
	}
	hl := startBindHarness(t, &Daemon{}, local)
	if resp := hl.send(t, local, sandboxrelay.HookRequest{Stdin: []byte(`{"transcript_path":"~/.claude/projects/a/b.jsonl"}`)}); resp.Refused != "" {
		t.Errorf("a local record no longer expands ~/: %+v", resp)
	}
}

// TestBindOldHostedRecordUsesOnlyItsOwnRoots (FX4 fix round 2, FX4-R1): a
// hosted record written before FX4 and still live across the upgrade (never
// re-keyed) has no RemoteBox, a PathMap, and this machine's ~/.claude and
// ~/.claude.json among its stored Roots. An ABSOLUTE path under this
// machine's home was still accepted and read from those roots. Now a record
// whose home is not this machine's reads only its workspace and its PathMap
// hosts, at bind time and in the confined reader, whatever Roots says; a
// local record keeps its stored roots.
func TestBindOldHostedRecordUsesOnlyItsOwnRoots(t *testing.T) {
	tr := newBindTree(t)
	home := filepath.Join(filepath.Dir(tr.ws), "home")
	if err := os.MkdirAll(filepath.Join(home, ".claude", "projects", "a"), 0o700); err != nil {
		t.Fatal(err)
	}
	transcript := filepath.Join(home, ".claude", "projects", "a", "b.jsonl")
	login := filepath.Join(home, ".claude.json")
	for _, f := range []string{transcript, login} {
		if err := os.WriteFile(f, []byte("{}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	quar := filepath.Join(filepath.Dir(tr.ws), "quar", "0")
	if err := os.MkdirAll(quar, 0o700); err != nil {
		t.Fatal(err)
	}
	stored := []string{tr.ws, filepath.Join(home, ".claude"), login, login + ".backup", quar}
	old, err := NewRunRecord(RunRecord{
		RunID: "run-old", Tool: "claude-code", ProjectRoot: tr.ws, WorkspaceDir: tr.ws, Roots: stored,
		PathMap: []PathPrefix{{Box: "/sandbox/workspace", Host: tr.ws}, {Box: "/home/sandbox/.claude", Host: quar}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := old.ReadRoots(); !slices.Equal(got, []string{tr.ws, quar}) {
		t.Fatalf("read roots %v, want the workspace and the mapped hosts", got)
	}
	h := startBindHarness(t, &Daemon{}, old)
	for _, p := range []string{transcript, login} {
		if resp := h.send(t, old, sandboxrelay.HookRequest{Stdin: []byte(`{"transcript_path":"` + p + `"}`)}); resp.Refused != sandboxrelay.RefusedPath {
			t.Errorf("old hosted record, absolute %s: %+v, want path_outside_run", p, resp)
		}
	}
	for _, p := range []string{transcript, login} {
		if _, err := ConfinedFiles(old.ReadRoots()).ReadFile(p); err == nil {
			t.Errorf("the old hosted record's confined reader opened %s", p)
		}
	}
	// The mapped agent-state class still works.
	if resp := h.send(t, old, sandboxrelay.HookRequest{Stdin: []byte(`{"transcript_path":"/home/sandbox/.claude/projects/a/b.jsonl"}`)}); resp.Refused == sandboxrelay.RefusedPath {
		t.Errorf("a mapped agent-state file was refused: %+v", resp)
	}
	// A local record keeps its stored roots.
	local, err := NewRunRecord(RunRecord{RunID: "run-loc", Tool: "claude-code", ProjectRoot: tr.ws, WorkspaceDir: tr.ws, Roots: stored})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(local.ReadRoots(), stored) {
		t.Fatalf("a local record's read roots changed: %v", local.ReadRoots())
	}
	hl := startBindHarness(t, &Daemon{}, local)
	if resp := hl.send(t, local, sandboxrelay.HookRequest{Stdin: []byte(`{"transcript_path":"` + transcript + `"}`)}); resp.Refused != "" {
		t.Errorf("a local record refused its own tool state: %+v", resp)
	}
}
