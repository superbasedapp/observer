//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
)

// fx6Dirs makes a workspace and a directory standing for this machine's
// tool state (~/.claude), both resolved.
func fx6Dirs(t *testing.T) (ws, state string) {
	t.Helper()
	ws, state = filepath.Join(t.TempDir(), "ws"), filepath.Join(t.TempDir(), "claude-state")
	for _, d := range []string{ws, state} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	ws, _ = filepath.EvalSymlinks(ws)
	state, _ = filepath.EvalSymlinks(state)
	return ws, state
}

// TestRelayChildDirReadsTheRecordsReadRoots (fold delta audit N1): a hosted
// record from before FX4 that stays live without a re-key still lists this
// machine's tool state in its stored roots. A relay child's working
// directory is held to the record's read roots (RunRecord.ReadRoots), so a
// box cwd naming that state falls back to the run's workspace; a local
// record keeps its stored roots.
func TestRelayChildDirReadsTheRecordsReadRoots(t *testing.T) {
	ws, state := fx6Dirs(t)
	old := sandboxrelayd.RunRecord{WorkspaceDir: ws, Roots: []string{ws, state}, RemoteBox: true}
	if got := relayChildDir(old, state); got != ws {
		t.Errorf("an old-shape hosted record put the child in %q, want the workspace %q", got, ws)
	}
	local := sandboxrelayd.RunRecord{WorkspaceDir: ws, Roots: []string{ws, state}}
	if got := relayChildDir(local, state); got != state {
		t.Errorf("a local record's own root was refused: %q", got)
	}
}

// TestRelayHooksDisabledReadsTheRecordsReadRoots (fold delta audit N1): the
// hooks-off scan reads project files under the record's read roots, not the
// stored list, so an old-shape hosted record's stale root is not scanned.
func TestRelayHooksDisabledReadsTheRecordsReadRoots(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	ws, state := fx6Dirs(t)
	sw := filepath.Join(state, ".claude", "settings.local.json")
	if err := os.MkdirAll(filepath.Dir(sw), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sw, []byte(`{"disableAllHooks": true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	named := func(got []string) bool {
		return slices.ContainsFunc(got, func(s string) bool { return strings.Contains(s, state) })
	}
	old := sandboxrelayd.RunRecord{Tool: "claude-code", WorkspaceDir: ws, Roots: []string{ws, state}, RemoteBox: true}
	if got := relayHooksDisabled(old); named(got) {
		t.Errorf("an old-shape hosted record's stale root was scanned: %v", got)
	}
	local := sandboxrelayd.RunRecord{Tool: "claude-code", WorkspaceDir: ws, Roots: []string{ws, state}}
	if got := relayHooksDisabled(local); !named(got) {
		t.Errorf("a local record's root was not scanned (the control): %v", got)
	}
}

// TestRemoteBoxRootsOneOwner (fold delta audit N3): the read-roots rule of
// a box whose home is not this machine's has one owner, which ReadRoots
// returns for such a record.
func TestRemoteBoxRootsOneOwner(t *testing.T) {
	pm := []sandboxrelayd.PathPrefix{{Box: "/sandbox/work", Host: "/runs/r1/ws"}, {Box: "/home/sandbox/.claude", Host: "/runs/r1/q"}, {Box: "/x", Host: ""}, {Box: "/y", Host: "/runs/r1/ws"}}
	want := []string{"/runs/r1/ws", "/runs/r1/q"}
	if got := sandboxrelayd.RemoteBoxRoots("/runs/r1/ws", pm); !slices.Equal(got, want) {
		t.Errorf("RemoteBoxRoots %v, want %v", got, want)
	}
	rec := sandboxrelayd.RunRecord{WorkspaceDir: "/runs/r1/ws", PathMap: pm, Roots: []string{"/home/dev/.claude"}, RemoteBox: true}
	if got := rec.ReadRoots(); !slices.Equal(got, want) {
		t.Errorf("ReadRoots %v, want %v", got, want)
	}
}

// TestNoteHostedRelayLog (lane FX6, F-P7-5): the daemon's relay line about
// a hosted run (a refusal, with its class, key and run) is appended to the
// run's kept relay log, where the box's answer points; a run with no kept
// log gets nothing, and nothing is created.
func TestNoteHostedRelayLog(t *testing.T) {
	obs := t.TempDir()
	const run, local = "runHOSTEDfx6", "runLOCALfx6"
	p := hostedRelayLogPath(obs, run)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("2026-11-05T09:00:00Z the relay process started\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	noteHostedRelayLog(obs, run, "refused a hook request: path_outside_run (the payload's files lie under the run's roots) key=transcript_path")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "the relay process started") || !strings.Contains(string(b), "path_outside_run") || !strings.Contains(string(b), "key=transcript_path") {
		t.Errorf("relay log:\n%s", b)
	}
	noteHostedRelayLog(obs, local, "refused a hook request: path_outside_run")
	if _, err := os.Stat(filepath.Dir(hostedRelayLogPath(obs, local))); err == nil {
		t.Error("a run with no kept relay log got one")
	}
	noteHostedRelayLog(obs, "../escape", "x")
}

// TestRelayLogCapAcrossBothWriters (lane FX6, FX6-A6): the run's helper and
// the daemon append to one relay log. Each re-reads the size before every
// append, so the log never passes its cap however the two interleave, and
// the cap line is written once.
func TestRelayLogCapAcrossBothWriters(t *testing.T) {
	obs := t.TempDir()
	const run = "runCAPPEDfx6"
	helper := openHostedRelayLog(obs, run, nil, nil)
	if helper == nil {
		t.Fatal("no log")
	}
	long := strings.Repeat("x", hostedRelayLineMax)
	for i := range 2 * hostedRelayLogMax / hostedRelayLineMax {
		if i%2 == 0 {
			noteHostedRelayLog(obs, run, long)
		} else {
			helper.line("%s", long)
		}
	}
	helper.line("one more from the helper")
	noteHostedRelayLog(obs, run, "one more from the daemon")
	b, err := os.ReadFile(hostedRelayLogPath(obs, run))
	if err != nil {
		t.Fatal(err)
	}
	if len(b) > hostedRelayLogMax {
		t.Errorf("the log is %d bytes, past its cap of %d", len(b), hostedRelayLogMax)
	}
	if n := strings.Count(string(b), hostedRelayCapLine); n != 1 {
		t.Errorf("the cap line is there %d times, want once", n)
	}
	if !strings.HasSuffix(string(b), hostedRelayCapLine+"\n") {
		t.Error("the log does not end with the cap line")
	}
}
