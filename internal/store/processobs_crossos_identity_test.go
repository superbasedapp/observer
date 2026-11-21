package store

import (
	"context"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/procmodel"
)

// crossOSRun is a minimal persisted Windows run for the cross-OS identity
// tests.
func crossOSRun(key, parent, exe, cwd string, pid int, started time.Time, attr procmodel.Attribution) procmodel.ProcessRun {
	if attr.Source == "" {
		attr.Source, attr.Confidence = procmodel.AttrNone, procmodel.ConfNone
	}
	return procmodel.ProcessRun{
		ProcessKey: key, ParentProcessKey: parent, BootID: "boot", PID: pid,
		StartTimeTicks: int64(pid), ExePath: `C:\bin\` + exe, ExeBasename: exe, CWD: cwd,
		StartedAt: started, LastSeenAt: started, Attribution: attr,
	}
}

// TestCorrelateCrossOSRehomesHostToChildIdentity reproduces the live shape: a
// Windows claude.exe whose bash.exe children carry the env token for "main"
// had been correlated to a resume stub session that started next to its
// launch. Either session's pass now moves the host (and its non-authoritative
// children) to "main", and a re-run is a no-op.
func TestCorrelateCrossOSRehomesHostToChildIdentity(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, _ := newTestStore(t)

	const root = `D:\proj`
	projectID, err := s.UpsertProject(ctx, root, "")
	if err != nil {
		t.Fatalf("UpsertProject: %v", err)
	}
	t0 := time.Now().UTC().Add(-30 * time.Hour).Truncate(time.Second)
	launch := t0.Add(26 * time.Hour)
	for id, started := range map[string]time.Time{"main": t0, "stub": launch.Add(2 * time.Second)} {
		if _, err := s.db.ExecContext(ctx,
			`INSERT INTO sessions (id, project_id, tool, started_at) VALUES (?, ?, 'claude-code', ?)`,
			id, projectID, timestamp(started)); err != nil {
			t.Fatalf("seed session %s: %v", id, err)
		}
	}
	stubAttr := procmodel.Attribution{
		SessionID: "stub", Tool: "claude-code", ProjectID: projectID,
		Source: procmodel.AttrCrossOSCorrelation, Confidence: procmodel.ConfMedium,
	}
	envAttr := procmodel.Attribution{
		SessionID: "main", Tool: "claude-code", ProjectID: projectID,
		Source: procmodel.AttrEnvToken, Confidence: procmodel.ConfHigh,
	}
	runs := []procmodel.ProcessRun{
		crossOSRun("host", "", "claude.exe", root, 100, launch, stubAttr),
		crossOSRun("con", "host", "conhost.exe", root, 101, launch.Add(time.Second), stubAttr),
		crossOSRun("sh1", "host", "bash.exe", root, 102, launch.Add(time.Minute), envAttr),
		crossOSRun("sh2", "host", "bash.exe", root, 103, launch.Add(2*time.Minute), envAttr),
	}
	if _, err := s.PersistRuns(ctx, runs); err != nil {
		t.Fatalf("PersistRuns: %v", err)
	}

	want := attrState{
		sessionID: "main", projectID: projectID, tool: "claude-code",
		source: procmodel.AttrCrossOSCorrelation, confidence: procmodel.ConfMedium,
	}
	n, err := s.CorrelateCrossOS(ctx, "stub")
	if err != nil {
		t.Fatalf("CorrelateCrossOS(stub): %v", err)
	}
	if n != 2 {
		t.Fatalf("re-homed %d rows, want 2 (host, con)", n)
	}
	for _, k := range []string{"host", "con"} {
		if got := readAttr(t, s, k); got != want {
			t.Errorf("%s = %+v, want %+v", k, got, want)
		}
	}
	if got := readAttr(t, s, "sh1"); got.source != procmodel.AttrEnvToken || got.sessionID != "main" {
		t.Errorf("the env-token child must be untouched: %+v", got)
	}
	for _, id := range []string{"stub", "main"} {
		if n, err := s.CorrelateCrossOS(ctx, id); err != nil || n != 0 {
			t.Errorf("re-run for %s = %d, %v; want 0, nil", id, n, err)
		}
	}
}

// TestCorrelateCrossOSSeesEveryChildSessionOfAHost pins the loader arm that
// pulls a host's env-token children from OTHER sessions: s1's pass reaches the
// host only through the up-walk from its own child, and must still see the s2
// child to know the host is multi-session.
func TestCorrelateCrossOSSeesEveryChildSessionOfAHost(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, _ := newTestStore(t)

	const root = `D:\proj`
	projectID, err := s.UpsertProject(ctx, root, "")
	if err != nil {
		t.Fatalf("UpsertProject: %v", err)
	}
	t0 := time.Now().UTC().Add(-10 * time.Hour).Truncate(time.Second)
	for id, started := range map[string]time.Time{"s1": t0, "s2": t0.Add(3 * time.Hour)} {
		if _, err := s.db.ExecContext(ctx,
			`INSERT INTO sessions (id, project_id, tool, started_at) VALUES (?, ?, 'claude-code', ?)`,
			id, projectID, timestamp(started)); err != nil {
			t.Fatalf("seed session %s: %v", id, err)
		}
	}
	env := func(sid string) procmodel.Attribution {
		return procmodel.Attribution{
			SessionID: sid, Tool: "claude-code", ProjectID: projectID,
			Source: procmodel.AttrEnvToken, Confidence: procmodel.ConfHigh,
		}
	}
	runs := []procmodel.ProcessRun{
		crossOSRun("host", "", "claude.exe", root, 200, t0.Add(-time.Hour), procmodel.Attribution{}),
		crossOSRun("sh1", "host", "bash.exe", root, 201, t0.Add(time.Minute), env("s1")),
		crossOSRun("sh2", "host", "bash.exe", root, 202, t0.Add(3*time.Hour), env("s2")),
	}
	if _, err := s.PersistRuns(ctx, runs); err != nil {
		t.Fatalf("PersistRuns: %v", err)
	}
	for _, id := range []string{"s1", "s2"} {
		if n, err := s.CorrelateCrossOS(ctx, id); err != nil || n != 0 {
			t.Errorf("CorrelateCrossOS(%s) = %d, %v; a multi-session host must stay unattributed", id, n, err)
		}
	}
	if got := readAttr(t, s, "host"); got.sessionID != "" {
		t.Errorf("host attributed to %q, want unattributed", got.sessionID)
	}
}
