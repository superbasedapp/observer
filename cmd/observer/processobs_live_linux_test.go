//go:build linux

package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/pidbridge"
	"github.com/marmutapp/superbased-observer/internal/processobs"
	"github.com/marmutapp/superbased-observer/internal/processobs/poll"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestProcessObserverLive_AttributesSelfAndChild is the §16.4 live smoke for
// the wired P2 pipeline: real poll backend (real /proc) → Observer →
// attribution (this test process is the bridged "AI-tool root") → store. It
// spawns a child and asserts the bridged root AND its inherited descendant
// land in process_runs.
//
// Gated (spec §16.3): skipped unless OBSERVER_PROCESS_LIVE=1, because it
// reads /proc, spawns a process, and uses real timing. Run it in WSL/Linux:
//
//	GOOS=linux go test -c -o /tmp/o.test ./cmd/observer/
//	OBSERVER_PROCESS_LIVE=1 /tmp/o.test -test.run TestProcessObserverLive
func TestProcessObserverLive_AttributesSelfAndChild(t *testing.T) {
	if os.Getenv("OBSERVER_PROCESS_LIVE") != "1" {
		t.Skip("live process-observability smoke: set OBSERVER_PROCESS_LIVE=1 to run")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "obs.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer func() { _ = database.Close() }()
	st := store.New(database)

	// Seed the project + session + the pidbridge row that names THIS test
	// process as the AI-tool root (what the SessionStart hook would write).
	projID, err := st.UpsertProject(ctx, "/proj", "")
	if err != nil {
		t.Fatalf("UpsertProject: %v", err)
	}
	const sess = "sess-live"
	if _, err := database.ExecContext(ctx,
		`INSERT INTO sessions (id, project_id, tool, started_at) VALUES (?, ?, ?, ?)`,
		sess, projID, "claude-code", time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("seed session: %v", err)
	}
	bridge := pidbridge.New(database)
	self := os.Getpid()
	if err := bridge.Write(ctx, pidbridge.Entry{PID: self, SessionID: sess, Tool: "claude-code", CWD: "/proj"}); err != nil {
		t.Fatalf("bridge.Write: %v", err)
	}

	seed := func(pid int) (processobs.Seed, bool) {
		e, ok, lerr := bridge.Lookup(ctx, pid)
		if lerr != nil || !ok {
			return processobs.Seed{}, false
		}
		return processobs.Seed{SessionID: e.SessionID, Tool: e.Tool, Source: processobs.AttrBridge, Confidence: processobs.ConfHigh}, true
	}
	obs := processobs.NewObserver(processobs.Options{
		Backend:       poll.New(poll.Options{Interval: 100 * time.Millisecond}),
		Attributor:    processobs.NewAttributor(seed, buildProcessScrubber(config.Default().Observer.Process), nil),
		Sink:          st,
		BatchSize:     50,
		FlushInterval: 150 * time.Millisecond,
	})

	done := make(chan struct{})
	go func() { _ = obs.Run(ctx); close(done) }()

	// Let the first poll capture the existing table (incl. self), then spawn a
	// child that outlives a couple of poll intervals so it's seen alive.
	time.Sleep(250 * time.Millisecond)
	// Ingest the run_command action that "issues" the child, so the §9.2.4
	// correlation can later link the spawned process back to it.
	if _, err := st.Ingest(ctx, []models.ToolEvent{{
		SourceFile: "cc.jsonl", SourceEventID: "run-sleep", SessionID: sess,
		ProjectRoot: "/proj", Timestamp: time.Now().UTC(), Tool: models.ToolClaudeCode,
		ActionType: models.ActionRunCommand, Target: "sleep 2", TurnIndex: 7, Success: true,
	}}, nil, store.IngestOptions{}); err != nil {
		t.Fatalf("Ingest run_command: %v", err)
	}
	child := exec.Command("sleep", "2")
	if err := child.Start(); err != nil {
		t.Fatalf("spawn child: %v", err)
	}
	defer func() { _ = child.Process.Kill() }()
	time.Sleep(600 * time.Millisecond) // ≥4 polls + a flush

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("observer did not stop")
	}

	// Fresh context — the run ctx is now cancelled.
	runs, err := st.ProcessRunsForSession(context.Background(), sess)
	if err != nil {
		t.Fatalf("ProcessRunsForSession: %v", err)
	}
	var sawSelf, sawChild bool
	for _, r := range runs {
		if r.PID == self {
			sawSelf = true
			if r.AttributionSource != string(processobs.AttrBridge) {
				t.Errorf("self attribution source = %q, want bridge", r.AttributionSource)
			}
		}
		if r.PID == child.Process.Pid {
			sawChild = true
			if r.AttributionSource != string(processobs.AttrInherited) {
				t.Errorf("child attribution source = %q, want inherited", r.AttributionSource)
			}
		}
	}
	if !sawSelf {
		t.Errorf("bridged root (self pid %d) not persisted; got %d runs", self, len(runs))
	}
	if !sawChild {
		t.Errorf("child (pid %d) not attributed/persisted; got %d runs", child.Process.Pid, len(runs))
	}

	// §9.2.4 end-to-end: correlate the captured tree to the run_command
	// action and confirm the child (the `sleep` process) links back to it.
	if _, err := st.CorrelateProcessActions(context.Background(), sess); err != nil {
		t.Fatalf("CorrelateProcessActions: %v", err)
	}
	linked, err := st.ProcessRunsForSession(context.Background(), sess)
	if err != nil {
		t.Fatalf("re-read: %v", err)
	}
	var childLinked bool
	for _, r := range linked {
		if r.PID == child.Process.Pid && r.ActionID != nil {
			childLinked = true
			if r.TurnIndex == nil || *r.TurnIndex != 7 {
				t.Errorf("child turn_index = %v, want 7", r.TurnIndex)
			}
		}
	}
	if !childLinked {
		t.Error("child process was not correlated to the run_command action")
	}
	t.Logf("live smoke: %d attributed runs; child linked to action=%v", len(runs), childLinked)
}
