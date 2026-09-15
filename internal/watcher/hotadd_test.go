package watcher

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/adapter/codex"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// hotAddRollout is one complete Codex rollout: session_meta + a
// shell_command turn + token_count. Written into a staging directory and
// renamed into place so the file is ALREADY there, in full, the instant
// the watch root first exists — exactly the shape of the live finding
// (a store that a tool wrote hours before the daemon noticed the root).
func hotAddRollout(t *testing.T, dir, sessionUUID string) string {
	t.Helper()
	lines := []string{
		`{"timestamp":"2026-09-03T15:00:00.000Z","type":"session_meta","payload":{"id":"` + sessionUUID + `","cwd":"/tmp/hotadd","model":"gpt-5.5"}}`,
		`{"timestamp":"2026-09-03T15:00:01.000Z","type":"event_msg","payload":{"type":"task_started","turn_id":"t1"}}`,
		`{"timestamp":"2026-09-03T15:00:02.000Z","type":"turn_context","payload":{"turn_id":"t1","cwd":"/tmp/hotadd","model":"gpt-5.5"}}`,
		`{"timestamp":"2026-09-03T15:00:03.000Z","type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"run a command"}]}}`,
		`{"timestamp":"2026-09-03T15:00:04.000Z","type":"response_item","payload":{"type":"function_call","name":"shell_command","arguments":"{\"command\":\"echo hot-add\"}","call_id":"call_h"}}`,
		`{"timestamp":"2026-09-03T15:00:05.000Z","type":"event_msg","payload":{"type":"token_count","info":{"last_token_usage":{"input_tokens":100,"cached_input_tokens":0,"output_tokens":10,"reasoning_output_tokens":0,"total_tokens":110},"total_token_usage":{"input_tokens":100,"cached_input_tokens":0,"output_tokens":10,"reasoning_output_tokens":0,"total_tokens":110}}}}`,
		`{"timestamp":"2026-09-03T15:00:06.000Z","type":"response_item","payload":{"type":"function_call_output","call_id":"call_h","output":"hot-add\n"}}`,
		`{"timestamp":"2026-09-03T15:00:07.000Z","type":"event_msg","payload":{"type":"task_complete","turn_id":"t1","last_agent_message":"done","completed_at":1788447607,"duration_ms":3000}}`,
	}
	path := filepath.Join(dir, "rollout-2026-09-03T15-00-00-"+sessionUUID+".jsonl")
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestHotAddedRootWalksPreExistingFiles pins Ticket W1 (2026-09-03): a
// watch root that appears AFTER the daemon started must have its
// existing files walked, not just fsnotify-registered.
//
// Live finding: `watcher: hot-added watch root` for freebuff-desktop and
// open-interpreter's desktop codex-home was logged minutes into the
// daemon's life, and the desktop-v2.db / rollout-*.jsonl files that were
// already sitting under those roots stayed uningested until the operator
// ran `observer scan --force`. fsnotify only ever reports what happens
// AFTER a watch is added, and applyDetectedRoots only ever registered —
// the backlog walk was left to whatever full Scan the call site happened
// to run next, which for the automatic path lived inside the poller's
// every-15th-tick branch.
//
// The test therefore runs with polling DISABLED and never calls Scan /
// Rescan / RefreshRoots: the only thing that can ingest the file is the
// hot-add's own walk.
func TestHotAddedRootWalksPreExistingFiles(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dbPath := filepath.Join(t.TempDir(), "w.db")
	database, err := db.Open(ctx, db.Options{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	s := store.New(database)

	// The adapter's root does not exist yet, so the adapter is not
	// Detected when Watch starts — the "tool installed after the daemon"
	// case the New Terminal install arc depends on.
	home := t.TempDir()
	sessions := filepath.Join(home, "sessions")
	staging := filepath.Join(home, "sessions-staging")
	if err := os.MkdirAll(staging, 0o700); err != nil {
		t.Fatal(err)
	}
	const sessionUUID = "019dfbc2-344c-7a41-9766-9e6d97c28899"
	hotAddRollout(t, staging, sessionUUID)

	reg := adapter.NewRegistry()
	reg.Register(codex.NewWithOptions(nil, sessions))

	w := New(s, reg, Options{
		Logger:   slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
		Debounce: 20 * time.Millisecond,
		// Polling OFF: proves the hot-add walk does not depend on the
		// poller's every-15th-tick full Scan (which a node with
		// `poll_interval_seconds = 0` never gets at all).
		PollInterval:       0,
		RootDetectInterval: 25 * time.Millisecond,
	})

	watchDone := make(chan struct{})
	go func() { defer close(watchDone); _ = w.Watch(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-watchDone:
		case <-time.After(5 * time.Second):
			t.Error("Watch did not stop with ctx")
		}
	})

	// Wait until the event loop is live (fsw set) so the root genuinely
	// appears mid-Watch, after the initial Scan already ran.
	waitFor(t, 5*time.Second, func() bool {
		w.liveMu.Lock()
		defer w.liveMu.Unlock()
		return w.fsw != nil
	}, "Watch never became live")

	// The whole populated tree appears at once (atomic rename), so no
	// fsnotify Create for the file itself can be delivered — nothing but
	// the hot-add walk can find it.
	if err := os.Rename(staging, sessions); err != nil {
		t.Fatal(err)
	}

	waitFor(t, 10*time.Second, func() bool {
		var n int
		if err := database.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM actions WHERE session_id = ? AND action_type = ?`,
			sessionUUID, "run_command").Scan(&n); err != nil {
			return false
		}
		return n > 0
	}, "pre-existing file under a hot-added root was never ingested")

	// Ingestion writes actions before token rows. Observing an action does not
	// mean the asynchronous walk has completed its remaining writes.
	waitFor(t, 10*time.Second, func() bool {
		var tokens int
		err := database.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM token_usage WHERE session_id = ?`, sessionUUID).Scan(&tokens)
		return err == nil && tokens > 0
	}, "token rows missing - the hot-add walk must take the same processFile path as the startup walk")
}

// TestHotAddRootsIsIdempotent pins that a second pass over an unchanged
// root neither re-registers it nor re-walks it: the ledger is byRoot, and
// re-ingest would otherwise be paid on every re-detect tick.
func TestHotAddRootsIsIdempotent(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	dbPath := filepath.Join(t.TempDir(), "w.db")
	database, err := db.Open(ctx, db.Options{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })

	home := t.TempDir()
	sessions := filepath.Join(home, "sessions")
	if err := os.MkdirAll(sessions, 0o700); err != nil {
		t.Fatal(err)
	}
	const sessionUUID = "019dfbc2-344c-7a41-9766-9e6d97c28898"
	hotAddRollout(t, sessions, sessionUUID)

	reg := adapter.NewRegistry()
	reg.Register(codex.NewWithOptions(nil, sessions))
	w := New(store.New(database), reg, Options{
		Logger: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
	})

	// Stand up the live fsnotify state the way Watch does, without
	// running the event loop.
	fsw, err := fsnotify.NewWatcher()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { fsw.Close() })
	w.liveMu.Lock()
	w.fsw = fsw
	w.byRoot = map[string]adapter.Adapter{}
	w.liveMu.Unlock()

	if n := w.hotAddRoots(ctx); n != 1 {
		t.Fatalf("first hotAddRoots added %d roots, want 1", n)
	}
	var first int
	if err := database.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM actions WHERE session_id = ?`, sessionUUID).Scan(&first); err != nil {
		t.Fatal(err)
	}
	if first == 0 {
		t.Fatal("hotAddRoots did not walk the newly added root")
	}
	if n := w.hotAddRoots(ctx); n != 0 {
		t.Fatalf("second hotAddRoots added %d roots, want 0", n)
	}
	var second int
	if err := database.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM actions WHERE session_id = ?`, sessionUUID).Scan(&second); err != nil {
		t.Fatal(err)
	}
	if second != first {
		t.Errorf("action rows moved %d → %d on a re-detect of an unchanged root", first, second)
	}
}

// waitFor polls cond until it is true or the deadline passes.
func waitFor(t *testing.T, limit time.Duration, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal(msg)
}
