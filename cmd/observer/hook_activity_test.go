package main

import (
	"context"
	"encoding/json"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/hookspool"
	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/testsupport/latencygate"
)

// recordingActivityDeps captures the records an emission appends.
func recordingActivityDeps(env map[string]string, got *[]hookspool.Record) hookActivityDeps {
	return hookActivityDeps{
		now:       func() time.Time { return time.Date(2026, 10, 25, 9, 0, 0, 0, time.UTC) },
		getenv:    func(k string) string { return env[k] },
		spoolPath: func(string) string { return "/spool" },
		appendRow: func(_ string, r hookspool.Record) error { *got = append(*got, r); return nil },
	}
}

// TestEmitHookActivity: one record per invocation; the first session id a
// receiver reports attributes it, none leaves it in the unattributed bucket,
// a foreign replay is not recorded, and the event is the binding's native
// name.
func TestEmitHookActivity(t *testing.T) {
	cases := []struct {
		name    string
		tool    string
		event   string
		note    func()
		want    int
		session string
		native  string
	}{
		{"payload id", "claude-code", "pre-tool", func() { noteHookPayload([]byte(`{"session_id":"s1","tool_input":{}}`)) }, 1, "s1", "PreToolUse"},
		{"first id wins", "claude-code", "pre-tool", func() { noteHookSession("a"); noteHookSession("b") }, 1, "a", "PreToolUse"},
		{"unattributed", "claude-code", "stop", func() { noteHookPayload([]byte(`{"x":1}`)) }, 1, "", "Stop"},
		{"unknown tool keeps argv event", "nosuch-tool", "whatever", func() {}, 1, "", "whatever"},
		{"foreign replay", "claude-code", "pre-tool", func() { noteHookPayload([]byte(`{"session_id":"s1"}`)); noteHookForeign() }, 0, "", ""},
		{"no event", "claude-code", "", func() {}, 0, "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resetHookActivity()
			t.Cleanup(resetHookActivity)
			tc.note()
			var got []hookspool.Record
			emitHookActivity(tc.tool, tc.event, "", io.Discard, recordingActivityDeps(map[string]string{
				"ANTHROPIC_BASE_URL": "https://api.anthropic.com", "SECRET": "x",
			}, &got))
			if len(got) != tc.want {
				t.Fatalf("records %d, want %d: %+v", len(got), tc.want, got)
			}
			if tc.want == 0 {
				return
			}
			r := got[0]
			if r.Kind != hookspool.KindActivity || r.Tool != tc.tool || r.SessionID != tc.session || r.HookEvent != tc.native {
				t.Fatalf("record %+v", r)
			}
			if !reflect.DeepEqual(r.Env, map[string]string{"ANTHROPIC_BASE_URL": "provider_direct"}) {
				t.Fatalf("env %v (names and classes only)", r.Env)
			}
		})
	}
}

// TestHookActivityPathOpensNoDatabase is the acceptance pin "the hook
// process never opens SQLite" for the liveness work, twice over: the file
// that does the hook-side work imports nothing that can open a database,
// and a real invocation through runHookInvocation leaves a spool line and
// no database file behind.
func TestHookActivityPathOpensNoDatabase(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "hook_activity.go", nil, parser.ImportsOnly)
	if err != nil {
		t.Fatal(err)
	}
	for _, imp := range f.Imports {
		p, _ := strconv.Unquote(imp.Path.Value)
		for _, bad := range []string{"database/sql", "modernc.org/sqlite", "/internal/db", "/internal/store"} {
			if p == bad || strings.HasSuffix(p, bad) {
				t.Errorf("hook_activity.go imports %s: the hook-side liveness path must not reach a database", p)
			}
		}
	}

	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	cfgDir := filepath.Join(home, ".observer")
	if err := os.MkdirAll(cfgDir, 0o700); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(cfgDir, "config.toml")
	if err := os.WriteFile(cfgPath, []byte("[observer.hooks]\nauto_register = false\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	h := newFailureHarness(t, hookFailurePlan{})
	withStdinT(t, `{"session_id":"live-1","hook_event_name":"Whatever"}`, func() {
		runHookInvocation(context.Background(), []string{"nosuch-tool", "whatever"}, cfgPath, 20*time.Second, h.exit)
	})
	var dbs []string
	_ = filepath.WalkDir(home, func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && (strings.HasSuffix(p, ".db") || strings.Contains(p, ".db-")) {
			dbs = append(dbs, p)
		}
		return nil
	})
	if len(dbs) > 0 {
		t.Fatalf("a hook invocation created database files: %v", dbs)
	}
	raw, err := os.ReadFile(hookspool.Path(cfgPath))
	if err != nil {
		t.Fatalf("no activity spool: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != 1 {
		t.Fatalf("spool lines %d, want one record per invocation: %q", len(lines), raw)
	}
	var r hookspool.Record
	if err := json.Unmarshal([]byte(lines[0]), &r); err != nil || r.Kind != hookspool.KindActivity || r.Tool != "nosuch-tool" || r.HookEvent != "whatever" {
		t.Fatalf("record %+v err %v", r, err)
	}
}

// TestDrainHookActivity: the daemon's one drainer hands activity records to
// the one writer, beside the lifecycle events of the same file, and the
// rows land aggregated in hook_activity.
func TestDrainHookActivity(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(dir, "o.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	st := store.New(database)
	p := filepath.Join(dir, hookspool.Filename)
	now := time.Now().UTC()
	for _, r := range []hookspool.Record{
		{Kind: hookspool.KindActivity, Tool: "claude-code", HookEvent: "PreToolUse", SessionID: "s1", Timestamp: now, Env: map[string]string{"ANTHROPIC_BASE_URL": "loopback"}},
		{Kind: hookspool.KindActivity, Tool: "claude-code", HookEvent: "PreToolUse", SessionID: "s1", Timestamp: now.Add(time.Second)},
		{Kind: hookspool.KindActivity, Tool: "claude-code", HookEvent: "Stop", Timestamp: now},
	} {
		if err := hookspool.Append(p, r); err != nil {
			t.Fatal(err)
		}
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	deps := lifecycleDrainDeps{st: st, activity: st.UpsertHookActivity}
	drainHookLifecycleSpool(ctx, p, deps, now, logger)
	drainHookLifecycleSpool(ctx, p, deps, now.Add(hookspool.Grace+time.Second), logger)
	rows, err := st.LoadHookActivity(ctx, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Event < rows[j].Event })
	if len(rows) != 2 || rows[0].Event != "PreToolUse" || rows[0].Count != 2 || rows[0].EnvClasses["ANTHROPIC_BASE_URL"] != "loopback" ||
		rows[1].Event != "Stop" || rows[1].SessionID != "" || rows[1].Count != 1 {
		t.Fatalf("rows %+v", rows)
	}
	if ready, _ := hookspool.Ready(p, now.Add(time.Hour)); len(ready) != 0 {
		t.Fatalf("aside file not consumed: %+v", ready)
	}
	// The plan never treats an activity record as an event or a hold.
	plan := planLifecycleAside(ctx, st, []hookspool.Record{{Kind: hookspool.KindActivity, Tool: "t", HookEvent: "E"}}, map[string]bool{}, new(int), now, logger)
	if len(plan.activity) != 1 || len(plan.events)+len(plan.holds)+plan.expired != 0 {
		t.Fatalf("plan %+v", plan)
	}
}

// claudePreToolBody is a typical Claude Code PreToolUse payload (an Edit
// with a few KB of new_string), the hot case of the hook path.
func claudePreToolBody() []byte {
	body, _ := json.Marshal(map[string]any{
		"session_id":      "8f2c6a0e-3d51-4c1b-9a7e-1f0b9d2e4c77",
		"transcript_path": "/home/dev/.claude/projects/x/8f2c6a0e.jsonl",
		"cwd":             "/home/dev/src/project",
		"hook_event_name": "PreToolUse",
		"tool_name":       "Edit",
		"tool_input": map[string]any{
			"file_path":  "/home/dev/src/project/main.go",
			"old_string": strings.Repeat("old line of code\n", 100),
			"new_string": strings.Repeat("new line of code\n", 200),
		},
	})
	return body
}

// BenchmarkHookActivity measures everything liveness adds to one hook
// invocation: the payload session id read, the env class probe and the one
// O_APPEND spool write (the acceptance bound is 1 ms p95; see
// TestHookActivityLatencyP95).
func BenchmarkHookActivity(b *testing.B) {
	dir := b.TempDir()
	body := claudePreToolBody()
	deps := productionHookActivityDeps(func(k string) string {
		if k == "ANTHROPIC_BASE_URL" {
			return "http://127.0.0.1:8820"
		}
		return ""
	})
	cfg := filepath.Join(dir, "config.toml")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resetHookActivity()
		noteHookPayload(body)
		emitHookActivity("claude-code", "pre-tool", cfg, io.Discard, deps)
	}
}

// TestHookActivityLatencyP95 holds the added hook-path work under 1 ms at
// the 95th percentile over 400 invocations into a real temp spool. The
// bound is the review's acceptance line; the measured p95 is typically two
// orders of magnitude below it on an idle host. It is a wall-clock bound,
// so it runs where the bound means something: ci.yml's no-race latency step
// (scripts/ci/latency-tests.txt), never in a loaded -race test shard, where
// the detector's instrumentation and the shared 2-vCPU runner measured a
// p95 of 2.2 ms (p50 182 us, max 9.8 ms) for the same work.
func TestHookActivityLatencyP95(t *testing.T) {
	latencygate.Gate(t) // listed, and skipped under -short and in a loaded CI shard
	if raceDetectorOn {
		t.Skip("wall-clock latency bound is not measurable under the race detector; ci.yml's no-race latency step runs this")
	}
	dir := t.TempDir()
	body := claudePreToolBody()
	deps := productionHookActivityDeps(func(string) string { return "" })
	cfg := filepath.Join(dir, "config.toml")
	const n = 400
	d := make([]time.Duration, n)
	for i := range d {
		start := time.Now()
		resetHookActivity()
		noteHookPayload(body)
		emitHookActivity("claude-code", "pre-tool", cfg, io.Discard, deps)
		d[i] = time.Since(start)
	}
	resetHookActivity()
	sort.Slice(d, func(i, j int) bool { return d[i] < d[j] })
	p95 := d[n*95/100]
	t.Logf("hook liveness added work: p50 %v p95 %v max %v", d[n/2], p95, d[n-1])
	if p95 > time.Millisecond {
		t.Fatalf("p95 %v exceeds the 1 ms hook latency budget", p95)
	}
}
