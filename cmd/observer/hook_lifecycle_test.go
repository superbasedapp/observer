package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/hookdisable"
	"github.com/marmutapp/superbased-observer/internal/hookspool"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/pidbridge"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// recordingDeps returns lifecycle deps that record instead of writing.
func recordingDeps(t *testing.T, rows *[]hookspool.Record, seeds *[]pidbridge.Entry) lifecycleDeps {
	t.Helper()
	at := time.Date(2026, 10, 3, 9, 0, 0, 0, time.UTC)
	return lifecycleDeps{
		now:       func() time.Time { return at },
		spoolPath: func(string) string { return "/spool/hook-lifecycle.jsonl" },
		appendRow: func(_ string, r hookspool.Record) error { *rows = append(*rows, r); return nil },
		parentPID: 4242,
		ancestors: func(int) []int { return []int{4242} },
		pidbridge: func(string) pidbridgeWriter {
			return func(_ context.Context, e pidbridge.Entry) error { *seeds = append(*seeds, e); return nil }
		},
	}
}

// TestHandleLifecycleHook is one case per lifecycle binding Lane C wired on
// a registered (vendor-config) mechanism, using payloads shaped like the
// node-1 captures (2026-10-03, anonymized): the reply is always the neutral
// {}, a start seeds pidbridge and records no row, an end spools a row.
func TestHandleLifecycleHook(t *testing.T) {
	for _, tc := range []struct {
		tool, event, body string
		wantAction        string
		wantSeed          bool
	}{
		{"qoder", "SessionStart", `{"session_id":"q1","cwd":"/w","hook_event_name":"SessionStart","source":"startup"}`, "", true},
		{"qoder", "Stop", `{"session_id":"q1","cwd":"/w","hook_event_name":"Stop","last_assistant_message":"OK"}`, models.ActionTaskComplete, false},
		{"qoder", "SessionEnd", `{"session_id":"q1","cwd":"/w","hook_event_name":"SessionEnd","reason":"other"}`, models.ActionSessionEnd, false},
		{"qoder", "SubagentStart", `{"session_id":"q1","agent_id":"ageneral-purpose-1","agent_type":"general-purpose","hook_event_name":"SubagentStart"}`, models.ActionSubagentStart, false},
		{"qoder", "SubagentStop", `{"session_id":"q1","agent_id":"ageneral-purpose-1","hook_event_name":"SubagentStop"}`, models.ActionSubagentStop, false},
		{"codex", "SessionEnd", `{"session_id":"c1","cwd":"/w","hook_event_name":"SessionEnd"}`, models.ActionSessionEnd, false},
		{"codex", "SubagentStart", `{"session_id":"c1","agent_id":"c2","hook_event_name":"SubagentStart"}`, models.ActionSubagentStart, false},
		{"codex", "SubagentStop", `{"session_id":"c1","agent_id":"c2","hook_event_name":"SubagentStop"}`, models.ActionSubagentStop, false},
		{"qwen-code", "SessionStart", `{"session_id":"w1","cwd":"/w","hook_event_name":"SessionStart"}`, "", true},
		{models.ToolClaudeCode, "SessionEnd", `{"session_id":"cc1","cwd":"/w","hook_event_name":"SessionEnd","reason":"exit"}`, models.ActionSessionEnd, false},
	} {
		t.Run(tc.tool+"/"+tc.event, func(t *testing.T) {
			b, ok := lifecycleBinding(tc.tool, tc.event)
			if !ok {
				t.Fatalf("no wired lifecycle binding for %s %s", tc.tool, tc.event)
			}
			var rows []hookspool.Record
			var seeds []pidbridge.Entry
			var stdout, stderr bytes.Buffer
			hookReplied = false
			handleLifecycleHook(context.Background(), tc.tool, tc.tool+":"+tc.event, b, []byte(tc.body), "", &stdout, &stderr, recordingDeps(t, &rows, &seeds))
			if stdout.String() != "{}\n" || !hookReplied {
				t.Errorf("reply = %q (replied %v), want the neutral {}", stdout.String(), hookReplied)
			}
			if tc.wantAction == "" {
				if len(rows) != 0 {
					t.Errorf("a start spooled %d rows", len(rows))
				}
			} else if len(rows) != 1 || rows[0].ActionType != tc.wantAction || rows[0].Tool != tc.tool {
				t.Errorf("rows = %+v, want one %s under %s", rows, tc.wantAction, tc.tool)
			}
			if (len(seeds) > 0) != tc.wantSeed {
				t.Errorf("pidbridge seeds = %d, want seeded %v", len(seeds), tc.wantSeed)
			}
		})
	}
}

// TestLifecycleBindingLeavesOwnedEvents: an event whose own receiver owns it
// (Codex SessionStart / Stop, every Cursor event) or that is vendor-only
// (droid, qwen SessionEnd until grounded) is not routed to the handler.
func TestLifecycleBindingLeavesOwnedEvents(t *testing.T) {
	for _, tc := range [][2]string{
		{"codex", "SessionStart"},
		{"codex", "Stop"},
		{"cursor", "sessionEnd"},
		{"cursor", "stop"},
		{"droid", "SessionEnd"},
		{"qwen-code", "SessionEnd"},
		{"qwen-code", "Stop"},
		{models.ToolClaudeCode, "session-end"},
		{"qoder", "UserPromptSubmit"},
	} {
		if _, ok := lifecycleBinding(tc[0], tc[1]); ok {
			t.Errorf("%s %s routed to the lifecycle handler", tc[0], tc[1])
		}
	}
	if _, ok := lifecycleBinding("grok", "SessionEnd"); !ok {
		t.Error("grok SessionEnd (the Claude settings replay) must route to the lifecycle handler")
	}
}

func TestHandleLifecycleHookNoSessionRecordsNothing(t *testing.T) {
	b, _ := lifecycleBinding("qoder", "SessionEnd")
	var rows []hookspool.Record
	var seeds []pidbridge.Entry
	var stdout, stderr bytes.Buffer
	handleLifecycleHook(context.Background(), "qoder", "qoder:SessionEnd", b, []byte(`{"cwd":"/w"}`), "", &stdout, &stderr, recordingDeps(t, &rows, &seeds))
	if stdout.String() != "{}\n" || len(rows) != 0 || !strings.Contains(stderr.String(), "no session id") {
		t.Fatalf("stdout %q rows %d stderr %q", stdout.String(), len(rows), stderr.String())
	}
}

type fakeIngester struct {
	got []models.ToolEvent
	err error
	// missing names sessions the fake reports as not yet ingested.
	missing map[string]bool
}

func (f *fakeIngester) SessionExists(_ context.Context, id string) (bool, error) {
	return !f.missing[id], nil
}

func (f *fakeIngester) ProjectRootForSession(context.Context, string) (string, error) {
	return "/w", nil
}

func (f *fakeIngester) Ingest(_ context.Context, evs []models.ToolEvent, _ []models.TokenEvent, _ store.IngestOptions) (store.IngestResult, error) {
	if f.err != nil {
		return store.IngestResult{}, f.err
	}
	f.got = append(f.got, evs...)
	return store.IngestResult{}, nil
}

// TestDrainHookLifecycleSpool: a failed ingest keeps the aside file for the
// next pass; a successful one removes it.
func TestDrainHookLifecycleSpool(t *testing.T) {
	p := filepath.Join(t.TempDir(), hookspool.Filename)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ev := models.ToolEvent{
		Tool: "qoder", SourceFile: "qoder:hook", SourceEventID: "q1:session_end", SessionID: "q1",
		ActionType: models.ActionSessionEnd, Success: true, Timestamp: time.Now(),
	}
	if err := hookspool.Append(p, hookspool.FromEvent(ev)); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if n := drainHookLifecycleSpool(context.Background(), p, lifecycleDrainDeps{st: &fakeIngester{}}, now, logger); n != 0 {
		t.Fatalf("first pass ingested %d (the live spool is only set aside)", n)
	}
	failing := &fakeIngester{err: errors.New("db busy")}
	later := now.Add(hookspool.Grace + time.Second)
	if n := drainHookLifecycleSpool(context.Background(), p, lifecycleDrainDeps{st: failing}, later, logger); n != 0 {
		t.Fatalf("failing ingest reported %d", n)
	}
	ok := &fakeIngester{}
	if n := drainHookLifecycleSpool(context.Background(), p, lifecycleDrainDeps{st: ok}, later.Add(time.Second), logger); n != 1 || len(ok.got) != 1 || ok.got[0].SessionID != "q1" {
		t.Fatalf("retry ingested %d: %+v", n, ok.got)
	}
	if n := drainHookLifecycleSpool(context.Background(), p, lifecycleDrainDeps{st: ok}, later.Add(time.Hour), logger); n != 0 {
		t.Fatalf("a drained file was ingested again: %d", n)
	}
}

type fakePersister struct{ vs []guard.ActionVerdict }

func (f *fakePersister) PersistGuardVerdicts(_ context.Context, vs []guard.ActionVerdict) (int, error) {
	f.vs = append(f.vs, vs...)
	return len(vs), nil
}

// TestHookDisableWatch: a switch is persisted as a guard_error flag with
// degraded_from hooks_disabled when it turns on, not on every tick, and
// again after it was cleared and set again (T-046).
func TestHookDisableWatch(t *testing.T) {
	files := map[string]string{}
	w := &hookDisableWatch{home: "/h", read: func(p string) ([]byte, error) {
		if s, ok := files[p]; ok {
			return []byte(s), nil
		}
		return nil, errors.New("absent")
	}}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	st := &fakePersister{}
	claude := filepath.Join("/h", ".claude", "settings.json")
	now := time.Now()
	if n := w.check(context.Background(), st, now, logger); n != 0 {
		t.Fatalf("clean home persisted %d", n)
	}
	files[claude] = `{"disableAllHooks":true}`
	if n := w.check(context.Background(), st, now, logger); n != 1 {
		t.Fatalf("switch on persisted %d, want 1", n)
	}
	if n := w.check(context.Background(), st, now, logger); n != 0 {
		t.Fatalf("unchanged switch persisted again: %d", n)
	}
	delete(files, claude)
	w.check(context.Background(), st, now, logger)
	files[claude] = `{"disableAllHooks":true}`
	if n := w.check(context.Background(), st, now, logger); n != 1 {
		t.Fatalf("re-set switch persisted %d, want 1", n)
	}
	v := st.vs[0]
	if !v.GuardError || v.DegradedFrom != "hooks_disabled" || v.Verdict.RuleID != guard.GuardErrorRuleID ||
		!strings.Contains(v.Verdict.Advice, "grok") || v.Input.Target != claude {
		t.Fatalf("verdict = %+v", v)
	}
	_ = hookdisable.Switches
}

type fakeRootLister struct {
	roots []string
	err   error
	calls int
}

func (f *fakeRootLister) RecentProjectRoots(_ context.Context, limit int) ([]string, error) {
	f.calls++
	if limit != hookdisable.MaxProjectRoots {
		return nil, errors.New("unbounded")
	}
	return f.roots, f.err
}

// TestHookDisableWatchProjectScope (T-910): a project's
// .claude/settings.local.json disableAllHooks is reported once as a guard
// event carrying the project root; the project scan runs on its own
// cadence, and a failed root read keeps the previous result instead of
// reporting the switch cleared and set again.
func TestHookDisableWatchProjectScope(t *testing.T) {
	files := map[string]string{}
	lister := &fakeRootLister{roots: []string{"/work/app"}}
	w := newHookDisableWatch(lister)
	w.home, w.goos = "/h", ""
	w.read = func(p string) ([]byte, error) {
		if s, ok := files[p]; ok {
			return []byte(s), nil
		}
		return nil, errors.New("absent")
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	st := &fakePersister{}
	local := filepath.Join("/work/app", ".claude", "settings.local.json")
	files[local] = `{"permissions":{"allow":["Bash(ls)"]},"disableAllHooks":true}`
	now := time.Now()
	if n := w.check(context.Background(), st, now, logger); n != 1 {
		t.Fatalf("project switch persisted %d, want 1", n)
	}
	v := st.vs[0]
	if v.Input.ProjectRoot != filepath.Clean("/work/app") || v.Input.Target != local || !strings.Contains(v.Verdict.Advice, "in project "+filepath.Clean("/work/app")) ||
		!strings.Contains(v.Verdict.Reason, "project scope") {
		t.Fatalf("verdict = %+v", v)
	}
	// Within the interval the project files are not re-read, and the
	// standing finding is not reported again.
	delete(files, local)
	if n := w.check(context.Background(), st, now.Add(time.Second), logger); n != 0 || lister.calls != 1 {
		t.Fatalf("within interval: persisted %d, root reads %d", n, lister.calls)
	}
	// A failed root read keeps the last project result.
	files[local] = `{"disableAllHooks":true}`
	lister.err = errors.New("db busy")
	if n := w.check(context.Background(), st, now.Add(hookProjectScanInterval), logger); n != 0 {
		t.Fatalf("failed root read persisted %d", n)
	}
	// Cleared, then set again: reported again.
	lister.err = nil
	delete(files, local)
	w.check(context.Background(), st, now.Add(2*hookProjectScanInterval), logger)
	files[local] = `{"disableAllHooks":true}`
	if n := w.check(context.Background(), st, now.Add(3*hookProjectScanInterval), logger); n != 1 {
		t.Fatalf("re-set project switch persisted %d, want 1", n)
	}
}
