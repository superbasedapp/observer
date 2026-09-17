package main

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestClaudeCodeHookDoubleFireIsIdempotent characterises what happens when
// the SAME Claude Code hook event is delivered TWICE with an identical
// payload — the shape a user gets when they have both installed the
// SuperBased Observer Claude Code plugin (plugins/claude-code/observer,
// which carries hooks/hooks.json) AND run `observer init --claude-code`
// (which writes the same events into ~/.claude/settings.json). Claude Code
// merges hook configurations from every source, so each event fires the
// observer hook binary once per registration.
//
// The finding this pins: every claude-code hook builder derives a
// DETERMINISTIC SourceEventID from the payload, and every row lands under
// the constant SourceFile "claude-code:hook", so the actions table's
// UNIQUE(source_file, source_event_id) constraint (migration 001) turns the
// second fire into the store's ON CONFLICT DO UPDATE path. Row counts do
// not grow. Duplicate hook wiring therefore costs a wasted process spawn
// per event, not a corrupted action history.
//
// This is a characterisation test, not an aspiration: if a future builder
// grows a non-deterministic SourceEventID (a timestamp, a random nonce),
// this test goes red and the double-wiring caveat has to be re-graded.
//
// SCOPE: this covers the builder+Ingest events only. The events that take
// their OWN handler path out of handleClaudeCodeHook — pre-compact and
// post-compact — are covered by
// TestClaudeCodePreCompactDoubleFireDuplicates, which drives the REAL
// dispatcher. Any new event added to the dispatcher's switch needs a row
// in one of the two.
func TestClaudeCodeHookDoubleFireIsIdempotent(t *testing.T) {
	cases := []struct {
		name  string
		body  []byte
		build claudeActionBuilder
	}{
		{
			"user_prompt_submit",
			[]byte(`{"session_id":"s1","cwd":"/repo","permission_mode":"default","prompt":"hello"}`),
			buildClaudeUserPromptSubmitEvent,
		},
		{
			"post_tool_failure",
			[]byte(`{"session_id":"s1","cwd":"/repo","tool_name":"Bash","tool_use_id":"tu_1","error":"boom","duration_ms":12}`),
			buildClaudePostToolFailureEvent,
		},
		{
			"stop_failure",
			[]byte(`{"session_id":"s1","cwd":"/repo","error":"stopped"}`),
			buildClaudeStopFailureEvent,
		},
		{
			"subagent_start",
			[]byte(`{"session_id":"s1","cwd":"/repo","agent_id":"a1","agent_type":"Explore"}`),
			buildClaudeSubagentStartEvent,
		},
		{
			"subagent_stop",
			[]byte(`{"session_id":"s1","cwd":"/repo","agent_id":"a1","agent_type":"Explore"}`),
			buildClaudeSubagentStopEvent,
		},
		{
			"stop",
			[]byte(`{"session_id":"s1","cwd":"/repo","last_assistant_message":"done"}`),
			buildClaudeStopEvent,
		},
		{
			"notification",
			[]byte(`{"session_id":"s1","cwd":"/repo","notification_type":"idle_prompt","message":"waiting"}`),
			buildClaudeNotificationEvent,
		},
		{
			"cwd_changed",
			[]byte(`{"session_id":"s1","cwd":"/repo","old_cwd":"/repo","new_cwd":"/repo/sub"}`),
			buildClaudeCwdChangedEvent,
		},
		{
			"setup",
			[]byte(`{"session_id":"s1","cwd":"/repo","trigger":"init"}`),
			buildClaudeSetupEvent,
		},
		{
			"user_prompt_expansion",
			[]byte(`{"session_id":"s1","cwd":"/repo","prompt":"a","expanded_prompt":"aaa"}`),
			buildClaudeUserPromptExpansionEvent,
		},
		{
			"post_tool_batch",
			[]byte(`{"session_id":"s1","cwd":"/repo","tool_calls":[{"tool_name":"Read","tool_use_id":"tu_b1"}]}`),
			buildClaudePostToolBatchEvent,
		},
		{
			"permission_request",
			[]byte(`{"session_id":"s1","cwd":"/repo","tool_name":"Bash","tool_use_id":"tu_2"}`),
			buildClaudePermissionRequestEvent,
		},
		{
			"permission_denied",
			[]byte(`{"session_id":"s1","cwd":"/repo","tool_name":"Bash","tool_use_id":"tu_3","reason":"nope"}`),
			buildClaudePermissionDeniedEvent,
		},
		{
			"instructions_loaded",
			[]byte(`{"session_id":"s1","cwd":"/repo","file_path":"/repo/CLAUDE.md"}`),
			buildClaudeInstructionsLoadedEvent,
		},
		{
			"config_change",
			[]byte(`{"session_id":"s1","cwd":"/repo","source":"user","file_path":"/home/u/.claude/settings.json"}`),
			buildClaudeConfigChangeEvent,
		},
		{
			"worktree_remove",
			[]byte(`{"session_id":"s1","cwd":"/repo","worktree_path":"/repo/.wt/x"}`),
			buildClaudeWorktreeRemoveEvent,
		},
		// session_end is deliberately LAST: Ingest refuses to bootstrap a
		// session from a terminal marker, so it only lands once the other
		// events above have created session s1.
		{
			"session_end",
			[]byte(`{"session_id":"s1","cwd":"/repo","permission_mode":"default"}`),
			buildClaudeSessionEndEvent,
		},
	}

	ctx := context.Background()
	database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "obs.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer database.Close()
	st := store.New(database)

	countActions := func(t *testing.T) int {
		t.Helper()
		var n int
		if err := database.QueryRow(`SELECT COUNT(*) FROM actions`).Scan(&n); err != nil {
			t.Fatalf("count actions: %v", err)
		}
		return n
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ev, ok := c.build(c.body)
			if !ok {
				t.Fatalf("builder rejected fixture payload")
			}

			before := countActions(t)

			// Fire 1 — the registration in ~/.claude/settings.json.
			if _, err := st.Ingest(ctx, []models.ToolEvent{ev}, nil, store.IngestOptions{}); err != nil {
				t.Fatalf("ingest #1: %v", err)
			}
			afterFirst := countActions(t)
			if afterFirst != before+1 {
				t.Fatalf("first fire wrote %d rows, want exactly 1 (before=%d after=%d)",
					afterFirst-before, before, afterFirst)
			}

			// Fire 2 — the plugin's hooks/hooks.json. Claude Code rebuilds
			// the payload, so re-run the builder rather than reusing ev:
			// that also exercises the timestamp, which differs between
			// fires and must NOT participate in the dedup key.
			ev2, ok := c.build(c.body)
			if !ok {
				t.Fatalf("builder rejected fixture payload on second fire")
			}
			if ev2.SourceEventID != ev.SourceEventID {
				t.Fatalf("SourceEventID is not deterministic: %q vs %q",
					ev.SourceEventID, ev2.SourceEventID)
			}
			if ev2.SourceFile != ev.SourceFile {
				t.Fatalf("SourceFile is not deterministic: %q vs %q", ev.SourceFile, ev2.SourceFile)
			}
			if _, err := st.Ingest(ctx, []models.ToolEvent{ev2}, nil, store.IngestOptions{}); err != nil {
				t.Fatalf("ingest #2: %v", err)
			}
			if got := countActions(t); got != afterFirst {
				t.Errorf("double fire added %d duplicate action row(s) (want 0): %d -> %d",
					got-afterFirst, afterFirst, got)
			}
		})
	}
}

// TestClaudeCodeEffortDoubleFireIsIdempotent characterises the OTHER
// write the claude-code hook path performs: the per-turn effort sidecar
// (claudecode_effort, written by recordClaudecodeEffort on PreToolUse and
// PostToolUse). Its store helper upserts on (session_id, tool_use_id), so a
// double fire re-writes one row instead of appending.
func TestClaudeCodeEffortDoubleFireIsIdempotent(t *testing.T) {
	ctx := context.Background()
	database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "obs.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer database.Close()
	st := store.New(database)

	for i := 0; i < 2; i++ {
		if err := st.UpsertClaudecodeEffort(ctx, "s1", "tu_1", "high", "PreToolUse"); err != nil {
			t.Fatalf("upsert #%d: %v", i+1, err)
		}
	}
	var n int
	if err := database.QueryRow(`SELECT COUNT(*) FROM claudecode_effort`).Scan(&n); err != nil {
		t.Fatalf("count claudecode_effort: %v", err)
	}
	if n != 1 {
		t.Errorf("claudecode_effort rows = %d after a double fire, want 1", n)
	}
}

// TestClaudeCodePreCompactDoubleFireDuplicates drives the REAL dispatcher
// (handleClaudeCodeHook) for pre-compact, which takes its own handler path
// and never touches the builder+Ingest machinery the test above exercises.
// Driving the dispatcher — not a builder — is the point: the compaction
// path was missed by the builder-level test precisely because it bypasses
// it.
//
// The behaviour it pins is a KNOWN, DOCUMENTED RESIDUE, not a bug fixed
// here: a doubled PreCompact writes TWO compaction_events rows.
//
// compaction_events has no uniqueness constraint (migration 001) and the
// PreCompact payload carries nothing that identifies one compaction
// occurrence. Verified against the shipped Claude Code v2.1.220 binary:
// the payload is {session_id, transcript_path, cwd, prompt_id?,
// agent_type?, hook_event_name, trigger, custom_instructions} and the
// strings compact_id / compaction_id / compactId / compactionId /
// compact_uuid appear NOWHERE in the binary. `prompt_id` is prompt-grain
// by its own documented definition ("correlating a user prompt with all
// subsequent events until the next prompt"), is optional, and is absent
// until the first user input.
//
// That matters because Claude Code can legitimately fire PreCompact more
// than once inside a single prompt: a speculative "precomputed" compaction
// (which carries its own retry counter) and then a reactive one, and a
// hook that returns new custom instructions forces the precomputed result
// to be discarded and recompacted. Two such fires produce BYTE-IDENTICAL
// payloads. So every candidate key — a content hash, (session_id,
// prompt_id), (session_id, trigger) — would silently collapse two REAL
// compactions into one. Eating a genuine event is strictly worse than
// keeping a duplicate, so no dedupe is applied and the duplicate is
// documented instead: in plugins/README.md, the plugin README, the
// doctor probe's cost note, and the plan of record.
//
// If Claude Code ever adds an occurrence identifier, this test is where
// the change lands: assert 1 row and add the uniqueness constraint.
func TestClaudeCodePreCompactDoubleFireDuplicates(t *testing.T) {
	ctx := context.Background()
	home := t.TempDir()
	dbPath := filepath.Join(home, "observer.db")
	cfgPath := filepath.Join(home, "config.toml")
	if err := os.WriteFile(cfgPath,
		[]byte("[observer]\ndb_path = \""+filepath.ToSlash(dbPath)+"\"\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	// Seed the project + session the compaction recorder resolves against.
	database, err := dbtemplate.Open(ctx, db.Options{Path: dbPath})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	st := store.New(database)
	root := filepath.Join(home, "repo")
	if _, err := st.Ingest(ctx, []models.ToolEvent{{
		SourceFile:    "claude-code:hook",
		SourceEventID: "seed",
		SessionID:     "s-compact",
		ProjectRoot:   root,
		Timestamp:     time.Now().UTC(),
		Tool:          models.ToolClaudeCode,
		ActionType:    models.ActionUserPrompt,
		Target:        "seed",
		Success:       true,
	}}, nil, store.IngestOptions{}); err != nil {
		t.Fatalf("seed ingest: %v", err)
	}
	database.Close()

	payload := `{"session_id":"s-compact","cwd":` + strconvQuote(root) +
		`,"transcript_path":"/tmp/t.jsonl","hook_event_name":"PreCompact",` +
		`"trigger":"auto","custom_instructions":null}`

	countCompactions := func() int {
		d, err := dbtemplate.Open(ctx, db.Options{Path: dbPath})
		if err != nil {
			t.Fatalf("db.Open: %v", err)
		}
		defer d.Close()
		var n int
		if err := d.QueryRow(`SELECT COUNT(*) FROM compaction_events`).Scan(&n); err != nil {
			t.Fatalf("count compaction_events: %v", err)
		}
		return n
	}

	// Fire 1 — the ~/.claude/settings.json registration.
	// Fire 2 — the plugin's hooks/hooks.json, same payload.
	for i := 1; i <= 2; i++ {
		withStdio(t, payload, func() {
			handleClaudeCodeHook(ctx, "pre-compact", cfgPath)
		})
		if got := countCompactions(); got != i {
			t.Fatalf("after fire %d: compaction_events = %d, want %d", i, got, i)
		}
	}

	// The residue, stated as an assertion so it can never regress
	// silently into "we fixed it" or "it got worse".
	if got := countCompactions(); got != 2 {
		t.Errorf("compaction_events = %d after a double PreCompact, want 2 (documented residue)", got)
	}
}

// withStdio runs fn with os.Stdin fed from body and os.Stdout/os.Stderr
// redirected to a temp file, restoring all three afterwards. The hook
// handlers read os.Stdin directly, so driving the real dispatcher means
// swapping the process's own descriptors.
func withStdio(t *testing.T, body string, fn func()) {
	t.Helper()
	dir := t.TempDir()
	inPath := filepath.Join(dir, "stdin")
	if err := os.WriteFile(inPath, []byte(body), 0o600); err != nil {
		t.Fatalf("write stdin: %v", err)
	}
	in, err := os.Open(inPath) //nolint:gosec // G304: a path this test just created under t.TempDir().
	if err != nil {
		t.Fatalf("open stdin: %v", err)
	}
	defer in.Close()
	sink, err := os.Create(filepath.Join(dir, "out"))
	if err != nil {
		t.Fatalf("create sink: %v", err)
	}
	defer sink.Close()

	oldIn, oldOut, oldErr := os.Stdin, os.Stdout, os.Stderr
	os.Stdin, os.Stdout, os.Stderr = in, sink, sink
	defer func() { os.Stdin, os.Stdout, os.Stderr = oldIn, oldOut, oldErr }()
	fn()
}

// strconvQuote is strconv.Quote, named locally to keep the JSON fixture
// above readable without importing strconv for one call.
func strconvQuote(s string) string { return strconv.Quote(s) }
