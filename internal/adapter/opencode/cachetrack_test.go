package opencode

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

// TestCacheObservations_Anthropic_Shape pins the §14.3 opencode
// Tier-2 emission against an assistant message that carries the
// full Anthropic-shape token bundle (input + output + cache.read +
// cache.write). One observation, on the assistant turn, with
// BlockHashes folded in for the user prompt + the assistant's
// tool/reasoning/text parts.
func TestCacheObservations_Anthropic_Shape(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "opencode.db")
	setupOpenCodeDBForCachetrack(t, path)

	a := NewWithOptions(nil, []string{root})
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if got := len(res.CacheObservations); got != 1 {
		t.Fatalf("CacheObservations = %d, want 1 (one assistant turn with tokens)", got)
	}
	obs := res.CacheObservations[0]
	if obs.MessageID != "msg_assist" {
		t.Errorf("MessageID = %q, want msg_assist", obs.MessageID)
	}
	if obs.SourceEventID != "cachetrack:msg_assist" {
		t.Errorf("SourceEventID = %q, want cachetrack:msg_assist", obs.SourceEventID)
	}
	if obs.Model != "claude-sonnet-4" {
		t.Errorf("Model = %q, want claude-sonnet-4", obs.Model)
	}
	if obs.Usage.CacheReadTokens != 4096 {
		t.Errorf("CacheReadTokens = %d, want 4096", obs.Usage.CacheReadTokens)
	}
	if obs.Usage.CacheCreationTokens != 1024 {
		t.Errorf("CacheCreationTokens = %d, want 1024", obs.Usage.CacheCreationTokens)
	}
	if obs.Usage.NetInputTokens != 200 {
		t.Errorf("NetInputTokens = %d, want 200", obs.Usage.NetInputTokens)
	}
	if obs.Usage.OutputTokens != 300 {
		t.Errorf("OutputTokens = %d, want 300", obs.Usage.OutputTokens)
	}
	// User prompt (1 text part) + assistant (1 tool + 1 reasoning +
	// 1 text) = 4 blocks; step-finish is excluded by design.
	if got := len(obs.BlockHashes); got != 4 {
		t.Fatalf("BlockHashes = %d, want 4 (text + tool + reasoning + text; step-finish excluded)", got)
	}
}

// TestCacheObservations_VolatileExclusion_R3 pins the volatile-
// element exclusion strategy from
// docs/audits/cachetrack-opencode-tier2-audit-2026-06-09.md: the
// wall-clock fields inside tool/reasoning/subtask part bodies
// (state.time.{start,end}, state.title, time.{start,end},
// time.created) must NEVER appear in CanonicalBytes. The test
// re-parses the same DB twice, then mutates JUST the volatile
// fields and re-parses again — all three runs must produce
// byte-identical CanonicalBytes per emitted block.
func TestCacheObservations_VolatileExclusion_R3(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "opencode.db")
	setupOpenCodeDBForCachetrack(t, path)

	a := NewWithOptions(nil, []string{root})

	first, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("first parse: %v", err)
	}
	second, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("second parse: %v", err)
	}
	if len(first.CacheObservations) == 0 || len(second.CacheObservations) == 0 {
		t.Fatal("expected at least one CacheObservation in both runs")
	}
	for i := range first.CacheObservations[0].BlockHashes {
		a := first.CacheObservations[0].BlockHashes[i].CanonicalBytes
		b := second.CacheObservations[0].BlockHashes[i].CanonicalBytes
		if !bytes.Equal(a, b) {
			t.Fatalf("block %d differs between identical parses\n  first:  %s\n  second: %s", i, a, b)
		}
	}

	// Now mutate ONLY the volatile fields on every part: bump
	// state.time / time / title by a wall-clock-style delta. The
	// resulting canonical bytes MUST be identical to the first
	// parse — if they aren't, a volatile field has slipped past
	// the audit's exclusion list.
	mutateVolatileFields(t, path)
	mutated, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("mutated parse: %v", err)
	}
	if len(mutated.CacheObservations) == 0 {
		t.Fatal("expected at least one CacheObservation after volatile-field mutation")
	}
	for i := range first.CacheObservations[0].BlockHashes {
		a := first.CacheObservations[0].BlockHashes[i].CanonicalBytes
		b := mutated.CacheObservations[0].BlockHashes[i].CanonicalBytes
		if !bytes.Equal(a, b) {
			t.Fatalf("R3 BROKEN: block %d differs after mutating volatile fields\n  pre:  %s\n  post: %s\n(a volatile field slipped past the audit's exclusion list — re-read docs/audits/cachetrack-opencode-tier2-audit-2026-06-09.md and add the field to marshalCanonicalPartTier2's struct exclusions)", i, a, b)
		}
	}
}

// TestCacheObservations_Idempotent pins the cross-tier idempotency
// contract: re-parsing from offset 0 twice produces the same
// observation set (MessageID, SourceEventID, BlockHashes content).
// The (SourceFile, SourceEventID) dedup gate in store.Ingest
// depends on this byte-stability.
func TestCacheObservations_Idempotent(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "opencode.db")
	setupOpenCodeDBForCachetrack(t, path)

	a := NewWithOptions(nil, []string{root})
	first, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("first parse: %v", err)
	}
	second, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("second parse: %v", err)
	}
	if len(first.CacheObservations) != len(second.CacheObservations) {
		t.Fatalf("observation count drift: first=%d second=%d", len(first.CacheObservations), len(second.CacheObservations))
	}
	for i := range first.CacheObservations {
		if first.CacheObservations[i].SourceEventID != second.CacheObservations[i].SourceEventID {
			t.Errorf("obs[%d] SourceEventID drift: %q vs %q", i, first.CacheObservations[i].SourceEventID, second.CacheObservations[i].SourceEventID)
		}
		if first.CacheObservations[i].MessageID != second.CacheObservations[i].MessageID {
			t.Errorf("obs[%d] MessageID drift: %q vs %q", i, first.CacheObservations[i].MessageID, second.CacheObservations[i].MessageID)
		}
	}
}

// TestCacheObservations_IncrementalClosesEmittedDeltas pins T-930: on an
// incremental 1.x parse the session is replayed from its first message to
// keep the chain complete, but a step an earlier parse already emitted must
// close its delta, so the first new step carries only the blocks written
// since that step (here the new prompt and the new reply), not the
// session's older blocks again. Mirrors loadCacheObservationsV2.
func TestCacheObservations_IncrementalClosesEmittedDeltas(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "opencode.db")
	setupOpenCodeDBForCachetrack(t, path)

	a := NewWithOptions(nil, []string{root})
	first, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("first parse: %v", err)
	}
	if len(first.CacheObservations) != 1 || len(first.CacheObservations[0].BlockHashes) != 4 {
		t.Fatalf("first parse = %d observations, want 1 with 4 blocks", len(first.CacheObservations))
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	stmts := []string{
		`INSERT INTO message(id, session_id, time_created, time_updated, data) VALUES
			('msg_user2', 'ses_1', 6000, 6001,
			 '{"role":"user","agent":"build","model":{"providerID":"anthropic","modelID":"claude-sonnet-4"},"time":{"created":6000}}'),
			('msg_assist2', 'ses_1', 7000, 7500,
			 '{"role":"assistant","agent":"build","modelID":"claude-sonnet-4","providerID":"anthropic","path":{"cwd":"/tmp/oc"},"time":{"created":7000,"completed":7500},"finish":"stop","tokens":{"input":20,"output":10,"reasoning":0,"cache":{"read":5120,"write":64}},"cost":0.001}')`,
		`INSERT INTO part(id, message_id, session_id, time_created, time_updated, data) VALUES
			('prt_u2', 'msg_user2',   'ses_1', 6000, 6001, '{"type":"text","text":"And again"}'),
			('prt_t2', 'msg_assist2', 'ses_1', 7100, 7200, '{"type":"text","text":"Still green."}')`,
	}
	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("exec %q: %v", stmt, err)
		}
	}
	_ = db.Close()

	later, err := a.ParseSessionFile(context.Background(), path, first.NewOffset)
	if err != nil {
		t.Fatalf("incremental parse: %v", err)
	}
	if len(later.CacheObservations) != 1 {
		t.Fatalf("incremental observations = %d, want 1", len(later.CacheObservations))
	}
	obs := later.CacheObservations[0]
	if obs.MessageID != "msg_assist2" {
		t.Errorf("MessageID = %q, want msg_assist2", obs.MessageID)
	}
	if got := len(obs.BlockHashes); got != 2 {
		t.Errorf("BlockHashes = %d, want 2 (new prompt + new reply; the already-emitted step's delta is closed)", got)
	}
}

// TestCacheObservations_SkipsAssistantWithoutTokens pins the
// "in-progress turn" carve-out. An assistant message whose tokens
// bundle is fully zero (early streaming row, or a slot that never
// completed) must NOT emit a CacheTurnObservation — same gate as
// the existing loadTokenEvents path.
func TestCacheObservations_SkipsAssistantWithoutTokens(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "opencode.db")
	setupOpenCodeDB(t, path) // setup writes assistant rows with zero tokens

	a := NewWithOptions(nil, []string{root})
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if got := len(res.CacheObservations); got != 0 {
		t.Fatalf("CacheObservations = %d, want 0 (assistant rows in setupOpenCodeDB carry no tokens)", got)
	}
}

func setupOpenCodeDBForCachetrack(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	stmts := []string{
		`CREATE TABLE session (id TEXT PRIMARY KEY, directory TEXT NOT NULL, time_updated INTEGER NOT NULL)`,
		`CREATE TABLE message (id TEXT PRIMARY KEY, session_id TEXT NOT NULL, time_created INTEGER NOT NULL, time_updated INTEGER NOT NULL, data TEXT NOT NULL)`,
		`CREATE TABLE part (id TEXT PRIMARY KEY, message_id TEXT NOT NULL, session_id TEXT NOT NULL, time_created INTEGER NOT NULL, time_updated INTEGER NOT NULL, data TEXT NOT NULL)`,
		`INSERT INTO session(id, directory, time_updated) VALUES ('ses_1', '/tmp/oc', 5000)`,
		// User prompt at t=1000, assistant turn at t=2000-2500 with
		// full Anthropic-shape token bundle including cache.read +
		// cache.write.
		`INSERT INTO message(id, session_id, time_created, time_updated, data) VALUES
			('msg_user', 'ses_1', 1000, 1001,
			 '{"role":"user","agent":"build","model":{"providerID":"anthropic","modelID":"claude-sonnet-4"},"time":{"created":1000}}'),
			('msg_assist', 'ses_1', 2000, 2500,
			 '{"role":"assistant","agent":"build","modelID":"claude-sonnet-4","providerID":"anthropic","path":{"cwd":"/tmp/oc"},"time":{"created":2000,"completed":2500},"finish":"stop","tokens":{"input":200,"output":300,"reasoning":42,"cache":{"read":4096,"write":1024}},"cost":0.0123}')`,
		// Parts: user prompt, then assistant tool + reasoning + text
		// + step-finish. step-finish must NOT enter the chain (usage
		// rollup; would double-count vs message-level tokens).
		`INSERT INTO part(id, message_id, session_id, time_created, time_updated, data) VALUES
			('prt_u',     'msg_user',   'ses_1', 1000, 1001,
			 '{"type":"text","text":"Cache me if you can"}'),
			('prt_tool',  'msg_assist', 'ses_1', 2100, 2300,
			 '{"type":"tool","tool":"bash","callID":"call_1","state":{"status":"completed","input":{"command":"go test","description":"Run"},"output":"ok","metadata":{"output":"ok","exit":0,"description":"Run","truncated":false},"title":"Run @ 2:30 PM","time":{"start":2100,"end":2300}}}'),
			('prt_think', 'msg_assist', 'ses_1', 2300, 2350,
			 '{"type":"reasoning","text":"I should check the tests","time":{"start":2300,"end":2350}}'),
			('prt_text',  'msg_assist', 'ses_1', 2400, 2450,
			 '{"type":"text","text":"All green."}'),
			('prt_step',  'msg_assist', 'ses_1', 2450, 2500,
			 '{"type":"step-finish","reason":"stop","tokens":{"input":200,"output":300,"reasoning":42,"total":542,"cache":{"read":4096,"write":1024}},"cost":0.0123}')`,
	}
	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("exec %q: %v", stmt, err)
		}
	}
}

// mutateVolatileFields bumps the wall-clock fields the audit
// classified as volatile (state.time.{start,end}, state.title,
// time.{start,end}) by 60 seconds. The mutation MUST NOT change
// any canonical-byte block — that's the R3 byte-stability guarantee.
func mutateVolatileFields(t *testing.T, path string) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	rows, err := db.Query(`SELECT id, data FROM part`)
	if err != nil {
		t.Fatal(err)
	}
	type row struct{ id, data string }
	var all []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.data); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		all = append(all, r)
	}
	rows.Close()

	for _, r := range all {
		var m map[string]any
		if err := json.Unmarshal([]byte(r.data), &m); err != nil {
			continue
		}
		bumpWallClock(m)
		buf, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`UPDATE part SET data = ? WHERE id = ?`, string(buf), r.id); err != nil {
			t.Fatal(err)
		}
	}
}

// bumpWallClock walks a part's decoded JSON and bumps every
// volatile field by 60_000 ms. Adds an arbitrary suffix to title.
func bumpWallClock(m map[string]any) {
	if t, ok := m["time"].(map[string]any); ok {
		bumpTime(t)
	}
	if state, ok := m["state"].(map[string]any); ok {
		if t, ok := state["time"].(map[string]any); ok {
			bumpTime(t)
		}
		if title, ok := state["title"].(string); ok {
			state["title"] = title + " (mutated)"
		}
	}
}

func bumpTime(t map[string]any) {
	for _, key := range []string{"start", "end", "created"} {
		if v, ok := t[key].(float64); ok {
			t[key] = v + 60_000
		}
	}
}
