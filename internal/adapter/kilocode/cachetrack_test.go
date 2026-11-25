package kilocode

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

// TestCLIAdapter_CacheObservations_Anthropic_Shape pins the §14.3
// kilo-cli Tier-2 emission: one assistant turn with the full
// Anthropic-shape cache bundle (cache.read + cache.write) emits
// exactly one observation, with the ordered parts folded into
// BlockHashes minus step-finish.
func TestCLIAdapter_CacheObservations_Anthropic_Shape(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "kilo.db")
	setupCLIDBForCachetrack(t, path)

	a := NewCLIWithOptions(nil, []string{root})
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if got := len(res.CacheObservations); got != 1 {
		t.Fatalf("CacheObservations = %d, want 1", got)
	}
	obs := res.CacheObservations[0]
	if obs.MessageID != "msg_assist" {
		t.Errorf("MessageID = %q, want msg_assist", obs.MessageID)
	}
	if obs.SourceEventID != "cachetrack:msg_assist" {
		t.Errorf("SourceEventID = %q, want cachetrack:msg_assist", obs.SourceEventID)
	}
	if obs.Model != "kilo-auto" {
		t.Errorf("Model = %q, want kilo-auto", obs.Model)
	}
	if obs.Usage.CacheReadTokens != 45696 {
		t.Errorf("CacheReadTokens = %d, want 45696", obs.Usage.CacheReadTokens)
	}
	if obs.Usage.CacheCreationTokens != 2048 {
		t.Errorf("CacheCreationTokens = %d, want 2048", obs.Usage.CacheCreationTokens)
	}
	if obs.Usage.NetInputTokens != 368 {
		t.Errorf("NetInputTokens = %d, want 368", obs.Usage.NetInputTokens)
	}
	// User prompt (1 text part) + assistant (1 tool + 1 reasoning +
	// 1 text) = 4 blocks. step-finish excluded by design.
	if got := len(obs.BlockHashes); got != 4 {
		t.Fatalf("BlockHashes = %d, want 4", got)
	}
}

// TestCLIAdapter_CacheObservations_VolatileExclusion_R3 pins the
// volatile-element exclusion strategy from the audit
// (docs/audits/cachetrack-kilo-cli-tier2-audit-2026-06-09.md):
// wall-clock fields inside tool/reasoning/subtask part bodies
// (state.time.{start,end}, state.title, time.{start,end},
// time.created) must NEVER appear in CanonicalBytes. Two parses
// with the volatile fields mutated between them must produce
// byte-identical CanonicalBytes block-by-block.
func TestCLIAdapter_CacheObservations_VolatileExclusion_R3(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "kilo.db")
	setupCLIDBForCachetrack(t, path)

	a := NewCLIWithOptions(nil, []string{root})
	first, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("first parse: %v", err)
	}
	if len(first.CacheObservations) == 0 {
		t.Fatal("expected at least one CacheObservation")
	}

	mutateCLIVolatileFields(t, path)
	mutated, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("mutated parse: %v", err)
	}
	if len(mutated.CacheObservations) == 0 {
		t.Fatal("expected at least one CacheObservation after mutation")
	}
	for i := range first.CacheObservations[0].BlockHashes {
		a := first.CacheObservations[0].BlockHashes[i].CanonicalBytes
		b := mutated.CacheObservations[0].BlockHashes[i].CanonicalBytes
		if !bytes.Equal(a, b) {
			t.Fatalf("R3 BROKEN: block %d differs after mutating volatile fields\n  pre:  %s\n  post: %s\n(a volatile field slipped past the audit's exclusion list — re-read docs/audits/cachetrack-kilo-cli-tier2-audit-2026-06-09.md and add the field to marshalCanonicalPartTier2's struct exclusions)", i, a, b)
		}
	}
}

// TestCLIAdapter_CacheObservations_Idempotent pins the cross-tier
// idempotency contract: re-parsing the same DB from offset 0
// twice produces the same observation set with byte-identical
// canonical bytes.
func TestCLIAdapter_CacheObservations_Idempotent(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "kilo.db")
	setupCLIDBForCachetrack(t, path)

	a := NewCLIWithOptions(nil, []string{root})
	first, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("first parse: %v", err)
	}
	second, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("second parse: %v", err)
	}
	if len(first.CacheObservations) != len(second.CacheObservations) {
		t.Fatalf("count drift: %d vs %d", len(first.CacheObservations), len(second.CacheObservations))
	}
	for i := range first.CacheObservations {
		if first.CacheObservations[i].SourceEventID != second.CacheObservations[i].SourceEventID {
			t.Errorf("obs[%d] SourceEventID drift", i)
		}
		for j := range first.CacheObservations[i].BlockHashes {
			a := first.CacheObservations[i].BlockHashes[j].CanonicalBytes
			b := second.CacheObservations[i].BlockHashes[j].CanonicalBytes
			if !bytes.Equal(a, b) {
				t.Errorf("obs[%d] block[%d] canonical bytes drift\n  first:  %s\n  second: %s", i, j, a, b)
			}
		}
	}
}

func setupCLIDBForCachetrack(t *testing.T, path string) {
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
		`CREATE TABLE project (id TEXT PRIMARY KEY, worktree TEXT NOT NULL, time_updated INTEGER NOT NULL, sandboxes TEXT NOT NULL DEFAULT '[]')`,
		`CREATE TABLE session (id TEXT PRIMARY KEY, project_id TEXT NOT NULL, directory TEXT NOT NULL, time_updated INTEGER NOT NULL)`,
		`CREATE TABLE message (id TEXT PRIMARY KEY, session_id TEXT NOT NULL, time_created INTEGER NOT NULL, time_updated INTEGER NOT NULL, data TEXT NOT NULL)`,
		`CREATE TABLE part (id TEXT PRIMARY KEY, message_id TEXT NOT NULL, session_id TEXT NOT NULL, time_created INTEGER NOT NULL, time_updated INTEGER NOT NULL, data TEXT NOT NULL)`,
		`INSERT INTO project(id, worktree, time_updated) VALUES ('proj_a', '/tmp/kilo-test', 1000)`,
		`INSERT INTO session(id, project_id, directory, time_updated) VALUES ('ses_1', 'proj_a', '/tmp/kilo-test', 9000)`,
		// Token bundle: numbers mirror the §14.3 audit's reference
		// assistant turn (Gateway-routed kilo-auto with cache hit AND
		// cold write — 45696 read + 2048 write).
		`INSERT INTO message(id, session_id, time_created, time_updated, data) VALUES
			('msg_user',   'ses_1', 1000, 1001,
			 '{"role":"user","agent":"code","model":{"providerID":"kilo","modelID":"kilo-auto"},"time":{"created":1000}}'),
			('msg_assist', 'ses_1', 2000, 9000,
			 '{"parentID":"msg_user","role":"assistant","mode":"code","agent":"code","path":{"cwd":"/tmp/kilo-test","root":"/tmp/kilo-test"},"modelID":"kilo-auto","providerID":"kilo","time":{"created":2000,"completed":9000},"finish":"stop","tokens":{"total":48211,"input":368,"output":49,"reasoning":98,"cache":{"read":45696,"write":2048}},"cost":0.0211}')`,
		`INSERT INTO part(id, message_id, session_id, time_created, time_updated, data) VALUES
			('prt_u',     'msg_user',   'ses_1', 1000, 1001,
			 '{"type":"text","text":"Cache me if you can"}'),
			('prt_tool',  'msg_assist', 'ses_1', 2100, 2300,
			 '{"type":"tool","tool":"bash","callID":"c_bash","state":{"status":"completed","input":{"command":"ls","workdir":"/tmp/kilo-test"},"output":"a\nb\n","metadata":{"output":"a\nb\n","exit":0,"description":"ls","truncated":false},"title":"Run @ 2:30 PM","time":{"start":2100,"end":2300}},"metadata":{"openrouter":{"reasoning_details":[{"type":"text","text":"intermediate","format":"plain","index":0}]}}}'),
			('prt_think', 'msg_assist', 'ses_1', 2300, 2350,
			 '{"type":"reasoning","text":"Thinking about it","time":{"start":2300,"end":2350}}'),
			('prt_text',  'msg_assist', 'ses_1', 2400, 2450,
			 '{"type":"text","text":"All green."}'),
			('prt_step',  'msg_assist', 'ses_1', 2500, 2550,
			 '{"type":"step-finish","reason":"stop","tokens":{"total":48211,"input":368,"output":49,"reasoning":98,"cache":{"read":45696,"write":2048}},"cost":0.0211}')`,
	}
	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("exec %q: %v", stmt, err)
		}
	}
}

func mutateCLIVolatileFields(t *testing.T, path string) {
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
		bumpCLIWallClock(m)
		buf, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`UPDATE part SET data = ? WHERE id = ?`, string(buf), r.id); err != nil {
			t.Fatal(err)
		}
	}
}

func bumpCLIWallClock(m map[string]any) {
	if t, ok := m["time"].(map[string]any); ok {
		bumpCLITime(t)
	}
	if state, ok := m["state"].(map[string]any); ok {
		if t, ok := state["time"].(map[string]any); ok {
			bumpCLITime(t)
		}
		if title, ok := state["title"].(string); ok {
			state["title"] = title + " (mutated)"
		}
	}
}

func bumpCLITime(t map[string]any) {
	for _, key := range []string{"start", "end", "created"} {
		if v, ok := t[key].(float64); ok {
			t[key] = v + 60_000
		}
	}
}

// TestCLIAdapter_CacheObservations_IncrementalClosesEmittedDeltas pins
// CAPTURE-01 (opencode's T-930 ported to kilo-code CLI): an incremental parse
// replays the session from its first message to keep the chain complete, but a
// step an earlier parse already emitted must close its delta without emitting,
// so the first new step carries only the blocks written since that step (here
// the new prompt and the new reply), not the session's older blocks again.
// Each block is observed once across the two parses.
func TestCLIAdapter_CacheObservations_IncrementalClosesEmittedDeltas(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "kilo.db")
	setupCLIDBForCachetrack(t, path)

	a := NewCLIWithOptions(nil, []string{root})
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
			('msg_user2',   'ses_1', 10000, 10001,
			 '{"role":"user","agent":"code","model":{"providerID":"kilo","modelID":"kilo-auto"},"time":{"created":10000}}'),
			('msg_assist2', 'ses_1', 11000, 11500,
			 '{"parentID":"msg_user2","role":"assistant","mode":"code","agent":"code","path":{"cwd":"/tmp/kilo-test","root":"/tmp/kilo-test"},"modelID":"kilo-auto","providerID":"kilo","time":{"created":11000,"completed":11500},"finish":"stop","tokens":{"total":5214,"input":20,"output":10,"reasoning":0,"cache":{"read":5120,"write":64}},"cost":0.001}')`,
		`INSERT INTO part(id, message_id, session_id, time_created, time_updated, data) VALUES
			('prt_u2', 'msg_user2',   'ses_1', 10000, 10001, '{"type":"text","text":"And again"}'),
			('prt_t2', 'msg_assist2', 'ses_1', 11100, 11200, '{"type":"text","text":"Still green."}')`,
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
	seen := map[string]bool{}
	for _, b := range first.CacheObservations[0].BlockHashes {
		seen[b.Kind+"\x00"+string(b.CanonicalBytes)] = true
	}
	for _, b := range obs.BlockHashes {
		if seen[b.Kind+"\x00"+string(b.CanonicalBytes)] {
			t.Errorf("block %s %s was observed by both parses", b.Kind, b.CanonicalBytes)
		}
	}
}

// TestCLIAdapter_CacheObservations_IncrementalKeepsUnemittedStepBlocks pins
// the other half of the T-930 contract: an assistant step the earlier parse
// did NOT emit (zero tokens, still streaming) closes no delta, so its blocks
// ride on the first emitted step of the next parse instead of being lost.
func TestCLIAdapter_CacheObservations_IncrementalKeepsUnemittedStepBlocks(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "kilo.db")
	setupCLIDBForCachetrack(t, path)

	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO message(id, session_id, time_created, time_updated, data) VALUES
		('msg_user2',   'ses_1', 9100, 9101,
		 '{"role":"user","agent":"code","model":{"providerID":"kilo","modelID":"kilo-auto"},"time":{"created":9100}}'),
		('msg_assist2', 'ses_1', 9200, 9300,
		 '{"parentID":"msg_user2","role":"assistant","agent":"code","modelID":"kilo-auto","providerID":"kilo","time":{"created":9200},"tokens":{"total":0,"input":0,"output":0,"reasoning":0,"cache":{"read":0,"write":0}}}')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO part(id, message_id, session_id, time_created, time_updated, data) VALUES
		('prt_u2', 'msg_user2',   'ses_1', 9100, 9101, '{"type":"text","text":"And again"}'),
		('prt_t2', 'msg_assist2', 'ses_1', 9250, 9260, '{"type":"text","text":"Working"}')`); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()

	a := NewCLIWithOptions(nil, []string{root})
	first, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("first parse: %v", err)
	}
	if len(first.CacheObservations) != 1 {
		t.Fatalf("first parse = %d observations, want 1 (the streaming step has no tokens)", len(first.CacheObservations))
	}

	db, err = sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	// The streaming step completes, with tokens, after the first parse.
	if _, err := db.Exec(`UPDATE message SET time_updated = 12000, data =
		'{"parentID":"msg_user2","role":"assistant","agent":"code","modelID":"kilo-auto","providerID":"kilo","time":{"created":9200,"completed":12000},"finish":"stop","tokens":{"total":5214,"input":20,"output":10,"reasoning":0,"cache":{"read":5120,"write":64}}}'
		WHERE id = 'msg_assist2'`); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()

	later, err := a.ParseSessionFile(context.Background(), path, first.NewOffset)
	if err != nil {
		t.Fatalf("incremental parse: %v", err)
	}
	if len(later.CacheObservations) != 1 {
		t.Fatalf("incremental observations = %d, want 1", len(later.CacheObservations))
	}
	if got := len(later.CacheObservations[0].BlockHashes); got != 2 {
		t.Errorf("BlockHashes = %d, want 2 (the step's own prompt + reply, never emitted before)", got)
	}
}
