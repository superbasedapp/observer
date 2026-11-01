package opencode

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
)

// v2CacheRows is a synthetic Anthropic-routed 2.x session: a prompt and
// two assistant steps with usage, then a step still streaming (no usage)
// and a compaction (never observed).
var v2CacheRows = []string{
	`INSERT INTO session_v2 (id, project_id, slug, directory, version, time_created, time_updated)
		VALUES ('ses_c', 'global', 'cache-run', '/tmp/oc2', '2.1.1', 1000, 6000)`,
	`INSERT INTO session_message (id, session_id, type, seq, time_created, time_updated, data) VALUES
		('m_u1', 'ses_c', 'user', 1, 1000, 1000, '{"time":{"created":1000},"text":"Synthetic prompt"}'),
		('m_a1', 'ses_c', 'assistant', 2, 2000, 2600,
		 '{"time":{"created":2000,"completed":2600},"model":{"id":"claude-sonnet-4","providerID":"anthropic"},"content":[{"type":"reasoning","text":"plan","time":{"created":2001}},{"type":"tool","id":"call_1","name":"read","state":{"status":"completed","input":{"path":"a.go"},"content":[{"type":"text","text":"package a"}]},"time":{"created":2100,"ran":2200,"completed":2250}}],"finish":"tool-calls","tokens":{"input":900,"output":20,"reasoning":0,"cache":{"read":0,"write":4000}}}'),
		('m_a2', 'ses_c', 'assistant', 3, 3000, 3600,
		 '{"time":{"created":3000,"completed":3600},"model":{"id":"claude-sonnet-4","providerID":"anthropic"},"content":[{"type":"text","text":"Done."}],"finish":"stop","tokens":{"input":30,"output":5,"reasoning":0,"cache":{"read":4000,"write":0}}}'),
		('m_a3', 'ses_c', 'assistant', 4, 4000, 4100,
		 '{"time":{"created":4000},"model":{"id":"claude-sonnet-4","providerID":"anthropic"},"content":[{"type":"text","text":"partial"}]}'),
		('m_c1', 'ses_c', 'compaction', 5, 5000, 6000,
		 '{"time":{"created":5000},"status":"completed","summary":"s","model":{"id":"claude-sonnet-4","providerID":"anthropic"},"tokens":{"input":300,"output":30,"reasoning":0,"cache":{"read":0,"write":0}}}')`,
}

// TestCacheObservations_V2 pins T-925: an OpenCode 2.x store yields one
// Tier-2 observation per assistant step with usage, with a cumulative
// per-session block chain, and nothing again past the cursor.
func TestCacheObservations_V2(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "opencode.db")
	createDB(t, path, v2DDL, v2CacheRows)

	a := NewWithOptions(nil, []string{root})
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if got := len(res.CacheObservations); got != 2 {
		t.Fatalf("CacheObservations = %d, want 2 (two steps with usage; streaming step and compaction excluded)", got)
	}
	first, second := res.CacheObservations[0], res.CacheObservations[1]
	if first.MessageID != "m_a1" || second.MessageID != "m_a2" {
		t.Fatalf("message ids = %q, %q", first.MessageID, second.MessageID)
	}
	if first.SessionID != "ses_c" || first.Model != "claude-sonnet-4" || first.SourceFile != path {
		t.Errorf("first obs = %+v", first)
	}
	// Each observation carries the blocks since the previous step:
	// prompt + reasoning + tool = 3, then the text = 1.
	if len(first.BlockHashes) != 3 || len(second.BlockHashes) != 1 {
		t.Errorf("block counts = %d, %d, want 3, 1", len(first.BlockHashes), len(second.BlockHashes))
	}
	if first.Usage.CacheCreationTokens != 4000 || first.Usage.NetInputTokens != 900 {
		t.Errorf("first usage = %+v", first.Usage)
	}
	if second.Usage.CacheReadTokens != 4000 || second.Usage.OutputTokens != 5 {
		t.Errorf("second usage = %+v", second.Usage)
	}

	again, err := a.ParseSessionFile(context.Background(), path, res.NewOffset)
	if err != nil {
		t.Fatal(err)
	}
	if len(again.CacheObservations) != 0 {
		t.Errorf("re-parse past the cursor emitted %d observations", len(again.CacheObservations))
	}

	// A step written after the completed compaction: an incremental parse
	// emits it alone, with only its own block (the earlier steps' deltas
	// are closed, the compaction reset the chain) and CompactionSeen set.
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO session_message (id, session_id, type, seq, time_created, time_updated, data) VALUES
		('m_a4', 'ses_c', 'assistant', 6, 7000, 7100,
		 '{"time":{"created":7000,"completed":7100},"model":{"id":"claude-sonnet-4","providerID":"anthropic"},"content":[{"type":"text","text":"More."}],"finish":"stop","tokens":{"input":10,"output":3,"reasoning":0,"cache":{"read":0,"write":500}}}')`); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	later, err := a.ParseSessionFile(context.Background(), path, res.NewOffset)
	if err != nil {
		t.Fatal(err)
	}
	if len(later.CacheObservations) != 1 {
		t.Fatalf("incremental observations = %d, want 1", len(later.CacheObservations))
	}
	if obs := later.CacheObservations[0]; obs.MessageID != "m_a4" || len(obs.BlockHashes) != 1 || !obs.CompactionSeen {
		t.Errorf("incremental obs = id %q blocks %d compaction %v, want m_a4, 1, true", obs.MessageID, len(obs.BlockHashes), obs.CompactionSeen)
	}
}

// TestCacheObservationsV2_BesideV1EmitsOnlyOwnedSteps: in an upgraded
// database a step whose id is still in the 1.x `message` table belongs to
// the 1.x emitter; the 2.x path still observes it (chain continuity) but
// emits only the steps written after the upgrade.
func TestCacheObservationsV2_BesideV1EmitsOnlyOwnedSteps(t *testing.T) {
	path := filepath.Join(t.TempDir(), "opencode.db")
	createDB(t, path, v2DDL, v2CacheRows, []string{
		`CREATE TABLE message (id text PRIMARY KEY)`,
		`INSERT INTO message (id) VALUES ('m_u1'), ('m_a1')`,
	})
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	a := NewWithOptions(nil, nil)
	obs, err := a.loadCacheObservationsV2(context.Background(), db, path, 0, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(obs) != 1 || obs[0].MessageID != "m_a2" {
		t.Fatalf("observations = %+v, want only m_a2", obs)
	}
	if len(obs[0].BlockHashes) != 1 {
		t.Errorf("m_a2 blocks = %d, want 1 (m_a1's delta belongs to the 1.x emitter)", len(obs[0].BlockHashes))
	}
}
