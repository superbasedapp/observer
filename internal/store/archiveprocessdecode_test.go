package store

import (
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/archive"
)

// The decoder is the P3.5 direct-read last mile: archived driver values back
// into the SAME ProcessRunRow the hot read path produces. These tests pin its
// two documented contracts — decode BY NAME (column order must not matter) and
// forward/backward tolerance (unknown columns ignored, absent columns zero) —
// plus the Exited derivation the hot path also performs.
func TestDecodeArchivedProcessRuns_ByNameNotPosition(t *testing.T) {
	started := time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC)
	exited := started.Add(90 * time.Second)
	batch := archive.RowBatch{
		Table: "process_runs",
		// Deliberately NOT the hot table's column order, with an unknown
		// future column mixed in mid-list.
		Cols: []string{
			"exe_basename", "some_future_column", "pid", "process_key",
			"started_at", "exited_at", "exit_code", "action_id",
			"max_rss_bytes", "thread_count",
		},
		Vals: [][]any{
			{
				"go", "ignored", int64(4321), "boot1:4321:77",
				started.Format(time.RFC3339Nano), exited.Format(time.RFC3339Nano),
				int64(2), int64(99),
				int64(1 << 20), int64(7),
			},
		},
	}

	rows, err := DecodeArchivedProcessRuns(batch)
	if err != nil {
		t.Fatalf("DecodeArchivedProcessRuns: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(rows))
	}
	r := rows[0]
	if r.ExeBasename != "go" || r.PID != 4321 || r.ProcessKey != "boot1:4321:77" {
		t.Fatalf("identity fields misdecoded: %+v", r)
	}
	if !r.StartedAt.Equal(started) || !r.ExitedAt.Equal(exited) {
		t.Fatalf("timestamps misdecoded: started %v exited %v", r.StartedAt, r.ExitedAt)
	}
	if r.ExitCode != 2 || r.MaxRSSBytes != 1<<20 || r.ThreadCount != 7 {
		t.Fatalf("metrics misdecoded: %+v", r)
	}
	if r.ActionID == nil || *r.ActionID != 99 {
		t.Fatalf("nullable action_id misdecoded: %v", r.ActionID)
	}
	if !r.Exited {
		t.Fatal("Exited must derive from a non-zero exited_at, as on the hot path")
	}
}

func TestDecodeArchivedProcessRuns_AbsentColumnsStayZero(t *testing.T) {
	// A row archived before a later ALTER TABLE simply lacks the new columns:
	// they must decode to zero values, and a NULL nullable stays nil.
	batch := archive.RowBatch{
		Table: "process_runs",
		Cols:  []string{"process_key", "pid", "action_id", "exited_at"},
		Vals:  [][]any{{"boot1:1:1", int64(1), nil, nil}},
	}
	rows, err := DecodeArchivedProcessRuns(batch)
	if err != nil {
		t.Fatalf("DecodeArchivedProcessRuns: %v", err)
	}
	r := rows[0]
	if r.ActionID != nil {
		t.Fatalf("NULL action_id must stay nil, got %v", *r.ActionID)
	}
	if r.Exited || !r.ExitedAt.IsZero() {
		t.Fatal("absent/NULL exited_at must leave the run un-exited")
	}
	if r.ExeBasename != "" || r.CPUUserMs != 0 {
		t.Fatalf("absent columns must stay zero: %+v", r)
	}
}

func TestDecodeArchivedProcessRuns_RefusesForeignTable(t *testing.T) {
	_, err := DecodeArchivedProcessRuns(archive.RowBatch{Table: "process_events"})
	if err == nil {
		t.Fatal("a non-process_runs batch must be refused, not silently mis-decoded")
	}
}
