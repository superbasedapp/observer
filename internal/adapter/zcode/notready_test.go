package zcode

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// TestParseSessionFile_NotReadyStore pins that a db.sqlite without the
// core tables is a quiet no-op that warns once per file, and that a
// store without model_usage still parses (the old single-statement
// watermark failed with "no such table: model_usage").
func TestParseSessionFile_NotReadyStore(t *testing.T) {
	tests := []struct {
		name      string
		tables    []string
		wantReady bool
	}{
		{"empty database", nil, false},
		{"core tables without model_usage", []string{
			`CREATE TABLE session (id TEXT PRIMARY KEY, directory TEXT NOT NULL DEFAULT '', time_updated INTEGER NOT NULL)`,
			`CREATE TABLE message (id TEXT PRIMARY KEY, session_id TEXT NOT NULL, time_created INTEGER NOT NULL, time_updated INTEGER NOT NULL, data TEXT NOT NULL)`,
			`CREATE TABLE part (id TEXT PRIMARY KEY, message_id TEXT NOT NULL, session_id TEXT NOT NULL, time_created INTEGER NOT NULL, time_updated INTEGER NOT NULL, data TEXT NOT NULL)`,
			`INSERT INTO session (id, time_updated) VALUES ('s1', 77)`,
		}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, "db.sqlite")
			db, err := sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec(`CREATE TABLE kv (k text)`); err != nil {
				t.Fatal(err)
			}
			for _, stmt := range tt.tables {
				if _, err := db.Exec(stmt); err != nil {
					t.Fatal(err)
				}
			}
			_ = db.Close()
			t.Cleanup(func() { adapter.ClearNotReady(models.ToolZcode, path) })

			a := NewWithOptions(nil, []string{root})
			res, err := a.ParseSessionFile(context.Background(), path, 5)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if tt.wantReady {
				if res.NewOffset != 77 || len(res.Warnings) != 0 {
					t.Errorf("offset=%d warnings=%v, want 77 and none", res.NewOffset, res.Warnings)
				}
				return
			}
			if res.NewOffset != 5 || len(res.Warnings) != 1 {
				t.Errorf("offset=%d warnings=%v, want 5 and one warning", res.NewOffset, res.Warnings)
			}
			again, err := a.ParseSessionFile(context.Background(), path, 5)
			if err != nil || len(again.Warnings) != 0 {
				t.Errorf("second parse: err=%v warnings=%v, want quiet", err, again.Warnings)
			}
		})
	}
}
