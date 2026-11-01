package kilocode

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// TestParseSessionFile_CLINotReadyStore pins that a kilo.db without the
// core tables (a store Kilo is still bootstrapping, or a future storage
// generation like OpenCode 2.x's session_v2) is a quiet no-op that warns
// once per file, never a "no such table" error on every scan.
func TestParseSessionFile_CLINotReadyStore(t *testing.T) {
	tests := []struct {
		name   string
		tables []string
	}{
		{"empty database", nil},
		{"opencode 2.x style tables only", []string{
			`CREATE TABLE session_v2 (id text PRIMARY KEY, time_updated integer NOT NULL)`,
			`CREATE TABLE session_message (id text PRIMARY KEY, session_id text NOT NULL, time_updated integer NOT NULL, data text NOT NULL)`,
		}},
		{"message and part without session", []string{
			`CREATE TABLE message (id TEXT PRIMARY KEY, time_updated INTEGER NOT NULL)`,
			`CREATE TABLE part (id TEXT PRIMARY KEY, time_updated INTEGER NOT NULL)`,
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, "kilo.db")
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
			t.Cleanup(func() { adapter.ClearNotReady(models.ToolKiloCodeCLI, path) })

			a := NewCLIWithOptions(nil, []string{root})
			for i, want := range []int{1, 0} {
				res, err := a.ParseSessionFile(context.Background(), path, 5)
				if err != nil {
					t.Fatalf("parse %d: %v (missing tables must not be an error)", i, err)
				}
				if res.NewOffset != 5 || len(res.Warnings) != want {
					t.Errorf("parse %d: offset=%d warnings=%v, want 5 and %d warning(s)", i, res.NewOffset, res.Warnings, want)
				}
			}
		})
	}
}
