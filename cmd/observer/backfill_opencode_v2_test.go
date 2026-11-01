package main

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
)

// TestBackfillOpenCodeParts_SkipsV2Store pins T-928: `observer backfill
// --opencode-parts` reads the 1.x part table only. An OpenCode 2.x store
// (session_message, no part) is counted as skipped, not silently zero,
// and nothing is touched.
func TestBackfillOpenCodeParts_SkipsV2Store(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(root, "obs.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	ocDBPath := filepath.Join(root, "opencode-stable.db")
	for _, s := range []string{
		`INSERT INTO projects (id, root_path, created_at) VALUES (1, '/tmp/test', '2026-10-20T00:00:00Z')`,
		`INSERT INTO sessions (id, tool, started_at, project_id) VALUES ('s1', 'opencode', '2026-10-20T00:00:00Z', 1)`,
	} {
		if _, err := database.ExecContext(ctx, s); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := database.ExecContext(ctx,
		`INSERT INTO actions (session_id, project_id, timestamp, action_type, raw_tool_name, target, tool, source_file, source_event_id)
		 VALUES ('s1', 1, '2026-10-20T00:00:01Z', 'read_file', 'read', 'a.go', 'opencode', ?, 'tool:m1:c1')`, ocDBPath); err != nil {
		t.Fatal(err)
	}
	oc, err := sql.Open("sqlite", ocDBPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := oc.Exec(`CREATE TABLE session_message (id text PRIMARY KEY, session_id text NOT NULL, type text NOT NULL, seq integer NOT NULL, time_created integer NOT NULL, time_updated integer NOT NULL, data text NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	_ = oc.Close()

	res, err := backfillOpenCodeParts(ctx, database)
	if err != nil {
		t.Fatalf("backfillOpenCodeParts: %v", err)
	}
	if res.V2StoresSkipped != 1 || res.PartsExamined != 0 {
		t.Errorf("result = %+v, want one 2.x store skipped and no parts examined", res)
	}
}
