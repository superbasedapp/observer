package main

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
)

// TestControlCoverageRouteProofCountsObservedSurfaces is AW-48 end to end on
// the doctor line: a node with no Codex session at all shows the registry
// proof and says so (never "proven" on the strength of nothing); with Codex
// CLI sessions and no Xcode session the line keeps "route proven" and names
// ide/xcode as not observed on this node; one session stamped ide/xcode
// flips it to "route unproven".
func TestControlCoverageRouteProofCountsObservedSurfaces(t *testing.T) {
	ctx := context.Background()
	database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "obs.db")})
	if err != nil {
		t.Fatalf("db open: %v", err)
	}
	defer func() { _ = database.Close() }()
	empty, _ := controlCoverageLineObserved(ctx, database, "codex")
	if !strings.Contains(empty, "route proof from the registry: no session of this tool on this node") ||
		!strings.Contains(empty, "route proof skips ide/xcode: no adapter captures it yet") {
		t.Fatalf("no codex session: line %q, want the registry proof with its reason", empty)
	}
	for _, q := range []string{
		`INSERT INTO projects (id, root_path, created_at) VALUES (1, '/repo', '2026-10-28T00:00:00Z')`,
		`INSERT INTO sessions (id, tool, started_at, project_id, surface, surface_host) VALUES ('c1', 'codex', '2026-10-28T01:00:00Z', 1, 'cli', 'codex-cli')`,
	} {
		if _, err := database.ExecContext(ctx, q); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	line, ok := controlCoverageLineObserved(ctx, database, "codex")
	if !ok || !strings.Contains(line, "(route proven)") || !strings.Contains(line, "ide/xcode") || !strings.Contains(line, "no sessions observed on this node") {
		t.Fatalf("no xcode session: line %q, want route proven and ide/xcode named as not observed", line)
	}
	if _, err := database.ExecContext(ctx,
		`INSERT INTO sessions (id, tool, started_at, project_id, surface, surface_host) VALUES ('x1', 'codex', '2026-10-28T02:00:00Z', 1, 'ide', 'xcode')`); err != nil {
		t.Fatalf("seed xcode: %v", err)
	}
	line, _ = controlCoverageLineObserved(ctx, database, "codex")
	if !strings.Contains(line, "(route unproven)") {
		t.Fatalf("one xcode session: line %q, want route unproven", line)
	}
	if strings.Contains(line, "skips ide/xcode") {
		t.Errorf("one xcode session: line %q still names ide/xcode as skipped", line)
	}
	// No database: the registry view (only NoProducer surfaces skipped).
	reg, _ := controlCoverageLineObserved(ctx, nil, "codex")
	if !strings.Contains(reg, "(route proven)") || !strings.Contains(reg, "route proof skips ide/xcode: no adapter captures it yet") {
		t.Errorf("registry view: %q", reg)
	}
}
