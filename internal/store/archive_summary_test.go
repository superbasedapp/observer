package store

import (
	"context"
	"fmt"
	"testing"
)

// TestArchivedSummaryCountsBeyondTheListerCap is the honesty proof on the P5.1
// aggregate storage surface.
//
// The marker LISTERS (CodeIntelArchivedProjects, ProcessArchivedWindows) exist
// to render a table, so they cap their result — 500 projects and 100 day
// windows. Summing them to produce a total would silently under-report a larger
// archive: the surface would say "487 projects" forever and never say it had
// stopped counting. ArchivedSummary is a separate COUNT/SUM seam for exactly
// that reason.
//
// This test writes MORE markers than either cap and asserts the aggregate sees
// all of them.
//
// Mutation proof: reimplement ArchivedSummary as a fold over
// CodeIntelArchivedProjects(ctx, 0) / ProcessArchivedWindows(ctx, 0) and it
// fails with "CodeIntelProjects = 500, want 520".
func TestArchivedSummaryCountsBeyondTheListerCap(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, _ := newTestStore(t)

	const (
		projects = 520 // > the 500-project lister cap
		windows  = 130 // > the 100-window lister cap
	)
	for i := range projects {
		if _, err := s.db.ExecContext(ctx,
			`INSERT INTO codeintel_archived_projects (project, archived_at, last_indexed_at, rows_archived)
			 VALUES (?, ?, ?, ?)`,
			fmt.Sprintf("/repo/p%03d", i), 1000+i, 900+i, 10); err != nil {
			t.Fatalf("insert project marker %d: %v", i, err)
		}
	}
	for i := range windows {
		if _, err := s.db.ExecContext(ctx,
			`INSERT INTO process_archived_windows (day, archived_at, runs, events, bodies)
			 VALUES (?, ?, ?, ?, ?)`,
			fmt.Sprintf("2026-%02d-%02d", 1+i/28, 1+i%28), 2000+i, 3, 4, 5); err != nil {
			t.Fatalf("insert window marker %d: %v", i, err)
		}
	}

	got, err := s.ArchivedSummary(ctx)
	if err != nil {
		t.Fatalf("ArchivedSummary: %v", err)
	}
	want := ArchivedSummary{
		CodeIntelProjects: projects,
		CodeIntelRows:     projects * 10,
		ProcessWindows:    windows,
		ProcessRows:       windows * (3 + 4 + 5),
	}
	if got != want {
		t.Errorf("ArchivedSummary = %+v, want %+v — the aggregate must not inherit the listers' caps", got, want)
	}

	// And the listers really are capped, so the property above is not vacuous.
	list, err := s.CodeIntelArchivedProjects(ctx, 0)
	if err != nil {
		t.Fatalf("CodeIntelArchivedProjects: %v", err)
	}
	if len(list) >= projects {
		t.Fatalf("the project lister returned %d of %d rows — it is no longer capped, so this test proves nothing; "+
			"re-check whether ArchivedSummary still needs to be a separate seam", len(list), projects)
	}
}

// TestArchivedSummaryEmpty pins the zero case: an install that has never
// archived anything reports zeros, not an error and not a NULL scan failure
// (the COALESCE around SUM is what makes that true).
func TestArchivedSummaryEmpty(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	got, err := s.ArchivedSummary(context.Background())
	if err != nil {
		t.Fatalf("ArchivedSummary on an empty archive: %v", err)
	}
	if (got != ArchivedSummary{}) {
		t.Errorf("ArchivedSummary = %+v, want all zeros", got)
	}
}
