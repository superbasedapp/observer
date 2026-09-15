package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/archive"
	"github.com/marmutapp/superbased-observer/internal/codeintel"
)

// archivedProvider is an otherwise-unavailable code index that reports one
// project as archived — the state an operator lands in when their only indexed
// project has moved to cold storage.
type archivedProvider struct {
	codeintel.Provider
	project string
	marker  archive.Marker
	calls   int
}

func (p *archivedProvider) ArchivedProject(_ context.Context, project string) (archive.Marker, bool, error) {
	p.calls++
	if project == p.project {
		return p.marker, true, nil
	}
	return archive.Marker{}, false, nil
}

// TestArchivedNoteNamesTheDateAndBothRecoveryCommands pins the wording an
// operator (and an agent) actually acts on.
//
// Both commands are named because they are not interchangeable: rehydrate
// replays the verified cold copy and is fast and exact; index re-derives from
// the repository and works even when the cold copy is gone. A message offering
// only one of them would strand the operator in whichever case it omitted.
func TestArchivedNoteNamesTheDateAndBothRecoveryCommands(t *testing.T) {
	t.Parallel()
	// 2026-02-03T00:00:00Z
	note := formatArchivedNote("/repo/cold", 1770076800)
	for _, want := range []string{"2026-02-03", "observer archive rehydrate /repo/cold", "observer index /repo/cold"} {
		if !strings.Contains(note, want) {
			t.Errorf("note is missing %q:\n%s", want, note)
		}
	}
}

// TestArchivedNoteFailsOpen pins the direction the check errs in. A wrong
// "archived" claim is worse than the silence it replaces, so anything short of
// a definite marker hit yields nothing.
func TestArchivedNoteFailsOpen(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	if _, archived := archivedNote(ctx, nil, "/repo/x"); archived {
		t.Error("a nil provider reported a project as archived")
	}
	p := &archivedProvider{Provider: codeintel.Unavailable(), project: "/repo/cold"}
	if _, archived := archivedNote(ctx, p, ""); archived {
		t.Error("an empty project key reported as archived")
	}
	if _, archived := archivedNote(ctx, p, "/repo/never-indexed"); archived {
		t.Error("a never-indexed project reported as archived — the honest-empty " +
			"distinction runs backwards")
	}
	if _, archived := archivedNote(ctx, p, "/repo/cold"); !archived {
		t.Error("an archived project was not recognised")
	}
}

// TestSearchSymbolsDistinguishesArchivedFromEmpty is the P2.3 behaviour under
// test: the same zero-result answer must read differently for a project whose
// index is in cold storage.
func TestSearchSymbolsDistinguishesArchivedFromEmpty(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p := &archivedProvider{
		Provider: codeintel.Unavailable(),
		project:  "/repo/cold",
		marker:   archive.Marker{Project: "/repo/cold", LastIndexedAt: 1770076800, RowsArchived: 42},
	}
	tool := newSearchSymbolsTool(p)

	got, err := tool.Invoke(ctx, json.RawMessage(`{"query":"Handle","project_root":"/repo/cold"}`))
	if err != nil {
		t.Fatalf("archived search: %v", err)
	}
	res, ok := got.(searchSymbolsResult)
	if !ok {
		t.Fatalf("unexpected result type %T", got)
	}
	if !hasWarning(res.Warnings, WarningProjectArchived) {
		t.Errorf("archived project did not carry the %s tag: %+v", WarningProjectArchived, res.Warnings)
	}
	if res.Note == "" {
		t.Error("archived project carried no note — an agent has nothing to act on")
	}

	// The control: a project with no marker must look exactly as it did
	// before this arc, or "no hits" stops meaning "no hits".
	got, err = tool.Invoke(ctx, json.RawMessage(`{"query":"Handle","project_root":"/repo/live"}`))
	if err != nil {
		t.Fatalf("live search: %v", err)
	}
	res, _ = got.(searchSymbolsResult)
	if hasWarning(res.Warnings, WarningProjectArchived) {
		t.Error("a non-archived project was tagged as archived")
	}
	if res.Note != "" {
		t.Errorf("a non-archived project carried a note: %q", res.Note)
	}
}

func hasWarning(warnings []string, tag string) bool {
	for _, w := range warnings {
		if w == tag {
			return true
		}
	}
	return false
}
