package mcp

import (
	"context"
	"fmt"
	"time"

	"github.com/marmutapp/superbased-observer/internal/codeintel"
)

// This file is P2.3 of the corpus archival arc
// (docs/plans/observer-corpus-archival-lazyload-design-2026-08-26.md §4.2).
//
// THE PROBLEM IT SOLVES. Once a project's code index moves to cold storage,
// every symbol tool answers exactly the same way it answers for a project that
// was never indexed at all: zero results. Those two states call for opposite
// responses — "run `observer index` on this repo, it has never been indexed"
// versus "this index exists, it is one rehydrate away" — and an agent that
// cannot tell them apart will confidently report a project has no symbols when
// it has thousands (memory:feedback_honest_disable_copy).
//
// THE COST BUDGET. The check is ONE indexed primary-key lookup against a table
// with one row per archived project. It runs only when the answer was already
// empty or degraded, so the common path — a hot project with hits — pays
// nothing, and the archive file is never opened by a query path (design §4.4:
// no scoped read may enumerate archived things).

// archivedNote returns the honest in-band explanation for an empty or degraded
// symbol answer, plus true when the project really is archived.
//
// It fails open in the strongest sense: any error, an unavailable provider, or
// an empty project key yields ("", false), which leaves the caller emitting
// exactly the response it emitted before this arc existed. A wrong "archived"
// claim would be worse than the silence it replaces.
func archivedNote(ctx context.Context, cg codeintel.Provider, project string) (string, bool) {
	if cg == nil || project == "" {
		return "", false
	}
	marker, found, err := cg.ArchivedProject(ctx, project)
	if err != nil || !found {
		return "", false
	}
	return formatArchivedNote(project, marker.LastIndexedAt), true
}

// formatArchivedNote renders the operator-facing sentence. Split out so the
// wording is pinned by one test rather than asserted in three tool tests.
//
// It names BOTH recovery commands because they are not interchangeable:
// `observer archive rehydrate` replays the verified cold copy (fast, exact),
// and `observer index` re-derives from the repository (always works, even when
// the cold copy is gone or was written by a parser this build has retired).
func formatArchivedNote(project string, lastIndexedAt int64) string {
	when := "an unknown date"
	if lastIndexedAt > 0 {
		when = time.Unix(lastIndexedAt, 0).UTC().Format("2006-01-02")
	}
	return fmt.Sprintf(
		"this project's code index is archived to cold storage (last indexed %s); "+
			"run `observer archive rehydrate %s` to restore it, or `observer index %s` to rebuild it",
		when, project, project,
	)
}
