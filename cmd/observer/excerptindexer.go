package main

import (
	"database/sql"

	"github.com/marmutapp/superbased-observer/internal/compression/indexing"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// excerptIndexer is the ONE place this binary resolves
// [compression.indexing].enabled for a writer of action_excerpts (T-420).
// The watcher (observer start) and every hook process that captures tool
// output build their indexer here, so the switch governs both writers the
// same way: off means nil, and a nil indexer leaves every capture write in
// place and skips only the FTS5 excerpt insert.
//
// Before this seam the hook processes built an indexer unconditionally, so a
// node that turned indexing off still grew action_excerpts from every
// cursor postToolUse / stop event while the watcher wrote nothing.
//
// It is resolved once where the caller builds its store, never per action.
func excerptIndexer(database *sql.DB, c config.IndexingConfig) *indexing.Indexer {
	if !c.Enabled {
		return nil
	}
	return indexing.New(database, c.MaxExcerptBytes)
}

// hookCaptureStore is the Store a hook process captures through: the hook
// ingest store (hookIngestStore, its root resolver wired) bound to the
// excerpt indexer the switch allows (excerptIndexer).
// Every hook capture site builds its store here.
func hookCaptureStore(database *sql.DB, c config.IndexingConfig) *store.Store {
	return hookIngestStore(database).WithIndexer(excerptIndexer(database, c))
}
