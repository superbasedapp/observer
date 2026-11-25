package config

// This file holds the config types of [archive].

// ArchiveConfig is the [archive] block — cold storage for data that is not
// garbage but is no longer part of the hot working set
// (docs/plans/observer-corpus-archival-lazyload-design-2026-08-26.md).
//
// The block is LOCAL-ONLY (like [routing] / [cachewarm] / [codeintel]) and
// entirely additive: an operator who never writes it sees byte-identical
// behaviour, because Enabled defaults to false.
type ArchiveConfig struct {
	// Enabled switches the retention pass's stale-project handling from
	// DELETE to ARCHIVE. Default false.
	//
	// What turning it on changes, precisely: a codeintel project past
	// [codeintel].retention_days is copied to the archive database, verified
	// there, and only then removed from the hot one — instead of being
	// deleted outright, which is what happens today. So enabling it is a
	// strict improvement on the destructiveness axis even before the
	// rehydrate surfaces land.
	//
	// RESTORING an archived project is `observer archive rehydrate <path>`,
	// which replays the verified cold copy back into the hot database and
	// rebuilds the derived search index (shipped in P2 — an earlier version of
	// this comment said restoring meant a full re-index, and that has been
	// false since). The replay is refused, honestly and by name, when the cold
	// copy is missing, incomplete, or was produced by a parser this build no
	// longer accepts; the command then points at `observer index <path>`, the
	// disaster-recovery floor that always works because the code index is
	// derived from the repository on disk.
	//
	// Archived PROCESS capture needs no rehydrate at all: the dashboard reads
	// it straight from cold storage, with nothing copied back.
	//
	// What enabling this does NOT do is shrink the database file. Archived rows
	// leave the hot tables, but SQLite keeps the freed pages on its freelist —
	// turning them back into free disk is `observer archive reclaim`, which is
	// operator-invoked and never automatic.
	Enabled bool `toml:"enabled"`
	// Path is the archive database file. Empty applies
	// ~/.observer/archive.db — a sibling of observer.db, matching the
	// internal/edge/wal precedent of one flat file per subsystem. `~` is
	// expanded at load.
	//
	// It is deliberately a SEPARATE FILE rather than more tables in
	// observer.db: the entire point is that archived data stops being
	// carried on every VACUUM, backup, quick_check and dbstat walk of the
	// hot database.
	Path string `toml:"path"`
	// MaxProjectsPerPass caps how many projects one retention pass moves.
	// Default 8; ≤ 0 applies the default.
	//
	// The cap is not a performance tuning knob so much as an incident guard:
	// an unbounded "drain the whole backlog now" sweep is exactly the
	// loop-until-done shape that made a single retention pass hang the
	// machine for minutes. A capped batch on the ordinary startup + periodic
	// tick converges just as surely.
	MaxProjectsPerPass int `toml:"max_projects_per_pass"`
	// BatchRows bounds one streamed copy batch. Default 512; ≤ 0 applies the
	// default. Keeps a single move's memory proportional to the batch, not to
	// the project.
	BatchRows int `toml:"batch_rows"`
}
