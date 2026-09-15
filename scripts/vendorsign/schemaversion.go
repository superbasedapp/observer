package main

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/db/migrations"
)

// schemaversion.go answers ONE question at release time: what agent database
// schema does the binary in this release carry?
//
// The manifest field it feeds is not decoration. A node reads schema_version
// to decide whether an apply CROSSES A MIGRATION, and therefore whether it
// must take a `VACUUM INTO` snapshot of its database before swapping the
// binary. Zero means unknown, and unknown is treated as "may advance" — the
// safe direction, but it makes every node on every apply copy a database that
// can be tens of gigabytes. The pipeline shipped zero for the plain reason
// that nothing computed the number.
//
// It is computed from the SAME embedded migrations the agent applies, not from
// a shell glob over the source tree, so the declared number cannot drift from
// the migrations the released binary actually contains: a file the embed
// pattern misses is a file this does not count either, and both sides are
// wrong together rather than the manifest being confidently wrong alone.

// agentSchemaVersion returns the highest migration version embedded in
// internal/db/migrations — the value internal/db records in schema_meta once
// every migration has run.
//
// It mirrors internal/db.readMigrationEntries' parse (the numeric prefix
// before the first underscore) rather than calling it, because that function
// is unexported and opening a database to ask would mean linking a SQLite
// driver into a release-time signing tool.
func agentSchemaVersion() (int, error) {
	entries, err := fs.ReadDir(migrations.Files, ".")
	if err != nil {
		return 0, fmt.Errorf("vendorsign: read embedded migrations: %w", err)
	}
	highest := 0
	for _, de := range entries {
		if de.IsDir() {
			continue
		}
		name := de.Name()
		if filepath.Ext(name) != ".sql" {
			continue
		}
		v, cerr := strconv.Atoi(strings.SplitN(name, "_", 2)[0])
		if cerr != nil {
			// The agent's own loader treats an unparseable migration as
			// fatal, so guessing here would let a release declare a schema
			// version for a set of migrations the agent will refuse to apply.
			return 0, fmt.Errorf("vendorsign: unparseable migration %q: %w", name, cerr)
		}
		if v > highest {
			highest = v
		}
	}
	if highest == 0 {
		return 0, fmt.Errorf("vendorsign: no migrations are embedded, so no schema version can be declared")
	}
	return highest, nil
}
