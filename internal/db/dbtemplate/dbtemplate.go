package dbtemplate

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"

	"github.com/marmutapp/superbased-observer/internal/db"
)

// DisableEnv names the opt-out switch. Setting it to "0" on the command line
// makes every [Open] in the run behave exactly like [db.Open] — see the
// package doc.
const DisableEnv = "OBSERVER_DBTEST_SQLITE_TEMPLATE"

// enabled is resolved ONCE at package-init time, before any test function can
// run. Reading it per call would let t.Setenv flip the mechanism halfway
// through a binary, which would make a "template artefact" bisect meaningless
// and would race the sync.Once below under t.Parallel.
var enabled = os.Getenv(DisableEnv) != "0"

// Enabled reports whether this binary is using the template. Exported so a
// staleness guard can skip itself when the operator opted out.
func Enabled() bool { return enabled }

// Open is a drop-in replacement for [db.Open] in test code: same arguments,
// same results, same cleanup obligations. It seeds opt.Path from a
// pre-migrated template when the path is brand new, then calls [db.Open].
//
// It is deliberately behaviour-preserving:
//
//   - [db.GuardLiveDB] runs FIRST, so a refused path still gets no file
//     created. Copying before the guard would defeat the point of it.
//   - An EXISTING file is never touched. Tests that close and reopen a path,
//     that pre-seed a file to observe how Open handles it, or that hand Open
//     a snapshot they just wrote, see their own bytes.
//   - ":memory:" and an empty path fall straight through.
//   - Every template failure falls back to a plain [db.Open]. The fallback is
//     correct, only slow; the callers' staleness guards (for example
//     internal/intelligence/dashboard's TestTemplateDBMatchesMigrationSet)
//     are what keep a silent permanent fallback from going unnoticed.
func Open(ctx context.Context, opts db.Options) (*sql.DB, error) {
	database, _, err := OpenSeeded(ctx, opts)
	return database, err
}

// OpenSeeded is [Open] plus the fact of whether this call actually seeded
// from the template.
//
// That second return exists so a test can assert the speedup. Without it the
// mechanism is unpinnable: if the copy silently stopped happening every test
// would still PASS — just slowly — and the suite would drift back to the
// 40-minute cliff with nothing red. Returning the fact per call, rather than
// counting copies in a package global, keeps it correct under t.Parallel.
func OpenSeeded(ctx context.Context, opts db.Options) (*sql.DB, bool, error) {
	seeded := false
	if enabled && opts.Path != "" && opts.Path != ":memory:" {
		if err := db.GuardLiveDB(opts.Path); err != nil {
			return nil, false, err
		}
		if isFreshPath(opts.Path) {
			if image, terr := Bytes(); terr == nil {
				if writeFile(opts.Path, image) == nil {
					seeded = true
				}
			}
		}
	}
	database, err := db.Open(ctx, opts)
	return database, seeded, err
}

// OpenFresh is [db.Open] under an explicit name. Migration-behaviour tests
// call it instead of [Open] so that "this test exercises the real chain from
// scratch" is stated in the code rather than inferred from which helper the
// file happened to use.
func OpenFresh(ctx context.Context, opts db.Options) (*sql.DB, error) {
	return db.Open(ctx, opts)
}

var (
	templateOnce  sync.Once
	templateImage []byte
	templateErr   error

	// Resolved at package init, before any test can rewrite the environment
	// variables os.MkdirTemp consults. Tests in several packages t.Setenv
	// HOME/USERPROFILE/TMPDIR to a t.TempDir(); if one of those happened to
	// trigger the build, the template file would land inside a directory
	// `testing` deletes at that test's end.
	baseTempDir = os.TempDir()
)

// Bytes returns the fully migrated template database as a byte image, built
// once per process.
//
// The image is held in memory and the file it was built from is removed
// immediately, so a run leaks no template files and no TestMain is required
// of any caller. A failed build is remembered and returned to EVERY later
// caller, so the failure is loud and uniform rather than a per-test flake.
func Bytes() ([]byte, error) {
	templateOnce.Do(buildTemplate)
	return templateImage, templateErr
}

func buildTemplate() {
	dir, err := os.MkdirTemp(baseTempDir, "observer-db-template-")
	if err != nil {
		templateErr = fmt.Errorf("dbtemplate: mkdtemp: %w", err)
		return
	}
	// The directory exists only for as long as it takes to read the image
	// back out; from then on the template lives in memory.
	defer func() { _ = os.RemoveAll(dir) }()
	path := filepath.Join(dir, "template.db")

	ctx := context.Background()
	database, err := db.Open(ctx, db.Options{Path: path})
	if err != nil {
		templateErr = fmt.Errorf("dbtemplate: build template: %w", err)
		return
	}
	// Fold the WAL back into the main file before closing: a copy of the main
	// file alone is only a complete database if nothing is left in the
	// sidecar. Without this the copy silently loses every migration still
	// sitting in -wal, and db.Open would replay the whole chain on top of it.
	//
	// The Exec is NOT the guarantee, and it would be easy to read it as one:
	// a busy checkpoint reports itself in the RESULT ROW, which ExecContext
	// discards. The guarantee is the post-close stat below — SQLite only
	// deletes the sidecars on last-connection close after a successful
	// checkpoint, so "no non-empty -wal survives Close" does imply the main
	// file is complete. Keep both: the Exec makes the common case cheap, the
	// stat makes it correct.
	_, ckptErr := database.ExecContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)")
	closeErr := database.Close()
	if ckptErr != nil {
		templateErr = fmt.Errorf("dbtemplate: checkpoint template: %w", ckptErr)
		return
	}
	if closeErr != nil {
		templateErr = fmt.Errorf("dbtemplate: close template: %w", closeErr)
		return
	}
	if info, statErr := os.Stat(path + "-wal"); statErr == nil && info.Size() > 0 {
		templateErr = errors.New("dbtemplate: template database left a non-empty -wal after close")
		return
	}
	image, err := os.ReadFile(path)
	if err != nil {
		templateErr = fmt.Errorf("dbtemplate: read template: %w", err)
		return
	}
	if len(image) == 0 {
		templateErr = errors.New("dbtemplate: template database is empty")
		return
	}
	templateImage = image
}

// isFreshPath reports whether nothing at all lives at path yet.
//
// The sidecars are part of the question, not a detail. SQLite treats a `-wal`
// next to a main database as a journal to REPLAY, so dropping the template
// over a stale foreign `-wal` yields that WAL's tables and loses the
// template's — including schema_meta, after which db.Open re-runs every
// migration on top of a foreign image. Without a main file SQLite instead
// discards the stale WAL, so the pre-template behaviour was correct and this
// would be a real divergence.
func isFreshPath(path string) bool {
	for _, candidate := range []string{path, path + "-wal", path + "-shm"} {
		if _, err := os.Stat(candidate); !errors.Is(err, fs.ErrNotExist) {
			return false
		}
	}
	return true
}

// writeFile materialises the template image at path. O_EXCL, not O_TRUNC:
// isFreshPath already said nothing is there, and if that changed underneath
// us the correct outcome is to fall back to a full migration rather than to
// clobber whatever appeared. A partially written file is removed, because the
// caller's fallback ("open normally and pay for the migrations") is only
// correct when there is no half-written database left for db.Open to find.
func writeFile(path string, image []byte) error {
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	out, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := out.Write(image); err != nil {
		out.Close()
		os.Remove(path)
		return err
	}
	// Close can fail at flush (ENOSPC, EIO); remove the destination on that
	// path too.
	if err := out.Close(); err != nil {
		os.Remove(path)
		return err
	}
	return nil
}
