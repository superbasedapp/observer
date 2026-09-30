package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// maxToolVersionRunes bounds a captured tool/CLI version string. A real
// version-shaped token ("0.150.0", "3.17.4-beta.1", "v0.130.0",
// "0.45.0+build.7") is well under this; anything longer is a mis-decoded
// free-text field, not a version, and is rejected rather than persisted.
// Re-exported here (rather than referenced as orgcontract.MaxToolVersionRunes
// at every call site) purely so this file's own doc comments and the
// existing test file keep their short, unqualified name; the VALUE is
// orgcontract's, not a second one.
const maxToolVersionRunes = orgcontract.MaxToolVersionRunes

// validToolVersion reports whether v is a plausible bounded, ASCII,
// version-shaped token store.SetSessionToolVersion will persist
// (TOOLVERSION-1, docs/security.md). It delegates to
// orgcontract.ValidToolVersion — the single grammar shared with this
// column's other boundary, internal/orgserver/ingest.go's re-validation of
// a pushed row, so a value that passes here is guaranteed to also pass
// there. See that function's doc comment for the exact grammar (an
// optional leading "v"/"V", then a digit, then up to 62 more
// alphanumeric/"."/"_"/"+"/"-" characters, AND at least one "." anywhere)
// and the shapes it excludes: a URL, an email address, a path-traversal
// segment need a character outside the charset (space, "/", ":", "@");
// a compact secret such as an AWS access key id or a GitHub PAT is
// alphanumeric noise with no leading-digit-then-dot structure, which a real
// vendor-stamped version always has (MAJOR.MINOR[.PATCH] is the one
// structural feature every version scheme shares). A rejected value is
// skipped, never stored, so the honest "unknown" empty is preserved.
func validToolVersion(v string) bool {
	return orgcontract.ValidToolVersion(v)
}

// SetSessionToolVersion stamps the captured tool/CLI version (migration
// 125: sessions.tool_version) onto an existing session row. It is the
// ONE write path for that column — UpsertSession never touches it, so a
// re-parse that carries no version can never clear a captured value.
//
// SEMANTICS: FIRST-WINS-UNLESS-EMPTY, mirroring SetSessionSurface. The
// first grounded stamp sticks; a later parse can only FILL a column that
// is still empty, never change one that already holds a value. The
// version is a property of the session's ORIGIN — the tool build that
// produced it, fixed when the session was created — so a later
// re-derivation is not a correction; genuine repair is a backfill
// concern, not something a routine re-parse should do.
//
// The version is NOT an enum but IS a bounded token: validToolVersion
// length-caps it and rejects whitespace / control / prose. A value that
// fails validation is SKIPPED (returns false, nil) rather than
// persisted — a stray free-text field must never land in the column, but
// it must also never fail an ingest whose actions/tokens already landed.
//
// The returned bool honestly reports whether the UPDATE actually
// changed anything: true only when an EMPTY column became non-empty. An
// identical re-stamp, a differing later stamp, a rejected value, and an
// empty stamp all match zero rows and return false. A missing session id
// is a silent no-op — the next parse re-stamps.
func (s *Store) SetSessionToolVersion(ctx context.Context, tv models.SessionToolVersion) (bool, error) {
	if tv.SessionID == "" {
		return false, errors.New("store.SetSessionToolVersion: SessionID is required")
	}
	if !validToolVersion(tv.Version) {
		// Empty or malformed: skip, not fail. The honest "unknown" empty
		// is preserved and the actions/tokens already written are kept.
		return false, nil
	}
	// FIRST-WINS-UNLESS-EMPTY: the stored value is preferred; the incoming
	// one is used only where the column is currently NULL/''. The WHERE
	// guard restricts the UPDATE to rows where that actually fills
	// something, so RowsAffected stays an honest "changed".
	res, err := s.db.ExecContext(
		ctx,
		`UPDATE sessions SET
		   tool_version = COALESCE(NULLIF(tool_version, ''), NULLIF(?, ''))
		 WHERE id = ?
		   AND ? != '' AND IFNULL(tool_version, '') = ''`,
		tv.Version, tv.SessionID, tv.Version,
	)
	if err != nil {
		return false, fmt.Errorf("store.SetSessionToolVersion: %w", err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// LoadSessionToolVersion returns the stored tool/CLI version for a
// session. The result is "" when the session exists but no adapter has
// stamped a version (the honest unknown). sql.ErrNoRows propagates
// unwrapped when the session does not exist so callers can 404.
func (s *Store) LoadSessionToolVersion(ctx context.Context, sessionID string) (string, error) {
	if sessionID == "" {
		return "", errors.New("store.LoadSessionToolVersion: sessionID is required")
	}
	var v string
	if err := s.db.QueryRowContext(
		ctx,
		`SELECT COALESCE(tool_version, '') FROM sessions WHERE id = ?`,
		sessionID,
	).Scan(&v); err != nil {
		return "", err // sql.ErrNoRows propagates to the caller unwrapped.
	}
	return v, nil
}
