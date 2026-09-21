package store

import (
	"context"
	"errors"
	"fmt"
	"unicode"
	"unicode/utf8"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// maxToolVersionRunes bounds a captured tool/CLI version string. A real
// semver-ish token ("0.150.0", "3.17.4-beta.1", a short git sha suffix)
// is well under this; anything longer is a mis-decoded free-text field,
// not a version, and is rejected rather than persisted.
const maxToolVersionRunes = 64

// validToolVersion reports whether v is a plausible bounded version
// token: non-empty, at most maxToolVersionRunes runes, valid UTF-8, and
// free of whitespace and control characters. It deliberately does NOT
// enforce a semver grammar — vendors stamp all sorts of shapes ("v1.2",
// "2026.8.2", "7.3.40") and the column is free-form — it only rejects
// the shapes that betray a mis-decoded PROSE field (a space, a tab, a
// newline, a control byte). A rejected value is skipped, never stored,
// so the honest "unknown" empty is preserved.
func validToolVersion(v string) bool {
	if v == "" || !utf8.ValidString(v) {
		return false
	}
	if utf8.RuneCountInString(v) > maxToolVersionRunes {
		return false
	}
	for _, r := range v {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return false
		}
	}
	return true
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
